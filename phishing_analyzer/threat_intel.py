"""URLhaus (abuse.ch) uzerinden bilinen kotu amacli URL sorgusu yapar.

Auth-Key gerektirir (abuse.ch, auth.abuse.ch'den ucretsiz alinir).
Key .env dosyasindan okunur, repoya girmez (.gitignore'da).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from phishing_analyzer.attachments import Attachment
from phishing_analyzer.checks import Finding, Severity
from phishing_analyzer.config import get_urlhaus_auth_key, get_virustotal_api_key

_URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
_VIRUSTOTAL_FILE_ENDPOINT = "https://www.virustotal.com/api/v3/files/{sha256}"
_TIMEOUT_SECONDS = 10


def query_urlhaus(url: str, auth_key: str) -> dict | None:
    """URLhaus'a bir URL sorgusu gonderir, JSON yaniti doner.

    Ag hatasi/zaman asimi durumunda None doner - cagiran taraf bunu
    "kontrol edilemedi" olarak ele almali, hata olarak degil.
    """
    data = urllib.parse.urlencode({"url": url}).encode("ascii")
    request = urllib.request.Request(
        _URLHAUS_ENDPOINT, data=data, method="POST", headers={"Auth-Key": auth_key}
    )
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        return None


def check_urlhaus(urls: list[str]) -> list[Finding]:
    """Her URL'yi URLhaus'ta sorgular, bilinen kotu amacli ise bulgu uretir.

    URLHAUS_AUTH_KEY .env'de yoksa ag cagrisi hic yapilmadan tek bir
    BILGI bulgusuyla atlanir.
    """
    auth_key = get_urlhaus_auth_key()
    if not auth_key:
        return [
            Finding(
                check="urlhaus_skipped",
                severity=Severity.INFO,
                message=(
                    "URLHAUS_AUTH_KEY .env'de tanimli degil, URLhaus kontrolu "
                    "atlandi. Ucretsiz key: https://auth.abuse.ch"
                ),
            )
        ]

    findings: list[Finding] = []
    checked: set[str] = set()

    for url in urls:
        if not url or url in checked:
            continue
        checked.add(url)

        result = query_urlhaus(url, auth_key)
        if result is None:
            findings.append(
                Finding(
                    check="urlhaus_unreachable",
                    severity=Severity.INFO,
                    message=f"URLhaus sorgusu yapilamadi (ag hatasi/zaman asimi): {url}",
                )
            )
            continue

        status = result.get("query_status")
        if status == "ok":
            threat = result.get("threat", "bilinmiyor")
            tags = ", ".join(result.get("tags") or []) or "etiket yok"
            date_added = result.get("date_added", "bilinmiyor")
            findings.append(
                Finding(
                    check="urlhaus_known_malicious",
                    severity=Severity.HIGH,
                    message=(
                        f"URL URLhaus veritabaninda KOTU AMACLI olarak kayitli: {url} "
                        f"(tehdit: {threat}, etiketler: {tags}, eklenme: {date_added})"
                    ),
                )
            )
        # status == "no_results" / "invalid_url" icin bulgu uretmiyoruz

    return findings


def query_virustotal_hash(sha256: str, api_key: str) -> dict | None:
    """VirusTotal'da bir SHA256 hash'ini sorgular (GET /files/{hash}).

    Hash hic analiz edilmemisse (404) {'found': False} doner.
    Ag hatasi/zaman asimi durumunda None doner.
    """
    url = _VIRUSTOTAL_FILE_ENDPOINT.format(sha256=sha256)
    request = urllib.request.Request(url, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return {"found": False}
        return None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        return None


def check_attachment_hashes(attachments: list[Attachment]) -> list[Finding]:
    """Her ek dosyanin SHA256 hash'ini VirusTotal'da sorgular.

    Hic ek yoksa veya VIRUSTOTAL_API_KEY tanimli degilse ag cagrisi
    yapilmaz. Hash VirusTotal'da bilinmiyorsa (daha once analiz
    edilmemis) bulgu uretilmez - bu "guvenli" demek degildir, sadece
    "bilgi yok" demektir.
    """
    if not attachments:
        return []

    api_key = get_virustotal_api_key()
    if not api_key:
        return [
            Finding(
                check="virustotal_skipped",
                severity=Severity.INFO,
                message=(
                    "VIRUSTOTAL_API_KEY .env'de tanimli degil, ek hash kontrolu "
                    "atlandi. Ucretsiz key: virustotal.com hesap ayarlari."
                ),
            )
        ]

    findings: list[Finding] = []
    for att in attachments:
        result = query_virustotal_hash(att.sha256, api_key)
        if result is None:
            findings.append(
                Finding(
                    check="virustotal_unreachable",
                    severity=Severity.INFO,
                    message=f"VirusTotal sorgusu yapilamadi: {att.filename}",
                )
            )
            continue

        if not result.get("found", True) and "data" not in result:
            continue  # hash VirusTotal'da hic yok, bulgu uretme

        stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0:
            findings.append(
                Finding(
                    check="attachment_known_malware",
                    severity=Severity.HIGH,
                    message=(
                        f"Ek '{att.filename}' (sha256:{att.sha256[:16]}...) "
                        f"VirusTotal'da {malicious} motor tarafindan ZARARLI "
                        f"olarak isaretlendi ({suspicious} supheli)."
                    ),
                )
            )
        elif suspicious > 0:
            findings.append(
                Finding(
                    check="attachment_suspicious",
                    severity=Severity.MEDIUM,
                    message=(
                        f"Ek '{att.filename}' VirusTotal'da {suspicious} motor "
                        f"tarafindan supheli olarak isaretlendi."
                    ),
                )
            )

    return findings
