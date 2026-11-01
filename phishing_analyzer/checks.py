"""Analiz kontrolleri - her biri ParsedEmail alir, Finding listesi doner."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from phishing_analyzer.parsing import ParsedEmail


class Severity(str, Enum):
    INFO = "BILGI"
    LOW = "DUSUK"
    MEDIUM = "ORTA"
    HIGH = "YUKSEK"


@dataclass
class Finding:
    check: str
    severity: Severity
    message: str


def _domain(address: str) -> str:
    """E-posta adresinden domain kismini cikarir, kucuk harfe cevirir."""
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[-1].lower()


def check_sender_mismatch(parsed: ParsedEmail) -> list[Finding]:
    """From / Return-Path / Reply-To domainlerini karsilastirir.

    Return-Path, mesaji gercekte kimin gonderdigini (zarf adresi) gosterir;
    From ise kullaniciya gosterilen, kolayca sahtelestirilebilen basliktir.
    Bu ikisinin domaini farkliysa klasik bir spoofing/phishing isaretidir.
    """
    findings: list[Finding] = []

    from_domain = _domain(parsed.from_address)
    return_path_domain = _domain(parsed.return_path)
    reply_to_domain = _domain(parsed.reply_to_address)

    if from_domain and return_path_domain and from_domain != return_path_domain:
        findings.append(
            Finding(
                check="sender_mismatch",
                severity=Severity.HIGH,
                message=(
                    f"From domaini ({from_domain}) ile Return-Path domaini "
                    f"({return_path_domain}) uyusmuyor. Gorunen gonderici ile "
                    f"gercek zarf adresi farkli - klasik spoofing isareti."
                ),
            )
        )

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        findings.append(
            Finding(
                check="reply_to_mismatch",
                severity=Severity.MEDIUM,
                message=(
                    f"Reply-To domaini ({reply_to_domain}) From domaininden "
                    f"({from_domain}) farkli. Yanitlarin farkli bir adrese "
                    f"yonlendirilmesi phishing kampanyalarinda yaygindir."
                ),
            )
        )

    return findings


# spf/dkim/dmarc sonuc siddetleri. "pass" icin bulgu uretmiyoruz.
_AUTH_SEVERITY = {
    "fail": Severity.HIGH,
    "softfail": Severity.MEDIUM,
    "none": Severity.LOW,
    "neutral": Severity.LOW,
    "temperror": Severity.LOW,
    "permerror": Severity.MEDIUM,
}


def check_authentication_results(parsed: ParsedEmail) -> list[Finding]:
    """Authentication-Results basligindan SPF/DKIM/DMARC sonuclarini yorumlar.

    Bu baslik, alici mail sunucusunun gonderici dogrulama protokollerini
    calistirdiktan sonra ekledigi sonuc ozetidir - mail istemcisi tarafindan
    degil, alici tarafindan uretilir, bu yuzden From basligindan daha
    guvenilir bir imza kaynagidir.
    """
    findings: list[Finding] = []
    header = parsed.authentication_results

    if not header:
        findings.append(
            Finding(
                check="auth_results_missing",
                severity=Severity.LOW,
                message=(
                    "Authentication-Results basligi yok, SPF/DKIM/DMARC "
                    "sonucu dogrulanamiyor."
                ),
            )
        )
        return findings

    for mechanism, result in re.findall(r"\b(spf|dkim|dmarc)=(\w+)", header, re.IGNORECASE):
        mechanism = mechanism.lower()
        result = result.lower()
        if result == "pass":
            continue
        severity = _AUTH_SEVERITY.get(result, Severity.LOW)
        findings.append(
            Finding(
                check=f"{mechanism}_{result}",
                severity=severity,
                message=f"{mechanism.upper()} sonucu '{result}' - basarisiz/supheli dogrulama.",
            )
        )

    return findings
