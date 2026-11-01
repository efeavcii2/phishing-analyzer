"""E-postadaki ekleri listeler ve hash'ler.

Guvenlik: ek icerigini ASLA diske yazmaz, acmaz veya calistirmaz -
sadece bellekte decode edip MD5/SHA256 hash'ini hesaplar.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from email.message import Message


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    md5: str
    sha256: str


def extract_attachments(msg: Message) -> list[Attachment]:
    """Mesajdaki tum ekleri bulur, icerigini (sadece bellekte) hash'ler.

    "Ek" sayilma kosulu: bir dosya adi olmasi veya Content-Disposition'in
    "attachment" olmasi (inline resim gibi govde parcalarini haric tutar).
    """
    attachments: list[Attachment] = []

    if not msg.is_multipart():
        return attachments

    for part in msg.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        if not filename and disposition != "attachment":
            continue

        payload = part.get_payload(decode=True)
        if payload is None:
            continue

        attachments.append(
            Attachment(
                filename=filename or "(adsiz)",
                content_type=part.get_content_type(),
                size=len(payload),
                md5=hashlib.md5(payload).hexdigest(),
                sha256=hashlib.sha256(payload).hexdigest(),
            )
        )

    return attachments
