"""E-posta (.eml) dosyasini okuyup yapilandirilmis veriye cevirir."""

from __future__ import annotations

import email
from dataclasses import dataclass, field
from email.message import Message
from email.utils import parseaddr
from pathlib import Path


@dataclass
class ParsedEmail:
    raw_message: Message
    subject: str
    date: str
    from_display: str
    from_address: str
    reply_to_display: str
    reply_to_address: str
    return_path: str
    received_chain: list[str] = field(default_factory=list)
    authentication_results: str = ""


def load_eml(path: str | Path) -> Message:
    """.eml dosyasini diskten okuyup email.message.Message nesnesine cevirir."""
    with open(path, "rb") as f:
        return email.message_from_binary_file(f)


def parse_headers(msg: Message) -> ParsedEmail:
    """Basliklari ayristirip ParsedEmail olarak doner."""
    from_display, from_address = parseaddr(msg.get("From", ""))
    reply_display, reply_address = parseaddr(msg.get("Reply-To", ""))
    _, return_path = parseaddr(msg.get("Return-Path", ""))

    raw_received = msg.get_all("Received", []) or []
    received_chain = [" ".join(hop.split()) for hop in raw_received]

    return ParsedEmail(
        raw_message=msg,
        subject=msg.get("Subject", "(konu yok)"),
        date=msg.get("Date", "(tarih yok)"),
        from_display=from_display,
        from_address=from_address,
        reply_to_display=reply_display,
        reply_to_address=reply_address,
        return_path=return_path,
        received_chain=received_chain,
        authentication_results=" ".join(msg.get("Authentication-Results", "").split()),
    )
