"""E-posta govdesinden linkleri cikarir (gorunen metin + gercek href)."""

from __future__ import annotations

from dataclasses import dataclass
from email.message import Message
from html.parser import HTMLParser


@dataclass
class ExtractedLink:
    href: str
    display_text: str


class _AnchorExtractor(HTMLParser):
    """HTML icindeki <a href=...>metin</a> ciftlerini toplar."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[ExtractedLink] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            self._current_href = dict(attrs).get("href")
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current_href is not None:
            self.links.append(
                ExtractedLink(
                    href=self._current_href,
                    display_text="".join(self._current_text).strip(),
                )
            )
            self._current_href = None
            self._current_text = []


def _decode_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if not payload:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return payload.decode("utf-8", errors="replace")


def get_body_text(msg: Message) -> tuple[str, str]:
    """Mesaj govdesini (html_body, plain_body) olarak doner.

    Multipart mesajlarda ilk text/html ve ilk text/plain parcasini bulur.
    """
    html_body = ""
    plain_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            content_type = part.get_content_type()
            if content_type == "text/html" and not html_body:
                html_body = _decode_part(part)
            elif content_type == "text/plain" and not plain_body:
                plain_body = _decode_part(part)
    elif msg.get_content_type() == "text/html":
        html_body = _decode_part(msg)
    else:
        plain_body = _decode_part(msg)

    return html_body, plain_body


def extract_links(html_body: str) -> list[ExtractedLink]:
    """HTML govdesindeki <a> etiketlerini (href + gorunen metin) cikarir."""
    parser = _AnchorExtractor()
    parser.feed(html_body)
    return parser.links
