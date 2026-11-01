#!/usr/bin/env python3
"""Phishing analiz araci - giris noktasi.

Kullanim: python analyze.py <dosya.eml>
"""

from __future__ import annotations

import sys

from phishing_analyzer.attachments import extract_attachments
from phishing_analyzer.checks import (
    check_authentication_results,
    check_ip_based_url,
    check_link_mismatch,
    check_lookalike_domain,
    check_punycode_domain,
    check_sender_mismatch,
    check_suspicious_language,
)
from phishing_analyzer.links import extract_links, get_body_text, html_to_text
from phishing_analyzer.parsing import load_eml, parse_headers
from phishing_analyzer.report import render_report
from phishing_analyzer.threat_intel import check_attachment_hashes, check_urlhaus


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Kullanim: python analyze.py <dosya.eml>")
        return 1

    msg = load_eml(argv[1])
    parsed = parse_headers(msg)

    html_body, plain_body = get_body_text(msg)
    links = extract_links(html_body) if html_body else []
    body_text = html_to_text(html_body) if html_body else plain_body
    hrefs = [link.href for link in links if link.href]
    attachments = extract_attachments(msg)

    findings = (
        check_sender_mismatch(parsed)
        + check_authentication_results(parsed)
        + check_link_mismatch(links)
        + check_suspicious_language(body_text)
        + check_ip_based_url(links)
        + check_lookalike_domain(parsed, links)
        + check_punycode_domain(parsed, links)
        + check_urlhaus(hrefs)
        + check_attachment_hashes(attachments)
    )

    print(render_report(parsed, links, findings, attachments))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
