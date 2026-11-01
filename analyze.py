#!/usr/bin/env python3
"""Phishing analiz araci - giris noktasi.

Kullanim: python analyze.py <dosya.eml>
"""

from __future__ import annotations

import sys

from phishing_analyzer.checks import (
    check_authentication_results,
    check_link_mismatch,
    check_sender_mismatch,
)
from phishing_analyzer.links import extract_links, get_body_text
from phishing_analyzer.parsing import load_eml, parse_headers
from phishing_analyzer.report import render_report


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Kullanim: python analyze.py <dosya.eml>")
        return 1

    msg = load_eml(argv[1])
    parsed = parse_headers(msg)

    html_body, _plain_body = get_body_text(msg)
    links = extract_links(html_body) if html_body else []

    findings = (
        check_sender_mismatch(parsed)
        + check_authentication_results(parsed)
        + check_link_mismatch(links)
    )

    print(render_report(parsed, links, findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
