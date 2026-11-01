#!/usr/bin/env python3
"""Phishing analiz araci - giris noktasi.

Kullanim: python analyze.py <dosya.eml>
"""

from __future__ import annotations

import sys

from phishing_analyzer.checks import check_authentication_results, check_sender_mismatch
from phishing_analyzer.parsing import load_eml, parse_headers


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Kullanim: python analyze.py <dosya.eml>")
        return 1

    msg = load_eml(argv[1])
    parsed = parse_headers(msg)

    print(f"Konu        : {parsed.subject}")
    print(f"Tarih       : {parsed.date}")
    print(f"From        : {parsed.from_display!r} <{parsed.from_address}>")
    print(f"Reply-To    : {parsed.reply_to_display!r} <{parsed.reply_to_address}>")
    print(f"Return-Path : {parsed.return_path}")
    print(f"Auth-Results: {parsed.authentication_results or '(yok)'}")
    print(f"Received zinciri ({len(parsed.received_chain)} hop):")
    for i, hop in enumerate(parsed.received_chain, 1):
        print(f"  [{i}] {hop}")

    findings = check_sender_mismatch(parsed) + check_authentication_results(parsed)
    print(f"\nBulgular ({len(findings)}):")
    if not findings:
        print("  (supheli bir bulgu tespit edilmedi)")
    for f in findings:
        print(f"  [{f.severity.value}] {f.check}: {f.message}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
