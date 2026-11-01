"""Bulgulari okunabilir bir terminal raporuna donusturur."""

from __future__ import annotations

from phishing_analyzer.attachments import Attachment
from phishing_analyzer.checks import Finding, Severity
from phishing_analyzer.links import ExtractedLink
from phishing_analyzer.parsing import ParsedEmail
from phishing_analyzer.scoring import RiskScore

_SEVERITY_ORDER = {
    Severity.HIGH: 0,
    Severity.MEDIUM: 1,
    Severity.LOW: 2,
    Severity.INFO: 3,
}


def render_report(
    parsed: ParsedEmail,
    links: list[ExtractedLink],
    findings: list[Finding],
    attachments: list[Attachment] | None = None,
    risk: RiskScore | None = None,
) -> str:
    lines: list[str] = []

    lines.append("=" * 60)
    lines.append("PHISHING ANALIZ RAPORU")
    lines.append("=" * 60)
    if risk is not None:
        lines.append(f"RISK SEVIYESI: {risk.level} (puan: {risk.score})")
        lines.append("")
    lines.append(f"Konu        : {parsed.subject}")
    lines.append(f"Tarih       : {parsed.date}")
    lines.append(f"From        : {parsed.from_display!r} <{parsed.from_address}>")
    lines.append(f"Reply-To    : {parsed.reply_to_display!r} <{parsed.reply_to_address}>")
    lines.append(f"Return-Path : {parsed.return_path}")
    lines.append("")

    lines.append(f"Received zinciri ({len(parsed.received_chain)} hop):")
    for i, hop in enumerate(parsed.received_chain, 1):
        lines.append(f"  [{i}] {hop}")
    lines.append("")

    lines.append(f"Linkler ({len(links)}):")
    if not links:
        lines.append("  (govdede link bulunamadi)")
    for link in links:
        lines.append(f"  '{link.display_text}' -> {link.href}")
    lines.append("")

    attachments = attachments or []
    lines.append(f"Ekler ({len(attachments)}):")
    if not attachments:
        lines.append("  (ek bulunamadi)")
    for att in attachments:
        lines.append(f"  {att.filename} ({att.content_type}, {att.size} byte)")
        lines.append(f"    md5:    {att.md5}")
        lines.append(f"    sha256: {att.sha256}")
    lines.append("")

    sorted_findings = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

    lines.append("-" * 60)
    lines.append(f"BULGULAR ({len(sorted_findings)})")
    lines.append("-" * 60)
    if not sorted_findings:
        lines.append("  Supheli bir bulgu tespit edilmedi.")
    for f in sorted_findings:
        lines.append(f"  [{f.severity.value:<6}] {f.check}: {f.message}")
    lines.append("")

    counts: dict[Severity, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ", ".join(
        f"{sev.value}: {cnt}"
        for sev, cnt in sorted(counts.items(), key=lambda kv: _SEVERITY_ORDER.get(kv[0], 99))
    )
    lines.append(f"Ozet: {summary or 'bulgu yok'}")
    lines.append("=" * 60)

    return "\n".join(lines)
