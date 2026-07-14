"""Render a :class:`ScanResult` as text, JSON, or a self-contained HTML report."""

from __future__ import annotations

import html
import json
from typing import Dict

from security_analyser.model import ScanResult, Severity

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

_SEVERITY_COLORS: Dict[str, str] = {
    "critical": "#7c1d1d",
    "high": "#b91c1c",
    "medium": "#c2660c",
    "low": "#b59105",
    "info": "#2563eb",
}


def render_text(result: ScanResult) -> str:
    ctx = result.context
    lines = []
    lines.append("=" * 70)
    lines.append("SECURITY ANALYSER REPORT")
    lines.append("=" * 70)
    lines.append(f"Target      : {ctx.requested_url}")
    lines.append(f"Final URL   : {ctx.final_url}")
    lines.append(f"Scanned at  : {result.scanned_at.isoformat()}")

    if not ctx.reachable:
        lines.append("")
        lines.append(f"ERROR: target could not be reached: {ctx.error}")
        return "\n".join(lines)

    lines.append(f"HTTP status : {ctx.status_code}")
    if ctx.tls is not None:
        tls = ctx.tls
        state = "verified" if tls.verified else f"UNVERIFIED ({tls.verify_error})"
        expiry = "" if tls.days_to_expiry is None else f", expires in {tls.days_to_expiry}d"
        lines.append(f"TLS         : {tls.protocol or 'n/a'} [{state}]{expiry}")

    counts = result.counts()
    lines.append("")
    lines.append(
        "Summary     : "
        + ", ".join(f"{counts[s.label]} {s.label}" for s in _SEVERITY_ORDER)
    )
    lines.append("-" * 70)

    findings = result.sorted_findings()
    if not findings:
        lines.append("No issues found. ✓")
        return "\n".join(lines)

    for i, finding in enumerate(findings, 1):
        lines.append(f"[{i}] {finding.severity.label.upper():8} {finding.title}")
        lines.append(f"    Category : {finding.category}  (id: {finding.id})")
        lines.append(f"    Issue    : {finding.description}")
        if finding.evidence:
            lines.append(f"    Evidence : {finding.evidence}")
        lines.append(f"    Fix      : {finding.recommendation}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def grade(result: ScanResult) -> str:
    """Return an A–F letter grade summarising the result's risk."""
    if not result.context.reachable:
        return "N/A"
    counts = result.counts()
    if counts["critical"]:
        return "F"
    if counts["high"]:
        return "E" if counts["high"] > 1 else "D"
    if counts["medium"]:
        return "C" if counts["medium"] > 2 else "B"
    if counts["low"] or counts["info"]:
        return "B"
    return "A"


def result_to_payload(result: ScanResult) -> Dict[str, object]:
    """Build the serialisable dict shared by the JSON report and the web API."""
    ctx = result.context
    return {
        "target": ctx.requested_url,
        "final_url": ctx.final_url,
        "host": ctx.host,
        "scheme": ctx.scheme,
        "scanned_at": result.scanned_at.isoformat(),
        "reachable": ctx.reachable,
        "error": ctx.error,
        "status_code": ctx.status_code,
        "tls": ctx.tls.to_dict() if ctx.tls else None,
        "summary": result.counts(),
        "total_findings": len(result.findings),
        "grade": grade(result),
        "highest_severity": (
            result.highest_severity.label if result.highest_severity else None
        ),
        "findings": [f.to_dict() for f in result.sorted_findings()],
    }


def render_json(result: ScanResult) -> str:
    return json.dumps(result_to_payload(result), indent=2)


def render_html(result: ScanResult) -> str:
    ctx = result.context
    counts = result.counts()
    e = html.escape

    summary_cards = "".join(
        f'<div class="card sev-{s.label}">'
        f'<div class="count">{counts[s.label]}</div>'
        f'<div class="label">{s.label}</div></div>'
        for s in _SEVERITY_ORDER
    )

    if not ctx.reachable:
        rows = (
            f'<tr><td colspan="2" class="error">Target could not be reached: '
            f"{e(ctx.error or 'unknown error')}</td></tr>"
        )
        findings_html = ""
    else:
        findings = result.sorted_findings()
        if findings:
            items = []
            for finding in findings:
                evidence = (
                    f'<div class="evidence"><span>Evidence</span>'
                    f"<code>{e(finding.evidence)}</code></div>"
                    if finding.evidence
                    else ""
                )
                items.append(
                    f'<article class="finding sev-{finding.severity.label}">'
                    f'<div class="finding-head">'
                    f'<span class="badge sev-{finding.severity.label}">'
                    f"{finding.severity.label.upper()}</span>"
                    f"<h3>{e(finding.title)}</h3></div>"
                    f'<div class="meta">{e(finding.category)} &middot; '
                    f"{e(finding.id)}</div>"
                    f"<p>{e(finding.description)}</p>"
                    f"{evidence}"
                    f'<div class="fix"><span>Recommended fix</span>'
                    f"<p>{e(finding.recommendation)}</p></div>"
                    f"</article>"
                )
            findings_html = "\n".join(items)
        else:
            findings_html = '<p class="ok">No issues found. ✓</p>'
        rows = ""

    tls_row = ""
    if ctx.tls is not None:
        tls = ctx.tls
        state = "verified" if tls.verified else f"unverified: {tls.verify_error}"
        expiry = "" if tls.days_to_expiry is None else f" (expires in {tls.days_to_expiry} days)"
        tls_row = (
            f"<tr><th>TLS</th><td>{e(tls.protocol or 'n/a')} &mdash; "
            f"{e(state)}{e(expiry)}</td></tr>"
        )

    meta_table = (
        "<table class='meta-table'>"
        f"<tr><th>Target</th><td>{e(ctx.requested_url)}</td></tr>"
        f"<tr><th>Final URL</th><td>{e(ctx.final_url)}</td></tr>"
        f"<tr><th>HTTP status</th><td>{e(str(ctx.status_code))}</td></tr>"
        f"{tls_row}"
        f"<tr><th>Scanned at</th><td>{e(result.scanned_at.isoformat())}</td></tr>"
        f"{rows}"
        "</table>"
    )

    return _HTML_TEMPLATE.format(
        target=e(ctx.requested_url),
        summary_cards=summary_cards,
        meta_table=meta_table,
        findings=findings_html,
    )


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Report &mdash; {target}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         margin: 0; background: #f4f5f7; color: #1a1a1a; line-height: 1.5; }}
  .wrap {{ max-width: 900px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }}
  h1 {{ font-size: 1.6rem; margin: 0 0 .25rem; }}
  .sub {{ color: #666; margin: 0 0 1.5rem; word-break: break-all; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: .75rem; margin-bottom: 1.5rem; }}
  .card {{ flex: 1 1 120px; background: #fff; border-radius: 10px; padding: 1rem;
          text-align: center; border-top: 4px solid #ccc; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .card .count {{ font-size: 1.8rem; font-weight: 700; }}
  .card .label {{ text-transform: uppercase; font-size: .72rem; letter-spacing: .05em; color: #666; }}
  .card.sev-critical {{ border-top-color: #7c1d1d; }}
  .card.sev-high {{ border-top-color: #b91c1c; }}
  .card.sev-medium {{ border-top-color: #c2660c; }}
  .card.sev-low {{ border-top-color: #b59105; }}
  .card.sev-info {{ border-top-color: #2563eb; }}
  table.meta-table {{ width: 100%; border-collapse: collapse; background: #fff;
          border-radius: 10px; overflow: hidden; margin-bottom: 2rem; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .meta-table th, .meta-table td {{ text-align: left; padding: .6rem .9rem; border-bottom: 1px solid #eee;
          font-size: .9rem; vertical-align: top; }}
  .meta-table th {{ width: 130px; color: #555; font-weight: 600; }}
  .meta-table td.error {{ color: #b91c1c; font-weight: 600; }}
  .finding {{ background: #fff; border-radius: 10px; padding: 1.1rem 1.25rem; margin-bottom: 1rem;
          border-left: 5px solid #ccc; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .finding.sev-critical {{ border-left-color: #7c1d1d; }}
  .finding.sev-high {{ border-left-color: #b91c1c; }}
  .finding.sev-medium {{ border-left-color: #c2660c; }}
  .finding.sev-low {{ border-left-color: #b59105; }}
  .finding.sev-info {{ border-left-color: #2563eb; }}
  .finding-head {{ display: flex; align-items: center; gap: .6rem; }}
  .finding h3 {{ margin: 0; font-size: 1.05rem; }}
  .badge {{ font-size: .68rem; font-weight: 700; color: #fff; padding: .15rem .5rem;
          border-radius: 999px; letter-spacing: .04em; }}
  .badge.sev-critical {{ background: #7c1d1d; }}
  .badge.sev-high {{ background: #b91c1c; }}
  .badge.sev-medium {{ background: #c2660c; }}
  .badge.sev-low {{ background: #b59105; }}
  .badge.sev-info {{ background: #2563eb; }}
  .meta {{ color: #888; font-size: .78rem; margin: .25rem 0 .6rem; }}
  .finding p {{ margin: .35rem 0; font-size: .92rem; }}
  .evidence, .fix {{ margin-top: .6rem; font-size: .85rem; }}
  .evidence span, .fix span {{ display: block; text-transform: uppercase; font-size: .68rem;
          letter-spacing: .05em; color: #888; margin-bottom: .2rem; }}
  .evidence code {{ display: block; background: #f6f6f6; padding: .5rem .6rem; border-radius: 6px;
          font-size: .82rem; word-break: break-all; }}
  .fix {{ background: #f3f8f3; border-radius: 6px; padding: .55rem .7rem; }}
  .ok {{ font-size: 1.1rem; color: #15803d; font-weight: 600; }}
  footer {{ margin-top: 2rem; color: #999; font-size: .78rem; text-align: center; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #16181d; color: #e6e6e6; }}
    .card, table.meta-table, .finding {{ background: #21242b; box-shadow: none; }}
    .sub, .card .label, .meta-table th {{ color: #9aa0aa; }}
    .meta-table th, .meta-table td {{ border-bottom-color: #2c2f37; }}
    .evidence code {{ background: #16181d; }}
    .fix {{ background: #1a241a; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <h1>Security Analyser Report</h1>
  <p class="sub">{target}</p>
  <div class="cards">{summary_cards}</div>
  {meta_table}
  <h2>Findings</h2>
  {findings}
  <footer>Generated by security-analyser &middot; review findings and prioritise by severity.</footer>
</div>
</body>
</html>
"""


def render(result: ScanResult, fmt: str = "text") -> str:
    fmt = fmt.lower()
    if fmt == "text":
        return render_text(result)
    if fmt == "json":
        return render_json(result)
    if fmt == "html":
        return render_html(result)
    raise ValueError(f"Unknown report format: {fmt!r}")
