"""Render a :class:`ScanResult` as text, JSON, or a self-contained HTML report.

The JSON and HTML renderers work from the serialisable *payload* built by
:func:`result_to_payload`, so the CLI and the web server produce identical
reports from the same data.
"""

from __future__ import annotations

import html
import json
from typing import Dict

from security_analyser.audit import build_scorecard
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

_STATUS_LABEL = {"safe": "SAFE", "review": "REVIEW", "unsafe": "UNSAFE", "n/a": "N/A"}
_STATUS_COLORS = {"safe": "#15803d", "review": "#b59105", "unsafe": "#b91c1c", "n/a": "#6b7280"}


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
    """Build the serialisable dict shared by the reports and the web API."""
    ctx = result.context
    scorecard = build_scorecard(result)
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
        "pages_scanned": ctx.pages_scanned,
        "paths_probed": ctx.paths_probed,
        "summary": result.counts(),
        "total_findings": len(result.findings),
        "grade": grade(result),
        "score": scorecard["overall_score"],
        "highest_severity": (
            result.highest_severity.label if result.highest_severity else None
        ),
        "scorecard": scorecard,
        "findings": [f.to_dict() for f in result.sorted_findings()],
    }


# --------------------------------------------------------------------------- #
# Text report
# --------------------------------------------------------------------------- #

def render_text(result: ScanResult) -> str:
    payload = result_to_payload(result)
    lines = []
    lines.append("=" * 70)
    lines.append("SECURITY ANALYSER REPORT")
    lines.append("=" * 70)
    lines.append(f"Target      : {payload['target']}")
    lines.append(f"Final URL   : {payload['final_url']}")
    lines.append(f"Scanned at  : {payload['scanned_at']}")

    if not payload["reachable"]:
        lines.append("")
        lines.append(f"ERROR: target could not be reached: {payload['error']}")
        return "\n".join(lines) + "\n"

    lines.append(f"HTTP status : {payload['status_code']}")
    tls = payload["tls"]
    if tls:
        state = "verified" if tls["verified"] == "True" else f"UNVERIFIED ({tls['verify_error']})"
        expiry = "" if not tls["days_to_expiry"] else f", expires in {tls['days_to_expiry']}d"
        lines.append(f"TLS         : {tls['protocol'] or 'n/a'} [{state}]{expiry}")

    if payload.get("pages_scanned", 1) > 1:
        lines.append(f"Pages scanned : {payload['pages_scanned']}")

    lines.append("")
    lines.append(f"OVERALL SCORE : {payload['score']}/100   (grade {payload['grade']})")
    counts = payload["summary"]
    lines.append(
        "Findings      : "
        + ", ".join(f"{counts[s.label]} {s.label}" for s in _SEVERITY_ORDER)
    )

    # Scorecard: every control, safe or not.
    lines.append("")
    lines.append("SCORECARD (every check)")
    lines.append("-" * 70)
    for c in payload["scorecard"]["controls"]:
        status = _STATUS_LABEL[c["status"]]
        score = "  -  " if c["score"] is None else f"{c['score']:>3}/100"
        lines.append(f"[{status:^6}] {c['title']:<34} {score}")
        lines.append(f"           {c['summary']}")
    lines.append("-" * 70)

    findings = payload["findings"]
    if not findings:
        lines.append("No issues found. ✓")
        return "\n".join(lines) + "\n"

    lines.append("DETAILED FINDINGS")
    lines.append("")
    for i, f in enumerate(findings, 1):
        lines.append(f"[{i}] {f['severity'].upper():8} {f['title']}")
        lines.append(f"    Category : {f['category']}  (id: {f['id']})")
        if f.get("page"):
            lines.append(f"    Page     : {f['page']}")
        lines.append(f"    Issue    : {f['description']}")
        if f["evidence"]:
            lines.append(f"    Evidence : {f['evidence']}")
        lines.append(f"    Fix      : {f['recommendation']}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# --------------------------------------------------------------------------- #
# JSON report
# --------------------------------------------------------------------------- #

def render_json(result: ScanResult) -> str:
    return json.dumps(result_to_payload(result), indent=2)


# --------------------------------------------------------------------------- #
# HTML report (payload-based so the web server can reuse it)
# --------------------------------------------------------------------------- #

def render_html(result: ScanResult) -> str:
    return render_html_payload(result_to_payload(result))


def render_html_payload(payload: dict) -> str:
    e = html.escape
    target = e(str(payload.get("target", "")))

    if not payload.get("reachable", False):
        body = (
            f'<h1>Security Analyser Report</h1><p class="sub">{target}</p>'
            f'<div class="err">Target could not be reached: '
            f'{e(str(payload.get("error") or "unknown error"))}</div>'
        )
        return _HTML_TEMPLATE.format(target=target, body=body)

    score = payload.get("score")
    grade_letter = e(str(payload.get("grade", "N/A")))
    score_class = _score_class(score)

    counts = payload.get("summary", {})
    cards = "".join(
        f'<div class="card sev-{s.label}"><div class="count">{counts.get(s.label, 0)}</div>'
        f'<div class="label">{s.label}</div></div>'
        for s in _SEVERITY_ORDER
    )

    # Meta table
    tls = payload.get("tls")
    tls_row = ""
    if tls:
        state = "verified" if tls.get("verified") == "True" else f"unverified: {tls.get('verify_error')}"
        exp = tls.get("days_to_expiry")
        expiry = f" (expires in {exp} days)" if exp else ""
        tls_row = f"<tr><th>TLS</th><td>{e(str(tls.get('protocol') or 'n/a'))} &mdash; {e(state)}{e(expiry)}</td></tr>"
    pages = payload.get("pages_scanned", 1)
    pages_row = f"<tr><th>Pages scanned</th><td>{e(str(pages))}</td></tr>" if pages and pages > 1 else ""
    meta = (
        "<table class='meta'>"
        f"<tr><th>Target</th><td>{target}</td></tr>"
        f"<tr><th>Final URL</th><td>{e(str(payload.get('final_url', '')))}</td></tr>"
        f"<tr><th>HTTP status</th><td>{e(str(payload.get('status_code')))}</td></tr>"
        f"{pages_row}"
        f"{tls_row}"
        f"<tr><th>Scanned at</th><td>{e(str(payload.get('scanned_at', '')))}</td></tr>"
        "</table>"
    )

    # Scorecard rows
    sc = payload.get("scorecard", {})
    rows = []
    for c in sc.get("controls", []):
        st = c["status"]
        sval = "&mdash;" if c["score"] is None else f"{c['score']}/100"
        bar = "" if c["score"] is None else (
            f'<div class="bar"><span style="width:{c["score"]}%;background:{_STATUS_COLORS[st]}"></span></div>'
        )
        rows.append(
            f'<tr class="st-{st}">'
            f'<td class="st"><span class="dot" style="background:{_STATUS_COLORS[st]}"></span>{_STATUS_LABEL[st]}</td>'
            f'<td class="ct"><b>{e(c["title"])}</b><div class="cat">{e(c["category"])}</div>'
            f'<div class="sm">{e(c["summary"])}</div></td>'
            f'<td class="sc">{sval}{bar}</td></tr>'
        )
    scorecard_html = "<table class='score'>" + "".join(rows) + "</table>"

    # Findings
    findings = payload.get("findings", [])
    if findings:
        items = []
        for f in findings:
            sev = f["severity"]
            evidence = (
                f'<div class="evidence"><span>Evidence</span><code>{e(f["evidence"])}</code></div>'
                if f["evidence"] else ""
            )
            page = (
                f'<div class="evidence"><span>Page</span><code>{e(f["page"])}</code></div>'
                if f.get("page") else ""
            )
            items.append(
                f'<article class="finding sev-{sev}">'
                f'<div class="fh"><span class="badge sev-{sev}">{sev.upper()}</span>'
                f'<h3>{e(f["title"])}</h3></div>'
                f'<div class="meta2">{e(f["category"])} &middot; {e(f["id"])}</div>'
                f'<p>{e(f["description"])}</p>{page}{evidence}'
                f'<div class="fix"><span>Recommended fix</span><p>{e(f["recommendation"])}</p></div>'
                f"</article>"
            )
        findings_html = "\n".join(items)
    else:
        findings_html = '<p class="ok">No issues found. All checks passed. ✓</p>'

    body = f"""
      <h1>Security Analyser Report</h1>
      <p class="sub">{target}</p>
      <div class="hero">
        <div class="ring {score_class}">
          <div class="sval">{score}<small>/100</small></div>
          <div class="glabel">GRADE {grade_letter}</div>
        </div>
        <div class="hero-right">
          <div class="tally">
            <span class="t safe">{sc.get('passed', 0)} safe</span>
            <span class="t review">{sc.get('review', 0)} review</span>
            <span class="t unsafe">{sc.get('unsafe', 0)} unsafe</span>
            <span class="t na">{sc.get('not_applicable', 0)} n/a</span>
          </div>
          <div class="cards">{cards}</div>
        </div>
      </div>
      {meta}
      <h2>Scorecard &mdash; every check</h2>
      {scorecard_html}
      <h2>Detailed findings</h2>
      {findings_html}
    """
    return _HTML_TEMPLATE.format(target=target, body=body)


def _score_class(score) -> str:
    if score is None:
        return "s-na"
    if score >= 90:
        return "s-a"
    if score >= 75:
        return "s-b"
    if score >= 60:
        return "s-c"
    if score >= 45:
        return "s-d"
    return "s-f"


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
  .wrap {{ max-width: 920px; margin: 0 auto; padding: 2rem 1.25rem 4rem; }}
  h1 {{ font-size: 1.6rem; margin: 0 0 .25rem; }}
  h2 {{ font-size: 1.15rem; margin: 2rem 0 .8rem; }}
  .sub {{ color: #666; margin: 0 0 1.5rem; word-break: break-all; }}
  .err {{ background: #fde8e8; border: 1px solid #b91c1c; color: #7c1616; padding: 1rem 1.2rem;
          border-radius: 10px; font-weight: 600; }}
  .hero {{ display: flex; gap: 1.5rem; align-items: center; flex-wrap: wrap;
          background: #fff; border-radius: 14px; padding: 1.3rem 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .ring {{ width: 120px; height: 120px; border-radius: 50%; display: grid; place-items: center;
          color: #fff; text-align: center; flex-shrink: 0; }}
  .ring.s-a {{ background: linear-gradient(140deg,#16a34a,#22c55e); }}
  .ring.s-b {{ background: linear-gradient(140deg,#65a30d,#a3b70a); }}
  .ring.s-c {{ background: linear-gradient(140deg,#d6b60a,#e0a020); }}
  .ring.s-d {{ background: linear-gradient(140deg,#e08a1e,#e0662a); }}
  .ring.s-f {{ background: linear-gradient(140deg,#e0483d,#b4232a); }}
  .ring.s-na {{ background: #6b7280; }}
  .sval {{ font-size: 2.3rem; font-weight: 800; line-height: 1; }}
  .sval small {{ font-size: .9rem; font-weight: 600; opacity: .85; }}
  .glabel {{ font-size: .68rem; font-weight: 700; letter-spacing: .1em; margin-top: .2rem; }}
  .hero-right {{ flex: 1; min-width: 240px; }}
  .tally {{ display: flex; gap: .5rem; flex-wrap: wrap; margin-bottom: .8rem; }}
  .tally .t {{ font-size: .78rem; font-weight: 600; padding: .2rem .6rem; border-radius: 999px; }}
  .t.safe {{ background: #dcfce7; color: #15803d; }}
  .t.review {{ background: #fef9c3; color: #a16207; }}
  .t.unsafe {{ background: #fee2e2; color: #b91c1c; }}
  .t.na {{ background: #eef1f4; color: #6b7280; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: .4rem; }}
  .card {{ flex: 1 1 60px; background: #f7f8fa; border-radius: 8px; padding: .5rem; text-align: center;
          border-top: 3px solid #ccc; }}
  .card .count {{ font-size: 1.3rem; font-weight: 700; }}
  .card .label {{ text-transform: uppercase; font-size: .6rem; letter-spacing: .05em; color: #666; }}
  .card.sev-critical {{ border-top-color: #7c1d1d; }} .card.sev-high {{ border-top-color: #b91c1c; }}
  .card.sev-medium {{ border-top-color: #c2660c; }} .card.sev-low {{ border-top-color: #b59105; }}
  .card.sev-info {{ border-top-color: #2563eb; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 10px; overflow: hidden;
          box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  table.meta {{ margin-top: 1.5rem; }}
  .meta th, .meta td {{ text-align: left; padding: .55rem .9rem; border-bottom: 1px solid #eee; font-size: .9rem; }}
  .meta th {{ width: 130px; color: #555; }}
  .score td {{ padding: .7rem .9rem; border-bottom: 1px solid #eee; vertical-align: top; font-size: .9rem; }}
  .score .st {{ width: 90px; font-size: .72rem; font-weight: 700; white-space: nowrap; }}
  .dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: .35rem; }}
  .score .cat {{ color: #888; font-size: .74rem; }}
  .score .sm {{ color: #555; font-size: .82rem; margin-top: .2rem; }}
  .score .sc {{ width: 110px; text-align: right; font-weight: 700; font-size: .85rem; }}
  .bar {{ height: 5px; background: #eee; border-radius: 999px; margin-top: .35rem; overflow: hidden; }}
  .bar span {{ display: block; height: 100%; }}
  .finding {{ background: #fff; border-radius: 10px; padding: 1rem 1.2rem; margin-bottom: .9rem;
          border-left: 5px solid #ccc; box-shadow: 0 1px 3px rgba(0,0,0,.08); }}
  .finding.sev-critical {{ border-left-color: #7c1d1d; }} .finding.sev-high {{ border-left-color: #b91c1c; }}
  .finding.sev-medium {{ border-left-color: #c2660c; }} .finding.sev-low {{ border-left-color: #b59105; }}
  .finding.sev-info {{ border-left-color: #2563eb; }}
  .fh {{ display: flex; align-items: center; gap: .6rem; }}
  .finding h3 {{ margin: 0; font-size: 1.02rem; }}
  .badge {{ font-size: .66rem; font-weight: 700; color: #fff; padding: .15rem .5rem; border-radius: 999px; }}
  .badge.sev-critical {{ background: #7c1d1d; }} .badge.sev-high {{ background: #b91c1c; }}
  .badge.sev-medium {{ background: #c2660c; }} .badge.sev-low {{ background: #b59105; }}
  .badge.sev-info {{ background: #2563eb; }}
  .meta2 {{ color: #888; font-size: .76rem; margin: .25rem 0 .5rem; }}
  .finding p {{ margin: .3rem 0; font-size: .9rem; }}
  .evidence, .fix {{ margin-top: .55rem; font-size: .84rem; }}
  .evidence span, .fix span {{ display: block; text-transform: uppercase; font-size: .66rem;
          letter-spacing: .05em; color: #888; margin-bottom: .2rem; }}
  .evidence code {{ display: block; background: #f6f6f6; padding: .5rem .6rem; border-radius: 6px;
          font-size: .8rem; word-break: break-all; }}
  .fix {{ background: #f3f8f3; border-radius: 6px; padding: .5rem .7rem; }}
  .ok {{ font-size: 1.05rem; color: #15803d; font-weight: 600; }}
  footer {{ margin-top: 2rem; color: #999; font-size: .78rem; text-align: center; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #16181d; color: #e6e6e6; }}
    .hero, table, .finding, .card {{ background: #21242b; box-shadow: none; }}
    .card {{ background: #191c22; }}
    .sub, .meta th, .score .cat {{ color: #9aa0aa; }}
    .meta th, .meta td, .score td {{ border-bottom-color: #2c2f37; }}
    .score .sm {{ color: #b7bdc8; }}
    .evidence code {{ background: #16181d; }} .fix {{ background: #1a241a; }}
    .bar {{ background: #2c2f37; }}
    .t.safe {{ background: #123122; }} .t.review {{ background: #322c12; }}
    .t.unsafe {{ background: #331717; }} .t.na {{ background: #24272e; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  {body}
  <footer>Generated by security-analyser &middot; scorecard covers every check; prioritise unsafe items first.</footer>
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
