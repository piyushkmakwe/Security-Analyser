"""Scorecard / audit layer.

The checks in ``checks.py`` only emit :class:`Finding` objects when something is
wrong. This module turns a :class:`ScanResult` into a full **scorecard** that
lists *every* security control the tool covers — including the ones that passed
— with a "safe / review / unsafe" verdict and a numeric score per control, plus
a weighted overall score (0–100).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from security_analyser.model import ScanContext, ScanResult, Severity

# How much of a control's score survives a finding of each severity.
_SEVERITY_FRACTION: Dict[str, float] = {
    "critical": 0.0,
    "high": 0.25,
    "medium": 0.5,
    "low": 0.75,
    "info": 0.9,
}


@dataclass(frozen=True)
class Control:
    """A single security control shown on the scorecard."""

    key: str
    title: str
    category: str
    weight: int
    ok_text: str
    match: Callable[[str], bool]
    na_text: str = "Not applicable to this target."
    applies: Callable[[ScanContext], bool] = lambda ctx: True


def _prefix(*prefixes: str) -> Callable[[str], bool]:
    return lambda fid: any(fid.startswith(p) for p in prefixes)


def _exact(*ids: str) -> Callable[[str], bool]:
    allowed = set(ids)
    return lambda fid: fid in allowed


# Weights sum to 100, so the overall score reads directly as a percentage when
# every control applies.
CONTROLS: List[Control] = [
    Control("https", "HTTPS enforcement", "Transport security", 12,
            "Served over HTTPS and HTTP redirects to it.",
            _exact("HTTPS-001", "HTTPS-002", "HDR-REDIRECT-DOWNGRADE")),
    Control("tls", "TLS certificate", "Transport security", 12,
            "Certificate is valid, trusted and uses a modern protocol.",
            _prefix("TLS-"), na_text="Only applies to HTTPS sites.",
            applies=lambda ctx: ctx.is_https),
    Control("hsts", "Strict-Transport-Security (HSTS)", "Security headers", 6,
            "HSTS is enabled with a strong max-age.",
            _prefix("HDR-HSTS"),
            na_text="Only applies to HTTPS sites.",
            applies=lambda ctx: ctx.is_https),
    Control("csp", "Content-Security-Policy", "Security headers", 10,
            "A strong Content-Security-Policy is present.",
            _prefix("HDR-CSP")),
    Control("clickjacking", "Clickjacking protection", "Security headers", 7,
            "Framing is restricted (X-Frame-Options / frame-ancestors).",
            _exact("HDR-XFO")),
    Control("mime", "MIME-sniffing protection", "Security headers", 4,
            "X-Content-Type-Options: nosniff is set.",
            _exact("HDR-XCTO")),
    Control("referrer", "Referrer-Policy", "Security headers", 3,
            "A Referrer-Policy is set.", _exact("HDR-REFPOL")),
    Control("permissions", "Permissions-Policy", "Security headers", 2,
            "A Permissions-Policy is set.", _exact("HDR-PERMPOL")),
    Control("cookies", "Cookie security", "Cookies", 9,
            "Cookies use Secure, HttpOnly, SameSite and safe scope.",
            lambda i: i.startswith("COOKIE-") or i == "HDR-CACHE-SESSION",
            na_text="No cookies are set by this page.",
            applies=lambda ctx: bool(ctx.cookies)),
    Control("cors", "CORS configuration", "CORS", 6,
            "No unsafe cross-origin sharing.", _prefix("CORS-")),
    Control("info", "Information disclosure", "Information disclosure", 2,
            "No server/technology version banners leaked.", _prefix("INFO-")),
    Control("integrity", "Content integrity", "Content integrity", 10,
            "No mixed content, missing SRI or insecure forms.",
            _prefix("INTEGRITY-")),
    Control("malware", "Malware / compromise", "Malware / compromise", 12,
            "No signs of injected malware, miners or web shells.",
            _prefix("MALWARE-")),
    Control("secrets", "Secret exposure", "Secret exposure", 17,
            "No API keys or credentials found in page source.",
            _prefix("SECRET-")),
    Control("components", "Outdated components", "Outdated components", 6,
            "No end-of-life software versions disclosed.",
            _prefix("VERSION-")),
    Control("paths", "Sensitive paths & files", "Exposed paths", 8,
            "No exposed .git/.env/backups; security.txt published.",
            _prefix("PATH-"),
            na_text="Path probing was not run (enable it to check).",
            applies=lambda ctx: getattr(ctx, "paths_probed", False)),
    Control("dns", "Email & DNS (SPF/DMARC/CAA)", "DNS & email", 6,
            "SPF, DMARC and CAA records are published.",
            _prefix("DNS-"),
            na_text="DNS checks were not run (enable them to check).",
            applies=lambda ctx: getattr(ctx, "dns_checked", False)),
    Control("active", "Active vulnerabilities", "Active probes", 10,
            "No open redirect or reflected-input issues found.",
            _prefix("ACTIVE-"),
            na_text="Active probing was not run (enable it to check).",
            applies=lambda ctx: getattr(ctx, "active_checked", False)),
]


def _status_for(rank: int) -> str:
    if rank >= Severity.MEDIUM.rank:
        return "unsafe"
    return "review"


def build_scorecard(result: ScanResult) -> dict:
    """Return the full scorecard dict for ``result``."""
    ctx = result.context
    if not ctx.reachable:
        return {
            "applicable": False,
            "overall_score": None,
            "controls": [],
            "passed": 0,
            "review": 0,
            "unsafe": 0,
            "not_applicable": 0,
        }

    findings = result.findings
    controls_out: List[dict] = []
    total_weight = 0.0
    earned = 0.0
    passed = review = unsafe = na = 0

    for control in CONTROLS:
        if not control.applies(ctx):
            na += 1
            controls_out.append({
                "key": control.key, "title": control.title,
                "category": control.category, "status": "n/a",
                "score": None, "weight": control.weight,
                "severity": None, "summary": control.na_text, "findings": [],
            })
            continue

        related = [f for f in findings if control.match(f.id)]
        total_weight += control.weight
        if not related:
            passed += 1
            fraction: float = 1.0
            severity: Optional[str] = None
            status = "safe"
            summary = control.ok_text
        else:
            worst = min(related, key=lambda f: _SEVERITY_FRACTION[f.severity.label])
            severity = worst.severity.label
            fraction = _SEVERITY_FRACTION[severity]
            status = _status_for(worst.severity.rank)
            if status == "unsafe":
                unsafe += 1
            else:
                review += 1
            summary = "; ".join(dict.fromkeys(f.title for f in related))

        earned += control.weight * fraction
        controls_out.append({
            "key": control.key, "title": control.title,
            "category": control.category, "status": status,
            "score": round(fraction * 100), "weight": control.weight,
            "severity": severity, "summary": summary,
            "findings": [f.to_dict() for f in related],
        })

    overall = round(earned / total_weight * 100) if total_weight else 100
    return {
        "applicable": True,
        "overall_score": overall,
        "controls": controls_out,
        "passed": passed,
        "review": review,
        "unsafe": unsafe,
        "not_applicable": na,
    }
