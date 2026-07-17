"""Error-page and debug-mode disclosure probing.

Sends a request to a non-existent path and one with malformed input, then looks
for framework stack traces and debug consoles in the responses. Debug pages
leak source, configuration and internal paths, and often allow code execution.
Requests are ordinary GETs — no destructive input.
"""

from __future__ import annotations

from typing import List
from urllib.parse import urljoin

from security_analyser.fetch import DEFAULT_TIMEOUT, probe_path
from security_analyser.model import Finding, Severity

# (signature, framework/description) — matched case-insensitively.
_DEBUG_SIGNATURES = [
    ("werkzeug debugger", "Flask/Werkzeug interactive debugger"),
    ("traceback (most recent call last)", "Python traceback"),
    ("django.core.exceptions", "Django exception"),
    ("you're seeing this error because you have debug = true", "Django DEBUG=True"),
    ("whoops, looks like something went wrong", "Laravel debug page"),
    ("stack trace:", "stack trace"),
    ("action controller: exception caught", "Ruby on Rails exception"),
    ("rails.application", "Ruby on Rails internals"),
    ("server error in '/' application", "ASP.NET error page"),
    ("microsoft .net framework", ".NET stack trace"),
    ("org.springframework", "Spring stack trace"),
    ("java.lang.", "Java stack trace"),
    ("fatal error: uncaught", "PHP fatal error"),
    ("call stack", "call stack dump"),
]

_BOGUS_PATH = "/sa-error-probe-8e21c7"


def _scan(body: str):
    low = body.lower()
    for sig, desc in _DEBUG_SIGNATURES:
        if sig in low:
            return desc
    return None


def check_error_disclosure(
    base_url: str, timeout: float = DEFAULT_TIMEOUT, verify_tls: bool = True
) -> List[Finding]:
    """Probe for stack traces / debug pages. Returns findings (may be empty)."""
    probes = [
        urljoin(base_url, _BOGUS_PATH),
        # Malformed input often triggers an unhandled exception.
        urljoin(base_url, "/?sa_probe[]=%27%22%3C%3E"),
    ]
    for url in probes:
        res = probe_path(url, timeout, verify_tls)
        if not res:
            continue
        status, _ctype, body = res
        desc = _scan(body)
        if desc:
            severe = "debug" in desc.lower() or "debugger" in desc.lower()
            return [Finding(
                id="INFO-DEBUG" if severe else "INFO-STACKTRACE",
                title=("Debug mode / interactive debugger exposed" if severe
                       else "Stack trace / error details disclosed"),
                severity=Severity.HIGH if severe else Severity.MEDIUM,
                category="Information disclosure",
                description=(
                    f"An error response revealed a {desc}. Stack traces leak source "
                    "paths, library versions and internal logic; an exposed debug "
                    "console can allow remote code execution."
                ),
                recommendation=(
                    "Disable debug mode in production and return generic error pages; "
                    "never expose interactive debuggers publicly."
                ),
                evidence=f"{desc} in response to {url} (HTTP {status})",
            )]
    return []
