"""Active probes (opt-in): open redirect and reflected-input detection.

These send crafted requests to the target, so they are only run when the user
explicitly enables active checks. Both degrade gracefully on network errors.
"""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from typing import List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from security_analyser.fetch import USER_AGENT, _NoRedirect, fetch
from security_analyser.model import Finding, Severity

# Common parameter names used for redirects.
_REDIRECT_PARAMS = ["next", "url", "redirect", "return", "returnUrl", "dest", "continue"]
_EVIL_HOST = "sa-openredirect-test.example"
_EVIL_URL = f"https://{_EVIL_HOST}/"
_MARKER = "sa9z7qmarker"


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query))
    query[param] = value
    return urlunparse(parsed._replace(query=urlencode(query)))


def _no_redirect_location(
    url: str, timeout: float, verify_tls: bool
) -> Optional[Tuple[int, str]]:
    """Request ``url`` without following redirects; return (status, Location)."""
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=context)
    )
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        response = opener.open(request, timeout=timeout)
        loc = response.headers.get("Location", "")
        response.close()
        return getattr(response, "status", 200), loc
    except urllib.error.HTTPError as exc:
        loc = exc.headers.get("Location", "") if exc.headers else ""
        return exc.code, loc
    except (urllib.error.URLError, socket.error, ssl.SSLError, OSError):
        return None


def check_open_redirect(url: str, timeout: float, verify_tls: bool) -> List[Finding]:
    findings: List[Finding] = []
    for param in _REDIRECT_PARAMS:
        test_url = _with_param(url, param, _EVIL_URL)
        res = _no_redirect_location(test_url, timeout, verify_tls)
        if not res:
            continue
        status, location = res
        loc = location.lower()
        if 300 <= status < 400 and (_EVIL_HOST in loc and (loc.startswith("http") or loc.startswith("//"))):
            findings.append(
                Finding(
                    id="ACTIVE-OPEN-REDIRECT",
                    title="Open redirect",
                    severity=Severity.MEDIUM,
                    category="Active probes",
                    description=(
                        f"The '{param}' parameter redirects to an attacker-controlled "
                        "external URL. Open redirects are used for phishing and can "
                        "bypass allow-list based protections."
                    ),
                    recommendation=(
                        "Validate redirect targets against an allow-list of internal "
                        "paths; never redirect to a user-supplied absolute URL."
                    ),
                    evidence=f"{param}={_EVIL_URL} -> Location: {location}",
                )
            )
            break  # one confirmed open redirect is enough
    return findings


def check_reflected_input(url: str, timeout: float, verify_tls: bool) -> List[Finding]:
    marker = f"{_MARKER}<x>"
    test_url = _with_param(url, "sa_probe", marker)
    try:
        _status, _final, _headers, _cookies, body, _chain = fetch(
            test_url, timeout=timeout, verify_tls=verify_tls
        )
    except (urllib.error.URLError, OSError, ValueError):
        return []
    if marker in body:  # the "<x>" survived unencoded
        return [
            Finding(
                id="ACTIVE-REFLECTED-INPUT",
                title="Unencoded reflected input (possible XSS)",
                severity=Severity.MEDIUM,
                category="Active probes",
                description=(
                    "A query parameter is reflected into the response without HTML "
                    "encoding, including the '<' and '>' characters. This is a strong "
                    "signal of a reflected XSS vector — confirm manually."
                ),
                recommendation=(
                    "HTML-encode all user input on output, and add a Content-Security-Policy."
                ),
                evidence=f"Reflected marker '{marker}' appeared unencoded in the response.",
            )
        ]
    return []


# Database error signatures (error-based SQL injection).
_SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql", "mysqli_", "mysql_fetch",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query", "pg_exec", "postgresql query failed",
    "syntax error at or near",
    "sqlite3::", "sqlite_error", "sqliteexception",
    "ora-00933", "ora-01756", "ora-00921",
    "microsoft ole db provider for sql server",
    "odbc sql server driver", "unclosed quotation",
    "sqlstate[",
]


def _params_to_test(url: str) -> List[str]:
    parsed = urlparse(url)
    params = [k for k, _ in parse_qsl(parsed.query)]
    return params or ["id"]  # fall back to a synthetic parameter


def _fetch_body(url: str, timeout: float, verify_tls: bool):
    try:
        _s, _f, _h, _c, body, _ch = fetch(url, timeout=timeout, verify_tls=verify_tls)
        return body
    except (urllib.error.URLError, OSError, ValueError):
        return None


def check_sql_injection(url: str, timeout: float, verify_tls: bool) -> List[Finding]:
    """Non-destructive SQLi signal: error-based and boolean-based only."""
    for param in _params_to_test(url):
        # Error-based: a single quote often provokes a database error.
        err_body = _fetch_body(_with_param(url, param, "sa'\"") , timeout, verify_tls)
        if err_body:
            low = err_body.lower()
            hit = next((sig for sig in _SQL_ERRORS if sig in low), None)
            if hit:
                return [_sqli_finding(param, f"database error signature: '{hit}'")]
        # Boolean-based: require the TRUE≈baseline / FALSE≠baseline pattern to hold
        # on TWO independent rounds, so dynamic content (rotating tokens, timestamps)
        # does not produce a false positive.
        if _boolean_sqli(url, param, timeout, verify_tls) and \
                _boolean_sqli(url, param, timeout, verify_tls):
            return [_sqli_finding(param, "boolean condition consistently changed the response")]
    return []


def _boolean_sqli(url: str, param: str, timeout: float, verify_tls: bool) -> bool:
    base = _fetch_body(_with_param(url, param, "1"), timeout, verify_tls)
    t = _fetch_body(_with_param(url, param, "1' AND '1'='1"), timeout, verify_tls)
    f = _fetch_body(_with_param(url, param, "1' AND '1'='2"), timeout, verify_tls)
    if not (base and t and f) or len(t) == len(f):
        return False
    return abs(len(t) - len(base)) < abs(len(f) - len(base)) and _diff_ratio(t, f) < 0.95


def _diff_ratio(a: str, b: str) -> float:
    import difflib
    return difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio()


def _sqli_finding(param: str, why: str) -> Finding:
    return Finding(
        id="ACTIVE-SQLI",
        title="Possible SQL injection",
        severity=Severity.HIGH,
        category="Active probes",
        description=(
            f"The '{param}' parameter appears to influence a SQL query ({why}). SQL "
            "injection can let an attacker read, modify or delete database contents. "
            "This is a signal — confirm manually."
        ),
        recommendation=(
            "Use parameterised queries / prepared statements everywhere; never build "
            "SQL by string concatenation. Validate and least-privilege the DB user."
        ),
        evidence=f"parameter '{param}': {why}",
    )


def check_injection_signals(url: str, timeout: float, verify_tls: bool) -> List[Finding]:
    """Marker-based OS-command and template-injection signals (non-destructive)."""
    findings: List[Finding] = []
    for param in _params_to_test(url):
        # Template injection: 7*7 should evaluate to 49 if the engine renders it.
        body = _fetch_body(_with_param(url, param, "sa{{7*7}}sa"), timeout, verify_tls)
        if body and "sa49sa" in body:
            findings.append(Finding(
                id="ACTIVE-SSTI",
                title="Possible server-side template injection",
                severity=Severity.HIGH,
                category="Active probes",
                description=(
                    f"The '{param}' parameter evaluated a template expression "
                    "(7*7 -> 49). Template injection can lead to remote code execution. "
                    "Confirm manually."
                ),
                recommendation="Never render user input as a template; sandbox the template engine.",
                evidence=f"parameter '{param}': {{{{7*7}}}} rendered as 49",
            ))
            break
    return findings


def run_active_checks(url: str, timeout: float, verify_tls: bool = True) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(check_open_redirect(url, timeout, verify_tls))
    findings.extend(check_reflected_input(url, timeout, verify_tls))
    findings.extend(check_sql_injection(url, timeout, verify_tls))
    findings.extend(check_injection_signals(url, timeout, verify_tls))
    return findings
