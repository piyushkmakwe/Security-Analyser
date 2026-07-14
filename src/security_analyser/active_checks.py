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


def run_active_checks(url: str, timeout: float, verify_tls: bool = True) -> List[Finding]:
    findings: List[Finding] = []
    findings.extend(check_open_redirect(url, timeout, verify_tls))
    findings.extend(check_reflected_input(url, timeout, verify_tls))
    return findings
