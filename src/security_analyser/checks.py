"""Security checks.

Each check is a function that takes a :class:`ScanContext` and returns a list
of :class:`Finding`. All checks are registered in ``ALL_CHECKS`` and run by the
scanner. Adding a new rule is as simple as writing a function and appending it
to that list.
"""

from __future__ import annotations

from typing import Callable, List

from security_analyser.content_checks import CONTENT_CHECKS
from security_analyser.model import Finding, ScanContext, Severity

Check = Callable[[ScanContext], List[Finding]]

# Threshold (in days) below which a certificate is considered "expiring soon".
CERT_EXPIRY_WARN_DAYS = 21


def check_https_enforcement(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    if not ctx.is_https:
        findings.append(
            Finding(
                id="HTTPS-001",
                title="Site is not served over HTTPS",
                severity=Severity.HIGH,
                category="Transport security",
                description=(
                    "The final response was served over plain HTTP. Traffic can be "
                    "read or modified by anyone on the network path, exposing "
                    "credentials, session cookies and page content."
                ),
                recommendation=(
                    "Serve the site exclusively over HTTPS with a valid certificate "
                    "and redirect all HTTP requests to HTTPS."
                ),
                evidence=f"Final URL: {ctx.final_url}",
            )
        )
        return findings

    # HTTPS is in use; check that plain HTTP redirects to it.
    if ctx.http_redirects_to_https is False and ctx.http_reachable_plaintext:
        findings.append(
            Finding(
                id="HTTPS-002",
                title="HTTP does not redirect to HTTPS",
                severity=Severity.MEDIUM,
                category="Transport security",
                description=(
                    "The site answers plain HTTP requests without redirecting to "
                    "HTTPS. Users who type the bare domain may be served insecurely."
                ),
                recommendation=(
                    "Return a 301 redirect from http:// to https:// for all paths, "
                    "and enable HSTS to force future requests over HTTPS."
                ),
                evidence=f"http://{ctx.host}/ served content without redirecting.",
            )
        )
    return findings


def check_hsts(ctx: ScanContext) -> List[Finding]:
    if not ctx.is_https:
        return []
    hsts = ctx.headers.get("Strict-Transport-Security")
    if not hsts:
        return [
            Finding(
                id="HDR-HSTS",
                title="Missing Strict-Transport-Security header",
                severity=Severity.MEDIUM,
                category="Security headers",
                description=(
                    "Without HSTS, browsers will attempt plain HTTP on the first "
                    "visit and can be downgraded by an active attacker."
                ),
                recommendation=(
                    "Add 'Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains' (consider 'preload' once verified)."
                ),
            )
        ]
    findings: List[Finding] = []
    max_age = _hsts_max_age(hsts)
    if max_age is not None and max_age < 15552000:  # < 180 days
        findings.append(
            Finding(
                id="HDR-HSTS-MAXAGE",
                title="Strict-Transport-Security max-age is low",
                severity=Severity.LOW,
                category="Security headers",
                description=(
                    "A short HSTS max-age reduces the protection window against "
                    "protocol-downgrade attacks."
                ),
                recommendation="Use a max-age of at least 31536000 (one year).",
                evidence=f"Strict-Transport-Security: {hsts}",
            )
        )
    return findings


def _hsts_max_age(value: str):
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age"):
            _, _, num = part.partition("=")
            try:
                return int(num.strip())
            except ValueError:
                return None
    return None


def check_csp(ctx: ScanContext) -> List[Finding]:
    csp = ctx.headers.get("Content-Security-Policy")
    if not csp:
        return [
            Finding(
                id="HDR-CSP",
                title="Missing Content-Security-Policy header",
                severity=Severity.MEDIUM,
                category="Security headers",
                description=(
                    "A Content-Security-Policy is a primary defence against "
                    "cross-site scripting (XSS) and data injection. Without it the "
                    "browser will execute any injected script."
                ),
                recommendation=(
                    "Define a restrictive Content-Security-Policy, e.g. "
                    "\"default-src 'self'; object-src 'none'; frame-ancestors 'none'\", "
                    "and tighten it to your application's needs."
                ),
            )
        ]
    findings: List[Finding] = []
    lowered = csp.lower()
    if "unsafe-inline" in lowered or "unsafe-eval" in lowered:
        findings.append(
            Finding(
                id="HDR-CSP-UNSAFE",
                title="Content-Security-Policy allows unsafe inline/eval",
                severity=Severity.LOW,
                category="Security headers",
                description=(
                    "The policy permits 'unsafe-inline' or 'unsafe-eval', which "
                    "substantially weakens its protection against XSS."
                ),
                recommendation=(
                    "Remove 'unsafe-inline'/'unsafe-eval' and adopt nonces or "
                    "hashes for the scripts and styles you need."
                ),
                evidence=f"Content-Security-Policy: {csp}",
            )
        )
    return findings


def check_frame_options(ctx: ScanContext) -> List[Finding]:
    xfo = ctx.headers.get("X-Frame-Options")
    csp = (ctx.headers.get("Content-Security-Policy") or "").lower()
    if xfo or "frame-ancestors" in csp:
        return []
    return [
        Finding(
            id="HDR-XFO",
            title="No clickjacking protection (X-Frame-Options / frame-ancestors)",
            severity=Severity.MEDIUM,
            category="Security headers",
            description=(
                "The page can be embedded in a frame on any origin, allowing "
                "clickjacking attacks that trick users into unintended actions."
            ),
            recommendation=(
                "Send 'X-Frame-Options: DENY' (or SAMEORIGIN) and/or a CSP "
                "'frame-ancestors' directive restricting who may frame the page."
            ),
        )
    ]


def check_content_type_options(ctx: ScanContext) -> List[Finding]:
    value = (ctx.headers.get("X-Content-Type-Options") or "").lower()
    if value == "nosniff":
        return []
    return [
        Finding(
            id="HDR-XCTO",
            title="Missing X-Content-Type-Options: nosniff",
            severity=Severity.LOW,
            category="Security headers",
            description=(
                "Without 'nosniff', browsers may MIME-sniff responses and "
                "interpret them as a different content type, enabling some XSS "
                "and drive-by download attacks."
            ),
            recommendation="Add the header 'X-Content-Type-Options: nosniff'.",
        )
    ]


def check_referrer_policy(ctx: ScanContext) -> List[Finding]:
    if ctx.headers.has("Referrer-Policy"):
        return []
    return [
        Finding(
            id="HDR-REFPOL",
            title="Missing Referrer-Policy header",
            severity=Severity.LOW,
            category="Security headers",
            description=(
                "Without an explicit Referrer-Policy, full URLs (which may contain "
                "sensitive tokens or identifiers) can leak to third-party sites via "
                "the Referer header."
            ),
            recommendation=(
                "Add 'Referrer-Policy: strict-origin-when-cross-origin' "
                "(or 'no-referrer')."
            ),
        )
    ]


def check_permissions_policy(ctx: ScanContext) -> List[Finding]:
    if ctx.headers.has("Permissions-Policy") or ctx.headers.has("Feature-Policy"):
        return []
    return [
        Finding(
            id="HDR-PERMPOL",
            title="Missing Permissions-Policy header",
            severity=Severity.INFO,
            category="Security headers",
            description=(
                "A Permissions-Policy lets you disable powerful browser features "
                "(camera, microphone, geolocation, etc.) that the site does not use."
            ),
            recommendation=(
                "Add a Permissions-Policy disabling features you do not need, "
                "e.g. 'geolocation=(), camera=(), microphone=()'."
            ),
        )
    ]


def check_cookies(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    for cookie in ctx.cookies:
        label = cookie.name or "(unnamed)"
        if ctx.is_https and not cookie.secure:
            findings.append(
                Finding(
                    id="COOKIE-SECURE",
                    title=f"Cookie '{label}' missing Secure attribute",
                    severity=Severity.MEDIUM,
                    category="Cookies",
                    description=(
                        "A cookie without the Secure attribute can be transmitted "
                        "over plain HTTP and intercepted."
                    ),
                    recommendation="Set the 'Secure' attribute on the cookie.",
                    evidence=cookie.raw,
                )
            )
        if not cookie.http_only:
            findings.append(
                Finding(
                    id="COOKIE-HTTPONLY",
                    title=f"Cookie '{label}' missing HttpOnly attribute",
                    severity=Severity.MEDIUM,
                    category="Cookies",
                    description=(
                        "Without HttpOnly, the cookie is readable by JavaScript, so "
                        "an XSS flaw can steal it (e.g. a session token)."
                    ),
                    recommendation="Set the 'HttpOnly' attribute on the cookie.",
                    evidence=cookie.raw,
                )
            )
        if not cookie.same_site:
            findings.append(
                Finding(
                    id="COOKIE-SAMESITE",
                    title=f"Cookie '{label}' missing SameSite attribute",
                    severity=Severity.LOW,
                    category="Cookies",
                    description=(
                        "Without an explicit SameSite attribute the cookie may be "
                        "sent on cross-site requests, aiding CSRF."
                    ),
                    recommendation="Set 'SameSite=Lax' (or 'Strict') on the cookie.",
                    evidence=cookie.raw,
                )
            )
    return findings


def check_information_disclosure(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    server = ctx.headers.get("Server")
    if server and any(ch.isdigit() for ch in server):
        findings.append(
            Finding(
                id="INFO-SERVER",
                title="Server header discloses software version",
                severity=Severity.LOW,
                category="Information disclosure",
                description=(
                    "The Server header reveals the server software and version, "
                    "helping attackers target known vulnerabilities."
                ),
                recommendation="Remove version details from the Server header.",
                evidence=f"Server: {server}",
            )
        )
    for header in ("X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"):
        value = ctx.headers.get(header)
        if value:
            findings.append(
                Finding(
                    id="INFO-POWEREDBY",
                    title=f"{header} header discloses technology stack",
                    severity=Severity.LOW,
                    category="Information disclosure",
                    description=(
                        "This header advertises the underlying technology and "
                        "version, aiding reconnaissance."
                    ),
                    recommendation=f"Remove the '{header}' response header.",
                    evidence=f"{header}: {value}",
                )
            )
    return findings


def check_cors(ctx: ScanContext) -> List[Finding]:
    acao = ctx.headers.get("Access-Control-Allow-Origin")
    if not acao:
        return []
    creds = (ctx.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
    if acao.strip() == "*" and creds:
        return [
            Finding(
                id="CORS-WILDCARD-CREDS",
                title="CORS allows any origin together with credentials",
                severity=Severity.HIGH,
                category="CORS",
                description=(
                    "Access-Control-Allow-Origin '*' combined with "
                    "Allow-Credentials 'true' lets any site make authenticated "
                    "cross-origin requests and read the responses."
                ),
                recommendation=(
                    "Reflect only an explicit allow-list of trusted origins, and "
                    "never combine a wildcard origin with credentials."
                ),
                evidence=f"Access-Control-Allow-Origin: {acao}; credentials=true",
            )
        ]
    if acao.strip() == "*":
        return [
            Finding(
                id="CORS-WILDCARD",
                title="CORS allows any origin",
                severity=Severity.LOW,
                category="CORS",
                description=(
                    "Access-Control-Allow-Origin '*' exposes responses to scripts "
                    "on any origin. This is acceptable for public data but risky for "
                    "anything user-specific."
                ),
                recommendation=(
                    "Restrict Access-Control-Allow-Origin to the specific origins "
                    "that need cross-origin access."
                ),
                evidence=f"Access-Control-Allow-Origin: {acao}",
            )
        ]
    return []


def check_tls_certificate(ctx: ScanContext) -> List[Finding]:
    if not ctx.is_https or ctx.tls is None:
        return []
    tls = ctx.tls
    findings: List[Finding] = []
    if tls.connected and not tls.verified:
        findings.append(
            Finding(
                id="TLS-INVALID",
                title="TLS certificate failed validation",
                severity=Severity.HIGH,
                category="Transport security",
                description=(
                    "The server's certificate could not be verified (expired, "
                    "self-signed, wrong hostname, or untrusted issuer). Browsers "
                    "will warn users and the connection is not trustworthy."
                ),
                recommendation=(
                    "Install a certificate from a trusted CA that matches the "
                    "hostname and is within its validity period."
                ),
                evidence=tls.verify_error or "verification failed",
            )
        )
    elif tls.verified and tls.days_to_expiry is not None:
        if tls.days_to_expiry < 0:
            findings.append(
                Finding(
                    id="TLS-EXPIRED",
                    title="TLS certificate has expired",
                    severity=Severity.HIGH,
                    category="Transport security",
                    description="The server's TLS certificate is past its expiry date.",
                    recommendation="Renew and install a current TLS certificate.",
                    evidence=f"Expired on {tls.not_after}",
                )
            )
        elif tls.days_to_expiry <= CERT_EXPIRY_WARN_DAYS:
            findings.append(
                Finding(
                    id="TLS-EXPIRING",
                    title="TLS certificate expires soon",
                    severity=Severity.MEDIUM,
                    category="Transport security",
                    description=(
                        f"The TLS certificate expires in {tls.days_to_expiry} day(s). "
                        "An expired certificate causes browser errors and outages."
                    ),
                    recommendation="Renew the certificate and automate future renewals.",
                    evidence=f"Expires on {tls.not_after}",
                )
            )
    if tls.protocol and tls.protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        findings.append(
            Finding(
                id="TLS-PROTOCOL",
                title=f"Weak TLS protocol negotiated ({tls.protocol})",
                severity=Severity.MEDIUM,
                category="Transport security",
                description=(
                    "The server negotiated an outdated TLS/SSL protocol version "
                    "with known weaknesses."
                ),
                recommendation="Disable TLS 1.1 and below; require TLS 1.2 or 1.3.",
                evidence=f"Negotiated protocol: {tls.protocol}",
            )
        )
    return findings


ALL_CHECKS: List[Check] = [
    check_https_enforcement,
    check_tls_certificate,
    check_hsts,
    check_csp,
    check_frame_options,
    check_content_type_options,
    check_referrer_policy,
    check_permissions_policy,
    check_cookies,
    check_information_disclosure,
    check_cors,
    *CONTENT_CHECKS,
]


def run_checks(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(ctx))
    return findings
