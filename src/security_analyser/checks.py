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
    lowered = hsts.lower()
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
    if "includesubdomains" not in lowered:
        findings.append(
            Finding(
                id="HDR-HSTS-SUBDOMAINS",
                title="HSTS does not cover subdomains",
                severity=Severity.LOW,
                category="Security headers",
                description=(
                    "Without 'includeSubDomains', subdomains are not protected by "
                    "HSTS and can still be reached over plain HTTP."
                ),
                recommendation="Add 'includeSubDomains' to the HSTS header once all "
                "subdomains support HTTPS.",
                evidence=f"Strict-Transport-Security: {hsts}",
            )
        )
    elif "preload" not in lowered and (max_age or 0) >= 31536000:
        findings.append(
            Finding(
                id="HDR-HSTS-PRELOAD",
                title="HSTS is preload-eligible but not marked 'preload'",
                severity=Severity.INFO,
                category="Security headers",
                description=(
                    "The HSTS policy meets preload requirements but lacks the "
                    "'preload' token, so browsers will not ship it pre-trusted."
                ),
                recommendation="Add 'preload' and submit the domain at hstspreload.org.",
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
    directives = _csp_directives(csp)
    default_src = directives.get("default-src", "")
    # Wildcard sources in script/default weaken the policy substantially.
    if any(src.strip() == "*" for src in (directives.get("script-src") or default_src).split()):
        findings.append(
            Finding(
                id="HDR-CSP-WILDCARD",
                title="Content-Security-Policy uses a wildcard script source",
                severity=Severity.LOW,
                category="Security headers",
                description=(
                    "A '*' source allows scripts to load from any origin, largely "
                    "defeating the policy's XSS protection."
                ),
                recommendation="Replace '*' with an explicit allow-list of trusted origins.",
                evidence=f"Content-Security-Policy: {csp}",
            )
        )
    if "http:" in lowered:
        findings.append(
            Finding(
                id="HDR-CSP-HTTP",
                title="Content-Security-Policy allows insecure http: sources",
                severity=Severity.LOW,
                category="Security headers",
                description=(
                    "The policy permits resources over plain 'http:', which can be "
                    "tampered with in transit."
                ),
                recommendation="Use 'https:' sources only in the CSP.",
                evidence=f"Content-Security-Policy: {csp}",
            )
        )
    # object-src/base-uri are NOT covered by default-src, so check explicitly.
    missing = [d for d in ("object-src", "base-uri") if d not in directives]
    if missing:
        findings.append(
            Finding(
                id="HDR-CSP-DIRECTIVES",
                title=f"Content-Security-Policy missing {', '.join(missing)}",
                severity=Severity.INFO,
                category="Security headers",
                description=(
                    "'object-src' and 'base-uri' are not governed by 'default-src'. "
                    "Omitting them leaves plugin and <base> injection vectors open."
                ),
                recommendation="Add \"object-src 'none'\" and \"base-uri 'self'\" to the policy.",
                evidence=f"Content-Security-Policy: {csp}",
            )
        )
    return findings


def _csp_directives(csp: str) -> dict:
    result = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        name, _, value = part.partition(" ")
        result[name.strip().lower()] = value.strip().lower()
    return result


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
        if cookie.name.startswith("__Host-"):
            # __Host- prefix requires Secure, Path=/, and NO Domain attribute.
            if not cookie.secure or cookie.domain or (cookie.path or "/") != "/":
                findings.append(
                    Finding(
                        id="COOKIE-HOST-PREFIX",
                        title=f"Cookie '{label}' violates its __Host- prefix rules",
                        severity=Severity.LOW,
                        category="Cookies",
                        description=(
                            "A '__Host-' cookie must be Secure, have Path=/, and set "
                            "no Domain. This one does not, so browsers reject the "
                            "guarantee the prefix is meant to provide."
                        ),
                        recommendation="Set Secure and Path=/ and remove the Domain attribute.",
                        evidence=cookie.raw,
                    )
                )
        elif cookie.name.startswith("__Secure-") and not cookie.secure:
            findings.append(
                Finding(
                    id="COOKIE-SECURE-PREFIX",
                    title=f"Cookie '{label}' has __Secure- prefix without Secure",
                    severity=Severity.LOW,
                    category="Cookies",
                    description=(
                        "A '__Secure-' cookie must carry the Secure attribute; without "
                        "it browsers reject the cookie."
                    ),
                    recommendation="Set the 'Secure' attribute on the cookie.",
                    evidence=cookie.raw,
                )
            )
        if cookie.domain and cookie.domain.startswith("."):
            findings.append(
                Finding(
                    id="COOKIE-DOMAIN-SCOPE",
                    title=f"Cookie '{label}' is scoped to a wildcard parent domain",
                    severity=Severity.INFO,
                    category="Cookies",
                    description=(
                        "A leading-dot Domain shares the cookie with every subdomain, "
                        "widening its exposure. Prefer host-only cookies where possible."
                    ),
                    recommendation="Drop the Domain attribute unless subdomains truly need the cookie.",
                    evidence=cookie.raw,
                )
            )
    return findings


def check_cache_control(ctx: ScanContext) -> List[Finding]:
    """Flag pages that set a session cookie but allow caching of the response."""
    if not ctx.cookies:
        return []
    cache = (ctx.headers.get("Cache-Control") or "").lower()
    if "no-store" in cache or "private" in cache:
        return []
    return [
        Finding(
            id="HDR-CACHE-SESSION",
            title="Response sets a cookie but is cacheable",
            severity=Severity.LOW,
            category="Security headers",
            description=(
                "The response sets cookies without 'Cache-Control: no-store' (or "
                "'private'). Shared caches or the browser may store authenticated "
                "content and serve it to another user."
            ),
            recommendation="Send 'Cache-Control: no-store' on responses that set session cookies.",
            evidence=f"Cache-Control: {ctx.headers.get('Cache-Control') or '(absent)'}",
        )
    ]


def check_redirect_hygiene(ctx: ScanContext) -> List[Finding]:
    """Flag redirect chains that pass through cleartext http://."""
    chain = ctx.redirect_chain or []
    if len(chain) < 2:
        return []
    # Ignore the first hop if the user typed http:// themselves; flag any http
    # hop that occurs *after* an https hop (a downgrade in the chain).
    seen_https = False
    downgrade = False
    for url in chain:
        if url.lower().startswith("https://"):
            seen_https = True
        elif url.lower().startswith("http://") and seen_https:
            downgrade = True
    if not downgrade:
        return []
    return [
        Finding(
            id="HDR-REDIRECT-DOWNGRADE",
            title="Redirect chain drops back to plain HTTP",
            severity=Severity.MEDIUM,
            category="Transport security",
            description=(
                "The redirect chain moves from HTTPS back to HTTP at some point, "
                "exposing the request to interception during that hop."
            ),
            recommendation="Ensure every redirect target uses https:// end to end.",
            evidence=" -> ".join(chain[:5]),
        )
    ]


# Known-old version signatures -> a heuristic "review for CVEs" hint. This is a
# lightweight signal, NOT a live CVE feed.
_OUTDATED_SIGNATURES = [
    ("openssl/1.0", "OpenSSL 1.0.x is end-of-life and has known CVEs."),
    ("php/5.", "PHP 5.x is end-of-life."),
    ("php/7.0", "PHP 7.0 is end-of-life."),
    ("php/7.1", "PHP 7.1 is end-of-life."),
    ("php/7.2", "PHP 7.2 is end-of-life."),
    ("apache/2.2", "Apache httpd 2.2 is end-of-life."),
    ("nginx/1.0", "This nginx release line is very old."),
    ("nginx/1.1", "This nginx release line is very old."),
    ("openssh_5", "OpenSSH 5.x is very old."),
    ("openssh_6", "OpenSSH 6.x is very old."),
    ("jquery/1.", "jQuery 1.x has known XSS CVEs; upgrade to 3.x."),
    ("jquery/2.", "jQuery 2.x is unmaintained; upgrade to 3.x."),
]


def check_outdated_versions(ctx: ScanContext) -> List[Finding]:
    """Heuristic: flag disclosed software versions that are known to be old."""
    haystack = " ".join(
        v for v in (
            ctx.headers.get("Server"),
            ctx.headers.get("X-Powered-By"),
            ctx.headers.get("X-AspNet-Version"),
        ) if v
    ).lower()
    # jQuery version often appears in script URLs in the body.
    body_l = (ctx.body or "").lower()
    findings: List[Finding] = []
    seen = set()
    for needle, note in _OUTDATED_SIGNATURES:
        hit = needle in haystack or (needle.startswith("jquery") and needle.replace("/", "-") in body_l) \
            or (needle.startswith("jquery") and needle in body_l)
        if hit and needle not in seen:
            seen.add(needle)
            findings.append(
                Finding(
                    id="VERSION-OUTDATED",
                    title="Outdated software version disclosed",
                    severity=Severity.MEDIUM,
                    category="Outdated components",
                    description=(
                        f"{note} Outdated components frequently carry publicly known "
                        "vulnerabilities (CVEs). This is a heuristic signal — verify "
                        "the exact version and its advisories."
                    ),
                    recommendation="Upgrade to a supported version and re-check advisories.",
                    evidence=note,
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


_WEAK_CIPHER_TOKENS = ("RC4", "3DES", "DES-", "NULL", "EXPORT", "MD5", "ANON")


def check_tls_deep(ctx: ScanContext) -> List[Finding]:
    """Protocol-enumeration and cipher-strength checks (reliability additions)."""
    if not ctx.is_https or ctx.tls is None or not ctx.tls.connected:
        return []
    tls = ctx.tls
    findings: List[Finding] = []
    legacy = [p for p in tls.supported_protocols if p in ("TLSv1", "TLSv1.1")]
    if legacy:
        findings.append(Finding(
            id="TLS-PROTO-OLD",
            title=f"Legacy TLS protocol supported: {', '.join(legacy)}",
            severity=Severity.MEDIUM,
            category="Transport security",
            description=(
                "The server still accepts an outdated TLS version even if it prefers a "
                "modern one. These versions (TLS 1.0/1.1) have known weaknesses and are "
                "disallowed by PCI DSS and modern browsers."
            ),
            recommendation="Disable TLS 1.0 and 1.1 at the server; require TLS 1.2+ (ideally 1.3).",
            evidence=f"Supported: {', '.join(tls.supported_protocols)}",
        ))
    if tls.cipher_name and (
        any(tok in tls.cipher_name.upper() for tok in _WEAK_CIPHER_TOKENS)
        or (tls.cipher_bits is not None and tls.cipher_bits < 128)
    ):
        findings.append(Finding(
            id="TLS-CIPHER-WEAK",
            title=f"Weak TLS cipher negotiated ({tls.cipher_name})",
            severity=Severity.MEDIUM,
            category="Transport security",
            description=(
                "The negotiated cipher suite is weak (legacy algorithm or < 128-bit), "
                "which can allow decryption of intercepted traffic."
            ),
            recommendation="Configure a modern cipher suite list (AEAD ciphers, forward secrecy).",
            evidence=f"Cipher: {tls.cipher_name} ({tls.cipher_bits} bits)",
        ))
    return findings


def check_cross_origin_isolation(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    if not ctx.headers.has("Cross-Origin-Opener-Policy"):
        findings.append(Finding(
            id="HDR-ISOLATION-COOP",
            title="Missing Cross-Origin-Opener-Policy",
            severity=Severity.LOW,
            category="Security headers",
            description=(
                "Without COOP, a cross-origin window opener keeps a reference to your "
                "page, enabling cross-window attacks and blocking Spectre isolation."
            ),
            recommendation="Add 'Cross-Origin-Opener-Policy: same-origin'.",
        ))
    if not ctx.headers.has("Cross-Origin-Resource-Policy"):
        findings.append(Finding(
            id="HDR-ISOLATION-CORP",
            title="Missing Cross-Origin-Resource-Policy",
            severity=Severity.INFO,
            category="Security headers",
            description=(
                "CORP lets you stop other origins from embedding your resources, "
                "mitigating side-channel (Spectre) leaks."
            ),
            recommendation="Add 'Cross-Origin-Resource-Policy: same-origin' (or same-site).",
        ))
    if not ctx.headers.has("X-Permitted-Cross-Domain-Policies"):
        findings.append(Finding(
            id="HDR-ISOLATION-XPCDP",
            title="Missing X-Permitted-Cross-Domain-Policies",
            severity=Severity.INFO,
            category="Security headers",
            description=(
                "Without this header, legacy Flash/PDF clients may load cross-domain "
                "policy files and broaden your attack surface."
            ),
            recommendation="Add 'X-Permitted-Cross-Domain-Policies: none'.",
        ))
    return findings


def check_http_methods(ctx: ScanContext) -> List[Finding]:
    dangerous = {"PUT", "DELETE", "TRACE", "TRACK", "CONNECT", "PATCH"}
    present = sorted(dangerous & set(ctx.allowed_methods))
    if not present:
        return []
    sev = Severity.MEDIUM if ({"PUT", "DELETE", "TRACE", "TRACK"} & set(present)) else Severity.LOW
    return [Finding(
        id="HDR-METHODS",
        title=f"Dangerous HTTP methods enabled: {', '.join(present)}",
        severity=sev,
        category="Security headers",
        description=(
            "The server advertises risky HTTP methods. TRACE/TRACK enable "
            "cross-site tracing; PUT/DELETE may allow unauthorised file changes."
        ),
        recommendation="Disable methods the application does not need; restrict PUT/DELETE.",
        evidence=f"Allow: {', '.join(ctx.allowed_methods)}",
    )]


def check_cors_reflection(ctx: ScanContext) -> List[Finding]:
    if not ctx.cors_reflects_origin:
        return []
    if ctx.cors_reflect_with_credentials:
        return [Finding(
            id="CORS-REFLECT-CREDS",
            title="CORS reflects arbitrary origin with credentials",
            severity=Severity.HIGH,
            category="CORS",
            description=(
                "The server echoes any Origin into Access-Control-Allow-Origin and "
                "allows credentials, so any website can make authenticated requests "
                "and read a logged-in user's data."
            ),
            recommendation="Reflect only an allow-list of trusted origins; never combine reflection with credentials.",
            evidence="Reflected probe Origin with Access-Control-Allow-Credentials: true",
        )]
    return [Finding(
        id="CORS-REFLECT",
        title="CORS reflects arbitrary origins",
        severity=Severity.LOW,
        category="CORS",
        description=(
            "The server echoes any Origin into Access-Control-Allow-Origin, exposing "
            "responses to any site. Risky for anything user-specific."
        ),
        recommendation="Restrict Access-Control-Allow-Origin to specific trusted origins.",
        evidence="Reflected the probe Origin header",
    )]


ALL_CHECKS: List[Check] = [
    check_https_enforcement,
    check_tls_certificate,
    check_tls_deep,
    check_hsts,
    check_csp,
    check_frame_options,
    check_content_type_options,
    check_referrer_policy,
    check_permissions_policy,
    check_cross_origin_isolation,
    check_http_methods,
    check_cookies,
    check_cache_control,
    check_redirect_hygiene,
    check_information_disclosure,
    check_outdated_versions,
    check_cors,
    check_cors_reflection,
    *CONTENT_CHECKS,
]


def run_checks(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(ctx))
    return findings
