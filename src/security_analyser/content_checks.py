"""Checks that inspect the served response body (HTML/JavaScript).

Two families of checks live here:

* **Content integrity** — can the page's data/resources be altered in transit?
  (mixed content, missing Subresource Integrity, insecure form actions)
* **Secret exposure** — is an API key or credential extractable from what the
  server ships to the browser? Anything in the response body is visible to any
  visitor, so a secret there is effectively public.

Reported secrets are always **redacted** so the report itself never leaks them.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Dict, List, Tuple
from urllib.parse import urlparse

from security_analyser.model import Finding, ScanContext, Severity

# Tags whose external resource, if loaded over HTTP, can actively alter the page.
_ACTIVE_TAGS = {"script", "iframe", "object", "embed", "link"}
_RESOURCE_TAGS = _ACTIVE_TAGS | {"img", "audio", "video", "source"}


class _TagCollector(HTMLParser):
    """Collect (tag, attrs) tuples for the tags we care about."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: List[Tuple[str, Dict[str, str]]] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in _RESOURCE_TAGS or tag == "form":
            self.tags.append((tag, {k.lower(): (v or "") for k, v in attrs}))

    handle_startendtag = handle_starttag


def _collect_tags(body: str) -> List[Tuple[str, Dict[str, str]]]:
    parser = _TagCollector()
    try:
        parser.feed(body)
    except Exception:  # pragma: no cover - tolerate malformed HTML
        pass
    return parser.tags


def check_mixed_content(ctx: ScanContext) -> List[Finding]:
    if not ctx.is_https or not ctx.body:
        return []
    active: List[str] = []
    passive: List[str] = []
    for tag, attrs in _collect_tags(ctx.body):
        url = attrs.get("src") or attrs.get("href") or attrs.get("data") or ""
        if not url.lower().startswith("http://"):
            continue
        # A <link> only loads active content when it is a stylesheet.
        if tag == "link" and "stylesheet" not in attrs.get("rel", "").lower():
            passive.append(f"<{tag}> {url}")
        elif tag in _ACTIVE_TAGS:
            active.append(f"<{tag}> {url}")
        else:
            passive.append(f"<{tag}> {url}")

    findings: List[Finding] = []
    if active:
        findings.append(
            Finding(
                id="INTEGRITY-MIXED-ACTIVE",
                title="Active mixed content loaded over HTTP",
                severity=Severity.HIGH,
                category="Content integrity",
                description=(
                    "This HTTPS page loads active resources (scripts, stylesheets, "
                    "iframes) over plain HTTP. A network attacker can modify those "
                    "responses in transit and alter — or fully take over — the page."
                ),
                recommendation=(
                    "Load every subresource over HTTPS, and add "
                    "'upgrade-insecure-requests' to your Content-Security-Policy."
                ),
                evidence=f"{len(active)} resource(s): " + "; ".join(active[:3]),
            )
        )
    if passive:
        findings.append(
            Finding(
                id="INTEGRITY-MIXED-PASSIVE",
                title="Passive mixed content loaded over HTTP",
                severity=Severity.LOW,
                category="Content integrity",
                description=(
                    "This HTTPS page loads images or media over plain HTTP. These can "
                    "be swapped by a network attacker and cause the browser to drop "
                    "the secure-connection indicator."
                ),
                recommendation="Serve all images and media over HTTPS.",
                evidence=f"{len(passive)} resource(s): " + "; ".join(passive[:3]),
            )
        )
    return findings


def check_subresource_integrity(ctx: ScanContext) -> List[Finding]:
    if not ctx.body:
        return []
    host = (ctx.host or "").lower()
    missing: List[str] = []
    for tag, attrs in _collect_tags(ctx.body):
        if tag != "script":
            continue
        src = attrs.get("src", "")
        if not src.lower().startswith(("http://", "https://")):
            continue  # inline or same-origin relative script
        src_host = (urlparse(src).hostname or "").lower()
        if src_host and src_host != host and "integrity" not in attrs:
            missing.append(src)
    if not missing:
        return []
    return [
        Finding(
            id="INTEGRITY-SRI",
            title="Third-party scripts without Subresource Integrity",
            severity=Severity.MEDIUM,
            category="Content integrity",
            description=(
                f"{len(missing)} external script(s) are loaded from other origins "
                "without a Subresource Integrity (integrity=) hash. If that CDN or "
                "third party is compromised, altered JavaScript will execute on your "
                "site with full access to your users."
            ),
            recommendation=(
                "Add an 'integrity' (SRI hash) and 'crossorigin' attribute to each "
                "third-party <script>, or self-host the code."
            ),
            evidence="e.g. " + "; ".join(missing[:3]),
        )
    ]


def check_insecure_form(ctx: ScanContext) -> List[Finding]:
    if not ctx.body:
        return []
    insecure = [
        attrs["action"]
        for tag, attrs in _collect_tags(ctx.body)
        if tag == "form" and attrs.get("action", "").lower().startswith("http://")
    ]
    if not insecure:
        return []
    return [
        Finding(
            id="INTEGRITY-FORM-HTTP",
            title="Form submits data over plain HTTP",
            severity=Severity.HIGH,
            category="Content integrity",
            description=(
                "A form targets an http:// action URL, so everything submitted "
                "(potentially including passwords) travels in cleartext and can be "
                "read or altered by anyone on the network path."
            ),
            recommendation="Point every form 'action' at an https:// endpoint.",
            evidence=f"action={insecure[0]}",
        )
    ]


# (id, label, severity, compiled pattern, tailored recommendation)
_SECRET_PATTERNS = [
    (
        "SECRET-AWS-KEY", "AWS access key ID", Severity.CRITICAL,
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "Remove it from client-side code, move AWS calls server-side, and rotate the key now.",
    ),
    (
        "SECRET-AWS-SECRET", "AWS secret access key", Severity.CRITICAL,
        re.compile(r"(?i)aws.{0,20}?secret.{0,20}?['\"]([A-Za-z0-9/+]{40})['\"]"),
        "Rotate this AWS secret immediately and never ship it to the browser.",
    ),
    (
        "SECRET-GOOGLE-API", "Google API key", Severity.HIGH,
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        "Restrict the key (HTTP referrer / API restrictions) or move it server-side, then rotate it.",
    ),
    (
        "SECRET-GOOGLE-OAUTH", "Google OAuth client secret", Severity.CRITICAL,
        re.compile(r"\bGOCSPX-[0-9A-Za-z_\-]{20,}\b"),
        "Client secrets must stay server-side. Rotate it and remove it from the page.",
    ),
    (
        "SECRET-STRIPE-SECRET", "Stripe live secret key", Severity.CRITICAL,
        re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b"),
        "Roll this Stripe secret key immediately; it must never appear in client code.",
    ),
    (
        "SECRET-STRIPE-PUB", "Stripe live publishable key", Severity.INFO,
        re.compile(r"\bpk_live_[0-9A-Za-z]{16,}\b"),
        "This is a Stripe *publishable* key and is safe to expose — just confirm it is not the secret key.",
    ),
    (
        "SECRET-GITHUB", "GitHub token", Severity.CRITICAL,
        re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
        "Revoke this GitHub token now and remove it from the page.",
    ),
    (
        "SECRET-SLACK", "Slack token", Severity.HIGH,
        re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
        "Revoke this Slack token and keep it server-side.",
    ),
    (
        "SECRET-PRIVATE-KEY", "Private key block", Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        "A private key is embedded in the page. Rotate the key pair and remove it immediately.",
    ),
    (
        "SECRET-JWT", "JSON Web Token (JWT)", Severity.MEDIUM,
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{6,}\b"),
        "If this token grants access, treat it as leaked: invalidate it and avoid embedding tokens in page source.",
    ),
    (
        "SECRET-GENERIC", "Hard-coded secret / API key", Severity.MEDIUM,
        re.compile(
            r"(?i)(?:api[_-]?key|secret|access[_-]?token|client[_-]?secret|password)"
            r"\s*[=:]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]"
        ),
        "Move the value to a server-side call and rotate it if it is a real credential.",
    ),
]


def _redact(secret: str) -> str:
    secret = secret.strip()
    if len(secret) <= 8:
        return (secret[:1] or "?") + "***"
    return f"{secret[:4]}…{secret[-2:]} ({len(secret)} chars)"


def check_exposed_secrets(ctx: ScanContext) -> List[Finding]:
    if not ctx.body:
        return []
    findings: List[Finding] = []
    for finding_id, label, severity, pattern, advice in _SECRET_PATTERNS:
        redacted: List[str] = []
        for match in pattern.finditer(ctx.body):
            secret = match.group(1) if match.groups() else match.group(0)
            red = _redact(secret)
            if red not in redacted:
                redacted.append(red)
            if len(redacted) >= 3:
                break
        if not redacted:
            continue
        if severity is Severity.INFO:
            description = (
                f"A value matching a {label} was found in the page source. This type "
                "of key is designed to be public, so it is normally safe to expose — "
                "it is flagged only so you can confirm it is the intended key."
            )
        else:
            description = (
                f"A value matching a {label} was found in the HTML/JavaScript served "
                "to the browser. Anything shipped to the client is visible to anyone "
                "who views the source, so a malicious actor can extract and abuse it."
            )
        findings.append(
            Finding(
                id=finding_id,
                title=f"Possible {label} exposed in page source",
                severity=severity,
                category="Secret exposure",
                description=description,
                recommendation=advice,
                evidence="Redacted match(es): " + "; ".join(redacted),
            )
        )
    return findings


# Signatures of a compromised page. Each: (id, title, severity, regex, description).
_MALWARE_SIGNATURES = [
    (
        "MALWARE-MINER", "In-browser cryptominer", Severity.HIGH,
        re.compile(r"(?i)coinhive|coin-hive|cryptonight|cryptoloot|webminepool|"
                   r"crypto-?loot|miner\.start\s*\(|new\s+Miner|jsecoin"),
        "The page loads an in-browser cryptocurrency miner, which hijacks visitors' "
        "CPUs — a common sign the site has been compromised.",
    ),
    (
        "MALWARE-EVAL", "Obfuscated script execution", Severity.MEDIUM,
        re.compile(r"(?i)eval\s*\(\s*(?:atob|unescape|decodeURIComponent|"
                   r"String\.fromCharCode)|eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c"),
        "The page runs obfuscated, dynamically-decoded JavaScript (eval of "
        "base64/packed code) — a frequent malware-injection pattern.",
    ),
    (
        "MALWARE-WEBSHELL", "Server-side web-shell pattern", Severity.HIGH,
        re.compile(r"(?i)eval\s*\(\s*base64_decode\s*\(|shell_exec\s*\(|"
                   r"passthru\s*\(|\$_(?:GET|POST|REQUEST)\s*\[[^\]]+\]\s*\("),
        "The served content contains a server-side web-shell pattern, suggesting the "
        "site may be backdoored.",
    ),
]


class _HiddenIframeCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag != "iframe":
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        src = a.get("src", "")
        style = a.get("style", "").lower().replace(" ", "")
        hidden = (
            "display:none" in style or "visibility:hidden" in style
            or a.get("width", "") in ("0", "1") or a.get("height", "") in ("0", "1")
        )
        if hidden and src.lower().startswith(("http://", "https://", "//")):
            self.hidden.append(src)


def check_malware_indicators(ctx: ScanContext) -> List[Finding]:
    """Passively scan the served HTML/JS for signs of compromise/malware."""
    body = ctx.body or ""
    if not body:
        return []
    findings: List[Finding] = []
    for finding_id, title, severity, pattern, description in _MALWARE_SIGNATURES:
        match = pattern.search(body)
        if match:
            findings.append(
                Finding(
                    id=finding_id, title=title, severity=severity,
                    category="Malware / compromise", description=description,
                    recommendation=(
                        "Investigate immediately: this often means the site is hacked. "
                        "Compare against a known-good copy, remove the injected code, "
                        "rotate credentials, and check server logs."
                    ),
                    evidence=match.group(0)[:120],
                )
            )
    parser = _HiddenIframeCollector()
    try:
        parser.feed(body)
    except Exception:  # pragma: no cover
        pass
    if parser.hidden:
        findings.append(
            Finding(
                id="MALWARE-IFRAME",
                title="Hidden external iframe",
                severity=Severity.HIGH,
                category="Malware / compromise",
                description=(
                    "The page embeds a hidden (0-size or display:none) iframe pointing "
                    "to an external site — a classic drive-by malware / redirect "
                    "injection technique."
                ),
                recommendation=(
                    "Remove the hidden iframe and audit the site for compromise; check "
                    "how the code was injected."
                ),
                evidence="; ".join(parser.hidden[:3]),
            )
        )
    return findings


CONTENT_CHECKS = [
    check_mixed_content,
    check_subresource_integrity,
    check_insecure_form,
    check_exposed_secrets,
    check_malware_indicators,
]
