"""Standardised metadata for findings: CWE, OWASP Top 10, references,
confidence and an indicative CVSS band.

Resolved by exact finding id first, then by id prefix, so whole families
(``COOKIE-*``, ``SECRET-*`` …) share a mapping without listing every id.
The CVSS value is an *indicative* base score derived from severity and
confidence — a quick prioritisation aid, not a computed CVSS vector.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

# Findings whose detection is heuristic / signal-based, not definitive.
_TENTATIVE_PREFIXES = ("ACTIVE-", "VERSION-", "JSLIB-", "MALWARE-", "SECRET-GENERIC")

_OWASP = {
    "A01": "A01:2021 Broken Access Control",
    "A02": "A02:2021 Cryptographic Failures",
    "A03": "A03:2021 Injection",
    "A04": "A04:2021 Insecure Design",
    "A05": "A05:2021 Security Misconfiguration",
    "A06": "A06:2021 Vulnerable and Outdated Components",
    "A07": "A07:2021 Identification and Authentication Failures",
    "A08": "A08:2021 Software and Data Integrity Failures",
    "A09": "A09:2021 Security Logging and Monitoring Failures",
    "A10": "A10:2021 Server-Side Request Forgery",
}

_CHEATSHEET = "https://cheatsheetseries.owasp.org/cheatsheets/"

# id/prefix -> (cwe, owasp-key, [reference urls])
_META: Dict[str, Tuple[str, str, List[str]]] = {
    # Transport
    "HTTPS-": ("CWE-319", "A02", [_CHEATSHEET + "Transport_Layer_Security_Cheat_Sheet.html"]),
    "TLS-": ("CWE-295", "A02", [_CHEATSHEET + "Transport_Layer_Security_Cheat_Sheet.html"]),
    "HDR-HSTS": ("CWE-319", "A05", [_CHEATSHEET + "HTTP_Strict_Transport_Security_Cheat_Sheet.html"]),
    "HDR-REDIRECT-DOWNGRADE": ("CWE-319", "A02", [_CHEATSHEET + "Transport_Layer_Security_Cheat_Sheet.html"]),
    # Headers
    "HDR-CSP": ("CWE-1021", "A05", [_CHEATSHEET + "Content_Security_Policy_Cheat_Sheet.html"]),
    "HDR-XFO": ("CWE-1021", "A05", [_CHEATSHEET + "Clickjacking_Defense_Cheat_Sheet.html"]),
    "HDR-XCTO": ("CWE-693", "A05", ["https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options"]),
    "HDR-REFPOL": ("CWE-200", "A05", ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy"]),
    "HDR-PERMPOL": ("CWE-693", "A05", ["https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy"]),
    "HDR-CACHE-SESSION": ("CWE-525", "A05", [_CHEATSHEET + "Session_Management_Cheat_Sheet.html"]),
    "HDR-ISOLATION": ("CWE-668", "A05", ["https://developer.mozilla.org/docs/Web/HTTP/Cross-Origin_Resource_Policy"]),
    "HDR-METHODS": ("CWE-650", "A05", [_CHEATSHEET + "REST_Security_Cheat_Sheet.html"]),
    # Cookies
    "COOKIE-": ("CWE-614", "A05", [_CHEATSHEET + "Session_Management_Cheat_Sheet.html"]),
    "FORM-CSRF": ("CWE-352", "A01", [_CHEATSHEET + "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"]),
    # CORS
    "CORS-": ("CWE-942", "A05", [_CHEATSHEET + "HTML5_Security_Cheat_Sheet.html"]),
    # JWT / scan meta
    "JWT-ALG-NONE": ("CWE-347", "A02", [_CHEATSHEET + "JSON_Web_Token_for_Java_Cheat_Sheet.html"]),
    "SCAN-": ("CWE-693", "A09", []),
    # Info / components
    "INFO-DEBUG": ("CWE-489", "A05", [_CHEATSHEET + "Error_Handling_Cheat_Sheet.html"]),
    "INFO-STACKTRACE": ("CWE-209", "A05", [_CHEATSHEET + "Error_Handling_Cheat_Sheet.html"]),
    "INFO-": ("CWE-200", "A05", [_CHEATSHEET + "Error_Handling_Cheat_Sheet.html"]),
    "TLS-CIPHER-WEAK": ("CWE-327", "A02", [_CHEATSHEET + "Transport_Layer_Security_Cheat_Sheet.html"]),
    "TLS-PROTO-OLD": ("CWE-326", "A02", [_CHEATSHEET + "Transport_Layer_Security_Cheat_Sheet.html"]),
    "DNS-AXFR": ("CWE-538", "A05", ["https://owasp.org/www-community/attacks/DNS_zone_transfer"]),
    "VERSION-": ("CWE-1104", "A06", [_CHEATSHEET + "Vulnerable_Dependency_Management_Cheat_Sheet.html"]),
    "JSLIB-": ("CWE-1104", "A06", ["https://owasp.org/www-project-top-ten/2017/A9_2017-Using_Components_with_Known_Vulnerabilities"]),
    # Integrity
    "INTEGRITY-SRI": ("CWE-353", "A08", [_CHEATSHEET + "Third_Party_Javascript_Management_Cheat_Sheet.html"]),
    "INTEGRITY-": ("CWE-319", "A08", [_CHEATSHEET + "Transport_Layer_Security_Cheat_Sheet.html"]),
    # Secrets
    "SECRET-": ("CWE-798", "A07", [_CHEATSHEET + "Secrets_Management_Cheat_Sheet.html"]),
    # Paths
    "PATH-": ("CWE-538", "A05", [_CHEATSHEET + "Attack_Surface_Analysis_Cheat_Sheet.html"]),
    # DNS / email
    "DNS-": ("CWE-346", "A05", ["https://cheatsheetseries.owasp.org/"]),
    # Active
    "ACTIVE-SQLI": ("CWE-89", "A03", [_CHEATSHEET + "SQL_Injection_Prevention_Cheat_Sheet.html"]),
    "ACTIVE-SSTI": ("CWE-1336", "A03", ["https://portswigger.net/web-security/server-side-template-injection"]),
    "ACTIVE-REFLECTED-INPUT": ("CWE-79", "A03", [_CHEATSHEET + "Cross_Site_Scripting_Prevention_Cheat_Sheet.html"]),
    "ACTIVE-OPEN-REDIRECT": ("CWE-601", "A01", [_CHEATSHEET + "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"]),
    # Malware
    "MALWARE-": ("CWE-506", "A08", [_CHEATSHEET + "Third_Party_Javascript_Management_Cheat_Sheet.html"]),
}

# Indicative CVSS base score per severity (firm confidence).
_CVSS_BY_SEVERITY = {"critical": 9.3, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0}


def _resolve(finding_id: str) -> Tuple[str, str, List[str]]:
    if finding_id in _META:
        return _META[finding_id]
    # longest matching prefix wins
    best = None
    for key in _META:
        if finding_id.startswith(key) and (best is None or len(key) > len(best)):
            best = key
    if best:
        return _META[best]
    return ("CWE-693", "A05", [])


def confidence_for(finding_id: str) -> str:
    return "tentative" if finding_id.startswith(_TENTATIVE_PREFIXES) else "firm"


def indicative_cvss(severity: str, confidence: str) -> float:
    base = _CVSS_BY_SEVERITY.get(severity, 0.0)
    if confidence == "tentative" and base > 0:
        base = round(max(0.0, base - 0.8), 1)
    return base


def enrich(finding: dict) -> dict:
    """Add cwe/owasp/references/confidence/cvss to a finding dict (in place)."""
    fid = finding.get("id", "")
    cwe, owasp_key, refs = _resolve(fid)
    confidence = confidence_for(fid)
    finding["cwe"] = cwe
    finding["owasp"] = _OWASP.get(owasp_key, owasp_key)
    finding["references"] = refs
    finding["confidence"] = confidence
    finding["cvss"] = indicative_cvss(finding.get("severity", "info"), confidence)
    return finding
