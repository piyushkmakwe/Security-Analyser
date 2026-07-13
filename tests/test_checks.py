"""Tests for the security checks (no network required)."""

from datetime import datetime, timedelta, timezone

from security_analyser.checks import run_checks
from security_analyser.model import Cookie, Headers, ScanContext, Severity, TlsInfo


def make_context(headers=None, cookies=None, tls=None, scheme="https", **kwargs):
    ctx = ScanContext(
        requested_url="https://example.com/",
        final_url="https://example.com/",
        scheme=scheme,
        host="example.com",
        status_code=200,
        headers=Headers(list((headers or {}).items())),
        cookies=cookies or [],
        tls=tls,
        http_redirects_to_https=kwargs.get("http_redirects_to_https", True),
        http_reachable_plaintext=kwargs.get("http_reachable_plaintext", False),
    )
    return ctx


def ids(findings):
    return {f.id for f in findings}


def test_hardened_site_has_no_header_findings():
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
    tls = TlsInfo(host="example.com", connected=True, verified=True,
                  protocol="TLSv1.3", days_to_expiry=200)
    findings = run_checks(make_context(headers=headers, tls=tls))
    assert findings == []


def test_missing_headers_are_flagged():
    tls = TlsInfo(host="example.com", connected=True, verified=True,
                  protocol="TLSv1.3", days_to_expiry=200)
    findings = run_checks(make_context(headers={}, tls=tls))
    found = ids(findings)
    assert {"HDR-HSTS", "HDR-CSP", "HDR-XFO", "HDR-XCTO", "HDR-REFPOL"} <= found


def test_plain_http_is_high_severity():
    ctx = make_context(scheme="http")
    ctx.final_url = "http://example.com/"
    findings = run_checks(ctx)
    https = [f for f in findings if f.id == "HTTPS-001"]
    assert https and https[0].severity is Severity.HIGH


def test_insecure_cookie_flags():
    cookie = Cookie(name="session", secure=False, http_only=False,
                    same_site=None, raw="session=abc")
    tls = TlsInfo(host="example.com", connected=True, verified=True,
                  protocol="TLSv1.3", days_to_expiry=200)
    findings = run_checks(make_context(headers=_hardened_headers(), cookies=[cookie], tls=tls))
    found = ids(findings)
    assert {"COOKIE-SECURE", "COOKIE-HTTPONLY", "COOKIE-SAMESITE"} <= found


def test_secure_cookie_has_no_findings():
    cookie = Cookie(name="session", secure=True, http_only=True,
                    same_site="Lax", raw="session=abc; Secure; HttpOnly; SameSite=Lax")
    tls = TlsInfo(host="example.com", connected=True, verified=True,
                  protocol="TLSv1.3", days_to_expiry=200)
    findings = run_checks(make_context(headers=_hardened_headers(), cookies=[cookie], tls=tls))
    assert not any(f.id.startswith("COOKIE") for f in findings)


def test_expired_certificate_flagged():
    tls = TlsInfo(host="example.com", connected=True, verified=True,
                  protocol="TLSv1.3", days_to_expiry=-3,
                  not_after=datetime.now(timezone.utc) - timedelta(days=3))
    findings = run_checks(make_context(headers=_hardened_headers(), tls=tls))
    assert "TLS-EXPIRED" in ids(findings)


def test_unverified_certificate_flagged():
    tls = TlsInfo(host="example.com", connected=True, verified=False,
                  verify_error="self-signed certificate")
    findings = run_checks(make_context(headers=_hardened_headers(), tls=tls))
    assert "TLS-INVALID" in ids(findings)


def test_cors_wildcard_with_credentials_is_high():
    headers = dict(_hardened_headers())
    headers["Access-Control-Allow-Origin"] = "*"
    headers["Access-Control-Allow-Credentials"] = "true"
    tls = TlsInfo(host="example.com", connected=True, verified=True,
                  protocol="TLSv1.3", days_to_expiry=200)
    findings = run_checks(make_context(headers=headers, tls=tls))
    cors = [f for f in findings if f.id == "CORS-WILDCARD-CREDS"]
    assert cors and cors[0].severity is Severity.HIGH


def test_information_disclosure_flagged():
    headers = dict(_hardened_headers())
    headers["Server"] = "nginx/1.18.0"
    headers["X-Powered-By"] = "PHP/8.1.2"
    tls = TlsInfo(host="example.com", connected=True, verified=True,
                  protocol="TLSv1.3", days_to_expiry=200)
    findings = run_checks(make_context(headers=headers, tls=tls))
    found = ids(findings)
    assert "INFO-SERVER" in found
    assert "INFO-POWEREDBY" in found


def _hardened_headers():
    return {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()",
    }
