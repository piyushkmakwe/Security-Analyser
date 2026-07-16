"""Tests for the metadata layer, SARIF export, and the new checks."""

import json

from security_analyser.checks import (
    check_cors_reflection,
    check_cross_origin_isolation,
    check_http_methods,
)
from security_analyser.content_checks import check_csrf_token, check_vulnerable_js
from security_analyser.metadata import confidence_for, enrich, indicative_cvss
from security_analyser.model import Finding, Headers, ScanContext, ScanResult, Severity
from security_analyser.report import render, result_to_payload


def ctx(headers=None, body="", methods=None, reflect=False, reflect_creds=False):
    return ScanContext(
        requested_url="https://example.com/", final_url="https://example.com/",
        scheme="https", host="example.com", status_code=200,
        headers=Headers(list((headers or {}).items())), body=body,
        allowed_methods=methods or [], cors_reflects_origin=reflect,
        cors_reflect_with_credentials=reflect_creds,
    )


def ids(findings):
    return {f.id for f in findings}


# ---- metadata ----

def test_enrich_adds_cwe_owasp_confidence_cvss():
    d = enrich({"id": "ACTIVE-SQLI", "severity": "high"})
    assert d["cwe"] == "CWE-89"
    assert d["owasp"].startswith("A03")
    assert d["confidence"] == "tentative"  # active check
    assert d["references"]
    assert d["cvss"] > 0


def test_confidence_firm_for_header_checks():
    assert confidence_for("HDR-CSP") == "firm"
    assert confidence_for("VERSION-OUTDATED") == "tentative"


def test_cvss_reduced_for_tentative():
    assert indicative_cvss("high", "tentative") < indicative_cvss("high", "firm")


def test_prefix_fallback_resolves():
    d = enrich({"id": "COOKIE-SECURE", "severity": "medium"})
    assert d["cwe"] == "CWE-614"


# ---- new header/probe checks ----

def test_isolation_headers_flagged_when_missing():
    found = ids(check_cross_origin_isolation(ctx()))
    assert "HDR-ISOLATION-COOP" in found


def test_isolation_ok_when_present():
    headers = {
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "X-Permitted-Cross-Domain-Policies": "none",
    }
    assert check_cross_origin_isolation(ctx(headers)) == []


def test_dangerous_methods_flagged():
    findings = check_http_methods(ctx(methods=["GET", "POST", "PUT", "TRACE"]))
    assert "HDR-METHODS" in ids(findings)


def test_safe_methods_not_flagged():
    assert check_http_methods(ctx(methods=["GET", "POST", "HEAD", "OPTIONS"])) == []


def test_cors_reflection_with_credentials_is_high():
    f = check_cors_reflection(ctx(reflect=True, reflect_creds=True))
    assert f and f[0].id == "CORS-REFLECT-CREDS" and f[0].severity is Severity.HIGH


def test_cors_no_reflection_no_finding():
    assert check_cors_reflection(ctx(reflect=False)) == []


# ---- vulnerable JS + CSRF ----

def test_vulnerable_jquery_flagged():
    body = '<script src="https://cdn.example/jquery-3.3.1.min.js"></script>'
    findings = check_vulnerable_js(ctx(body=body))
    assert "JSLIB-OUTDATED" in ids(findings)


def test_current_jquery_not_flagged():
    body = '<script src="https://cdn.example/jquery-3.7.1.min.js"></script>'
    assert check_vulnerable_js(ctx(body=body)) == []


def test_csrf_missing_token_flagged():
    body = '<form method="post" action="/x"><input name="q"></form>'
    findings = check_csrf_token(ctx(body=body))
    assert "FORM-CSRF" in ids(findings)


def test_csrf_token_present_ok():
    body = '<form method="post"><input type="hidden" name="csrf_token" value="x"></form>'
    assert check_csrf_token(ctx(body=body)) == []


def test_get_form_not_flagged_for_csrf():
    body = '<form method="get" action="/search"><input name="q"></form>'
    assert check_csrf_token(ctx(body=body)) == []


# ---- SARIF ----

def _result_with(fid, sev):
    c = ctx()
    f = Finding(id=fid, title="t", severity=sev, category="c", description="d", recommendation="r")
    return ScanResult(context=c, findings=[f])


def test_sarif_is_valid_and_maps_severity():
    out = render(_result_with("ACTIVE-SQLI", Severity.HIGH), fmt="sarif")
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "security-analyser"
    assert run["results"][0]["level"] == "error"
    assert run["tool"]["driver"]["rules"][0]["properties"]["cwe"] == "CWE-89"


def test_payload_findings_carry_metadata():
    payload = result_to_payload(_result_with("HDR-CSP", Severity.MEDIUM))
    f = payload["findings"][0]
    assert f["cwe"] and f["owasp"] and f["confidence"] == "firm"
    assert payload["scanner_version"]
