"""Tests for content-integrity and secret-exposure checks (no network)."""

from security_analyser.content_checks import (
    check_exposed_secrets,
    check_insecure_form,
    check_mixed_content,
    check_subresource_integrity,
)
from security_analyser.model import Headers, ScanContext


def ctx_with_body(body, scheme="https", host="example.com"):
    return ScanContext(
        requested_url=f"{scheme}://{host}/",
        final_url=f"{scheme}://{host}/",
        scheme=scheme,
        host=host,
        status_code=200,
        headers=Headers(),
        body=body,
    )


def ids(findings):
    return {f.id for f in findings}


# ---- mixed content ----

def test_active_mixed_content_flagged():
    body = '<html><head><script src="http://cdn.example.net/a.js"></script></head></html>'
    findings = check_mixed_content(ctx_with_body(body))
    assert "INTEGRITY-MIXED-ACTIVE" in ids(findings)


def test_passive_mixed_content_is_low():
    body = '<img src="http://cdn.example.net/logo.png">'
    findings = check_mixed_content(ctx_with_body(body))
    f = [x for x in findings if x.id == "INTEGRITY-MIXED-PASSIVE"]
    assert f and f[0].severity.label == "low"


def test_no_mixed_content_when_all_https():
    body = '<script src="https://example.com/app.js"></script><img src="https://example.com/x.png">'
    assert check_mixed_content(ctx_with_body(body)) == []


def test_mixed_content_ignored_on_http_page():
    body = '<script src="http://cdn.example.net/a.js"></script>'
    assert check_mixed_content(ctx_with_body(body, scheme="http")) == []


# ---- subresource integrity ----

def test_third_party_script_without_sri_flagged():
    body = '<script src="https://cdn.jsdelivr.net/npm/lib.js"></script>'
    findings = check_subresource_integrity(ctx_with_body(body))
    assert "INTEGRITY-SRI" in ids(findings)


def test_third_party_script_with_sri_ok():
    body = '<script src="https://cdn.jsdelivr.net/npm/lib.js" integrity="sha384-abc" crossorigin></script>'
    assert check_subresource_integrity(ctx_with_body(body)) == []


def test_same_origin_script_not_flagged_for_sri():
    body = '<script src="https://example.com/app.js"></script>'
    assert check_subresource_integrity(ctx_with_body(body)) == []


# ---- insecure form ----

def test_http_form_action_flagged():
    body = '<form action="http://example.com/login" method="post"></form>'
    findings = check_insecure_form(ctx_with_body(body))
    assert "INTEGRITY-FORM-HTTP" in ids(findings)


def test_https_form_action_ok():
    body = '<form action="https://example.com/login"></form>'
    assert check_insecure_form(ctx_with_body(body)) == []


# ---- secret exposure ----

def test_aws_key_detected_and_redacted():
    body = 'var k = "AKIAIOSFODNN7EXAMPLE";'
    findings = check_exposed_secrets(ctx_with_body(body))
    assert "SECRET-AWS-KEY" in ids(findings)
    # The full secret must never appear in the report.
    assert "AKIAIOSFODNN7EXAMPLE" not in findings[0].evidence


def test_google_api_key_detected():
    body = "key=AIza" + "B" * 35  # AIza + exactly 35 chars
    findings = check_exposed_secrets(ctx_with_body(body))
    assert "SECRET-GOOGLE-API" in ids(findings)


def test_private_key_detected_critical():
    body = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    findings = check_exposed_secrets(ctx_with_body(body))
    f = [x for x in findings if x.id == "SECRET-PRIVATE-KEY"]
    assert f and f[0].severity.label == "critical"


def test_generic_api_key_assignment_detected():
    body = 'const config = { api_key: "abcd1234efgh5678ijkl" };'
    findings = check_exposed_secrets(ctx_with_body(body))
    assert "SECRET-GENERIC" in ids(findings)


def test_clean_body_has_no_secret_findings():
    body = "<html><body><h1>Hello</h1><p>Nothing secret here.</p></body></html>"
    assert check_exposed_secrets(ctx_with_body(body)) == []


def test_stripe_publishable_key_is_info():
    body = 'Stripe("pk_live_51ABCDEFabcdef1234567890")'
    findings = check_exposed_secrets(ctx_with_body(body))
    f = [x for x in findings if x.id == "SECRET-STRIPE-PUB"]
    assert f and f[0].severity.label == "info"
