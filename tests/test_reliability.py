"""Tests for coverage reporting, CORS bypass, JWT, and block detection."""

import base64
import json

from security_analyser.checks import check_cors_bypass, check_scan_blocked
from security_analyser.content_checks import check_jwt_weakness
from security_analyser.model import Headers, ScanContext
from security_analyser.report import result_to_payload
from security_analyser.model import ScanResult


def _ctx(**kw):
    base = dict(requested_url="https://example.com/", final_url="https://example.com/",
                scheme="https", host="example.com", status_code=200,
                headers=Headers(), body="")
    base.update(kw)
    return ScanContext(**base)


def ids(findings):
    return {f.id for f in findings}


# ---- CORS bypass ----

def test_cors_null_origin_flagged():
    findings = check_cors_bypass(_ctx(cors_allows_null=True))
    assert "CORS-NULL-ORIGIN" in ids(findings)


def test_cors_bypass_origin_flagged():
    findings = check_cors_bypass(_ctx(cors_bypass_origin="https://example.com.attacker.example"))
    assert "CORS-BYPASS" in ids(findings)


def test_cors_bypass_none_when_safe():
    assert check_cors_bypass(_ctx()) == []


# ---- JWT weakness ----

def _jwt(alg):
    header = base64.urlsafe_b64encode(json.dumps({"alg": alg, "typ": "JWT"}).encode()).rstrip(b"=").decode()
    return f"{header}.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturepart"


def test_jwt_alg_none_flagged():
    ctx = _ctx(body=f'var t = "{_jwt("none")}";')
    assert "JWT-ALG-NONE" in ids(check_jwt_weakness(ctx))


def test_jwt_signed_not_flagged():
    ctx = _ctx(body=f'var t = "{_jwt("RS256")}";')
    assert check_jwt_weakness(ctx) == []


# ---- block / rate-limit detection ----

def test_block_detected_on_403():
    findings = check_scan_blocked(_ctx(status_code=403, body="Access Denied by WAF"))
    assert "SCAN-INCOMPLETE" in ids(findings)


def test_block_detected_on_429():
    ctx = _ctx(status_code=429, body="too many requests")
    findings = check_scan_blocked(ctx)
    assert "SCAN-INCOMPLETE" in ids(findings)
    assert ctx.coverage.get("blocking", {}).get("status") == "blocked"


def test_no_block_on_200():
    assert check_scan_blocked(_ctx(status_code=200, body="<html>ok</html>")) == []


# ---- coverage in payload ----

def test_coverage_included_in_payload():
    ctx = _ctx()
    ctx.coverage["tls"] = {"status": "ran", "detail": "TLSv1.3"}
    payload = result_to_payload(ScanResult(context=ctx, findings=[]))
    assert payload["coverage"]["tls"]["status"] == "ran"
