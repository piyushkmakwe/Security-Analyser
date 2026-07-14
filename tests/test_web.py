"""Tests for the web API layer and shared report payload (no network)."""

from security_analyser import web
from security_analyser.model import Finding, Headers, ScanContext, ScanResult, Severity
from security_analyser.report import grade, result_to_payload


def _result(findings=None, reachable=True, error=None):
    ctx = ScanContext(
        requested_url="https://example.com/",
        final_url="https://example.com/",
        scheme="https",
        host="example.com",
        reachable=reachable,
        error=error,
        status_code=200 if reachable else None,
        headers=Headers(),
    )
    return ScanResult(context=ctx, findings=findings or [])


def _finding(sev):
    return Finding(
        id=f"X-{sev.label}", title=f"{sev.label} issue", severity=sev,
        category="Test", description="d", recommendation="fix it",
    )


def test_payload_shape():
    payload = result_to_payload(_result([_finding(Severity.MEDIUM)]))
    assert payload["host"] == "example.com"
    assert payload["total_findings"] == 1
    assert payload["summary"]["medium"] == 1
    assert payload["highest_severity"] == "medium"
    assert payload["findings"][0]["id"] == "X-medium"
    # Scorecard + overall score are part of the payload.
    assert payload["score"] is not None
    assert payload["scorecard"]["controls"]


def test_report_request_from_payload():
    payload = result_to_payload(_result([_finding(Severity.HIGH)]))
    status, html = web.run_report_request({"payload": payload})
    assert status == 200
    assert "<!DOCTYPE html>" in html
    assert "Scorecard" in html


def test_report_request_requires_input():
    status, html = web.run_report_request({})
    assert status == 400


def test_grade_scale():
    assert grade(_result([])) == "A"
    assert grade(_result([_finding(Severity.LOW)])) == "B"
    assert grade(_result([_finding(Severity.CRITICAL)])) == "F"
    assert grade(_result([_finding(Severity.HIGH), _finding(Severity.HIGH)])) == "E"
    assert grade(_result(reachable=False, error="boom")) == "N/A"


def test_run_scan_request_requires_url():
    status, body = web.run_scan_request({})
    assert status == 400
    assert "url" in body["error"].lower()


def test_run_scan_request_bad_timeout():
    status, body = web.run_scan_request({"url": "https://example.com", "timeout": "abc"})
    assert status == 400


def test_run_scan_request_success(monkeypatch):
    monkeypatch.setattr(web, "scan", lambda *a, **k: _result([_finding(Severity.HIGH)]))
    status, body = web.run_scan_request({"url": "https://example.com"})
    assert status == 200
    assert body["grade"] == "D"
    assert body["highest_severity"] == "high"


def test_run_scan_request_invalid_url(monkeypatch):
    def boom(*a, **k):
        raise ValueError("Unsupported URL scheme: 'ftp'")

    monkeypatch.setattr(web, "scan", boom)
    status, body = web.run_scan_request({"url": "ftp://x"})
    assert status == 400
    assert "scheme" in body["error"]


def test_static_index_is_packaged():
    body = web._read_static("index.html")
    assert b"<!DOCTYPE html>" in body
    assert b"Security Analyser" in body


def test_timeout_is_clamped(monkeypatch):
    captured = {}

    def fake_scan(url, timeout, verify_tls, **kwargs):
        captured["timeout"] = timeout
        return _result([])

    monkeypatch.setattr(web, "scan", fake_scan)
    web.run_scan_request({"url": "https://example.com", "timeout": 9999})
    assert captured["timeout"] == 120.0
