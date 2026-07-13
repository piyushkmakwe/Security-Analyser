"""Tests for URL normalization, cookie parsing, report rendering, and CLI."""

import json

import pytest

from security_analyser.fetch import normalize_url, parse_cookie
from security_analyser.model import Finding, Headers, ScanContext, ScanResult, Severity
from security_analyser.report import render


def test_normalize_url_adds_https():
    assert normalize_url("example.com") == "https://example.com/"
    assert normalize_url("example.com/path?q=1") == "https://example.com/path?q=1"


def test_normalize_url_preserves_scheme():
    assert normalize_url("http://example.com") == "http://example.com/"


def test_normalize_url_rejects_bad_input():
    with pytest.raises(ValueError):
        normalize_url("")
    with pytest.raises(ValueError):
        normalize_url("ftp://example.com")


def test_parse_cookie_attributes():
    cookie = parse_cookie("sid=abc123; Secure; HttpOnly; SameSite=Strict; Path=/")
    assert cookie.name == "sid"
    assert cookie.secure is True
    assert cookie.http_only is True
    assert cookie.same_site == "Strict"


def test_parse_cookie_defaults():
    cookie = parse_cookie("tracking=1")
    assert cookie.name == "tracking"
    assert cookie.secure is False
    assert cookie.http_only is False
    assert cookie.same_site is None


def _sample_result():
    ctx = ScanContext(
        requested_url="https://example.com/",
        final_url="https://example.com/",
        scheme="https",
        host="example.com",
        status_code=200,
        headers=Headers(),
    )
    findings = [
        Finding(
            id="HDR-CSP",
            title="Missing Content-Security-Policy header",
            severity=Severity.MEDIUM,
            category="Security headers",
            description="No CSP.",
            recommendation="Add a CSP.",
        )
    ]
    return ScanResult(context=ctx, findings=findings)


def test_render_text_contains_finding():
    text = render(_sample_result(), fmt="text")
    assert "SECURITY ANALYSER REPORT" in text
    assert "Missing Content-Security-Policy header" in text
    assert "1 medium" in text


def test_render_json_is_valid():
    payload = json.loads(render(_sample_result(), fmt="json"))
    assert payload["target"] == "https://example.com/"
    assert payload["highest_severity"] == "medium"
    assert payload["findings"][0]["id"] == "HDR-CSP"


def test_render_html_contains_finding():
    out = render(_sample_result(), fmt="html")
    assert "<!DOCTYPE html>" in out
    assert "Missing Content-Security-Policy header" in out
    assert "sev-medium" in out


def test_render_unknown_format_raises():
    with pytest.raises(ValueError):
        render(_sample_result(), fmt="pdf")


def test_result_counts_and_highest():
    result = _sample_result()
    assert result.counts()["medium"] == 1
    assert result.highest_severity is Severity.MEDIUM


def test_cli_json_output(tmp_path, monkeypatch, capsys):
    from security_analyser import cli

    monkeypatch.setattr(cli, "scan", lambda *a, **k: _sample_result())
    exit_code = cli.main(["scan", "https://example.com", "--format", "json"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["findings"][0]["id"] == "HDR-CSP"
    # Highest severity is MEDIUM, default --fail-on is high => exit 0.
    assert exit_code == 0


def test_cli_fail_on_threshold(monkeypatch):
    from security_analyser import cli

    monkeypatch.setattr(cli, "scan", lambda *a, **k: _sample_result())
    # MEDIUM finding, --fail-on medium => exit 1.
    assert cli.main(["scan", "https://example.com", "--fail-on", "medium"]) == 1


def test_cli_writes_output_file(tmp_path, monkeypatch):
    from security_analyser import cli

    monkeypatch.setattr(cli, "scan", lambda *a, **k: _sample_result())
    out = tmp_path / "report.html"
    cli.main(["scan", "https://example.com", "--format", "html", "--output", str(out)])
    assert out.exists()
    assert "<!DOCTYPE html>" in out.read_text()
