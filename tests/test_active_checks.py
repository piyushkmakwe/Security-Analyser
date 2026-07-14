"""Tests for active probes (open redirect, reflected input) — no real network."""

from security_analyser import active_checks
from security_analyser.model import Headers


def test_open_redirect_detected(monkeypatch):
    def fake_location(url, timeout, verify_tls):
        if "next=" in url:
            return 302, "https://sa-openredirect-test.example/"
        return 200, ""

    monkeypatch.setattr(active_checks, "_no_redirect_location", fake_location)
    findings = active_checks.check_open_redirect("https://example.com/go", 5, True)
    assert findings and findings[0].id == "ACTIVE-OPEN-REDIRECT"


def test_open_redirect_not_flagged_when_internal(monkeypatch):
    monkeypatch.setattr(active_checks, "_no_redirect_location",
                        lambda url, t, v: (302, "https://example.com/dashboard"))
    assert active_checks.check_open_redirect("https://example.com/go", 5, True) == []


def test_reflected_input_detected(monkeypatch):
    def fake_fetch(url, timeout, verify_tls):
        # echo the marker back unencoded
        marker = url.split("sa_probe=", 1)[1]
        from urllib.parse import unquote
        return 200, url, Headers(), [], f"<p>{unquote(marker)}</p>", [url]

    monkeypatch.setattr(active_checks, "fetch", fake_fetch)
    findings = active_checks.check_reflected_input("https://example.com/search", 5, True)
    assert findings and findings[0].id == "ACTIVE-REFLECTED-INPUT"


def test_reflected_input_not_flagged_when_encoded(monkeypatch):
    def fake_fetch(url, timeout, verify_tls):
        return 200, url, Headers(), [], "<p>sa9z7qmarker&lt;x&gt;</p>", [url]

    monkeypatch.setattr(active_checks, "fetch", fake_fetch)
    assert active_checks.check_reflected_input("https://example.com/search", 5, True) == []
