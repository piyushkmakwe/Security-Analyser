"""Tests for link discovery, path validators, and crawl aggregation."""

from security_analyser import crawler
from security_analyser.model import Finding, Headers, ScanContext, ScanResult, Severity
from security_analyser.paths import PATH_SPECS


# ---- link discovery ----

def test_discover_links_same_origin_only():
    body = """
      <a href="/about">about</a>
      <a href="https://example.com/contact">contact</a>
      <a href="https://other.com/x">external</a>
      <a href="mailto:a@example.com">mail</a>
      <a href="/style.css">css</a>
      <a href="#top">frag</a>
    """
    links = crawler.discover_links("https://example.com/", body, "example.com")
    assert "https://example.com/about" in links
    assert "https://example.com/contact" in links
    assert all("other.com" not in link for link in links)
    assert all(not link.endswith(".css") for link in links)
    assert all("mailto" not in link for link in links)


def test_discover_links_dedupes_and_strips_fragments():
    body = '<a href="/p">a</a><a href="/p#x">b</a><a href="/p">c</a>'
    links = crawler.discover_links("https://example.com/", body, "example.com")
    assert links == ["https://example.com/p"]


# ---- path validators ----

def _spec(spec_id):
    return next(s for s in PATH_SPECS if s.id == spec_id)


def test_git_validator_signature():
    spec = _spec("PATH-GIT")
    assert spec.validate(200, "text/plain", "ref: refs/heads/main\n") is True
    assert spec.validate(200, "text/html", "<html>404</html>") is False
    assert spec.validate(404, "text/plain", "") is False


def test_env_validator_rejects_html():
    spec = _spec("PATH-ENV")
    assert spec.validate(200, "text/plain", "SECRET=abc\nDB=1") is True
    assert spec.validate(200, "text/html", "<html>SECRET=x</html>") is False


def test_backup_validator_rejects_html_page():
    spec = _spec("PATH-BACKUP")
    assert spec.validate(200, "application/zip", "PK\x03\x04....") is True
    assert spec.validate(200, "text/html", "<html>not found</html>") is False


# ---- crawl aggregation (no network: monkeypatch scan + fetch) ----

def _ctx(body, cookies=None):
    return ScanContext(
        requested_url="https://example.com/", final_url="https://example.com/",
        scheme="https", host="example.com", reachable=True, status_code=200,
        headers=Headers(), body=body, cookies=cookies or [],
    )


def test_crawl_single_page_behaves_like_scan(monkeypatch):
    base = ScanResult(context=_ctx("<html></html>"), findings=[])
    monkeypatch.setattr(crawler, "scan", lambda *a, **k: base)
    result = crawler.crawl("https://example.com", max_pages=1)
    assert result.context.pages_scanned == 1


def test_crawl_visits_linked_pages_and_aggregates(monkeypatch):
    start_body = '<a href="/login">login</a>'
    base = ScanResult(context=_ctx(start_body), findings=[])
    monkeypatch.setattr(crawler, "scan", lambda *a, **k: base)

    # /login serves a page exposing a secret.
    def fake_fetch(url, timeout, verify_tls, extra_headers=None):
        body = 'var k = "AKIAIOSFODNN7EXAMPLE";'
        return 200, url, Headers(), [], body, [url]

    monkeypatch.setattr(crawler.fetch, "fetch", fake_fetch)
    result = crawler.crawl("https://example.com", max_pages=5, depth=1)
    assert result.context.pages_scanned == 2
    secret = [f for f in result.findings if f.id == "SECRET-AWS-KEY"]
    assert secret and "login" in secret[0].page


def test_crawl_probe_paths_flag_sets_context(monkeypatch):
    base = ScanResult(context=_ctx("<html></html>"), findings=[])
    monkeypatch.setattr(crawler, "scan", lambda *a, **k: base)
    monkeypatch.setattr(crawler, "probe_paths", lambda *a, **k: [
        Finding(id="PATH-ENV", title="Exposed .env", severity=Severity.CRITICAL,
                category="Exposed paths", description="d", recommendation="r"),
    ])
    result = crawler.crawl("https://example.com", max_pages=1, probe_paths_enabled=True)
    assert result.context.paths_probed is True
    assert any(f.id == "PATH-ENV" for f in result.findings)


def test_crawl_unreachable_returns_base(monkeypatch):
    ctx = ScanContext(requested_url="https://x/", final_url="https://x/",
                      scheme="https", host="x", reachable=False, error="boom")
    monkeypatch.setattr(crawler, "scan", lambda *a, **k: ScanResult(context=ctx, findings=[]))
    result = crawler.crawl("https://x", max_pages=5)
    assert result.context.reachable is False
