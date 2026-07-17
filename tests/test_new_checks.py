"""Tests for the Tier 1-3 additions: headers, DNS, active probes, paths."""

from security_analyser.checks import (
    check_cache_control,
    check_csp,
    check_hsts,
    check_outdated_versions,
    check_redirect_hygiene,
)
from security_analyser.dns_checks import _parse_answers, check_dns
from security_analyser.model import Cookie, Headers, ScanContext, Severity


def ctx(headers=None, cookies=None, scheme="https", redirect_chain=None, body=""):
    return ScanContext(
        requested_url="https://example.com/", final_url="https://example.com/",
        scheme=scheme, host="example.com", status_code=200,
        headers=Headers(list((headers or {}).items())), cookies=cookies or [],
        redirect_chain=redirect_chain or [], body=body,
    )


def ids(findings):
    return {f.id for f in findings}


# ---- HSTS flags ----

def test_hsts_missing_subdomains_flagged():
    findings = check_hsts(ctx({"Strict-Transport-Security": "max-age=31536000"}))
    assert "HDR-HSTS-SUBDOMAINS" in ids(findings)


def test_hsts_preload_eligible_info():
    findings = check_hsts(ctx({"Strict-Transport-Security": "max-age=31536000; includeSubDomains"}))
    assert "HDR-HSTS-PRELOAD" in ids(findings)


# ---- CSP depth ----

def test_csp_wildcard_and_missing_directives():
    findings = check_csp(ctx({"Content-Security-Policy": "default-src 'self'; script-src *"}))
    found = ids(findings)
    assert "HDR-CSP-WILDCARD" in found
    assert "HDR-CSP-DIRECTIVES" in found


def test_csp_http_source_flagged():
    findings = check_csp(ctx({"Content-Security-Policy": "default-src 'self' http://cdn.example object-src 'none'; base-uri 'self'"}))
    assert "HDR-CSP-HTTP" in ids(findings)


# ---- cache-control on session cookie ----

def test_cache_control_flagged_with_cookie():
    c = [Cookie(name="sid", raw="sid=1")]
    findings = check_cache_control(ctx(cookies=c))
    assert "HDR-CACHE-SESSION" in ids(findings)


def test_cache_control_ok_with_no_store():
    c = [Cookie(name="sid", raw="sid=1")]
    findings = check_cache_control(ctx({"Cache-Control": "no-store"}, cookies=c))
    assert findings == []


# ---- redirect hygiene ----

def test_redirect_downgrade_flagged():
    chain = ["https://example.com/", "http://example.com/insecure"]
    findings = check_redirect_hygiene(ctx(redirect_chain=chain))
    assert "HDR-REDIRECT-DOWNGRADE" in ids(findings)


def test_redirect_all_https_ok():
    chain = ["http://example.com/", "https://example.com/", "https://example.com/home"]
    assert check_redirect_hygiene(ctx(redirect_chain=chain)) == []


# ---- outdated version heuristic ----

def test_outdated_server_version_flagged():
    findings = check_outdated_versions(ctx({"Server": "Apache/2.2.15"}))
    f = [x for x in findings if x.id == "VERSION-OUTDATED"]
    assert f and f[0].severity is Severity.MEDIUM


def test_modern_server_not_flagged():
    assert check_outdated_versions(ctx({"Server": "nginx/1.25.3"})) == []


# ---- DNS parsing + checks ----

def test_dns_txt_answer_parsing():
    # header (id, flags, qd=1, an=1, ns=0, ar=0)
    import struct
    header = struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack(">HH", 16, 1)
    txt = b"\x0bv=spf1 -all"
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 300, len(txt)) + txt
    data = header + question + answer
    rdatas = _parse_answers(data, 16)
    assert rdatas and rdatas[0] == txt


def test_check_dns_reports_missing_records(monkeypatch):
    import security_analyser.dns_checks as d
    monkeypatch.setattr(d, "txt_records", lambda name, timeout=5.0: [])
    monkeypatch.setattr(d, "caa_records", lambda name, timeout=5.0: [])
    monkeypatch.setattr(d, "dnskey_present", lambda name, timeout=5.0: True)
    monkeypatch.setattr(d, "zone_transfer_open", lambda name, timeout=5.0: False)
    findings = check_dns("example.com")
    found = ids(findings)
    assert {"DNS-SPF", "DNS-DMARC", "DNS-CAA"} <= found


def test_check_dns_unreachable_returns_empty(monkeypatch):
    import security_analyser.dns_checks as d
    monkeypatch.setattr(d, "txt_records", lambda name, timeout=5.0: None)
    assert check_dns("example.com") == []
