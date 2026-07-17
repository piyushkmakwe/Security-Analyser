"""Robustness / fuzz tests: parsers and checks must never raise on bad input."""

import random
import string

from security_analyser.assets import discover_assets
from security_analyser.checks import run_checks
from security_analyser.content_checks import (
    check_csrf_token,
    check_exposed_secrets,
    check_jwt_weakness,
    check_malware_indicators,
    check_mixed_content,
    check_vulnerable_js,
)
from security_analyser.crawler import discover_links
from security_analyser.fetch import parse_cookie
from security_analyser.model import Headers, ScanContext

# A grab-bag of hostile / malformed inputs.
_BAD_BODIES = [
    "",
    "<",
    "<html><script src=",
    "<a href=" + "x" * 100000,
    "<iframe " * 5000,
    "".join(chr(random.randint(0, 0x10FFFF) - (0xD800 if False else 0)) for _ in range(2000)) if False else "\x00\x01\x02�",
    "".join(random.choice(string.printable) for _ in range(5000)),
    "<script>eval(</script>",
    "eyJ" + "!" * 50,  # broken JWT
    "<form method=post><input name=",
    "𐀀 invalid surrogate handling",
    "%%%{{7*7}}<>\"'",
]


def _ctx(body, scheme="https"):
    return ScanContext(
        requested_url=f"{scheme}://example.com/", final_url=f"{scheme}://example.com/",
        scheme=scheme, host="example.com", status_code=200, headers=Headers(), body=body,
    )


def test_content_checks_never_crash():
    for body in _BAD_BODIES:
        ctx = _ctx(body)
        for check in (check_mixed_content, check_exposed_secrets, check_malware_indicators,
                      check_vulnerable_js, check_csrf_token, check_jwt_weakness):
            assert isinstance(check(ctx), list)


def test_link_and_asset_discovery_never_crash():
    for body in _BAD_BODIES:
        assert isinstance(discover_links("https://example.com/", body, "example.com"), list)
        assert isinstance(discover_assets("https://example.com/", body, "example.com"), list)


def test_cookie_parsing_never_crashes():
    for raw in ["", ";", "=", "a", "a=b; ; ;", "=; Secure", "x" * 10000, "a=b; SameSite="]:
        c = parse_cookie(raw)
        assert c is not None


def test_run_checks_isolates_failures_and_records_coverage():
    ctx = _ctx("<html></html>")
    findings = run_checks(ctx)
    assert isinstance(findings, list)
    assert "checks" in ctx.coverage
    assert ctx.coverage["checks"]["status"] in ("ran", "partial")


def test_weird_headers_never_crash():
    weird = Headers([
        ("Strict-Transport-Security", "max-age=abc; ;;"),
        ("Content-Security-Policy", "default-src; ; script-src ***  http:"),
        ("Set-Cookie", "=; ="),
        ("Server", "\x00\x01"),
    ])
    ctx = ScanContext(requested_url="https://e/", final_url="https://e/", scheme="https",
                      host="e", status_code=200, headers=weird, body="<html></html>")
    assert isinstance(run_checks(ctx), list)
