"""Tests for the scorecard / audit layer."""

from security_analyser.audit import build_scorecard
from security_analyser.model import Cookie, Finding, Headers, ScanContext, ScanResult, Severity


def _result(findings=None, reachable=True, scheme="https", cookies=None, tls=True):
    from security_analyser.model import TlsInfo

    ctx = ScanContext(
        requested_url="https://example.com/",
        final_url="https://example.com/",
        scheme=scheme,
        host="example.com",
        reachable=reachable,
        status_code=200 if reachable else None,
        headers=Headers(),
        cookies=cookies or [],
        tls=TlsInfo(host="example.com", connected=True, verified=True) if tls else None,
    )
    return ScanResult(context=ctx, findings=findings or [])


def _f(fid, sev, title="x"):
    return Finding(id=fid, title=title, severity=sev, category="c",
                   description="d", recommendation="r")


def controls_by_key(scorecard):
    return {c["key"]: c for c in scorecard["controls"]}


def test_clean_site_scores_100_all_safe():
    sc = build_scorecard(_result([]))
    assert sc["overall_score"] == 100
    assert sc["unsafe"] == 0
    # Every applicable control is "safe".
    statuses = {c["status"] for c in sc["controls"] if c["status"] != "n/a"}
    assert statuses == {"safe"}


def test_control_marked_unsafe_when_finding_present():
    sc = build_scorecard(_result([_f("HDR-CSP", Severity.MEDIUM)]))
    csp = controls_by_key(sc)["csp"]
    assert csp["status"] == "unsafe"
    assert csp["score"] == 50
    assert sc["overall_score"] < 100


def test_low_severity_is_review_not_unsafe():
    sc = build_scorecard(_result([_f("HDR-REFPOL", Severity.LOW)]))
    ref = controls_by_key(sc)["referrer"]
    assert ref["status"] == "review"
    assert ref["score"] == 75


def test_critical_secret_zeroes_that_control():
    sc = build_scorecard(_result([_f("SECRET-AWS-KEY", Severity.CRITICAL)]))
    secrets = controls_by_key(sc)["secrets"]
    assert secrets["status"] == "unsafe"
    assert secrets["score"] == 0


def test_tls_and_hsts_not_applicable_on_http():
    sc = build_scorecard(_result([], scheme="http", tls=False))
    by_key = controls_by_key(sc)
    assert by_key["tls"]["status"] == "n/a"
    assert by_key["hsts"]["status"] == "n/a"
    assert by_key["tls"]["score"] is None


def test_cookies_not_applicable_without_cookies():
    sc = build_scorecard(_result([]))
    assert controls_by_key(sc)["cookies"]["status"] == "n/a"


def test_cookies_applicable_when_cookies_present():
    cookies = [Cookie(name="s", secure=True, http_only=True, same_site="Lax")]
    sc = build_scorecard(_result([], cookies=cookies))
    assert controls_by_key(sc)["cookies"]["status"] == "safe"


def test_unreachable_has_no_score():
    sc = build_scorecard(_result([], reachable=False))
    assert sc["applicable"] is False
    assert sc["overall_score"] is None
    assert sc["controls"] == []
