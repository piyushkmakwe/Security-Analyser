"""Tests for the attack-scenario / impact layer."""

from security_analyser.impact import _SCENARIOS, attack_scenario, build_attack_summary
from security_analyser.model import Finding, Headers, ScanContext, ScanResult, Severity
from security_analyser.report import result_to_payload


def test_known_finding_has_specific_scenario():
    text = attack_scenario({"id": "SECRET-AWS-KEY"})
    assert "AWS" in text
    assert text != attack_scenario({"id": "HDR-XFO"})


def test_unknown_finding_uses_fallback():
    assert attack_scenario({"id": "DOES-NOT-EXIST"}) == attack_scenario({"id": ""})


def test_every_scenario_is_nonempty():
    assert all(v.strip() for v in _SCENARIOS.values())


def test_attack_summary_collects_themes():
    findings = [
        {"id": "SECRET-AWS-KEY"},
        {"id": "HTTPS-001"},
        {"id": "HDR-XFO"},
    ]
    summary = build_attack_summary(findings)
    joined = " ".join(summary).lower()
    assert "credential" in joined or "cloud" in joined
    assert "intercept" in joined
    assert "clickjacking" in joined


def test_attack_summary_empty_when_clean():
    assert build_attack_summary([]) == []


def test_payload_includes_impact_and_summary():
    ctx = ScanContext(
        requested_url="https://example.com/", final_url="https://example.com/",
        scheme="https", host="example.com", status_code=200, headers=Headers(),
    )
    f = Finding(id="HDR-XFO", title="No clickjacking protection", severity=Severity.MEDIUM,
                category="Security headers", description="d", recommendation="r")
    payload = result_to_payload(ScanResult(context=ctx, findings=[f]))
    assert payload["findings"][0]["impact"]
    assert payload["attack_summary"]
