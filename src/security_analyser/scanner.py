"""Scan orchestration: fetch the target, gather context, run the checks."""

from __future__ import annotations

import urllib.error
from typing import Optional
from urllib.parse import urlparse

from security_analyser import fetch
from security_analyser.checks import run_checks
from security_analyser.model import ScanContext, ScanResult


def scan(
    url: str,
    timeout: float = fetch.DEFAULT_TIMEOUT,
    verify_tls: bool = True,
    extra_headers: Optional[dict] = None,
    dns_checks_enabled: bool = False,
    active_checks_enabled: bool = False,
    scan_assets: bool = True,
) -> ScanResult:
    """Scan ``url`` and return a :class:`ScanResult`.

    Network errors are captured on the context (``reachable=False``) rather than
    raised, so the caller always gets a result to report.
    """
    normalized = fetch.normalize_url(url)
    parsed = urlparse(normalized)
    host = parsed.hostname or ""

    try:
        status, final_url, headers, cookies, body, chain = fetch.fetch(
            normalized, timeout=timeout, verify_tls=verify_tls,
            extra_headers=extra_headers,
        )
    except (urllib.error.URLError, OSError, ValueError) as exc:
        ctx = ScanContext(
            requested_url=normalized,
            final_url=normalized,
            scheme=parsed.scheme,
            host=host,
            reachable=False,
            error=str(getattr(exc, "reason", exc)),
        )
        return ScanResult(context=ctx, findings=[])

    final_parsed = urlparse(final_url)
    final_scheme = final_parsed.scheme
    final_host = final_parsed.hostname or host

    tls = None
    if final_scheme == "https":
        port = final_parsed.port or 443
        tls = fetch.inspect_tls(final_host, port=port, timeout=timeout)

    redirects_to_https, plaintext_reachable = fetch.probe_http_redirect(
        final_host, timeout=timeout
    )

    try:
        methods, cors_reflects, cors_creds = fetch.probe_options(
            final_url, timeout=timeout, verify_tls=verify_tls
        )
    except Exception:  # pragma: no cover - probe is best-effort
        methods, cors_reflects, cors_creds = [], False, False

    try:
        cors_null, cors_bypass = fetch.probe_cors_bypass(
            final_url, final_host, timeout=timeout, verify_tls=verify_tls
        )
    except Exception:  # pragma: no cover - probe is best-effort
        cors_null, cors_bypass = False, None

    ctx = ScanContext(
        requested_url=normalized,
        final_url=final_url,
        scheme=final_scheme,
        host=final_host,
        reachable=True,
        status_code=status,
        headers=headers,
        cookies=cookies,
        body=body,
        tls=tls,
        http_redirects_to_https=redirects_to_https,
        http_reachable_plaintext=plaintext_reachable,
        redirect_chain=chain,
        allowed_methods=methods,
        cors_reflects_origin=cors_reflects,
        cors_reflect_with_credentials=cors_creds,
        cors_allows_null=cors_null,
        cors_bypass_origin=cors_bypass,
    )

    # Record scan coverage so "no findings" is distinguishable from "not tested".
    ctx.coverage["page_fetch"] = {"status": "ran", "detail": f"HTTP {status}"}
    if final_scheme == "https":
        if tls and tls.connected:
            ctx.coverage["tls"] = {"status": "ran",
                                   "detail": f"{tls.protocol}; verified={tls.verified}"}
        else:
            ctx.coverage["tls"] = {"status": "error",
                                   "detail": (tls.verify_error if tls else "handshake failed")}
    else:
        ctx.coverage["tls"] = {"status": "skipped", "detail": "target is not HTTPS"}

    findings = run_checks(ctx)

    # Error-page / debug-mode disclosure (lightweight, always on).
    from security_analyser.error_checks import check_error_disclosure
    findings.extend(check_error_disclosure(final_url, timeout=timeout, verify_tls=verify_tls))
    ctx.coverage["error_disclosure"] = {"status": "ran", "detail": "bogus-path + malformed-input probes"}

    # Scan linked same-origin JS/CSS for secrets and malware (reliability).
    if scan_assets and body:
        from security_analyser.assets import discover_assets, scan_assets as _scan_assets
        n_assets = len(discover_assets(final_url, body, final_host))
        seen = {(f.id, f.evidence) for f in findings}
        for finding in _scan_assets(final_url, body, final_host, final_scheme,
                                    timeout=timeout, verify_tls=verify_tls):
            if (finding.id, finding.evidence) not in seen:
                seen.add((finding.id, finding.evidence))
                findings.append(finding)
        ctx.coverage["asset_scan"] = {"status": "ran", "detail": f"{n_assets} same-origin asset(s) discovered"}
    else:
        ctx.coverage["asset_scan"] = {"status": "skipped", "detail": "disabled or no body"}

    if dns_checks_enabled:
        from security_analyser.dns_checks import check_dns
        ctx.dns_checked = True
        dns_findings = check_dns(final_host, timeout=timeout)
        findings.extend(dns_findings)
        ctx.coverage["dns"] = {"status": "ran", "detail": "SPF/DMARC/CAA/DNSSEC/AXFR"}
    else:
        ctx.coverage["dns"] = {"status": "skipped", "detail": "enable with --dns"}

    if active_checks_enabled:
        from security_analyser.active_checks import run_active_checks
        ctx.active_checked = True
        findings.extend(run_active_checks(final_url, timeout=timeout, verify_tls=verify_tls))
        ctx.coverage["active"] = {"status": "ran", "detail": "open-redirect/reflected/SQLi/SSTI"}
    else:
        ctx.coverage["active"] = {"status": "skipped", "detail": "enable with --active"}

    return ScanResult(context=ctx, findings=findings)
