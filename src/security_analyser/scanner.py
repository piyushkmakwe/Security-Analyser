"""Scan orchestration: fetch the target, gather context, run the checks."""

from __future__ import annotations

import urllib.error
from urllib.parse import urlparse

from security_analyser import fetch
from security_analyser.checks import run_checks
from security_analyser.model import ScanContext, ScanResult


def scan(url: str, timeout: float = fetch.DEFAULT_TIMEOUT, verify_tls: bool = True) -> ScanResult:
    """Scan ``url`` and return a :class:`ScanResult`.

    Network errors are captured on the context (``reachable=False``) rather than
    raised, so the caller always gets a result to report.
    """
    normalized = fetch.normalize_url(url)
    parsed = urlparse(normalized)
    host = parsed.hostname or ""

    try:
        status, final_url, headers, cookies, body = fetch.fetch(
            normalized, timeout=timeout, verify_tls=verify_tls
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
    )

    findings = run_checks(ctx)
    return ScanResult(context=ctx, findings=findings)
