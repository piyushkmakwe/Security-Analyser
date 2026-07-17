"""Scan linked same-origin JavaScript/CSS assets.

Secrets, credentials and malicious code usually live in bundled script files,
not the HTML the server returns. This module discovers same-origin ``<script>``
and stylesheet links, fetches them (capped and size-limited), and runs the
secret-exposure and malware checks over their contents — attributing any
finding to the asset URL it was found in.
"""

from __future__ import annotations

import dataclasses
from html.parser import HTMLParser
from typing import List
from urllib.parse import urldefrag, urljoin, urlparse

from security_analyser import fetch
from security_analyser.content_checks import check_exposed_secrets, check_malware_indicators
from security_analyser.model import Finding, Headers, ScanContext

MAX_ASSETS = 12


class _AssetCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.assets: List[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.assets.append(a["src"])
        elif tag == "link" and "stylesheet" in a.get("rel", "").lower() and a.get("href"):
            self.assets.append(a["href"])


def discover_assets(base_url: str, body: str, host: str) -> List[str]:
    parser = _AssetCollector()
    try:
        parser.feed(body)
    except Exception:  # pragma: no cover - tolerate malformed HTML
        pass
    seen = {}
    for ref in parser.assets:
        absolute = urldefrag(urljoin(base_url, ref))[0]
        parsed = urlparse(absolute)
        if parsed.scheme in ("http", "https") and (parsed.hostname or "").lower() == host.lower():
            seen.setdefault(absolute, None)
    return list(seen)


def scan_assets(
    base_url: str, body: str, host: str, scheme: str,
    timeout: float = fetch.DEFAULT_TIMEOUT, verify_tls: bool = True,
    max_assets: int = MAX_ASSETS,
) -> List[Finding]:
    """Fetch same-origin assets and return secret/malware findings from them."""
    findings: List[Finding] = []
    seen_keys = set()
    for url in discover_assets(base_url, body, host)[:max_assets]:
        try:
            _s, _f, _h, _c, content, _ch = fetch.fetch(url, timeout=timeout, verify_tls=verify_tls)
        except Exception:
            continue
        if not content:
            continue
        asset_ctx = ScanContext(
            requested_url=url, final_url=url, scheme=scheme, host=host,
            reachable=True, headers=Headers(), body=content,
        )
        for finding in check_exposed_secrets(asset_ctx) + check_malware_indicators(asset_ctx):
            key = (finding.id, finding.evidence)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            findings.append(dataclasses.replace(finding, page=url))
    return findings
