"""Multi-page crawling.

Starts from a single URL (fully scanned as usual), discovers same-origin links,
and runs the per-page **content checks** (mixed content, missing SRI, insecure
forms, exposed secrets) on each additional page. Findings from extra pages are
attributed to the page they were found on and merged into one result, so the
scorecard reflects the whole crawled surface. Optionally probes for exposed
sensitive paths.
"""

from __future__ import annotations

import dataclasses
import time
from collections import deque
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple
from urllib.parse import urldefrag, urljoin, urlparse

from security_analyser import fetch
from security_analyser.content_checks import CONTENT_CHECKS
from security_analyser.model import Finding, ScanContext, ScanResult
from security_analyser.paths import probe_paths
from security_analyser.scanner import scan

# Content findings (attributed per page) are grouped and deduped by these ids.
_CONTENT_PREFIXES = ("INTEGRITY-", "SECRET-")

# Skip links that clearly are not HTML pages.
_SKIP_EXTS = (
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".png", ".jpg", ".jpeg",
    ".gif", ".svg", ".webp", ".ico", ".css", ".js", ".mjs", ".json", ".xml",
    ".mp4", ".mp3", ".webm", ".woff", ".woff2", ".ttf", ".eot", ".dmg", ".exe",
)


class _LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: List[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag == "a":
            for k, v in attrs:
                if k.lower() == "href" and v:
                    self.hrefs.append(v)


def discover_links(base_url: str, body: str, host: str) -> List[str]:
    """Return normalised same-origin page URLs linked from ``body``."""
    parser = _LinkCollector()
    try:
        parser.feed(body)
    except Exception:  # pragma: no cover - tolerate malformed HTML
        pass
    seen: Dict[str, None] = {}
    for href in parser.hrefs:
        href = href.strip()
        if not href or href.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
            continue
        absolute = urldefrag(urljoin(base_url, href))[0]
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        if (parsed.hostname or "").lower() != host.lower():
            continue
        if parsed.path.lower().endswith(_SKIP_EXTS):
            continue
        seen.setdefault(absolute, None)
    return list(seen)


def _run_content_checks(ctx: ScanContext) -> List[Finding]:
    findings: List[Finding] = []
    for check in CONTENT_CHECKS:
        findings.extend(check(ctx))
    return findings


def _robots_disallow(base_url: str, timeout: float, verify_tls: bool) -> List[str]:
    """Return Disallow path prefixes for User-agent '*' from robots.txt."""
    try:
        _s, _f, _h, _c, body, _ch = fetch.fetch(
            urljoin(base_url, "/robots.txt"), timeout=timeout, verify_tls=verify_tls
        )
    except Exception:
        return []
    disallow: List[str] = []
    applies = False
    for line in body.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "user-agent":
            applies = value == "*"
        elif key == "disallow" and applies and value:
            disallow.append(value)
    return disallow


def crawl(
    url: str,
    max_pages: int = 10,
    depth: int = 1,
    timeout: float = fetch.DEFAULT_TIMEOUT,
    verify_tls: bool = True,
    probe_paths_enabled: bool = False,
    extra_headers: Optional[dict] = None,
    respect_robots: bool = False,
    delay: float = 0.0,
    dns_checks_enabled: bool = False,
    active_checks_enabled: bool = False,
) -> ScanResult:
    """Scan ``url`` and up to ``max_pages`` same-origin pages, plus optional
    sensitive-path probing. Returns a single aggregated :class:`ScanResult`."""
    base = scan(
        url, timeout=timeout, verify_tls=verify_tls, extra_headers=extra_headers,
        dns_checks_enabled=dns_checks_enabled,
        active_checks_enabled=active_checks_enabled,
    )
    ctx = base.context
    if not ctx.reachable:
        return base

    start = ctx.final_url
    host = ctx.host
    disallow = _robots_disallow(start, timeout, verify_tls) if respect_robots else []

    def _allowed(link: str) -> bool:
        if not disallow:
            return True
        path = urlparse(link).path or "/"
        return not any(path.startswith(rule) for rule in disallow)

    # Split the start page's findings into host-level and content-level.
    host_findings: List[Finding] = []
    # key (id, evidence) -> {"finding": Finding, "pages": [urls]}
    content_groups: Dict[Tuple[str, str], dict] = {}

    def add_content(finding: Finding, page: str) -> None:
        key = (finding.id, finding.evidence)
        group = content_groups.get(key)
        if group is None:
            content_groups[key] = {"finding": finding, "pages": [page]}
        elif page not in group["pages"]:
            group["pages"].append(page)

    for f in base.findings:
        if f.id.startswith(_CONTENT_PREFIXES):
            add_content(f, start)
        else:
            host_findings.append(f)

    # Breadth-first crawl of additional pages.
    max_pages = max(1, max_pages)
    visited = {start}
    queue: deque = deque()
    if max_pages > 1:
        for link in discover_links(start, ctx.body, host):
            if link not in visited and _allowed(link):
                visited.add(link)
                queue.append((link, 1))

    pages_scanned = 1
    while queue and pages_scanned < max_pages:
        page, page_depth = queue.popleft()
        if delay:
            time.sleep(delay)
        try:
            status, final_url, headers, _cookies, body, _chain = fetch.fetch(
                page, timeout=timeout, verify_tls=verify_tls, extra_headers=extra_headers
            )
        except Exception:
            continue
        pages_scanned += 1
        page_ctx = ScanContext(
            requested_url=page, final_url=final_url,
            scheme=urlparse(final_url).scheme or ctx.scheme, host=host,
            reachable=True, status_code=status, headers=headers, body=body,
        )
        for f in _run_content_checks(page_ctx):
            add_content(f, final_url)
        if page_depth < depth:
            for link in discover_links(final_url, body, host):
                if link not in visited and _allowed(link) and len(visited) < max_pages * 5:
                    visited.add(link)
                    queue.append((link, page_depth + 1))

    # Materialise content findings with page attribution.
    content_findings: List[Finding] = []
    for group in content_groups.values():
        finding = group["finding"]
        pages = group["pages"]
        page_label = pages[0]
        if len(pages) > 1:
            extra = len(pages) - 3
            shown = ", ".join(pages[:3]) + (f" (+{extra} more)" if extra > 0 else "")
            page_label = shown
        content_findings.append(dataclasses.replace(finding, page=page_label))

    path_findings: List[Finding] = []
    if probe_paths_enabled:
        path_findings = probe_paths(start, timeout=timeout, verify_tls=verify_tls)

    ctx.pages_scanned = pages_scanned
    ctx.paths_probed = probe_paths_enabled
    findings = host_findings + content_findings + path_findings
    return ScanResult(context=ctx, findings=findings, scanned_at=base.scanned_at)
