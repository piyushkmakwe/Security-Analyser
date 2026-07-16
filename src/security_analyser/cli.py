"""Command-line interface for the Security Analyser."""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

from security_analyser import __version__
from security_analyser.fetch import DEFAULT_TIMEOUT
from security_analyser.model import Severity
from security_analyser.report import render
from security_analyser.scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-analyser",
        description="Scan a website for common security issues and generate a report.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_p = subparsers.add_parser("scan", help="Scan a URL and report findings.")
    scan_p.add_argument("url", help="The website URL to scan (e.g. https://example.com).")
    scan_p.add_argument(
        "-f", "--format",
        choices=["text", "json", "html", "sarif"],
        default="text",
        help="Report format (default: text). 'sarif' suits CI / code-scanning.",
    )
    scan_p.add_argument(
        "-o", "--output",
        help="Write the report to this file instead of stdout.",
    )
    scan_p.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Network timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    scan_p.add_argument(
        "--insecure",
        action="store_true",
        help="Do not verify the TLS certificate when fetching (still reported).",
    )
    scan_p.add_argument(
        "--fail-on",
        choices=[s.label for s in Severity],
        default="high",
        help=(
            "Exit non-zero if a finding at this severity or higher is present "
            "(default: high). Use 'critical'..'info'."
        ),
    )
    scan_p.add_argument(
        "--max-pages", type=int, default=1,
        help="Crawl up to N same-origin pages (default: 1, only the given URL).",
    )
    scan_p.add_argument(
        "--depth", type=int, default=1,
        help="Maximum link depth to follow when crawling (default: 1).",
    )
    scan_p.add_argument(
        "--probe-paths", action="store_true",
        help="Probe for exposed sensitive files (.git, .env, backups, security.txt, ...).",
    )
    scan_p.add_argument(
        "--dns", action="store_true",
        help="Check DNS/email records (SPF, DMARC, CAA) for the domain.",
    )
    scan_p.add_argument(
        "--active", action="store_true",
        help="Run active probes (open redirect, reflected input). Only on sites you own.",
    )
    scan_p.add_argument(
        "--header", action="append", metavar="NAME:VALUE", default=[],
        help="Extra request header for authenticated scans (repeatable).",
    )
    scan_p.add_argument(
        "--cookie", metavar="COOKIES",
        help="Cookie header value to send for authenticated scans.",
    )
    scan_p.add_argument(
        "--respect-robots", action="store_true",
        help="Honour robots.txt Disallow rules while crawling.",
    )
    scan_p.add_argument(
        "--delay", type=float, default=0.0,
        help="Seconds to wait between page fetches while crawling (politeness).",
    )

    serve_p = subparsers.add_parser("serve", help="Launch the web UI.")
    serve_p.add_argument(
        "--host", default=os.environ.get("HOST", "127.0.0.1"),
        help=(
            "Interface to bind (default: 127.0.0.1, localhost only; or the HOST "
            "env var). Use 0.0.0.0 to accept external connections when hosting."
        ),
    )
    serve_p.add_argument(
        "-p", "--port", type=int, default=int(os.environ.get("PORT", "8000")),
        help="Port to listen on (default: 8000, or the PORT env var).",
    )
    return parser


def _threshold_rank(name: str) -> int:
    for severity in Severity:
        if severity.label == name:
            return severity.rank
    return Severity.HIGH.rank


def _build_headers(args: argparse.Namespace) -> dict:
    headers = {}
    for item in args.header or []:
        name, _, value = item.partition(":")
        if name.strip():
            headers[name.strip()] = value.strip()
    if args.cookie:
        headers["Cookie"] = args.cookie
    return headers


def _run_scan(args: argparse.Namespace) -> int:
    extra_headers = _build_headers(args) or None
    verify_tls = not args.insecure
    crawling = args.max_pages > 1 or args.depth > 1 or args.probe_paths or args.respect_robots
    if crawling or args.dns or args.active:
        from security_analyser.crawler import crawl

        result = crawl(
            args.url, max_pages=args.max_pages, depth=args.depth,
            timeout=args.timeout, verify_tls=verify_tls,
            probe_paths_enabled=args.probe_paths, extra_headers=extra_headers,
            respect_robots=args.respect_robots, delay=args.delay,
            dns_checks_enabled=args.dns, active_checks_enabled=args.active,
        )
    else:
        result = scan(
            args.url, timeout=args.timeout, verify_tls=verify_tls,
            extra_headers=extra_headers,
        )
    output = render(result, fmt=args.format)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(output)
        except OSError as exc:
            print(f"error: could not write to {args.output}: {exc}", file=sys.stderr)
            return 2
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    if not result.context.reachable:
        return 2

    highest = result.highest_severity
    threshold = _threshold_rank(args.fail_on)
    if highest is not None and highest.rank >= threshold:
        return 1
    return 0


def _run_serve(args: argparse.Namespace) -> int:
    from security_analyser.web import serve

    serve(host=args.host, port=args.port)
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "serve":
        return _run_serve(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
