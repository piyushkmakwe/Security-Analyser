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
        choices=["text", "json", "html"],
        default="text",
        help="Report format (default: text).",
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


def _run_scan(args: argparse.Namespace) -> int:
    result = scan(args.url, timeout=args.timeout, verify_tls=not args.insecure)
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
