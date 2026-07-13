"""Command-line interface for the Security Analyser."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from security_analyser import __version__
from security_analyser.analyser import Analyser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-analyser",
        description="A starter scaffold for a security analysis tool.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a file or directory for issues.")
    scan.add_argument("target", help="Path to the file or directory to scan.")
    scan.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="Follow symbolic links while walking directories.",
    )

    return parser


def _run_scan(target: str, follow_symlinks: bool) -> int:
    analyser = Analyser(follow_symlinks=follow_symlinks)
    try:
        findings = analyser.scan(Path(target))
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not findings:
        print(f"No findings for {target}.")
        return 0

    for finding in findings:
        print(finding.format())
    print(f"\n{len(findings)} finding(s).")
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        return _run_scan(args.target, args.follow_symlinks)

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
