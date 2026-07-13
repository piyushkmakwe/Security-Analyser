"""Tests for the analyser scaffold."""

from pathlib import Path

import pytest

from security_analyser.analyser import Analyser, Finding, Severity
from security_analyser.cli import main


def test_finding_format():
    finding = Finding(
        rule_id="EX001",
        message="example issue",
        severity=Severity.HIGH,
        path="a/b.py",
        line=12,
    )
    assert finding.format() == "[HIGH] EX001: example issue (a/b.py:12)"


def test_finding_format_without_line():
    finding = Finding(
        rule_id="EX002",
        message="file-level issue",
        severity=Severity.LOW,
        path="a/b.py",
    )
    assert finding.format() == "[LOW] EX002: file-level issue (a/b.py)"


def test_scan_returns_empty_for_valid_target(tmp_path: Path):
    (tmp_path / "sample.py").write_text("print('hello')\n")
    assert Analyser().scan(tmp_path) == []


def test_scan_missing_target_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        Analyser().scan(tmp_path / "does-not-exist")


def test_iter_files_excludes_ignored_dirs(tmp_path: Path):
    (tmp_path / "keep.py").write_text("x = 1\n")
    hidden = tmp_path / "__pycache__"
    hidden.mkdir()
    (hidden / "skip.pyc").write_text("")

    files = Analyser().iter_files(tmp_path)
    names = {f.name for f in files}
    assert "keep.py" in names
    assert "skip.pyc" not in names


def test_cli_scan_reports_no_findings(tmp_path: Path, capsys):
    (tmp_path / "sample.py").write_text("print('hi')\n")
    exit_code = main(["scan", str(tmp_path)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "No findings" in captured.out


def test_cli_scan_missing_target_errors(tmp_path: Path, capsys):
    exit_code = main(["scan", str(tmp_path / "nope")])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "error:" in captured.err
