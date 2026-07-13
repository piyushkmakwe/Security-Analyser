"""Core analysis logic.

This module intentionally ships with a minimal scanning engine. It defines the
data model (``Finding``, ``Severity``) and an ``Analyser`` that walks a target
path. Real security rules should be added to :meth:`Analyser.scan`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List


class Severity(str, Enum):
    """Severity level of a finding."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Finding:
    """A single issue reported by the analyser."""

    rule_id: str
    message: str
    severity: Severity
    path: str
    line: int = 0

    def format(self) -> str:
        location = self.path if self.line <= 0 else f"{self.path}:{self.line}"
        return f"[{self.severity.value.upper()}] {self.rule_id}: {self.message} ({location})"


@dataclass
class Analyser:
    """Walks a target path and produces a list of :class:`Finding`.

    The current implementation contains no security rules — it only discovers
    files. Add rules by inspecting each file and appending ``Finding`` objects
    in :meth:`scan`.
    """

    follow_symlinks: bool = False
    _exclude_dirs: frozenset = field(
        default=frozenset({".git", "__pycache__", ".venv", "venv", "node_modules"}),
        repr=False,
    )

    def iter_files(self, target: Path) -> List[Path]:
        """Return the list of files under ``target`` (or ``target`` itself)."""
        if target.is_file():
            return [target]
        files: List[Path] = []
        for path in target.rglob("*"):
            if any(part in self._exclude_dirs for part in path.parts):
                continue
            if path.is_symlink() and not self.follow_symlinks:
                continue
            if path.is_file():
                files.append(path)
        return files

    def scan(self, target: Path) -> List[Finding]:
        """Scan ``target`` and return findings.

        No rules are implemented yet, so this always returns an empty list for
        a valid target. Implement rules here.
        """
        target = Path(target)
        if not target.exists():
            raise FileNotFoundError(f"Target does not exist: {target}")

        findings: List[Finding] = []
        for _file in self.iter_files(target):
            # TODO: apply security rules to `_file` and append Finding objects.
            pass
        return findings
