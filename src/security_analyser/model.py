"""Data model for the security analyser.

Everything the scanner produces is expressed in terms of the classes here:
``Finding`` objects (each a single issue with a severity and remediation),
gathered from a ``ScanContext`` (the observed state of the target) into a
``ScanResult``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional


class Severity(Enum):
    """Severity of a finding, ordered from least to most serious."""

    INFO = ("info", 0)
    LOW = ("low", 1)
    MEDIUM = ("medium", 2)
    HIGH = ("high", 3)
    CRITICAL = ("critical", 4)

    def __init__(self, label: str, rank: int) -> None:
        self.label = label
        self.rank = rank

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.label


@dataclass(frozen=True)
class Finding:
    """A single security issue discovered on the target."""

    id: str
    title: str
    severity: Severity
    category: str
    description: str
    recommendation: str
    evidence: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.label,
            "category": self.category,
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


@dataclass
class Cookie:
    """A cookie parsed from a ``Set-Cookie`` response header."""

    name: str
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None
    raw: str = ""


@dataclass
class TlsInfo:
    """Details about the target's TLS certificate and connection."""

    host: str
    port: int = 443
    connected: bool = False
    verified: bool = False
    verify_error: Optional[str] = None
    protocol: Optional[str] = None
    not_after: Optional[datetime] = None
    days_to_expiry: Optional[int] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {
            "host": self.host,
            "port": str(self.port),
            "connected": str(self.connected),
            "verified": str(self.verified),
            "verify_error": self.verify_error,
            "protocol": self.protocol,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "days_to_expiry": None if self.days_to_expiry is None else str(self.days_to_expiry),
            "issuer": self.issuer,
            "subject": self.subject,
        }


class Headers:
    """Case-insensitive view over HTTP response headers."""

    def __init__(self, items: Optional[List[tuple]] = None) -> None:
        self._items: List[tuple] = list(items or [])
        self._map: Dict[str, str] = {}
        for name, value in self._items:
            self._map.setdefault(name.lower(), value)

    def get(self, name: str, default: Optional[str] = None) -> Optional[str]:
        return self._map.get(name.lower(), default)

    def has(self, name: str) -> bool:
        return name.lower() in self._map

    def items(self) -> List[tuple]:
        return list(self._items)

    def to_dict(self) -> Dict[str, str]:
        return dict(self._map)


@dataclass
class ScanContext:
    """Everything observed about the target, fed to the checks."""

    requested_url: str
    final_url: str
    scheme: str
    host: str
    reachable: bool = True
    error: Optional[str] = None
    status_code: Optional[int] = None
    headers: Headers = field(default_factory=Headers)
    cookies: List[Cookie] = field(default_factory=list)
    body: str = ""
    tls: Optional[TlsInfo] = None
    # Result of probing http:// for a redirect to https://.
    http_redirects_to_https: Optional[bool] = None
    http_reachable_plaintext: Optional[bool] = None

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"


@dataclass
class ScanResult:
    """The context plus all findings from a scan."""

    context: ScanContext
    findings: List[Finding] = field(default_factory=list)
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def counts(self) -> Dict[str, int]:
        result = {s.label: 0 for s in Severity}
        for finding in self.findings:
            result[finding.severity.label] += 1
        return result

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.rank, f.category, f.id))

    @property
    def highest_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)
