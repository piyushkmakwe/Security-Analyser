"""Active probing for exposed sensitive files and paths.

Given a base URL, this requests a small set of well-known sensitive paths
(version-control dirs, environment files, backups, status pages) and reports
the ones that are actually accessible. A soft-404 baseline plus per-path
content signatures keep false positives down on sites that return 200 for
everything.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List
from urllib.parse import urljoin

from security_analyser.fetch import DEFAULT_TIMEOUT, probe_path
from security_analyser.model import Finding, Severity

# A path that should never exist, used to learn how the site answers 404s.
_BASELINE_PATH = "/sa-nonexistent-9f3a2b7c1d.html"


def _not_html(ctype: str, body: str) -> bool:
    return "text/html" not in ctype.lower() and not body.lstrip().lower().startswith("<")


@dataclass(frozen=True)
class PathSpec:
    id: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    paths: List[str]
    validate: Callable[[int, str, str], bool]


PATH_SPECS: List[PathSpec] = [
    PathSpec(
        "PATH-GIT", "Exposed Git repository", Severity.HIGH,
        "A .git directory is served publicly. Attackers can download it and "
        "reconstruct your full source code and history, including secrets.",
        "Block access to /.git/ at the web server, or remove it from the web root.",
        ["/.git/HEAD"],
        lambda s, c, b: s == 200 and b.strip().startswith("ref:"),
    ),
    PathSpec(
        "PATH-ENV", "Exposed environment file (.env)", Severity.CRITICAL,
        "A .env file is publicly accessible. These typically contain database "
        "credentials, API keys and other secrets.",
        "Deny access to dotfiles at the web server and move secrets out of the web root.",
        ["/.env", "/.env.local", "/.env.production"],
        lambda s, c, b: s == 200 and "=" in b and _not_html(c, b),
    ),
    PathSpec(
        "PATH-SVN", "Exposed Subversion metadata", Severity.HIGH,
        "A .svn directory is publicly accessible and can leak source code.",
        "Block access to /.svn/ or remove it from the web root.",
        ["/.svn/entries"],
        lambda s, c, b: s == 200 and bool(b.strip()) and _not_html(c, b),
    ),
    PathSpec(
        "PATH-BACKUP", "Exposed backup / database dump", Severity.HIGH,
        "A backup or database dump is downloadable. These often contain the "
        "entire application source or database contents.",
        "Remove backups from the web root and deny access to archive/SQL files.",
        ["/backup.zip", "/backup.sql", "/backup.tar.gz", "/database.sql",
         "/dump.sql", "/db.sql", "/backup.tar"],
        lambda s, c, b: s == 200 and bool(b) and _not_html(c, b),
    ),
    PathSpec(
        "PATH-WPCONFIG", "Exposed WordPress config backup", Severity.CRITICAL,
        "A wp-config backup is accessible and contains database credentials.",
        "Remove the backup file; never keep editable copies of wp-config in the web root.",
        ["/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.save"],
        lambda s, c, b: s == 200 and "DB_PASSWORD" in b,
    ),
    PathSpec(
        "PATH-SERVER-STATUS", "Apache server-status exposed", Severity.MEDIUM,
        "The Apache server-status page is public and reveals request URLs, "
        "client IPs and server internals.",
        "Restrict mod_status to localhost or disable it.",
        ["/server-status"],
        lambda s, c, b: s == 200 and "Apache Server Status" in b,
    ),
    PathSpec(
        "PATH-PHPINFO", "phpinfo() page exposed", Severity.MEDIUM,
        "A phpinfo() page is public and discloses the full PHP configuration, "
        "paths and loaded modules.",
        "Remove phpinfo pages from production.",
        ["/phpinfo.php", "/info.php"],
        lambda s, c, b: s == 200 and ("phpinfo()" in b.lower() or "PHP Version" in b),
    ),
    PathSpec(
        "PATH-DSSTORE", "Exposed .DS_Store file", Severity.LOW,
        "A macOS .DS_Store file is accessible and can reveal directory and file "
        "names that are otherwise hidden.",
        "Deny access to .DS_Store files and avoid deploying them.",
        ["/.DS_Store"],
        lambda s, c, b: s == 200 and ("Bud1" in b or "application/octet-stream" in c.lower()),
    ),
]


def probe_paths(
    base_url: str, timeout: float = DEFAULT_TIMEOUT, verify_tls: bool = True
) -> List[Finding]:
    """Probe ``base_url`` for exposed sensitive paths and return findings."""
    findings: List[Finding] = []

    baseline = probe_path(urljoin(base_url, _BASELINE_PATH), timeout, verify_tls)
    baseline_status = baseline[0] if baseline else 404

    for spec in PATH_SPECS:
        matched: List[str] = []
        for path in spec.paths:
            res = probe_path(urljoin(base_url, path), timeout, verify_tls)
            if not res:
                continue
            status, ctype, body = res
            # If the site soft-404s with 200, a bare 200 is not enough — the
            # per-spec validator's content signature must still match.
            if status == baseline_status == 200 and not body:
                continue
            if spec.validate(status, ctype, body):
                matched.append(path)
        if matched:
            findings.append(
                Finding(
                    id=spec.id, title=spec.title, severity=spec.severity,
                    category="Exposed paths", description=spec.description,
                    recommendation=spec.recommendation,
                    evidence="Accessible: " + ", ".join(matched),
                )
            )

    # security.txt is a best-practice disclosure file: flag its absence.
    has_security_txt = False
    for path in ("/.well-known/security.txt", "/security.txt"):
        res = probe_path(urljoin(base_url, path), timeout, verify_tls)
        if res and res[0] == 200 and "contact" in res[2].lower():
            has_security_txt = True
            break
    if not has_security_txt:
        findings.append(
            Finding(
                id="PATH-SECURITYTXT",
                title="No security.txt policy published",
                severity=Severity.INFO,
                category="Exposed paths",
                description=(
                    "No /.well-known/security.txt was found. This file tells "
                    "security researchers how to report vulnerabilities to you."
                ),
                recommendation=(
                    "Publish /.well-known/security.txt with a security contact "
                    "(see https://securitytxt.org)."
                ),
            )
        )
    return findings
