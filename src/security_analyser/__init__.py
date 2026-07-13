"""Security Analyser — scan a website for common security issues.

Fetches a target URL and inspects its security headers, TLS certificate,
cookies, and information disclosure, producing a report of vulnerabilities and
recommended fixes.
"""

__version__ = "0.1.0"

from security_analyser.model import Finding, ScanContext, ScanResult, Severity
from security_analyser.scanner import scan

__all__ = ["Finding", "ScanContext", "ScanResult", "Severity", "scan", "__version__"]
