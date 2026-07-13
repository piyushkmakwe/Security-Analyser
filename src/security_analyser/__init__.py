"""Security Analyser — a starter scaffold for a security analysis tool."""

__version__ = "0.1.0"

from security_analyser.analyser import Analyser, Finding, Severity

__all__ = ["Analyser", "Finding", "Severity", "__version__"]
