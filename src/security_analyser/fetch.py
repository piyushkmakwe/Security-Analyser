"""Network layer: fetching the target and inspecting its TLS certificate.

Implemented with the Python standard library only (``urllib``, ``ssl``,
``http``) so the tool has no third-party dependencies.
"""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

from security_analyser.model import Cookie, Headers, TlsInfo

USER_AGENT = "security-analyser/0.1 (+https://github.com/piyushkmakwe/Security-Analyser)"
DEFAULT_TIMEOUT = 15.0
# Cap how much of the response body we read for content checks (2 MiB).
MAX_BODY_BYTES = 2 * 1024 * 1024


def normalize_url(url: str) -> str:
    """Return an absolute URL, defaulting to https:// when no scheme is given."""
    url = url.strip()
    if not url:
        raise ValueError("URL must not be empty")
    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = urlparse("https://" + url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {parsed.scheme!r}")
    if not parsed.netloc:
        raise ValueError(f"Could not parse host from URL: {url!r}")
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, ""))


def parse_cookie(raw: str) -> Cookie:
    """Parse a single ``Set-Cookie`` header value into a :class:`Cookie`."""
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0].strip() if parts and parts[0] else ""
    cookie = Cookie(name=name, raw=raw)
    for attr in parts[1:]:
        key, _, value = attr.partition("=")
        key = key.strip().lower()
        if key == "secure":
            cookie.secure = True
        elif key == "httponly":
            cookie.http_only = True
        elif key == "samesite":
            cookie.same_site = value.strip() or None
        elif key == "domain":
            cookie.domain = value.strip() or None
        elif key == "path":
            cookie.path = value.strip() or None
    return cookie


class _CaptureRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect handler that records each hop while still following them."""

    def __init__(self) -> None:
        self.chain: List[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
        self.chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect handler that refuses to follow redirects."""

    def redirect_request(self, *args, **kwargs):  # noqa: N802
        return None


def _request_headers(extra_headers: Optional[dict]) -> dict:
    merged = {"User-Agent": USER_AGENT}
    if extra_headers:
        merged.update(extra_headers)
    return merged


def fetch(
    url: str, timeout: float = DEFAULT_TIMEOUT, verify_tls: bool = True,
    extra_headers: Optional[dict] = None,
) -> Tuple[int, str, Headers, List[Cookie], str, List[str]]:
    """Fetch ``url`` (following redirects) and return status, final URL,
    headers, cookies, a size-limited response body, and the redirect chain.
    ``extra_headers`` are merged into the request (for authenticated scans).
    Raises ``urllib.error.URLError`` on failure."""
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    handler = _CaptureRedirect()
    opener = urllib.request.build_opener(
        handler, urllib.request.HTTPSHandler(context=context)
    )
    request = urllib.request.Request(url, headers=_request_headers(extra_headers))

    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        # A 4xx/5xx is still a valid, inspectable response.
        response = exc

    status = getattr(response, "status", None) or getattr(response, "code", 0)
    final_url = response.geturl()
    raw_headers = list(response.headers.items())
    headers = Headers(raw_headers)
    set_cookies = response.headers.get_all("Set-Cookie") or []
    cookies = [parse_cookie(c) for c in set_cookies]
    body = ""
    try:
        raw = response.read(MAX_BODY_BYTES)
        body = raw.decode("utf-8", errors="replace")
    except Exception:  # pragma: no cover - body is best-effort
        pass
    finally:
        try:
            response.close()
        except Exception:  # pragma: no cover
            pass
    chain = [url] + handler.chain
    return int(status), final_url, headers, cookies, body, chain


def probe_path(
    url: str, timeout: float = DEFAULT_TIMEOUT, verify_tls: bool = True
) -> Optional[Tuple[int, str, str]]:
    """Fetch ``url`` without following redirects for path probing.

    Returns ``(status, content_type, body_snippet)`` or ``None`` on a network
    error. Only a small prefix of the body is read.
    """
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=context)
    )
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        ctype = exc.headers.get("Content-Type", "") if exc.headers else ""
        try:
            body = exc.read(4096).decode("utf-8", errors="replace")
        except Exception:  # pragma: no cover - best effort
            body = ""
        return exc.code, ctype, body
    except (urllib.error.URLError, socket.error, ssl.SSLError, OSError):
        return None
    try:
        ctype = response.headers.get("Content-Type", "")
        body = response.read(4096).decode("utf-8", errors="replace")
    except Exception:  # pragma: no cover - best effort
        ctype, body = "", ""
    finally:
        try:
            response.close()
        except Exception:  # pragma: no cover
            pass
    return int(getattr(response, "status", 200)), ctype, body


CORS_PROBE_ORIGIN = "https://sa-cors-probe.example"


def probe_options(url: str, timeout: float = DEFAULT_TIMEOUT, verify_tls: bool = True):
    """Send an OPTIONS request with a probe Origin.

    Returns ``(allowed_methods, cors_reflects, cors_with_credentials)``.
    Best-effort: returns empty/false values on any error.
    """
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=context)
    )
    request = urllib.request.Request(
        url, method="OPTIONS",
        headers={
            "User-Agent": USER_AGENT,
            "Origin": CORS_PROBE_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    try:
        response = opener.open(request, timeout=timeout)
        headers = response.headers
        response.close()
    except urllib.error.HTTPError as exc:
        headers = exc.headers
    except (urllib.error.URLError, socket.error, ssl.SSLError, OSError):
        return [], False, False
    if headers is None:
        return [], False, False
    allow = headers.get("Allow", "") or headers.get("Access-Control-Allow-Methods", "")
    methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
    acao = (headers.get("Access-Control-Allow-Origin", "") or "").strip()
    creds = (headers.get("Access-Control-Allow-Credentials", "") or "").strip().lower() == "true"
    reflects = acao == CORS_PROBE_ORIGIN
    return methods, reflects, (reflects and creds)


def probe_http_redirect(
    host: str, timeout: float = DEFAULT_TIMEOUT
) -> Tuple[Optional[bool], Optional[bool]]:
    """Probe ``http://host/`` (no redirect following).

    Returns ``(redirects_to_https, reachable_over_plaintext)``.
    """
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(
        f"http://{host}/", headers={"User-Agent": USER_AGENT}
    )
    try:
        response = opener.open(request, timeout=timeout)
        # Opened without a redirect: plaintext content is served directly.
        response.close()
        return False, True
    except urllib.error.HTTPError as exc:
        location = exc.headers.get("Location", "") if exc.headers else ""
        if 300 <= exc.code < 400 and location:
            return location.lower().startswith("https://"), True
        return False, True
    except (urllib.error.URLError, socket.error, ssl.SSLError, OSError):
        return None, False


def inspect_tls(host: str, port: int = 443, timeout: float = DEFAULT_TIMEOUT) -> TlsInfo:
    """Connect to ``host:port`` and inspect its TLS certificate."""
    info = TlsInfo(host=host, port=port)
    context = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                info.connected = True
                info.verified = True
                info.protocol = tls_sock.version()
                cipher = tls_sock.cipher()
                if cipher:
                    info.cipher_name, _, info.cipher_bits = cipher
                cert = tls_sock.getpeercert()
                _populate_cert(info, cert)
    except ssl.SSLCertVerificationError as exc:
        info.connected = True
        info.verified = False
        info.verify_error = str(exc)
        info.self_signed = "self-signed" in str(exc).lower() or "self signed" in str(exc).lower()
        _inspect_tls_unverified(info, host, port, timeout)
    except (socket.timeout, socket.gaierror, ConnectionError, ssl.SSLError, OSError) as exc:
        info.connected = False
        info.verify_error = str(exc)
    if info.connected:
        info.supported_protocols = _enumerate_protocols(host, port, timeout)
    return info


# Protocol label -> the ssl.TLSVersion to pin the connection to.
_PROTOCOL_VERSIONS = [
    ("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)),
    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
    ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
]


def _enumerate_protocols(host: str, port: int, timeout: float) -> List[str]:
    """Return the TLS protocol versions the server will actually negotiate."""
    supported = []
    for label, version in _PROTOCOL_VERSIONS:
        if version is None:
            continue
        ctx = ssl._create_unverified_context()  # noqa: SLF001 - probing only
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except (ValueError, OSError):
            # The local OpenSSL build refuses to offer this version at all.
            continue
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    supported.append(label)
        except (OSError, ssl.SSLError, ValueError):
            continue
    return supported


def _inspect_tls_unverified(
    info: TlsInfo, host: str, port: int, timeout: float
) -> None:
    """Best-effort: still record protocol/expiry for an unverified cert."""
    context = ssl._create_unverified_context()  # noqa: SLF001 - intentional
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                info.protocol = tls_sock.version()
    except OSError:  # pragma: no cover - best effort only
        pass


def _populate_cert(info: TlsInfo, cert: Optional[dict]) -> None:
    if not cert:
        return
    not_after = cert.get("notAfter")
    if not_after:
        try:
            epoch = ssl.cert_time_to_seconds(not_after)
            expiry = datetime.fromtimestamp(epoch, tz=timezone.utc)
            info.not_after = expiry
            info.days_to_expiry = (expiry - datetime.now(timezone.utc)).days
        except ValueError:  # pragma: no cover - unusual date format
            pass
    info.subject = _format_name(cert.get("subject"))
    info.issuer = _format_name(cert.get("issuer"))


def _format_name(name) -> Optional[str]:
    if not name:
        return None
    parts = []
    for rdn in name:
        for key, value in rdn:
            if key in ("commonName", "organizationName"):
                parts.append(value)
    return ", ".join(parts) if parts else None
