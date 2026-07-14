"""A small, dependency-free web front end for the security analyser.

Serves a single-page UI and a JSON ``POST /api/scan`` endpoint, built on the
standard library's ``http.server``. Binds to localhost by default: the scanner
issues outbound requests to whatever URL it is given, so exposing it on a
public interface would let anyone use your host to probe other sites.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Tuple

from security_analyser import __version__
from security_analyser.fetch import DEFAULT_TIMEOUT
from security_analyser.report import result_to_payload
from security_analyser.scanner import scan

MAX_BODY_BYTES = 64 * 1024

_STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
}


def _read_static(name: str) -> bytes:
    """Load a packaged static asset by file name."""
    return (resources.files("security_analyser") / "static" / name).read_bytes()


def run_scan_request(payload: dict) -> Tuple[int, dict]:
    """Validate a scan request payload and run the scan.

    Returns ``(http_status, response_dict)``.
    """
    url = (payload.get("url") or "").strip()
    if not url:
        return 400, {"error": "A 'url' field is required."}

    try:
        timeout = float(payload.get("timeout") or DEFAULT_TIMEOUT)
    except (TypeError, ValueError):
        return 400, {"error": "'timeout' must be a number."}
    timeout = max(1.0, min(timeout, 120.0))
    verify_tls = bool(payload.get("verify_tls", True))

    try:
        result = scan(url, timeout=timeout, verify_tls=verify_tls)
    except ValueError as exc:
        return 400, {"error": str(exc)}
    return 200, result_to_payload(result)


class Handler(BaseHTTPRequestHandler):
    server_version = f"security-analyser/{__version__}"

    def log_message(self, *args) -> None:  # noqa: D401 - quieten default logging
        """Suppress the default per-request stderr logging."""

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(self, status: int, obj: dict) -> None:
        self._send(status, json.dumps(obj).encode("utf-8"), "application/json; charset=utf-8")

    def _serve_static(self, name: str) -> None:
        ext = name[name.rfind(".") :] if "." in name else ""
        content_type = _STATIC_TYPES.get(ext, "application/octet-stream")
        try:
            body = _read_static(name)
        except (FileNotFoundError, OSError):
            self._send_json(404, {"error": "Not found"})
            return
        self._send(200, body, content_type)

    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._serve_static("index.html")
        elif path == "/health":
            self._send_json(200, {"status": "ok", "version": __version__})
        elif path.startswith("/static/"):
            self._serve_static(path[len("/static/") :])
        else:
            self._send_json(404, {"error": "Not found"})

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] != "/api/scan":
            self._send_json(404, {"error": "Not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send_json(400, {"error": "Invalid or missing request body."})
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            self._send_json(400, {"error": "Request body must be a JSON object."})
            return
        status, response = run_scan_request(payload)
        self._send_json(status, response)


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Start the web server (blocking)."""
    httpd = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{port}/"
    print(f"Security Analyser web UI running at {url}")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        httpd.server_close()
