"""End-to-end integration test against a local, deliberately-insecure server.

This proves the scanner actually finds planted issues over a real HTTP
connection — not just in unit tests with mocked network. The fixture server
serves a vulnerable page plus a couple of exposed paths and a debug error page.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from security_analyser.scanner import scan

VULN_PAGE = b"""<!DOCTYPE html><html><head>
<script src="http://cdn.evil.example/track.js"></script>
<script src="https://cdn.jsdelivr.net/npm/jquery@1.7.0/jquery.min.js"></script>
</head><body>
<form method="post" action="http://insecure.example/login">
  <input name="user"><input name="password" type="password">
</form>
<iframe src="http://evil.example/x" style="display:none"></iframe>
<script>
  var AWS = "AKIAIOSFODNN7EXAMPLE";
  var cfg = { api_key: "abcd1234efgh5678ijkl" };
</script>
</body></html>"""

APP_JS = b'var GITHUB = "ghp_' + b"a" * 36 + b'";\n'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def version_string(self):  # the auto-sent Server header
        return "Apache/2.2.15"

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, PUT, DELETE, TRACE, OPTIONS")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/app.js":
            self._send(APP_JS, "application/javascript")
        elif path == "/.env":
            self._send(b"SECRET_KEY=supersecret\nDB_PASSWORD=hunter2\n", "text/plain")
        elif path.startswith("/sa-error-probe") or "sa_probe" in self.path:
            self._send(b"Traceback (most recent call last):\n  File app.py", "text/plain", 500)
        else:
            # No security headers, sets an insecure cookie.
            body = VULN_PAGE.replace(b"/app.js", b"/app.js")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", "session=abc123")
            self.end_headers()
            self.wfile.write(body + b'<script src="/app.js"></script>')

    def _send(self, data, ctype, status=200):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/"
    httpd.shutdown()


def test_scanner_finds_planted_issues(server):
    result = scan(server, timeout=5)
    assert result.context.reachable
    ids = {f.id for f in result.findings}

    # Missing security headers
    assert "HDR-CSP" in ids
    assert "HDR-HSTS" not in ids  # HSTS only applies to HTTPS; ensure no false positive
    assert "HDR-XFO" in ids
    # Cookie hardening (HttpOnly/SameSite missing on the insecure cookie)
    assert "COOKIE-HTTPONLY" in ids
    # Content integrity: insecure form action (mixed-content only applies to HTTPS)
    assert "INTEGRITY-FORM-HTTP" in ids
    # Secret in inline HTML
    assert "SECRET-AWS-KEY" in ids
    # Secret in the linked app.js (proves asset scanning works)
    assert "SECRET-GITHUB" in ids
    # Malware indicator (hidden external iframe)
    assert "MALWARE-IFRAME" in ids
    # Vulnerable JS library (jQuery 1.7.0)
    assert "JSLIB-OUTDATED" in ids
    # Dangerous HTTP methods advertised via OPTIONS
    assert "HDR-METHODS" in ids
    # Outdated server banner
    assert "VERSION-OUTDATED" in ids
    # Error-page disclosure probe found the stack trace
    assert "INFO-STACKTRACE" in ids


def test_scanner_finds_exposed_env_with_probe(server):
    result = scan(server, timeout=5)
    # /.env is only checked when path probing is enabled -> not here.
    assert "PATH-ENV" not in {f.id for f in result.findings}
    from security_analyser.paths import probe_paths
    env_findings = {f.id for f in probe_paths(server, timeout=5)}
    assert "PATH-ENV" in env_findings


def test_github_secret_attributed_to_asset(server):
    result = scan(server, timeout=5)
    gh = [f for f in result.findings if f.id == "SECRET-GITHUB"]
    assert gh and gh[0].page.endswith("/app.js")
