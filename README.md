# Security Analyser

A dependency-free command-line tool that scans a website for common security
issues and generates a report of the vulnerabilities and threats it finds,
along with how to fix each one.

It fetches your site and inspects:

- **HTTPS enforcement** — is the site served over HTTPS, and does plain HTTP
  redirect to it?
- **TLS certificate** — validity, trust, hostname match, expiry, and protocol
  version (flags TLS 1.1 and below).
- **Security headers** — `Strict-Transport-Security` (HSTS),
  `Content-Security-Policy`, `X-Frame-Options` / `frame-ancestors`,
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`.
- **Cookies** — missing `Secure`, `HttpOnly`, and `SameSite` attributes.
- **CORS** — dangerous `Access-Control-Allow-Origin: *`, especially combined
  with credentials.
- **Information disclosure** — `Server` / `X-Powered-By` version banners.
- **Cross-origin isolation** — COOP / CORP / `X-Permitted-Cross-Domain-Policies`.
- **HTTP methods** — flags dangerous methods (TRACE / PUT / DELETE) via `OPTIONS`.
- **CORS Origin reflection** — server echoing arbitrary origins (critical with credentials).
- **Vulnerable JS libraries** — known-vulnerable jQuery/Angular/lodash/etc. versions.
- **CSRF** — POST forms without an anti-CSRF token.
- **Exposed API surface** (with `--probe-paths`) — Swagger/OpenAPI, GraphQL
  introspection, Spring actuator, metrics endpoints.
- **DNSSEC** (with `--dns`) — flags domains without DNSSEC.
- **Content integrity** (can the page/data be altered?) — mixed content
  (HTTP resources on an HTTPS page), third-party scripts without Subresource
  Integrity, and forms that submit over plain HTTP.
- **Secret exposure** (is an API key extractable?) — scans the served
  HTML/JavaScript for exposed API keys, tokens, and private keys (AWS, Google,
  Stripe, GitHub, Slack, JWTs, generic `api_key = "…"`). Matches are
  **redacted** in the report so it never leaks the secret itself.
- **Exposed sensitive paths** (optional) — probes for `/.git/`, `/.env`,
  database/backup dumps, `server-status`, `phpinfo`, `.DS_Store`, directory
  listing, and whether `security.txt` / `mta-sts` policies are published.
- **DNS & email** (optional) — checks SPF, DMARC and CAA records for the domain
  (email-spoofing and certificate-issuance protection), via a built-in DNS
  resolver (no dependencies).
- **Active probes** (optional, opt-in) — sends crafted requests to detect
  **open redirects**, **reflected input** (reflected-XSS signal), **SQL
  injection** (error/boolean-based, non-destructive), and **template
  injection**. These are signals for manual confirmation, not an exploitation
  engine.
- **Malware / compromise indicators** — passively scans the served HTML/JS for
  signs the site is hacked: in-browser cryptominers, obfuscated `eval`, hidden
  external iframes, and web-shell patterns.
- **Outdated components** — heuristic flag when disclosed software versions
  (Server / X-Powered-By / jQuery) are end-of-life and likely to carry CVEs.

It can scan just the entry URL, or **crawl multiple same-origin pages** so
content and secret checks cover more than the home page.

Each issue is reported as a **finding** with a severity
(`critical` → `info`), an explanation, supporting evidence, and a concrete
recommendation.

Every scan also produces a **scorecard**: a full checklist of *all* controls —
not just the failing ones — with a **safe / review / unsafe** verdict and a
score (0–100) per check, plus a weighted **overall score** and letter grade.
Reports can be downloaded as a self-contained HTML file (or JSON).

Reports also explain **how each issue could be exploited** — a plain-language
attacker's-eye view of the harm each finding enables — plus an overall
**"How this site could be harmed"** summary that synthesises the findings into
the concrete ways someone could attack the site.

Every finding carries standardised metadata: a **CWE** id, its **OWASP Top 10**
category, a **confidence** level (firm / tentative), reference links, and an
**indicative CVSS** band. Reports export as text, JSON, self-contained HTML, or
**SARIF 2.1.0** (`--format sarif`) for GitHub code scanning / CI dashboards.

> ⚠️ **Only scan sites you own or are authorised to test.** This tool makes
> ordinary HTTP requests to the target, but you are responsible for having
> permission to assess it.

## Install

Requires Python 3.9+. No third-party dependencies.

```bash
python -m pip install -e .
```

## Web UI

Prefer a point-and-click interface? Launch the built-in web app:

```bash
security-analyser serve
# Security Analyser web UI running at http://127.0.0.1:8000/
```

Then open http://127.0.0.1:8000 in your browser, type a URL, and hit **Scan**.
You get a letter **risk grade (A–F)**, clickable severity cards to filter
findings, a search box, and one-click **JSON export** / **print**. It has a
light and dark theme and works on mobile.

The server binds to **localhost only** by default. Because the scanner makes
outbound requests to whatever URL it is given, avoid exposing it on a public
interface (`--host 0.0.0.0`) where others could use your host to probe other
sites.

```bash
security-analyser serve --host 127.0.0.1 --port 8080
```

### Want a shareable / hosted link?

See **[DEPLOY.md](DEPLOY.md)** for three options: run locally (private), a
temporary public tunnel, or a permanent hosted URL (a `Dockerfile` and
`render.yaml` blueprint are included for one-click deploys).

## Command-line usage

```bash
# Text report to the terminal
security-analyser scan https://your-website.com

# Machine-readable JSON
security-analyser scan https://your-website.com --format json

# A shareable, self-contained HTML report
security-analyser scan https://your-website.com --format html --output report.html
```

Options:

| Option | Description |
|--------|-------------|
| `-f, --format {text,json,html}` | Output format (default `text`). |
| `-o, --output PATH` | Write the report to a file instead of stdout. |
| `--timeout SECONDS` | Network timeout (default 15). |
| `--insecure` | Don't verify the TLS certificate when fetching (still reported as a finding). |
| `--fail-on {critical,high,medium,low,info}` | Exit non-zero when a finding at this severity or higher exists (default `high`). Handy for CI gates. |
| `--max-pages N` | Crawl up to N same-origin pages, scanning each for content issues (default `1` = only the given URL). |
| `--depth N` | Maximum link depth to follow while crawling (default `1`). |
| `--probe-paths` | Probe for exposed sensitive files: `/.git/`, `/.env`, backups, `server-status`, `security.txt`, etc. |
| `--dns` | Check SPF, DMARC and CAA DNS records for the domain. |
| `--active` | Run active probes (open redirect, reflected input). **Only on sites you own.** |
| `--header NAME:VALUE` | Extra request header for authenticated scans (repeatable). |
| `--cookie "a=1; b=2"` | Cookie header to send for authenticated scans. |
| `--respect-robots` | Honour `robots.txt` Disallow rules while crawling. |
| `--delay SECONDS` | Wait between page fetches while crawling (politeness). |

### Scanning more than the home page

```bash
# Crawl up to 20 same-origin pages and probe for exposed files
security-analyser scan https://your-website.com --max-pages 20 --probe-paths
```

Content checks (secrets, mixed content, SRI, insecure forms) run on **every**
crawled page, and each finding is attributed to the page it was found on.
Header/TLS/cookie checks run on the entry page. In the web UI, use the
**Crawl pages** and **Probe sensitive paths** toggles.

### Exit codes

- `0` — scan completed, nothing at/above the `--fail-on` threshold.
- `1` — a finding at/above the threshold was found.
- `2` — the target could not be reached, or the report could not be written.

### Example

```
$ security-analyser scan https://example.com
======================================================================
SECURITY ANALYSER REPORT
======================================================================
Target      : https://example.com/
TLS         : TLSv1.3 [verified], expires in 84d
Summary     : 0 critical, 0 high, 3 medium, 2 low, 1 info
----------------------------------------------------------------------
[1] MEDIUM   Missing Content-Security-Policy header
    Category : Security headers  (id: HDR-CSP)
    Issue    : A Content-Security-Policy is a primary defence against XSS ...
    Fix      : Define a restrictive Content-Security-Policy ...
```

## Use in CI

Fail a pipeline when a high-or-worse issue appears:

```bash
security-analyser scan https://staging.your-website.com --fail-on high
```

## Project layout

```
src/security_analyser/
├── __init__.py     # package API (exposes scan(), models)
├── model.py        # Finding, Severity, Cookie, TlsInfo, ScanContext, ScanResult
├── fetch.py        # network layer: fetch, cookie parsing, TLS inspection
├── checks.py       # the security checks (one function per rule)
├── content_checks.py # per-page content checks (mixed content, SRI, secrets)
├── crawler.py      # multi-page same-origin crawling + aggregation
├── paths.py        # sensitive-path probing (.git, .env, backups, ...)
├── audit.py        # scorecard: per-control verdict + scores
├── scanner.py      # orchestration: fetch -> context -> run checks
├── report.py       # text / JSON / HTML renderers + shared payload builder
├── web.py          # stdlib web server + /api/scan endpoint
├── static/         # self-contained single-page UI (HTML/CSS/JS)
└── cli.py          # command-line entry point (scan + serve)
tests/              # unit tests (no network required)
```

## Extending it with new checks

Every rule lives in `checks.py` as a function that takes a `ScanContext` and
returns a list of `Finding`. To add a check, write the function and append it
to `ALL_CHECKS`:

```python
def check_x_download_options(ctx: ScanContext) -> list[Finding]:
    if ctx.headers.has("X-Download-Options"):
        return []
    return [Finding(
        id="HDR-XDO",
        title="Missing X-Download-Options header",
        severity=Severity.INFO,
        category="Security headers",
        description="...",
        recommendation="Add 'X-Download-Options: noopen'.",
    )]

ALL_CHECKS.append(check_x_download_options)
```

## Development

```bash
python -m pip install -r requirements-dev.txt
python -m ruff check .
python -m pytest -q
```

## License

Released under the [MIT License](LICENSE).
