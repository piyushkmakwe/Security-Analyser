"""Attack scenarios and impact narratives.

For each finding this module supplies a plain-language "how an attacker could
exploit this" explanation, and it synthesises an overall attack-surface summary
for the whole scan. The goal is defensive: help the site owner understand the
real-world impact of each issue. These are impact descriptions, not exploit
instructions.
"""

from __future__ import annotations

from typing import Dict, List

# finding id -> how an attacker abuses it, and the harm that results.
_SCENARIOS: Dict[str, str] = {
    # Transport
    "HTTPS-001": (
        "An attacker on the same network (public Wi-Fi, a compromised router, a "
        "malicious ISP) can read and modify traffic in transit — stealing login "
        "credentials and session cookies, or injecting malicious content into pages."
    ),
    "HTTPS-002": (
        "A victim who types the bare domain is served over HTTP first; an attacker "
        "can intercept that request and keep the victim on a spoofed HTTP version "
        "(SSL stripping) to harvest credentials."
    ),
    "HDR-REDIRECT-DOWNGRADE": (
        "Because the redirect chain passes through HTTP, an attacker can intercept "
        "that hop and hijack the request before it reaches HTTPS."
    ),
    "TLS-INVALID": (
        "With an untrusted certificate, users are trained to click through warnings, "
        "and an attacker can present their own certificate to run a man-in-the-middle "
        "attack and decrypt all traffic."
    ),
    "TLS-EXPIRED": (
        "An expired certificate breaks trust; attackers can exploit the confusion to "
        "impersonate the site, and browsers may block legitimate users."
    ),
    "TLS-EXPIRING": (
        "If the certificate lapses, the site becomes unreachable and users are exposed "
        "to impersonation during the outage window."
    ),
    "TLS-PROTOCOL": (
        "Old TLS/SSL versions have known cryptographic breaks (e.g. BEAST, POODLE) that "
        "let a network attacker decrypt or tamper with the session."
    ),
    # HSTS / headers
    "HDR-HSTS": (
        "Without HSTS, the first visit happens over HTTP, giving an attacker a window "
        "to downgrade the connection and strip TLS before the browser upgrades."
    ),
    "HDR-HSTS-MAXAGE": "A short HSTS lifetime shrinks the protection window, leaving repeat downgrade openings.",
    "HDR-HSTS-SUBDOMAINS": "Subdomains stay reachable over HTTP, so an attacker can plant a rogue subdomain and steal cookies scoped to the parent domain.",
    "HDR-HSTS-PRELOAD": "Until preloaded, the very first request to the site can still be downgraded by an attacker.",
    "HDR-CSP": (
        "With no Content-Security-Policy, any injected script (via XSS) runs freely — "
        "an attacker can steal session tokens, log keystrokes, or rewrite the page to "
        "phish users."
    ),
    "HDR-CSP-UNSAFE": "'unsafe-inline'/'unsafe-eval' let injected inline scripts execute, so the CSP no longer stops XSS payloads.",
    "HDR-CSP-WILDCARD": "A wildcard source lets an attacker host malicious JavaScript anywhere and have it load within your page's trust context.",
    "HDR-CSP-HTTP": "Allowing http: sources lets a network attacker swap a script in transit and execute code on your page.",
    "HDR-CSP-DIRECTIVES": "Without object-src/base-uri, an attacker can inject a <base> tag or plugin content to hijack relative URLs and script loading.",
    "HDR-XFO": (
        "The page can be framed on an attacker's site and overlaid with invisible "
        "controls (clickjacking), tricking a logged-in user into performing actions "
        "such as changing settings or making payments."
    ),
    "HDR-XCTO": "Without nosniff, the browser may execute an uploaded/user-controlled file as script, turning a file upload into stored XSS.",
    "HDR-REFPOL": "Full referrer URLs leak to third parties, exposing session tokens or private identifiers embedded in URLs.",
    "HDR-PERMPOL": "Powerful features (camera, mic, geolocation) stay enabled, so an XSS or malicious embed can silently abuse them.",
    "HDR-CACHE-SESSION": "A shared cache (proxy, CDN, browser) may store an authenticated page and serve one user's private content to another.",
    # Cookies
    "COOKIE-SECURE": "The cookie is sent over plain HTTP too, so a network attacker can sniff the session token and hijack the account.",
    "COOKIE-HTTPONLY": "JavaScript can read the cookie, so a single XSS flaw lets an attacker exfiltrate the session token and impersonate the user.",
    "COOKIE-SAMESITE": "The cookie rides along on cross-site requests, enabling CSRF — an attacker's page can trigger state-changing actions as the victim.",
    "COOKIE-HOST-PREFIX": "The prefix guarantee is void, so a subdomain or network attacker can overwrite (fixate) the cookie.",
    "COOKIE-SECURE-PREFIX": "Browsers reject the cookie, and its Secure guarantee is not enforced, exposing it over HTTP.",
    "COOKIE-DOMAIN-SCOPE": "Sharing the cookie with every subdomain means a single vulnerable subdomain can leak or fixate it.",
    # CORS
    "CORS-WILDCARD-CREDS": (
        "Any website can make authenticated requests to your API and read the responses "
        "— an attacker's page can silently pull a logged-in victim's private data."
    ),
    "CORS-WILDCARD": "Any origin can read the response, so any user-specific data returned here is exposed to malicious sites.",
    # Info disclosure / versions
    "INFO-SERVER": "The disclosed version lets an attacker look up matching public exploits and target known vulnerabilities directly.",
    "INFO-POWEREDBY": "Advertising the framework/version hands attackers a shortlist of applicable CVEs to try.",
    "VERSION-OUTDATED": "End-of-life software commonly has public, weaponised exploits; an attacker can match the version to a known CVE and take over the server.",
    # Content integrity
    "INTEGRITY-MIXED-ACTIVE": "A network attacker rewrites the HTTP-loaded script in transit and runs arbitrary code in your page — full account/session compromise.",
    "INTEGRITY-MIXED-PASSIVE": "A network attacker can swap images/media to deface the page or drop the secure-connection indicator.",
    "INTEGRITY-SRI": "If the third-party/CDN is compromised, the altered script executes on your site with full access to your users' sessions (a supply-chain attack).",
    "INTEGRITY-FORM-HTTP": "Credentials submitted through the form travel in cleartext and are read or altered by anyone on the network path.",
    # Secrets
    "SECRET-AWS-KEY": "An attacker uses the leaked AWS key to access or destroy your cloud resources and data, and to run up costs.",
    "SECRET-AWS-SECRET": "The AWS secret grants direct programmatic access to your cloud account — data theft, resource abuse and lateral movement.",
    "SECRET-GOOGLE-API": "The API key can be abused to run up billing or access the associated Google services under your account.",
    "SECRET-GOOGLE-OAUTH": "The OAuth client secret lets an attacker impersonate your application and phish user authorisations.",
    "SECRET-STRIPE-SECRET": "A live Stripe secret key lets an attacker issue refunds, read customers, and move money from your account.",
    "SECRET-STRIPE-PUB": "Publishable keys are meant to be public — low risk, but confirm it is not the secret key.",
    "SECRET-GITHUB": "The token grants access to your repositories/CI — an attacker can steal source, inject backdoors, or pivot into your infrastructure.",
    "SECRET-SLACK": "The Slack token lets an attacker read messages and impersonate the app inside your workspace.",
    "SECRET-PRIVATE-KEY": "With the private key an attacker can decrypt traffic, impersonate the server, or sign malicious artifacts.",
    "SECRET-JWT": "If the token is a live session/credential, an attacker replays it to access the account it belongs to.",
    "SECRET-GENERIC": "If this is a real credential, an attacker copies it straight from the page source and uses it to access the protected system.",
    # Paths
    "PATH-GIT": "An attacker downloads the exposed .git directory, reconstructs your entire source code and history, and mines it for secrets and logic flaws.",
    "PATH-ENV": "The .env file hands an attacker your database passwords, API keys and app secrets directly — often a full compromise.",
    "PATH-SVN": "The exposed VCS metadata lets an attacker recover source code and secrets.",
    "PATH-BACKUP": "The downloadable backup/dump gives an attacker your source or entire database contents (users, password hashes, PII).",
    "PATH-WPCONFIG": "The config backup contains database credentials, giving an attacker direct database access.",
    "PATH-SERVER-STATUS": "server-status reveals live request URLs and client IPs, aiding session hijacking and reconnaissance.",
    "PATH-PHPINFO": "phpinfo() exposes paths, modules and configuration that an attacker uses to tailor an exploit.",
    "PATH-DSSTORE": "The .DS_Store file leaks hidden file and directory names an attacker then requests directly.",
    "PATH-DIRLISTING": "Directory listing hands an attacker a map of files to download, including ones not meant to be public.",
    "PATH-MTASTS": "Without MTA-STS, inbound mail can be downgraded and intercepted by a network attacker.",
    "PATH-SECURITYTXT": "Not directly exploitable, but researchers have no clear way to report issues, slowing your response to real attacks.",
    # DNS / email
    "DNS-SPF": "Without SPF, an attacker can send email that appears to come from your domain (spoofing/phishing your users and staff).",
    "DNS-DMARC": "Without DMARC, spoofed email from your domain is not detected or rejected, enabling convincing phishing.",
    "DNS-CAA": "Without CAA, any CA can be tricked into issuing a certificate for your domain, aiding man-in-the-middle attacks.",
    # Active
    "ACTIVE-OPEN-REDIRECT": "An attacker crafts a link on your trusted domain that bounces victims to a phishing site, lending it your site's credibility.",
    "ACTIVE-REFLECTED-INPUT": "An attacker crafts a URL that injects script into the page for anyone who clicks it (reflected XSS) — stealing sessions or acting as the victim.",
    "ACTIVE-SQLI": "An attacker injects SQL through the parameter to read, alter or delete your entire database — dumping user records, password hashes and PII, or bypassing login.",
    "ACTIVE-SSTI": "An attacker injects a template expression that the server evaluates, typically escalating to remote code execution and full server takeover.",
    # Isolation / methods / CORS reflection / CSRF / JS libs / API surface / DNSSEC
    "HDR-ISOLATION-COOP": "A cross-origin page that opens yours keeps a window handle to it, enabling cross-window scripting and side-channel (Spectre) data leaks.",
    "HDR-ISOLATION-CORP": "Other origins can embed your resources and probe them via speculative-execution side channels to read cross-origin data.",
    "HDR-ISOLATION-XPCDP": "Legacy Flash/PDF clients may fetch a cross-domain policy and use it to reach your site's data from another origin.",
    "HDR-METHODS": "An attacker uses the enabled method (TRACE for cross-site tracing, or PUT/DELETE) to steal headers or upload/delete files on the server.",
    "CORS-REFLECT-CREDS": "Because the server reflects any origin and allows credentials, an attacker's page reads a logged-in victim's private data cross-origin.",
    "CORS-REFLECT": "Any site can read responses from this endpoint, exposing any user-specific data it returns.",
    "CORS-NULL-ORIGIN": "An attacker obtains a 'null' origin from a sandboxed iframe and reads a logged-in victim's data cross-origin.",
    "CORS-BYPASS": "An attacker registers a domain that satisfies the flawed origin check and reads authenticated cross-origin responses.",
    "JWT-ALG-NONE": "If the server trusts 'alg: none' tokens, an attacker forges a token with any identity/claims and logs in as any user.",
    "SCAN-INCOMPLETE": "Not an attacker action — a warning that a WAF or rate limiter may have blocked checks, so a clean result cannot be trusted without re-scanning.",
    "FORM-CSRF": "An attacker's page auto-submits this form using the victim's session cookie, performing state-changing actions (CSRF) as the victim.",
    "JSLIB-OUTDATED": "An attacker exploits the library's public vulnerability (often XSS or prototype pollution) to run code in your users' browsers.",
    "PATH-SWAGGER": "The exposed API schema hands an attacker a complete map of endpoints and parameters to attack.",
    "PATH-GRAPHQL": "Introspection reveals the whole GraphQL schema, letting an attacker discover sensitive queries and mutations to abuse.",
    "PATH-ACTUATOR": "Actuator endpoints leak environment variables, config and internals — often including secrets — for direct use in an attack.",
    "PATH-METRICS": "Metrics expose internal operational details that help an attacker profile and target the system.",
    "DNS-DNSSEC": "Without DNSSEC, an attacker who can poison DNS responses redirects your users to attacker-controlled servers.",
    "DNS-AXFR": "An attacker performs a zone transfer to download every DNS record, revealing internal hosts, staging servers and infrastructure to target next.",
    "DNS-SPF-ALL": "The permissive SPF lets an attacker send email as your domain that still passes SPF, powering convincing phishing.",
    "DNS-DMARC-WEAK": "With DMARC set to p=none, spoofed email is reported but still delivered, so phishing using your domain reaches inboxes.",
    "TLS-PROTO-OLD": "A network attacker forces a downgrade to the legacy TLS version and exploits its known weaknesses to decrypt or tamper with traffic.",
    "TLS-CIPHER-WEAK": "The weak cipher lets a capable network attacker decrypt intercepted traffic, exposing credentials and session data.",
    "INFO-DEBUG": "The exposed debugger/debug mode leaks source and configuration and can often be driven directly to execute code on the server.",
    "INFO-STACKTRACE": "The stack trace reveals file paths, library versions and internal logic that an attacker uses to craft a targeted exploit.",
    # Malware / compromise
    "MALWARE-MINER": "Visitors' CPUs are hijacked to mine cryptocurrency for the attacker; its presence means your site is already compromised and serving attacker code.",
    "MALWARE-EVAL": "Obfuscated injected JavaScript runs in every visitor's browser — it can redirect users, steal data, or push malware, and indicates the site is hacked.",
    "MALWARE-WEBSHELL": "A web shell gives the attacker a remote command channel into your server — effectively full control of the host.",
    "MALWARE-IFRAME": "The hidden iframe silently loads an attacker's page in every visitor's browser to deliver drive-by malware or redirects.",
}

_FALLBACK = "An attacker can leverage this weakness to move closer to compromising the site or its users."


def attack_scenario(finding: dict) -> str:
    """Return the exploit/impact narrative for a finding dict."""
    return _SCENARIOS.get(finding.get("id", ""), _FALLBACK)


# High-level harm statements, keyed by finding id/prefix, for the summary.
# (matcher, harm sentence) — first matching finding contributes each harm once.
_HARM_THEMES = [
    (("SECRET-AWS", "SECRET-GOOGLE-OAUTH", "SECRET-STRIPE-SECRET", "SECRET-GITHUB",
      "SECRET-SLACK", "SECRET-PRIVATE-KEY", "SECRET-GENERIC", "PATH-ENV", "PATH-WPCONFIG"),
     "steal exposed credentials/keys and access your backend systems, cloud account or database"),
    (("PATH-GIT", "PATH-SVN", "PATH-BACKUP"),
     "download your source code or database and mine it for further weaknesses"),
    (("HTTPS-001", "HTTPS-002", "TLS-INVALID", "TLS-PROTOCOL", "HDR-REDIRECT-DOWNGRADE",
      "INTEGRITY-MIXED-ACTIVE", "INTEGRITY-FORM-HTTP"),
     "intercept or tamper with traffic on the network to capture credentials and sessions"),
    (("ACTIVE-SQLI",),
     "read, alter or dump your database via SQL injection (user records, password hashes, PII)"),
    (("ACTIVE-SSTI",),
     "run arbitrary code on your server via template injection, leading to full takeover"),
    (("MALWARE-",),
     "note that the site already appears compromised — injected code is served to your visitors right now"),
    (("HDR-CSP", "HDR-XCTO", "ACTIVE-REFLECTED-INPUT", "INTEGRITY-SRI"),
     "run malicious JavaScript in your users' browsers (XSS) to hijack their sessions"),
    (("COOKIE-SECURE", "COOKIE-HTTPONLY", "COOKIE-SAMESITE", "COOKIE-HOST-PREFIX",
      "COOKIE-SECURE-PREFIX"),
     "steal or forge session cookies to take over user accounts"),
    (("HDR-XFO",),
     "trick logged-in users into unintended actions via clickjacking"),
    (("CORS-WILDCARD", "CORS-WILDCARD-CREDS", "CORS-REFLECT"),
     "read your users' private data from other websites via permissive CORS"),
    (("FORM-CSRF",),
     "make victims' browsers submit state-changing requests without consent (CSRF)"),
    (("PATH-SWAGGER", "PATH-GRAPHQL", "PATH-ACTUATOR", "PATH-METRICS"),
     "map your API surface and internal endpoints from exposed docs/metrics"),
    (("HDR-METHODS",),
     "abuse dangerous HTTP methods (TRACE/PUT/DELETE) enabled on the server"),
    (("ACTIVE-OPEN-REDIRECT",),
     "abuse your trusted domain to make phishing links look legitimate"),
    (("DNS-SPF", "DNS-DMARC"),
     "spoof email from your domain to phish your users and staff"),
    (("VERSION-OUTDATED", "INFO-SERVER", "INFO-POWEREDBY"),
     "match your disclosed software versions to known public exploits"),
]


def build_attack_summary(findings: List[dict]) -> List[str]:
    """Synthesise a prioritised list of how the site could be harmed."""
    present = {f.get("id", "") for f in findings}
    summary: List[str] = []
    for matchers, harm in _HARM_THEMES:
        if any(any(fid.startswith(m) for m in matchers) for fid in present):
            summary.append(harm)
    return summary
