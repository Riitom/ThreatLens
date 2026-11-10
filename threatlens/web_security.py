"""Passive web-security assessment from the response the page already gave us,
plus an opt-in, authorisation-gated check for exposed files."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from . import netsafe
from .content_analyzer import PageInfo
from .models import Finding

SESSION_COOKIE = re.compile(r"sess|sid|token|auth|jwt|login|csrf|xsrf", re.I)

# (regex, predicate on the match, label). Upstream end-of-life; distributions may backport fixes.
EOL_RULES = [
    (re.compile(r"Apache/(\d+)\.(\d+)"), lambda m: (int(m[1]), int(m[2])) < (2, 4), "Apache"),
    (re.compile(r"PHP/(\d+)\.(\d+)"), lambda m: (int(m[1]), int(m[2])) < (8, 2), "PHP"),
    (re.compile(r"Microsoft-IIS/(\d+)"), lambda m: int(m[1]) < 10, "IIS"),
    (re.compile(r"OpenSSL/(\d+)\.(\d+)\.(\d+)"), lambda m: (int(m[1]), int(m[2]), int(m[3])) < (1, 1, 1), "OpenSSL"),
    (re.compile(r"Python/(\d+)"), lambda m: int(m[1]) < 3, "Python"),
]


def analyze_headers(res: netsafe.FetchResult, page: PageInfo | None) -> tuple[list[Finding], list[dict]]:
    findings: list[Finding] = []
    table: list[dict] = []
    if res.status is None:
        return findings, table
    h = res.headers
    https = res.final_url.startswith("https://")

    def add(fid, sev, title, detail="", advice="", pw=None, axis="posture"):
        findings.append(Finding(f"sec.{fid}", "security", axis, sev, title, detail, advice, weight=0, posture_weight=pw))

    def row(name, status, note=""):
        v = h.get(name.lower())
        table.append({"name": name, "present": v is not None, "value": (v or "")[:220], "status": status, "note": note})

    if not https:
        add("plain_http", "high", "Site is served over plain HTTP", "Traffic can be read and altered in transit.",
            "Serve everything over HTTPS and redirect HTTP to it.", pw=25)

    # HSTS
    hsts = h.get("strict-transport-security")
    if https:
        if not hsts:
            add("no_hsts", "medium", "Strict-Transport-Security header is missing",
                "Browsers can be tricked into using HTTP on first visit.", "Send Strict-Transport-Security with a max-age of at least 15552000.", pw=10)
            row("Strict-Transport-Security", "fail", "Missing")
        else:
            m = re.search(r"max-age=(\d+)", hsts, re.I)
            age = int(m.group(1)) if m else 0
            if age < 15_552_000:
                add("short_hsts", "low", f"HSTS max-age is short ({age}s)", pw=4)
            row("Strict-Transport-Security", "pass" if age >= 15_552_000 else "warn",
                "" if age >= 15_552_000 else "max-age under 180 days")
    else:
        row("Strict-Transport-Security", "info", "Only applies to HTTPS")

    # CSP
    csp = h.get("content-security-policy")
    directives = {}
    for directive in (csp or "").split(";"):
        tokens = directive.strip().split()
        if tokens:
            directives.setdefault(tokens[0].lower(), tokens[1:])
    if not csp:
        add("no_csp", "medium", "Content-Security-Policy header is missing",
            "Without a policy, injected scripts run freely.", "Start with default-src 'self' and tighten from there.", pw=12)
        row("Content-Security-Policy", "fail", "Missing")
    else:
        script_sources = directives.get("script-src", directives.get("default-src"))
        weak = script_sources is None or bool(set(script_sources) & {"*", "'unsafe-inline'", "'unsafe-eval'", "http:", "https:"})
        if weak:
            add("weak_csp", "low", "Content-Security-Policy allows unsafe script sources", pw=5)
        row("Content-Security-Policy", "warn" if weak else "pass", "Script restrictions are missing or permissive" if weak else "")

    # Clickjacking
    ancestors = directives.get("frame-ancestors")
    if ancestors is not None:
        # An enforcing CSP frame-ancestors directive takes precedence over XFO.
        frame_protected = bool(ancestors) and not bool(set(ancestors) & {"*", "http:", "https:", "data:", "blob:"})
    else:
        frame_protected = (h.get("x-frame-options") or "").strip().upper() in {"DENY", "SAMEORIGIN"}
    if frame_protected:
        row("X-Frame-Options", "pass", "Covered by frame protection")
    else:
        add("no_frame_protection", "low", "Page can be embedded in other sites (clickjacking)",
            advice="Send X-Frame-Options or CSP frame-ancestors.", pw=6)
        row("X-Frame-Options", "fail", "Missing")

    if (h.get("x-content-type-options") or "").lower() != "nosniff":
        add("no_nosniff", "low", "X-Content-Type-Options: nosniff is missing", pw=5)
        row("X-Content-Type-Options", "fail", "Missing")
    else:
        row("X-Content-Type-Options", "pass")
    if not h.get("referrer-policy"):
        add("no_referrer_policy", "low", "Referrer-Policy header is missing", "Full URLs may leak to other sites.", pw=3)
        row("Referrer-Policy", "fail", "Missing")
    else:
        row("Referrer-Policy", "pass")
    if not h.get("permissions-policy"):
        add("no_permissions_policy", "info", "Permissions-Policy header is missing", pw=2)
        row("Permissions-Policy", "info", "Missing")
    else:
        row("Permissions-Policy", "pass")

    # Cross-Origin Policies
    coop = h.get("cross-origin-opener-policy")
    if coop:
        row("Cross-Origin-Opener-Policy", "pass", coop[:60])
    else:
        row("Cross-Origin-Opener-Policy", "info", "Not configured")

    corp = h.get("cross-origin-resource-policy")
    if corp:
        row("Cross-Origin-Resource-Policy", "pass", corp[:60])
    else:
        row("Cross-Origin-Resource-Policy", "info", "Not configured")

    # CORS
    if h.get("access-control-allow-origin") == "*" and (h.get("access-control-allow-credentials") or "").lower() == "true":
        add("cors_wildcard_creds", "medium", "CORS allows any origin together with credentials",
            "Browsers reject this combination, which points to a confused CORS configuration.", pw=8)

    # Technology disclosure and end-of-life software
    banner = " ".join(filter(None, [h.get("server"), h.get("x-powered-by"), h.get("x-aspnet-version")]))
    if banner and re.search(r"\d+\.\d+", banner):
        add("version_disclosure", "low", "Server discloses software versions", banner[:120],
            "Hide version numbers from response headers.", pw=3)
    for rx, is_old, label in EOL_RULES:
        m = rx.search(banner)
        if m and is_old(m):
            add("eol_software", "high", f"{label} version looks end-of-life ({m.group(0)})",
                "The upstream project no longer ships security fixes for this version. Some distributions backport fixes, so verify.",
                f"Upgrade {label} to a supported release.", pw=15)
    # Cookies
    for raw in res.set_cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0]
        attrs = {p.split("=", 1)[0].lower() for p in parts[1:]}
        sessionish = bool(SESSION_COOKIE.search(name))
        if https and "secure" not in attrs:
            add(f"cookie_secure_{name}", "medium" if sessionish else "low", f"Cookie '{name}' lacks the Secure flag",
                "It can be sent over unencrypted connections.", pw=6 if sessionish else 2)
        if sessionish and "httponly" not in attrs:
            add(f"cookie_httponly_{name}", "medium", f"Cookie '{name}' lacks HttpOnly", "Scripts can read it, so XSS can steal the session.", pw=6)
        if "samesite" not in attrs:
            add(f"cookie_samesite_{name}", "low", f"Cookie '{name}' has no SameSite attribute", pw=2)

    # Mixed content
    if https and page is not None:
        active = [u for k, u in page.resources if k in ("script", "css", "iframe", "object") and u.lower().startswith("http://")]
        passive = [u for k, u in page.resources if k == "img" and u.lower().startswith("http://")]
        if active:
            add("mixed_active", "high", f"{len(active)} script/style/frame resources load over HTTP", active[0][:120],
                "Load every resource over HTTPS.", pw=15)
        elif passive:
            add("mixed_passive", "low", f"{len(passive)} images load over HTTP", passive[0][:120], pw=4)
    return findings, table


# --------------------------------------------------------------------------- active exposure checks
EXPOSURES = [
    ("/.git/HEAD", lambda b: b.startswith("ref:"), "critical", "Git repository is publicly readable",
     "Source code and secrets in history can be downloaded.", 30),
    ("/.env", lambda b: bool(re.search(r"^[A-Z][A-Z0-9_]{2,}=.+", b, re.M)) and "<html" not in b[:300].lower(),
     "critical", "Environment file is publicly readable", "It usually holds API keys and database passwords.", 30),
    ("/server-status", lambda b: "Apache Server Status" in b, "medium", "Apache server-status page is public",
     "Reveals live requests and client addresses.", 10),
    ("/phpinfo.php", lambda b: "phpinfo()" in b or "PHP Version" in b, "high", "phpinfo() page is public",
     "Discloses configuration, paths and modules.", 15),
]


def check_exposures(url: str) -> list[Finding]:
    """GET a handful of well-known sensitive paths. Only call with the site owner's authorisation."""
    p = urlsplit(url)
    base = f"{p.scheme}://{p.netloc}"
    out: list[Finding] = []
    for path, predicate, sev, title, detail, pw in EXPOSURES:
        r = netsafe.safe_fetch(urljoin(base, path))
        if r.status == 200 and r.body and predicate(r.body[:20000]):
            out.append(Finding(f"sec.exposed{path.replace('/', '_')}", "security", "posture", sev, title, detail,
                               f"Remove or block {path} on the web server.", weight=0, posture_weight=pw))
    return out
