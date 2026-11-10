"""Page-content analysis: forms, scripts, iframes, redirects and scam language."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from . import domains
from .models import Finding
from .netsafe import FetchResult

SENSITIVE_PATTERNS = {
    "card": re.compile(r"card.?(number|no)|cc.?num|cvv|cvc|expir", re.I),
    "otp": re.compile(r"\botp\b|one.?time.?(pass|code)", re.I),
    "pin": re.compile(r"upi.?pin|\bmpin\b|atm.?pin|\bpin\b", re.I),
    "identity": re.compile(r"aadhaa?r|\bpan\b|\bssn\b|social.?security|passport", re.I),
    "bank": re.compile(r"account.?(number|no)|ifsc|routing", re.I),
}
URGENCY = re.compile(
    r"account (will be )?(suspended|locked|closed|blocked)|verify your (identity|account)|unusual (sign.?in|activity)|"
    r"within 24 hours|immediate action|your account has been (limited|compromised)|kyc (update|expired|pending)|"
    r"confirm your (identity|details)|failure to (verify|comply)", re.I)
JOB_WORDS = re.compile(r"job offer|offer letter|recruit|hiring|vacanc|placement|work from home|data entry", re.I)
FEE_WORDS = re.compile(
    r"registration fee|processing fee|security deposit|refundable|training fee|kit fee|pay (₹|rs\.?|inr|\$)\s?\d", re.I)
PAYMENT_TRICK = re.compile(
    r"enter (your )?(upi )?pin to receive|scan (the )?qr( code)? to receive|accept the collect request", re.I)
PRIZE_BAIT = re.compile(r"you have won|claim your (prize|reward)|lottery winner|double your (money|crypto|bitcoin)", re.I)
EDU_WORDS = re.compile(r"degree without (exam|class)|pay (exam|examination|admission) fee|hall ticket download fee|scholarship (processing|registration) fee|instant degree|guaranteed marks", re.I)
GOVT_SCAM_WORDS = re.compile(r"link (your )?aadhaar (with|to)|pan card (update|blocked|verify)|pm (kisan|yojna)|welfare grant approval|subsidy (claim|release)|income tax refund (approval|pending)", re.I)
APK_LURE_WORDS = re.compile(r"download (our )?(official |bank )?(security |kyc )?app|install (the )?apk|quicksupport|anydesk|teamviewer", re.I)
DOWNLOAD_EXT = re.compile(r"\.(apk|exe|scr|msi|iso|hta|bat|ps1|vbs|jar)(\?|$)", re.I)
JS_REDIRECT = re.compile(
    r"(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*['\"](https?://[^'\"]+)['\"]|"
    r"location\.(?:replace|assign)\(\s*['\"](https?://[^'\"]+)['\"]", re.I)
OBFUSCATION = {
    "eval": re.compile(r"\beval\s*\("),
    "atob": re.compile(r"\batob\s*\("),
    "unescape": re.compile(r"\bunescape\s*\("),
    "fromCharCode": re.compile(r"String\.fromCharCode"),
    "document.write": re.compile(r"document\.write\s*\("),
    "hex escapes": re.compile(r"(?:\\x[0-9a-fA-F]{2}){20,}"),
}


@dataclass
class PageInfo:
    title: str = ""
    text: str = ""
    forms: list = field(default_factory=list)
    inputs: list = field(default_factory=list)
    iframes: list = field(default_factory=list)
    scripts: list = field(default_factory=list)
    inline_js: str = ""
    links: list = field(default_factory=list)
    resources: list = field(default_factory=list)  # (kind, url)
    icons: list = field(default_factory=list)
    meta_refresh: str | None = None
    handlers: list = field(default_factory=list)
    base: str | None = None

    def public(self) -> dict:
        return {
            "title": self.title[:200], "forms": len(self.forms),
            "password_fields": sum(1 for i in self.inputs if i["type"] == "password"),
            "iframes": len(self.iframes), "scripts": len(self.scripts),
            "links": len(self.links), "text_chars": len(self.text),
        }


class _Parser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.p = PageInfo()
        self._form = None
        self._in_title = self._in_script = self._in_style = False
        self._script_buf: list[str] = []
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        for k, v in a.items():
            if k.startswith("on"):
                self.p.handlers.append((k, v.lower()[:80]))
        if tag == "title":
            self._in_title = True
        elif tag == "base" and a.get("href"):
            self.p.base = a["href"]
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "inputs": []}
            self.p.forms.append(self._form)
        elif tag in ("input", "textarea", "select"):
            inp = {"type": a.get("type", "text" if tag == "input" else tag).lower(),
                   "name": a.get("name", ""), "id": a.get("id", ""),
                   "placeholder": a.get("placeholder", ""), "autocomplete": a.get("autocomplete", "")}
            self.p.inputs.append(inp)
            if self._form is not None:
                self._form["inputs"].append(inp)
        elif tag == "script":
            self._in_script = True
            if a.get("src"):
                self.p.scripts.append(a["src"])
                self.p.resources.append(("script", a["src"]))
        elif tag == "style":
            self._in_style = True
        elif tag == "link":
            rel, href = a.get("rel", "").lower(), a.get("href", "")
            if "icon" in rel and href:
                self.p.icons.append(href)
            if "stylesheet" in rel and href:
                self.p.resources.append(("css", href))
        elif tag == "img" and a.get("src"):
            self.p.resources.append(("img", a["src"]))
        elif tag in ("iframe", "frame"):
            style = a.get("style", "").replace(" ", "").lower()
            size_small = any(a.get(d, "").strip().rstrip("px") in ("0", "1", "2") for d in ("width", "height"))
            hidden = "hidden" in a or size_small or "display:none" in style or "visibility:hidden" in style
            self.p.iframes.append({"src": a.get("src", ""), "hidden": hidden})
            if a.get("src"):
                self.p.resources.append(("iframe", a["src"]))
        elif tag == "a" and a.get("href"):
            self.p.links.append(a["href"])
        elif tag in ("embed", "object"):
            src = a.get("src") or a.get("data")
            if src:
                self.p.resources.append(("object", src))
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", a.get("content", ""), re.I)
            if m:
                self.p.meta_refresh = m.group(1).strip()

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None
        elif tag == "script":
            self._in_script = False
            self.p.inline_js += "\n".join(self._script_buf)[:200_000] + "\n"
            self._script_buf = []
        elif tag == "style":
            self._in_style = False

    def handle_data(self, data):
        if self._in_title:
            self.p.title += data
        elif self._in_script:
            self._script_buf.append(data)
        elif not self._in_style and len(self._text) < 4000:
            self._text.append(data)


def parse_html(html: str) -> PageInfo:
    parser = _Parser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # malformed markup should never break a scan
        pass
    page = parser.p
    page.title = re.sub(r"\s+", " ", page.title).strip()
    page.text = re.sub(r"\s+", " ", " ".join(parser._text)).strip()[:30_000]
    return page


def _host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def _reg(url: str) -> str:
    h = _host_of(url)
    return domains.registered_domain(h) if h else ""


def analyze_content(res: FetchResult, features: dict) -> tuple[list[Finding], PageInfo | None]:
    findings: list[Finding] = []

    def add(fid, sev, title, detail="", advice="", weight=None):
        findings.append(Finding(f"content.{fid}", "content", "threat", sev, title, detail, advice, weight))

    if res.error and not res.body:
        add("unreachable", "info", "Page could not be fetched", res.error)
        return findings, None

    # ---- redirect chain ------------------------------------------------------
    if res.redirects:
        regs = [_reg(res.url)] + [_reg(r["to"]) for r in res.redirects]
        distinct = list(dict.fromkeys(r for r in regs if r))
        if len(distinct) >= 3:
            add("redirect_hops", "medium", f"Redirects through {len(distinct)} different domains",
                " → ".join(distinct), weight=18)
        elif len(distinct) == 2 and features.get("registered_domain") != _reg(res.final_url):
            add("redirect_cross_domain", "low", "Link redirects to a different domain",
                f"{distinct[0]} → {distinct[-1]}")

    if res.status and res.status >= 400:
        add("http_error", "info", f"Server answered HTTP {res.status}")
    if not res.body or "html" not in res.content_type.lower() and "<html" not in res.body[:2000].lower():
        return findings, None

    page = parse_html(res.body)
    page_url = res.final_url
    page_reg = _reg(page_url)
    page_host = _host_of(page_url)
    pw_inputs = [i for i in page.inputs if i["type"] == "password"]
    sensitive_kinds = set()
    for i in page.inputs:
        blob = " ".join([i["name"], i["id"], i["placeholder"], i["autocomplete"]])
        for kind, rx in SENSITIVE_PATTERNS.items():
            if rx.search(blob):
                sensitive_kinds.add(kind)
    collects_secrets = bool(pw_inputs or sensitive_kinds)

    if pw_inputs:
        add("password_field", "info", "Page asks for a password")
    if sensitive_kinds:
        add("sensitive_fields", "medium", "Page collects sensitive data: " + ", ".join(sorted(sensitive_kinds)),
            "Card, PIN, OTP and ID fields are what credential-harvesting pages are built to capture.", weight=15)

    # ---- where do forms send data? ------------------------------------------
    bad_forms = set()
    for form in page.forms:
        action = (form["action"] or "").strip()
        has_secret = any(i["type"] == "password" for i in form["inputs"]) or any(
            rx.search(" ".join([i["name"], i["id"], i["placeholder"]])) for i in form["inputs"] for rx in SENSITIVE_PATTERNS.values())
        if not has_secret:
            continue
        if action.lower().startswith("mailto:"):
            bad_forms.add(("mailto", action))
            continue
        if action.lower().startswith("javascript:"):
            continue
        target = urljoin(page.base or page_url, action) if action else page_url
        t_host, t_scheme = _host_of(target), urlsplit(target).scheme
        if t_host and domains.registered_domain(t_host) != page_reg:
            bad_forms.add(("cross", target))
        elif page_url.startswith("https://") and t_scheme == "http":
            bad_forms.add(("downgrade", target))
    for kind, target in sorted(bad_forms):
        if kind == "cross":
            add("form_cross_domain", "high", "Login or payment form sends data to another domain",
                f"This page is on {page_reg} but the form submits to {_host_of(target)}.",
                "Never enter credentials here; the form sends them somewhere you did not visit.")
        elif kind == "mailto":
            add("form_mailto", "high", "Form emails your details instead of submitting to a server", target[:120])
        else:
            add("form_downgrade", "high", "Form on an HTTPS page submits over plain HTTP", target[:120])

    # ---- brand claims --------------------------------------------------------
    haystack = (page.title + " " + page.text[:6000]).lower()
    claimed = []
    for brand in domains.brands():
        if domains.host_belongs_to(page_host, brand):
            continue
        in_title = any(re.search(rf"\b{re.escape(k)}\b", page.title.lower()) for k in brand["keywords"])
        mentions = sum(len(re.findall(rf"\b{re.escape(k)}\b", haystack)) for k in brand["keywords"])
        if in_title or mentions >= 3:
            claimed.append(brand["name"])
    expected = features.get("impersonated_brand")
    if expected and expected not in claimed and expected.lower() in haystack:
        claimed.append(expected)
    if claimed and collects_secrets:
        add("brand_mismatch", "high", f"Page presents itself as {claimed[0]} and collects credentials",
            f"It is hosted on {page_reg}, which is not a {claimed[0]} domain.",
            f"Open {claimed[0]} from its official app or by typing the address yourself.")
    elif claimed and page.title and any(k in page.title.lower() for b in domains.brands() if b["name"] == claimed[0] for k in b["keywords"]):
        add("brand_title", "low", f"Page title mentions {claimed[0]} on an unrelated domain")

    # ---- assets hot-linked from a brand -------------------------------------
    hotlinked = set()
    for kind, src in page.resources:
        if kind == "img" or kind == "css":
            h = _host_of(urljoin(page_url, src))
            b = domains.legit_brand_for_host(h) if h else None
            if b and not domains.host_belongs_to(page_host, b):
                hotlinked.add(b["name"])
    if hotlinked and collects_secrets:
        add("hotlinked_brand_assets", "medium", "Logos or styles are loaded straight from " + ", ".join(sorted(hotlinked)),
            "Phishing kits often reuse the real site's images so the copy looks authentic.", weight=15)

    # ---- hidden frames, refresh, scripts ------------------------------------
    for fr in page.iframes:
        if fr["hidden"]:
            cross = fr["src"] and _reg(urljoin(page_url, fr["src"])) not in ("", page_reg)
            add("hidden_iframe", "high" if cross else "medium", "Page embeds an invisible frame",
                (fr["src"] or "no source")[:120], "Invisible frames are used for drive-by downloads and click tracking.")
            break
    if page.meta_refresh:
        target = urljoin(page_url, page.meta_refresh)
        if _reg(target) not in ("", page_reg):
            add("meta_refresh", "medium", "Page automatically redirects to another domain", target[:120])
    for m in JS_REDIRECT.finditer(page.inline_js):
        target = m.group(1) or m.group(2)
        if _reg(target) not in ("", page_reg):
            add("js_redirect", "medium", "Script redirects the visitor to another domain", target[:120])
            break
    kinds_hit = [k for k, rx in OBFUSCATION.items() if (len(rx.findall(page.inline_js)) >= (1 if k != "hex escapes" else 1))]
    if len(kinds_hit) >= 3:
        add("obfuscated_js", "high", "Heavily obfuscated JavaScript", "Techniques seen: " + ", ".join(kinds_hit))
    elif len(kinds_hit) == 2:
        add("obfuscated_js", "medium", "Obfuscated JavaScript", "Techniques seen: " + ", ".join(kinds_hit), weight=15)
    if any(k == "oncontextmenu" and "false" in v for k, v in page.handlers):
        add("right_click_blocked", "low", "Page blocks right-click and inspection",
            "Copying phishing kits often disable the context menu to hide their source.")
    dl = next((l for l in page.links if DOWNLOAD_EXT.search(l)), None)
    if dl:
        add("risky_download", "medium", "Page links to an executable or app package", dl[:120],
            "Only install apps from the official store.", weight=15)

    # ---- scam language -------------------------------------------------------
    text = page.title + " " + page.text
    urgency_hits = {m.group(0).lower() for m in URGENCY.finditer(text)}
    if len(urgency_hits) >= 2 or (urgency_hits and collects_secrets):
        add("urgency_language", "medium", "Pressure language typical of account-takeover scams",
            "; ".join(sorted(urgency_hits)[:3]), weight=18)
    if JOB_WORDS.search(text) and FEE_WORDS.search(text):
        add("advance_fee_recruitment", "high", "Job offer that asks you to pay a fee",
            "Real employers do not charge registration, training or security deposits.",
            "Do not pay anything to receive a job. Check the company on its official website.")
    if PAYMENT_TRICK.search(text):
        add("payment_trick", "high", "Page asks for a PIN or QR scan to 'receive' money",
            "You never enter a PIN or approve a request to receive a payment.")
    if PRIZE_BAIT.search(text):
        add("prize_bait", "medium", "Prize or doubling-money bait", weight=18)
    if EDU_WORDS.search(text):
        add("education_scam", "high", "Deceptive education or degree fee solicitation",
            "Legitimate universities and exam authorities do not solicit backdoor admissions or unverified fees.",
            "Verify any admission or degree requirement directly on the official university portal.", weight=25)
    if GOVT_SCAM_WORDS.search(text) and not (page_reg.endswith(".gov.in") or page_reg.endswith(".gov") or page_reg.endswith(".nic.in")):
        add("fake_govt_scheme", "high", "Deceptive government welfare or identity update lure",
            f"The page solicits sensitive identity or welfare details on '{page_reg}', which is not an official government portal.",
            "Official government services operate on verified government domains.", weight=30)
    if APK_LURE_WORDS.search(text):
        add("malicious_app_lure", "high", "Prompts download of sideloaded APK or remote access tool",
            "Attackers frequently ask targets to download APKs or remote support tools to hijack banking sessions.",
            "Never install applications outside of official app stores.", weight=20)
    return findings, page
