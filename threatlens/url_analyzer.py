"""Lexical and structural analysis of the URL itself. No network access."""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import unquote, urlsplit

from . import domains
from .models import Finding

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "click", "country", "gq", "tk", "ml", "ga", "cf", "work", "support",
    "rest", "link", "cam", "icu", "buzz", "monster", "sbs", "cyou", "bond", "lol", "quest", "cfd",
}
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in", "s.id", "t.ly", "bl.ink",
}
LURE_WORDS = {
    "login", "signin", "verify", "verification", "secure", "security", "account", "update", "confirm",
    "banking", "wallet", "password", "passwd", "otp", "kyc", "claim", "reward", "refund", "suspended",
    "unlock", "validate", "authenticate", "billing", "invoice", "recovery", "helpdesk", "alert",
    "bonus", "gift", "lottery", "prize", "payment",
}
NUMERIC_HOST = re.compile(r"^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+)){0,3}$", re.I)
GENERIC_LABELS = {"com", "net", "org", "gov", "edu", "co", "in", "mil", "ac"}


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Enter a URL to scan")
    if len(raw) > 2048:
        raise ValueError("URL is longer than 2048 characters")
    if re.search(r"[\x00-\x20\x7f]", raw):
        raise ValueError("URL must not contain spaces or control characters")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    parts = urlsplit(raw)
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http and https URLs can be scanned")
    if not parts.hostname:
        raise ValueError("URL has no host")
    try:
        parts.port
    except ValueError:
        raise ValueError("URL has an invalid port") from None
    return raw


def _tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def _scripts(label: str) -> set[str]:
    out = set()
    for ch in label:
        if ch.isalpha():
            out.add(unicodedata.name(ch, "UNKNOWN").split()[0])
    return out


def analyze_url(url: str) -> tuple[list[Finding], dict]:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    findings: list[Finding] = []

    def add(fid, sev, title, detail="", advice="", weight=None):
        findings.append(Finding(f"url.{fid}", "url", "threat", sev, title, detail, advice, weight))

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass
    numeric_obfuscated = not is_ip and bool(NUMERIC_HOST.match(host))

    sub_labels, sld, suffix = domains.split_host(host) if not is_ip else ([], host, "")
    reg = domains.registered_domain(host) if not is_ip else host
    unicode_host = domains.to_unicode_host(host)
    path_query = unquote(f"{parts.path} {parts.query}").lower()
    features = {
        "host": host, "registered_domain": reg, "scheme": parts.scheme, "tld": suffix.split(".")[-1] if suffix else "",
        "url_length": len(url), "is_ip": is_ip, "impersonated_brand": None, "known_brand": None,
        "unicode_host": unicode_host if unicode_host != host else None,
    }

    # ---- structure -----------------------------------------------------------
    if is_ip or numeric_obfuscated:
        add("ip_host", "high" if is_ip else "high",
            "Address uses a raw IP number instead of a domain name" if is_ip else "Host is an obfuscated numeric IP address",
            "Legitimate services almost always use a registered domain name.",
            "Do not sign in on pages hosted at a bare IP address.")
    if "@" in parts.netloc:
        add("userinfo", "high", "URL contains '@' before the host",
            "Everything before the '@' is a username, so the real destination is the part after it.",
            "Check the text after the '@'; that is where the browser will connect.")
    if parts.scheme == "http":
        add("no_https", "medium", "Page is not served over HTTPS",
            "Anything typed on this page travels unencrypted.", weight=12)
    if port and port not in (80, 443):
        add("odd_port", "low", f"Non-standard port {port}", "Phishing kits are often run on unusual ports.")
    if len(url) > 200:
        add("very_long", "medium", f"Very long URL ({len(url)} characters)", "Long URLs hide the real destination.", weight=12)
    elif len(url) > 100:
        add("long", "low", f"Long URL ({len(url)} characters)")
    if not is_ip and len(sub_labels) > 3:
        add("many_subdomains", "medium", f"{len(sub_labels)} subdomain levels",
            "Deep subdomain chains push the real domain out of view.", weight=12)
    if host.count("-") >= 3:
        add("hyphens", "low", "Many hyphens in the host name")
    if suffix and suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        add("suspicious_tld", "low", f"Top-level domain .{suffix.split('.')[-1]} is heavily abused",
            "Not malicious by itself, but a large share of phishing uses low-cost TLDs like this.", weight=8)
    if reg in SHORTENERS:
        add("shortener", "medium", "Link shortener hides the final destination",
            "You cannot see where this link goes before opening it.",
            "Expand the link with a trusted preview tool before visiting.")
    if re.search(r"https?(://|%3a%2f%2f)", parts.query + parts.fragment, re.I):
        add("embedded_url", "medium", "Another URL is embedded in the query string",
            "Often an open-redirect parameter used to bounce visitors to a malicious page.")
    if not is_ip and len(sld) >= 12 and domains.shannon_entropy(sld) > 3.5 and re.search(r"\d", sld):
        add("random_name", "low", "Domain name looks randomly generated")
    # domain names that fake a bigger domain inside subdomains: paypal.com.evil.xyz
    if any(lbl in GENERIC_LABELS for lbl in sub_labels[1:]):
        add("domain_in_subdomain", "high", "A real-looking domain is placed in the subdomain",
            f"The real site is {reg}; the text before it is only decoration.")

    # ---- lure words ----------------------------------------------------------
    host_words = {t for t in _tokens(host) if t in LURE_WORDS}
    path_words = {t for t in _tokens(path_query) if t in LURE_WORDS}
    if host_words and (len(host_words | path_words) >= 2 or sub_labels):
        add("lure_words_host", "medium", "Host name contains account-related words: " + ", ".join(sorted(host_words)),
            "Words like login, verify and secure are staples of phishing domains.", weight=18)
    elif len(path_words) >= 2:
        add("lure_words_path", "low", "Path contains account-related words: " + ", ".join(sorted(path_words)))

    # ---- internationalised domain names -------------------------------------
    labels_unicode = unicode_host.split(".")
    mixed = [lbl for lbl in labels_unicode if len(_scripts(lbl) - {"DIGIT"}) > 1]
    if mixed:
        add("mixed_script", "high", "A domain label mixes alphabets (for example Latin and Cyrillic)",
            "Mixing scripts is the classic homograph trick for faking a familiar name.")
    elif unicode_host != host:
        add("idn", "low", "Domain uses internationalised characters (punycode)",
            f"It displays as {unicode_host}.")

    # ---- brand impersonation -------------------------------------------------
    legit = None if is_ip else domains.legit_brand_for_host(host)
    if legit:
        features["known_brand"] = legit["name"]
    elif not is_ip:
        host_tokens = _tokens(".".join(sub_labels + [sld]))
        sld_unicode = domains.to_unicode_host(sld)
        candidates = {sld_unicode} | {t for t in re.split(r"[-_]", sld_unicode) if len(t) >= 5}
        for brand in domains.brands():
            name = brand["name"]
            brand_labels = {d.split(".")[0] for d in brand["domains"]}
            hit = None
            for kw in brand["keywords"]:
                if any(t == kw or (len(kw) >= 6 and kw in t) for t in host_tokens):
                    hit = ("brand_in_domain", f"Domain uses the {name} name but does not belong to {name}",
                           f"The registered domain is {reg}. {name} only uses " + ", ".join(sorted(brand["domains"])[:3]) + ".", "high")
                    break
            if not hit:
                for cand in candidates:
                    for bl in brand_labels:
                        if len(bl) < 5 or cand == bl:
                            continue
                        if domains.skeleton(cand) == domains.skeleton(bl):
                            sev = "critical" if cand != sld or unicode_host != host else "high"
                            hit = ("homoglyph", f"Domain imitates {name} using look-alike characters",
                                   f"'{cand}' is visually almost identical to '{bl}'.", sev)
                        elif domains.levenshtein(cand, bl, 2) <= (1 if len(bl) < 10 else 2):
                            hit = ("typosquat", f"Domain is a near-misspelling of {name}",
                                   f"'{cand}' differs from '{bl}' by a character or two.", "high")
                        if hit:
                            break
                    if hit:
                        break
            if hit:
                fid, title, detail, sev = hit
                add(fid, sev, title, detail, f"Go to {name} by typing its address yourself or using its official app.")
                features["impersonated_brand"] = name
                break
        if not features["impersonated_brand"]:
            path_tokens = set(_tokens(path_query))
            for brand in domains.brands():
                if any(len(kw) >= 4 and kw in path_tokens for kw in brand["keywords"]):
                    add("brand_in_path", "medium", f"Path mentions {brand['name']} on an unrelated domain",
                        f"This page lives on {reg}, not on a {brand['name']} domain.", weight=15)
                    features["impersonated_brand"] = brand["name"]
                    break

    return findings, features
