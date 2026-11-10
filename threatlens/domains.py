"""Domain helpers shared by the URL and content engines."""
from __future__ import annotations

import json
import math
import unicodedata
from collections import Counter
from functools import lru_cache

from . import config

# Common two-label public suffixes. A full Public Suffix List would be better;
# this keeps the scanner dependency-free and offline.
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "edu.au",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "res.in", "nic.in", "firm.in", "gen.in", "ind.in",
    "co.jp", "ne.jp", "or.jp", "com.br", "com.cn", "com.hk", "com.sg", "com.my", "com.mx", "com.tr", "com.ar",
    "co.za", "co.nz", "co.kr", "co.id", "com.pk", "com.bd", "com.np", "com.lk", "com.ng", "com.ph", "com.vn",
}

# Cyrillic/Greek characters that are visually identical to Latin ones.
_CONFUSABLE = {
    "0": "o", "1": "l", "i": "l", "|": "l", "3": "e", "5": "s", "$": "s", "@": "a",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "ѕ": "s",
    "і": "l", "ј": "j", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w",
    "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ι": "l", "κ": "k",
}


def registered_domain(host: str) -> str:
    host = host.lower().strip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def split_host(host: str) -> tuple[list[str], str, str]:
    """Return (subdomain labels, second-level label, public suffix)."""
    host = host.lower().strip(".")
    reg = registered_domain(host)
    reg_labels = reg.split(".")
    host_labels = host.split(".")
    sub = host_labels[: len(host_labels) - len(reg_labels)]
    return sub, reg_labels[0], ".".join(reg_labels[1:])


def levenshtein(a: str, b: str, limit: int = 3) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def skeleton(text: str) -> str:
    """Collapse look-alike characters so 'paypa1', 'раураl' and 'pay-pal' compare equal."""
    s = unicodedata.normalize("NFKC", text.lower()).replace("rn", "m").replace("vv", "w")
    return "".join(_CONFUSABLE.get(c, c) for c in s if c not in "-_")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts, n = Counter(text), len(text)
    return -sum(v / n * math.log2(v / n) for v in counts.values())


def to_unicode_host(host: str) -> str:
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label[4:].encode("ascii").decode("punycode")
            except Exception:
                pass
        labels.append(label)
    return ".".join(labels)


# --------------------------------------------------------------------------- brands
@lru_cache(maxsize=1)
def brands() -> list[dict]:
    return json.loads((config.DATA_DIR / "brands.json").read_text(encoding="utf-8"))


def host_belongs_to(host: str, brand: dict) -> bool:
    host = host.lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in brand["domains"])


def legit_brand_for_host(host: str) -> dict | None:
    for brand in brands():
        if host_belongs_to(host, brand):
            return brand
    return None
