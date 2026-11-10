"""Optional external reputation providers. Disabled unless an API key is set."""
from __future__ import annotations

import requests

from . import config, netsafe

SB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
SB_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]


def parse_safe_browsing(payload: dict) -> list[str]:
    return sorted({m.get("threatType", "UNKNOWN") for m in payload.get("matches", [])})


def safe_browsing_lookup(url: str) -> list[str] | None:
    """Return matched threat types ([] if clean), or None if the provider is off or unreachable.

    Note: this sends the full URL to Google. Enable it only if that is acceptable.
    """
    key = config.safe_browsing_key()
    if not key:
        return None
    body = {
        "client": {"clientId": "threatlens", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": SB_TYPES, "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}],
        },
    }
    try:
        r = requests.post(SB_ENDPOINT, params={"key": key}, json=body, timeout=config.fetch_timeout(),
                          headers={"User-Agent": netsafe.USER_AGENT})
        r.raise_for_status()
        return parse_safe_browsing(r.json())
    except Exception:
        return None
