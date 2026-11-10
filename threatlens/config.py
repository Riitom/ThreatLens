"""Runtime configuration. Values are read lazily from the environment so tests
(and operators) can change behaviour without re-importing modules."""
from __future__ import annotations

import os
import secrets
import tempfile
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent
DATA_DIR = PKG_DIR / "data"
STATIC_DIR = PKG_DIR / "static"

# Ports the scanner is willing to contact on a third-party host.
ALLOWED_PORTS = {80, 443, 8080, 8443}
_SESSION_SALT = secrets.token_hex(32)


def _flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def allow_private() -> bool:
    """Disable the SSRF guard. Only for tests and trusted lab networks."""
    return _flag("THREATLENS_ALLOW_PRIVATE")


def any_port() -> bool:
    return _flag("THREATLENS_ANY_PORT")


def ct_lookup_enabled() -> bool:
    """Query crt.sh for the scanned host (sends the hostname to a third party)."""
    return _flag("THREATLENS_CT_LOOKUP")


def extra_ca_file() -> str | None:
    """Optional PEM bundle appended to the system trust store (internal CAs)."""
    return os.environ.get("THREATLENS_CA_FILE") or None


def db_path() -> str:
    if os.environ.get("THREATLENS_DB"):
        return os.environ["THREATLENS_DB"]
    root = Path(tempfile.gettempdir()) if os.environ.get("VERCEL") else Path.cwd() / "instance"
    root.mkdir(parents=True, exist_ok=True)
    return str(root / "threatlens.db")


def salt() -> str:
    return os.environ.get("THREATLENS_SALT") or _SESSION_SALT


def safe_browsing_key() -> str | None:
    return os.environ.get("SAFE_BROWSING_API_KEY") or None


def fetch_timeout() -> int:
    return _int("THREATLENS_TIMEOUT", 8)


def max_body_bytes() -> int:
    return _int("THREATLENS_MAX_BODY", 1_500_000)


def max_redirects() -> int:
    return _int("THREATLENS_MAX_REDIRECTS", 5)


def scan_rate_per_min() -> int:
    return _int("THREATLENS_SCAN_RATE", 30)


def report_rate_per_hour() -> int:
    return _int("THREATLENS_REPORT_RATE", 10)
