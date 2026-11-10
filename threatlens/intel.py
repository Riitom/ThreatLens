"""Collaborative threat intelligence backed by SQLite.

* community reports and confirm/dispute votes, one per reporter per host
* time-decayed reputation so stale reports fade
* imported third-party feeds (one URL or host per line)
* a registry of public keys seen in scans, used to spot shared RSA primes
* privacy: reporters are stored only as salted HMACs, URLs without query strings
"""
from __future__ import annotations

import hmac
import hashlib
import math
import re
import sqlite3
import threading
import time
from collections import Counter
from urllib.parse import urlsplit

CATEGORIES = {"phishing", "malware", "fake_recruitment", "payment_scam", "impersonation", "other"}
HALF_LIFE_DAYS = 14.0
# Three fresh, independent reports must clear CONFIRMED_SCORE even after a few days of decay.
CONFIRMED_SCORE, REPORTED_SCORE, WEAK_SCORE = 2.4, 1.2, 0.2
CONFIRMED_MIN_REPORTERS = 3
_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9\-\.]{0,251}[a-z0-9])?$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports(
  id INTEGER PRIMARY KEY, host TEXT NOT NULL, url TEXT, category TEXT, comment TEXT,
  reporter TEXT NOT NULL, created_at REAL NOT NULL, UNIQUE(host, reporter));
CREATE INDEX IF NOT EXISTS idx_reports_host ON reports(host);
CREATE TABLE IF NOT EXISTS votes(
  host TEXT NOT NULL, reporter TEXT NOT NULL, vote TEXT NOT NULL, created_at REAL NOT NULL,
  PRIMARY KEY(host, reporter));
CREATE TABLE IF NOT EXISTS feed_entries(
  host TEXT NOT NULL, source TEXT NOT NULL, category TEXT, added_at REAL NOT NULL,
  PRIMARY KEY(host, source));
CREATE TABLE IF NOT EXISTS cert_keys(
  spki TEXT PRIMARY KEY, alg TEXT NOT NULL, modulus_hex TEXT, subject TEXT, issuer TEXT, first_seen REAL NOT NULL);
"""


def reporter_id(salt: str, client: str) -> str:
    return hmac.new(salt.encode(), client.encode(), hashlib.sha256).hexdigest()[:20]


def host_of(url_or_host: str) -> str:
    text = url_or_host.strip()
    if "://" not in text:
        text = "http://" + text
    return (urlsplit(text).hostname or "").lower().rstrip(".")


def clean_url(url: str) -> str:
    """Drop query string and fragment so tokens or personal data never reach the database."""
    p = urlsplit(url if "://" in url else "http://" + url)
    return f"{p.scheme}://{p.netloc.split('@')[-1]}{p.path}"[:500]


def _decay(created: float, now: float) -> float:
    return 0.5 ** (max(0.0, now - created) / 86400 / HALF_LIFE_DAYS)


def _strip_ctrl(text: str, limit: int) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", " ", text or "")[:limit].strip()


class IntelStore:
    def __init__(self, path: str = ":memory:"):
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.executescript(SCHEMA)
            self._db.commit()

    # ------------------------------------------------------------------ reports
    def add_report(self, url: str, category: str, comment: str, reporter: str) -> dict:
        host = host_of(url)
        if not host or not _HOST_RE.match(host):
            raise ValueError("Could not read a host name from that URL")
        category = category if category in CATEGORIES else "other"
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO reports(host,url,category,comment,reporter,created_at) VALUES(?,?,?,?,?,?)",
                    (host, clean_url(url), category, _strip_ctrl(comment, 500), reporter, time.time()))
                self._db.commit()
                status = "recorded"
            except sqlite3.IntegrityError:
                status = "duplicate"
        return {"status": status, "host": host, "reputation": self.reputation(host)}

    def vote(self, url: str, vote: str, reporter: str) -> dict:
        host = host_of(url)
        if vote not in ("confirm", "dispute") or not host:
            raise ValueError("Vote must be 'confirm' or 'dispute' for a valid URL")
        with self._lock:
            self._db.execute(
                "INSERT INTO votes(host,reporter,vote,created_at) VALUES(?,?,?,?) "
                "ON CONFLICT(host,reporter) DO UPDATE SET vote=excluded.vote, created_at=excluded.created_at",
                (host, reporter, vote, time.time()))
            self._db.commit()
        return {"status": "recorded", "host": host, "reputation": self.reputation(host)}

    def reputation(self, host: str) -> dict:
        host = host_of(host)
        now = time.time()
        with self._lock:
            reports = self._db.execute("SELECT category, reporter, created_at FROM reports WHERE host=?", (host,)).fetchall()
            votes = self._db.execute("SELECT vote, created_at FROM votes WHERE host=?", (host,)).fetchall()
        score, cats, reporters = 0.0, Counter(), set()
        for r in reports:
            score += _decay(r["created_at"], now)
            cats[r["category"]] += 1
            reporters.add(r["reporter"])
        for v in votes:
            w = _decay(v["created_at"], now)
            score += 0.5 * w if v["vote"] == "confirm" else -0.7 * w
        score = max(0.0, score)
        if not reports:
            level = "none"
        elif score >= CONFIRMED_SCORE and len(reporters) >= CONFIRMED_MIN_REPORTERS:
            level = "confirmed"
        elif score >= REPORTED_SCORE:
            level = "reported"
        elif score >= WEAK_SCORE:
            level = "weak"
        else:
            level = "none"
        return {
            "host": host, "level": level, "score": round(score, 2), "reports": len(reports),
            "unique_reporters": len(reporters), "categories": dict(cats),
            "confirmations": sum(1 for v in votes if v["vote"] == "confirm"),
            "disputes": sum(1 for v in votes if v["vote"] == "dispute"),
            "last_report": max((r["created_at"] for r in reports), default=None),
        }

    def feed(self, min_score: float = CONFIRMED_SCORE, limit: int = 1000) -> list[dict]:
        with self._lock:
            hosts = [r["host"] for r in self._db.execute("SELECT DISTINCT host FROM reports")]
        out = []
        for h in hosts:
            rep = self.reputation(h)
            if rep["score"] >= min_score and rep["unique_reporters"] >= CONFIRMED_MIN_REPORTERS:
                top = max(rep["categories"], key=rep["categories"].get) if rep["categories"] else "other"
                out.append({"host": h, "score": rep["score"], "reporters": rep["unique_reporters"],
                            "category": top, "last_report": rep["last_report"]})
        out.sort(key=lambda r: -r["score"])
        return out[:limit]

    # ------------------------------------------------------------------ imported feeds
    def import_feed(self, lines, source: str, category: str = "phishing", max_lines: int = 500_000) -> int:
        count = 0
        now = time.time()
        with self._lock:
            for i, line in enumerate(lines):
                if i >= max_lines:
                    break
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                host = host_of(line.split()[0])
                if host and _HOST_RE.match(host) and ("." in host or ":" in host):
                    self._db.execute(
                        "INSERT OR REPLACE INTO feed_entries(host,source,category,added_at) VALUES(?,?,?,?)",
                        (host, source[:60], category, now))
                    count += 1
            self._db.commit()
        return count

    def feed_matches(self, host: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT source, category FROM feed_entries WHERE host=?", (host_of(host),)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------ key registry
    def record_key(self, spki: str, alg: str, modulus_hex: str | None, subject: str, issuer: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO cert_keys(spki,alg,modulus_hex,subject,issuer,first_seen) VALUES(?,?,?,?,?,?)",
                (spki, alg, modulus_hex, subject[:120], issuer[:120], time.time()))
            self._db.commit()

    def find_shared_prime(self, modulus: int, spki: str, limit: int = 20_000) -> dict | None:
        """Return a previously seen key whose modulus shares a factor with *modulus*."""
        with self._lock:
            rows = self._db.execute(
                "SELECT spki, modulus_hex, subject FROM cert_keys WHERE alg='RSA' AND spki != ? LIMIT ?", (spki, limit)).fetchall()
        for r in rows:
            other = int(r["modulus_hex"], 16)
            if math.gcd(modulus, other) > 1:
                return {"spki": r["spki"], "subject": r["subject"]}
        return None

    def stats(self) -> dict:
        with self._lock:
            q = lambda sql: self._db.execute(sql).fetchone()[0]
            return {"reported_hosts": q("SELECT COUNT(DISTINCT host) FROM reports"), "reports": q("SELECT COUNT(*) FROM reports"),
                    "feed_entries": q("SELECT COUNT(*) FROM feed_entries"), "keys_seen": q("SELECT COUNT(*) FROM cert_keys")}
