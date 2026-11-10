"""Flask application: JSON API plus the single-page UI."""
from __future__ import annotations

import csv
import io
import logging
import math
import os
import threading
import time
from collections import defaultdict, deque

from flask import Flask, Response, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException

from . import __version__, cert_analyzer, config, demo, engine, netsafe, url_analyzer
from .intel import CATEGORIES, CONFIRMED_SCORE, IntelStore, reporter_id

log = logging.getLogger("threatlens")

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


class RateLimiter:
    def __init__(self):
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: float) -> bool:
        now = time.time()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True


def create_app(store: IntelStore | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = 256 * 1024
    store = store or IntelStore(config.db_path())
    limiter = RateLimiter()
    if not os.environ.get("THREATLENS_SALT"):
        log.warning("THREATLENS_SALT is not set; reporter identities last only for this process.")

    def client_id() -> str:
        return reporter_id(config.salt(), request.remote_addr or "unknown")

    def body() -> dict:
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            raise ValueError("Send a JSON object")
        return data

    def string(data, key, default=""):
        value = data.get(key, default)
        if not isinstance(value, str):
            raise ValueError(f"'{key}' must be a string")
        return value

    def feed_args():
        try:
            score = float(request.args.get("min_score", CONFIRMED_SCORE))
            limit = int(request.args.get("limit", 1000))
        except ValueError:
            raise ValueError("min_score and limit must be numbers") from None
        if not math.isfinite(score) or score < 0 or not 1 <= limit <= 5000:
            raise ValueError("min_score must be finite and non-negative; limit must be between 1 and 5000")
        return score, limit

    @app.after_request
    def secure(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.is_secure:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.errorhandler(ValueError)
    @app.errorhandler(netsafe.BlockedTarget)
    def bad_request(exc):
        return jsonify(error=str(exc)), 400

    @app.errorhandler(404)
    def not_found(_exc):
        return jsonify(error="Not found"), 404

    @app.errorhandler(Exception)
    def server_error(exc):
        if isinstance(exc, HTTPException):
            response = exc.get_response()
            response.data = app.json.dumps({"error": exc.description})
            response.content_type = "application/json"
            return response
        log.exception("unhandled error")
        return jsonify(error="Internal error while processing the request"), 500

    @app.get("/")
    def index():
        return send_from_directory(config.STATIC_DIR, "index.html")

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(config.STATIC_DIR, name)

    @app.get("/api/health")
    def health():
        return jsonify(status="ok", version=__version__, storage={
            "backend": "sqlite", "durable": not bool(os.environ.get("VERCEL")),
            "note": "Temporary storage: reports can reset and are not shared across server instances." if os.environ.get("VERCEL") else "Local SQLite storage",
        }, **store.stats())

    @app.post("/api/scan")
    def scan():
        data = body()
        if not limiter.allow("scan:" + client_id(), config.scan_rate_per_min(), 60):
            return jsonify(error="Too many scans. Wait a minute and try again."), 429
        url = string(data, "url")
        for key in ("deep", "authorized"):
            if key in data and not isinstance(data[key], bool):
                raise ValueError(f"'{key}' must be a boolean")
        result = engine.scan(url, deep=data.get("deep", False), authorized=data.get("authorized", False), store=store)
        return jsonify(result)

    @app.post("/api/report")
    def report():
        data = body()
        if not limiter.allow("report:" + client_id(), config.report_rate_per_hour(), 3600):
            return jsonify(error="Report limit reached. Try again later."), 429
        if data.get("demo"):
            raise ValueError("Demonstration results cannot be submitted as live threat intelligence")
        category = string(data, "category", "other")
        if category not in CATEGORIES:
            raise ValueError("Unknown category. Use one of: " + ", ".join(sorted(CATEGORIES)))
        return jsonify(store.add_report(string(data, "url"), category, string(data, "comment"), client_id()))

    @app.post("/api/vote")
    def vote():
        data = body()
        if not limiter.allow("report:" + client_id(), config.report_rate_per_hour() * 3, 3600):
            return jsonify(error="Vote limit reached. Try again later."), 429
        if data.get("demo"):
            raise ValueError("Demonstration results cannot receive live community votes")
        return jsonify(store.vote(string(data, "url"), string(data, "vote"), client_id()))

    @app.get("/api/reputation")
    def reputation():
        url = request.args.get("url", "")
        if not url:
            raise ValueError("Provide a 'url' query parameter")
        return jsonify(store.reputation(url))

    @app.get("/api/feed")
    def feed():
        min_score, limit = feed_args()
        return jsonify(generated_at=time.time(), entries=store.feed(min_score, limit))

    @app.get("/api/feed/export")
    def feed_export():
        min_score, _limit = feed_args()
        fmt = request.args.get("format", "csv").lower()
        if fmt not in ("csv", "json"):
            raise ValueError("format must be csv or json")
        entries = store.feed(min_score, limit=5000)
        if fmt == "json":
            return jsonify(entries=entries)
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["host", "score", "reporters", "category", "last_report_iso"])
        for e in entries:
            lr = e.get("last_report")
            lr_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(lr)) if lr else ""
            writer.writerow([e["host"], e["score"], e["reporters"], e["category"], lr_iso])
        csv_data = output.getvalue()
        return Response(csv_data, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=threatlens-feed.csv"})

    @app.get("/api/demo/scenarios")
    def demo_scenarios():
        return jsonify(scenarios=demo.list_scenarios())

    @app.post("/api/demo/run")
    def demo_run():
        data = body()
        sid = data.get("scenario")
        if not sid:
            raise ValueError("Provide 'scenario' ID")
        res = demo.get_scenario(str(sid))
        if not res:
            raise ValueError(f"Unknown scenario: {sid}")
        return jsonify(res)

    @app.get("/api/demo/certificate")
    def demo_certificate():
        return jsonify(pem=(config.DATA_DIR / "fermat_demo.pem").read_text(encoding="utf-8"), demo=True)

    @app.post("/api/cert/inspect")
    def cert_inspect():
        data = body()
        if not limiter.allow("cert:" + client_id(), config.scan_rate_per_min(), 60):
            return jsonify(error="Too many certificate audits. Wait a minute and try again."), 429
        pem = string(data, "pem")
        host = string(data, "host") or string(data, "url")
        if pem:
            findings, cert_info = cert_analyzer.analyze_pem_text(pem, host=host or "custom.domain", store=store)
        elif host:
            import urllib.parse
            target = url_analyzer.normalize_url(host)
            netsafe.validate_url(target)
            parsed = urllib.parse.urlsplit(target)
            try:
                findings, cert_info = cert_analyzer.analyze_certificate(parsed.hostname, parsed.port or 443, store=store)
            except OSError as exc:
                raise ValueError("Could not read a TLS certificate from this host. Check the address and try again.") from exc
        else:
            raise ValueError("Provide 'pem' certificate text or 'host' string")
        return jsonify(findings=[f.to_dict() for f in findings], certificate=cert_info)

    @app.get("/api/stats")
    def stats():
        st = store.stats()
        feed_count = len(store.feed(CONFIRMED_SCORE, limit=10000))
        return jsonify(status="ok", version=__version__, confirmed_threats=feed_count, **st)

    return app
