"""Regressions found during the complete application and deployment audit."""
import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from threatlens import cert_analyzer, config, engine, netsafe, url_analyzer, web_security
from threatlens.intel import IntelStore
from threatlens.server import create_app


@pytest.fixture
def client():
    return create_app(IntelStore()).test_client()


def test_vercel_database_uses_writable_temp_directory():
    with mock.patch.dict(os.environ, {"VERCEL": "1"}):
        with mock.patch.dict(os.environ):
            os.environ.pop("THREATLENS_DB", None)
            assert Path(config.db_path()).parent != Path.cwd()
            assert Path(config.db_path()).parent == Path(tempfile.gettempdir())


@pytest.mark.parametrize("payload", [
    {"url": "example.com", "deep": "false", "authorized": "false"},
    {"url": "example.com", "authorized": 1},
])
def test_scan_options_require_booleans(client, payload):
    with mock.patch.object(engine, "scan", return_value={}):
        assert client.post("/api/scan", json=payload).status_code == 400


@pytest.mark.parametrize("payload", [
    {"url": "a.example", "category": []},
    {"url": ["a.example"]},
    {"url": "a.example", "comment": {}},
])
def test_report_types_return_client_error(client, payload):
    assert client.post("/api/report", json=payload).status_code == 400


def test_http_statuses_are_not_converted_to_500(client):
    assert client.get("/api/scan").status_code == 405
    oversized = '{"pem":"' + "x" * 270_000 + '"}'
    assert client.post("/api/cert/inspect", data=oversized, content_type="application/json").status_code == 413


@pytest.mark.parametrize("query", ["limit=-1", "min_score=nan", "min_score=-1", "min_score=inf"])
def test_feed_rejects_invalid_bounds(client, query):
    assert client.get("/api/feed?" + query).status_code == 400


def test_exports_validate_format_and_threshold(client):
    assert client.get("/api/feed/export?format=xml").status_code == 400
    assert client.get("/api/feed/export?min_score=nan").status_code == 400


@pytest.mark.parametrize("host", ["https://example.com:22", "ftp://example.com", "example.com:25"])
def test_certificate_inspection_enforces_port_and_scheme_policy(client, host):
    with mock.patch.object(cert_analyzer, "analyze_certificate", return_value=([], {})) as inspect:
        assert client.post("/api/cert/inspect", json={"host": host}).status_code == 400
        inspect.assert_not_called()


def test_certificate_internal_target_has_actionable_error(client):
    assert client.post("/api/cert/inspect", json={"host": "127.0.0.1"}).status_code == 400


def test_unavailable_target_never_gets_low_risk_verdict():
    fetch = netsafe.FetchResult(url="https://example.org", error="DNS lookup failed")
    with mock.patch.object(netsafe, "safe_fetch", return_value=fetch), \
         mock.patch.object(cert_analyzer, "analyze_certificate", side_effect=OSError("unavailable")), \
         mock.patch("threatlens.providers.safe_browsing_lookup", return_value=None):
        result = engine.scan("https://example.org")
    assert result["verdict"]["label"] == "Inconclusive"
    assert result["verdict"]["level"] == "unknown"
    assert result["verdict"]["confidence"] == "low"
    assert result["verdict"]["advice"]


@pytest.mark.parametrize("url", ["https://example.com/" + "a" * 2050, "https://exa mple.com", "https://example.com/\x00"])
def test_normalize_rejects_invalid_urls(url):
    with pytest.raises(ValueError):
        url_analyzer.normalize_url(url)


def test_real_demo_pem_can_be_audited(client):
    response = client.get("/api/demo/certificate")
    assert response.status_code == 200
    pem = response.get_json()["pem"]
    assert "-----BEGIN CERTIFICATE-----" in pem
    audited = client.post("/api/cert/inspect", json={"pem": pem})
    assert audited.status_code == 200
    result = audited.get_json()
    assert "cert.close_primes" in {f["id"] for f in result["findings"]}
    assert result["certificate"]["protocol"] is None


def test_demo_results_are_identified_and_cannot_pollute_reports(client):
    data = client.post("/api/demo/run", json={"scenario": "sbi_kyc_phish"}).get_json()
    assert data["demo"] is True
    assert client.post("/api/report", json={"url": data["url"], "category": "phishing", "demo": True}).status_code == 400


def test_redirect_destination_is_scored_and_certificate_inspected():
    fetch = netsafe.FetchResult(url="https://example.org/", final_url="https://paypa1-login.top/", status=200,
        content_type="text/html", body="<html><title>Sign in</title></html>",
        redirects=[{"from": "https://example.org/", "to": "https://paypa1-login.top/", "status": 302}])
    with mock.patch.object(netsafe, "safe_fetch", return_value=fetch), \
         mock.patch.object(cert_analyzer, "analyze_certificate", return_value=([], {"host": "example.org"})) as audit, \
         mock.patch("threatlens.providers.safe_browsing_lookup", return_value=None):
        result = engine.scan("https://example.org/", deep=True, authorized=True)
    assert any(call.args[0] == "paypa1-login.top" for call in audit.call_args_list)
    assert any(f["id"] == "url.suspicious_tld" for f in result["findings"])
    assert any(c["engine"] == "exposure" and c["status"] == "skipped" for c in result["coverage"])


def test_partial_page_does_not_get_high_confidence():
    fetch = netsafe.FetchResult(url="https://example.org/", final_url="https://example.org/", status=403,
        content_type="text/html", body="<html>Access denied</html>")
    with mock.patch.object(netsafe, "safe_fetch", return_value=fetch), \
         mock.patch.object(cert_analyzer, "analyze_certificate", return_value=([], {"host": "example.org"})), \
         mock.patch("threatlens.providers.safe_browsing_lookup", return_value=None):
        result = engine.scan("https://example.org/")
    assert result["verdict"]["label"] == "Inconclusive"
    assert result["verdict"]["confidence"] != "high"


@pytest.mark.parametrize("headers", [
    {"x-frame-options": "ALLOWALL"},
    {"content-security-policy": "frame-ancestors *"},
    {"content-security-policy": "frame-ancestors https:"},
])
def test_invalid_or_unrestricted_frame_policy_is_not_graded_as_protection(headers):
    fetch = netsafe.FetchResult(url="https://example.org", final_url="https://example.org", status=200, headers=headers)
    findings, rows = web_security.analyze_headers(fetch, None)
    assert "sec.no_frame_protection" in {f.id for f in findings}
    assert next(r for r in rows if r["name"] == "X-Frame-Options")["status"] == "fail"


def test_csp_without_script_restrictions_is_not_graded_strong():
    fetch = netsafe.FetchResult(url="https://example.org", final_url="https://example.org", status=200,
        headers={"content-security-policy": "base-uri 'none'; frame-ancestors 'none'"})
    findings, rows = web_security.analyze_headers(fetch, None)
    assert "sec.weak_csp" in {f.id for f in findings}
