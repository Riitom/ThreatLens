"""End-to-end tests against real local HTTPS servers with generated certificates."""
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from threatlens import cert_analyzer, engine, netsafe, providers
from threatlens.intel import IntelStore
from threatlens.server import create_app

import helpers as H


def fids(result):
    return {f["id"] for f in result["findings"]}


def find(result, fid):
    return next(f for f in result["findings"] if f["id"] == fid)


class E2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        cls.ca_key, cls.ca_cert = H.make_ca()
        cls.ca_path, _ = H.write_pair(cls.tmp, "ca", cls.ca_key, cls.ca_cert)
        cls.servers = []

        def serve(name, key, self_signed=False, names=("localhost",)):
            cert = H.make_leaf(cls.ca_key, cls.ca_cert, key, names=names, self_signed=self_signed)
            cp, kp = H.write_pair(cls.tmp, name, key, cert)
            srv, port = H.start_https_server(cp, kp)
            cls.servers.append(srv)
            return port

        cls.self_signed_port = serve("selfsigned", ec.generate_private_key(ec.SECP256R1()), self_signed=True)
        cls.trusted_port = serve("trusted", ec.generate_private_key(ec.SECP256R1()))
        cls.wrongname_port = serve("wrongname", ec.generate_private_key(ec.SECP256R1()), names=("other.example",))

        # Weak RSA key: two 1024-bit primes only 2000 apart.
        base = rsa.generate_private_key(65537, 2048).private_numbers()
        p = base.p
        q_close = H.next_prime(p + 2000)
        cls.close_port = serve("close", H.rsa_key_from_primes(p, q_close))

        # Two keys that share the prime `shared`.
        shared = rsa.generate_private_key(65537, 2048).private_numbers().p
        qa = rsa.generate_private_key(65537, 2048).private_numbers().q
        qb = rsa.generate_private_key(65537, 2048).private_numbers().q
        cls.shared_a_port = serve("shared_a", H.rsa_key_from_primes(shared, qa))
        cls.shared_b_port = serve("shared_b", H.rsa_key_from_primes(shared, qb))

    def setUp(self):
        patcher = mock.patch.dict(os.environ, {"THREATLENS_ALLOW_PRIVATE": "1", "THREATLENS_CA_FILE": str(self.ca_path)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def url(self, port, path="/"):
        return f"https://localhost:{port}{path}"

    # ------------------------------------------------------------------
    def test_phishing_page_on_self_signed_cert(self):
        r = engine.scan(self.url(self.self_signed_port), store=IntelStore())
        ids = fids(r)
        for expected in ("cert.untrusted", "content.form_cross_domain", "content.brand_mismatch", "content.hidden_iframe",
                         "content.obfuscated_js", "content.urgency_language", "content.sensitive_fields"):
            self.assertIn(expected, ids)
        self.assertEqual(find(r, "cert.untrusted")["title"], "Certificate is self-signed")
        self.assertEqual(r["verdict"]["label"], "Dangerous", r["verdict"])
        self.assertEqual(r["verdict"]["confidence"], "high")
        self.assertFalse(r["certificate"]["trusted"])
        # Hygiene findings are reported, but did not drive the threat verdict.
        self.assertIn("sec.eol_software", ids)
        self.assertIn("sec.no_csp", ids)
        self.assertIn("sec.cookie_httponly_PHPSESSID", ids)
        self.assertIn(r["posture"]["grade"], ("D", "F"))
        self.assertTrue(all(f["axis"] == "posture" for f in r["findings"] if f["engine"] == "security"))

    def test_trusted_chain_and_transparency(self):
        r = engine.scan(self.url(self.trusted_port))
        self.assertTrue(r["certificate"]["trusted"], r["certificate"]["trust_error"])
        self.assertNotIn("cert.untrusted", fids(r))
        self.assertIn("cert.no_sct", fids(r))  # no embedded SCTs on a test certificate
        self.assertEqual(r["certificate"]["transparency"]["embedded_scts"], 0)
        with mock.patch.object(cert_analyzer, "_ct_lookup", return_value=False):
            r2 = engine.scan(self.url(self.trusted_port), ct_lookup=True)
        self.assertIn("cert.not_in_ct_logs", fids(r2))
        with mock.patch.object(cert_analyzer, "_ct_lookup", return_value=None):
            r3 = engine.scan(self.url(self.trusted_port), ct_lookup=True)
        self.assertNotIn("cert.not_in_ct_logs", fids(r3))
        self.assertEqual(r3["certificate"]["transparency"]["crtsh"], "unavailable")

    def test_wrong_hostname_is_flagged(self):
        r = engine.scan(self.url(self.wrongname_port))  # CA-signed, but only for other.example
        self.assertIn("cert.untrusted", fids(r))
        self.assertIn("different domain", find(r, "cert.untrusted")["title"])

    def test_weak_rsa_key_forces_critical(self):
        r = engine.scan(self.url(self.close_port))
        self.assertIn("cert.close_primes", fids(r))
        self.assertGreaterEqual(r["verdict"]["threat_score"], 85)
        self.assertEqual(r["verdict"]["label"], "Dangerous")

    def test_shared_prime_across_scans(self):
        store = IntelStore()
        first = engine.scan(self.url(self.shared_a_port), store=store)
        self.assertNotIn("cert.shared_prime", fids(first))
        second = engine.scan(self.url(self.shared_b_port), store=store)
        self.assertIn("cert.shared_prime", fids(second))
        self.assertGreaterEqual(second["verdict"]["threat_score"], 85)

    def test_blocked_key_list(self):
        got = cert_analyzer.fetch_chain("localhost", self.trusted_port)
        spki = cert_analyzer._spki_hash(cert_analyzer.x509.load_der_x509_certificate(got["chain"][0]))
        with mock.patch.object(cert_analyzer, "_distrust", return_value={"blocked_spki_sha256": [spki], "issuer_watch": []}):
            f, _ = cert_analyzer.analyze_certificate("localhost", self.trusted_port)
        self.assertIn("cert.blocked_key", {x.id for x in f})

    def test_issuer_watch_rule(self):
        rules = {"blocked_spki_sha256": [], "issuer_watch": [{"pattern": "threatlens test ca", "note": "under review"}]}
        with mock.patch.object(cert_analyzer, "_distrust", return_value=rules):
            f, _ = cert_analyzer.analyze_certificate("localhost", self.trusted_port)
        self.assertIn("cert.issuer_watch", {x.id for x in f})

    def test_deep_scan_requires_authorisation(self):
        denied = engine.scan(self.url(self.trusted_port), deep=True, authorized=False)
        self.assertNotIn("sec.exposed_.git_HEAD", fids(denied))
        self.assertTrue(any("authorisation" in n for n in denied["notes"]))
        allowed = engine.scan(self.url(self.trusted_port), deep=True, authorized=True)
        self.assertIn("sec.exposed_.git_HEAD", fids(allowed))

    def test_redirect_into_metadata_service_is_blocked(self):
        port = self.trusted_port
        real = netsafe.resolve_public

        def only_test_server(host, p):
            return [(socket.AF_INET, "127.0.0.1")] if p == port else real(host, p)

        env = {"THREATLENS_ALLOW_PRIVATE": "", "THREATLENS_ANY_PORT": "1"}
        with mock.patch.dict(os.environ, env), mock.patch.object(netsafe, "resolve_public", only_test_server):
            res = netsafe.safe_fetch(f"https://127.0.0.1:{port}/redirect")
        self.assertTrue(res.error and res.error.startswith("Blocked"), res.error)
        self.assertEqual(res.redirects[0]["to"], "http://169.254.169.254/latest/meta-data/")

    def test_safe_browsing_and_feed_override(self):
        with mock.patch.object(providers, "safe_browsing_lookup", return_value=["SOCIAL_ENGINEERING"]):
            r = engine.scan(self.url(self.trusted_port, "/missing"))
        self.assertGreaterEqual(r["verdict"]["threat_score"], 80)
        store = IntelStore()
        store._db.execute("INSERT INTO feed_entries(host,source,category,added_at) VALUES('localhost','testfeed','phishing',0)")
        r2 = engine.scan(self.url(self.trusted_port, "/missing"), store=store)
        self.assertIn("intel.feed_match", fids(r2))

    def test_unreachable_target_degrades_gracefully(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]
        s.close()
        r = engine.scan(f"https://localhost:{dead}/")
        self.assertEqual(r["verdict"]["confidence"], "low")
        self.assertIsNone(r["posture"]["grade"])
        self.assertTrue(any(c["status"] == "failed" for c in r["coverage"]))

    def test_safe_browsing_parser(self):
        payload = {"matches": [{"threatType": "MALWARE"}, {"threatType": "SOCIAL_ENGINEERING"}, {"threatType": "MALWARE"}]}
        self.assertEqual(providers.parse_safe_browsing(payload), ["MALWARE", "SOCIAL_ENGINEERING"])
        self.assertEqual(providers.parse_safe_browsing({}), [])


class ApiTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.dict(os.environ, {"THREATLENS_SALT": "test-salt", "THREATLENS_REPORT_RATE": "3"})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.store = IntelStore()
        self.client = create_app(self.store).test_client()

    def post(self, path, data, ip="198.51.100.1"):
        return self.client.post(path, json=data, environ_overrides={"REMOTE_ADDR": ip})

    def test_community_loop_and_feed(self):
        for i in range(3):
            r = self.post("/api/report", {"url": "https://fake-recruit.example/apply?id=7", "category": "fake_recruitment",
                                          "comment": "asked for a fee"}, ip=f"203.0.113.{i + 1}")
            self.assertEqual(r.status_code, 200)
        rep = self.client.get("/api/reputation", query_string={"url": "https://fake-recruit.example/"}).get_json()
        self.assertEqual(rep["level"], "confirmed")
        self.assertEqual(rep["unique_reporters"], 3)
        feed = self.client.get("/api/feed").get_json()["entries"]
        self.assertEqual(feed[0]["host"], "fake-recruit.example")
        # The public feed carries a reporter count only: no identities, comments or full URLs.
        self.assertEqual(set(feed[0]), {"host", "score", "reporters", "category", "last_report"})
        self.assertIsInstance(feed[0]["reporters"], int)
        dup = self.post("/api/report", {"url": "https://fake-recruit.example/", "category": "phishing"}, ip="203.0.113.1")
        self.assertEqual(dup.get_json()["status"], "duplicate")

    def test_confirmed_community_flag_raises_scan_score_but_brands_are_protected(self):
        for i in range(3):
            self.post("/api/report", {"url": "https://www.paypal.com/", "category": "phishing"}, ip=f"192.0.2.{i + 1}")
        with mock.patch.dict(os.environ, {"THREATLENS_ALLOW_PRIVATE": "1"}):
            s = engine.scan("https://www.paypal.com/", store=self.store)
        self.assertEqual(s["community"]["level"], "confirmed")
        self.assertEqual(s["community"]["effective_level"], "reported")
        self.assertNotIn("intel.community_confirmed", fids(s))

    def test_validation_rate_limit_and_headers(self):
        self.assertEqual(self.post("/api/scan", {"url": 5}).status_code, 400)
        self.assertEqual(self.post("/api/scan", {"url": "ftp://x"}).status_code, 400)
        self.assertEqual(self.client.post("/api/scan", data="nope", content_type="text/plain").status_code, 400)
        self.assertEqual(self.post("/api/report", {"url": "x.example", "category": "bogus"}).status_code, 400)
        for _ in range(3):
            self.post("/api/report", {"url": "a.example", "category": "phishing"}, ip="198.51.100.9")
        self.assertEqual(self.post("/api/report", {"url": "b.example", "category": "phishing"}, ip="198.51.100.9").status_code, 429)
        h = self.client.get("/api/health")
        self.assertEqual(h.status_code, 200)
        self.assertIn("default-src 'none'", h.headers["Content-Security-Policy"])
        self.assertEqual(h.headers["Cache-Control"], "no-store")
        self.assertEqual(self.client.get("/static/../server.py").status_code, 404)

    def test_scan_endpoint_blocks_internal_targets(self):
        r = self.post("/api/scan", {"url": "http://169.254.169.254/latest/meta-data/"})
        body = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(body["http"]["error"].startswith("Blocked"), body["http"])
        self.assertIsNone(body["certificate"])


if __name__ == "__main__":
    unittest.main()
