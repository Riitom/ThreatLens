import ipaddress
import time
import unittest
from unittest import mock

from threatlens import domains, keychecks, netsafe, scoring, url_analyzer
from threatlens.intel import IntelStore
from threatlens.models import Finding

from helpers import next_prime


def ids(findings):
    return {f.id for f in findings}


class UrlAnalyzerTests(unittest.TestCase):
    def scan(self, url):
        return url_analyzer.analyze_url(url_analyzer.normalize_url(url))

    def test_legit_brand_is_clean(self):
        f, feats = self.scan("https://www.paypal.com/signin")
        self.assertEqual(feats["known_brand"], "PayPal")
        self.assertFalse({i for i in ids(f) if "brand" in i or "typo" in i or "homoglyph" in i})

    def test_brand_in_unrelated_domain(self):
        f, feats = self.scan("https://paypal-secure-login.xyz/verify")
        self.assertIn("url.brand_in_domain", ids(f))
        self.assertEqual(feats["impersonated_brand"], "PayPal")
        self.assertIn("url.suspicious_tld", ids(f))

    def test_typosquat_and_homoglyph(self):
        self.assertIn("url.typosquat", ids(self.scan("https://paypa1l.com/")[0]) | ids(self.scan("https://paypall.com/")[0]))
        self.assertTrue({"url.homoglyph"} & ids(self.scan("https://paypa1.com/")[0]))

    def test_punycode_homograph(self):
        f, _ = self.scan("https://xn--pypal-4ve.com/")  # pаypal with Cyrillic a
        self.assertTrue({"url.homoglyph", "url.mixed_script"} & ids(f))

    def test_ip_userinfo_shortener(self):
        self.assertIn("url.ip_host", ids(self.scan("http://192.0.2.10/login")[0]))
        self.assertIn("url.ip_host", ids(self.scan("http://2130706433/")[0]))
        self.assertIn("url.userinfo", ids(self.scan("https://paypal.com@evil.example/")[0]))
        self.assertIn("url.shortener", ids(self.scan("https://bit.ly/abc")[0]))

    def test_domain_in_subdomain(self):
        self.assertIn("url.domain_in_subdomain", ids(self.scan("https://www.sbi.co.in.kyc-update.top/")[0]))

    def test_indian_services(self):
        f, feats = self.scan("https://sbi-kyc-update.in/login")
        self.assertEqual(feats["impersonated_brand"], "State Bank of India")
        f2, feats2 = self.scan("https://onlinesbi.sbi/")
        self.assertEqual(feats2["known_brand"], "State Bank of India")

    def test_plain_site_has_no_threat_findings(self):
        f, _ = self.scan("https://example.org/about")
        self.assertEqual([x for x in f if (x.weight or 0) > 7], [])

    def test_registered_domain(self):
        self.assertEqual(domains.registered_domain("a.b.sbi.co.in"), "sbi.co.in")
        self.assertEqual(domains.registered_domain("www.example.com"), "example.com")

    def test_bad_input(self):
        for bad in ("", "ftp://x.com", "javascript:alert(1)"):
            with self.assertRaises(ValueError):
                url_analyzer.analyze_url(url_analyzer.normalize_url(bad))


class KeyCheckTests(unittest.TestCase):
    def test_small_factor(self):
        n = 3 * next_prime(2 ** 1023)
        self.assertEqual(keychecks.small_factor(n), 3)
        self.assertTrue(any(i[0] == "small_factor" for i in keychecks.check_rsa(n, 65537)))

    def test_close_primes_detected(self):
        p = next_prime(2 ** 1023 + 12345)
        q = next_prime(p + 2000)
        t = time.time()
        issues = keychecks.check_rsa(p * q, 65537)
        self.assertTrue(any(i[0] == "close_primes" for i in issues), issues)
        self.assertLess(time.time() - t, 5)

    def test_independent_primes_pass(self):
        p = next_prime(3 * 2 ** 1022 + 98765)
        q = next_prime(3 * 2 ** 1022 + 2 ** 1010 + 4321)
        self.assertEqual((p * q).bit_length(), 2048)
        t = time.time()
        issues = keychecks.check_rsa(p * q, 65537)
        self.assertEqual(issues, [])
        self.assertLess(time.time() - t, 5)

    def test_short_key_and_bad_exponent(self):
        p, q = next_prime(2 ** 511 + 77), next_prime(2 ** 511 + 2 ** 500 + 5)
        kinds = {i[0] for i in keychecks.check_rsa(p * q, 65537)}
        self.assertIn("weak_rsa_size", kinds)
        self.assertIn("bad_rsa_exponent", {i[0] for i in keychecks.check_rsa(p * q, 4)})


class SsrfTests(unittest.TestCase):
    def test_ip_policy(self):
        bad = ["127.0.0.1", "10.1.2.3", "172.16.0.5", "192.168.1.1", "169.254.169.254", "0.0.0.0", "::1", "fe80::1",
               "fc00::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::1", "100.64.0.1", "224.0.0.1"]
        for ip in bad:
            self.assertFalse(netsafe.ip_is_public(ipaddress.ip_address(ip)), ip)
        for ip in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
            self.assertTrue(netsafe.ip_is_public(ipaddress.ip_address(ip)), ip)

    def test_resolution_blocks(self):
        for host in ("127.0.0.1", "localhost", "2130706433", "0x7f.1", "[::1]"):
            with self.assertRaises((netsafe.BlockedTarget, OSError)):
                netsafe.resolve_public(host, 80)

    def test_fetch_reports_block(self):
        r = netsafe.safe_fetch("http://127.0.0.1:80/")
        self.assertTrue(r.error and r.error.startswith("Blocked"), r.error)
        r = netsafe.safe_fetch("http://example.com:22/")
        self.assertTrue(r.error and "Port 22" in r.error, r.error)

    def test_rejects_other_schemes(self):
        for u in ("file:///etc/passwd", "ftp://example.com/"):
            self.assertIn("http", netsafe.safe_fetch(u).error)

    def test_pinned_connect_rechecks_dns(self):
        """A host that resolves public at check time but private at connect time must not connect."""
        calls = []

        def fake_getaddrinfo(host, port, **kw):
            calls.append(host)
            ip = "93.184.216.34" if len(calls) == 1 else "127.0.0.1"
            return [(2, 1, 6, "", (ip, port))]

        with mock.patch.object(netsafe.socket, "getaddrinfo", fake_getaddrinfo):
            netsafe.resolve_public("rebind.example", 80)  # first lookup: public
            with self.assertRaises(netsafe.BlockedTarget):
                netsafe.pinned_connect("rebind.example", 80, 2)  # second lookup: private


class IntelAndScoringTests(unittest.TestCase):
    def test_reports_dedupe_and_levels(self):
        s = IntelStore()
        self.assertEqual(s.add_report("http://evil.example/login?token=secret", "phishing", "bad", "r1")["status"], "recorded")
        self.assertEqual(s.add_report("http://evil.example/other", "phishing", "bad", "r1")["status"], "duplicate")
        self.assertEqual(s.reputation("evil.example")["level"], "weak")
        for r in ("r2", "r3", "r4"):
            s.add_report("http://evil.example/", "phishing", "", r)
        rep = s.reputation("evil.example")
        self.assertEqual(rep["level"], "confirmed")
        self.assertEqual(rep["unique_reporters"], 4)
        row = s._db.execute("SELECT url FROM reports WHERE reporter='r1'").fetchone()
        self.assertNotIn("secret", row["url"])  # query string never stored

    def test_disputes_reduce_score(self):
        s = IntelStore()
        for r in ("a", "b", "c"):
            s.add_report("http://x.example", "phishing", "", r)
        before = s.reputation("x.example")["score"]
        for r in ("d", "e", "f", "g"):
            s.vote("http://x.example", "dispute", r)
        self.assertLess(s.reputation("x.example")["score"], before)

    def test_decay(self):
        s = IntelStore()
        s.add_report("http://old.example", "phishing", "", "r1")
        s._db.execute("UPDATE reports SET created_at = created_at - ?", (60 * 86400,))
        self.assertLess(s.reputation("old.example")["score"], 0.1)

    def test_feed_and_import(self):
        s = IntelStore()
        n = s.import_feed(["# comment", "http://bad.example/x", "worse.example", "", "not a host!!"], "openfeed")
        self.assertEqual(n, 2)
        self.assertEqual(s.feed_matches("bad.example")[0]["source"], "openfeed")

    def test_shared_prime_detection(self):
        s = IntelStore()
        p = next_prime(2 ** 1023 + 999)
        q1, q2 = next_prime(2 ** 1023 + 2 ** 1015), next_prime(2 ** 1023 + 2 ** 1016)
        s.record_key("a" * 64, "RSA", format(p * q1, "x"), "site-a", "ca")
        self.assertIsNotNone(s.find_shared_prime(p * q2, "b" * 64))
        r1, r2 = next_prime(2 ** 1023 + 2 ** 1000), next_prime(2 ** 1023 + 2 ** 1018)
        self.assertNotIn(r1, (p, q1, q2))
        self.assertIsNone(s.find_shared_prime(r1 * r2, "c" * 64))

    def test_scoring(self):
        weak = [Finding("a", "url", "threat", "low", "x"), Finding("b", "content", "threat", "low", "y")]
        self.assertLess(scoring.threat_score(weak), 20)
        strong = [Finding("a", "url", "threat", "high", "x"), Finding("b", "content", "threat", "high", "y")]
        self.assertGreaterEqual(scoring.threat_score(strong), 70)
        self.assertEqual(scoring.threat_score([Finding("f", "intel", "threat", "high", "z", floor=85)]), 85)
        hygiene = [Finding("h", "security", "posture", "medium", "h", weight=0, posture_weight=12)]
        self.assertEqual(scoring.threat_score(hygiene), 0)
        self.assertEqual(scoring.posture(hygiene), (88, "B"))


if __name__ == "__main__":
    unittest.main()
