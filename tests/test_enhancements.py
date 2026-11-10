import unittest
import json
from threatlens import cert_analyzer, content_analyzer, demo, domains, keychecks
from threatlens.intel import IntelStore
from threatlens.server import create_app
from threatlens.netsafe import FetchResult

class TestEnhancements(unittest.TestCase):
    def test_new_brands_exist(self):
        brand_names = {b["name"] for b in domains.brands()}
        self.assertIn("Chase Bank", brand_names)
        self.assertIn("Wells Fargo", brand_names)
        self.assertIn("Naukri", brand_names)
        self.assertIn("Passport Seva", brand_names)
        self.assertIn("Coursera", brand_names)

    def test_education_scam_detection(self):
        res = FetchResult(
            url="https://fake-university-degrees.top/admission",
            final_url="https://fake-university-degrees.top/admission",
            status=200,
            content_type="text/html",
            body="<html><title>Instant Degree Portal</title><body><h1>Get degree without exam</h1><p>Pay admission fee now for guaranteed marks.</p></body></html>",
            headers={"content-type": "text/html"}
        )
        findings, page = content_analyzer.analyze_content(res, {"registered_domain": "fake-university-degrees.top"})
        fids = {f.id for f in findings}
        self.assertIn("content.education_scam", fids)

    def test_fake_govt_scheme_detection(self):
        res = FetchResult(
            url="https://claim-pm-kisan-subsidy.xyz/verify",
            final_url="https://claim-pm-kisan-subsidy.xyz/verify",
            status=200,
            content_type="text/html",
            body="<html><title>Government Portal</title><body><h1>PM Kisan Yojana Subsidy Claim</h1><p>Link your aadhaar to receive direct cash transfer.</p></body></html>",
            headers={"content-type": "text/html"}
        )
        findings, page = content_analyzer.analyze_content(res, {"registered_domain": "claim-pm-kisan-subsidy.xyz"})
        fids = {f.id for f in findings}
        self.assertIn("content.fake_govt_scheme", fids)

    def test_demo_scenarios(self):
        scenarios = demo.list_scenarios()
        self.assertGreaterEqual(len(scenarios), 5)
        ids = [s["id"] for s in scenarios]
        self.assertIn("sbi_kyc_phish", ids)
        self.assertIn("recruitment_advance_fee", ids)
        self.assertIn("emudhra_compromised_ca", ids)
        self.assertIn("weak_fermat_key", ids)
        self.assertIn("hardened_bank", ids)

        # Check full scenario output
        for s in ids:
            res = demo.get_scenario(s)
            self.assertIsNotNone(res)
            self.assertIn("verdict", res)
            self.assertIn("posture", res)
            self.assertIn("findings", res)
            self.assertIn("certificate", res)

    def test_server_demo_endpoints(self):
        app = create_app(IntelStore(":memory:"))
        client = app.test_client()

        res = client.get("/api/demo/scenarios")
        self.assertEqual(res.status_code, 200)
        self.assertIn("scenarios", res.get_json())

        res2 = client.post("/api/demo/run", json={"scenario": "emudhra_compromised_ca"})
        self.assertEqual(res2.status_code, 200)
        data2 = res2.get_json()
        self.assertEqual(data2["host"], "portal.bank-gateway.org")
        self.assertIn("eMudhra", data2["verdict"]["summary"])

    def test_server_feed_export_csv(self):
        store = IntelStore(":memory:")
        store.add_report("https://malicious-scam.xyz/pay", "payment_scam", "Fake UPI payment", "rep1")
        store.add_report("https://malicious-scam.xyz/pay", "payment_scam", "Fake UPI payment", "rep2")
        store.add_report("https://malicious-scam.xyz/pay", "payment_scam", "Fake UPI payment", "rep3")
        app = create_app(store)
        client = app.test_client()

        res = client.get("/api/feed/export?format=csv")
        self.assertEqual(res.status_code, 200)
        self.assertIn("attachment; filename=threatlens-feed.csv", res.headers.get("Content-Disposition", ""))
        csv_text = res.data.decode("utf-8")
        self.assertIn("malicious-scam.xyz", csv_text)
        self.assertIn("payment_scam", csv_text)

if __name__ == "__main__":
    unittest.main()
