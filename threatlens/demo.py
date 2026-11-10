"""Realistic threat scenarios and mock demonstrations for testing and education."""
from __future__ import annotations

import datetime as dt
import copy
from datetime import timezone

SCENARIOS = {
    "sbi_kyc_phish": {
        "id": "sbi_kyc_phish",
        "title": "State Bank of India KYC Phishing Scam",
        "category": "Banking & Identity Theft",
        "description": "Deceptive portal imitating SBI. Solicits PAN, NetBanking password and OTP under threat of 24-hour account suspension, with cross-domain form submission.",
        "url": "https://sbi-kyc-verification.top/login.php",
        "threat_level": "danger",
        "threat_score": 95,
        "posture_grade": "F",
        "result": {
            "url": "https://sbi-kyc-verification.top/login.php",
            "host": "sbi-kyc-verification.top",
            "scanned_at": dt.datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_ms": 312,
            "verdict": {
                "label": "Dangerous",
                "level": "danger",
                "threat_score": 95,
                "confidence": "high",
                "summary": "Brand impersonation of State Bank of India; credential-harvesting form (password, PAN, OTP); form submits to an external domain; urgent pressure language.",
                "advice": [
                    "Do not enter passwords, card details, PAN or OTPs.",
                    "If you already submitted details, change your SBI NetBanking password immediately and contact your bank.",
                    "Access official SBI NetBanking exclusively at https://onlinesbi.sbi or using the YONO SBI mobile app."
                ]
            },
            "posture": {"grade": "F", "score": 18},
            "findings": [
                {
                    "id": "url.brand_in_domain",
                    "engine": "url",
                    "axis": "threat",
                    "severity": "high",
                    "title": "Domain name contains 'sbi' but does not belong to State Bank of India",
                    "detail": "Hosted on 'sbi-kyc-verification.top', not on official 'sbi.co.in' or 'onlinesbi.sbi'.",
                    "advice": "Do not trust brand names embedded in unofficial domains.",
                    "weight": 35
                },
                {
                    "id": "url.suspicious_tld",
                    "engine": "url",
                    "axis": "threat",
                    "severity": "medium",
                    "title": "Domain uses suspicious high-risk TLD (.top)",
                    "detail": "TLD frequently exploited for short-lived disposable phishing attacks.",
                    "advice": "Exercise caution with unconventional domain extensions.",
                    "weight": 15
                },
                {
                    "id": "content.brand_mismatch",
                    "engine": "content",
                    "axis": "threat",
                    "severity": "high",
                    "title": "Page presents itself as State Bank of India and collects credentials",
                    "detail": "Presents official SBI branding and logos while hosted on an unrelated domain.",
                    "advice": "Open State Bank of India from its official app or verified URL.",
                    "weight": 40
                },
                {
                    "id": "content.sensitive_fields",
                    "engine": "content",
                    "axis": "threat",
                    "severity": "high",
                    "title": "Page collects sensitive credentials: PAN, Bank Account, Password, OTP",
                    "detail": "Input fields explicitly capture NetBanking credentials, OTP and identity documents.",
                    "advice": "Never share OTP or banking passwords on third-party links.",
                    "weight": 30
                },
                {
                    "id": "content.form_cross_domain",
                    "engine": "content",
                    "axis": "threat",
                    "severity": "critical",
                    "title": "Login form secretly submits data to another domain",
                    "detail": "Page is hosted on sbi-kyc-verification.top but credentials submit to 'https://steal-credentials.xyz/collect.php'.",
                    "advice": "Never enter credentials here; data is exfiltrated to an unknown server.",
                    "weight": 65
                },
                {
                    "id": "content.urgency_language",
                    "engine": "content",
                    "axis": "threat",
                    "severity": "medium",
                    "title": "High-pressure urgency language typical of account-takeover scams",
                    "detail": "'account will be suspended within 24 hours', 'immediate action required', 'kyc update expired'.",
                    "advice": "Banks do not send sudden threats to freeze accounts via unofficial links.",
                    "weight": 18
                },
                {
                    "id": "cert.brand_new",
                    "engine": "certificate",
                    "axis": "threat",
                    "severity": "low",
                    "title": "Certificate was issued within the last 24 hours",
                    "detail": "Phishing domains commonly obtain automated certificates hours before launching campaigns.",
                    "advice": "",
                    "weight": 7
                },
                {
                    "id": "sec.no_hsts",
                    "engine": "security",
                    "axis": "posture",
                    "severity": "medium",
                    "title": "Strict-Transport-Security header is missing",
                    "detail": "Missing HSTS allows potential downgrade attacks.",
                    "advice": "Send Strict-Transport-Security with max-age >= 15552000.",
                    "posture_weight": 10
                },
                {
                    "id": "sec.no_csp",
                    "engine": "security",
                    "axis": "posture",
                    "severity": "medium",
                    "title": "Content-Security-Policy header is missing",
                    "detail": "No restriction on script sources or form submission targets.",
                    "advice": "Deploy CSP to prevent data exfiltration and cross-site scripting.",
                    "posture_weight": 12
                }
            ],
            "certificate": {
                "host": "sbi-kyc-verification.top",
                "port": 443,
                "ip": "198.51.100.44",
                "trusted": True,
                "protocol": "TLSv1.3",
                "cipher": "TLS_AES_128_GCM_SHA256",
                "subject_cn": "sbi-kyc-verification.top",
                "issuer": "Let's Encrypt Authority X3",
                "san": ["sbi-kyc-verification.top", "www.sbi-kyc-verification.top"],
                "not_before": dt.datetime.now(timezone.utc).isoformat(),
                "not_after": (dt.datetime.now(timezone.utc) + dt.timedelta(days=90)).isoformat(),
                "days_left": 90,
                "validity_days": 90,
                "key": "EC secp256r1",
                "signature": "sha256",
                "self_signed": False,
                "sha256": "3a4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef012",
                "serial": "03fa99b18972ec01a",
                "transparency": {"embedded_scts": 2, "crtsh": "found"},
                "chain": [
                    {"role": "leaf", "subject": "sbi-kyc-verification.top", "issuer": "R3", "key": "EC secp256r1", "spki_sha256": "aa11bb22cc33", "not_after": "2027-02-09"},
                    {"role": "intermediate", "subject": "R3", "issuer": "ISRG Root X1", "key": "RSA 2048", "spki_sha256": "dd44ee55ff66", "not_after": "2030-09-15"}
                ]
            },
            "headers": [
                {"name": "Strict-Transport-Security", "present": False, "value": "", "status": "fail", "note": "Missing"},
                {"name": "Content-Security-Policy", "present": False, "value": "", "status": "fail", "note": "Missing"},
                {"name": "X-Frame-Options", "present": False, "value": "", "status": "fail", "note": "Missing"},
                {"name": "X-Content-Type-Options", "present": False, "value": "", "status": "fail", "note": "Missing"},
                {"name": "Referrer-Policy", "present": False, "value": "", "status": "fail", "note": "Missing"}
            ],
            "page": {
                "title": "State Bank of India - KYC Verification Portal",
                "forms": 1,
                "password_fields": 1,
                "iframes": 0,
                "scripts": 2,
                "links": 3,
                "text_chars": 1420
            },
            "http": {
                "status": 200,
                "final_url": "https://sbi-kyc-verification.top/login.php",
                "redirects": [],
                "elapsed_ms": 140,
                "error": None
            },
            "features": {
                "host": "sbi-kyc-verification.top",
                "registered_domain": "sbi-kyc-verification.top",
                "scheme": "https",
                "tld": "top",
                "url_length": 45,
                "is_ip": False,
                "impersonated_brand": "State Bank of India",
                "known_brand": None,
                "unicode_host": None
            },
            "community": {
                "host": "sbi-kyc-verification.top",
                "level": "confirmed",
                "score": 4.8,
                "reports": 6,
                "unique_reporters": 5,
                "categories": {"phishing": 4, "impersonation": 2},
                "confirmations": 12,
                "disputes": 0,
                "last_report": dt.datetime.now(timezone.utc).timestamp(),
                "effective_level": "confirmed"
            },
            "coverage": [
                {"engine": "url", "status": "ok", "note": ""},
                {"engine": "intel", "status": "ok", "note": ""},
                {"engine": "certificate", "status": "ok", "note": ""},
                {"engine": "content", "status": "ok", "note": ""},
                {"engine": "security", "status": "ok", "note": ""}
            ],
            "notes": []
        }
    },
    "recruitment_advance_fee": {
        "id": "recruitment_advance_fee",
        "title": "Advance-Fee Recruitment Fraud",
        "category": "Employment & Education Fraud",
        "description": "Fake recruitment portal offering remote data-entry jobs with ₹45,000 salary while demanding a non-refundable registration and laptop deposit fee.",
        "url": "https://tcs-careers-interview.online/apply",
        "threat_level": "danger",
        "threat_score": 88,
        "posture_grade": "F",
        "result": {
            "url": "https://tcs-careers-interview.online/apply",
            "host": "tcs-careers-interview.online",
            "scanned_at": dt.datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_ms": 280,
            "verdict": {
                "label": "Dangerous",
                "level": "danger",
                "threat_score": 88,
                "confidence": "high",
                "summary": "Advance fee recruitment scam detected; unauthorized use of company brand; registration fee demanded for appointment letter.",
                "advice": [
                    "Never pay registration, training, or kit fees to receive a job.",
                    "Legitimate recruiters (such as TCS, Infosys, Wipro) do not charge application fees or send WhatsApp interview links.",
                    "Apply only on official corporate career portals."
                ]
            },
            "posture": {"grade": "F", "score": 25},
            "findings": [
                {
                    "id": "content.advance_fee_recruitment",
                    "engine": "content",
                    "axis": "threat",
                    "severity": "high",
                    "title": "Job offer demands an advance registration or deposit fee",
                    "detail": "Prompts payment of '₹2,500 refundable security deposit for appointment letter and laptop dispatch'.",
                    "advice": "Genuine employers never demand money from candidates.",
                    "weight": 50
                },
                {
                    "id": "url.brand_in_domain",
                    "engine": "url",
                    "axis": "threat",
                    "severity": "high",
                    "title": "Domain mimics 'TCS' on an unofficial registered domain",
                    "detail": "Registered under 'tcs-careers-interview.online', not the official corporate domain.",
                    "advice": "Verify job openings directly on the employer's official website.",
                    "weight": 35
                },
                {
                    "id": "content.malicious_app_lure",
                    "engine": "content",
                    "axis": "threat",
                    "severity": "high",
                    "title": "Prompts download of sideloaded APK or remote screen-sharing tool",
                    "detail": "Asks candidates to install 'InterviewAssistant.apk' to proceed with the hiring process.",
                    "advice": "Never sideload APKs; they often contain spyware or remote-access Trojans.",
                    "weight": 20
                }
            ],
            "certificate": {
                "host": "tcs-careers-interview.online",
                "port": 443,
                "ip": "203.0.113.88",
                "trusted": True,
                "protocol": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "subject_cn": "tcs-careers-interview.online",
                "issuer": "ZeroSSL RSA Domain Secure Site CA",
                "san": ["tcs-careers-interview.online"],
                "not_before": dt.datetime.now(timezone.utc).isoformat(),
                "not_after": (dt.datetime.now(timezone.utc) + dt.timedelta(days=90)).isoformat(),
                "days_left": 89,
                "validity_days": 90,
                "key": "RSA 2048",
                "signature": "sha256",
                "self_signed": False,
                "sha256": "4b5c6d7e8f90123456789abcdef0123456789abcdef0123456789abcdef01234",
                "serial": "1122334455667788",
                "transparency": {"embedded_scts": 2, "crtsh": "found"},
                "chain": [
                    {"role": "leaf", "subject": "tcs-careers-interview.online", "issuer": "ZeroSSL Sub CA", "key": "RSA 2048", "spki_sha256": "123456", "not_after": "2027-02-09"}
                ]
            },
            "headers": [
                {"name": "Strict-Transport-Security", "present": False, "value": "", "status": "fail", "note": "Missing"},
                {"name": "Content-Security-Policy", "present": False, "value": "", "status": "fail", "note": "Missing"}
            ],
            "page": {
                "title": "TCS Global Hiring - Remote Operations Selection Portal",
                "forms": 1,
                "password_fields": 0,
                "iframes": 0,
                "scripts": 3,
                "links": 2,
                "text_chars": 2100
            },
            "http": {"status": 200, "final_url": "https://tcs-careers-interview.online/apply", "redirects": [], "elapsed_ms": 160, "error": None},
            "features": {"host": "tcs-careers-interview.online", "registered_domain": "tcs-careers-interview.online", "scheme": "https", "tld": "online", "url_length": 42, "is_ip": False, "impersonated_brand": "Tata Consultancy Services", "known_brand": None, "unicode_host": None},
            "community": {"host": "tcs-careers-interview.online", "level": "reported", "score": 3.2, "reports": 4, "unique_reporters": 4, "categories": {"fake_recruitment": 4}, "confirmations": 8, "disputes": 0, "last_report": dt.datetime.now(timezone.utc).timestamp(), "effective_level": "reported"},
            "coverage": [{"engine": "url", "status": "ok", "note": ""}, {"engine": "intel", "status": "ok", "note": ""}, {"engine": "certificate", "status": "ok", "note": ""}, {"engine": "content", "status": "ok", "note": ""}, {"engine": "security", "status": "ok", "note": ""}],
            "notes": []
        }
    },
    "emudhra_compromised_ca": {
        "id": "emudhra_compromised_ca",
        "title": "eMudhra Incident & Flawed CA Hierarchy",
        "category": "Certificate Authority Trust Failure",
        "description": "Inspects a TLS certificate whose chain includes an eMudhra intermediate CA compromised by flawed key generation, leading to industry-wide browser distrust.",
        "url": "https://portal.bank-gateway.org/login",
        "threat_level": "high",
        "threat_score": 75,
        "posture_grade": "F",
        "result": {
            "url": "https://portal.bank-gateway.org/login",
            "host": "portal.bank-gateway.org",
            "scanned_at": dt.datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_ms": 215,
            "verdict": {
                "label": "High risk",
                "level": "high",
                "threat_score": 75,
                "confidence": "high",
                "summary": "Certificate chain relies on an intermediate CA subject to public distrust (eMudhra Global TLS Incident); chain validation rejected by modern root stores.",
                "advice": [
                    "Treat this site as untrusted; the Certificate Authority's key generation ceremony was compromised.",
                    "Fraudulent certificates could potentially be minted without authorization.",
                    "Website operators must replace the certificate with one issued by an unaffected, trusted CA."
                ]
            },
            "posture": {"grade": "F", "score": 30},
            "findings": [
                {
                    "id": "cert.issuer_watch",
                    "engine": "certificate",
                    "axis": "both",
                    "severity": "critical",
                    "title": "eMudhra Global TLS Incident: Intermediate CA key generation flawed",
                    "detail": "eMudhra disclosed that eight intermediate CAs in its global TLS hierarchy had weak private keys from a flawed ceremony on 30 Apr 2025. Mozilla OneCRL and Google Chrome Root Programs distrusted the affected intermediates.",
                    "advice": "Do not trust certificates chained to eMudhra intermediate CAs under public incident review.",
                    "weight": 60,
                    "floor": 75
                },
                {
                    "id": "cert.untrusted",
                    "engine": "certificate",
                    "axis": "both",
                    "severity": "high",
                    "title": "Certificate chain does not lead to a trusted authority",
                    "detail": "The issuing intermediate CA has been distrusted or revoked in browser root trust stores.",
                    "advice": "Do not proceed past browser certificate warnings.",
                    "weight": 40
                },
                {
                    "id": "cert.no_sct",
                    "engine": "certificate",
                    "axis": "threat",
                    "severity": "medium",
                    "title": "Missing Certificate Transparency (CT) proofs",
                    "detail": "No embedded Signed Certificate Timestamps (SCTs) found; cannot verify public logging.",
                    "advice": "Ensure all public TLS certificates are logged to public CT logs.",
                    "weight": 20
                }
            ],
            "certificate": {
                "host": "portal.bank-gateway.org",
                "port": 443,
                "ip": "192.0.2.77",
                "trusted": False,
                "trust_error": "Certificate authority distrusted by root programs (eMudhra incident)",
                "protocol": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "subject_cn": "portal.bank-gateway.org",
                "issuer": "eMudhra Sub CA - TLS 2025",
                "san": ["portal.bank-gateway.org", "*.bank-gateway.org"],
                "not_before": "2025-05-15T00:00:00+00:00",
                "not_after": "2026-05-15T23:59:59+00:00",
                "days_left": -177,
                "validity_days": 365,
                "key": "EC secp384r1",
                "signature": "sha384",
                "self_signed": False,
                "sha256": "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b",
                "serial": "7766554433221100",
                "transparency": {"embedded_scts": 0, "crtsh": "not_found"},
                "chain": [
                    {
                        "role": "leaf",
                        "subject": "portal.bank-gateway.org",
                        "issuer": "eMudhra Sub CA - TLS 2025",
                        "key": "EC secp384r1",
                        "spki_sha256": "47deb542129d2f707f15b81e8b7a4f9104050e687258380e227aa71c42f0b7e2",
                        "not_after": "2026-05-15"
                    },
                    {
                        "role": "intermediate",
                        "subject": "eMudhra Sub CA - TLS 2025",
                        "issuer": "eMudhra Root CA",
                        "key": "EC secp384r1",
                        "spki_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "not_after": "2035-04-30"
                    }
                ]
            },
            "headers": [
                {"name": "Strict-Transport-Security", "present": True, "value": "max-age=31536000", "status": "pass", "note": ""},
                {"name": "Content-Security-Policy", "present": False, "value": "", "status": "fail", "note": "Missing"}
            ],
            "page": {"title": "Corporate Banking Gateway", "forms": 1, "password_fields": 1, "iframes": 0, "scripts": 1, "links": 0, "text_chars": 450},
            "http": {"status": 200, "final_url": "https://portal.bank-gateway.org/login", "redirects": [], "elapsed_ms": 110, "error": None},
            "features": {"host": "portal.bank-gateway.org", "registered_domain": "bank-gateway.org", "scheme": "https", "tld": "org", "url_length": 37, "is_ip": False, "impersonated_brand": None, "known_brand": None, "unicode_host": None},
            "community": {"host": "portal.bank-gateway.org", "level": "none", "score": 0.0, "reports": 0, "unique_reporters": 0, "categories": {}, "confirmations": 0, "disputes": 0, "last_report": None, "effective_level": "none"},
            "coverage": [{"engine": "url", "status": "ok", "note": ""}, {"engine": "intel", "status": "ok", "note": ""}, {"engine": "certificate", "status": "ok", "note": ""}, {"engine": "content", "status": "ok", "note": ""}, {"engine": "security", "status": "ok", "note": ""}],
            "notes": []
        }
    },
    "weak_fermat_key": {
        "id": "weak_fermat_key",
        "title": "Cryptographic Key Flaw: Fermat Factorization",
        "category": "Cryptographic Vulnerability",
        "description": "Demonstrates detection of an RSA-2048 public key generated with close prime factors (p ≈ q). Anyone can factor the modulus in milliseconds and forge certificates.",
        "url": "https://legacy-payment-hub.internal/verify",
        "threat_level": "danger",
        "threat_score": 85,
        "posture_grade": "F",
        "result": {
            "url": "https://legacy-payment-hub.internal/verify",
            "host": "legacy-payment-hub.internal",
            "scanned_at": dt.datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_ms": 195,
            "verdict": {
                "label": "Dangerous",
                "level": "danger",
                "threat_score": 85,
                "confidence": "high",
                "summary": "Critical cryptographic flaw: RSA modulus factors instantly using Fermat's method; private key can be computed by any eavesdropper.",
                "advice": [
                    "Immediately revoke and replace the SSL certificate.",
                    "Regenerate the RSA key pair using a cryptographically secure random number generator (CSPRNG).",
                    "Do not transmit sensitive payment credentials over this connection."
                ]
            },
            "posture": {"grade": "F", "score": 35},
            "findings": [
                {
                    "id": "cert.close_primes",
                    "engine": "certificate",
                    "axis": "both",
                    "severity": "critical",
                    "title": "RSA modulus factors with Fermat's method in leaf certificate",
                    "detail": "The two 1024-bit primes p and q are only ~1,840 apart. Fermat's factorization reveals the private key in less than 5 milliseconds.",
                    "advice": "Regenerate the private key immediately with independent random primes.",
                    "weight": 65,
                    "floor": 85
                },
                {
                    "id": "cert.untrusted",
                    "engine": "certificate",
                    "axis": "both",
                    "severity": "high",
                    "title": "Certificate chain does not lead to a trusted authority",
                    "detail": "Internal self-signed root not recognized by public PKI.",
                    "advice": "Deploy certificates issued by recognized public CAs.",
                    "weight": 40
                }
            ],
            "certificate": {
                "host": "legacy-payment-hub.internal",
                "port": 443,
                "ip": "10.0.0.12",
                "trusted": False,
                "protocol": "TLSv1.2",
                "cipher": "ECDHE-RSA-AES256-GCM-SHA384",
                "subject_cn": "legacy-payment-hub.internal",
                "issuer": "Internal Root CA",
                "san": ["legacy-payment-hub.internal"],
                "not_before": "2026-01-01T00:00:00+00:00",
                "not_after": "2027-01-01T00:00:00+00:00",
                "days_left": 53,
                "validity_days": 365,
                "key": "RSA 2048 (Fermat-vulnerable)",
                "signature": "sha256",
                "self_signed": False,
                "sha256": "1f2e3d4c5b6a7980abcdef1234567890abcdef1234567890abcdef1234567890",
                "serial": "9988776655",
                "transparency": {"embedded_scts": 0, "crtsh": "not_found"},
                "chain": [
                    {"role": "leaf", "subject": "legacy-payment-hub.internal", "issuer": "Internal Root CA", "key": "RSA 2048", "spki_sha256": "closeprimes123", "not_after": "2027-01-01"}
                ]
            },
            "headers": [
                {"name": "Strict-Transport-Security", "present": False, "value": "", "status": "fail", "note": "Missing"},
                {"name": "Content-Security-Policy", "present": False, "value": "", "status": "fail", "note": "Missing"}
            ],
            "page": {"title": "Legacy Payment Settlement Gateway", "forms": 1, "password_fields": 1, "iframes": 0, "scripts": 0, "links": 0, "text_chars": 320},
            "http": {"status": 200, "final_url": "https://legacy-payment-hub.internal/verify", "redirects": [], "elapsed_ms": 95, "error": None},
            "features": {"host": "legacy-payment-hub.internal", "registered_domain": "legacy-payment-hub.internal", "scheme": "https", "tld": "internal", "url_length": 42, "is_ip": False, "impersonated_brand": None, "known_brand": None, "unicode_host": None},
            "community": {"host": "legacy-payment-hub.internal", "level": "none", "score": 0.0, "reports": 0, "unique_reporters": 0, "categories": {}, "confirmations": 0, "disputes": 0, "last_report": None, "effective_level": "none"},
            "coverage": [{"engine": "url", "status": "ok", "note": ""}, {"engine": "intel", "status": "ok", "note": ""}, {"engine": "certificate", "status": "ok", "note": ""}, {"engine": "content", "status": "ok", "note": ""}, {"engine": "security", "status": "ok", "note": ""}],
            "notes": []
        }
    },
    "hardened_bank": {
        "id": "hardened_bank",
        "title": "Legitimate Bank Reference (Clean Baseline)",
        "category": "Legitimate & Hardened Service",
        "description": "Baseline scan of an authentic, fully hardened online banking infrastructure demonstrating TLS 1.3, HSTS preloading, strict CSP, and valid public CA trust.",
        "url": "https://www.hdfcbank.com/personal",
        "threat_level": "ok",
        "threat_score": 0,
        "posture_grade": "A+",
        "result": {
            "url": "https://www.hdfcbank.com/personal",
            "host": "www.hdfcbank.com",
            "scanned_at": dt.datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_ms": 178,
            "verdict": {
                "label": "Low risk",
                "level": "ok",
                "threat_score": 0,
                "confidence": "high",
                "summary": "No signs of phishing or malicious behaviour found; domain matches verified legitimate brand; TLS certificate valid and publicly logged.",
                "advice": []
            },
            "posture": {"grade": "A+", "score": 98},
            "findings": [
                {
                    "id": "sec.hsts_pass",
                    "engine": "security",
                    "axis": "posture",
                    "severity": "info",
                    "title": "Strict-Transport-Security enabled with preload and subdomains",
                    "detail": "max-age=31536000; includeSubDomains; preload",
                    "advice": "",
                    "posture_weight": 0
                },
                {
                    "id": "sec.csp_pass",
                    "engine": "security",
                    "axis": "posture",
                    "severity": "info",
                    "title": "Comprehensive Content-Security-Policy deployed",
                    "detail": "default-src 'self'; script-src 'self' 'nonce-...'",
                    "advice": "",
                    "posture_weight": 0
                }
            ],
            "certificate": {
                "host": "www.hdfcbank.com",
                "port": 443,
                "ip": "104.18.25.10",
                "trusted": True,
                "protocol": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "subject_cn": "www.hdfcbank.com",
                "issuer": "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
                "san": ["www.hdfcbank.com", "hdfcbank.com"],
                "not_before": "2026-03-01T00:00:00+00:00",
                "not_after": "2027-03-01T23:59:59+00:00",
                "days_left": 112,
                "validity_days": 365,
                "key": "RSA 2048",
                "signature": "sha256",
                "self_signed": False,
                "sha256": "887766554433221100aabbccddeeff00112233445566778899aabbccddeeff00",
                "serial": "029fa8c187b2210a",
                "transparency": {"embedded_scts": 3, "crtsh": "found"},
                "chain": [
                    {"role": "leaf", "subject": "www.hdfcbank.com", "issuer": "DigiCert Global G2", "key": "RSA 2048", "spki_sha256": "digicert1122", "not_after": "2027-03-01"},
                    {"role": "intermediate", "subject": "DigiCert Global G2", "issuer": "DigiCert Global Root G2", "key": "RSA 2048", "spki_sha256": "digiroot2233", "not_after": "2030-09-24"}
                ]
            },
            "headers": [
                {"name": "Strict-Transport-Security", "present": True, "value": "max-age=31536000; includeSubDomains; preload", "status": "pass", "note": ""},
                {"name": "Content-Security-Policy", "present": True, "value": "default-src 'self'; frame-ancestors 'none'", "status": "pass", "note": ""},
                {"name": "X-Frame-Options", "present": True, "value": "DENY", "status": "pass", "note": ""},
                {"name": "X-Content-Type-Options", "present": True, "value": "nosniff", "status": "pass", "note": ""},
                {"name": "Referrer-Policy", "present": True, "value": "strict-origin-when-cross-origin", "status": "pass", "note": ""},
                {"name": "Cross-Origin-Opener-Policy", "present": True, "value": "same-origin", "status": "pass", "note": ""}
            ],
            "page": {"title": "HDFC Bank: Personal Banking Services", "forms": 1, "password_fields": 0, "iframes": 0, "scripts": 8, "links": 42, "text_chars": 4800},
            "http": {"status": 200, "final_url": "https://www.hdfcbank.com/personal", "redirects": [], "elapsed_ms": 115, "error": None},
            "features": {"host": "www.hdfcbank.com", "registered_domain": "hdfcbank.com", "scheme": "https", "tld": "com", "url_length": 34, "is_ip": False, "impersonated_brand": None, "known_brand": "HDFC Bank", "unicode_host": None},
            "community": {"host": "www.hdfcbank.com", "level": "none", "score": 0.0, "reports": 0, "unique_reporters": 0, "categories": {}, "confirmations": 25, "disputes": 0, "last_report": None, "effective_level": "none"},
            "coverage": [{"engine": "url", "status": "ok", "note": ""}, {"engine": "intel", "status": "ok", "note": ""}, {"engine": "certificate", "status": "ok", "note": ""}, {"engine": "content", "status": "ok", "note": ""}, {"engine": "security", "status": "ok", "note": ""}],
            "notes": []
        }
    }
}


def list_scenarios() -> list[dict]:
    return [
        {
            "id": s["id"],
            "title": s["title"],
            "category": s["category"],
            "description": s["description"],
            "url": s["url"],
            "threat_level": s["threat_level"],
            "threat_score": s["threat_score"],
            "posture_grade": s["posture_grade"]
        }
        for s in SCENARIOS.values()
    ]


def get_scenario(scenario_id: str) -> dict | None:
    item = SCENARIOS.get(scenario_id)
    if item is None:
        return None
    result = copy.deepcopy(item["result"])
    result.update(demo=True, scenario=scenario_id)
    return result
