# Verification record

Verified on 11 November 2026 (Asia/Kolkata) against the supplied problem statement.

## Automated checks

- **75 Python tests passed**, including **28 regression cases** added during this audit.
- A fresh project virtual environment installed the declared dependencies successfully: Flask 3.1.3, requests 2.34.2, cryptography 48.0.1, pytest 9.2.0 on Windows/Python 3.15.2.
- `pip check` and JavaScript syntax validation passed.
- Real local TLS fixtures cover trusted, self-signed, wrong-host, close-prime, and shared-prime certificates. SSRF blocking, redirect checks, and explicitly authorized exposure tests are exercised.
- New regressions cover serverless writable storage, strict JSON/boolean validation, HTTP 400/405/413 responses, feed bounds/exports, certificate port restrictions, inconclusive results, redirected-target scoring/TLS, demo isolation, usable PEM samples, and weak frame/CSP configurations.
- Vercel's preview build used Python 3.13 and successfully initialized the app. Preview API checks exercised live `example.com` scanning, private-address blocking, synthetic demo results, real weak-PEM detection, feed/export, and deployed assets. Vercel adds its own preview-feedback script to HTML; the application markup and JS/CSS were checked separately.

## Browser checks

A real Chromium browser exercised the application rather than a static HTML mockup:

- All five scenarios and all six detail tabs per scenario.
- Arrow-key tab navigation and JSON download.
- Real weak-key sample loading, repeated PEM audit, empty/malformed PEM errors, and recovery through live-host inspection.
- Missing/invalid URL errors, correction and live HTTPS scanning, unavailable-host inconclusive state.
- Local reserved-domain report submission, updated reputation, dispute voting, duplicate-report feedback, feed filters, and CSV download. Synthetic demos cannot submit reports through their results view.
- Widths 320, 390, 768, and 1440 pixels without page-level horizontal overflow. Wide, narrow, result, mobile lab, mobile hardening, and dark/reduced-motion captures were visually inspected against the existing paper/ultramarine design.
- No uncaught browser JavaScript errors. Deliberately malformed API requests returned the expected HTTP 400 resource messages in the console.

Local evidence and source hashes are kept in ignored `output/playwright/visual-evidence.json` and adjacent captures. They are development evidence, not public application assets. Protected preview APIs were verified with Vercel's authenticated CLI; public production UI is checked after release.

## Boundaries

This is an explainable heuristic scanner. These tests do not establish phishing-detection accuracy, exhaustive cryptographic validation, accessibility certification, or compatibility with every device/browser. The static architecture graph used during inspection had unresolved external-symbol endpoints; runtime checks and source inspection supplied the verification evidence.

Temporary Vercel SQLite storage was explicitly selected. Reports, votes, imported feeds, and scanned-key history are instance-local and may reset. Online revocation checking, cryptographic SCT verification, a continuously maintained compromised-key feed, distributed rate limiting, and a trained ML classifier are not implemented. See [deployment](DEPLOYMENT.md) and [README limitations](../README.md#what-the-results-mean).
