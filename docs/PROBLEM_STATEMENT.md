# Problem statement

Build an intelligent platform that detects phishing and malicious websites by combining threat analysis, web security assessment, certificate validation, and collaborative threat intelligence.

The internet powers banking, education, recruitment, e-commerce, digital payments, and communication. Phishing websites, fraudulent payment links, fake recruitment portals, impersonation, malicious redirects, deceptive advertising, and credential harvesting put people and organizations at risk. Fraudulent sites can closely resemble legitimate banks, universities, government services, and companies.

Certificates and Certificate Authorities establish HTTPS identity and trust. Weak cryptography, compromised authorities, and mismanaged trust chains can undermine that infrastructure. The eMudhra incident illustrates why cryptographic validation, Certificate Transparency, and continuous trust monitoring matter. Application misconfiguration, exposed services, and outdated software increase risk further.

ThreatLens brings these concerns together in an accessible platform. This implementation uses explainable heuristics rather than a trained ML model, keeps phishing risk separate from configuration hardening, makes incomplete coverage explicit, and supplies synthetic scenarios for education.

## Acceptance mapping

| Required capability | Code | Primary verification |
| --- | --- | --- |
| Threat analysis | `url_analyzer.py`, `content_analyzer.py`, `engine.py` | Lexical/content unit tests and local phishing-page HTTPS fixtures |
| Web security assessment | `web_security.py`, `netsafe.py` | Header/cookie/mixed-content tests and authorized exposed-file fixtures |
| Certificate validation | `cert_analyzer.py`, `keychecks.py` | Trusted/self-signed/wrong-name local chains, PEM, weak/shared RSA keys |
| Collaborative intelligence | `intel.py`, `server.py` | Independent reports, deduplication, votes, reputation, feed import/export |
| Accessible integrated interface | `static/index.html`, `static/app.js`, `static/style.css` | Browser flows, keyboard tabs, responsive screenshots |

Paths above are relative to `threatlens/`. Hosted intelligence persistence remains limited by the explicitly selected temporary-storage deployment; see [deployment](DEPLOYMENT.md).
