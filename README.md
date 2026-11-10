# ThreatLens

**Explainable phishing detection, website security assessment, certificate inspection, and collaborative threat intelligence in one Python platform.**

[Live application](https://threatlens-one.vercel.app) · [Problem statement](docs/PROBLEM_STATEMENT.md) · [API reference](docs/API.md) · [Deployment guide](docs/DEPLOYMENT.md)

Created and maintained by [Riitom Modak](https://github.com/Riitom).

## What it does

ThreatLens combines four complementary checks. Threat score and hardening grade are independent: a phishing page can have valid HTTPS, and a legitimate site can have weak security headers.

| Problem area | Implementation |
| --- | --- |
| Phishing and malicious websites | Brand impersonation, typosquats, homoglyphs, deceptive subdomains, sensitive forms, cross-domain credential submissions, urgency, fake recruitment fees, APK lures, and suspicious redirects. |
| Web security | Security headers, cookie flags, mixed content, disclosed software versions, and optional exposed-file checks restricted to an authorized origin. |
| Certificates and trust | System trust validation for live TLS, hostname/expiry/signature checks, available chain inspection, RSA close-prime and shared-prime checks, ROCA fingerprinting, CA watchlists, and embedded SCT counts. |
| Collaborative intelligence | Privacy-preserving reports, confirm/dispute votes, time-decayed weighted reputation, protected-brand safeguards, third-party feed import, and CSV/JSON export. |

The interface includes a live scanner with six detail tabs, five clearly labeled synthetic scenarios, a certificate lab with a real weak-key PEM sample, a searchable feed, an incident case study, and administrator hardening guidance. It supports light/dark system themes, keyboard navigation, and mobile layouts without a frontend build step.

## Run locally

Requires **Python 3.13+**. Python 3.13 introduced the public SSL chain-inspection APIs used here. Vercel uses the version in `.python-version`.

```powershell
git clone https://github.com/Riitom/ThreatLens.git
cd ThreatLens
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
$env:THREATLENS_SALT = (.venv\Scripts\python.exe -c "import secrets; print(secrets.token_hex(32))")
.venv\Scripts\python.exe run.py serve --host 127.0.0.1 --port 8080
```

Open **http://127.0.0.1:8080**. On macOS/Linux use `.venv/bin/python` and `export THREATLENS_SALT="..."`. Only runtime dependencies are required for deployment: `pip install -r requirements.txt`.

Local data is created automatically in `instance/threatlens.db`. The server reads environment variables directly; `.env.example` documents settings but `.env` files are not automatically loaded by `run.py`.

## CLI

```powershell
python run.py scan https://example.com --json
python run.py scan https://your-owned-site.example --deep --authorized
python run.py import-feed feed.txt --source my-feed --category phishing
```

Exposure checks require explicit permission and stay on the originally authorized origin. Normal scans inspect public HTTP/HTTPS resources without submitting forms or executing page JavaScript.

## Vercel

The app exports Flask as **`api.index:app`**, selected explicitly by `pyproject.toml`. The frontend is served from `threatlens/static/`; there is one maintained backend and one frontend.

The current hosting choice uses **temporary SQLite storage** in the function's writable temp directory. **Community reports and the key registry can reset during cold starts/deployments and are not shared across function instances.** The health API and interface disclose this. Durable shared intelligence requires a persistent database adapter/service or hosting with a persistent disk; setting a local SQLite path alone does not make Vercel storage persistent.

Set `THREATLENS_SALT` to a strong random secret in the project settings. Optional Google Safe Browsing and crt.sh checks are disabled unless configured. See [deployment and operational limitations](docs/DEPLOYMENT.md).

## Verification

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest -q
node --check threatlens/static/app.js
```

The suite exercises URL/content analysis, SSRF policy, API validation, reports/votes/exports, demo isolation, PEM inspection, redirect handling, and real local HTTPS servers with generated trusted, self-signed, wrong-name, close-prime, and shared-prime certificates. Browser verification covers scanner controls, result tabs, the certificate lab, reports, feed filters, downloads, and responsive layouts. See [verification notes](docs/VERIFICATION.md) for the actual checked scope and limitations.

## Directory layout

```text
api/index.py             Vercel Flask entrypoint
threatlens/              Analysis engines, API, configuration, intelligence store
  data/                  Brand rules, CA watchlist, public demonstration certificate
  static/                Maintained HTML, CSS, and browser JavaScript
tests/                   Unit, API, regression, and local HTTPS integration tests
docs/                    Problem statement, API, deployment, verification
run.py                   Serve, scan, and import-feed commands
requirements.txt         Production dependencies
requirements-dev.txt     Test dependencies
pyproject.toml           Project metadata and Vercel entrypoint
vercel.json              Vercel function configuration
instance/                Local runtime data (generated, ignored by Git)
```

## What the results mean

- **Explainable heuristics, not a trained ML classifier.** No measured phishing-detection accuracy is claimed. A low threat score is not a safety certificate.
- Missing, blocked, non-HTML, truncated, and HTTP error pages receive limited coverage. Insufficient page evidence produces **Inconclusive**, while positive malicious evidence still raises the threat verdict.
- Certificate trust uses the runtime trust store, which can differ from a browser. There is no online OCSP/CRL validation. PEM audits do not establish trust or invent a negotiated protocol/cipher.
- Embedded SCTs are counted, **not cryptographically verified**. Optional crt.sh lookup is third-party evidence, not a complete proof of CT compliance.
- The bundled CA rules are an **issuer-name watchlist**, not an authoritative live revocation feed. The production SPKI blocklist starts empty; operators must populate it with verified hashes. Synthetic scenario hashes are not production intelligence.
- Structural RSA tests do not prove entropy, recover arbitrary private keys, or detect every weak ECC key. The Fermat demo is separate from the eMudhra ECC incident.
- Community agreement is a reputation signal, not independent proof. Rate limits and reporter deduplication are per process/network address; NATs, proxies, restarts, and distributed attackers affect them.
- Never submit secrets or private signed links. Query strings are removed from stored report URLs, but optional Safe Browsing receives the submitted scan URL and report comments can contain text the user enters.

## eMudhra case study

The October 2026 incident involved eight weak intermediate ECC keys: six TLS and two code-signing keys. eMudhra reported a faulty wrap/unwrap ceremony step, revocation of the eight intermediates, and no end-entity issuance by those intermediates. ThreatLens demonstrates why chain inspection, maintained trust stores, and multiple independent signals matter; a name-only match does not establish that a specific key was compromised. Sources: [eMudhra's updated statement](https://emudhra.com/en/post/certificate-security-incident), [Go Security Team response](https://go.dev/blog/emudhra-incident).

## License

[MIT](LICENSE).
