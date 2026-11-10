# Deployment and operations

## Vercel configuration

- Existing project: `riitom/threatlens`.
- Public alias: https://threatlens-one.vercel.app.
- Framework: Flask; entrypoint: `api.index:app` in `pyproject.toml`.
- Python: `.python-version` selects 3.13.
- `vercel.json` grants the scanner function a 120-second execution budget. Network engines use shorter timeouts; slow/unreachable hosts still produce incomplete coverage.
- Dependencies: `requirements.txt`. No Node build is needed for the plain HTML/CSS/JS frontend.
- Deployment exclusions are in `.vercelignore`; runtime databases, secrets, tests, and local evidence are excluded.

The original deployment returned `FUNCTION_INVOCATION_FAILED` at `/api/health`. The app had attempted to initialize SQLite in the deployment directory. `config.db_path()` now uses the writable temporary directory on Vercel and `instance/` locally.

## Storage choice

The project owner selected **temporary storage** for this deployment. There is no external database connection. Health returns `storage.durable: false`, and the feed shows a corresponding notice. Reports, votes, imported feeds, and scanned-key history may reset or differ across instances. Do not use this mode as a durable shared threat database.

For durable operation, deploy the same app with a persistent writable disk and set `THREATLENS_DB`, or implement and verify an external shared database adapter. A file path on Vercel does not supply persistence. No provisioned paid or free database is required by the current deployment.

## Environment settings

| Variable | Default / purpose |
| --- | --- |
| `THREATLENS_SALT` | Set a strong random secret in production. Without it, identities use a random process-lifetime key. |
| `THREATLENS_DB` | Local SQLite path override; auto-selected writable location otherwise. |
| `SAFE_BROWSING_API_KEY` | Optional Google provider; transmits submitted scan URLs to Google. |
| `THREATLENS_CT_LOOKUP` | Default off; enables hostname lookup through crt.sh. |
| `THREATLENS_TIMEOUT` | Default 8 seconds per network operation. |
| `THREATLENS_MAX_BODY` | Default 1,500,000 response bytes. |
| `THREATLENS_MAX_REDIRECTS` | Default 5 redirects; every destination is SSRF-checked. |
| `THREATLENS_SCAN_RATE` | Default 30 per minute per process/client. |
| `THREATLENS_REPORT_RATE` | Default 10 reports per hour per process/client. |
| `THREATLENS_CA_FILE` | Optional PEM trust bundle for an internal authorized lab. |

`THREATLENS_ALLOW_PRIVATE` and `THREATLENS_ANY_PORT` are test/lab escape hatches. Keep them unset on a public deployment. Rate limits are in-memory; production at scale needs shared rate limiting and trusted client-IP handling. The app deliberately does not trust arbitrary forwarded-IP headers.

The production and preview reporter salt is configured as a Vercel secret. Never commit `.env.local` or `.vercel` contents. `run.py` reads the process environment; use your shell or process manager to load local settings.

## Release checks

1. Install development dependencies and run `python -m pytest -q` plus `node --check threatlens/static/app.js`.
2. Deploy a preview with `vercel deploy --scope riitom`; inspect build logs and health.
3. Exercise live scan, blocked-target scan, demos, PEM inspection, feed/export, static assets, and desktop/mobile UI.
4. Push the reviewed release to `main`; Git integration deploys production. Verify the deployment SHA and public alias.
5. Confirm the temporary-storage notice remains visible. Browser trust/CT results are not substitutes for a maintained revocation service.
