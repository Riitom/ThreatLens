# API reference

All API responses are JSON except CSV export. Errors use `{"error": "message"}`. API responses are not cached. Requests are capped at 256 KiB. Invalid field types return 400, unsupported methods 405, oversized requests 413, and exhausted per-process rate limits 429.

| Method | Route | Input / result |
| --- | --- | --- |
| GET | `/api/health` | Version, database counts, and actual storage durability/limitations |
| GET | `/api/stats` | Report, feed, key, and confirmed-host counts |
| POST | `/api/scan` | `url` string; optional `deep` and `authorized` booleans |
| POST | `/api/cert/inspect` | `host` / `url` string, or public certificate `pem` string |
| POST | `/api/report` | `url`, `category`, optional `comment` (stored up to 500 characters) |
| POST | `/api/vote` | `url` and `vote`: `confirm` or `dispute` |
| GET | `/api/reputation?url=example.com` | Decayed score, reports, unique reporters, categories, votes |
| GET | `/api/feed` | Corroborated hosts; optional finite nonnegative `min_score`, `limit` from 1 to 5000 |
| GET | `/api/feed/export?format=csv` | CSV attachment; `format=json` also supported; optional `min_score` |
| GET | `/api/demo/scenarios` | Five synthetic scenario summaries |
| POST | `/api/demo/run` | `scenario` ID; result is marked `demo: true` |
| GET | `/api/demo/certificate` | Public demonstration PEM with a Fermat-factorable RSA modulus |

Categories: `phishing`, `malware`, `fake_recruitment`, `payment_scam`, `impersonation`, `other`. Feed results require at least three independent reporters and sufficient decayed score (default 2.4). A vote does not create an independent report. Protected-brand scans cap community-only verdict escalation. Duplicate reports from the same reporter/host return `status: duplicate`.

```powershell
$body = @{ url = "https://example.com"; deep = $false } | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8080/api/scan -Method Post -ContentType application/json -Body $body
```

Scan responses include `verdict`, `posture`, `findings`, `certificate`, `headers`, `page`, `http`, `features`, `community`, `coverage`, `notes`, timestamps, and duration. Each finding names its engine, severity, and threat/posture axis. `coverage` distinguishes successful, partial, failed, skipped, and blocked checks. `Inconclusive` means insufficient page evidence; it does not imply a zero-risk site.

Allowed public destination ports are 80, 443, 8080, and 8443. Certificate inspection enforces the same policy. Deep probes require authorization and stay on the original origin. No form submission or JavaScript execution occurs on scanned sites. Client identity is a keyed HMAC of the network address. Synthetic demo data is excluded from reporting controls; explicit `demo: true` report/vote submissions are rejected.

Scan/certificate limits default to 30 per minute; reports to 10 per hour; votes to 30 per hour. Limits are process-local, not a distributed abuse-prevention system. See [deployment limitations](DEPLOYMENT.md).
