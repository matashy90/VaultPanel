# Vault Dashboard

A clean web UI for HashiCorp Vault: browse and edit secrets, inspect policies, look at leases and audit your setup.

- **Overview**: seal status, version, your token's policies and expiry (warns on root tokens).
- **Secrets**: KV v1/v2 browser with masked values (reveal/copy), version history, **path search**, and **create / edit / delete**. In KV v2, delete is a soft delete of the latest version and editing saves a new version.
- **Policies**: parsed rules per path with capabilities. Broad rules (`sudo`, `*`, write+delete on wildcards) are flagged.
- **Auth methods** and **Leases**: list backends, browse lease prefixes with TTL/expiry.
- **Expiry**: one list of everything that expires, sorted by date, with expired / critical (≤7d) / warning (configurable window) status and a counter on the Overview page.
  - **Tokens**: from token accessors (`expire_time`).
  - **Certificates**: every non-revoked certificate and the issuing CA of each PKI mount (parsed from the PEM).
  - **AppRole**: secret IDs of each role. A role-id itself never expires, so roles whose secret IDs never expire are listed in the notes instead.
  - Checks are capped (200 tokens, 200 certs per mount, 100 roles, 100 secret IDs per role) and the page says when something was skipped.
- **Audit**: scans for root tokens, tokens without expiry, overly broad policy rules and stale KV v2 secrets (configurable age). Limited to what the signed-in token may read; skipped areas are listed.

The browser holds your Vault token only in `sessionStorage`. The backend is a thin proxy that forwards it per request and stores nothing.

## Run
Python 3.10+:
```
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
set VAULT_ADDR=http://127.0.0.1:8200
.venv\Scripts\uvicorn main:app --app-dir app --port 8080
```
Open http://127.0.0.1:8080 and sign in with a Vault token. Quick local try-out: `vault server -dev -dev-root-token-id=root`, then sign in with token `root`.

### Docker
```
docker compose up --build
```
Uses `VAULT_ADDR` (default `http://host.docker.internal:8200`) and publishes on `127.0.0.1:8080` only. Built and tested with Docker Engine 29 against a Vault 1.18 container; for an internal CA see `VAULT_CACERT` in `docker-compose.yml`.

## Configuration
| Variable | Purpose |
|---|---|
| `VAULT_ADDR` | Vault address (default `http://127.0.0.1:8200`). |
| `VAULT_CACERT` | Path to a CA bundle (PEM) for a Vault with an internal/private TLS certificate. |
| `VAULT_DASH_READONLY` | `1` disables create/edit/delete in the API and hides the buttons. |

## Namespaces (Vault Enterprise / HCP)
Type the namespace (e.g. `admin` or `admin/team-a`) in the sidebar field. It is sent as `X-Vault-Namespace` with every request, and child namespaces are suggested when the token can list them. Leave it empty for the root namespace. Open source Vault has no namespaces and ignores the header. Namespace support is covered by unit tests only; it has not been tried against an Enterprise or HCP instance.

## Several Vaults (fleet monitoring)
List the clusters in a JSON file and point `VAULT_CLUSTERS_FILE` at it (see [clusters.example.json](clusters.example.json)); without it a single cluster is taken from `VAULT_ADDR`.

```json
[{"name": "prod", "addr": "https://vault-prod:8200", "cacert": "/certs/ca.pem",
  "namespace": "admin", "monitor_token_env": "VAULT_TOKEN_PROD"},
 {"name": "staging", "addr": "https://vault-staging:8200", "monitor_token_file": "/run/secrets/vault_token_staging"}]
```
- **Cluster picker**: with 2+ clusters the login page and sidebar show a picker. Tokens and namespaces are stored per cluster in `sessionStorage` and sent only to the cluster they belong to.
- **Fleet page**: health (active/standby/sealed/unreachable, version, enterprise) and expiry counts for every cluster, with the worst items.
- **Background monitor**: every `VAULT_MONITOR_INTERVAL` seconds (default 300, `0` disables) each cluster is checked, and expiry is scanned when it has a monitoring token (`monitor_token_env` or `monitor_token_file`, never inline in the JSON). Give it a dedicated read-only token with [onepane-monitor.hcl](onepane-monitor.hcl). Listing token accessors needs `sudo` in Vault, which is why that policy has it on that single path. The monitor does not renew the token, so use a periodic token and renew it, or a long TTL.
- **Alerts** fire once for each *new* expired/critical item, and when a cluster becomes unreachable or sealed (plus a recovery notice). They repeat only if the problem disappears and returns, or after a restart.
- **Prometheus**: `GET /metrics` exposes `vault_dash_cluster_up`, `vault_dash_cluster_sealed`, `vault_dash_expiry_items{cluster,kind,status}` and `vault_dash_last_check_timestamp_seconds`. Set `VAULT_DASH_METRICS_TOKEN` to require `Authorization: Bearer <token>`.

| Variable | Purpose |
|---|---|
| `VAULT_CLUSTERS_FILE` | JSON list of clusters (above). |
| `VAULT_MONITOR_INTERVAL` | Seconds between background checks (default 300, minimum 30, `0` = off). |
| `VAULT_ALERT_WEBHOOK` | Webhook URL. Slack/Mattermost get `{"text": ..., "lines": [...]}`; Microsoft Teams gets an Adaptive Card (see below). |
| `VAULT_ALERT_FORMAT` | `teams` or `text`. Normally guessed from the URL (`*.logic.azure.com`, `*.powerplatform.com`, `*.office.com` mean Teams). |
| `VAULT_ALERT_SMTP_HOST`, `_PORT` (587), `_USER`, `_PASSWORD`, `_STARTTLS` (1) | SMTP server for email alerts. |
| `VAULT_ALERT_EMAIL_FROM`, `VAULT_ALERT_EMAIL_TO` | Sender and comma-separated recipients. |
| `VAULT_DASH_METRICS_TOKEN` | Optional bearer token for `/metrics`. |

### Microsoft Teams
Office 365 "Incoming Webhook" connectors are retired; use a Workflow instead:
1. In Teams open the channel, **… > Workflows**, and pick the template **Post to a channel when a webhook request is received** (a Workflow built in Power Automate with the trigger "When a Teams webhook request is received" works too).
2. Choose the team and channel, create it, and copy the generated HTTP POST URL.
3. Set `VAULT_ALERT_WEBHOOK` to that URL. Treat it as a secret: anyone with it can post to the channel.

The URL is recognised as Teams automatically and the alert is posted as an Adaptive Card. The workflow posts as you (or the flow owner), and needs a licence that allows Power Automate workflows in Teams. If your tenant blocks them, ask the Teams admin.

Fleet details are only served to someone holding a valid token on the selected cluster, but `/metrics` is open unless you set the token above. The dashboard itself has no login of its own: anyone who can reach the port can read what the monitoring tokens can see on the Fleet page after signing in with any valid token. Keep it on a trusted network.

## Large clusters (audit and expiry scans)

Audit and Expiry run as background jobs with a rate limit, so they cannot flood Vault. They walk every namespace (breadth-first), show progress, can be cancelled, and return partial results with a note if a limit or the time budget is hit. Results are cached per token; changing the warn window does not rescan.

| Variable | Default | Meaning |
|---|---|---|
| `VAULT_SCAN_RPS` | 20 | Max Vault requests per second per scan (slows down on HTTP 429) |
| `VAULT_SCAN_CONCURRENCY` | 4 | Parallel requests |
| `VAULT_SCAN_BUDGET` | 900 | Max seconds per scan (min 10) |
| `VAULT_SCAN_MAX_NAMESPACES` | 50 | Namespaces walked |
| `VAULT_SCAN_MAX_TOKENS` | 5000 | Token accessors per namespace |
| `VAULT_SCAN_MAX_SECRETS` | 5000 | Secrets per KV v2 mount |
| `VAULT_SCAN_MAX_CERTS` | 1000 | Certificates per PKI mount |
| `VAULT_SCAN_MAX_ROLES` / `VAULT_SCAN_MAX_SECRET_IDS` | 500 / 100 | AppRole roles / secret IDs per role |

Advice: start with `VAULT_SCAN_RPS=10`, raise it while watching Vault's own metrics, and set `VAULT_MONITOR_INTERVAL=3600` or more for the background monitor. Measured on a local dev Vault at 40 req/s: 408 tokens + 502 secrets in about 24 s.

## Security notes
- Serve it over HTTPS (reverse proxy) if it is reachable beyond localhost; tokens travel in a request header.
- Writes are only possible with what the token's own policies allow. Set `VAULT_DASH_READONLY=1` for view-only deployments.

## Tests
```
.venv\Scripts\pip install -r requirements-dev.txt
cd app
..\.venv\Scripts\python -m pytest
```
