# OnePane: Vault Dashboard

A clean web UI for HashiCorp Vault: browse and edit secrets, inspect policies, look at leases and audit your setup.

- **Overview**: seal status, version, your token's policies and expiry (warns on root tokens).
- **Secrets**: KV v1/v2 browser with masked values (reveal/copy), version history, **path search**, and **create / edit / delete**. In KV v2, delete is a soft delete of the latest version and editing saves a new version.
- **Policies**: parsed rules per path with capabilities. Broad rules (`sudo`, `*`, write+delete on wildcards) are flagged.
- **Auth methods** and **Leases**: list backends, browse lease prefixes with TTL/expiry.
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
Uses `VAULT_ADDR` (default `http://host.docker.internal:8200`) and publishes on `127.0.0.1:8080` only. The Docker setup has not been built or tested yet.

## Configuration
| Variable | Purpose |
|---|---|
| `VAULT_ADDR` | Vault address (default `http://127.0.0.1:8200`). |
| `VAULT_DASH_READONLY` | `1` disables create/edit/delete in the API and hides the buttons. |

## Security notes
- Serve it over HTTPS (reverse proxy) if it is reachable beyond localhost; tokens travel in a request header.
- Writes are only possible with what the token's own policies allow. Set `VAULT_DASH_READONLY=1` for view-only deployments.

## Tests
```
.venv\Scripts\pip install -r requirements-dev.txt
cd app
..\.venv\Scripts\python -m pytest
```
