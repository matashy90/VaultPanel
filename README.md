# OnePane: Vault Dashboard

A clean, read-only web UI for HashiCorp Vault: browse secrets, inspect policies and look at leases.

- **Overview**: seal status, version, your token's policies and expiry (warns on root tokens).
- **Secrets**: KV v1 and v2 browser with masked values (reveal/copy) and version history.
- **Policies**: parsed rules per path with capabilities. Broad rules (`sudo`, `*`, write+delete on wildcards) are flagged.
- **Auth methods**: list of enabled auth backends.
- **Leases**: browse lease prefixes and see TTL/expiry.

The browser holds your Vault token only in `sessionStorage`. The backend is a thin proxy that forwards it per request and stores nothing.

## Run
Python 3.10+:
```
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
set VAULT_ADDR=http://127.0.0.1:8200
.venv\Scripts\uvicorn main:app --app-dir app --port 8080
```
Open http://127.0.0.1:8080 and sign in with a Vault token. `VAULT_ADDR` defaults to `http://127.0.0.1:8200`.

Quick local try-out: `vault server -dev -dev-root-token-id=root`, then sign in with token `root`.

## Security notes
- Serve it over HTTPS (reverse proxy) if it is reachable beyond localhost; tokens travel in a request header.
- It is read-only by design and only shows what the token's own policies allow.

## Tests
```
cd app
..\.venv\Scripts\python -m pytest
```
