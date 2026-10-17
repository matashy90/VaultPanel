import hmac
import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import monitor
import scan
from clusters import cluster_var, get_cluster, load_clusters
from vault import (_http, call, clean_namespace, clean_path, list_keys, namespace_var, parse_policy,
                   readonly, tls_verify, vault_addr, walk_kv)


@asynccontextmanager
async def lifespan(_: FastAPI):
    stop = monitor.start(scan.monitor_expiry)
    yield
    if stop:
        stop.set()


app = FastAPI(title="Vault Dashboard", lifespan=lifespan)


# Async so the ContextVars are set in the request's context, which sync endpoints inherit.
async def select_cluster(x_vault_cluster: str | None = Header(default=None)) -> None:
    cluster = get_cluster(x_vault_cluster)
    if cluster is None:
        raise HTTPException(400, "Unknown cluster")
    cluster_var.set(cluster)
    namespace_var.set(cluster.namespace)


async def token(x_vault_token: str | None = Header(default=None),
                x_vault_namespace: str | None = Header(default=None),
                _: None = Depends(select_cluster)) -> str:
    if not x_vault_token:
        raise HTTPException(401, "Missing Vault token")
    if x_vault_namespace is not None:
        namespace_var.set(clean_namespace(x_vault_namespace))
    return x_vault_token


@app.get("/api/clusters")
def clusters():
    """Configured clusters (names and addresses only; never tokens)."""
    return {"clusters": [{"name": c.name, "addr": c.addr, "namespace": c.namespace,
                          "monitored": bool(c.monitor_token),
                          "oidc": bool(c.oidc_mount), "oidc_role": c.oidc_role} for c in load_clusters()],
            "token_login": os.environ.get("VAULT_LOGIN_TOKEN", "on").lower() not in ("0", "off", "false", "no")}


class OidcStart(BaseModel):
    redirect_uri: str
    client_nonce: str
    role: str = ""


class OidcFinish(BaseModel):
    state: str
    code: str
    client_nonce: str


def oidc_mount() -> str:
    c = cluster_var.get()
    if not c or not c.oidc_mount:
        raise HTTPException(400, "OIDC login is not configured for this cluster (set VAULT_OIDC_MOUNT)")
    return clean_path(c.oidc_mount)


async def anon(x_vault_namespace: str | None = Header(default=None), _: None = Depends(select_cluster)) -> None:
    if x_vault_namespace is not None:
        namespace_var.set(clean_namespace(x_vault_namespace))


@app.post("/api/oidc/auth_url")
def oidc_auth_url(body: OidcStart, _: None = Depends(anon)):
    """Step 1: ask Vault's OIDC auth method for the identity provider URL to send the browser to."""
    payload = {"redirect_uri": body.redirect_uri, "client_nonce": body.client_nonce}
    role = body.role or cluster_var.get().oidc_role
    if role:
        payload["role"] = role
    data = call("POST", f"auth/{oidc_mount()}/oidc/auth_url", "", payload).get("data", {})
    if not data.get("auth_url"):
        raise HTTPException(502, "Vault returned no auth_url")
    return {"auth_url": data["auth_url"]}


@app.post("/api/oidc/callback")
def oidc_callback(body: OidcFinish, _: None = Depends(anon)):
    """Step 2: exchange the code and state from the identity provider for a Vault token."""
    qs = urlencode({"state": body.state, "code": body.code, "client_nonce": body.client_nonce})
    auth = call("GET", f"auth/{oidc_mount()}/oidc/callback?{qs}", "").get("auth") or {}
    if not auth.get("client_token"):
        raise HTTPException(502, "Vault returned no token")
    return {"token": auth["client_token"], "policies": auth.get("policies", []),
            "ttl": auth.get("lease_duration", 0), "renewable": auth.get("renewable", False)}


@app.get("/api/fleet")
def fleet(t: str = Depends(token)):
    """Health and expiry counts of every cluster. Needs a valid token on the selected cluster."""
    call("GET", "auth/token/lookup-self", t)
    clusters_cfg = load_clusters()
    with ThreadPoolExecutor(max_workers=min(8, len(clusters_cfg))) as pool:
        health = list(pool.map(monitor.cluster_health, clusters_cfg))
    out = []
    for c, h in zip(clusters_cfg, health):
        cached = monitor.STATE.get(c.name, {})
        scan_data = {k: cached[k] for k in ("counts", "notes", "items", "by_kind", "scan_error", "checked_at",
                                            "namespaces") if k in cached}
        out.append({"name": c.name, "addr": c.addr, "namespace": c.namespace,
                    "monitored": bool(c.monitor_token), **scan_data, **h})
    return {"clusters": out, "alerts_enabled": monitor.alerts_enabled(), "interval": monitor.interval()}


@app.get("/metrics", response_class=PlainTextResponse)
def metrics(request: Request):
    """Prometheus metrics from the background monitor. Optional bearer token: VAULT_DASH_METRICS_TOKEN."""
    expected = os.environ.get("VAULT_DASH_METRICS_TOKEN")
    if expected and not hmac.compare_digest(request.headers.get("authorization", ""), f"Bearer {expected}"):
        raise HTTPException(401, "Invalid metrics token")
    return monitor.metrics_text()


@app.get("/api/namespaces")
def namespaces(t: str = Depends(token)):
    """Child namespaces of the current namespace (Vault Enterprise / HCP only)."""
    try:
        return {"namespaces": sorted(list_keys("sys/namespaces", t))}
    except HTTPException as e:
        if e.status_code in (400, 403, 404):
            return {"namespaces": []}
        raise


@app.get("/api/health")
def health(_: None = Depends(select_cluster)):
    url = f"{vault_addr()}/v1/sys/health?standbyok=true&sealedcode=200&uninitcode=200"
    try:
        data = _http("GET", url, timeout=5, verify=tls_verify()).json()
    except (httpx.HTTPError, ValueError) as e:
        return {"addr": vault_addr(), "reachable": False, "error": str(e), "readonly": readonly()}
    return {"addr": vault_addr(), "reachable": True, "readonly": readonly(), **data}


@app.get("/api/me")
def me(t: str = Depends(token)):
    return call("GET", "auth/token/lookup-self", t)["data"]


@app.get("/api/mounts")
def mounts(t: str = Depends(token)):
    data = call("GET", "sys/internal/ui/mounts", t)["data"]
    return {"secret": data.get("secret", {}), "auth": data.get("auth", {})}


def kv_mount(mount: str, t: str) -> tuple[str, bool]:
    m = clean_path(mount)
    if not m:
        raise HTTPException(400, "Mount is required")
    info = call("GET", f"sys/internal/ui/mounts/{m}", t)["data"]
    if not info.get("type", "").startswith("kv") and info.get("type") != "generic":
        raise HTTPException(400, f"Mount '{mount}' is not a KV engine")
    return m, str((info.get("options") or {}).get("version") or "1") == "2"


@app.get("/api/kv/list")
def kv_list(mount: str, path: str = "", t: str = Depends(token)):
    m, v2 = kv_mount(mount, t)
    p = clean_path(path)
    base = f"{m}/metadata" if v2 else m
    keys = list_keys(f"{base}/{p}".rstrip("/") + "/", t)
    return {"keys": keys, "kv_version": 2 if v2 else 1}


@app.get("/api/kv/read")
def kv_read(mount: str, path: str, t: str = Depends(token)):
    m, v2 = kv_mount(mount, t)
    p = clean_path(path)
    if not p:
        raise HTTPException(400, "Path is required")
    if not v2:
        return {"data": call("GET", f"{m}/{p}", t)["data"], "metadata": None, "kv_version": 1}
    secret = call("GET", f"{m}/data/{p}", t)["data"]
    versions = []
    try:
        meta = call("GET", f"{m}/metadata/{p}", t)["data"]
        versions = [
            {"version": int(v), "created_time": i.get("created_time"),
             "deleted": bool(i.get("deletion_time")), "destroyed": i.get("destroyed", False)}
            for v, i in meta.get("versions", {}).items()
        ]
        versions.sort(key=lambda x: x["version"], reverse=True)
    except HTTPException:
        pass
    return {"data": secret["data"], "metadata": secret["metadata"], "versions": versions,
            "kv_version": 2}


@app.get("/api/policies")
def policies(t: str = Depends(token)):
    return {"policies": sorted(list_keys("sys/policies/acl", t))}


@app.get("/api/policies/{name}")
def policy(name: str, t: str = Depends(token)):
    data = call("GET", f"sys/policies/acl/{clean_path(name)}", t)["data"]
    return {"name": data["name"], "policy": data["policy"], "rules": parse_policy(data["policy"])}


@app.get("/api/leases")
def leases(prefix: str = "", t: str = Depends(token)):
    p = clean_path(prefix)
    keys = list_keys(f"sys/leases/lookup/{p}".rstrip("/") + "/", t)
    return {"keys": keys}


@app.get("/api/leases/info")
def lease_info(lease_id: str, t: str = Depends(token)):
    return call("PUT", "sys/leases/lookup", t, {"lease_id": lease_id})["data"]


class SecretIn(BaseModel):
    mount: str
    path: str
    data: dict[str, Any]


def require_writable() -> None:
    if readonly():
        raise HTTPException(403, "Dashboard is running in read-only mode")


@app.post("/api/kv/write")
def kv_write(body: SecretIn, t: str = Depends(token)):
    require_writable()
    m, v2 = kv_mount(body.mount, t)
    p = clean_path(body.path)
    if not p or body.path.endswith("/"):
        raise HTTPException(400, "Path must name a secret, not a folder")
    if not body.data:
        raise HTTPException(400, "A secret needs at least one key")
    if v2:
        res = call("PUT", f"{m}/data/{p}", t, {"data": body.data})
        return {"ok": True, "version": res.get("data", {}).get("version")}
    call("PUT", f"{m}/{p}", t, body.data)
    return {"ok": True}


@app.delete("/api/kv/delete")
def kv_delete(mount: str, path: str, t: str = Depends(token)):
    """KV v2: soft-deletes the latest version (recoverable). KV v1: permanent."""
    require_writable()
    m, v2 = kv_mount(mount, t)
    p = clean_path(path)
    if not p:
        raise HTTPException(400, "Path is required")
    call("DELETE", f"{m}/data/{p}" if v2 else f"{m}/{p}", t)
    return {"ok": True, "recoverable": v2}


@app.get("/api/kv/search")
def kv_search(mount: str, q: str, t: str = Depends(token)):
    m, v2 = kv_mount(mount, t)
    needle = q.strip().lower()
    if not needle:
        raise HTTPException(400, "Search text is required")
    paths, truncated = walk_kv(m, v2, t)
    return {"results": [p for p in paths if needle in p.lower()], "scanned": len(paths),
            "truncated": truncated}


# Audit and expiry run as background jobs, because on a large Vault they take minutes.
SCAN_PARAMS = {"audit": ("stale_days", 90), "expiry": ("warn_days", 30)}


def scan_kind(kind: str) -> str:
    if kind not in SCAN_PARAMS:
        raise HTTPException(404, "Unknown scan")
    return kind


@app.get("/api/scan/{kind}")
def scan_status(kind: str, t: str = Depends(token)):
    """State, progress and (when done) result of the caller's latest scan on this cluster/namespace."""
    return scan.get_job(scan_kind(kind), t)


@app.post("/api/scan/{kind}")
def scan_start(kind: str, stale_days: int = 90, warn_days: int = 30, t: str = Depends(token)):
    scan_kind(kind)
    value = max(1, min(stale_days if kind == "audit" else warn_days, 3650))
    return scan.start_job(kind, t, value)


@app.post("/api/scan/{kind}/cancel")
def scan_cancel(kind: str, t: str = Depends(token)):
    return scan.cancel_job(scan_kind(kind), t)


@app.get("/api/scan-limits")
def scan_limits(_: str = Depends(token)):
    from dataclasses import asdict

    return asdict(scan.Limits.from_env())


app.mount("/", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="static")
