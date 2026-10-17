from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.staticfiles import StaticFiles

from vault import call, clean_path, list_keys, parse_policy, vault_addr

app = FastAPI(title="Vault Dashboard")


def token(x_vault_token: str | None = Header(default=None)) -> str:
    if not x_vault_token:
        raise HTTPException(401, "Missing Vault token")
    return x_vault_token


@app.get("/api/health")
def health():
    url = f"{vault_addr()}/v1/sys/health?standbyok=true&sealedcode=200&uninitcode=200"
    try:
        data = httpx.get(url, timeout=5).json()
    except (httpx.HTTPError, ValueError) as e:
        return {"addr": vault_addr(), "reachable": False, "error": str(e)}
    return {"addr": vault_addr(), "reachable": True, **data}


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


app.mount("/", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="static")
