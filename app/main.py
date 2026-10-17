from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from vault import (call, cert_info, clean_namespace, clean_path, expiry_status, list_keys,
                   namespace_var, parse_policy, parse_time, readonly, tls_verify, vault_addr, walk_kv)

app = FastAPI(title="Vault Dashboard")


# Async so the ContextVar is set in the request's context, which sync endpoints inherit.
async def token(x_vault_token: str | None = Header(default=None),
                x_vault_namespace: str | None = Header(default=None)) -> str:
    if not x_vault_token:
        raise HTTPException(401, "Missing Vault token")
    namespace_var.set(clean_namespace(x_vault_namespace))
    return x_vault_token


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
def health():
    url = f"{vault_addr()}/v1/sys/health?standbyok=true&sealedcode=200&uninitcode=200"
    try:
        data = httpx.get(url, timeout=5, verify=tls_verify()).json()
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


def finding(severity: str, category: str, title: str, detail: str) -> dict:
    return {"severity": severity, "category": category, "title": title, "detail": detail}


@app.get("/api/audit")
def audit(stale_days: int = 90, t: str = Depends(token)):
    findings: list[dict] = []
    notes: list[str] = []
    stats = {"policies": 0, "tokens": 0, "secrets": 0}
    now = datetime.now(timezone.utc)

    me_data = call("GET", "auth/token/lookup-self", t)["data"]
    if "root" in (me_data.get("policies") or []):
        findings.append(finding("high", "Tokens", "Dashboard is signed in with a root token",
                                "Root tokens bypass all policies. Use a scoped token for daily use."))

    try:
        names = [n for n in list_keys("sys/policies/acl", t) if n != "root"]
    except HTTPException as e:
        names = []
        notes.append(f"Policies not audited: {e.detail}")
    for name in names:
        stats["policies"] += 1
        data = call("GET", f"sys/policies/acl/{clean_path(name)}", t)["data"]
        for rule in parse_policy(data["policy"]):
            if not rule["risky"]:
                continue
            severe = "sudo" in rule["capabilities"] or rule["path"] in ("*", "/*")
            findings.append(finding(
                "high" if severe else "medium", "Policies", f"Broad rule in policy '{name}'",
                f'path "{rule["path"]}" grants {", ".join(rule["capabilities"]) or "no capabilities"}'))

    try:
        accessors = list_keys("auth/token/accessors", t)
        for acc in accessors[:200]:
            info = call("POST", "auth/token/lookup-accessor", t, {"accessor": acc})["data"]
            stats["tokens"] += 1
            label = info.get("display_name") or acc
            pols = info.get("policies") or []
            if "root" in pols:
                findings.append(finding("high", "Tokens", f"Active root token ({label})",
                                        f"Accessor {acc}. Revoke it once no longer needed."))
            elif not info.get("ttl") and not info.get("expire_time"):
                findings.append(finding("medium", "Tokens", f"Token without expiry ({label})",
                                        f"Accessor {acc}, policies: {', '.join(pols) or 'none'}."))
        if len(accessors) > 200:
            notes.append("Only the first 200 tokens were checked.")
    except HTTPException as e:
        notes.append(f"Tokens not audited: {e.detail}")

    mounts = call("GET", "sys/internal/ui/mounts", t)["data"].get("secret", {})
    for mount, info in mounts.items():
        if info.get("type") not in ("kv", "generic"):
            continue
        v2 = str((info.get("options") or {}).get("version") or "1") == "2"
        if not v2:
            continue  # KV v1 keeps no timestamps
        mname = mount.strip("/")
        try:
            paths, truncated = walk_kv(mname, True, t, limit=300)
        except HTTPException as e:
            notes.append(f"Secrets in '{mount}' not audited: {e.detail}")
            continue
        if truncated:
            notes.append(f"Only the first 300 secrets in '{mount}' were checked.")
        for p in paths:
            try:
                meta = call("GET", f"{mname}/metadata/{clean_path(p)}", t)["data"]
            except HTTPException:
                continue
            stats["secrets"] += 1
            updated = parse_time(meta.get("updated_time"))
            if updated and (now - updated).days >= stale_days:
                findings.append(finding(
                    "low", "Secrets", f"Stale secret {mname}/{p}",
                    f"Last changed {(now - updated).days} days ago (threshold {stale_days})."))

    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order[f["severity"]], f["category"], f["title"]))
    return {"findings": findings, "notes": notes, "stats": stats, "stale_days": stale_days}


@app.get("/api/expiry")
def expiry(warn_days: int = 30, t: str = Depends(token)):
    """Expiry of tokens, PKI certificates and AppRole secret IDs."""
    now = datetime.now(timezone.utc)
    items: list[dict] = []
    notes: list[str] = []

    def add(kind: str, name: str, source: str, expires: datetime | None) -> None:
        if expires is None:
            return
        days = (expires - now).days if expires > now else -((now - expires).days + 1)
        items.append({"kind": kind, "name": name, "source": source,
                      "expires": expires.isoformat(), "days_left": days,
                      "status": expiry_status(days, warn_days)})

    try:
        accessors = list_keys("auth/token/accessors", t)
        for acc in accessors[:200]:
            try:
                info = call("POST", "auth/token/lookup-accessor", t, {"accessor": acc})["data"]
            except HTTPException:
                continue
            add("token", info.get("display_name") or "token",
                f"accessor {acc} · {', '.join(info.get('policies') or [])}",
                parse_time(info.get("expire_time")))
        if len(accessors) > 200:
            notes.append("Only the first 200 tokens were checked.")
    except HTTPException as e:
        notes.append(f"Tokens not checked: {e.detail}")

    ui = call("GET", "sys/internal/ui/mounts", t)["data"]
    for mount, info in ui.get("secret", {}).items():
        if info.get("type") != "pki":
            continue
        mname = mount.strip("/")
        seen: set[tuple[str, datetime]] = set()
        try:
            serials = list_keys(f"{mname}/certs", t)
            if len(serials) > 200:
                notes.append(f"Only the first 200 certificates in '{mount}' were checked.")
            for serial in serials[:200]:
                data = call("GET", f"{mname}/cert/{clean_path(serial)}", t)["data"]
                if data.get("revocation_time"):
                    continue
                cn, exp = cert_info(data["certificate"])
                seen.add((cn, exp))
                add("certificate", cn, f"{mname} · serial {serial}", exp)
            ca = call("GET", f"{mname}/cert/ca", t).get("data", {}).get("certificate")
            if ca:
                cn, exp = cert_info(ca)
                if (cn, exp) not in seen:
                    add("certificate", f"{cn} (CA)", f"{mname} · issuing CA", exp)
        except HTTPException as e:
            notes.append(f"Certificates in '{mount}' not checked: {e.detail}")
        except Exception as e:
            notes.append(f"Certificates in '{mount}' could not be parsed: {e}")

    for mount, info in ui.get("auth", {}).items():
        if info.get("type") != "approle":
            continue
        mname = mount.strip("/")
        try:
            roles = list_keys(f"auth/{mname}/role", t)
            if len(roles) > 100:
                notes.append(f"Only the first 100 AppRoles in '{mount}' were checked.")
            for role in roles[:100]:
                r = clean_path(role)
                accs = list_keys(f"auth/{mname}/role/{r}/secret-id", t)
                never = 0
                for acc in accs[:100]:
                    try:
                        sid = call("POST", f"auth/{mname}/role/{r}/secret-id-accessor/lookup", t,
                                   {"secret_id_accessor": acc})["data"]
                    except HTTPException:
                        continue
                    exp = parse_time(sid.get("expiration_time"))
                    if exp is None:
                        never += 1
                    add("approle", f"{role} secret ID", f"{mname} · accessor {acc}", exp)
                if never:
                    notes.append(f"AppRole '{role}' has {never} secret ID(s) that never expire.")
        except HTTPException as e:
            notes.append(f"AppRoles in '{mount}' not checked: {e.detail}")

    items.sort(key=lambda i: i["expires"])
    counts = {s: sum(1 for i in items if i["status"] == s) for s in ("expired", "critical", "warning", "ok")}
    return {"items": items, "counts": counts, "notes": notes, "warn_days": warn_days}


app.mount("/", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="static")
