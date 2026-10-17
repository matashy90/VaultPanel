import os
import re
from datetime import datetime, timezone
from urllib.parse import quote

import httpx
from fastapi import HTTPException


def vault_addr() -> str:
    return os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200").rstrip("/")


def clean_path(path: str) -> str:
    """Validates a user-supplied Vault path and URL-encodes each segment."""
    path = path.strip("/")
    if not path:
        return ""
    segments = path.split("/")
    for s in segments:
        if s in ("", ".", "..") or "\\" in s or any(ord(c) < 32 for c in s):
            raise HTTPException(400, "Invalid path")
    return "/".join(quote(s, safe="") for s in segments)


def call(method: str, path: str, token: str, json: dict | None = None) -> dict:
    url = f"{vault_addr()}/v1/{path}"
    try:
        r = httpx.request(method, url, headers={"X-Vault-Token": token}, json=json, timeout=10)
    except httpx.HTTPError as e:
        raise HTTPException(502, f"Cannot reach Vault at {vault_addr()}: {e}")
    if r.status_code >= 400:
        try:
            errors = r.json().get("errors") or []
        except ValueError:
            errors = []
        raise HTTPException(r.status_code, "; ".join(errors) or f"Vault returned {r.status_code}")
    return r.json() if r.content else {}


def list_keys(path: str, token: str) -> list[str]:
    try:
        return call("LIST", path, token).get("data", {}).get("keys", [])
    except HTTPException as e:
        if e.status_code == 404:
            return []
        raise


def readonly() -> bool:
    return os.environ.get("VAULT_DASH_READONLY", "").lower() in ("1", "true", "yes")


def parse_time(value: str | None) -> datetime | None:
    if not value or value.startswith("0001"):
        return None
    # Vault emits nanosecond precision, which fromisoformat rejects.
    value = re.sub(r"(\.\d{6})\d+", r"\1", value).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def walk_kv(mount: str, v2: bool, token: str, limit: int = 500, max_depth: int = 10):
    """Returns (secret paths, truncated) by walking a KV mount's key tree."""
    base = f"{mount}/metadata" if v2 else mount
    found: list[str] = []
    stack = [("", 0)]
    while stack:
        prefix, depth = stack.pop()
        try:
            keys = list_keys(f"{base}/{clean_path(prefix)}".rstrip("/") + "/", token)
        except HTTPException as e:
            if e.status_code == 403:
                continue
            raise
        for k in sorted(keys, reverse=True):
            if k.endswith("/"):
                if depth < max_depth:
                    stack.append((prefix + k, depth + 1))
            else:
                if len(found) >= limit:
                    return sorted(found), True
                found.append(prefix + k)
    return sorted(found), False


def parse_policy(hcl: str) -> list[dict]:
    """Extracts path blocks and their capabilities from an ACL policy."""
    rules = []
    for m in re.finditer(r'path\s+"([^"]+)"\s*\{', hcl):
        depth, i = 1, m.end()
        while i < len(hcl) and depth:
            depth += {"{": 1, "}": -1}.get(hcl[i], 0)
            i += 1
        body = hcl[m.end():i - 1]
        caps_match = re.search(r"capabilities\s*=\s*\[(.*?)\]", body, re.DOTALL)
        caps = re.findall(r'"(\w+)"', caps_match.group(1)) if caps_match else []
        broad = not m.group(1).startswith("cubbyhole/") and (
            "sudo" in caps or m.group(1) in ("*", "/*") or (
                m.group(1).endswith("*") and "delete" in caps and "update" in caps
            )
        )
        rules.append({"path": m.group(1), "capabilities": caps, "risky": broad})
    return rules
