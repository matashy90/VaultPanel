import os
import re
import threading
import time
from contextvars import ContextVar
from datetime import datetime, timezone
from urllib.parse import quote

import httpx
from fastapi import HTTPException

from clusters import cluster_var

# Set per request by the auth dependency; read by call() for every Vault request.
namespace_var: ContextVar[str] = ContextVar("vault_namespace", default="")
NAMESPACE_RE = re.compile(r"^[A-Za-z0-9_\-./]*$")


class Throttle:
    """Caps the request rate towards one Vault (shared by all worker threads of a scan)."""

    def __init__(self, rps: float):
        self.interval = 1.0 / rps if rps > 0 else 0.0
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next)
            self._next = slot + self.interval
        if slot > now:
            time.sleep(slot - now)

    def slow_down(self) -> None:
        """Called when Vault answers 429: halve the rate (down to one request per two seconds)."""
        with self._lock:
            self.interval = min(max(self.interval * 2, 0.1), 2.0)


# Set by a scan; makes call() throttled and patient with 429 responses.
throttle_var: ContextVar[Throttle | None] = ContextVar("vault_throttle", default=None)


def vault_addr() -> str:
    c = cluster_var.get()
    return c.addr if c else os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200").rstrip("/")


def tls_verify() -> bool | str:
    """The selected cluster's CA bundle, else VAULT_CACERT, else the default trust store."""
    c = cluster_var.get()
    return c.verify if c else (os.environ.get("VAULT_CACERT") or True)


def clean_namespace(ns: str | None) -> str:
    ns = (ns or "").strip().strip("/")
    if ".." in ns.split("/") or not NAMESPACE_RE.match(ns):
        raise HTTPException(400, "Invalid namespace")
    return ns


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


# Shared clients (one per CA setting): building an SSL context per request costs seconds on some
# machines, and reusing connections avoids a TLS handshake per call.
_clients: dict = {}
_clients_lock = threading.Lock()


def _http(method: str, url: str, **kw) -> httpx.Response:
    verify = kw.pop("verify", True)
    with _clients_lock:
        client = _clients.get(verify)
        if client is None:
            client = _clients[verify] = httpx.Client(verify=verify)
    return client.request(method, url, **kw)


def call(method: str, path: str, token: str, json: dict | None = None) -> dict:
    url = f"{vault_addr()}/v1/{path}"
    headers = {"X-Vault-Token": token}
    if namespace_var.get():
        headers["X-Vault-Namespace"] = namespace_var.get()
    throttle = throttle_var.get()
    for attempt in range(4):
        if throttle:
            throttle.wait()
        try:
            r = _http(method, url, headers=headers, json=json, timeout=10, verify=tls_verify())
        except httpx.HTTPError as e:
            raise HTTPException(502, f"Cannot reach Vault at {vault_addr()}: {e}")
        # Rate-limit responses are retried with backoff, but only during scans.
        if r.status_code == 429 and throttle and attempt < 3:
            throttle.slow_down()
            time.sleep(2 ** attempt)
            continue
        break
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


def walk_kv(mount: str, v2: bool, token: str, limit: int = 500, max_depth: int = 10,
            max_lists: int = 2000, stop=None):
    """Returns (secret paths, truncated) by walking a KV mount's key tree.

    Stops at `limit` secrets, `max_lists` LIST calls, or when stop() returns true."""
    base = f"{mount}/metadata" if v2 else mount
    found: list[str] = []
    stack = [("", 0)]
    lists = 0
    while stack:
        if lists >= max_lists or (stop and stop()):
            return sorted(found), True
        prefix, depth = stack.pop()
        lists += 1
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


def cert_info(pem: str) -> tuple[str, datetime]:
    """Returns (common name, expiry) of a PEM certificate."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    cert = x509.load_pem_x509_certificate(pem.encode())
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    name = str(cns[0].value) if cns else cert.subject.rfc4514_string() or "(no subject)"
    return name, cert.not_valid_after_utc


def expiry_status(days_left: int, warn_days: int) -> str:
    if days_left < 0:
        return "expired"
    if days_left <= 7:
        return "critical"
    if days_left <= warn_days:
        return "warning"
    return "ok"


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
