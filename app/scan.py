"""Expiry and audit scans built for large Vaults.

Every scan runs in the background with a request-rate cap, a small worker pool, per-category
limits and a time budget, and reports progress. Nothing here stores tokens: a job keeps the
caller's token only in memory while its thread runs, and results are cached under a hash of it.
"""
import contextvars
import hashlib
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from fastapi import HTTPException

from clusters import cluster_var
from vault import (Throttle, call, cert_info, clean_path, expiry_status, list_keys, namespace_var,
                   parse_policy, parse_time, throttle_var, walk_kv)

KEEP_DAYS = 90        # expiry items further away are only counted, which keeps results small
MAX_ITEMS = 3000
MAX_STALE_FINDINGS = 500
STATUSES = ("expired", "critical", "warning", "ok")
KINDS = ("token", "certificate", "approle")


def _num(name: str, default: float, minimum: float = 0) -> float:
    try:
        return max(minimum, float(os.environ.get(name, default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Limits:
    rps: float = 20            # Vault requests per second per scan (0 = unlimited)
    concurrency: int = 4       # parallel requests
    tokens: int = 5000         # token accessors looked up per namespace
    secrets: int = 5000        # KV v2 secrets examined per mount
    certs: int = 1000          # certificates read per PKI mount
    roles: int = 500           # AppRoles per auth mount
    secret_ids: int = 100      # secret IDs per role
    namespaces: int = 50       # namespaces visited (the current one included)
    budget: int = 900          # seconds before a scan stops and reports partial results

    @classmethod
    def from_env(cls) -> "Limits":
        return cls(
            rps=_num("VAULT_SCAN_RPS", cls.rps), concurrency=int(_num("VAULT_SCAN_CONCURRENCY", cls.concurrency, 1)),
            tokens=int(_num("VAULT_SCAN_MAX_TOKENS", cls.tokens)), secrets=int(_num("VAULT_SCAN_MAX_SECRETS", cls.secrets)),
            certs=int(_num("VAULT_SCAN_MAX_CERTS", cls.certs)), roles=int(_num("VAULT_SCAN_MAX_ROLES", cls.roles)),
            secret_ids=int(_num("VAULT_SCAN_MAX_SECRET_IDS", cls.secret_ids)),
            namespaces=int(_num("VAULT_SCAN_MAX_NAMESPACES", cls.namespaces, 1)),
            budget=int(_num("VAULT_SCAN_BUDGET", cls.budget, 10)))


class Scan:
    def __init__(self, limits: Limits | None = None, progress=None, cancel: threading.Event | None = None):
        self.limits = limits or Limits.from_env()
        self.throttle = Throttle(self.limits.rps)
        self.deadline = time.monotonic() + self.limits.budget
        self.notes: list[str] = []
        self._progress = progress
        self._cancel = cancel or threading.Event()
        self._timed_out = False

    @contextmanager
    def active(self):
        token = throttle_var.set(self.throttle)
        try:
            yield self
        finally:
            throttle_var.reset(token)

    def stopped(self) -> bool:
        if self._cancel.is_set():
            return True
        if time.monotonic() >= self.deadline:
            self._timed_out = True
            return True
        return False

    def note(self, msg: str) -> None:
        if msg not in self.notes:
            self.notes.append(msg)

    def progress(self, phase: str, done: int = 0, total: int = 0) -> None:
        if self._progress:
            self._progress(phase, done, total)

    def map(self, fn, items: list, phase: str) -> list:
        """Runs fn over items in parallel; items whose request failed are dropped. Stops early on cancel or budget."""
        out, done = [], 0
        step = self.limits.concurrency * 8

        def safe(item):
            try:
                return fn(item)
            except HTTPException:
                return None

        with ThreadPoolExecutor(self.limits.concurrency) as pool:
            for i in range(0, len(items), step):
                if self.stopped():
                    self.note(self._stop_note(phase, done, len(items)))
                    break
                futures = [pool.submit(contextvars.copy_context().run, safe, it) for it in items[i:i + step]]
                out += [r for r in (f.result() for f in futures) if r is not None]
                done += len(futures)
                self.progress(phase, done, len(items))
        return out

    def _stop_note(self, phase: str, done: int, total: int) -> str:
        why = "Scan cancelled" if self._cancel.is_set() else f"Time budget of {self.limits.budget}s reached"
        return f"{why}: {phase} partly checked ({done} of {total})."

    def namespaces(self, t: str) -> list[str]:
        """The current namespace plus its descendants (Enterprise/HCP), breadth first, capped."""
        base = namespace_var.get()
        found, queue = [base], [base]
        while queue:
            ns = queue.pop(0)
            tok = namespace_var.set(ns)
            try:
                children = list_keys("sys/namespaces", t)
            except HTTPException:
                children = []  # open source Vault, or no permission to list
            finally:
                namespace_var.reset(tok)
            for child in sorted(children):
                if len(found) >= self.limits.namespaces:
                    self.note(f"Only the first {self.limits.namespaces} namespaces were scanned.")
                    return found
                path = f"{ns}/{child.strip('/')}".strip("/")
                found.append(path)
                queue.append(path)
        return found

    @contextmanager
    def in_namespace(self, ns: str):
        tok = namespace_var.set(ns)
        try:
            yield
        finally:
            namespace_var.reset(tok)


def _where(ns: str, multi: bool) -> str:
    return f"[{ns or 'root'}] " if multi else ""


def scan_expiry(t: str, warn_days: int, scan: Scan) -> dict:
    """Expiry of tokens, PKI certificates and AppRole secret IDs across the namespace tree."""
    now = datetime.now(timezone.utc)
    items: list[dict] = []
    seen = {k: {s: 0 for s in STATUSES} for k in KINDS}
    later = 0

    def add(kind: str, name: str, source: str, expires: datetime | None) -> None:
        nonlocal later
        if expires is None:
            return
        days = (expires - now).days if expires > now else -((now - expires).days + 1)
        status = expiry_status(days, warn_days)
        seen[kind][status] += 1
        if days > KEEP_DAYS:
            later += 1
            return
        items.append({"kind": kind, "name": name, "source": source, "expires": expires.isoformat(),
                      "days_left": days, "status": status})

    with scan.active():
        spaces = scan.namespaces(t)
        for n, ns in enumerate(spaces):
            if scan.stopped():
                scan.note(scan._stop_note("namespaces", n, len(spaces)))
                break
            with scan.in_namespace(ns):
                _expiry_one(t, ns, len(spaces) > 1, scan, add)

    items.sort(key=lambda i: i["expires"])
    if len(items) > MAX_ITEMS:
        scan.note(f"{len(items) - MAX_ITEMS} later-expiring items are counted but not listed.")
        items = items[:MAX_ITEMS]
    counts = {s: sum(seen[k][s] for k in KINDS) for s in STATUSES}
    return {"items": items, "counts": counts, "by_kind": seen, "notes": scan.notes, "warn_days": warn_days,
            "later": later, "namespaces": len(spaces)}


def _expiry_one(t: str, ns: str, multi: bool, scan: Scan, add) -> None:
    lim, w = scan.limits, _where(ns, multi)
    label = ns or "root"

    try:
        accessors = list_keys("auth/token/accessors", t)
        if len(accessors) > lim.tokens:
            scan.note(f"[{label}] Only {lim.tokens} of {len(accessors)} tokens were checked.")
        scan.progress(f"tokens in {label}", 0, min(len(accessors), lim.tokens))

        def lookup(acc):
            info = call("POST", "auth/token/lookup-accessor", t, {"accessor": acc})["data"]
            return acc, info

        for acc, info in scan.map(lookup, accessors[:lim.tokens], f"tokens in {label}"):
            add("token", info.get("display_name") or "token",
                f"{w}accessor {acc} · {', '.join(info.get('policies') or [])}", parse_time(info.get("expire_time")))
    except HTTPException as e:
        scan.note(f"[{label}] Tokens not checked: {e.detail}")

    try:
        ui = call("GET", "sys/internal/ui/mounts", t)["data"]
    except HTTPException as e:
        scan.note(f"[{label}] Mounts not readable: {e.detail}")
        return

    for mount, info in ui.get("secret", {}).items():
        if info.get("type") != "pki" or scan.stopped():
            continue
        mname = mount.strip("/")
        try:
            serials = list_keys(f"{mname}/certs", t)
            if len(serials) > lim.certs:
                scan.note(f"[{label}] Only {lim.certs} of {len(serials)} certificates in '{mount}' were checked.")

            def read_cert(serial, mname=mname):
                data = call("GET", f"{mname}/cert/{clean_path(serial)}", t)["data"]
                if data.get("revocation_time"):
                    return None
                cn, exp = cert_info(data["certificate"])
                return serial, cn, exp

            seen_certs = set()
            for serial, cn, exp in scan.map(read_cert, serials[:lim.certs], f"certificates in {mname}"):
                seen_certs.add((cn, exp))
                add("certificate", cn, f"{w}{mname} · serial {serial}", exp)
            ca = call("GET", f"{mname}/cert/ca", t).get("data", {}).get("certificate")
            if ca:
                cn, exp = cert_info(ca)
                if (cn, exp) not in seen_certs:
                    add("certificate", f"{cn} (CA)", f"{w}{mname} · issuing CA", exp)
        except HTTPException as e:
            scan.note(f"[{label}] Certificates in '{mount}' not checked: {e.detail}")
        except Exception as e:
            scan.note(f"[{label}] Certificates in '{mount}' could not be parsed: {e}")

    for mount, info in ui.get("auth", {}).items():
        if info.get("type") != "approle" or scan.stopped():
            continue
        mname = mount.strip("/")
        try:
            roles = list_keys(f"auth/{mname}/role", t)
            if len(roles) > lim.roles:
                scan.note(f"[{label}] Only {lim.roles} of {len(roles)} AppRoles in '{mount}' were checked.")

            def list_ids(role, mname=mname):
                accs = list_keys(f"auth/{mname}/role/{clean_path(role)}/secret-id", t)
                return role, accs

            pairs = []
            for role, accs in scan.map(list_ids, roles[:lim.roles], f"AppRole roles in {mname}"):
                if len(accs) > lim.secret_ids:
                    scan.note(f"[{label}] Only {lim.secret_ids} of {len(accs)} secret IDs of role '{role}' were checked.")
                pairs += [(role, a) for a in accs[:lim.secret_ids]]

            def lookup_id(pair, mname=mname):
                role, acc = pair
                sid = call("POST", f"auth/{mname}/role/{clean_path(role)}/secret-id-accessor/lookup", t,
                           {"secret_id_accessor": acc})["data"]
                return role, acc, parse_time(sid.get("expiration_time"))

            never: dict[str, int] = {}
            for role, acc, exp in scan.map(lookup_id, pairs, f"AppRole secret IDs in {mname}"):
                if exp is None:
                    never[role] = never.get(role, 0) + 1
                add("approle", f"{role} secret ID", f"{w}{mname} · accessor {acc}", exp)
            for role, n in never.items():
                scan.note(f"[{label}] AppRole '{role}' has {n} secret ID(s) that never expire.")
        except HTTPException as e:
            scan.note(f"[{label}] AppRoles in '{mount}' not checked: {e.detail}")


def _finding(severity: str, category: str, title: str, detail: str) -> dict:
    return {"severity": severity, "category": category, "title": title, "detail": detail}


def scan_audit(t: str, stale_days: int, scan: Scan) -> dict:
    findings: list[dict] = []
    stats = {"policies": 0, "tokens": 0, "secrets": 0, "namespaces": 0}
    now = datetime.now(timezone.utc)
    stale: list[dict] = []

    me = call("GET", "auth/token/lookup-self", t)["data"]
    if "root" in (me.get("policies") or []):
        findings.append(_finding("high", "Tokens", "Dashboard is signed in with a root token",
                                 "Root tokens bypass all policies. Use a scoped token for daily use."))

    with scan.active():
        spaces = scan.namespaces(t)
        stats["namespaces"] = len(spaces)
        for n, ns in enumerate(spaces):
            if scan.stopped():
                scan.note(scan._stop_note("namespaces", n, len(spaces)))
                break
            with scan.in_namespace(ns):
                _audit_one(t, ns, len(spaces) > 1, stale_days, now, scan, findings, stale, stats)

    if len(stale) > MAX_STALE_FINDINGS:
        scan.note(f"{len(stale)} stale secrets found; showing the {MAX_STALE_FINDINGS} oldest.")
    stale.sort(key=lambda f: f["_age"], reverse=True)
    findings += [{k: v for k, v in f.items() if k != "_age"} for f in stale[:MAX_STALE_FINDINGS]]
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (order[f["severity"]], f["category"], f["title"]))
    return {"findings": findings, "notes": scan.notes, "stats": stats, "stale_days": stale_days}


def _audit_one(t, ns, multi, stale_days, now, scan, findings, stale, stats) -> None:
    lim, w, label = scan.limits, _where(ns, multi), ns or "root"

    try:
        names = [n for n in list_keys("sys/policies/acl", t) if n != "root"]
    except HTTPException as e:
        names = []
        scan.note(f"[{label}] Policies not audited: {e.detail}")

    def read_policy(name):
        return name, call("GET", f"sys/policies/acl/{clean_path(name)}", t)["data"]["policy"]

    for name, hcl in scan.map(read_policy, names, f"policies in {label}"):
        stats["policies"] += 1
        for rule in parse_policy(hcl):
            if not rule["risky"]:
                continue
            severe = "sudo" in rule["capabilities"] or rule["path"] in ("*", "/*")
            findings.append(_finding(
                "high" if severe else "medium", "Policies", f"{w}Broad rule in policy '{name}'",
                f'path "{rule["path"]}" grants {", ".join(rule["capabilities"]) or "no capabilities"}'))

    try:
        accessors = list_keys("auth/token/accessors", t)
        if len(accessors) > lim.tokens:
            scan.note(f"[{label}] Only {lim.tokens} of {len(accessors)} tokens were checked.")

        def lookup(acc):
            return acc, call("POST", "auth/token/lookup-accessor", t, {"accessor": acc})["data"]

        for acc, info in scan.map(lookup, accessors[:lim.tokens], f"tokens in {label}"):
            stats["tokens"] += 1
            tag = info.get("display_name") or acc
            pols = info.get("policies") or []
            if "root" in pols:
                findings.append(_finding("high", "Tokens", f"{w}Active root token ({tag})",
                                         f"Accessor {acc}. Revoke it once no longer needed."))
            elif not info.get("ttl") and not info.get("expire_time"):
                findings.append(_finding("medium", "Tokens", f"{w}Token without expiry ({tag})",
                                         f"Accessor {acc}, policies: {', '.join(pols) or 'none'}."))
    except HTTPException as e:
        scan.note(f"[{label}] Tokens not audited: {e.detail}")

    try:
        mounts = call("GET", "sys/internal/ui/mounts", t)["data"].get("secret", {})
    except HTTPException as e:
        scan.note(f"[{label}] Mounts not readable: {e.detail}")
        return
    for mount, info in mounts.items():
        if info.get("type") not in ("kv", "generic") or scan.stopped():
            continue
        if str((info.get("options") or {}).get("version") or "1") != "2":
            continue  # KV v1 keeps no timestamps
        mname = mount.strip("/")
        scan.progress(f"listing secrets in {mname}", 0, 0)
        try:
            paths, truncated = walk_kv(mname, True, t, limit=lim.secrets, stop=scan.stopped)
        except HTTPException as e:
            scan.note(f"[{label}] Secrets in '{mount}' not audited: {e.detail}")
            continue
        if truncated:
            scan.note(f"[{label}] Only the first {len(paths)} secrets in '{mount}' were examined.")

        def read_meta(p, mname=mname):
            return p, call("GET", f"{mname}/metadata/{clean_path(p)}", t)["data"]

        for p, meta in scan.map(read_meta, paths, f"secrets in {mname}"):
            stats["secrets"] += 1
            updated = parse_time(meta.get("updated_time"))
            if updated and (now - updated).days >= stale_days:
                age = (now - updated).days
                stale.append({**_finding("low", "Secrets", f"{w}Stale secret {mname}/{p}",
                                         f"Last changed {age} days ago (threshold {stale_days})."), "_age": age})


# ---------- background jobs ----------
JOBS: dict[tuple, dict] = {}
_jobs_lock = threading.Lock()
MAX_RUNNING = 3
MAX_KEPT = 50


def _key(kind: str, t: str) -> tuple:
    c = cluster_var.get()
    digest = hashlib.sha256(f"{t}|{namespace_var.get()}".encode()).hexdigest()[:24]
    return (c.name if c else "", kind, digest)


def _public(job: dict | None) -> dict:
    if not job:
        return {"state": "none"}
    return {k: v for k, v in job.items() if not k.startswith("_")}


def get_job(kind: str, t: str) -> dict:
    with _jobs_lock:
        return _public(JOBS.get(_key(kind, t)))


def cancel_job(kind: str, t: str) -> dict:
    with _jobs_lock:
        job = JOBS.get(_key(kind, t))
        if job and job["state"] == "running":
            job["_cancel"].set()
        return _public(job)


def start_job(kind: str, t: str, param: int) -> dict:
    """Starts a scan of the selected cluster/namespace with the caller's token, unless one is running."""
    call("GET", "auth/token/lookup-self", t)  # reject bad tokens before spawning anything
    key = _key(kind, t)
    cluster, ns = cluster_var.get(), namespace_var.get()
    with _jobs_lock:
        job = JOBS.get(key)
        if job and job["state"] == "running":
            return _public(job)
        if sum(1 for j in JOBS.values() if j["state"] == "running") >= MAX_RUNNING:
            raise HTTPException(429, "Too many scans are running; try again in a minute")
        for k in sorted(JOBS, key=lambda k: JOBS[k]["started"])[:max(0, len(JOBS) - MAX_KEPT + 1)]:
            if JOBS[k]["state"] != "running":
                del JOBS[k]
        job = {"state": "running", "kind": kind, "started": time.time(), "finished": None,
               "progress": {"phase": "starting", "done": 0, "total": 0}, "param": param,
               "limits": asdict(Limits.from_env()), "result": None, "error": None, "_cancel": threading.Event()}
        JOBS[key] = job

    def progress(phase: str, done: int, total: int) -> None:
        job["progress"] = {"phase": phase, "done": done, "total": total}

    def run() -> None:
        cluster_var.set(cluster)
        namespace_var.set(ns)
        scan = Scan(progress=progress, cancel=job["_cancel"])
        try:
            fn = scan_expiry if kind == "expiry" else scan_audit
            job["result"] = fn(t, param, scan)
            job["state"] = "done"
        except HTTPException as e:
            job["error"], job["state"] = str(e.detail), "error"
        except Exception as e:
            job["error"], job["state"] = f"Scan failed: {e}", "error"
        finally:
            job["finished"] = time.time()

    threading.Thread(target=run, name=f"onepane-{kind}", daemon=True).start()
    return _public(job)


def monitor_expiry(token: str, warn_days: int) -> dict:
    """Entry point of the background monitor (cluster/namespace come from the context set by use_cluster)."""
    return scan_expiry(token, warn_days, Scan())
