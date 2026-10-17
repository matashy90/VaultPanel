import logging
import os
import smtplib
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.message import EmailMessage
from urllib.parse import urlparse

import httpx

from clusters import Cluster, load_clusters, use_cluster
from vault import parse_time, tls_verify, vault_addr

log = logging.getLogger("onepane.monitor")

KINDS = ("token", "certificate", "approle")
STATUSES = ("expired", "critical", "warning", "ok")

# cluster name -> latest background result; read by /api/fleet and /metrics.
STATE: dict[str, dict] = {}
_alerted: dict[str, set[str]] = {}
_lock = threading.Lock()


def cluster_health(cluster: Cluster) -> dict:
    """Unauthenticated sys/health of one cluster."""
    with use_cluster(cluster):
        url = f"{vault_addr()}/v1/sys/health?standbyok=true&sealedcode=200&uninitcode=200"
        try:
            d = httpx.get(url, timeout=5, verify=tls_verify()).json()
        except (httpx.HTTPError, ValueError) as e:
            return {"up": False, "error": str(e)}
    return {"up": True, "sealed": bool(d.get("sealed")), "standby": bool(d.get("standby")),
            "version": d.get("version"), "cluster_name": d.get("cluster_name"),
            "enterprise": bool(d.get("enterprise")) or "+ent" in str(d.get("version", ""))}


def scan_cluster(cluster: Cluster, scan_fn, warn_days: int) -> dict:
    result = {"name": cluster.name, "addr": cluster.addr, "namespace": cluster.namespace,
              "monitored": bool(cluster.monitor_token), "checked_at": time.time(),
              **cluster_health(cluster)}
    if result["up"] and not result["sealed"] and cluster.monitor_token:
        try:
            with use_cluster(cluster):
                scan = scan_fn(cluster.monitor_token, warn_days)
            result["counts"] = scan["counts"]
            result["notes"] = scan["notes"]
            result["items"] = [i for i in scan["items"] if i["status"] != "ok"][:100]
            result["by_kind"] = {k: {s: sum(1 for i in scan["items"] if i["kind"] == k and i["status"] == s)
                                     for s in STATUSES} for k in KINDS}
        except Exception as e:  # a broken scan must not kill the monitor loop
            result["scan_error"] = str(getattr(e, "detail", e))
    return result


def problems(r: dict) -> dict[str, str]:
    """Alert-worthy conditions of one cluster result: key -> message."""
    out: dict[str, str] = {}
    name = r["name"]
    if not r["up"]:
        out["down"] = f"[{name}] Vault is unreachable ({r.get('error', 'unknown error')})"
    elif r["sealed"]:
        out["sealed"] = f"[{name}] Vault is sealed"
    if r.get("scan_error"):
        out["scan_error"] = f"[{name}] Expiry scan failed: {r['scan_error']}"
    for i in r.get("items", []):
        if i["status"] in ("expired", "critical"):
            exp = parse_time(i["expires"])
            hrs = int((exp - datetime.now(timezone.utc)).total_seconds() // 3600) if exp else 0
            span = f"{abs(hrs)}h" if abs(hrs) < 48 else f"{abs(hrs) // 24}d"
            when = f"expired {span} ago" if i["status"] == "expired" else f"expires in {span}"
            out[f"{i['kind']}|{i['name']}|{i['source']}|{i['status']}"] = (
                f"[{name}] {i['kind']} '{i['name']}' {when} ({i['source']})")
    return out


def alert_format(url: str) -> str:
    """'teams' (Adaptive Card) or 'text' (Slack/Mattermost). VAULT_ALERT_FORMAT overrides the URL guess."""
    fmt = os.environ.get("VAULT_ALERT_FORMAT", "").lower()
    if fmt in ("teams", "text"):
        return fmt
    host = (urlparse(url).hostname or "").lower()
    teams_hosts = ("logic.azure.com", "powerplatform.com", "webhook.office.com", "office.com")
    return "teams" if any(host == h or host.endswith("." + h) for h in teams_hosts) else "text"


def teams_payload(subject: str, lines: list[str]) -> dict:
    return {"type": "message", "attachments": [{
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard", "version": "1.4",
            "body": [{"type": "TextBlock", "text": subject, "weight": "Bolder", "size": "Medium", "wrap": True}]
                    + [{"type": "TextBlock", "text": line, "wrap": True, "spacing": "Small"} for line in lines],
        }}]}


def send_alert(subject: str, lines: list[str]) -> None:
    if len(lines) > 30:
        lines = lines[:30] + [f"... and {len(lines) - 30} more (see the Fleet page)"]
    body = "\n".join(lines)
    url = os.environ.get("VAULT_ALERT_WEBHOOK", "")
    if url.startswith(("http://", "https://")):
        # The text format is understood by Slack and Mattermost; other receivers can read "lines".
        payload = (teams_payload(subject, lines) if alert_format(url) == "teams"
                   else {"text": f"{subject}\n{body}", "lines": lines})
        try:
            r = httpx.post(url, json=payload, timeout=10)
            if r.status_code >= 400:
                log.warning("Webhook alert rejected: HTTP %s %s", r.status_code, r.text[:200])
        except httpx.HTTPError as e:
            log.warning("Webhook alert failed: %s", e)
    host = os.environ.get("VAULT_ALERT_SMTP_HOST")
    to = [a.strip() for a in os.environ.get("VAULT_ALERT_EMAIL_TO", "").split(",") if a.strip()]
    if host and to:
        msg = EmailMessage()
        msg["Subject"], msg["To"] = subject, ", ".join(to)
        msg["From"] = os.environ.get("VAULT_ALERT_EMAIL_FROM", "onepane@localhost")
        msg.set_content(body)
        try:
            with smtplib.SMTP(host, int(os.environ.get("VAULT_ALERT_SMTP_PORT", "587")), timeout=15) as s:
                if os.environ.get("VAULT_ALERT_SMTP_STARTTLS", "1") != "0":
                    s.starttls()
                if os.environ.get("VAULT_ALERT_SMTP_USER"):
                    s.login(os.environ["VAULT_ALERT_SMTP_USER"], os.environ.get("VAULT_ALERT_SMTP_PASSWORD", ""))
                s.send_message(msg)
        except (OSError, smtplib.SMTPException) as e:
            log.warning("Email alert failed: %s", e)


def alerts_enabled() -> bool:
    return bool(os.environ.get("VAULT_ALERT_WEBHOOK") or
                (os.environ.get("VAULT_ALERT_SMTP_HOST") and os.environ.get("VAULT_ALERT_EMAIL_TO")))


def notify(results: list[dict]) -> None:
    """Sends one alert per pass for problems not seen in the previous pass, plus recoveries."""
    new_lines, resolved = [], []
    with _lock:
        for r in results:
            now = problems(r)
            before = _alerted.get(r["name"], set())
            new_lines += [msg for key, msg in now.items() if key not in before]
            resolved += [f"[{r['name']}] recovered: {k}" for k in before - now.keys()
                         if k in ("down", "sealed", "scan_error")]
            _alerted[r["name"]] = set(now)
    if new_lines and alerts_enabled():
        send_alert(f"OnePane: {len(new_lines)} new Vault alert(s)", new_lines)
    if resolved and alerts_enabled():
        send_alert("OnePane: Vault recovered", resolved)


def run_once(scan_fn, warn_days: int = 30) -> list[dict]:
    clusters = load_clusters()
    with ThreadPoolExecutor(max_workers=min(8, len(clusters))) as pool:
        results = list(pool.map(lambda c: scan_cluster(c, scan_fn, warn_days), clusters))
    with _lock:
        STATE.clear()
        STATE.update({r["name"]: r for r in results})
    notify(results)
    return results


def interval() -> int:
    try:
        return int(os.environ.get("VAULT_MONITOR_INTERVAL", "300"))
    except ValueError:
        return 300


def start(scan_fn) -> threading.Event | None:
    """Starts the background loop; returns its stop event, or None when disabled (interval 0)."""
    secs = interval()
    if secs <= 0:
        return None
    stop = threading.Event()

    def loop() -> None:
        while not stop.is_set():
            try:
                run_once(scan_fn)
            except Exception:
                log.exception("Monitor pass failed")
            stop.wait(max(secs, 30))

    threading.Thread(target=loop, name="onepane-monitor", daemon=True).start()
    return stop


def metrics_text(results: list[dict] | None = None) -> str:
    with _lock:
        results = list(STATE.values()) if results is None else results
    lines = [
        "# HELP vault_dash_cluster_up 1 if the cluster answered sys/health.",
        "# TYPE vault_dash_cluster_up gauge",
        "# HELP vault_dash_cluster_sealed 1 if the cluster is sealed.",
        "# TYPE vault_dash_cluster_sealed gauge",
        "# HELP vault_dash_expiry_items Tokens, certificates and AppRole secret IDs by expiry status.",
        "# TYPE vault_dash_expiry_items gauge",
        "# HELP vault_dash_last_check_timestamp_seconds Unix time of the last background check.",
        "# TYPE vault_dash_last_check_timestamp_seconds gauge",
    ]
    for r in results:
        c = f'cluster="{r["name"]}"'
        lines.append(f"vault_dash_cluster_up{{{c}}} {int(r['up'])}")
        lines.append(f"vault_dash_cluster_sealed{{{c}}} {int(r.get('sealed', False))}")
        lines.append(f"vault_dash_last_check_timestamp_seconds{{{c}}} {int(r['checked_at'])}")
        for kind, by_status in r.get("by_kind", {}).items():
            for status, n in by_status.items():
                lines.append(f'vault_dash_expiry_items{{{c},kind="{kind}",status="{status}"}} {n}')
    return "\n".join(lines) + "\n"
