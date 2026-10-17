import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from main import app
from vault import clean_path, parse_policy

client = TestClient(app)


def test_clean_path():
    assert clean_path("/a/b c/") == "a/b%20c"
    assert clean_path("") == ""
    for bad in ("a/../b", "a//b", "..", "a\\b", "a/\x00"):
        with pytest.raises(HTTPException):
            clean_path(bad)


def test_requires_token():
    assert client.get("/api/me").status_code == 401
    assert client.get("/api/kv/list?mount=secret").status_code == 401


def test_parse_policy_nested_and_risky():
    hcl = '''
    path "secret/data/app/*" { capabilities = ["read", "list"] }
    path "secret/data/rw/*" {
      capabilities = ["create", "update", "delete"]
      allowed_parameters = { "foo" = [] }
    }
    path "sys/*" { capabilities = ["sudo", "read"] }
    path "*" { capabilities = ["read"] }
    path "cubbyhole/*" { capabilities = ["create", "read", "update", "delete", "list"] }
    '''
    rules = parse_policy(hcl)
    assert [r["path"] for r in rules] == ["secret/data/app/*", "secret/data/rw/*", "sys/*", "*", "cubbyhole/*"]
    assert [r["risky"] for r in rules] == [False, True, True, True, False]
    assert rules[1]["capabilities"] == ["create", "update", "delete"]


def test_parse_time_handles_nanoseconds():
    from vault import parse_time

    dt = parse_time("2026-10-17T14:57:40.8335776Z")
    assert dt is not None and dt.year == 2026 and dt.tzinfo is not None
    assert parse_time("") is None and parse_time("0001-01-01T00:00:00Z") is None
    assert parse_time("garbage") is None


def test_walk_kv(monkeypatch):
    import vault

    tree = {"m/metadata/": ["a", "dir/"], "m/metadata/dir/": ["b", "sub/"], "m/metadata/dir/sub/": ["c"]}
    monkeypatch.setattr(vault, "list_keys", lambda path, token: tree.get(path, []))
    paths, truncated = vault.walk_kv("m", True, "tok")
    assert paths == ["a", "dir/b", "dir/sub/c"] and not truncated
    paths, truncated = vault.walk_kv("m", True, "tok", limit=2)
    assert len(paths) == 2 and truncated


def test_readonly_blocks_writes(monkeypatch):
    monkeypatch.setenv("VAULT_DASH_READONLY", "1")
    h = {"X-Vault-Token": "t"}
    r = client.post("/api/kv/write", json={"mount": "secret", "path": "x", "data": {"a": "b"}}, headers=h)
    assert r.status_code == 403
    assert client.delete("/api/kv/delete?mount=secret&path=x", headers=h).status_code == 403


def test_write_requires_token():
    r = client.post("/api/kv/write", json={"mount": "secret", "path": "x", "data": {"a": "b"}})
    assert r.status_code == 401
    assert client.get("/api/scan/audit").status_code == 401
    assert client.get("/api/kv/search?mount=secret&q=a").status_code == 401


def test_expiry_status_and_cert_info():
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from vault import cert_info, expiry_status

    assert [expiry_status(d, 30) for d in (-1, 0, 7, 8, 30, 31)] == [
        "expired", "critical", "critical", "warning", "warning", "ok"]

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "svc.example.com")])
    end = datetime.now(timezone.utc) + timedelta(days=10)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1)).not_valid_after(end)
            .sign(key, hashes.SHA256()))
    cn, exp = cert_info(cert.public_bytes(serialization.Encoding.PEM).decode())
    assert cn == "svc.example.com" and abs((exp - end).total_seconds()) < 2


def test_expiry_requires_token():
    assert client.get("/api/scan/expiry").status_code == 401
    assert client.post("/api/scan/expiry").status_code == 401
    assert client.get("/api/scan/nope", headers={"X-Vault-Token": "t"}).status_code == 404


def test_namespace_validation():
    from vault import clean_namespace

    assert clean_namespace("/admin/team-a/") == "admin/team-a"
    assert clean_namespace(None) == "" and clean_namespace("") == ""
    for bad in ("../x", "a/../b", "a b", "a?b", "a\nb"):
        with pytest.raises(HTTPException):
            clean_namespace(bad)


def test_namespace_header_and_ca_are_sent(monkeypatch):
    import httpx
    import vault

    seen = []

    def fake(method, url, **kw):
        seen.append((url, kw["headers"], kw["verify"]))
        return httpx.Response(200, json={"data": {"policies": ["default"]}}, request=httpx.Request(method, url))

    monkeypatch.setattr(vault, "_http", fake)
    monkeypatch.setenv("VAULT_CACERT", "/etc/ca.pem")
    h = {"X-Vault-Token": "t", "X-Vault-Namespace": "/admin/team-a/"}
    assert client.get("/api/me", headers=h).status_code == 200
    url, headers, verify = seen[-1]
    assert headers["X-Vault-Namespace"] == "admin/team-a" and headers["X-Vault-Token"] == "t"
    assert verify == "/etc/ca.pem"

    # No namespace header means none is forwarded, and a previous request's value must not leak.
    monkeypatch.delenv("VAULT_CACERT")
    client.get("/api/me", headers={"X-Vault-Token": "t"})
    assert "X-Vault-Namespace" not in seen[-1][1] and seen[-1][2] is True

    assert client.get("/api/me", headers={**h, "X-Vault-Namespace": "../x"}).status_code == 400


def write_clusters(tmp_path, monkeypatch, entries):
    import json

    f = tmp_path / "clusters.json"
    f.write_text(json.dumps(entries))
    monkeypatch.setenv("VAULT_CLUSTERS_FILE", str(f))


def test_clusters_file_and_per_cluster_routing(monkeypatch, tmp_path):
    import httpx

    monkeypatch.setenv("TOK_B", "svc-b")
    import vault

    write_clusters(tmp_path, monkeypatch, [
        {"name": "a", "addr": "https://a.example:8200/"},
        {"name": "b", "addr": "https://b.example:8200", "cacert": "/ca-b.pem", "namespace": "admin",
         "monitor_token_env": "TOK_B"}])
    listed = client.get("/api/clusters").json()["clusters"]
    assert [c["name"] for c in listed] == ["a", "b"] and listed[1]["monitored"] and not listed[0]["monitored"]
    assert "svc-b" not in client.get("/api/clusters").text

    seen = []

    def fake(method, url, **kw):
        seen.append((url, kw["headers"], kw["verify"]))
        return httpx.Response(200, json={"data": {}}, request=httpx.Request(method, url))

    monkeypatch.setattr(vault, "_http", fake)
    client.get("/api/me", headers={"X-Vault-Token": "t", "X-Vault-Cluster": "b"})
    url, headers, verify = seen[-1]
    assert url.startswith("https://b.example:8200/") and verify == "/ca-b.pem"
    assert headers["X-Vault-Namespace"] == "admin"
    client.get("/api/me", headers={"X-Vault-Token": "t"})
    assert seen[-1][0].startswith("https://a.example:8200/") and "X-Vault-Namespace" not in seen[-1][1]
    assert client.get("/api/me", headers={"X-Vault-Token": "t", "X-Vault-Cluster": "zzz"}).status_code == 400


def test_clusters_file_validation(monkeypatch, tmp_path):
    from clusters import load_clusters

    write_clusters(tmp_path, monkeypatch, [{"name": "a b", "addr": "https://x"}])
    with pytest.raises(ValueError):
        load_clusters()
    write_clusters(tmp_path, monkeypatch, [{"name": "a", "addr": "https://x"}, {"name": "a", "addr": "https://y"}])
    with pytest.raises(ValueError):
        load_clusters()
    write_clusters(tmp_path, monkeypatch, [{"name": "a", "addr": "ftp://x"}])
    with pytest.raises(ValueError):
        load_clusters()


def test_fleet_requires_token():
    assert client.get("/api/fleet").status_code == 401


def test_monitor_alerts_only_on_new_problems(monkeypatch):
    import monitor

    sent = []
    monkeypatch.setattr(monitor, "send_alert", lambda subject, lines: sent.append(lines))
    monkeypatch.setattr(monitor, "alerts_enabled", lambda: True)
    monitor._alerted.clear()
    from datetime import datetime, timedelta, timezone

    item = {"kind": "token", "name": "ci", "source": "acc", "status": "critical", "days_left": 2,
            "expires": (datetime.now(timezone.utc) + timedelta(hours=50)).isoformat()}
    down = {"name": "p", "up": False, "error": "boom", "checked_at": 0}
    ok = {"name": "p", "up": True, "sealed": False, "items": [item], "checked_at": 0}

    monitor.notify([down])
    assert len(sent) == 1 and "unreachable" in sent[-1][0]
    monitor.notify([down])
    assert len(sent) == 1                       # same problem, no repeat
    monitor.notify([ok])
    assert len(sent) == 3                       # new expiry alert, then the recovery notice
    assert "recovered" in sent[-1][0] and "expires in 2d" in sent[-2][0]
    monitor.notify([ok])
    assert len(sent) == 3


def test_metrics_endpoint(monkeypatch):
    import monitor

    monitor.STATE.clear()
    monitor.STATE["p"] = {"name": "p", "up": True, "sealed": False, "checked_at": 100.0,
                          "by_kind": {"token": {"expired": 1, "critical": 0, "warning": 2, "ok": 3}}}
    text = client.get("/metrics").text
    assert 'vault_dash_cluster_up{cluster="p"} 1' in text
    assert 'vault_dash_expiry_items{cluster="p",kind="token",status="warning"} 2' in text
    monkeypatch.setenv("VAULT_DASH_METRICS_TOKEN", "s3")
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer s3"}).status_code == 200
    monitor.STATE.clear()


def test_teams_webhook_format(monkeypatch):
    import httpx
    import monitor

    monkeypatch.delenv("VAULT_ALERT_FORMAT", raising=False)
    teams = "https://prod-12.westeurope.logic.azure.com:443/workflows/abc/triggers/manual/paths/invoke?sig=x"
    assert monitor.alert_format(teams) == "teams"
    assert monitor.alert_format("https://x.webhook.office.com/webhookb2/abc") == "teams"
    assert monitor.alert_format("https://hooks.slack.com/services/T/B/x") == "text"
    assert monitor.alert_format("https://evil.com/?u=logic.azure.com") == "text"
    monkeypatch.setenv("VAULT_ALERT_FORMAT", "teams")
    assert monitor.alert_format("https://hooks.slack.com/x") == "teams"

    sent = []
    monkeypatch.setattr(httpx, "post", lambda url, json, timeout: sent.append(json) or httpx.Response(
        202, request=httpx.Request("POST", url)))
    monkeypatch.setenv("VAULT_ALERT_WEBHOOK", teams)
    monkeypatch.delenv("VAULT_ALERT_FORMAT")
    monitor.send_alert("Subject", ["line one", "line two"])
    card = sent[0]["attachments"][0]
    assert sent[0]["type"] == "message" and card["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert [b["text"] for b in card["content"]["body"]] == ["Subject", "line one", "line two"]


def test_throttle_spaces_requests():
    import time
    from vault import Throttle

    th = Throttle(50)                        # one request per 20 ms
    start = time.monotonic()
    for _ in range(6):
        th.wait()
    assert time.monotonic() - start >= 0.09
    assert Throttle(0).interval == 0
    th.slow_down()
    assert th.interval >= 0.1


def test_call_retries_429_only_during_scans(monkeypatch):
    import httpx
    import vault

    calls = []

    def fake(method, url, **kw):
        calls.append(1)
        status = 429 if len(calls) < 3 else 200
        return httpx.Response(status, json={"errors": ["rate limited"], "data": {}}, request=httpx.Request(method, url))

    monkeypatch.setattr(vault, "_http", fake)
    monkeypatch.setattr(vault.time, "sleep", lambda s: None)
    with pytest.raises(HTTPException) as e:          # interactive request: no retry
        vault.call("GET", "x", "t")
    assert e.value.status_code == 429 and len(calls) == 1
    calls.clear()
    tok = vault.throttle_var.set(vault.Throttle(0))
    try:
        assert vault.call("GET", "x", "t") == {"errors": ["rate limited"], "data": {}}
    finally:
        vault.throttle_var.reset(tok)
    assert len(calls) == 3


def test_limits_from_env(monkeypatch):
    import scan

    monkeypatch.setenv("VAULT_SCAN_RPS", "5")
    monkeypatch.setenv("VAULT_SCAN_MAX_TOKENS", "10")
    monkeypatch.setenv("VAULT_SCAN_CONCURRENCY", "bogus")
    lim = scan.Limits.from_env()
    assert lim.rps == 5 and lim.tokens == 10 and lim.concurrency == scan.Limits.concurrency


def test_scan_map_respects_budget_and_skips_errors():
    import scan

    s = scan.Scan(scan.Limits(rps=0, concurrency=2, budget=10))

    def fn(i):
        if i == 1:
            raise HTTPException(403, "nope")
        return i

    assert sorted(s.map(fn, list(range(10)), "x")) == [0, 2, 3, 4, 5, 6, 7, 8, 9]
    s2 = scan.Scan(scan.Limits(rps=0, concurrency=2, budget=10))
    s2.deadline = 0                                   # budget already used up
    assert s2.map(fn, list(range(10)), "things") == []
    assert "Time budget" in s2.notes[0]


def test_namespace_walk_is_capped(monkeypatch):
    import scan
    import vault

    tree = {"": ["a/", "b/"], "a": ["a1/", "a2/"], "b": [], "a/a1": [], "a/a2": []}
    monkeypatch.setattr(scan, "list_keys", lambda path, t: tree[vault.namespace_var.get()])
    s = scan.Scan(scan.Limits(namespaces=10))
    assert s.namespaces("t") == ["", "a", "b", "a/a1", "a/a2"]
    s = scan.Scan(scan.Limits(namespaces=3))
    assert s.namespaces("t") == ["", "a", "b"] and "first 3 namespaces" in s.notes[0]


def fake_vault(monkeypatch, namespaces_tree):
    """Fake Vault with a token and a secret ID expiring soon in every namespace; records namespaces seen."""
    import scan
    import vault
    from datetime import datetime, timedelta, timezone

    soon = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    far = (datetime.now(timezone.utc) + timedelta(days=400)).isoformat()
    seen = []

    def list_keys(path, t):
        ns = vault.namespace_var.get()
        seen.append((ns, path))
        if path == "sys/namespaces":
            return namespaces_tree.get(ns, [])
        if path == "auth/token/accessors":
            return ["acc1", "acc2"]
        if path == "auth/approle/role":
            return ["r1"]
        if path.endswith("/secret-id"):
            return ["sid1"]
        return []

    def call(method, path, t, json=None):
        if path == "auth/token/lookup-accessor":
            exp = soon if json["accessor"] == "acc1" else far
            return {"data": {"display_name": json["accessor"], "policies": ["p"], "expire_time": exp}}
        if path == "sys/internal/ui/mounts":
            return {"data": {"secret": {}, "auth": {"approle/": {"type": "approle"}}}}
        if path.endswith("secret-id-accessor/lookup"):
            return {"data": {"expiration_time": soon}}
        raise HTTPException(404, "x")

    monkeypatch.setattr(scan, "list_keys", list_keys)
    monkeypatch.setattr(scan, "call", call)
    return seen


def test_scan_expiry_walks_namespaces(monkeypatch):
    import scan

    fake_vault(monkeypatch, {"": ["team/"]})
    res = scan.scan_expiry("t", 30, scan.Scan(scan.Limits(rps=0, concurrency=2)))
    assert res["namespaces"] == 2
    assert res["counts"] == {"expired": 0, "critical": 4, "warning": 0, "ok": 2}   # 2 tokens + 2 approle ids; far ones are "later"
    assert res["later"] == 2 and len(res["items"]) == 4
    assert any(i["source"].startswith("[team] ") for i in res["items"])
    assert res["by_kind"]["token"]["critical"] == 2


def test_scan_job_is_private_to_the_token(monkeypatch):
    import time
    import scan
    import vault

    fake_vault(monkeypatch, {})
    monkeypatch.setattr(scan, "call", lambda *a, **k: (
        {"data": {}} if a[1] == "auth/token/lookup-self" else
        {"data": {"display_name": "x", "policies": [], "expire_time": None}} if a[1] == "auth/token/lookup-accessor"
        else {"data": {"secret": {}, "auth": {}}}))
    scan.JOBS.clear()
    started = scan.start_job("expiry", "token-a", 30)
    assert started["state"] in ("running", "done")
    for _ in range(50):
        job = scan.get_job("expiry", "token-a")
        if job["state"] != "running":
            break
        time.sleep(0.05)
    assert job["state"] == "done" and job["result"]["counts"]["ok"] == 0
    assert "token-a" not in repr(scan.JOBS.keys())      # only a hash is used as the key
    assert scan.get_job("expiry", "token-b") == {"state": "none"}
    scan.JOBS.clear()
