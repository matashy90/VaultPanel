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
    assert client.get("/api/audit").status_code == 401
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
    assert client.get("/api/expiry").status_code == 401


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

    monkeypatch.setattr(httpx, "request", fake)
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

    monkeypatch.setattr(httpx, "request", fake)
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
