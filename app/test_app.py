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
