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
    '''
    rules = parse_policy(hcl)
    assert [r["path"] for r in rules] == ["secret/data/app/*", "secret/data/rw/*", "sys/*", "*"]
    assert [r["risky"] for r in rules] == [False, True, True, True]
    assert rules[1]["capabilities"] == ["create", "update", "delete"]
