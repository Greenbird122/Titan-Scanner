"""Tests for the scenario fixture routes.

Round 1: SCN-003 puzzle gate, SCN-004 integrity, SCN-005 gated redirect.
Round 2: SCN-007 stored XSS, SCN-011 stored SQLi, SCN-010 token leak channels,
         SCN-009 Host-header cache poisoning, SCN-013 prototype pollution.
"""
import base64
import sys
from pathlib import Path

import pytest

LAB_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LAB_ROOT))

from local_lab import app as lab  # noqa: E402
from local_lab import scenario_fixtures as sf  # noqa: E402


@pytest.fixture()
def client():
    c = lab.app.test_client()
    c.post("/lab-reset")  # clean slate for every test
    return c


# --- SCN-003: puzzle-gated hidden asset ------------------------------------
def test_puzzle_page_reveals_ciphertext(client):
    body = client.get("/puzzle").get_data(as_text=True)
    assert sf.PUZZLE_CIPHER in body
    assert "ciphertext" in body


def test_puzzle_admin_gated_without_key(client):
    r = client.get("/puzzle/admin")
    assert r.status_code == 403
    assert "TITANPUZZLE" in r.get_data(as_text=True)


def test_puzzle_admin_unlocks_with_solved_key(client):
    # Solve the puzzle exactly as hinted: base64-decode -> xor 0x5A -> utf-8.
    key = bytes(b ^ 0x5A for b in base64.b64decode(sf.PUZZLE_CIPHER)).decode("utf-8")
    assert key == sf.PUZZLE_PLAIN
    r = client.get(f"/puzzle/admin?key={key}")
    assert r.status_code == 200
    assert "flag{TITAN-puzzle-gate-3301}" in r.get_data(as_text=True)


def test_puzzle_admin_rejects_wrong_key(client):
    r = client.get("/puzzle/admin?key=WRONG")
    assert r.status_code == 403


# --- SCN-004: defacement integrity break ------------------------------------
def test_integrity_starts_clean(client):
    body = client.get("/integrity").get_data(as_text=True)
    assert "status: OK" in body
    assert "DEFACED-BY-TITAN" not in body


def test_deface_then_restore(client):
    assert client.get("/integrity").get_data(as_text=True).count("DEFACED-BY-TITAN") == 0
    r = client.post("/integrity/deface")
    assert r.status_code == 200
    body = client.get("/integrity").get_data(as_text=True)
    assert "DEFACED-BY-TITAN" in body
    assert "status: OK" not in body
    client.post("/integrity/restore")
    restored = client.get("/integrity").get_data(as_text=True)
    assert "status: OK" in restored
    assert "DEFACED-BY-TITAN" not in restored


# --- SCN-007: stored XSS (guestbook) ----------------------------------------
def test_guestbook_stores_and_echoes_entry(client):
    r = client.post("/guestbook/add", data={"entry": "<script>alert(1)</script>"})
    assert "Stored:" in r.get_data(as_text=True)
    body = client.get("/guestbook").get_data(as_text=True)
    assert "<script>alert(1)</script>" in body  # rendered unescaped (second-order)


def test_guestbook_clean_after_reset(client):
    body = client.get("/guestbook").get_data(as_text=True)
    assert "alert(1)" not in body


# --- SCN-011: stored SQLi (register -> login) --------------------------------
def test_stored_tautology_login_finds_user(client):
    client.post("/register", data={"username": "ghost' OR '1'='1"})
    r = client.post("/login", data={"username": "ghost' OR '1'='1"})
    assert "user found" in r.get_data(as_text=True)


def test_stored_tautology_case_insensitive(client):
    client.post("/register", data={"username": "ghost' oR '1'='1"})
    r = client.post("/login", data={"username": "ghost' oR '1'='1"})
    assert "user found" in r.get_data(as_text=True)


def test_benign_unknown_user_not_found(client):
    client.post("/register", data={"username": "ghost"})
    r = client.post("/login", data={"username": "ghost"})
    assert "user not found" in r.get_data(as_text=True)


def test_unregistered_user_rejected(client):
    r = client.post("/login", data={"username": "ghost' OR '1'='1"})
    assert "user not registered" in r.get_data(as_text=True)


# --- SCN-010: reset-token leak channels --------------------------------------
def test_reset_token_in_header(client):
    r = client.get("/reset?mode=header")
    token = r.headers.get("X-Debug-Token", "")
    assert token == sf.RESET_TOKEN


def test_reset_token_in_body(client):
    r = client.get("/reset?mode=body")
    assert sf.RESET_TOKEN in r.get_data(as_text=True)


def test_reset_token_in_cookie(client):
    r = client.get("/reset?mode=cookie")
    assert f"debug_token={sf.RESET_TOKEN}" in r.headers.get("Set-Cookie", "")


# --- SCN-009: Host-header cache poisoning ------------------------------------
def test_search_reflects_host_header(client):
    r = client.get("/search?q=test", headers={"Host": "evil.example"})
    body = r.get_data(as_text=True)
    assert "evil.example" in body
    assert r.headers.get("X-Cache") == "HIT"


def test_search_reflects_x_forwarded_host(client):
    r = client.get("/search?q=test", headers={"X-Forwarded-Host": "evil2.example"})
    assert "evil2.example" in r.get_data(as_text=True)


def test_search_normal_host_clean(client):
    r = client.get("/search?q=test")
    body = r.get_data(as_text=True)
    assert "cached host:" in body
    assert "evil" not in body


# --- SCN-013: server-side prototype pollution ---------------------------------
def test_proto_pollution_escalates_profile(client):
    client.post("/api/profile/update", json={"__proto__": {"isAdmin": True}})
    body = client.get("/api/profile").get_data(as_text=True)
    assert "ADMIN-ESCALATION" in body


def test_constructor_prototype_escalates(client):
    client.post("/api/profile/update", json={"constructor": {"prototype": {"isAdmin": True}}})
    assert "ADMIN-ESCALATION" in client.get("/api/profile").get_data(as_text=True)


def test_clean_profile_no_escalation(client):
    assert "ADMIN-ESCALATION" not in client.get("/api/profile").get_data(as_text=True)
