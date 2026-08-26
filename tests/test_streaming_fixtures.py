"""Tests for the STREAM-PEAK streaming fixtures (SCN-022/023/024).

The whole point of these fixtures: the red side can force a change (premium
unlock, admin panel, edge bypass) using only what the site itself ships —
the salt in the player JS, the unauthenticated signing oracle, and the
client-derivable challenge secret.
"""
import sys
from pathlib import Path

import pytest

LAB_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LAB_ROOT))

from local_lab import app as lab  # noqa: E402
from local_lab import streaming as st  # noqa: E402


@pytest.fixture()
def client():
    c = lab.app.test_client()
    c.post("/lab-reset")
    return c


# --- SCN-022: signed-URL token forgery (premium unlock) ---------------------
def test_stream_index_ships_the_salt(client):
    """The flaw: the player bundle leaks the signing salt."""
    body = client.get("/stream").get_data(as_text=True)
    assert st.STREAM_SALT in body
    assert "/stream/sign" in body  # the debug hint pointing at the oracle


def test_play_locked_without_token(client):
    r = client.get("/stream/play/3")
    assert r.status_code == 403
    assert "STREAM-LOCKED" in r.get_data(as_text=True)
    # The lock response itself names the signing oracle (second leak).
    assert "/stream/sign" in r.headers.get("X-Titan-Hint", "")


def test_play_locked_with_wrong_token(client):
    r = client.get("/stream/play/3", query_string={"token": "deadbeef"})
    assert r.status_code == 403
    assert "STREAM-LOCKED" in r.get_data(as_text=True)


def test_sign_oracle_mints_any_token(client):
    r = client.get("/stream/sign", query_string={"key": "3"})
    assert r.status_code == 200
    assert r.get_json()["token"] == st.stream_token("3")


def test_forged_token_unlocks_premium(client):
    token = st.stream_token("3")
    r = client.get("/stream/play/3", query_string={"token": token})
    assert r.status_code == 200
    body = r.get_json()
    assert body["stream"] == "STREAM-OK"
    assert body["title"] == "leaked-bloopers"
    assert body["tier"] == "premium"


# --- SCN-023: forged-token admin escalation ----------------------------------
def test_admin_gated_without_token(client):
    r = client.get("/stream/admin")
    assert r.status_code == 403
    assert "STREAM-ADMIN-GATED" in r.get_data(as_text=True)


def test_admin_gated_with_wrong_token(client):
    r = client.get("/stream/admin", query_string={"token": "deadbeef"})
    assert r.status_code == 403


def test_forged_admin_token_reaches_panel(client):
    token = st.stream_token(st.STREAM_ADMIN_KEY)
    r = client.get("/stream/admin", query_string={"token": token})
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "STREAM-ADMIN-OK" in body
    assert st.ADMIN_FLAG in body


# --- SCN-024: anti-scraper challenge secret shipped to client ----------------
def test_edge_403_with_challenge_header(client):
    r = client.get("/stream/cdn/edge")
    assert r.status_code == 403
    assert r.headers.get("X-Titan-Challenge") == st.edge_challenge()


def test_edge_bypass_with_client_computed_cookie(client):
    # The secret ships in the player JS; the answer is one read away.
    challenge = st.edge_challenge()
    client.set_cookie("titan_chl", challenge, domain="localhost")
    r = client.get("/stream/cdn/edge")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "EDGE-OK" in body
    assert st.EDGE_FLAG in body


def test_edge_wrong_cookie_still_blocked(client):
    r = client.get("/stream/cdn/edge", headers={"Cookie": "titan_chl=wrong"})
    assert r.status_code == 403
