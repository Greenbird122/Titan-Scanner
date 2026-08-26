"""Tests for the Titan Shop skeleton lab fixtures (auth + payment + database).

SCN-014 mass assignment, SCN-015 stored XSS, SCN-016 BOLA, SCN-017 price
tampering, SCN-018 unsigned webhook, SCN-019 plaintext PAN, SCN-020 SQLi,
SCN-021 session fixation + reset-token leak. Each test asserts the fixture's
vulnerable behaviour the way a real scanner would observe it.
"""
import sys
from pathlib import Path

import pytest

LAB_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LAB_ROOT))

from local_lab import app as lab  # noqa: E402


@pytest.fixture()
def client():
    c = lab.app.test_client()
    c.post("/lab-reset")  # re-seeds the shop DB for every test
    return c


# --- SCN-014: register mass assignment ---------------------------------------
def test_register_echoes_client_role(client):
    r = client.post("/shop/register",
                    json={"username": "hax", "password": "x", "role": "admin"})
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert '"role":"admin"' in body  # Flask compact JSON separators


def test_mass_assigned_admin_reaches_panel(client):
    client.post("/shop/register",
                json={"username": "hax", "password": "x", "role": "admin"})
    client.post("/shop/login", data={"username": "hax", "password": "x"})
    r = client.get("/shop/admin")
    assert r.status_code == 200
    assert "TITAN-SHOP-ADMIN-OK" in r.get_data(as_text=True)


def test_plain_user_forbidden_from_admin(client):
    client.post("/shop/register", json={"username": "u", "password": "x"})
    client.post("/shop/login", data={"username": "u", "password": "x"})
    r = client.get("/shop/admin")
    assert r.status_code == 403


# --- SCN-015: stored XSS via review ------------------------------------------
def test_review_stored_and_rendered_unescaped(client):
    client.post("/shop/product/1/review",
                data={"body": "<script>alert(1)</script>"})
    body = client.get("/shop/product/1").get_data(as_text=True)
    assert "<script>alert(1)</script>" in body


def test_review_clean_after_reset(client):
    assert "<script>" not in client.get("/shop/product/1").get_data(as_text=True)


# --- SCN-016: cross-user order read (BOLA) ------------------------------------
def test_alice_reads_bobs_order(client):
    client.post("/shop/login", data={"username": "alice", "password": "alice123"})
    body = client.get("/shop/order/1").get_data(as_text=True)
    assert "Bespoke Titan Widget" in body  # bob's product, read by alice


def test_order_requires_login(client):
    r = client.get("/shop/order/1")
    assert r.status_code == 401


# --- SCN-017: checkout price tampering ----------------------------------------
def test_checkout_trusts_client_total(client):
    client.post("/shop/login", data={"username": "alice", "password": "alice123"})
    r = client.post("/shop/checkout",
                    json={"total_cents": 1, "note": "TITAN-PENNY-CHARGE"})
    assert r.status_code == 200
    assert r.get_json()["total_cents"] == 1
    assert r.get_json()["note"] == "TITAN-PENNY-CHARGE"


def test_checkout_requires_login(client):
    assert client.post("/shop/checkout", json={"total_cents": 1}).status_code == 401


# --- SCN-018: unsigned payment webhook ----------------------------------------
def test_forged_webhook_marks_order_paid(client):
    r = client.post("/shop/webhook/payment",
                    json={"order_id": 1, "status": "paid"})
    assert r.status_code == 200
    assert r.get_json()["status"] == "paid"
    assert r.get_json()["ok"] is True


def test_webhook_rejects_missing_fields(client):
    assert client.post("/shop/webhook/payment", json={}).status_code == 400


# --- SCN-019: plaintext PAN exposure ------------------------------------------
def test_payments_list_leaks_every_card(client):
    client.post("/shop/login", data={"username": "alice", "password": "alice123"})
    body = client.get("/shop/payments").get_data(as_text=True)
    assert "4111-1111-1111-1111" in body  # bob's card, seen by alice


def test_order_detail_echoes_full_pan(client):
    client.post("/shop/login", data={"username": "alice", "password": "alice123"})
    body = client.get("/shop/order/1").get_data(as_text=True)
    assert "4111-1111-1111-1111" in body


def test_pay_echoes_card_number(client):
    client.post("/shop/login", data={"username": "alice", "password": "alice123"})
    r = client.post("/shop/pay", json={"order_id": 2, "amount_cents": 2999,
                                       "card_number": "4242-4242-4242-4242"})
    assert r.get_json()["card_number"] == "4242-4242-4242-4242"


# --- SCN-020: SQLi in product search ------------------------------------------
def test_products_tautology_returns_catalog(client):
    r = client.get("/shop/products?q=x' OR 1=1 --")
    assert "Bespoke Titan Widget" in r.get_data(as_text=True)


def test_products_clean_baseline_hides_product(client):
    r = client.get("/shop/products?q=zzz")
    assert "Bespoke Titan Widget" not in r.get_data(as_text=True)


# --- SCN-021: session fixation + reset token ----------------------------------
def test_login_reuses_attacker_sid(client):
    # Werkzeug's test client prefers its cookie jar over an explicit
    # Cookie header, so seed the jar exactly as an attacker would.
    client.set_cookie("sid", "attacker_fixed_token")
    r = client.post("/shop/login",
                    data={"username": "alice", "password": "alice123"})
    assert "attacker_fixed_token" in r.get_data(as_text=True)


def test_reset_leaks_deterministic_token(client):
    r = client.post("/shop/reset", data={"username": "alice"})
    body = r.get_data(as_text=True)
    assert '"token":"tk-' in body  # deterministic + leaked
