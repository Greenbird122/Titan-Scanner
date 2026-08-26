"""Titan Shop — the "real architecture" skeleton lab.

A deliberately-realistic mini e-commerce application (auth + catalog + cart +
payments + reviews) that mirrors the shape of a real production codebase, so
red team training exercises actual application architecture instead of bare
textbook routes. Every route carries a realistic bug planted on purpose:

  auth      POST /shop/register          mass assignment (role from client input)
            POST /shop/login             session fixation (no rotation)
            POST /shop/reset             deterministic, leaked reset token
            GET  /shop/admin             broken function-level authz
  catalog   GET  /shop/products          SQLi in the search filter (string concat)
  reviews   POST /shop/product/<id>/review   stored XSS (unescaped render)
  orders    POST /shop/checkout          client-supplied total (price tampering)
            GET  /shop/order/<id>        BOLA (no ownership check)
  payments  POST /shop/pay               plaintext PAN stored + echoed
            GET  /shop/payments          all users' cards (data exposure)
            POST /shop/refund/<id>       BOLA + client-supplied amount
            POST /shop/webhook/payment   unsigned webhook (forged confirmation)

State lives in an in-memory SQLite database (a single shared connection, as
many simple production apps do) seeded with users, products, orders and cards.
POST /shop/reseed (and the global /lab-reset) re-seed so batches and tests
stay hermetic. Registered as a blueprint by local_lab/app.py.
"""

import hashlib
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

from flask import Blueprint, jsonify, make_response, request

shop_bp = Blueprint("shop", __name__, url_prefix="/shop")

_LOCK = threading.Lock()
_CONN = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _md5(value: str) -> str:
    # Legacy accounts: passwords stored as unsalted MD5 (realistic older app).
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def _db() -> sqlite3.Connection:
    global _CONN
    if _CONN is None:
        _CONN = sqlite3.connect(":memory:", check_same_thread=False)
        _CONN.row_factory = sqlite3.Row
    return _CONN


_SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT
);
CREATE TABLE IF NOT EXISTS products(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  price_cents INTEGER NOT NULL,
  stock INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS orders(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  total_cents INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS order_items(
  order_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  qty INTEGER NOT NULL,
  unit_price_cents INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS payments(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  card_number TEXT NOT NULL,
  card_last4 TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'captured',
  provider_ref TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reviews(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL,
  user_id INTEGER,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS reset_tokens(
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
"""


def reseed() -> None:
    """Drop + rebuild every table with a deterministic seed (hermetic runs)."""
    with _LOCK:
        db = _db()
        for table in ("reset_tokens", "reviews", "payments", "order_items",
                      "orders", "sessions", "products", "users"):
            db.execute(f"DROP TABLE IF EXISTS {table}")
        db.executescript(_SCHEMA)
        now = _now()
        users = [
            (1, "admin", _md5("admin123"), "admin", now),
            (2, "alice", _md5("alice123"), "user", now),
            (3, "bob", _md5("bob123"), "user", now),
            (4, "guest", _md5("guest123"), "user", now),
        ]
        db.executemany(
            "INSERT INTO users(id, username, password_hash, role, created_at) VALUES (?,?,?,?,?)",
            users)
        products = [
            (1, "Bespoke Titan Widget", "premium", 499900, 12),
            (2, "USB-C Power Bank", "accessories", 2999, 200),
            (3, "Titan T-Shirt", "apparel", 1999, 50),
            (4, "Enterprise License", "premium", 999900, 3),
        ]
        db.executemany(
            "INSERT INTO products(id, name, category, price_cents, stock) VALUES (?,?,?,?,?)",
            products)
        # Order 1 belongs to bob, order 2 to alice — the cross-user read pair.
        orders = [
            (1, 3, 499900, "pending", "", now),
            (2, 2, 2999, "paid", "", now),
        ]
        db.executemany(
            "INSERT INTO orders(id, user_id, total_cents, status, note, created_at) VALUES (?,?,?,?,?,?)",
            orders)
        db.executemany(
            "INSERT INTO order_items(order_id, product_id, qty, unit_price_cents) VALUES (?,?,?,?)",
            [(1, 1, 1, 499900), (2, 2, 1, 2999)])
        # Plaintext PANs stored verbatim — the PCI violation red must find.
        payments = [
            (1, 1, 3, "4111-1111-1111-1111", "1111", 499900, "captured",
             "tok_test_bob", now),
            (2, 2, 2, "5500-0000-0000-0004", "0004", 2999, "captured",
             "tok_test_alice", now),
        ]
        db.executemany(
            "INSERT INTO payments(id, order_id, user_id, card_number, card_last4, "
            "amount_cents, status, provider_ref, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            payments)
        db.commit()


reseed()  # seed at import so the lab always has a working store


# -- helpers ---------------------------------------------------------------
def _require_user():
    """Resolve the sid cookie to a user record (or None)."""
    token = request.cookies.get("sid", "")
    if not token:
        return None
    with _LOCK:
        row = _db().execute(
            "SELECT u.id, u.username, u.role FROM sessions s "
            "JOIN users u ON u.id = s.user_id WHERE s.token = ?",
            (token,)).fetchone()
    return dict(row) if row else None


def _json_or_form():
    return request.get_json(silent=True) or request.form


# -- auth ------------------------------------------------------------------
@shop_bp.route("/register", methods=["POST"])
def register():
    data = _json_or_form()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    # Legacy accounts: passwords stored as unsalted MD5.
    rec = {"username": username, "password_hash": _md5(password),
           "role": "user", "created_at": _now()}
    # Mass assignment: every OTHER client-supplied field is written straight
    # into the record — including `role`, so anyone can self-register as admin.
    rec.update({k: v for k, v in data.items()
                if k not in ("username", "password", "password_hash")})
    with _LOCK:
        _db().execute(
            "INSERT OR REPLACE INTO users(username, password_hash, role, created_at) "
            "VALUES (?,?,?,?)",
            (rec["username"], rec["password_hash"], rec["role"], rec["created_at"]))
        _db().commit()
    return jsonify({"created": True,
                    "user": {"username": rec["username"], "role": rec["role"]}})


@shop_bp.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    with _LOCK:
        row = _db().execute(
            "SELECT id, username, role FROM users "
            "WHERE username = ? AND password_hash = ?",
            (username, _md5(password))).fetchone()
    if not row:
        return jsonify({"error": "invalid credentials"}), 401
    # Session fixation: an attacker-supplied sid cookie is REUSED verbatim
    # instead of being rotated on login — whatever value the client sent
    # becomes a valid, bound session token.
    token = request.cookies.get("sid") or ("s-" + _md5(f"{username}:{row[0]}:lab")[:24])
    with _LOCK:
        _db().execute(
            "INSERT OR REPLACE INTO sessions(token, user_id, created_at) VALUES (?,?,?)",
            (token, row[0], _now()))
        _db().commit()
    resp = make_response(jsonify({"session": token, "user": username}))
    resp.set_cookie("sid", token)
    return resp


@shop_bp.route("/logout", methods=["POST"])
def logout():
    token = request.cookies.get("sid", "")
    if token:
        with _LOCK:
            _db().execute("DELETE FROM sessions WHERE token = ?", (token,))
            _db().commit()
    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie("sid")
    return resp


@shop_bp.route("/account")
def account():
    user = _require_user()
    if not user:
        return jsonify({"error": "login required"}), 401
    return jsonify({"user": user, "account": {
        "email": f"{user['username']}@shop.local",
        "rewards_balance": 42,
    }})


@shop_bp.route("/admin")
def admin_panel():
    # Function-level authz relies purely on the role stored in the session —
    # which an attacker controls the moment mass assignment creates an admin.
    user = _require_user()
    if not user:
        return "TITAN-SHOP-ADMIN-GATED login required", 401
    if user["role"] != "admin":
        return "TITAN-SHOP-ADMIN-GATED forbidden", 403
    with _LOCK:
        revenue = _db().execute(
            "SELECT COALESCE(SUM(amount_cents), 0) FROM payments").fetchone()[0]
    return ("TITAN-SHOP-ADMIN-OK panel | total revenue: "
            f"${revenue / 100:.2f} | welcome {user['username']}")


@shop_bp.route("/reset", methods=["POST"])
def reset_password():
    data = _json_or_form()
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"error": "username required"}), 400
    with _LOCK:
        row = _db().execute("SELECT id FROM users WHERE username = ?",
                            (username,)).fetchone()
    if not row:
        return jsonify({"error": "unknown user"}), 404
    # Deterministic + guessable token derived from the username alone, and
    # returned in the response body — a leaked, predictable reset secret.
    token = "tk-" + _md5(username)[:8]
    with _LOCK:
        _db().execute(
            "INSERT OR REPLACE INTO reset_tokens(token, user_id, created_at) VALUES (?,?,?)",
            (token, row[0], _now()))
        _db().commit()
    return jsonify({"ok": True, "token": token})


@shop_bp.route("/reset/confirm", methods=["GET"])
def reset_confirm():
    token = request.args.get("token", "")
    with _LOCK:
        row = _db().execute(
            "SELECT user_id FROM reset_tokens WHERE token = ?", (token,)).fetchone()
    if not row:
        return jsonify({"error": "invalid or expired token"}), 400
    return jsonify({"ok": True, "message": "RESET-OK password updated"})


# -- catalog ----------------------------------------------------------------
@shop_bp.route("/")
def shop_home():
    return ("<html><head><title>Titan Shop</title></head><body>"
            "<h1>Titan Shop</h1>"
            "<p>Your one-stop store for premium widgets.</p>"
            "<ul><li><a href='/shop/products'>Catalog</a></li>"
            "<li><a href='/shop/account'>My account</a></li>"
            "<li><a href='/shop/admin'>Admin</a></li></ul></body></html>")


@shop_bp.route("/products")
def products():
    q = request.args.get("q", "")
    # SQLi: the search filter is built by string concatenation — the classic
    # legacy-catalog bug. A tautology in q returns the entire catalog.
    with _LOCK:
        rows = _db().execute(
            "SELECT id, name, category, price_cents FROM products "
            f"WHERE name LIKE '%{q}%' OR category LIKE '%{q}%'").fetchall()
    cards = "".join(
        f"<li>{r[0]} - {r[1]} ({r[2]}) ${r[3] / 100:.2f}</li>" for r in rows)
    return (f"<html><head><title>Catalog</title></head><body>"
            f"<h1>Catalog</h1><p>search: {q}</p><ul>{cards}</ul></body></html>")


@shop_bp.route("/product/<int:product_id>")
def product_detail(product_id):
    with _LOCK:
        prod = _db().execute(
            "SELECT id, name, category, price_cents, stock FROM products WHERE id = ?",
            (product_id,)).fetchone()
        reviews = _db().execute(
            "SELECT body FROM reviews WHERE product_id = ?", (product_id,)).fetchall()
    if not prod:
        return "product not found", 404
    # Stored XSS: review bodies are rendered unescaped.
    review_html = "".join(f"<div class='review'>{r[0]}</div>" for r in reviews)
    return (f"<html><head><title>{prod[1]}</title></head><body>"
            f"<h1>{prod[1]}</h1><p>{prod[3] / 100:.2f} - stock {prod[4]}</p>"
            f"<h2>Reviews</h2>{review_html}"
            f"<form action='/shop/product/{prod[0]}/review' method='POST'>"
            f"<input name='body'><button>Post review</button></form>"
            "</body></html>")


@shop_bp.route("/product/<int:product_id>/review", methods=["POST"])
def add_review(product_id):
    body = _json_or_form().get("body", "")
    if not body:
        return jsonify({"error": "review body required"}), 400
    user = _require_user()
    with _LOCK:
        _db().execute(
            "INSERT INTO reviews(product_id, user_id, body, created_at) VALUES (?,?,?,?)",
            (product_id, user["id"] if user else None, body, _now()))
        _db().commit()
    return jsonify({"stored": True, "product_id": product_id})


# -- cart / checkout --------------------------------------------------------
@shop_bp.route("/cart/add", methods=["POST"])
def cart_add():
    data = _json_or_form()
    try:
        product_id = int(data.get("product_id", 0))
        qty = int(data.get("qty", 1))
    except (TypeError, ValueError):
        return jsonify({"error": "bad product_id/qty"}), 400
    with _LOCK:
        prod = _db().execute(
            "SELECT id, name, price_cents FROM products WHERE id = ?",
            (product_id,)).fetchone()
    if not prod:
        return jsonify({"error": "unknown product"}), 404
    return jsonify({"added": True, "product": prod[1],
                    "unit_price_cents": prod[2], "qty": qty})


@shop_bp.route("/checkout", methods=["POST"])
def checkout():
    user = _require_user()
    if not user:
        return jsonify({"error": "login required"}), 401
    data = _json_or_form()
    try:
        total_cents = int(data.get("total_cents", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "bad total_cents"}), 400
    note = data.get("note", "")
    # Price tampering: the total is TRUSTED from the client instead of being
    # recomputed from the server-side cart — charge what the payload says.
    with _LOCK:
        cur = _db().execute(
            "INSERT INTO orders(user_id, total_cents, status, note, created_at) "
            "VALUES (?,?,?,?,?)",
            (user["id"], total_cents, "pending", note, _now()))
        order_id = cur.lastrowid
        _db().commit()
    return jsonify({"order_id": order_id, "total_cents": total_cents,
                    "status": "pending", "note": note, "charged": total_cents})


# -- orders / payments ------------------------------------------------------
@shop_bp.route("/order/<int:order_id>")
def order_detail(order_id):
    user = _require_user()
    if not user:
        return jsonify({"error": "login required"}), 401
    with _LOCK:
        order = _db().execute(
            "SELECT id, user_id, total_cents, status, note, created_at "
            "FROM orders WHERE id = ?", (order_id,)).fetchone()
        if not order:
            return jsonify({"error": "order not found"}), 404
        items = _db().execute(
            "SELECT oi.qty, oi.unit_price_cents, p.name FROM order_items oi "
            "JOIN products p ON p.id = oi.product_id WHERE oi.order_id = ?",
            (order_id,)).fetchall()
        payment = _db().execute(
            "SELECT card_number, card_last4, amount_cents, status, provider_ref "
            "FROM payments WHERE order_id = ?", (order_id,)).fetchone()
    # BOLA: NO ownership check — any authenticated user reads any order,
    # including the stored payment card of whoever paid for it.
    return jsonify({
        "order": {"id": order[0], "user_id": order[1], "total_cents": order[2],
                  "status": order[3], "note": order[4], "created_at": order[5]},
        "items": [{"name": i[2], "qty": i[0], "unit_price_cents": i[1]} for i in items],
        "payment": ({"card_number": payment[0], "card_last4": payment[1],
                     "amount_cents": payment[2], "status": payment[3],
                     "provider_ref": payment[4]} if payment else None),
    })


@shop_bp.route("/pay", methods=["POST"])
def pay():
    user = _require_user()
    if not user:
        return jsonify({"error": "login required"}), 401
    data = _json_or_form()
    try:
        order_id = int(data.get("order_id", 0))
        amount_cents = int(data.get("amount_cents", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "bad order_id/amount"}), 400
    card = data.get("card_number", "")
    if len(card) < 4:
        return jsonify({"error": "card_number required"}), 400
    # Plaintext PAN stored verbatim (legacy payment table) and echoed back
    # for the "receipt" — a PCI-level exposure in two channels at once.
    ref = "tok_" + uuid.uuid4().hex[:12]
    with _LOCK:
        _db().execute(
            "INSERT INTO payments(order_id, user_id, card_number, card_last4, "
            "amount_cents, status, provider_ref, created_at) VALUES (?,?,?,?,?,?,?,?)",
            (order_id, user["id"], card, card[-4:], amount_cents, "captured",
             ref, _now()))
        _db().commit()
    return jsonify({"paid": True, "order_id": order_id, "amount_cents": amount_cents,
                    "card_number": card, "last4": card[-4:], "provider_ref": ref})


@shop_bp.route("/payments")
def payments():
    user = _require_user()
    if not user:
        return jsonify({"error": "login required"}), 401
    # Data exposure: no per-user filter — every stored card, full PAN, for
    # any authenticated account.
    with _LOCK:
        rows = _db().execute(
            "SELECT id, order_id, user_id, card_number, card_last4, amount_cents, "
            "status FROM payments").fetchall()
    return jsonify({"payments": [
        {"id": r[0], "order_id": r[1], "user_id": r[2], "card_number": r[3],
         "card_last4": r[4], "amount_cents": r[5], "status": r[6]} for r in rows]})


@shop_bp.route("/refund/<int:order_id>", methods=["POST"])
def refund(order_id):
    user = _require_user()
    if not user:
        return jsonify({"error": "login required"}), 401
    data = _json_or_form()
    try:
        amount_cents = int(data.get("amount_cents", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "bad amount_cents"}), 400
    # BOLA + amount trust: no ownership check, and the refund amount is taken
    # from the caller — refund more than was ever paid.
    with _LOCK:
        order = _db().execute(
            "SELECT id, total_cents, status FROM orders WHERE id = ?",
            (order_id,)).fetchone()
    if not order:
        return jsonify({"error": "order not found"}), 404
    with _LOCK:
        _db().execute("UPDATE orders SET status = 'refunded' WHERE id = ?",
                      (order_id,))
        _db().commit()
    return jsonify({"refunded": True, "order_id": order_id,
                    "amount_cents": amount_cents, "prior_total": order[1]})


@shop_bp.route("/webhook/payment", methods=["POST"])
def webhook_payment():
    data = _json_or_form()
    try:
        order_id = int(data.get("order_id", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "bad order_id"}), 400
    status = data.get("status", "")
    if not order_id or not status:
        return jsonify({"error": "order_id and status required"}), 400
    # Unsigned webhook: the payment provider's callback is trusted with NO
    # signature or shared-secret verification — anyone can mark any order
    # paid (or refunded) by POSTing a crafted body.
    with _LOCK:
        _db().execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_id))
        _db().commit()
    return jsonify({"ok": True, "order_id": order_id, "status": status})


@shop_bp.route("/reseed", methods=["POST"])
def reseed_route():
    reseed()
    return jsonify({"status": "reseeded"})
