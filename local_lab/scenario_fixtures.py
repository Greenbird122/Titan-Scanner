"""Scenario fixtures for the purple batch rounds (titan-lab private lab).

Routes that give SCN-003 (puzzle-gated hidden asset), SCN-004 (simulated
defacement integrity break) and SCN-005 (referrer-gated ad redirect) a home in
the lab, so every registry scenario has an executable fixture. Registered as a
blueprint by local_lab/app.py.

Round 2 red sprint adds framework-shaped fixtures for SCN-007 (stored XSS),
SCN-011 (stored SQLi), SCN-010 (token leak channels), SCN-009 (Host-header
cache poisoning) and SCN-013 (server-side prototype pollution) — each shaped
like a real framework surface rather than a bare vulnerable route, and each
with an adversarial variant story.
"""

import base64
import re

from flask import Blueprint, jsonify, make_response, request

scenario_fixtures_bp = Blueprint("scenario_fixtures", __name__)

# --- SCN-003: puzzle-gated hidden asset ------------------------------------
# An admin route only reachable after solving an in-page keyed ciphertext.
# Naive crawlers never find /puzzle/admin (it is unlinked), and even if they
# probe it, access requires the key solved from the ciphertext. The red side
# must discover the route AND recognize the high-entropy gate; the blue side
# must surface hidden assets and flag high-entropy served content.
PUZZLE_PLAIN = "TITAN-PUZZLE-KEY-3301"
PUZZLE_CIPHER = base64.b64encode(
    bytes(b ^ 0x5A for b in PUZZLE_PLAIN.encode("utf-8"))
).decode("ascii")


@scenario_fixtures_bp.route("/puzzle")
def puzzle():
    return (
        "<html><head><title>Titan Puzzle Gate</title></head><body>"
        "<h1>Community puzzle</h1>"
        "<p>Keyed ciphertext: <code>" + PUZZLE_CIPHER + "</code></p>"
        "<p>Hint: base64-decode, xor 0x5A, then utf-8. The answer unlocks "
        "/puzzle/admin?key=...</p></body></html>"
    )


@scenario_fixtures_bp.route("/puzzle/admin")
def puzzle_admin():
    if request.args.get("key", "") != PUZZLE_PLAIN:
        return "TITANPUZZLE-ADMIN-GATED (solve the ciphertext to enter)", 403
    return "TITANPUZZLE-ADMIN-OK flag{TITAN-puzzle-gate-3301}"


# --- SCN-004: simulated defacement integrity break -------------------------
# A monitored page whose body can be replaced between scans. The red side
# "defaces" it via POST; the blue side must detect the integrity break by
# diffing the monitored page against its baseline.
_INTEGRITY_DEFAULT = (
    "<html><head><title>Titan Monitored Page</title></head>"
    "<body><h1>Titan Health Hub - official</h1><p>status: OK</p></body></html>"
)
_INTEGRITY_DEFACED = (
    "<html><head><title>DEFACED</title></head>"
    "<body><h1>DEFACED-BY-TITAN - you have been pwned</h1>"
    "<p>this page is no longer under operator control</p></body></html>"
)
_INTEGRITY_STATE = {"html": _INTEGRITY_DEFAULT, "defacements": 0}


@scenario_fixtures_bp.route("/integrity")
def integrity():
    return _INTEGRITY_STATE["html"]


@scenario_fixtures_bp.route("/integrity/deface", methods=["POST"])
def integrity_deface():
    _INTEGRITY_STATE["html"] = _INTEGRITY_DEFACED
    _INTEGRITY_STATE["defacements"] += 1
    return jsonify({"defacements": _INTEGRITY_STATE["defacements"]})


@scenario_fixtures_bp.route("/integrity/restore", methods=["POST"])
def integrity_restore():
    _INTEGRITY_STATE["html"] = _INTEGRITY_DEFAULT
    return jsonify({"status": "restored"})


# --- SCN-005: referrer-gated ad redirect -----------------------------------
# A redirect that only fires when a specific Referer is present — invisible to
# direct crawls, visible in real browser sessions. The red side must send the
# gate condition; the blue side must surface the gated hop.
@scenario_fixtures_bp.route("/redirect-gated")
def redirect_gated():
    ref = request.headers.get("Referer", "")
    if "google.com" in ref:
        return "", 302, {"Location": "https://evil.example/steal?src=ad"}
    return (
        "<html><head><title>Gated page</title></head>"
        "<body><h1>Gated page</h1><p>referrer not recognized</p></body></html>"
    )


# --- Round 2 red sprint fixtures (framework-shaped, adversarial) ------------
# Five new scenarios that target the public engine's blind spots, each shaped
# like a real framework surface rather than a bare vulnerable route:
#   SCN-007  guestbook/blog second-order stored XSS
#   SCN-011  auth registration second-order stored SQLi
#   SCN-010  ops /reset leaking the token across response channels
#   SCN-009  CDN /search reflecting the Host header into a cached body
#   SCN-013  API profile update with an unpinned JSON deep-merge

_GUESTBOOK: list = []
_USERS: list = []
_KNOWN_USERS = {"admin", "alice", "bob"}
_PROFILE_STATE = {"role": "user", "isAdmin": False}
RESET_TOKEN = "tk-5f4dcc3b5aa765d61d8327deb882cf99"


@scenario_fixtures_bp.route("/lab-reset", methods=["POST"])
def lab_reset():
    """Clear every stateful Round 2 fixture so tests/batches are hermetic."""
    _GUESTBOOK.clear()
    _USERS.clear()
    _PROFILE_STATE.update({"role": "user", "isAdmin": False})
    _INTEGRITY_STATE["html"] = _INTEGRITY_DEFAULT
    # Also re-seed the Titan Shop (auth/payment/catalog) database.
    try:
        from . import shop as _shop_mod
    except ImportError:  # imported standalone (python local_lab/app.py)
        import shop as _shop_mod
    _shop_mod.reseed()
    return jsonify({"status": "reset"})


# --- SCN-007: stored XSS (guestbook, blog shape) -----------------------------
@scenario_fixtures_bp.route("/guestbook")
def guestbook():
    rows = "".join(f"<div class='entry'>{e}</div>" for e in _GUESTBOOK)
    return f"<html><head><title>Guestbook</title></head><body><h1>Guestbook</h1>{rows}</body></html>"


@scenario_fixtures_bp.route("/guestbook/add", methods=["POST"])
def guestbook_add():
    entry = request.form.get("entry", "")
    if entry:
        _GUESTBOOK.append(entry)
    # Second-order: the stored value is echoed (storage confirmed) AND rendered
    # later by /guestbook without escaping.
    return f"Stored: {entry}"


# --- SCN-011: stored SQLi (registration -> login, auth shape) ----------------
@scenario_fixtures_bp.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    if username:
        _USERS.append(username)
    return f"registered {len(_USERS)} user(s)"


@scenario_fixtures_bp.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    if username not in _USERS:
        return "user not registered"
    # Vulnerable second-order lookup: the STORED username is interpolated into
    # the query. A tautology in the stored value matches; a benign unknown
    # stored value does not (boolean differential).
    if "--" in username or re.search(r"['\"]?\s+or\s+", username, re.I):
        return "LOGIN-OK user found"
    if username in _KNOWN_USERS:
        return "LOGIN-OK user found"
    return "user not found"


# --- SCN-010: reset-token leak across response channels (ops shape) ----------
@scenario_fixtures_bp.route("/reset")
def reset():
    mode = request.args.get("mode", "header")
    if mode == "body":
        return f"<html><body>reset token: {RESET_TOKEN}</body></html>"
    if mode == "cookie":
        resp = make_response("reset requested")
        resp.set_cookie("debug_token", RESET_TOKEN)
        return resp
    resp = make_response("reset requested")
    resp.headers["X-Debug-Token"] = RESET_TOKEN
    return resp


# --- SCN-009: Host-header cache poisoning (CDN shape) ------------------------
@scenario_fixtures_bp.route("/search")
def search():
    q = request.args.get("q", "")
    host = request.headers.get("X-Forwarded-Host", "") or request.host
    body = (
        "<html><body><h1>Search</h1>"
        f"<p>You searched: {q}</p><p>cached host: {host}</p></body></html>"
    )
    resp = make_response(body)
    resp.headers["X-Cache"] = "HIT"
    resp.headers["Age"] = "5"
    resp.headers["Via"] = "1.1 titan-cdn"
    resp.headers["Cache-Control"] = "public, max-age=60"
    return resp


# --- SCN-013: server-side prototype pollution (API update shape) -------------
def _deep_merge(base, patch):
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v


@scenario_fixtures_bp.route("/api/profile")
def api_profile():
    if _PROFILE_STATE.get("isAdmin"):
        return jsonify({**_PROFILE_STATE, "note": "ADMIN-ESCALATION"})
    return jsonify(_PROFILE_STATE)


@scenario_fixtures_bp.route("/api/profile/update", methods=["POST"])
def api_profile_update():
    patch = request.get_json(silent=True) or {}
    # Vulnerable unpinned deep merge: a __proto__ / constructor.prototype key
    # flips the profile's privilege (simulated server-side pollution).
    if "__proto__" in patch and isinstance(patch["__proto__"], dict):
        _PROFILE_STATE["isAdmin"] = bool(patch["__proto__"].get("isAdmin", True))
    if "constructor" in patch and isinstance(patch.get("constructor"), dict):
        proto = patch["constructor"].get("prototype", {})
        if isinstance(proto, dict):
            _PROFILE_STATE["isAdmin"] = bool(proto.get("isAdmin", True))
    _deep_merge(_PROFILE_STATE, patch)
    return jsonify({"updated": True, "profile": _PROFILE_STATE})
