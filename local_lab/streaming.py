"""Streaming-site fixtures for the purple batch rounds (titan-lab private lab).

A token-gated streaming platform (the "STREAM-PEAK" shape) with an
intentionally broken signed-URL scheme so the red side can actually force a
change (premium unlock / admin panel / edge bypass) on its own:

  * token  = md5(f"{key}:titan_stream_salt")        -- MD5, static salt
  * the salt ships inside the player page's JS       -- client-visible secret
  * GET /stream/sign?key=<any> mints a valid token   -- unauthenticated
    signing oracle (no auth, no expiry, no URL binding)
  * premium playback and the admin panel both trust
    the forged tokens                                -- gate bypass == change

Plus an anti-scraper edge: /stream/cdn/edge returns a 403 challenge whose
deterministic answer is derivable from a secret that ships in the same JS
bundle -- a naive bot-wall that a scraper can solve in one read.

SCN-022  signed-URL token forgery (premium unlock)
SCN-023  forged-token admin escalation (streaming panel)
SCN-024  anti-scraper challenge secret shipped to client
"""

import hashlib

from flask import Blueprint, jsonify, make_response, request

streaming_bp = Blueprint("streaming", __name__)

STREAM_SALT = "titan_stream_salt"
STREAM_ADMIN_KEY = "admin"
STREAM_CHALLENGE_SECRET = "titan-anti-scraper-challenge"

VIDEOS = {
    1: {"title": "premiere-episode", "tier": "free"},
    2: {"title": "director-cut", "tier": "premium"},
    3: {"title": "leaked-bloopers", "tier": "premium"},
}

ADMIN_FLAG = "flag{TITAN-stream-token-forgery-3301}"
EDGE_FLAG = "flag{TITAN-edge-challenge-bypass-3301}"


def stream_token(key: str) -> str:
    """The 'signed URL' scheme. MD5(key:salt) -- weak by design."""
    return hashlib.md5(f"{key}:{STREAM_SALT}".encode()).hexdigest()


def edge_challenge() -> str:
    """The anti-scraper challenge value. Deterministic -- the flaw."""
    return hashlib.md5(STREAM_CHALLENGE_SECRET.encode()).hexdigest()


@streaming_bp.route("/stream")
def stream_index():
    """The player landing page.

    Leaks the whole signing scheme in its JS bundle -- a 'debug' comment
    pointing at the signing oracle and both secrets sitting in plain sight,
    exactly like a real player bundle that shipped its signing config.
    """
    cards = []
    for vid, meta in VIDEOS.items():
        lock = "" if meta["tier"] == "free" else ' <span class="lock">PREMIUM</span>'
        cards.append(f"<li>EP-{vid:02d} {meta['title']}{lock} "
                     f"<a href='/stream/play/{vid}'>watch</a></li>")
    return (
        "<html><head><title>STREAM-PEAK</title></head><body>"
        "<h1>STREAM-PEAK</h1><p>the home of everything, allegedly</p>"
        f"<ul>{''.join(cards)}</ul>"
        "<!-- debug: signing oracle at /stream/sign?key=<id> (no auth) -->"
        "<script>"
        "/* player signing config */ "
        "var TITAN_SIGNER_SALT=\"titan_stream_salt\"; "
        "var TITAN_EDGE_SECRET=\"titan-anti-scraper-challenge\";"
        "</script>"
        "</body></html>"
    )


@streaming_bp.route("/stream/play/<int:vid>")
def stream_play(vid):
    """Token-gated playback endpoint.

    Every video is 'signed' with md5(vid:salt); a missing or wrong token is a
    403. The debug hint header on the lock response is the second leak -- it
    names the signing oracle so any scraper can mint its own token.
    """
    meta = VIDEOS.get(vid)
    if not meta:
        return "STREAM-404 no such video", 404
    token = request.args.get("token", "")
    if token == stream_token(str(vid)):
        return jsonify({
            "stream": "STREAM-OK",
            "title": meta["title"],
            "tier": meta["tier"],
            "url": f"/stream/play/{vid}?token={token}",
        })
    resp = make_response("STREAM-LOCKED 403 this video needs a valid token", 403)
    resp.headers["X-Titan-Hint"] = "sign@/stream/sign?key=<id>"
    return resp


@streaming_bp.route("/stream/sign")
def stream_sign():
    """The signing oracle -- THE FLAW.

    Unauthenticated, mints a valid token for any key. In a real CDN this is
    the private signing key exposed behind a debug route. Red uses it to forge
    playback tokens and the admin token alike.
    """
    key = request.args.get("key", "")
    if not key:
        return jsonify({"error": "provide ?key="}), 400
    return jsonify({"key": key, "token": stream_token(key)})


@streaming_bp.route("/stream/admin")
def stream_admin():
    """Admin panel gated by a forged token (key='admin')."""
    token = request.args.get("token", "")
    if token == stream_token(STREAM_ADMIN_KEY):
        return f"STREAM-ADMIN-OK {ADMIN_FLAG}"
    return "STREAM-ADMIN-GATED 403", 403


@streaming_bp.route("/stream/cdn/edge")
def stream_edge():
    """Anti-scraper edge.

    403 + challenge header unless the client echoes the challenge back as the
    `titan_chl` cookie. The deterministic answer is derivable from the secret
    leaked in the player JS bundle -- a bot-wall a scraper solves in one read.
    """
    ch = edge_challenge()
    if request.cookies.get("titan_chl", "") == ch:
        return f"EDGE-OK {EDGE_FLAG}"
    resp = make_response("EDGE-403 solve the challenge", 403)
    resp.headers["X-Titan-Challenge"] = ch
    return resp
