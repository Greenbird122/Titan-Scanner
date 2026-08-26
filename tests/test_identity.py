"""Track B — stateful identity testing (BOLA, mass assignment, JWT, session
fixation) and Track D flow typing.

Each test runs the real detector against a deterministic two-role mini Flask
app (alice owns records, bob is the attacker) through the fake
playwright-style context. Assertions enforce the *cross-identity oracle*:
a finding only fires when identity B receives identity A's unique content
(BOLA), the injected privilege field is honored (mass assignment), a forged
token is accepted (JWT), or the attacker-chosen session survives login
(fixation). Never on mere body diffs.
"""

import asyncio
import json
import secrets
import sys
from pathlib import Path
from urllib.parse import urlparse

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from flask import Flask, Response, jsonify, make_response, request

from titan.core.models import AttackType, Finding, Severity
from titan.core.sessions import Identity, SessionPool
from titan.verify.flows import apply_flows, infer_flows


# ─── Two-role mini vulnerable lab (deterministic, offline) ───────────────────

mini = Flask(__name__)

RECORDS = {
    "1": {"id": 1, "owner": "alice", "title": "Alice secret plan", "secret": "alice-secret-abc123"},
    "2": {"id": 2, "owner": "bob", "title": "Bob report", "secret": "bob-secret-xyz789"},
}


def _identity():
    return request.headers.get("X-Identity", "")


@mini.route("/api/bola_vuln")
def bola_vuln():
    # VULNERABLE: any authenticated identity can read any record by id.
    if not _identity():
        return jsonify({"error": "unauthorized"}), 401
    rec = RECORDS.get(request.args.get("id", "1"))
    if not rec:
        return jsonify({"error": "not found"}), 404
    return jsonify(rec)


@mini.route("/api/bola_secure")
def bola_secure():
    # SECURE: only the record owner may read it.
    user = _identity()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    rec = RECORDS.get(request.args.get("id", "1"))
    if not rec or rec["owner"] != user:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(rec)


@mini.route("/api/bola_public")
def bola_public():
    # PUBLIC: returns the SAME record to everyone regardless of id — the
    # attacker's cross request is identical to their own baseline, so no
    # cross-identity differential exists (must NOT fire).
    if not _identity():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(RECORDS["1"])


@mini.route("/api/bola_my")
def bola_my():
    # ID-IGNORING OWNER ENDPOINT: returns the REQUESTER'S OWN record for ANY
    # id. The owner's baseline has unique markers, but the attacker's cross
    # request returns the attacker's own content (cross == own) — this is
    # not cross-tenant access and the cross!=own guard must reject it.
    user = _identity()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    own = next((r for r in RECORDS.values() if r["owner"] == user), None)
    if not own:
        return jsonify({"error": "forbidden"}), 403
    return jsonify(own)


@mini.route("/api/bola_same_foreign")
def bola_same_foreign():
    # SHARED-RECORD ENDPOINT: alice and bob BOTH legitimately own id=1 (a
    # shared document). The cross request returns owner content that ALSO
    # matches the attacker's own baseline — no exclusive marker exists, so
    # the markers-presence gate (not just cross!=own) must reject it.
    if not _identity():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(RECORDS["1"])


@mini.route("/api/user_update", methods=["POST"])
def user_update():
    # VULNERABLE: honors an injected privilege field.
    data = request.get_json(silent=True) or dict(request.form)
    if "role" in data:
        return jsonify({"name": data.get("name", "u"), "role": data["role"]})
    return jsonify({"name": data.get("name", "u"), "role": "user"})


@mini.route("/api/user_update_secure", methods=["POST"])
def user_update_secure():
    # SECURE: ignores privilege fields.
    data = request.get_json(silent=True) or dict(request.form)
    return jsonify({"name": data.get("name", "u"), "role": "user"})


@mini.route("/api/user_update_noisy", methods=["POST"])
def user_update_noisy():
    # NOISY: echoes the submitted role field BUT the page ALWAYS carries
    # "admin" content (admin_count in the template). The injected value
    # therefore appears in BOTH baseline and test bodies — its presence
    # cannot prove the server honored the assignment. Only the
    # value-not-in-baseline guard rejects this; the JSON-reflection gate
    # alone (role: "admin" in test) would otherwise self-verify.
    data = request.get_json(silent=True) or dict(request.form)
    return jsonify({
        "name": data.get("name", "u"),
        "role": data.get("role", "user"),
        "admin_count": 3,
    })


@mini.route("/api/user_update_html", methods=["POST"])
def user_update_html():
    # HTML ECHO: reflects the injected field value into a form but as raw
    # HTML — there is no JSON field:value pairing proving the server HONORED
    # the assignment. The JSON-reflection guard must reject it.
    data = request.get_json(silent=True) or dict(request.form)
    role = data.get("role", "")
    return Response(
        f"<form><input name='name' value='{data.get('name', 'u')}'>"
        f"<input name='role' value='{role}'></form>",
        mimetype="text/html",
    )


@mini.route("/api/jwt_verify")
def jwt_verify():
    # VULNERABLE: accepts any well-formed token, including alg:none.
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "unauthorized"}), 401
    token = auth[7:]
    try:
        import base64
        header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
    except Exception:
        return jsonify({"error": "bad token"}), 401
    return jsonify({"user": "admin" if header.get("role") == "admin" else "user"})


@mini.route("/api/jwt_secure")
def jwt_secure():
    # SECURE: rejects alg:none (signature required).
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "unauthorized"}), 401
    token = auth[7:]
    parts = token.split(".")
    if len(parts) != 3 or not parts[2]:
        return jsonify({"error": "invalid signature"}), 401
    return jsonify({"user": "alice"})


@mini.route("/api/open")
def api_open():
    # OPEN: answers 200 to anyone, no auth required. Used to prove the JWT
    # detector's anon-gate (it must NOT forge tokens at open endpoints).
    return jsonify({"ok": True})


@mini.route("/api/login_fix", methods=["POST"])
def login_fix():
    # VULNERABLE: keeps the client-provided session id after login.
    fixed = request.cookies.get("session")
    resp = make_response("logged in")
    if fixed:
        resp.set_cookie("session", fixed)
    else:
        resp.set_cookie("session", secrets.token_hex(8))
    return resp


@mini.route("/api/login_secure", methods=["POST"])
def login_secure():
    # SECURE: always issues a fresh session id.
    resp = make_response("logged in")
    resp.set_cookie("session", secrets.token_hex(8))
    return resp


# ─── Fake playwright-style context (with identity headers) ───────────────────


class FakeResponse:
    def __init__(self, status_code, body_bytes, headers, url):
        self.status_code = status_code
        self._body = body_bytes
        self._headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.url = url

    @property
    def status(self):
        return self.status_code

    @property
    def headers(self):
        return self._headers

    async def text(self):
        return self._body.decode("utf-8", "replace")


class FakeRequest:
    def __init__(self, client):
        self._client = client

    async def get(self, url, params=None, headers=None, timeout=3000, **kwargs):
        return await asyncio.to_thread(self._do, "GET", url, params, None, headers)

    async def post(self, url, data=None, json=None, headers=None, timeout=3000, **kwargs):
        payload = json if json is not None else data
        return await asyncio.to_thread(self._do, "POST", url, None, payload, headers, json_body=json is not None)

    def _do(self, method, url, params, data, headers, json_body=False):
        parsed = urlparse(url)
        path = parsed.path or "/"
        hdrs = {k: v for k, v in (headers or {}).items()}
        # Faithful to a real browser/Playwright: the Cookie header sets the
        # jar (Flask's test client otherwise swallows it), and a dict body
        # with Content-Type: application/json is JSON-serialized.
        cookie_hdr = hdrs.pop("Cookie", None)
        if cookie_hdr:
            # FlaskClient keeps its own cookie jar (_cookies); clear it so a
            # previous request's jar state can't leak into this one.
            try:
                self._client._cookies.clear()
            except Exception:
                pass
            for pair in cookie_hdr.split(";"):
                if "=" in pair:
                    name, value = pair.strip().split("=", 1)
                    self._client.set_cookie(name, value)
        wants_json = json_body or str(hdrs.get("Content-Type", "")).lower() == "application/json"
        if method == "GET":
            resp = self._client.get(path, query_string=params, headers=hdrs)
        elif wants_json:
            resp = self._client.post(path, json=data or {}, headers=hdrs)
        else:
            resp = self._client.post(path, data=data or {}, headers=hdrs)
        return FakeResponse(resp.status_code, resp.data, dict(resp.headers), url)


class FakeLabContext:
    def __init__(self, client):
        self.request = FakeRequest(client)


@pytest.fixture(scope="module")
def client():
    mini.testing = True
    return mini.test_client()


@pytest.fixture()
def context(client):
    return FakeLabContext(client)


def _alice():
    return Identity(name="alice", headers={"X-Identity": "alice"})


def _bob():
    return Identity(name="bob", headers={"X-Identity": "bob"})


# ─── BOLA ────────────────────────────────────────────────────────────────────


class TestBOLA:
    async def test_cross_identity_read_is_verified(self, context):
        from titan.modules.bola.detector import BOLADetector
        findings = await BOLADetector(_stub(), {}).scan(
            context, "http://localhost:5000", "GET",
            "http://localhost:5000/api/bola_vuln", {"id": "1"}, [_alice(), _bob()],
        )
        assert findings, "bob reading alice's record must be found"
        f = findings[0]
        assert f.attack_type == AttackType.BOLA
        assert f.verified is True, f"expected verified BOLA, got diffs={f.diffs}"
        assert f.severity == Severity.CRITICAL
        assert "alice-secret-abc123" in f.verification_body, "owner marker must be present in attacker response"

    async def test_owner_only_endpoint_is_not_bola(self, context):
        from titan.modules.bola.detector import BOLADetector
        findings = await BOLADetector(_stub(), {}).scan(
            context, "http://localhost:5000", "GET",
            "http://localhost:5000/api/bola_secure", {"id": "1"}, [_alice(), _bob()],
        )
        assert findings == [], f"403 on cross-identity request must not be BOLA, got {findings}"

    async def test_public_endpoint_is_not_bola(self, context):
        """Same content for every identity is not BOLA — there is no
        cross-identity differential to prove."""
        from titan.modules.bola.detector import BOLADetector
        findings = await BOLADetector(_stub(), {}).scan(
            context, "http://localhost:5000", "GET",
            "http://localhost:5000/api/bola_public", {"id": "1"}, [_alice(), _bob()],
        )
        assert findings == [], f"public endpoint must not be BOLA, got {findings}"

    async def test_id_ignoring_owner_endpoint_is_not_bola(self, context):
        """An endpoint that returns the REQUESTER's own record for any id:
        the attacker's cross request equals their own baseline (cross==own),
        so no cross-tenant access occurred. The cross!=own guard must
        reject it even though the owner body carries unique markers."""
        from titan.modules.bola.detector import BOLADetector
        findings = await BOLADetector(_stub(), {}).scan(
            context, "http://localhost:5000", "GET",
            "http://localhost:5000/api/bola_my", {"id": "1"}, [_alice(), _bob()],
        )
        assert findings == [], f"own-record-for-any-id must not be BOLA, got {findings}"

    async def test_shared_record_is_not_bola(self, context):
        """A record BOTH identities legitimately own (shared doc): the cross
        response's content is also the attacker's own content, so no
        exclusive owner marker proves cross-tenant access. The
        markers-presence gate must reject it."""
        from titan.modules.bola.detector import BOLADetector
        findings = await BOLADetector(_stub(), {}).scan(
            context, "http://localhost:5000", "GET",
            "http://localhost:5000/api/bola_same_foreign", {"id": "1"}, [_alice(), _bob()],
        )
        assert findings == [], f"shared record must not be BOLA, got {findings}"

    async def test_single_identity_cannot_bola(self, context):
        from titan.modules.bola.detector import BOLADetector
        findings = await BOLADetector(_stub(), {}).scan(
            context, "http://localhost:5000", "GET",
            "http://localhost:5000/api/bola_vuln", {"id": "1"}, [_alice()],
        )
        assert findings == [], f"one identity cannot prove cross-tenant access, got {findings}"


# ─── Mass assignment ─────────────────────────────────────────────────────────


class TestMassAssignment:
    async def test_injected_role_is_verified(self, context):
        from titan.modules.massassignment.detector import MassAssignmentDetector
        findings = await MassAssignmentDetector(_stub(), {}).scan(
            context, "http://localhost:5000", "POST",
            "http://localhost:5000/api/user_update", {"name": "alice"},
        )
        assert findings, "role=admin accepted must be found"
        f = findings[0]
        assert f.attack_type == AttackType.MASS_ASSIGNMENT
        assert f.verified is True, f"expected verified mass assignment, got diffs={f.diffs}"
        assert "admin" in f.verification_body

    async def test_ignored_privilege_field_is_not_found(self, context):
        from titan.modules.massassignment.detector import MassAssignmentDetector
        findings = await MassAssignmentDetector(_stub(), {}).scan(
            context, "http://localhost:5000", "POST",
            "http://localhost:5000/api/user_update_secure", {"name": "alice"},
        )
        assert findings == [], f"server ignoring privilege field must not fire, got {findings}"

    async def test_value_already_in_baseline_is_not_mass_assignment(self, context):
        """A response that ALWAYS contains 'admin' (nav bar, role list)
        cannot prove the injected field was honored — the value is in the
        baseline too. The value-not-in-baseline guard must reject it."""
        from titan.modules.massassignment.detector import MassAssignmentDetector
        findings = await MassAssignmentDetector(_stub(), {}).scan(
            context, "http://localhost:5000", "POST",
            "http://localhost:5000/api/user_update_noisy", {"name": "alice"},
        )
        assert findings == [], f"'admin' in baseline must not prove mass assignment, got {findings}"

    async def test_html_echo_is_not_mass_assignment(self, context):
        """An HTML form that echoes the injected value without a JSON
        field:value pairing is not evidence the server honored it — the
        JSON-reflection gate must reject it."""
        from titan.modules.massassignment.detector import MassAssignmentDetector
        findings = await MassAssignmentDetector(_stub(), {}).scan(
            context, "http://localhost:5000", "POST",
            "http://localhost:5000/api/user_update_html", {"name": "alice"},
        )
        assert findings == [], f"HTML echo must not be mass assignment, got {findings}"

    async def test_get_is_not_mass_assignment(self, context):
        from titan.modules.massassignment.detector import MassAssignmentDetector
        findings = await MassAssignmentDetector(_stub(), {}).scan(
            context, "http://localhost:5000", "GET",
            "http://localhost:5000/api/user_update", {"name": "alice"},
        )
        assert findings == [], f"GET cannot be mass assignment, got {findings}"


# ─── JWT ─────────────────────────────────────────────────────────────────────


class TestJWT:
    async def test_alg_none_accepted_is_verified(self, context):
        from titan.modules.jwt.detector import JWTDetector
        findings = await JWTDetector(_stub(), {}).scan(
            context, "http://localhost:5000", "GET",
            "http://localhost:5000/api/jwt_verify", {},
        )
        assert findings, "alg:none token accepted must be found"
        f = findings[0]
        assert f.attack_type == AttackType.JWT_WEAKNESS
        assert f.verified is True, f"expected verified JWT alg:none, got diffs={f.diffs}"
        assert f.severity == Severity.CRITICAL

    async def test_signature_required_is_not_found(self, context):
        from titan.modules.jwt.detector import JWTDetector
        findings = await JWTDetector(_stub(), {}).scan(
            context, "http://localhost:5000", "GET",
            "http://localhost:5000/api/jwt_secure", {},
        )
        assert findings == [], f"endpoint rejecting alg:none must not fire, got {findings}"

    async def test_open_endpoint_is_not_jwt_tested(self, context):
        """An endpoint that answers 200 WITHOUT a token (no 401 gate) must
        not be JWT-tested — the anon-gate guards against forging tokens at
        endpoints that don't enforce auth at all."""
        from titan.modules.jwt.detector import JWTDetector
        findings = await JWTDetector(_stub(), {}).scan(
            context, "http://localhost:5000", "GET",
            "http://localhost:5000/api/open", {},
        )
        assert findings == [], f"endpoint without a 401 gate must not be JWT-tested, got {findings}"


# ─── Session fixation ────────────────────────────────────────────────────────


class TestSessionFixation:
    async def test_attacker_session_survives_login(self, context):
        from titan.modules.sessionfix.detector import SessionFixationDetector
        findings = await SessionFixationDetector(_stub(), {}).scan(
            context, "http://localhost:5000", "POST",
            "http://localhost:5000/api/login_fix", {"user": "alice"},
        )
        assert findings, "attacker-chosen session surviving login must be found"
        f = findings[0]
        assert f.attack_type == AttackType.SESSION_FIXATION
        assert f.verified is True, f"expected verified session fixation, got diffs={f.diffs}"

    async def test_fresh_session_is_not_fixation(self, context):
        from titan.modules.sessionfix.detector import SessionFixationDetector
        findings = await SessionFixationDetector(_stub(), {}).scan(
            context, "http://localhost:5000", "POST",
            "http://localhost:5000/api/login_secure", {"user": "alice"},
        )
        assert findings == [], f"server issuing fresh session must not fire, got {findings}"

    async def test_non_login_path_is_not_tested(self, context):
        from titan.modules.sessionfix.detector import SessionFixationDetector
        findings = await SessionFixationDetector(_stub(), {}).scan(
            context, "http://localhost:5000", "POST",
            "http://localhost:5000/api/user_update", {"name": "alice"},
        )
        assert findings == [], f"non-login endpoint must not be fixation-tested, got {findings}"


# ─── SessionPool ─────────────────────────────────────────────────────────────


class TestSessionPool:
    def test_pool_holds_concurrent_identities(self):
        pool = SessionPool()
        pool.add(_alice())
        pool.add(_bob())
        assert len(pool) == 2
        assert pool.primary().name == "alice"
        assert pool.second().name == "bob"

    def test_unauthenticated_identity_is_excluded(self):
        pool = SessionPool()
        pool.add(Identity(name="anon"))
        assert len(pool) == 0
        assert pool.primary() is None


# ─── Flow typing (Track D prerequisite) ─────────────────────────────────────


class TestFlows:
    def test_ssrf_metadata_upgrades_to_creds(self):
        f = Finding(
            target="t", url="u", method="GET", param="url", location="query",
            payload="http://169.254.169.254/latest/meta-data/",
            attack_type=AttackType.SSRF, verified=True,
        )
        assert infer_flows(f) == ["url_fetch", "creds"]

    def test_ssrf_plain_is_url_fetch(self):
        f = Finding(
            target="t", url="u", method="GET", param="url", location="query",
            payload="http://internal/x", attack_type=AttackType.SSRF, verified=True,
        )
        assert infer_flows(f) == ["url_fetch"]

    def test_unverified_finding_has_no_flow(self):
        f = Finding(
            target="t", url="u", method="GET", param="id", location="query",
            payload="x", attack_type=AttackType.SQLI, verified=False,
        )
        assert infer_flows(f) == []

    def test_lfi_provides_file_read(self):
        f = Finding(
            target="t", url="u", method="GET", param="file", location="query",
            payload="../../etc/passwd", attack_type=AttackType.LFI, verified=True,
        )
        assert infer_flows(f) == ["file_read"]

    def test_bola_provides_data_leak_and_auth_bypass(self):
        f = Finding(
            target="t", url="u", method="GET", param="id", location="query",
            payload="BOLA", attack_type=AttackType.BOLA, verified=True,
        )
        assert set(infer_flows(f)) == {"data_leak", "auth_bypass"}

    def test_apply_flows_populates_field_and_serializes(self):
        f = Finding(
            target="t", url="u", method="GET", param="key", location="body",
            payload="AKIA...", attack_type=AttackType.CRYPTO_WEAKNESS, verified=True,
        )
        apply_flows([f])
        assert f.flows == ["creds"]
        assert f.to_dict()["flows"] == ["creds"]

    def test_no_flow_for_unknown_attack(self):
        f = Finding(
            target="t", url="u", method="GET", param="p", location="query",
            payload="x", attack_type=AttackType.NO_ISSUE, verified=True,
        )
        assert infer_flows(f) == []


# ─── Engine wiring ───────────────────────────────────────────────────────────


class TestIdentityEngineWiring:
    async def test_identity_modules_run_through_engine(self, context):
        from titan.core.engine import TitanEngine
        cfg = {"governance": {"enabled": False}, "ai": {"enabled": False}}
        engine = TitanEngine(cfg)
        engine.session_pool.add(_alice())
        engine.session_pool.add(_bob())

        findings = await engine._run_identity_modules(
            context, "http://localhost:5000",
            "http://localhost:5000/api/bola_vuln?id=1", {},
        )
        bola = [f for f in findings if f.attack_type == AttackType.BOLA]
        assert bola, f"BOLA must fire through the engine identity seam, got {findings}"

    async def test_identity_seam_requires_two_identities(self, context):
        from titan.core.engine import TitanEngine
        cfg = {"governance": {"enabled": False}, "ai": {"enabled": False}}
        engine = TitanEngine(cfg)
        engine.session_pool.add(_alice())
        findings = await engine._run_identity_modules(
            context, "http://localhost:5000",
            "http://localhost:5000/api/bola_vuln?id=1", {},
        )
        assert findings == [], f"one identity must not run the identity matrix, got {findings}"


def _stub():
    from titan.ai.payloadforge import PayloadForge

    class StubSmith:
        def __init__(self):
            self.forge = PayloadForge()

        def get_base_payloads(self, attack_type, context):
            return self.forge.get_context_payloads(attack_type, context)

        def get_waf_bypass_payloads(self, base_payloads, waf):
            return base_payloads

        def detect_waf(self, headers, body, status):
            return None

        async def mutate(self, base_payloads, context):
            return []

    return StubSmith()
