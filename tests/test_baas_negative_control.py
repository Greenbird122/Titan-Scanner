"""Negative-control regression for the BaaS on-origin family sweep.

Lesson baked in from the adversarial-honeypot calibration target: a BaaS
finding is not dead until the full path family on the target's own origin
is swept (rest/v1, storage/v1, .json) AND responses are differentiated
from canned controls. An app that answers every BaaS-shaped path with the
same byte-identical body (or one canned guest row across every table) is a
honeypot — it must produce ZERO findings. A surface that returns data
differing from the nonsense control path is a real exposure.

Also pins the modules_runner wiring: the baas module dispatches to
BaasDetector (the class that exists), not the renamed SupabaseAuditModule.
"""

import asyncio

from titan.modules.baas.detector import BaasDetector

HONEYPOT_BODY = '[{"id":1,"guest":true,"message":"canned demo row","role":"USER"}]'
REAL_USERS_BODY = '[{"id":1,"email":"real@example.com","role":"ADMIN"}]'


class _Resp:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    async def text(self):
        return self._body


class _RouteContext:
    """context.request stub: prefix -> (status, body). Longest prefix wins.

    Every BaaS-shaped path under a routed prefix returns that route's body,
    so a honeypot can be modeled by routing the whole origin to one canned
    body (identical for real tables AND the nonsense control).
    """

    def __init__(self, routes, default_status=404, default_body=""):
        self._routes = routes
        self._default_status = default_status
        self._default_body = default_body
        self.calls = []

    @property
    def request(self):
        return self

    async def get(self, url, params=None, headers=None, timeout=3000, **kw):
        self.calls.append(url)
        best = None
        best_len = -1
        for prefix, route in self._routes.items():
            if url.startswith(prefix) and len(prefix) > best_len:
                best = route
                best_len = len(prefix)
        if best is None:
            return _Resp(self._default_status, self._default_body)
        if len(best) == 2:
            status, body = best
            return _Resp(status, body)
        status, body, _ = best
        return _Resp(status, body)


def _honeypot_context(base="https://honeypot.test"):
    """Whole-origin honeypot: every path (incl. nonsense control) 200-canned."""
    return _RouteContext({base: (200, HONEYPOT_BODY)})


def _hinted_fingerprint():
    return {
        "body": '<html><script src="/config.js"></script><div>built with supabase</div></html>',
        "technologies": ["supabase"],
    }


def _run(detector, ctx, target=None, url=None):
    target = target or "https://honeypot.test"
    url = url or target + "/api/rest/v1/products"
    return asyncio.run(detector.scan(ctx, target, "GET", url, {}))


def test_whole_origin_canned_body_produces_zero_findings():
    """The honeypot core: one canned body for EVERY path, control included."""
    BaasDetector.reset_sweep_cache()
    detector = BaasDetector(payload_smith=None, fingerprint=_hinted_fingerprint())
    findings = _run(detector, _honeypot_context())
    assert findings == [], f"canned honeypot produced findings: {findings}"


def test_canned_across_tables_with_404_control_is_still_demoted():
    """Even when the control 404s, one canned row served for every real
    table is a honeypot — cross-table byte-identity demotes it."""
    BaasDetector.reset_sweep_cache()
    base = "https://honeypot.test"
    # control path -> 404; every real table path -> identical canned row
    routes = {
        base + "/rest/v1/zz_titan_ctl_nonexistent_7f3a": (404, "not found"),
        base + "/rest/v1/users": (200, HONEYPOT_BODY),
        base + "/rest/v1/admin": (200, HONEYPOT_BODY),
        base + "/rest/v1/products": (200, HONEYPOT_BODY),
        base + "/api/rest/v1/zz_titan_ctl_nonexistent_7f3a": (404, "not found"),
        base + "/api/rest/v1/users": (200, HONEYPOT_BODY),
        base + "/api/rest/v1/admin": (200, HONEYPOT_BODY),
        base + "/api/rest/v1/products": (200, HONEYPOT_BODY),
    }
    detector = BaasDetector(payload_smith=None, fingerprint=_hinted_fingerprint())
    findings = _run(detector, _RouteContext(routes))
    assert findings == [], f"cross-table canned honeypot produced findings: {findings}"


def test_differentiated_live_rest_data_fires_finding():
    """A genuine open PostgREST-style table differs from the 404 control."""
    BaasDetector.reset_sweep_cache()
    base = "https://live.test"
    routes = {
        # control paths 404
        base + "/rest/v1/zz_titan_ctl_nonexistent_7f3a": (404, "relation does not exist"),
        base + "/api/rest/v1/zz_titan_ctl_nonexistent_7f3a": (404, "relation does not exist"),
        # one real open table
        base + "/rest/v1/users": (200, REAL_USERS_BODY),
        base + "/rest/v1/admin": (200, "[]"),
        base + "/api/rest/v1/users": (200, REAL_USERS_BODY),
    }
    detector = BaasDetector(payload_smith=None, fingerprint=_hinted_fingerprint())
    findings = _run(detector, _RouteContext(routes), target=base)
    assert len(findings) >= 1, "differentiated live REST data should fire"
    assert any("rest_v1" in (f.tags or []) for f in findings)


def test_storage_family_byte_identical_buckets_demoted():
    """Storage object listings that return one canned row across every
    bucket (while control 404s) are demoted by cross-bucket identity."""
    BaasDetector.reset_sweep_cache()
    base = "https://honeypot.test"
    routes = {
        base + "/storage/v1/zz_titan_ctl_nonexistent_7f3a": (404, "nf"),
        base + "/api/storage/v1/zz_titan_ctl_nonexistent_7f3a": (404, "nf"),
    }
    for bucket in BaasDetector.ON_ORIGIN_COMMON_BUCKETS:
        routes[base + f"/storage/v1/object/{bucket}/"] = (200, HONEYPOT_BODY)
        routes[base + f"/api/storage/v1/object/{bucket}/"] = (200, HONEYPOT_BODY)
    detector = BaasDetector(payload_smith=None, fingerprint=_hinted_fingerprint())
    findings = _run(detector, _RouteContext(routes))
    assert findings == [], f"canned storage family produced findings: {findings}"


def test_rtdb_every_json_path_canned_is_demoted():
    """Live-honeypot trap: a fake RTDB answers EVERY path ending in /.json
    (root, child, nonsense) with one canned body. Control is slash-shaped
    ({control}/.json) so it is byte-identical to root -> demoted."""
    BaasDetector.reset_sweep_cache()
    base = "https://honeypot.test"
    rtdb_body = '{"users":{"u1":{"name":"Guest"}},"posts":{"p1":{}},"meta":{"ok":true}}'
    # Root AND the slash-shaped nonsense control both serve the canned DB.
    routes = {
        base + "/.json": (200, rtdb_body),
        base + "/zz_titan_ctl_nonexistent_7f3a/.json": (200, rtdb_body),
        # bare-nonsense .json (no slash) is the soft-404 SAME_BODY trap
        base + "/zz_titan_ctl_nonexistent_7f3a.json": (200, HONEYPOT_BODY),
    }
    detector = BaasDetector(payload_smith=None, fingerprint=_hinted_fingerprint())
    findings = _run(detector, _RouteContext(routes))
    assert findings == [], f"canned .json family produced findings: {findings}"


def test_rtdb_root_data_with_null_control_fires():
    """A real open RTDB returns data at root and null at the slash-shaped
    nonsense control — the differentiated surface fires."""
    BaasDetector.reset_sweep_cache()
    base = "https://live.test"
    rtdb_body = '{"users":{"u1":{"name":"Real"}},"meta":{"ok":true}}'
    routes = {
        base + "/.json": (200, rtdb_body),
        base + "/zz_titan_ctl_nonexistent_7f3a/.json": (200, "null"),
    }
    detector = BaasDetector(payload_smith=None, fingerprint=_hinted_fingerprint())
    findings = _run(detector, _RouteContext(routes), target=base)
    assert len(findings) >= 1, "differentiated live RTDB data should fire"
    assert any("rtdb" in (f.tags or []) for f in findings)


def test_storage_bucket_name_list_alone_is_not_a_finding():
    """Live-honeypot trap: /storage/v1/bucket returns a plausible bucket
    NAME list (config noise) while object paths return []. Bucket names
    alone are not a vuln — object exposure is the signal."""
    BaasDetector.reset_sweep_cache()
    base = "https://honeypot.test"
    routes = {
        # bucket name list looks real but no object data behind it
        base + "/storage/v1/bucket": (200, '[{"id":"public","public":true}]'),
        base + "/api/storage/v1/bucket": (200, '[{"id":"public","public":true}]'),
        base + "/storage/v1/zz_titan_ctl_nonexistent_7f3a": (200, HONEYPOT_BODY),
        base + "/api/storage/v1/zz_titan_ctl_nonexistent_7f3a": (200, HONEYPOT_BODY),
    }
    for bucket in BaasDetector.ON_ORIGIN_COMMON_BUCKETS:
        routes[base + f"/storage/v1/object/{bucket}/"] = (200, "[]")
        routes[base + f"/api/storage/v1/object/{bucket}/"] = (200, "[]")
    detector = BaasDetector(payload_smith=None, fingerprint=_hinted_fingerprint())
    findings = _run(detector, _RouteContext(routes))
    assert findings == [], f"bucket name list alone produced findings: {findings}"


def test_sweep_runs_once_per_origin():
    """The module dispatches per endpoint; the origin sweep must not repeat."""
    BaasDetector.reset_sweep_cache()
    detector = BaasDetector(payload_smith=None, fingerprint=_hinted_fingerprint())
    ctx = _honeypot_context()
    _run(detector, ctx)
    len(ctx.calls)
    ctx2 = _honeypot_context()
    _run(detector, ctx2, url="https://honeypot.test/api/rest/v1/admin")
    assert len(ctx2.calls) == 0, "second dispatch re-ran the origin sweep"


def test_no_baas_hint_means_no_sweep():
    """A clean fingerprint with no BaaS markers must not trigger probes."""
    BaasDetector.reset_sweep_cache()
    detector = BaasDetector(payload_smith=None, fingerprint={"body": "<html>plain</html>"})
    ctx = _honeypot_context()
    findings = _run(detector, ctx, url="https://honeypot.test/api/search?q=x")
    assert findings == []
    assert ctx.calls == [], "sweep fired without any BaaS hint"


def test_modules_runner_wiring_target_exists():
    """modules_runner._run_baas imports BaasDetector — not the renamed
    SupabaseAuditModule that never existed post-modularization."""
    import titan.modules.baas.detector as det

    assert hasattr(det, "BaasDetector")
    assert not hasattr(det, "SupabaseAuditModule")
