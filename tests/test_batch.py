"""Tests for the purple batch runner (titan-lab private tooling)."""
import importlib.util
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent / "purple"
LAB_ROOT = Path(__file__).resolve().parent.parent


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


batch = _load("batch", "batch.py")
sb_mod = _load("sb", "scoreboard.py")


# -- registry selection ------------------------------------------------------
def test_selection_only_limit_status():
    reg = {"scenarios": [
        {"id": "SCN-001", "status": "defended"},
        {"id": "SCN-002", "status": "defended"},
        {"id": "SCN-003", "status": "open"},
        {"id": "SCN-004", "status": "open"},
    ]}
    assert [s["id"] for s in batch.select_scenarios(reg, only={"SCN-002", "SCN-004"})] == ["SCN-002", "SCN-004"]
    assert [s["id"] for s in batch.select_scenarios(reg, limit=2)] == ["SCN-001", "SCN-002"]
    assert [s["id"] for s in batch.select_scenarios(reg, status="open")] == ["SCN-003", "SCN-004"]


def test_registry_fully_covered_by_probes_or_fixture_missing():
    reg = batch.load_registry()
    for s in reg["scenarios"]:
        assert s["id"] in batch.PROBES or s["id"] in batch.FIXTURE_MISSING \
            or s["id"] in batch.CONTENT_SCENARIOS, \
            f"{s['id']} has no probes and is not marked fixture_missing/content"


def test_every_scenario_has_a_built_fixture():
    reg = batch.load_registry()
    for s in reg["scenarios"]:
        assert s["id"] not in batch.FIXTURE_MISSING, f"{s['id']} still fixture_missing"
        assert "NOT BUILT" not in (s.get("lab_fixture") or ""), f"{s['id']} fixture not built"


def test_probe_expands_base_template():
    probe = {"path": "/ssrf", "params": {"url": "{{base}}/internal/meta"},
             "attack_type": "SSRF", "payload": "{{base}}/internal/meta"}
    out = batch._expand_base(probe, "http://127.0.0.1:5055")
    assert out["params"]["url"] == "http://127.0.0.1:5055/internal/meta"
    assert out["payload"] == "http://127.0.0.1:5055/internal/meta"
    assert probe["params"]["url"] == "{{base}}/internal/meta"  # original untouched


# -- probing / verification --------------------------------------------------
def test_run_probe_verified_when_marker_present(monkeypatch):
    calls = {}
    def fake_get(base, path, params=None, timeout=6.0):
        calls["args"] = (base, path, params)
        return 200, "<html>ami-id: i-0lab1234</html>"
    monkeypatch.setattr(batch, "HTTP_GET", fake_get)
    probe = {"path": "/ssrf", "params": {"url": "http://x"}, "attack_type": "SSRF",
             "param": "url", "payload": "p", "marker": "ami-id",
             "severity": "critical", "confidence": 0.9}
    f = batch.run_probe("http://127.0.0.1:5000", probe)
    assert f["verified"] is True
    assert f["confidence"] == 0.9
    assert f["url"] == "http://127.0.0.1:5000/ssrf?url=http%3A%2F%2Fx"


def test_run_probe_unverified_when_marker_absent(monkeypatch):
    def fake_get(base, path, params=None, timeout=6.0):
        return 200, "no marker here"
    monkeypatch.setattr(batch, "HTTP_GET", fake_get)
    f = batch.run_probe("http://127.0.0.1:5000", {"path": "/ssrf", "attack_type": "SSRF",
                                                  "param": "url", "payload": "p",
                                                  "marker": "ami-id", "severity": "critical",
                                                  "confidence": 0.9})
    assert f["verified"] is False
    assert f["confidence"] < 0.9


def test_run_probe_with_pre_post_action(monkeypatch):
    calls = []
    def fake_post(base, path, timeout=6.0):
        calls.append(("POST", path))
        return 200, "ok"
    def fake_get(base, path, params=None, timeout=6.0):
        calls.append(("GET", path))
        return 200, "DEFACED-BY-TITAN marker present"
    monkeypatch.setattr(batch, "HTTP_POST", fake_post)
    monkeypatch.setattr(batch, "HTTP_GET", fake_get)
    probe = {"path": "/integrity", "method": "GET",
             "pre": {"method": "POST", "path": "/integrity/deface"},
             "attack_type": "Content Integrity", "param": "body",
             "payload": "x", "marker": "DEFACED-BY-TITAN",
             "severity": "medium", "confidence": 0.7}
    f = batch.run_probe("http://127.0.0.1:5000", probe)
    assert f["verified"] is True
    assert ("POST", "/integrity/deface") in calls
    assert ("GET", "/integrity") in calls


def test_probe_scenario_reports_fixture_missing(monkeypatch):
    monkeypatch.setattr(batch, "FIXTURE_MISSING", {"SCN-999"})
    status, findings = batch.probe_scenario("http://x", {"id": "SCN-999"})
    assert status == "fixture_missing"
    assert findings == []


def test_content_skimmer_finds_external_script(monkeypatch):
    html = '<html><script src="https://ads.example/track.js"></script></html>'
    monkeypatch.setattr(batch, "HTTP_GET", lambda base, path, params=None, timeout=6.0: (200, html))
    f = batch.content_skimmer("http://127.0.0.1:5000", "SCN-006")
    assert f is not None
    assert f["attack_type"] == "Skimmer"
    assert f["verified"] is True


def test_content_skimmer_clean_page_returns_none(monkeypatch):
    monkeypatch.setattr(batch, "HTTP_GET", lambda base, path, params=None, timeout=6.0: (200, "<html>no scripts</html>"))
    assert batch.content_skimmer("http://127.0.0.1:5000", "SCN-006") is None


# -- Round 2: JSON bodies, header verification, adversarial variants ---------
def test_run_probe_json_body_post(monkeypatch):
    captured = {}
    def fake_post(base, path, data=None, headers=None, json_body=None, timeout=6.0, capture_headers=False):
        captured["json_body"] = json_body
        return 200, "updated"
    monkeypatch.setattr(batch, "HTTP_POST", fake_post)
    probe = {"path": "/api/profile/update", "method": "POST",
             "json_body": {"__proto__": {"isAdmin": True}},
             "attack_type": "Prototype Pollution", "param": "body",
             "payload": "x", "marker": "updated", "severity": "high", "confidence": 0.8}
    f = batch.run_probe("http://127.0.0.1:5000", probe)
    assert captured["json_body"] == {"__proto__": {"isAdmin": True}}
    assert f["verified"] is True
    assert f["variant"] == 0 and f["variant_label"] == "base"


def test_run_probe_form_data_post(monkeypatch):
    captured = {}
    def fake_post(base, path, data=None, headers=None, json_body=None, timeout=6.0, capture_headers=False):
        captured["data"] = data
        return 200, "Stored: <script>alert(1)</script>"
    monkeypatch.setattr(batch, "HTTP_POST", fake_post)
    probe = {"path": "/guestbook/add", "method": "POST",
             "form_data": {"entry": "<script>alert(1)</script>"},
             "attack_type": "XSS", "param": "entry", "payload": "x",
             "marker": "<script>", "severity": "high", "confidence": 0.85}
    f = batch.run_probe("http://127.0.0.1:5000", probe)
    assert captured["data"] == {"entry": "<script>alert(1)</script>"}
    assert f["verified"] is True


def test_run_probe_verify_headers_marker(monkeypatch):
    def fake_get(base, path, params=None, headers=None, follow_redirects=True,
                 capture_headers=False, timeout=6.0):
        return 200, "reset requested", {"X-Debug-Token": "tk-abc123"}
    monkeypatch.setattr(batch, "HTTP_GET", fake_get)
    probe = {"path": "/reset?mode=header", "params": None, "verify_headers": True,
             "attack_type": "Info Leak", "param": "X-Debug-Token (header)",
             "payload": "x", "marker": "x-debug-token", "severity": "medium", "confidence": 0.8}
    f = batch.run_probe("http://127.0.0.1:5000", probe)
    assert f["verified"] is True
    assert f["evidence"] == "header"


def test_run_probe_variants_runs_every_attempt(monkeypatch):
    calls = []
    def fake_get(base, path, params=None, timeout=6.0):
        calls.append(params)
        entry = (params or {}).get("entry", "")
        body = "entry stored"
        if "onerror" in entry:
            body += " onerror"
        elif "<script>" in entry:
            body += " <script>"
        return 200, body
    monkeypatch.setattr(batch, "HTTP_GET", fake_get)
    probe = {"path": "/guestbook/add", "method": "GET",
             "params": {"entry": "<script>alert(1)</script>"},
             "attack_type": "XSS", "param": "entry", "payload": "x",
             "marker": "<script>", "severity": "high", "confidence": 0.85,
             "variants": [
                 {"label": "img-onerror",
                  "params": {"entry": "<img src=x onerror=alert(1)>"},
                  "marker": "onerror"},
             ]}
    findings = batch.run_probe_variants("http://127.0.0.1:5000", probe)
    assert len(findings) == 2
    assert [f["variant"] for f in findings] == [0, 1]
    assert findings[0]["variant_label"] == "base"
    assert findings[1]["variant_label"] == "img-onerror"
    assert findings[1]["verified"] is True


def test_variant_merges_nested_pre():
    probe = {"path": "/login", "method": "POST",
             "form_data": {"username": "a"},
             "pre": {"method": "POST", "path": "/register", "form_data": {"username": "a"}}}
    merged = batch._merge_variant(probe, {"form_data": {"username": "b"},
                                          "pre": {"form_data": {"username": "b"}}})
    assert merged["form_data"] == {"username": "b"}
    assert merged["pre"]["form_data"] == {"username": "b"}
    assert merged["pre"]["path"] == "/register"


# -- scoreboard integration --------------------------------------------------
def test_log_draft_rounds(tmp_path):
    store = tmp_path / "scoreboard.json"
    sb = sb_mod.Scoreboard(store)
    executed = [({"id": "SCN-002", "title": "t", "class": "cloud_native", "red_capability": "probe",
                  "blue_check": "check", "tests": "t.py", "mitre": ["T1190"]}, [{"attack_type": "SSRF"}])]
    n = batch.log_draft_rounds(store, executed)
    assert n == 1
    rows = sb.load()
    assert rows[0]["round_id"] == "R1"
    assert rows[0]["status"] == "proposed"
    assert rows[0]["outcome"] == "pending"
    assert rows[0]["threat_class"] == "cloud_native"


# -- end-to-end against a real lab ------------------------------------------
def _port_free(port):
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


@pytest.fixture(scope="module")
def live_lab():
    port = 5055
    if not _port_free(port):
        pytest.skip(f"port {port} busy — live-lab integration test skipped")
    python = sys.executable
    proc = subprocess.Popen(
        [python, "-c", f"from local_lab import app as m; m.app.run(host='127.0.0.1', port={port}, debug=False, use_reloader=False)"],
        cwd=str(LAB_ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                status, _ = batch.HTTP_GET(base, "/", None, timeout=2)
                if status == 200:
                    break
            except Exception:  # noqa: BLE001
                pass
            time.sleep(0.5)
        else:
            pytest.skip("lab did not come up in time")
        yield base
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_batch_against_live_lab(live_lab, tmp_path):
    out = tmp_path / "batch-findings.json"
    only = {"SCN-002", "SCN-003", "SCN-004", "SCN-005", "SCN-006",
            "SCN-007", "SCN-009", "SCN-010", "SCN-011", "SCN-013"}
    res = batch.run_batch(live_lab, only=only,
                          out_file=out, do_convert=False, do_score=False)
    assert "error" not in res
    statuses = {s["id"]: s["status"] for s in res["scenarios"]}
    # SCN-006 is content-probed: the lab root serves no external scripts, so
    # it honestly reports no_findings (its own unit tests cover the skimmer).
    content_only = {"SCN-006"}
    for sid in only - content_only:
        assert statuses[sid] == "executed", f"{sid} not executed"
    assert statuses["SCN-006"] in ("executed", "no_findings")

    by_type = {f["attack_type"] for f in res["findings"]}
    assert "SSRF" in by_type and "Crypto Weakness" in by_type
    assert "Hidden Asset" in by_type and "Content Integrity" in by_type
    assert "Ad Redirect Chain" in by_type
    assert "XSS" in by_type and "SQLi" in by_type and "Info Leak" in by_type
    assert "Cache Poisoning" in by_type and "Prototype Pollution" in by_type

    # every probed scenario must land at least one marker-verified finding
    for sid in only - content_only:
        assert any(f["verified"] and f["scenario_id"] == sid for f in res["findings"]), \
            f"{sid} produced no verified finding"

    ssrf = [f for f in res["findings"] if f["attack_type"] == "SSRF"][0]
    assert ssrf["verified"] is True  # ami-id marker from /internal/meta
    assert ssrf["scenario_id"] == "SCN-002"
    hidden = [f for f in res["findings"] if f["attack_type"] == "Hidden Asset"][0]
    assert hidden["verified"] is True  # TITANPUZZLE marker in the 403 gate body
    integrity = [f for f in res["findings"] if f["attack_type"] == "Content Integrity"][0]
    assert integrity["verified"] is True  # DEFACED-BY-TITAN after the deface POST

    # adversarial variants: the stored-XSS scenario must have tried > 1 attempt
    xss_variants = {f["variant"] for f in res["findings"] if f["scenario_id"] == "SCN-007"}
    assert len(xss_variants) > 1, "SCN-007 must have run adversarial variants"

    # header-verified finding: SCN-010 header channel carries evidence in headers
    info_leak = [f for f in res["findings"] if f["scenario_id"] == "SCN-010"]
    assert any(f["evidence"] == "header" for f in info_leak), "SCN-010 header channel not header-verified"

    # dumped file must be converter-compatible
    dumped = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(dumped["findings"], list)
    assert dumped["batch"]["scenarios_requested"] == len(only)


def test_batch_reports_missing_lab(tmp_path):
    res = batch.run_batch("http://127.0.0.1:59999", only={"SCN-002"},
                          out_file=tmp_path / "x.json", do_convert=False, do_score=False)
    assert "error" in res

# -- Round 3: login_as session support + the Titan Shop batch -----------------
def test_login_cookie_captures_set_cookie(monkeypatch):
    captured = {}
    def fake_post(base, path, data=None, headers=None, json_body=None,
                  timeout=6.0, capture_headers=False):
        captured["capture"] = capture_headers
        return (200, '{"session": "s-abc", "user": "alice"}',
                {"Set-Cookie": "sid=s-abc; Path=/"})
    monkeypatch.setattr(batch, "HTTP_POST", fake_post)
    cookie = batch._login_cookie("http://127.0.0.1:5000",
                                 {"username": "alice", "password": "alice123"})
    assert cookie == "sid=s-abc"
    assert captured["capture"] is True


def test_login_cookie_empty_without_creds(monkeypatch):
    def fake_post(base, path, data=None, headers=None, json_body=None,
                  timeout=6.0, capture_headers=False):
        raise AssertionError("must not POST without creds")
    monkeypatch.setattr(batch, "HTTP_POST", fake_post)
    assert batch._login_cookie("http://127.0.0.1:5000", None) == ""


def test_run_probe_login_as_attaches_cookie(monkeypatch):
    seen = {}
    def fake_post(base, path, data=None, headers=None, json_body=None,
                  timeout=6.0, capture_headers=False):
        if capture_headers:
            return 200, '{"session": "s-xyz"}', {"Set-Cookie": "sid=s-xyz; Path=/"}
        return 200, "ok"
    def fake_get(base, path, params=None, headers=None, follow_redirects=True,
                 capture_headers=False, timeout=6.0):
        seen["get_cookie"] = (headers or {}).get("Cookie")
        return 200, "TITAN-SHOP-ADMIN-OK"
    monkeypatch.setattr(batch, "HTTP_POST", fake_post)
    monkeypatch.setattr(batch, "HTTP_GET", fake_get)
    probe = {"path": "/shop/admin", "method": "GET",
             "login_as": {"username": "redadmin", "password": "x"},
             "attack_type": "Mass Assignment", "param": "role",
             "payload": "p", "marker": "TITAN-SHOP-ADMIN-OK",
             "severity": "high", "confidence": 0.85}
    f = batch.run_probe("http://127.0.0.1:5000", probe)
    assert seen["get_cookie"] == "sid=s-xyz"
    assert f["verified"] is True


def test_run_probe_pre_before_login(monkeypatch):
    """Pre-actions (register) must run BEFORE login_as (login) — the ordering
    SCN-014's admin-reach probe depends on."""
    order = []
    def fake_post(base, path, data=None, headers=None, json_body=None,
                  timeout=6.0, capture_headers=False):
        if capture_headers:
            order.append("login")
            return 200, '{"session": "s-1"}', {"Set-Cookie": "sid=s-1; Path=/"}
        order.append("pre")
        return 200, "registered"
    monkeypatch.setattr(batch, "HTTP_POST", fake_post)
    monkeypatch.setattr(batch, "HTTP_GET",
                        lambda *a, **k: (200, "TITAN-SHOP-ADMIN-OK"))
    probe = {"path": "/shop/admin", "method": "GET",
             "pre": {"method": "POST", "path": "/shop/register",
                     "json_body": {"username": "redadmin", "password": "x",
                                   "role": "admin"}},
             "login_as": {"username": "redadmin", "password": "x"},
             "attack_type": "Mass Assignment", "param": "role",
             "payload": "p", "marker": "TITAN-SHOP-ADMIN-OK",
             "severity": "high", "confidence": 0.85}
    f = batch.run_probe("http://127.0.0.1:5000", probe)
    assert order == ["pre", "login"], f"wrong order: {order}"
    assert f["verified"] is True


def test_batch_shop_against_live_lab(live_lab, tmp_path):
    out = tmp_path / "shop-findings.json"
    only = {"SCN-014", "SCN-015", "SCN-016", "SCN-017", "SCN-018",
            "SCN-019", "SCN-020", "SCN-021"}
    res = batch.run_batch(live_lab, only=only, out_file=out,
                          do_convert=False, do_score=False)
    assert "error" not in res
    statuses = {s["id"]: s["status"] for s in res["scenarios"]}
    for sid in only:
        assert statuses[sid] == "executed", f"{sid} not executed"
        assert any(f["verified"] and f["scenario_id"] == sid
                   for f in res["findings"]), f"{sid} produced no verified finding"
    types = {f["attack_type"] for f in res["findings"]}
    assert {"Mass Assignment", "XSS", "BOLA", "Price Tampering",
            "Unsigned Webhook", "Info Leak", "SQLi", "Session Fixation"} <= types
