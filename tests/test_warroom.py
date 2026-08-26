"""Tests for the war room dashboard generator (purple/warroom.py)."""
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "purple"


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


war = _load("warroom", "warroom.py")


def _extract_data(html: str) -> dict:
    m = re.search(r"let WAR = (\{.*?\});\n\nfunction renderAll", html, re.S)
    assert m, "embedded WAR data not found in HTML"
    return json.loads(m.group(1))


def test_collect_has_all_sections():
    data = war.collect()
    for key in ("generated_at", "repos", "rounds", "scenarios", "batch", "specs", "journal_tail"):
        assert key in data, f"missing {key}"
    assert isinstance(data["rounds"], list)
    assert data["repos"]["private"]["name"] == "titan-lab"
    assert data["repos"]["public"]["name"] == "vuln-scanner"


def test_collect_reads_live_rounds_and_scenarios():
    data = war.collect()
    assert len(data["rounds"]) >= 10, "scoreboard rounds not read"
    ids = {s["id"] for s in data["scenarios"]}
    assert "SCN-007" in ids and "SCN-013" in ids, "registry scenarios not read"
    assert data["repos"]["private"]["head"]["hash"], "private git head missing"


def test_build_writes_self_contained_html(tmp_path):
    out = tmp_path / "warroom.html"
    war.build(out)
    html = out.read_text(encoding="utf-8")
    assert "@DATA@" not in html, "placeholder not substituted"
    assert "<title>Titan War Room</title>" in html
    assert "SCOREBOARD" in html and "SCENARIO REGISTRY" in html
    assert "BLUE TASK QUEUE" in html and "WAR JOURNAL" in html
    assert "file://" not in html[:200], "no external deps allowed (offline file://)"  # sanity


def test_embedded_data_is_parseable_and_populated(tmp_path):
    out = tmp_path / "warroom.html"
    war.build(out)
    data = _extract_data(out.read_text(encoding="utf-8"))
    assert len(data["rounds"]) >= 10
    assert any(r["round_id"] == "R20" for r in data["rounds"]), "latest rounds not embedded"
    ids = {s["id"] for s in data["scenarios"]}
    assert {"SCN-003", "SCN-005", "SCN-007", "SCN-013"} <= ids


def test_embedded_batch_includes_variant_attempts(tmp_path):
    out = tmp_path / "warroom.html"
    war.build(out)
    data = _extract_data(out.read_text(encoding="utf-8"))
    findings = data.get("batch", {}).get("findings", [])
    assert findings, "batch findings not embedded"
    assert any("variant_label" in f for f in findings), "variant attempts missing"
    assert any(f.get("evidence") == "header" for f in findings), "header evidence missing"


def test_specs_section_carries_blue_tasks(tmp_path):
    out = tmp_path / "warroom.html"
    war.build(out)
    data = _extract_data(out.read_text(encoding="utf-8"))
    assert data["specs"], "inbox specs not embedded"
    assert all("check" in sp and "oracle" in sp for sp in data["specs"])


def test_new_war_features_present(tmp_path):
    out = tmp_path / "warroom.html"
    war.build(out)
    html = out.read_text(encoding="utf-8")
    for needle in (
        'id="themeBtn"', "html.light", "localStorage", "warroom-theme",
        'id="modal"', "openRound", "modalClose", "Escape",
        'id="blameBody"', 'id="remBody"', 'id="gaps"',
        "BLAME &amp; REMEDIATION", "RED'S OPEN LEDGER", "DRAFTED FIXES",
    ):
        assert needle in html, f"missing {needle}"


def test_embedded_json_cannot_break_the_script_tag(tmp_path):
    out = tmp_path / "warroom.html"
    war.build(out)
    html = out.read_text(encoding="utf-8")
    assert html.count("<script") == 1, "stored payload leaked a raw <script>"
    assert html.count("</script>") == 1, "stored payload leaked a raw </script>"
    assert "</script>" not in html.split("<script")[1].split("</script>")[0].split("let WAR = ")[1], "WAR JSON contains raw </script>"
    data = _extract_data(html)  # must still parse cleanly
    assert data["rounds"] and data["specs"]


def test_inline_script_parses(tmp_path):
    """Whole-script syntax gate: the dashboard is dead if this fails.
    Catches invalid template-literal expressions (e.g. backslash-escaped
    quotes inside ${...}) that browsers only surface at parse time."""
    import shutil
    import subprocess
    import re as _re
    if shutil.which("node") is None:
        import pytest
        pytest.skip("node not available")
    out = tmp_path / "warroom.html"
    war.build(out)
    html = out.read_text(encoding="utf-8")
    m = _re.search(r"<script>(.*)</script>", html, _re.S)
    assert m, "script block missing"
    js = tmp_path / "inline.js"
    js.write_text(m.group(1), encoding="utf-8")
    r = subprocess.run(["node", "--check", str(js)], capture_output=True, text=True)
    assert r.returncode == 0, f"inline script failed node --check:\n{r.stderr}"

def test_collect_includes_live_progress():
    data = war.collect()
    assert "progress" in data, "collect() must expose the live batch progress"
    assert isinstance(data["progress"], (dict, type(None)))


def test_live_state_endpoint_serves_fresh_json(tmp_path):
    import threading
    import urllib.request
    import http.server as _hs

    httpd = _hs.ThreadingHTTPServer(("127.0.0.1", 0), war._LiveHandler)
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever, daemon=True)
    th.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/state", timeout=5) as r:
            data = json.loads(r.read().decode("utf-8"))
        assert data["rounds"] and data["scenarios"], "/api/state must carry live data"
        assert "progress" in data
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/warroom.html", timeout=5) as r:
            assert "Titan War Room" in r.read().decode("utf-8")
    finally:
        httpd.shutdown()
        httpd.server_close()

