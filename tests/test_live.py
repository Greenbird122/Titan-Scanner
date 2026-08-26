"""Live progress file lifecycle: run_batch must publish running -> done/failed."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent / "purple"


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, ROOT / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


batch = _load("batch", "batch.py")


def _run(monkeypatch, tmp_path, fail_on=None):
    out_file = tmp_path / "findings.json"
    calls = []

    def fake_probe(base, scenario):
        calls.append(scenario["id"])
        if fail_on and scenario["id"] == fail_on:
            raise RuntimeError("boom")
        return ("executed", [{"scenario_id": scenario["id"], "attack_type": "XSS",
                              "verified": True, "variant": 1, "variant_label": "probe"}])

    monkeypatch.setattr(batch, "wait_for_lab", lambda base, timeout=6.0: True)
    monkeypatch.setattr(batch, "probe_scenario", fake_probe)
    monkeypatch.setattr(batch, "run_converter", lambda *a, **k: 0)
    monkeypatch.setattr(batch, "log_draft_rounds", lambda *a, **k: 0)
    monkeypatch.setattr(batch, "PURPLE", tmp_path)

    # Loopback base: the S5 authorization gate lets the lab through (the
    # batch probe path is gated on its base, exactly like the engine).
    res = batch.run_batch("http://127.0.0.1:5000", only=["SCN-002", "SCN-005"],
                          out_file=out_file, do_warroom=False, launch_lab=False)
    return res, calls


def test_run_batch_publishes_running_to_done_progress(monkeypatch, tmp_path):
    res, calls = _run(monkeypatch, tmp_path)
    assert res["batch_id"].startswith("B-")
    assert calls == ["SCN-002", "SCN-005"]
    prog = json.loads((tmp_path / "batch-progress.json").read_text(encoding="utf-8"))
    assert prog["status"] == "done"
    assert prog["done"] == ["SCN-002", "SCN-005"]
    assert prog["total"] == 2
    assert prog["current"] is None, "current must clear after the last scenario"
    assert prog["base"] == "http://127.0.0.1:5000"


def test_run_batch_marks_failed_progress_on_exception(monkeypatch, tmp_path):
    try:
        _run(monkeypatch, tmp_path, fail_on="SCN-005")
    except RuntimeError:
        pass
    else:  # pragma: no cover - the fake must raise
        raise AssertionError("fake probe did not raise")
    prog = json.loads((tmp_path / "batch-progress.json").read_text(encoding="utf-8"))
    assert prog["status"] == "failed"
    assert prog["done"] == ["SCN-002"]
