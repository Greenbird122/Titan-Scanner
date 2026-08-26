"""CLI override tests for run.py's Track E flags.

`apply_cli_overrides` layers `--exploit` / `--exploit-listener-start` /
`--consent-dir` onto the loaded config. The consent gate itself is enforced
later in the planners — this pins the flag plumbing only.
"""

import sys

import pytest

import run as runner


@pytest.fixture(autouse=True)
def _clean_argv():
    """Restore the real argv after each test."""
    yield
    sys.argv = ["run.py"]


def test_no_flags_leaves_config_untouched():
    sys.argv = ["run.py"]
    cfg = {"target": "http://x"}
    assert runner.apply_cli_overrides(cfg) == cfg
    assert "exploit" not in cfg


def test_exploit_flag_enables_phase():
    sys.argv = ["run.py", "--exploit"]
    cfg = runner.apply_cli_overrides({})
    assert cfg["exploit"]["enabled"] is True


def test_listener_start_implies_enabled():
    sys.argv = ["run.py", "--exploit-listener-start"]
    cfg = runner.apply_cli_overrides({})
    assert cfg["exploit"]["enabled"] is True
    assert cfg["exploit"]["listener"]["start"] is True


def test_consent_dir_override():
    sys.argv = ["run.py", "--consent-dir", "my-consents"]
    cfg = runner.apply_cli_overrides({})
    assert cfg["exploit"]["consent_dir"] == "my-consents"
    # A consent-dir override alone must not enable the phase.
    assert cfg["exploit"].get("enabled") is None


def test_listener_start_keeps_existing_consent_dir():
    sys.argv = ["run.py", "--exploit-listener-start", "--consent-dir", "c2"]
    cfg = runner.apply_cli_overrides({"exploit": {"consent_dir": "kept"}})
    # --consent-dir wins over the config value.
    assert cfg["exploit"]["consent_dir"] == "c2"
    assert cfg["exploit"]["enabled"] is True
    assert cfg["exploit"]["listener"]["start"] is True
