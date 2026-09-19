"""Behaviour pin for ``titan/core/config_schema.py``.

Follows ``specs/config-validation-spec.md`` §5. The highest-value test here is
the one that validates the shipped ``config.example.yaml`` (and every other
shipped profile): it permanently pins the real config files as valid, so a
future schema change that would reject a real config fails here first instead of
on an operator's machine.
"""

import sys
from pathlib import Path

import pytest
import yaml

import run as runner
from titan.core.config_schema import ConfigValidationError, validate_config

ROOT = Path(__file__).resolve().parents[1]
SHIPPED_PROFILES = sorted(ROOT.glob("config*.yaml"))


@pytest.fixture(autouse=True)
def _clean_argv():
    """Restore the real argv after each test (same pattern as test_run_cli)."""
    yield
    sys.argv = ["run.py"]


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


# --- 1. real config files must validate ------------------------------------


def test_example_config_validates():
    out = validate_config(_load(ROOT / "config.example.yaml"))
    assert out["crawl"]["profile"] == "fast"


@pytest.mark.parametrize("path", SHIPPED_PROFILES, ids=lambda p: p.name)
def test_every_shipped_profile_validates(path):
    """No shipped profile may be rejected, and none may lose a section."""
    data = _load(path)
    out = validate_config(data)
    assert out["crawl"]["profile"] in ("fast", "deep", "hostile")
    assert set(data) <= set(out), "a top-level section was dropped"


# --- 2. enums --------------------------------------------------------------


def test_unknown_crawl_profile_raises_naming_the_field():
    with pytest.raises(ConfigValidationError) as exc:
        validate_config({"crawl": {"profile": "depp"}})
    message = str(exc.value)
    assert "profile" in message
    assert "depp" in message


@pytest.mark.parametrize("bad", ["passve", "offensive", ""])
def test_unknown_aggression_raises(bad):
    with pytest.raises(ConfigValidationError):
        validate_config({"aggression": bad})


@pytest.mark.parametrize("bad", ["chromium", "firefox", ""])
def test_unknown_browser_raises(bad):
    with pytest.raises(ConfigValidationError):
        validate_config({"browser": bad})


@pytest.mark.parametrize("good", ["passive", "active", "aggressive", "hostile"])
def test_known_aggression_values_pass(good):
    assert validate_config({"aggression": good})["aggression"] == good


# --- 3. numeric bounds -----------------------------------------------------


@pytest.mark.parametrize(
    "crawl",
    [
        {"max_pages": 0},
        {"max_pages": -1},
        {"timeout": 0},
        {"timeout": -5},
        {"max_depth": -1},
        {"max_apis": -1},
    ],
)
def test_out_of_range_bounds_raise(crawl):
    with pytest.raises(ConfigValidationError):
        validate_config({"crawl": crawl})


@pytest.mark.parametrize("jitter", [-0.1, 10.1, 99])
def test_stealth_jitter_bounds_raise(jitter):
    with pytest.raises(ConfigValidationError):
        validate_config({"stealth": {"jitter": jitter}})


@pytest.mark.parametrize(
    "crawl",
    [{"max_pages": 1}, {"timeout": 1}, {"max_depth": 0}, {"max_apis": 0}],
)
def test_boundary_values_are_accepted(crawl):
    validate_config({"crawl": crawl})


# --- 4. wrong types --------------------------------------------------------


@pytest.mark.parametrize(
    "crawl",
    [{"max_pages": "lots"}, {"timeout": "soon"}, {"max_apis": [1]}, {"max_pages": 2.5}],
)
def test_wrong_type_raises(crawl):
    with pytest.raises(ConfigValidationError):
        validate_config({"crawl": crawl})


# --- 5 + 7. unknown keys pass through untouched ----------------------------


def test_unknown_top_level_key_passes_through():
    out = validate_config({"brand_new_section": {"x": 1}})
    assert out["brand_new_section"] == {"x": 1}


def test_unmodeled_section_survives_byte_identical():
    section = {"enabled": True, "nested": {"a": [1, 2]}}
    assert validate_config({"governance": section})["governance"] == section


def test_unknown_keys_inside_a_modeled_section_pass_through():
    crawl = {"profile": "fast", "spa": {"enabled": True}, "module_concurrency": 8}
    out = validate_config({"crawl": crawl})
    assert out["crawl"]["spa"] == {"enabled": True}
    assert out["crawl"]["module_concurrency"] == 8


# --- 6. defaults -----------------------------------------------------------


def test_defaults_are_filled():
    out = validate_config({})
    assert out["aggression"] == "passive"
    assert out["crawl"]["profile"] == "fast"
    assert out["headless"] is True
    assert out["exploit"]["enabled"] is False
    assert out["exploit"]["consent_dir"] == "consent"
    assert out["output_dir"] == "findings"


# --- profile-aware crawl keys stay the engine's business -------------------


def test_profile_aware_keys_left_absent_when_unset():
    """The engine defaults these from the profile, so we must not fill them.

    ``titan/core/engine.py`` uses 5 pages for fast but 20 for deep/hostile, and
    a 90/300s crawl timeout. A flat default here would silently override that.
    """
    crawl = validate_config({"crawl": {"profile": "deep"}})["crawl"]
    assert "max_pages" not in crawl
    assert "max_depth" not in crawl
    assert "timeout" not in crawl


def test_profile_aware_keys_kept_when_explicitly_set():
    crawl = validate_config({"crawl": {"profile": "deep", "max_pages": 50, "max_depth": 3, "timeout": 120}})["crawl"]
    assert crawl["max_pages"] == 50
    assert crawl["max_depth"] == 3
    assert crawl["timeout"] == 120


# --- 8. integration with the existing CLI override layer -------------------


def test_cli_overrides_still_apply_after_validation():
    sys.argv = ["run.py", "--exploit"]
    cfg = runner.apply_cli_overrides(validate_config({"target": "http://x"}))
    assert cfg["exploit"]["enabled"] is True


def test_validation_preserves_a_target_so_the_cli_layer_sees_it():
    out = validate_config({"target": "http://x"})
    assert out["target"] == "http://x"
