"""Secrets-hygiene pin: the lab must never ship the old hardcoded secret key.

Regression guard for the DataFactor remediation pass: the committed
``"supersecretkey"`` literal was replaced with an env-driven value
(``LOCAL_LAB_SECRET_KEY``) falling back to a random per-boot token. If
someone re-adds the literal to committed source, this test fails.
"""
import sys
from pathlib import Path

LAB_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(LAB_ROOT))

from local_lab import app as lab  # noqa: E402


def test_secret_key_is_not_the_old_literal():
    """The old hardcoded literal must not appear as the app's secret key."""
    assert lab.app.secret_key != "supersecretkey"


def test_secret_key_is_populated():
    """With no env var set, the random per-boot fallback still yields a key."""
    assert lab.app.secret_key