"""Consent ledger access for probes — DELEGATES to the strong gate.

SELF-AUDIT FIX (S2): this module previously verified consent by checking that
``signature`` / ``public_key`` fields merely EXIST in the JSON — presence, not
cryptography. Any file with those two keys passed ``load_consent`` +
``require_write``. It now delegates to ``titan.exploit.consent``, the same
ed25519 + trust-anchor-pinned gate that guards Track E exploitation:

    - signature is verified against the consent's embedded public key
    - that key must equal the operator's own keypair (~/.titan/consent.key)
    - scope (domain match), expiry, and per-flag capability checks apply

The probe scripts keep the same call shape (``load_consent`` /
``require_write`` / ``require_flag``) so their callers needed no changes;
only the enforcement underneath changed.

Usage:
    from consent import load_consent, require_write
    c = load_consent("repairai.co.ke")
    require_write(c, "for write probes")
"""
import json
import os
import sys
import time

# Anchor to the repo root (this file lives in <root>/scripts/audit/), so
# probes work from any CWD. Override with TITAN_CONSENT_DIR if needed.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CONSENT_DIR = os.environ.get("TITAN_CONSENT_DIR", os.path.join(_REPO_ROOT, "consent"))
# Same default keypair the exploit gate uses (~/.titan/consent.key); override
# with TITAN_CONSENT_KEY if the operator keeps it elsewhere.
_KEY_PATH = os.environ.get(
    "TITAN_CONSENT_KEY",
    os.path.join(os.path.expanduser("~"), ".titan", "consent.key"),
)


def slugify(target: str) -> str:
    return target.replace("https://", "").replace("http://", "").replace("/", "").replace(" ", "")


def consent_path(target: str) -> str:
    return os.path.join(CONSENT_DIR, slugify(target) + ".json")


def load_consent(target: str):
    """Return the verified consent dict or raise with a clear reason.

    Enforcement is the STRONG gate (titan.exploit.consent.verify_consent):
    signature verify, trust-anchor keypin, scope match, and expiry. A consent
    whose ``signature``/``public_key`` are mere strings will be REJECTED.
    """
    from titan.exploit.consent import ConsentError, verify_consent
    from pathlib import Path

    try:
        return verify_consent(
            target,
            consent_dir=Path(CONSENT_DIR),
            key_path=Path(_KEY_PATH),
        )
    except ConsentError as e:
        raise SystemExit(f"[consent] {e}")


def has_flag(c: dict, flag: str) -> bool:
    return flag in c.get("flags", [])


def require_write(c: dict, why: str):
    """Hard gate: no write probe runs without the write flag (on a VERIFIED consent)."""
    if not has_flag(c, "write"):
        raise SystemExit(
            f"[consent] {why} requires flags=['write'], but consent is "
            f"flags={c.get('flags')}. Ask the owner to upgrade: "
            "python titan_exploit_cli.py consent add <target> --write"
        )


def require_flag(c: dict, flag: str, why: str):
    if not has_flag(c, flag):
        raise SystemExit(
            f"[consent] {why} requires flags including '{flag}' "
            f"(have {c.get('flags')})."
        )


if __name__ == "__main__":
    # CLI: python consent.py <target> [--write]  → prints status, exit 0/1
    target = sys.argv[1] if len(sys.argv) > 1 else None
    if not target:
        raise SystemExit("usage: python consent.py <target> [--write]")
    c = load_consent(target)
    print(f"[consent] {target}: flags={c.get('flags')} "
          f"expires={c.get('expires_at')} signed={bool(c.get('signature'))}")
    if "--write" in sys.argv:
        require_write(c, "CLI check")
        print("[consent] write flag OK")
