"""S5 — hard authorization gate for the read-only scan path.

The scanner's active-probe and exploitation paths were already consent-gated
(``titan.exploit.consent``), but the read-only crawl + detector matrix ran
against ANY host. That design hole is what let the autonomous arena crawl
third-party properties (instagram.com, google.com, recordedfuture.com, ...)
with no authorization record. This module closes it.

A target may be scanned — read-only or active — only when ONE of:

  1. it is loopback (the operator's own machine: local lab, unit tests),
  2. a signed, unexpired consent file covers it
     (``titan.exploit.consent``: ed25519 + keypin + scope + expiry), or
  3. its host is listed on the authorized-practice manifest
     (``findings/AUTHORIZED-PRACTICE.json`` — training platforms whose own
     terms authorize offensive practice).

The gate is FAIL-CLOSED: a missing/unreadable manifest authorizes nothing,
and a missing/unreadable/expired consent authorizes nothing.

Enforced in ``TitanEngine.scan()`` (the run.py / fleet / bench choke point)
and ``purple/batch.py run_batch`` (the arena's probe path, which its API can
point at arbitrary hosts).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Set
from urllib.parse import urlparse

# Project root (titan/core/authorization.py -> titan/ -> repo root). Manifest
# paths in config are resolved against this so the gate works regardless of
# the caller's cwd (run.py from root, self-audit suite from findings/...).
REPO_ROOT = Path(__file__).resolve().parent.parent.parent

DEFAULT_PRACTICE_MANIFEST = "findings/AUTHORIZED-PRACTICE.json"

# The operator's own machine — always authorized. This is what keeps the
# local lab (127.0.0.1:5000) and unit-test targets scannable without ceremony.
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _host_of(target: str) -> str:
    return (urlparse(target).hostname or "").lower().rstrip(".")


def resolve_manifest(manifest_path: Optional[str] = None) -> Path:
    """Resolve a configured manifest path to an absolute one (fail-closed)."""
    p = Path(manifest_path) if manifest_path else Path(DEFAULT_PRACTICE_MANIFEST)
    if not p.is_absolute():
        p = REPO_ROOT / p
    return p


def practice_hosts(manifest_path: Optional[str] = None) -> Set[str]:
    """Hostnames from the authorized-practice manifest.

    Returns an empty set on ANY failure (missing file, unreadable, bad JSON,
    wrong shape) — the gate must never authorize a host because the manifest
    was malformed.
    """
    p = resolve_manifest(manifest_path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 - fail closed on any read/parse error
        return set()
    if isinstance(data, dict):
        hosts = data.get("hosts", [])
    elif isinstance(data, list):
        hosts = data
    else:
        return set()
    out: Set[str] = set()
    for h in hosts:
        h = str(h).strip().lower().rstrip(".")
        if h:
            out.add(h)
    return out


def host_is_practice(host: str, hosts: Set[str]) -> bool:
    """Host matches a manifest entry exactly or as a subdomain."""
    host = (host or "").lower().rstrip(".")
    if not host or not hosts:
        return False
    return host in hosts or any(host.endswith("." + h) for h in hosts)


def authorize_target(
    target: str,
    consent_dir: str = "consent",
    practice_manifest: Optional[str] = None,
    key_path: Optional[str] = None,
) -> Optional[str]:
    """Return None if scanning ``target`` is authorized, else a denial reason.

    Consent lookup uses ``titan.exploit.consent.verify_consent`` (ed25519 +
    keypin + scope + expiry). ``key_path`` defaults to the operator's own
    keypair (~/.titan/consent.key), which is what the CLI signs with; tests
    pass a temp key.
    """
    from titan.exploit.consent import DEFAULT_KEY_PATH, verify_consent

    host = _host_of(target)
    if not host:
        return f"target {target!r} has no resolvable hostname"
    if host in LOOPBACK_HOSTS:
        return None
    try:
        verify_consent(
            target,
            consent_dir=consent_dir,
            key_path=Path(key_path) if key_path else DEFAULT_KEY_PATH,
        )
        return None
    except Exception:  # noqa: BLE001 - any consent failure = not authorized
        pass
    if host_is_practice(host, practice_hosts(practice_manifest)):
        return None
    return (
        f"scan denied: no signed consent for {host} and host is not on the "
        f"authorized-practice manifest. Run: "
        f"titan_exploit_cli.py consent add {target}"
    )
