"""Reusable audit probe library.

Each probe is self-contained (stdlib only), consent-gated, and prints
deterministic results a fresh session can act on. See each module's --help.

Conventions:
  - Every probe reads the consent ledger first (scripts/audit/consent.py).
  - Write probes use a marker string (default SECPROBE) for clean residue.
  - Read-only probes never touch state; write probes self-clean when the API
    allows and print exact residue otherwise.
"""
