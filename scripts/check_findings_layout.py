#!/usr/bin/env python3
"""Findings layout enforcement for Titan.

Ensures every per-target artifact lives under findings/<slug>/ and nothing
strays into the repo root or the findings root.

Run after ANY assessment (mandatory step in deep-audit / deep-attacker):
    python scripts/check_findings_layout.py

Exit code 0  = clean layout
Exit code 1  = violations found (each printed with a remediation hint)
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FINDINGS = os.path.join(ROOT, "findings")
CONSENT = os.path.join(ROOT, "consent")

# Files that legitimately live at the repo root or findings root.
ROOT_ALLOWLIST = {
    # repo-root infrastructure / tooling (not per-target artifacts)
    "arena.log", "arena_lab.log", "config.yaml", "config.example.yaml",
    "config.deep.yaml", "config.quick.yaml", "config.omega.yaml",
    "config.mkulima.yaml", "config.dt-hostile.yaml", "config.gv-hostile.yaml",
    "README.md", "REPRO.md", "SECURITY.md", "LICENSE", "pyproject.toml",
    "requirements.txt", "pytest.ini", "setup.py", "setup_linux.sh",
    "run.py", "provider.py", "tscan_cli.py", "tscan_entry.py",
    "titan_bench_cli.py", "titan_exploit_cli.py", "titan_fleet_cli.py",
    "titan_learn_cli.py", "titan_repl.py", "deep_verify.py",
    "discover_endpoints.py", "extract_bundle.py", "extract_keys.py",
    "find_secret.py",
    "firebase_probe.py", "firebase_rtdb_probe.py",
    "firebase_surface.py", "Dockerfile", "docker-compose.yml",
    "MANIFEST.in", "index.html", "img1.jpg", "img2.jpg", "_config.yml",
    ".env", ".env.example", ".gitignore", ".dockerignore", ".gitattributes",
    # NOTE: per-target tooling that previously leaked at the repo root now
    # lives in its own findings/<slug>/tools/ dir — if generic-named target
    # scripts reappear at the repo root, that is a leak and SHOULD be flagged.
}
FINDINGS_ALLOWLIST = {
    "sites.json",            # roster of audited targets
    "TRENDS.json",           # cross-target trend data
    "GAP-ANALYSIS.md",       # cross-target gap analysis
    "AUTHORIZED-PRACTICE.json",  # global practice ledger
    "scan_",                 # global scan records (prefix)
}

# Junk dirs created by Windows path mangling (literal "C:", "~", ...).
JUNK_DIRS = {"C:", "~"}

# Container dirs at findings root that hold per-program / sub-target artifacts
# rather than a single site slug (their children are still checked as subdirs).
CONTAINER_DIRS = {"bounties"}


def slug_from_consent(filename):
    """consent/<domain>.json -> slug (dots to dashes)."""
    stem = filename[:-5] if filename.endswith(".json") else filename
    return stem.replace(".", "-")


def load_slugs():
    slugs = set()
    if os.path.isdir(CONSENT):
        for f in os.listdir(CONSENT):
            if f.endswith(".json"):
                slugs.add(slug_from_consent(f))
    sites = os.path.join(FINDINGS, "sites.json")
    if os.path.isfile(sites):
        try:
            with open(sites, encoding="utf-8-sig") as fh:
                data = json.load(fh)
            for s in data.get("sites", []):
                if s.get("slug"):
                    slugs.add(s["slug"])
        except (json.JSONDecodeError, OSError):
            pass
    return slugs


def anchor_tokens(slugs):
    """Tokens that identify a per-target artifact filename.

    For slug 'example-com' we accept: 'example-com', 'example_com', and
    'example' (the artifact's own prefix). We generate the first-two-words
    prefix too so e.g. EXAMPLE-HOSTILE-LOG.* is caught.
    """
    tokens = set()
    for slug in slugs:
        tokens.add(slug.lower())
        tokens.add(slug.replace("-", "_").lower())
        parts = slug.split("-")
        if len(parts) >= 2:
            tokens.add("-".join(parts[:2]).lower())
        if len(parts) >= 1:
            tokens.add(parts[0].lower())
    return tokens


def is_stray(filename, tokens):
    low = filename.lower()
    if low in ROOT_ALLOWLIST or low in FINDINGS_ALLOWLIST:
        return False
    if low.startswith("scan_"):
        return False
    # A per-target artifact is one whose name starts with a slug token.
    for tok in sorted(tokens, key=len, reverse=True):
        if len(tok) >= 4 and low.startswith(tok):
            return True
    return False


def main():
    slugs = load_slugs()
    tokens = anchor_tokens(slugs)
    problems = []

    # 1. Repo root: stray per-target artifacts.
    for f in sorted(os.listdir(ROOT)):
        full = os.path.join(ROOT, f)
        if os.path.isfile(full) and is_stray(f, tokens):
            problems.append(
                f"STRAY  repo-root/{f}  -> belongs in findings/<slug>/ "
                f"(e.g. mv {f} findings/<slug>/)"
            )
        elif os.path.isdir(full) and f in JUNK_DIRS:
            problems.append(
                f"JUNK   repo-root/{f}/  Windows path-mangling artifact — "
                f"remove it (rm -rf {f}) if you confirm it's accidental"
            )

    # 2. Findings root: stray per-target artifacts (files only).
    if os.path.isdir(FINDINGS):
        for f in sorted(os.listdir(FINDINGS)):
            full = os.path.join(FINDINGS, f)
            if os.path.isfile(full) and is_stray(f, tokens):
                problems.append(
                    f"STRAY  findings/{f}  -> belongs in findings/<slug>/ "
                    f"(e.g. mv findings/{f} findings/<slug>/)"
                )

        # 3. Findings subdirs not in the roster (legacy / unknown slugs).
        for d in sorted(os.listdir(FINDINGS)):
            full = os.path.join(FINDINGS, d)
            if os.path.isdir(full) and d not in slugs and d not in CONTAINER_DIRS:
                problems.append(
                    f"UNKNOWN findings/{d}/  not in consent/sites.json roster — "
                    f"verify the slug or register it"
                )

    if problems:
        print(f"[check_findings_layout] {len(problems)} violation(s):")
        for p in problems:
            print("  - " + p)
        return 1

    print("[check_findings_layout] clean: no stray per-target artifacts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())