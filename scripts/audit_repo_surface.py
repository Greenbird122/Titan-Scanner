#!/usr/bin/env python3
"""Audit tracked repo surface for engagement-specific leaks.

Scans all git-tracked files for patterns that should never appear in a public
repository: target domains, bounty-platform usernames, CDP ports, and
engagement-specific identifiers. Run before every push.

Exit code 0 = clean
Exit code 1 = leaks found
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Engagement-specific patterns that must not appear in tracked files.
LEAK_PATTERNS = [
    # CDP ports used in engagement scripts
    (re.compile(r"9222|9223|9224|9225"), "CDP debug port"),
    # HackerOne / Bugcrowd usernames
    (re.compile(r"HackerOne-[A-Za-z0-9_]+|bugcrowd[A-Za-z0-9_]*", re.IGNORECASE), "bounty platform username"),
    # Known target domains from engagements
    (
        re.compile(
            r"humo\.be|varonis\.io|parool\.nl|devolkskrant\.nl|demorgen\.be|trouw\.nl|ad\.nl|rtlnieuws\.nl",
            re.IGNORECASE,
        ),
        "engagement target domain",
    ),
    # Engagement output paths
    (re.compile(r"findings/bounties/(humo|varonis|dpg|parool)", re.IGNORECASE), "engagement output path"),
    # Specific engagement identifiers
    (re.compile(r"humo_|varonis_|dpg_cross_brand|H1-auth-helper", re.IGNORECASE), "engagement script prefix"),
]

# Files/directories that are allowed to contain these patterns because they are
# either public infrastructure or intentionally public.
ALLOWLIST_PATHS = {
    ".gitignore",
    "SECURITY.md",
    "README.md",
    "MARKET-SCAN.md",
    "LEARNINGS.md",
    "scripts/audit_repo_surface.py",
    # Lockfiles and scanner-internal references that legitimately contain
    # port numbers or API path fragments used as test fixtures.
    "uv.lock",
    "titan/modules/logic/probes.py",
}


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [ROOT / line for line in result.stdout.splitlines() if line]


def is_allowed(path: Path) -> bool:
    rel = path.relative_to(ROOT)
    as_str = str(rel)
    # Normalize to forward slashes for matching across platforms.
    as_str = as_str.replace("\\", "/")
    for allowed in ALLOWLIST_PATHS:
        allowed_norm = allowed.replace("\\", "/")
        if as_str == allowed_norm or as_str.startswith(allowed_norm):
            return True
    return False


def scan() -> list[tuple[Path, int, str, str]]:
    findings: list[tuple[Path, int, str, str]] = []

    for path in tracked_files():
        if not path.is_file():
            continue
        if is_allowed(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for pattern, label in LEAK_PATTERNS:
            for m in pattern.finditer(text):
                line_no = text[: m.start()].count("\n") + 1
                findings.append((path, line_no, label, m.group(0)))

    return findings


def main() -> int:
    findings = scan()
    if not findings:
        print("[audit_repo_surface] clean: no engagement leaks found in tracked files.")
        return 0

    print(f"[audit_repo_surface] {len(findings)} potential leak(s) found:\n")
    for path, line_no, label, match in findings:
        rel = path.relative_to(ROOT)
        print(f"  {rel}:{line_no}  [{label}]  matched: {match!r}")

    print("\nIf any of these are false positives, add the file to ALLOWLIST_PATHS in scripts/audit_repo_surface.py.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
