#!/usr/bin/env python3
"""Platform-safe regeneration and verification for .secrets.baseline.

Why this exists
---------------
The command historically documented in .github/workflows/tests.yml and
CONTRIBUTING.md was:

    detect-secrets scan > .secrets.baseline

That is the **fresh snapshot** mode (`baseline.create(...)` with no baseline
imported). It re-catalogs only what the local tree currently yields, so every
entry the local scan does not reproduce is **silently deleted**. That is how the
`titan/ai/payloadforge.py` entry disappeared and how the Linux lint job went red:
the pre-commit hook then reported a still-present secret as *new*.

A second hazard is cross-platform drift. detect-secrets records paths using the
native separator of whichever machine generated the file, so a Windows
regeneration rewrites every key and the committed file churns — and hand-editing
that churn is what dropped the entry in the first place.

Use this script instead:

    python scripts/secrets_baseline.py check          # fast gate (CI + pre-push)
    python scripts/secrets_baseline.py check --deep   # also verify convergence
    python scripts/secrets_baseline.py regenerate     # rewrite, refusing loss

`regenerate` scans exactly the git-tracked files from the repository root,
imports settings from the existing baseline and merges (`scan --baseline`, which
is additive), canonicalises every path to POSIX separators, and **refuses to
write if any previously catalogued finding would be dropped** unless `--force`
is given. It is therefore safe to run on Windows, macOS or Linux.

`check` fails if the committed baseline is not canonical; with `--deep` it also
fails when a finding present in the tree is absent from the baseline.

Exit codes: 0 ok, 1 policy failure, 2 internal error.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import shutil
import subprocess
import sys
from typing import Any

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(ROOT, ".secrets.baseline")

# The baseline must never be scanned for secrets: it stores hashed secrets and
# high-entropy digests by design. The pre-commit hook gets that exclusion from
# the baseline's own `is_baseline_file` filter, so we simply leave it out of the
# file list.
SELF_NAME = ".secrets.baseline"

# Scratch copy handed to the merge scan; relative so the tool records relative
# paths rather than absolute host-specific ones.
TMP_NAME = SELF_NAME + ".regen"

# The filter that stops the baseline being scanned for secrets in its own right.
BASELINE_FILTER = "detect_secrets.filters.common.is_baseline_file"

Finding = tuple[str, str]  # (type, hashed_secret) — mirrors PotentialSecret.fields_to_compare
ByFile = dict[str, set[Finding]]


def die(msg: str, code: int = 2) -> int:
    print(f"[secrets-baseline] ERROR: {msg}")
    return code


def canon(path: Any) -> str:
    """Canonical (POSIX) form of a path."""
    return str(path).replace("\\", "/")


def load_baseline() -> dict[str, Any]:
    with open(BASELINE, encoding="utf-8") as fh:
        return json.load(fh)


def tracked_files() -> list[str]:
    """Git-tracked files, minus the baseline itself (NUL-separated: space-safe)."""
    proc = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        capture_output=True,
        text=False,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git ls-files failed: {proc.stderr.decode('utf-8', 'replace').strip()}")
    names = [n for n in proc.stdout.decode("utf-8").split("\0") if n]
    files = [n for n in names if canon(n) != SELF_NAME]
    if not files:
        raise RuntimeError("git ls-files returned no files; refusing to scan an empty set")
    return files


def run_scan(extra: list[str]) -> dict[str, Any]:
    """Scan the tracked files from the repo root and return detect-secrets' JSON.

    Paths are passed explicitly rather than relying on the default directory
    walk: that keeps the file set identical to the pre-commit hook's
    `$(git ls-files)`, and the bare directory form is dramatically slower here.
    """
    cmd = [
        sys.executable,
        "-m",
        "detect_secrets",
        "scan",
        *extra,
        *tracked_files(),
    ]
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"detect-secrets scan exited {proc.returncode}\n{proc.stderr.strip()}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"scan did not emit JSON ({exc}); stderr: {proc.stderr.strip()[:400]}") from exc


def merged_scan() -> dict[str, Any]:
    """Re-catalog the tracked files with the existing baseline merged in.

    `detect-secrets scan --baseline <file>` has no stdout: it imports settings
    from <file>, merges the findings, and writes the result **back into <file>**,
    recording paths with the host's native separator. Pointing that at the real
    baseline is therefore what degrades a committed file when it runs on
    Windows. We hand it a throwaway copy instead and keep full control of the
    canonical form we commit.
    """
    tmp_abs = os.path.join(ROOT, TMP_NAME)
    shutil.copyfile(BASELINE, tmp_abs)
    try:
        cmd = [
            sys.executable,
            "-m",
            "detect_secrets",
            "scan",
            "--baseline",
            TMP_NAME,
            *tracked_files(),
        ]
        proc = subprocess.run(
            cmd,
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"detect-secrets scan --baseline exited {proc.returncode}\n{proc.stderr.strip()}")
        with open(tmp_abs, encoding="utf-8") as fh:
            return json.load(fh)
    finally:
        if os.path.exists(tmp_abs):
            os.remove(tmp_abs)


def findings_of(data: dict[str, Any]) -> ByFile:
    """Map canonical path -> {(type, hashed_secret)}."""
    out: ByFile = {}
    for key, items in (data.get("results") or {}).items():
        bucket = out.setdefault(canon(key), set())
        for item in items:
            bucket.add((str(item.get("type", "")), str(item.get("hashed_secret", ""))))
    return out


def flatten(by_file: ByFile) -> set[tuple[str, str, str]]:
    return {(path, kind, digest) for path, bag in by_file.items() for (kind, digest) in bag}


def canonicalise(data: dict[str, Any]) -> dict[str, Any]:
    """Return a POSIX-canonical **copy** of a baseline document.

    Only the per-finding `filename` fields under `results` are rewritten.
    `filters_used` is configuration, not findings: normalising the
    `is_baseline_file` filter's `filename` would repoint it at whatever scratch
    file the scan happened to use (an absolute, host-specific path). That filter
    is pinned to the repo-relative baseline name so the document is identical on
    every platform.

    The input is never mutated, so callers can inspect the original after this
    returns (an earlier version mutated in place, which silently suppressed the
    non-canonical report).
    """
    out = copy.deepcopy(data)

    rebuilt: dict[str, list[dict[str, Any]]] = {}
    for key, items in (out.get("results") or {}).items():
        bucket = rebuilt.setdefault(canon(key), [])
        seen = {(str(i.get("type", "")), str(i.get("hashed_secret", ""))) for i in bucket}
        for item in items:
            if "filename" in item:
                item["filename"] = canon(item["filename"])
            sig = (str(item.get("type", "")), str(item.get("hashed_secret", "")))
            if sig not in seen:
                seen.add(sig)
                bucket.append(item)
    out["results"] = rebuilt

    for entry in out.get("filters_used") or []:
        if entry.get("path") == BASELINE_FILTER and "filename" in entry:
            entry["filename"] = SELF_NAME

    return out


def non_canonical(data: dict[str, Any]) -> list[str]:
    """Anything in the document that is not platform-independent."""
    offenders: list[str] = []
    for key, items in (data.get("results") or {}).items():
        if "\\" in key:
            offenders.append(f"path key: {key}")
        for item in items:
            name = str(item.get("filename", ""))
            if "\\" in name:
                offenders.append(f"{key} -> filename: {name}")
    for entry in data.get("filters_used") or []:
        if entry.get("path") == BASELINE_FILTER:
            name = str(entry.get("filename", ""))
            if name != SELF_NAME:
                offenders.append(f"{BASELINE_FILTER} -> filename: {name!r} (expected {SELF_NAME!r})")
    return offenders


def write_baseline(data: dict[str, Any]) -> None:
    """Write canonically, preserving the file's existing trailing-newline state."""
    newline = ""
    if os.path.exists(BASELINE):
        with open(BASELINE, "rb") as fh:
            if fh.read().endswith(b"\n"):
                newline = "\n"
    tmp = BASELINE + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as fh:
        fh.write(json.dumps(data, indent=2) + newline)
    os.replace(tmp, BASELINE)


def cmd_check(args: argparse.Namespace) -> int:
    if not os.path.exists(BASELINE):
        return die(f"{BASELINE} not found", 1)

    committed = load_baseline()

    offenders = non_canonical(committed)
    if offenders:
        print(f"[secrets-baseline] FAIL: {len(offenders)} non-canonical path(s) in .secrets.baseline")
        for line in offenders[:10]:
            print(f"    {line}")
        if len(offenders) > 10:
            print(f"    ... and {len(offenders) - 10} more")
        print("    A regeneration on a non-POSIX host rewrote these. Fix:")
        print("    python scripts/secrets_baseline.py regenerate")
        return 1

    if not args.deep:
        print(
            f"[secrets-baseline] OK: .secrets.baseline is canonical "
            f"({len(committed.get('results') or {})} file(s)); run with --deep to verify convergence."
        )
        return 0

    try:
        scanned = run_scan([])
    except RuntimeError as exc:
        return die(str(exc))

    base = flatten(findings_of(canonicalise(committed)))
    live = flatten(findings_of(scanned))

    missed = sorted(live - base)
    stale = sorted(base - live)

    if missed:
        print(f"[secrets-baseline] FAIL: {len(missed)} finding(s) in the tree but absent from the baseline")
        for path, kind, _ in missed[:10]:
            print(f"    NEW    {path}  [{kind}]")
        if len(missed) > 10:
            print(f"    ... and {len(missed) - 10} more")
        print("    Mark a genuine false positive with `# pragma: allowlist secret`, else run:")
        print("    python scripts/secrets_baseline.py regenerate")
        return 1

    if stale:
        # Not fatal: the pre-commit hook trims these itself and fails its own step.
        print(f"[secrets-baseline] WARN: {len(stale)} stale baseline entr(y/ies) no longer found in the tree")
        for path, kind, _ in stale[:10]:
            print(f"    STALE  {path}  [{kind}]")
        print("    The hook trims these on the next run and asks you to `git add .secrets.baseline`.")

    print(f"[secrets-baseline] OK: baseline canonical and converged ({len(base)} entries).")
    return 0


def cmd_regenerate(args: argparse.Namespace) -> int:
    if not os.path.exists(BASELINE):
        return die(f"{BASELINE} not found; refusing to create a baseline by surprise", 1)

    before_data = load_baseline()
    offenders = non_canonical(before_data)
    before = flatten(findings_of(canonicalise(before_data)))

    try:
        # Merges the current baseline in, so previously catalogued findings
        # survive the re-catalog instead of being silently dropped.
        merged = canonicalise(merged_scan())
    except RuntimeError as exc:
        return die(str(exc))

    after = flatten(findings_of(merged))
    added = sorted(after - before)
    removed = sorted(before - after)

    for path, kind, _ in added:
        print(f"    ADDED    {path}  [{kind}]")
    for path, kind, _ in removed:
        print(f"    REMOVED  {path}  [{kind}]")

    if removed and not args.force:
        return die(
            f"{len(removed)} finding(s) would be dropped from the baseline; refusing to write.\n"
            "           Dropping a finding that still exists upstream is what broke CI before.\n"
            "           Re-run with --force only after verifying each removal is intentional."
        )

    write_baseline(merged)
    print(
        f"[secrets-baseline] Wrote {BASELINE}\n"
        f"    canonicalised {len(offenders)} path(s); added {len(added)}; removed {len(removed)}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command")

    p_check = sub.add_parser("check", help="verify the committed baseline")
    p_check.add_argument(
        "--deep",
        action="store_true",
        help="also scan the tree and verify every finding is catalogued (slower)",
    )
    p_check.set_defaults(func=cmd_check)

    p_regen = sub.add_parser("regenerate", help="rewrite the baseline without silently losing entries")
    p_regen.add_argument(
        "--force",
        action="store_true",
        help="allow entries to be dropped (default: refuse)",
    )
    p_regen.set_defaults(func=cmd_regenerate)

    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
