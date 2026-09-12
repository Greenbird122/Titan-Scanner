#!/usr/bin/env python3
"""Fast repo metrics — LOC, god files, test ratio. No traversal of venvs/caches.

    python scripts/repo_metrics.py [--threshold 500] [--top 15]

Exists because ad-hoc `find | xargs wc -l` is unusably slow on this repo
(multiple virtualenvs), and because third-party code valuations should be
checkable against the actual tree rather than trusted.
"""
import argparse
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PRUNE = {
    "venv", ".venv", "venv_linux", ".git", "__pycache__", ".mypy_cache",
    ".ruff_cache", ".pytest_cache", "build", "dist", "node_modules",
    ".dsk_undo", ".tmp_pp", ".tmp_pq", "titan_scanner.egg-info",
}


def walk():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in PRUNE and not d.endswith(".egg-info")]
        for fn in filenames:
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)


def count_lines(path):
    try:
        with open(path, "rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threshold", type=int, default=500)
    ap.add_argument("--top", type=int, default=15)
    ap.add_argument("--path", default=None, help="limit to a subtree, e.g. titan")
    args = ap.parse_args()

    prefix = None
    if args.path:
        prefix = os.path.abspath(os.path.join(ROOT, args.path)) + os.sep

    rows, total = [], 0
    for path in walk():
        if prefix and not path.startswith(prefix):
            continue
        n = count_lines(path)
        total += n
        rows.append((n, os.path.relpath(path, ROOT).replace(os.sep, "/")))

    over = sorted([r for r in rows if r[0] > args.threshold], reverse=True)
    tests = [r for r in rows if r[1].startswith("tests/") and os.path.basename(r[1]).startswith("test_")]
    src = [r for r in rows if not r[1].startswith("tests/")]

    print(f"python files          : {len(rows)}")
    print(f"total python LOC      : {total}")
    print(f"source files / LOC    : {len(src)} / {sum(r[0] for r in src)}")
    print(f"test files / LOC      : {len(tests)} / {sum(r[0] for r in tests)}")
    if tests and src:
        print(f"test:source file ratio: 1:{len(src)/len(tests):.1f}")
    print(f"files > {args.threshold} LOC        : {len(over)}")
    print(f"\ntop {args.top}:")
    for n, p in over[:args.top] or sorted(rows, reverse=True)[:args.top]:
        print(f"  {n:5d}  {p}")


if __name__ == "__main__":
    main()
