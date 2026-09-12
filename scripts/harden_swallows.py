#!/usr/bin/env python
"""Harden silent exception swallowing: convert `except: pass/continue` blocks
into `logger.debug(...)` + pass/continue.

Behavior-preserving: control flow is untouched (pass/continue stay), only a
diagnostic log line is added and the exception is bound. Run per-file or over
the whole tree:

    python scripts/harden_swallows.py titan/core/engine.py
    python scripts/harden_swallows.py --all
    python scripts/harden_swallows.py --dry-run titan/core/engine.py

When the tree is clean, remove S110/S112 from pyproject.toml [tool.ruff.lint]
ignore and `ruff check .` must pass.
"""

from __future__ import annotations

import ast
import pathlib
import re
import sys

EXCEPT_RE = re.compile(r"^( *)(except(?: [^:#]*)?):(?: #.*)?$")
PASS_OR_CONTINUE = ("pass", "continue")


def module_name(path: str) -> str:
    return pathlib.Path(path).stem


def has_module_logger(lines: list[str]) -> bool:
    return any(re.match(r"^logger = get_logger\(", ln) for ln in lines)


def transform(path: str, dry_run: bool = False) -> int:
    src = open(path, encoding="utf-8").read()
    lines = src.split("\n")

    # locate silent-swallow blocks
    targets: list[
        tuple[int, int, str | None, str, str | None]
    ] = []  # (except_idx, body_idx, except_new, kind, bound_name)
    i = 0
    while i < len(lines):
        m = EXCEPT_RE.match(lines[i])
        if m:
            indent, _ = m.groups()
            j = i + 1
            while j < len(lines) and (not lines[j].strip() or lines[j].strip().startswith("#")):
                j += 1
            if j < len(lines):
                body = lines[j]
                body_kind = body.strip().split("#", 1)[0].strip()  # drop trailing comments
                if body_kind in PASS_OR_CONTINUE and body[: len(body) - len(body.lstrip())] == indent + "    ":
                    kind = body_kind
                    clause = m.group(2)  # 'except' or 'except <types>'
                    types = clause[len("except") :].strip()
                    if " as " in types:
                        # already bound (e.g. `except X as e:`); keep the
                        # handler, log via the existing bound name
                        bound = types.rsplit(" as ", 1)[1].strip()
                        targets.append((i, j, None, kind, bound))
                    elif types:
                        targets.append((i, j, indent + f"except {types} as exc:", kind, None))
                    else:
                        targets.append((i, j, indent + "except BaseException as exc:", kind, None))
                    i = j + 1
                    continue
        i += 1

    if not targets:
        return 0

    if dry_run:
        print(f"{path}: {len(targets)} block(s) would be transformed")
        return len(targets)

    # 1. ensure module logger
    if not has_module_logger(lines):
        # Use AST for import boundaries: line-based heuristics break on
        # multiline imports (e.g. `from x import (\n  a,\n)`).
        tree = ast.parse(src)
        imps = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
        assert imps, f"{path}: no top-level imports to anchor the logger"
        first_imp = min(n.lineno for n in imps) - 1  # 0-based index
        last_imp_end = max(n.end_lineno for n in imps)  # 1-based line; 0-based index == value

        name = module_name(path)
        lines.insert(last_imp_end, "")
        lines.insert(last_imp_end, f'logger = get_logger("{name}")')
        lines.insert(last_imp_end, "")
        lines.insert(first_imp, "from titan.core.logger import get_logger")
        lines.insert(first_imp, "")
        # re-index targets: 3 inserts after last_imp_end, 2 inserts before first_imp
        shift = 3 + 2
        targets = [(a + shift, b + shift, ne, k, bd) for a, b, ne, k, bd in targets]

    # 2. rewrite blocks (walk backwards so indices stay valid)
    for a, b, new_except, kind, bound in sorted(targets, reverse=True):
        msg = "variant failed, continuing" if kind == "continue" else "suppressed exception"
        if new_except is None:
            new_except = lines[a].rstrip()  # keep original `except X as e:` line
            indent = new_except[: len(new_except) - len(new_except.lstrip())]
        else:
            indent = new_except[: len(new_except) - len(new_except.lstrip())]
        ref = bound if bound else "exc"
        log_line = f'{indent}    logger.debug(f"{msg}: {{{ref}}}")'
        lines[a] = new_except
        lines.insert(a + 1, log_line)
        # body line (pass/continue) shifts down by 1

    open(path, "w", encoding="utf-8", newline="\n").write("\n".join(lines))
    print(f"{path}: {len(targets)} block(s) hardened")
    return len(targets)


def audit(path: str) -> int:
    """Count remaining silent-swallow blocks (matches ruff S110/S112: any
    exception handler whose body is only `pass` or `continue`)."""
    try:
        tree = ast.parse(open(path, encoding="utf-8").read())
    except SyntaxError:
        return -1
    count = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            for h in node.handlers:
                stmts = [
                    s
                    for s in h.body
                    if not (
                        isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and isinstance(s.value.value, str)
                    )
                ]
                if len(stmts) == 1 and isinstance(stmts[0], (ast.Pass, ast.Continue)):
                    count += 1
    return count


def main() -> None:
    args = sys.argv[1:]
    dry_run = "--dry-run" in args
    args = [a for a in args if a != "--dry-run"]

    if not args:
        print(__doc__)
        sys.exit(1)

    if args == ["--all"]:
        skip = {".git", "build", "node_modules", "__pycache__", "findings", "consent", "titan_logs"}
        paths = sorted(
            str(p)
            for p in pathlib.Path(".").rglob("*.py")
            if not any(part in skip or part.lstrip(".").startswith("venv") for part in p.parts) and audit(str(p)) > 0
        )
    else:
        paths = args

    total = 0
    for p in paths:
        n = transform(p, dry_run=dry_run)
        total += n
        if not dry_run:
            remaining = audit(p)
            assert remaining == 0, f"{p}: {remaining} block(s) still silent after transform"
    print(f"TOTAL: {total} block(s) {'would be' if dry_run else 'hardened'}")


if __name__ == "__main__":
    main()
