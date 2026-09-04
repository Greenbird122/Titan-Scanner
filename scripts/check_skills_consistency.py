#!/usr/bin/env python3
"""Skills shelf consistency enforcement for Titan.

Ensures every canonical reference block (authored once) still matches its
embedded copies inside the per-skill self-contained references (deep-audit
canonical -> deep-attacker embedded copies).

Why this exists: skills are per-skill self-contained by policy, so shared
content (recipe sets, template shapes) is duplicated deliberately. The
duplication is only safe while a checker proves the copies did not drift.

    python scripts/check_skills_consistency.py

Exit code 0  = every canonical block matches its embedded copy
Exit code 1  = drift / missing anchors / missing markers (each printed)

Adding a new shared block:
  1. Author the block once in its canonical home (the skill that owns the
     topic, e.g. deep-audit/references/...).
  2. Embed a verbatim copy in each consuming skill's own references, wrapped
     in markers:
         <!-- skill-copy: <id> (canonical: <relative/path>) -->
         ...verbatim block...
         <!-- /skill-copy: <id> -->
  3. Add a BLOCKS entry below (canonical file + start/end anchors).

Not drift-checked (by design): core-principle statements that each skill
restates in its OWN voice (e.g. the Ground-Truth rule) — those are
intentionally voice-native, not verbatim copies, and are covered by the
skills' coverage-diff validation instead.
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS = os.path.join(ROOT, ".agents", "skills")


def _path(*parts):
    return os.path.join(SKILLS, *parts)


# Each entry: one canonical block + one embedded copy.
#   id             marker id used in the copy file
#   canonical      file that owns the block (authorship home)
#   start_anchor   first line of the canonical block (stripped-prefix match)
#   end_anchor     first line AFTER the block (exclusive); None = to EOF
#   copy           file containing the embedded copy (self-contained skill)
BLOCKS = [
    {
        "id": "cve-sweep-recipes",
        "canonical": _path("deep-audit", "references", "probe-techniques.md"),
        "start_anchor": "## 7. Framework CVE sweep (hunt the class, not the repo)",
        "end_anchor": None,
        "copy": _path("deep-attacker", "references", "cve-sweep.md"),
    },
    {
        "id": "cross-assessment-diff-template",
        "canonical": _path("deep-audit", "references", "report-templates.md"),
        "start_anchor": "## 6. `CROSS-ASSESSMENT-DIFF-<date>.md`",
        "end_anchor": "## 7. Findings hygiene",
        "copy": _path("deep-attacker", "references", "report-template.md"),
    },
    {
        "id": "framework-cve-sweep-doc-template",
        "canonical": _path("deep-audit", "references", "report-templates.md"),
        "start_anchor": "## 8. `FRAMEWORK-CVE-SWEEP-<date>.md`",
        "end_anchor": "## 9. Engagement metric row",
        "copy": _path("deep-attacker", "references", "report-template.md"),
    },
    {
        "id": "engagement-metric-row",
        "canonical": _path("deep-audit", "references", "report-templates.md"),
        "start_anchor": "## 9. Engagement metric row",
        "end_anchor": None,
        "copy": _path("deep-attacker", "references", "report-template.md"),
    },
]

OPEN_RE = re.compile(r"<!--\s*skill-copy:\s*([\w-]+)")
CLOSE_RE = re.compile(r"<!--\s*/skill-copy:\s*([\w-]+)")


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _normalize(text):
    """Collapse all whitespace runs to one space; strip. CRLF-safe."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return re.sub(r"\s+", " ", text).strip()


def extract_canonical(cfg):
    """Slice the canonical block out of its file by start/end anchors."""
    text = _read(cfg["canonical"])
    lines = text.split("\n")
    start = end = None
    for i, line in enumerate(lines):
        if line.strip().startswith(cfg["start_anchor"]):
            start = i
            break
    if start is None:
        return None, f"start anchor not found: {cfg['start_anchor']!r}"
    if cfg["end_anchor"]:
        for i in range(start + 1, len(lines)):
            if lines[i].strip().startswith(cfg["end_anchor"]):
                end = i
                break
        if end is None:
            return None, f"end anchor not found: {cfg['end_anchor']!r}"
    return "\n".join(lines[start:end]), None


def extract_copy(cfg):
    """Slice the embedded copy out of its file by open/close markers."""
    text = _read(cfg["copy"])
    open_line = close_line = None
    for i, line in enumerate(text.split("\n")):
        m = OPEN_RE.search(line)
        if m and m.group(1) == cfg["id"]:
            open_line = i
        m = CLOSE_RE.search(line)
        if m and m.group(1) == cfg["id"]:
            close_line = i
    if open_line is None:
        return None, f"open marker not found: skill-copy {cfg['id']!r}"
    if close_line is None:
        return None, f"close marker not found: skill-copy {cfg['id']!r}"
    if close_line <= open_line:
        return None, "close marker precedes open marker"
    lines = text.split("\n")
    return "\n".join(lines[open_line + 1:close_line]), None


def check_block(cfg):
    """Return (ok, message). Compares normalized canonical vs copy text."""
    canonical, err = extract_canonical(cfg)
    if err:
        return False, f"{cfg['canonical']}: {err}"
    copy, err = extract_copy(cfg)
    if err:
        return False, f"{cfg['copy']}: {err}"
    if _normalize(canonical) == _normalize(copy):
        return True, None
    return False, (
        f"{cfg['copy']} drifted from canonical {cfg['canonical']} — "
        f"re-embed the canonical block and re-run."
    )


def main():
    problems = []
    ok_count = 0
    for cfg in BLOCKS:
        ok, msg = check_block(cfg)
        if ok:
            ok_count += 1
            continue
        problems.append(f"{cfg['id']}: {msg}")
    if problems:
        print(
            f"[check_skills_consistency] {len(problems)} drift violation(s) "
            f"({ok_count}/{len(BLOCKS)} blocks match):"
        )
        for p in problems:
            print("  - " + p)
        return 1
    print(
        f"[check_skills_consistency] clean: {ok_count} canonical blocks "
        f"match their embedded copies."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
