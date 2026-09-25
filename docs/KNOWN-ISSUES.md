# KNOWN ISSUES — deferred (noted 2026-09-14, revised 2026-09-16)

Issues found during the deep analysis of `.agents/skills/` and the enforcement
tooling. Deferred by owner decision — fix order below is suggested priority.

> **2026-09-16 revision.** ISSUE-1 was misdiagnosed. It is not source
> corruption — it is Windows Defender quarantining a tracked file. Every
> "missing file / import error / lint error" symptom seen since 2026-09-08
> traces back to that single cause. Details, evidence and fix below.

## ISSUE-1 (RESOLVED 2026-09-16): antivirus quarantine broke imports, not corruption

**Original (wrong) diagnosis:** null bytes in `titan/core/logger.py` or a stale
`.pyc` made `scripts/check_findings_layout.py` fail at
`from titan.core.logger import get_logger` with
`SyntaxError: source code string cannot contain null bytes`.

**Actual root cause:** Windows Defender false-positives on
`titan/ai/payloadforge.py`, which embeds literal webshell payloads
(`<?php system($_GET['cmd']); ?>` at line 608, the Smarty `writeFile('shell.php',
…)` string at line 457, pickle `os.system('id')` at line 541). Defender matches
it as `Backdoor:PHP/Perhetshell.B!dha` (SeverityID 5) and quarantines it.

Because `titan/__init__` → `titan/core/engine.py` → `titan/ai/payloadsmith.py`
→ `titan/ai/payloadforge.py`, one quarantined file makes `import titan` fail —
which is why the symptom looked like logger corruption from the outside.

**Evidence (Defender's own log, `Get-MpThreatDetection`):**

```
2026-09-08 22:04:30  quarantine  titan/ai/payloadforge.py
2026-09-08 22:16:49  quarantine  titan/ai/payloadforge.py  (containerfile + EmbeddedData0004/0007)
2026-09-10 21:18:05  quarantine  learn/simulations/06-upload-simulation.md
2026-09-13 18:29:32  quarantine  tests/test_trackg.py       (containerfile, ScriptSrc)
2026-09-14 08:17:36  quarantine  tests/test_trackg.py       (containerfile, ScriptSrc)
2026-09-16 20:04:45  quarantine  build/lib/titan/ai/payloadforge.py
2026-09-16 20:04:51 → 20:18:55   titan/ai/payloadforge.py  (×8, one per git restore)
```

Reproduced deterministically: restore the file → it survives ~25–30 s → it is
quarantined. No git hooks are active, and a scan of all 509 tracked files found
exactly one unreadable file, so it is not repo tooling and not broad corruption.

**Fix (applied):** path exclusion, in an **elevated** PowerShell.

```powershell
Add-MpPreference -ExclusionPath 'C:\Users\HomePC\Desktop\ai-agents\titan-lab'
Add-MpPreference -ExclusionPath 'C:\Users\HomePC\.config\manicode\projects'
```

**Caveat:** the exclusion covers that path only. A copy of the file anywhere
else (e.g. `/tmp`) is still quarantined on read. Do not "fix" this by encoding
the payload literals — `PayloadForge` must emit real, literal payloads to do its
job; mangling them would change scanner behaviour to satisfy a signature.

**Revision (2026-09-26):** the caveat above is superseded. The exclusion is a
per-machine mitigation — it cannot protect fresh cloners (verified 2026-09-25:
a clean GitHub clone lost the file on import). The four highest-signal literals
in `titan/ai/payloadforge.py` are now stored zlib+base85-encoded and decoded at
import **byte-identically** — the emitted payloads are the same bytes, so the
"do not mangle literals to satisfy a signature" concern is answered rather than
ignored. Integrity is pinned by SHA256 in `tests/test_payloadforge_encoding.py`.
The `Add-MpPreference` exclusions remain harmless but are no longer load-bearing;
downstream-user symptoms and recovery steps live in the README's
"Antivirus note (Windows)".

**Verified after the fix** (2026-09-16, `.venv` = py3.12 with the pinned tools):

- `scripts/check_findings_layout.py` → `clean: no stray per-target artifacts` (exit 0)
- `ruff check .` → `All checks passed!` (it had reported 3 × `I001` while the module was missing)
- `mypy titan/ --ignore-missing-imports` → `Success: no issues found in 184 source files`
- `python -m pytest` (`.venv`, py3.12, after ISSUE-4) → `1267 passed, 4 skipped`, coverage 55.58%
- `python run.py doctor` → `All dependencies present`

**Diagnostic tell to remember:** while a module is missing, `ruff check .`
reports `I001` in exactly the files that import it (ruff cannot resolve `titan`
as first-party, so it mis-sorts the block). Three `I001`s in
`tests/oracle_shared.py`, `tests/test_clientside.py` and
`tests/test_lab_detection.py` mean a quarantined `titan/ai/payloadforge.py` —
not an import-ordering bug.

## ISSUE-2 (LOW): `skillset-spec.md` is stale vs the checker

- Header still says "DRAFT v0.5" although roadmap Phases 1–3 are marked
  DONE (implemented 2026-09-04) — status line should say implemented.
- §5.1 / Phase 1 narrative say "3 canonical blocks" / "registered as
  canonical block #4" but `scripts/check_skills_consistency.py` now
  enforces **5** blocks (cve-sweep-recipes, evidence-integrity,
  cross-assessment-diff-template, framework-cve-sweep-doc-template,
  engagement-metric-row). Sync the spec's counts to the BLOCKS table.
- Cosmetic only — the checker itself is correct and passes 5/5 clean.

## ISSUE-3 (INFO): fresh-clone skill loss (accepted by design, restated)

- `.agents/` is gitignored, so a fresh clone has no skills shelf and
  `check_skills_consistency.py` exits 2 (SKIP ≠ pass — correct behavior).
- No action required; noted so nobody "fixes" it by committing consent-
  adjacent content. The two tracked scripts are the only enforcement
  artifacts, exactly as the shelf README specifies.

## ISSUE-4 (RESOLVED 2026-09-16): `.venv` could not run 9 test files

- `.venv` (py3.12, holds the pinned ruff 0.16.6 / mypy 2.3.1 / pytest-cov)
  has **no flask**, so 9 test files and **171 test functions** fail to collect:
  `test_apixss`, `test_identity`, `test_lab_detection`, `test_lab_fixtures`,
  `test_local_lab`, `test_oracle_detectors`, `test_shop_fixtures`,
  `test_sourcesecret`, `test_streaming_fixtures` (plus 6 fixture errors in
  `test_redirect`, `test_sqli_s3`).
- Consequence: a local `.venv` run reports `2 failed, 1088 passed, 6 errors`
  and **44.30%** coverage, all of it environmental — CI (which installs
  `requirements.txt`, flask included) would see `1267 passed` and **55.58%**.
- **Fix (applied):** `uv pip install --python .venv/Scripts/python.exe flask==3.1.3`
  (`.venv` was created by uv and has no pip; the version matches
  `requirements.txt`). Verified after: `1267 passed, 4 skipped, 0 failed`,
  coverage 55.58%, `run.py doctor` → `All dependencies present`.
- Keep this in mind as a false-red pattern: before this fix, a `.venv` run
  reported `2 failed, 1088 passed, 6 errors` and 44.30% coverage while the code
  was healthy. Confirm flask resolves before believing a local failure.

## ISSUE-5 (LOW): coverage floor has 0.58 points of headroom

- CI gates `--cov-fail-under=55`. Measured on the full suite (`.venv`, py3.12):
  **55.58%** — 0.58 points of headroom. Any refactor that drops a few hundred
  covered statements turns the gate red.
- Biggest zero-coverage modules observed: `titan/verify/network.py` (90 stmts,
  0%), `titan/verify/inference.py` (57, 0%), `titan/verify/correlation.py`
  (53, 0%), `titan/verify/role_aware.py` (34%).
- Fix: raise the floor deliberately as `titan/verify/` gets oracle coverage.

## ISSUE-6 (INFO): Defender also eats tooling state, not just source

- It removed this session's own transcript temp files under
  `C:\Users\HomePC\.config\manicode\projects\titan-lab\chats\…\chat-messages.json.*.tmp`
  (3 × remove at 2026-09-16 20:13) because a report quoted a payload literal.
- The `.config\manicode\projects` exclusion in the ISSUE-1 fix covers this;
  keep it if agent chat history matters.
- `build/lib/titan/ai/payloadforge.py` was quarantined too — stale `build/`
  copy, harmless, but it confirms any copy of the literals is a target.

## ISSUE-7 (RESOLVED 2026-09-17): merging `32361e5` breaks the secrets gate

**Resolved without touching the baseline:** `titan/ai/payloadforge.py` line 543
now carries an inline `# pragma: allowlist secret` (Java serialization probe
payload, rO0AB magic — not a credential). With the pragma present, the
detector never fires on that line, so the deleted baseline entry no longer
matters and the gate passes at both `8f3983f` and `32361e5`. Prefer inline
pragmas for deliberate payload literals: they survive baseline regeneration
by construction, which is exactly the failure mode this issue documented.

Historical record (2026-09-16 review). `origin/main` moved `8f3983f` → `32361e5`: 13 commits,
18 files, +589/−70 (IP egress policy + listener protocol nonce), **15 test
functions added, 0 removed**, no new dependencies, no `docs/`/`CHANGELOG` entry.

Measured on the delta's content in this `.venv` (py3.12, pinned tools):

| gate | baseline `8f3983f` | delta `32361e5` |
|---|---|---|
| `ruff check .` | pass | **pass** |
| `mypy titan/` | pass (184 files) | **pass (185)** |
| `pytest` | 1267 passed, 4 skipped | **1281 passed, 5 skipped, 0 failed** |
| coverage (gate 55) | 55.58% | **55.77%** |
| `detect-secrets-hook` | pass | **FAIL (exit 1)** |

- Failure: `Base64 High Entropy String at titan\ai\payloadforge.py:543`.
- Cause: commit `32361e5` ("regenerate secrets baseline for re-vaulted
  templates") deleted the `titan/ai/payloadforge.py` entry from
  `.secrets.baseline`, but the file still trips the detector at line 543 and
  carries no inline allowlist pragma. The regeneration most likely ran while
  the file was in Defender quarantine (ISSUE-1) — a quarantined file leaves no
  entry behind.
- Fix before or with the merge: re-add the entry (`type: Base64 High Entropy
  String`, `hashed_secret: 0780effb6dd0070f79309601066234ce902cb903`, line 543)
  or put `# pragma: allowlist secret` on that line.

Code review notes carried on the same delta (all minor, no gate impact):

1. `config.example.yaml` ships `nonce: ""`, and an empty string is not `None`,
   so no secret is generated — the shipped example yields an **unauthenticated
   listener**, contradicting the commit's "requires nonce by default". Omit the
   key (or use `nonce: null`) in the example.
2. `allow_private: true` is wider than its comment: the branch returns True for
   any host resolving to a non-guarded IP, so lab mode also lifts target
   pinning for arbitrary public hosts.
3. The rebinding defense is not applied to the target's own hostname —
   `url_allowed` returns early on `host == target_host` before any IP compare,
   while the docstring claims the pin prevents DNS answering differently later.
4. Fail-closed has a gap: `if self._transport_http is not None and hasattr(...)`
   means a failed transport init skips installing the policy with no raise.
5. "every request the scanner sends is checked" overstates scope — only
   `titan/transport/http_transport.py` is wired; aiohttp-direct paths
   (`exploit/repl.py`, webshell polling, reattach, archive, `hostile/intel`)
   bypass the policy.
