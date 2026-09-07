# Titan remediation spec — DataFactor findings, zero regression gate

**Audience:** the operator (Greenbird), executed by the next agent session.
**Prerequisite:** no rewrite of working modules; only targeted edits + new files.
**Gate:** the existing pytest suite must still pass after every step, unless the
step explicitly adds or modifies a test and that test passes instead.

## What this spec fixes

It addresses the DataFactor assessment without touching any behavior that already
works. The three things it is allowed to change are:

1. **Secrets hygiene (high impact, reputational)** — remove the hardcoded-looking
   secret strings from committed source so a security tool does not ship its own
   apparent credentials.
2. **Reproducible installs (high impact, CI + fresh-clone)** — commit a lockfile
   and make the install path verify-clean.
3. **Engineering hygiene that raises the score without touching scan logic**
   — split the two 1000+ LOC files, make mypy gate instead of advisory, add a
   structured logger used by `engine.py`, fix `.env.example`, add SECURITY.md.

Everything else in the report (CI caching, test ratio, module layout, history
shape) stays as-is or is noted as future work at the end.

## Non-negotiable: what must not break

- `titan/core/engine.py` scan orchestration, transport init, scope, auth, report
  writing — behavior preserved.
- `titan/ai/adaptive.py` payload analysis, WAF fingerprints, dialect detection —
  behavior preserved.
- `titan/transport/*`, `titan/modules/*`, `titan/verify/*`, `titan/reporting/*` —
  untouched unless a step names a file explicitly.
- The local vulnerable lab (`local_lab/`) remains a deliberately vulnerable Flask
  app; only the `_secret_key` source changes.
- `deep_verify.py` and `firebase_probe.py` remain functional probes; only the
  hardcoded key literal is replaced with an environment-only contract.

## Step 0 — verify current baseline before touching anything

Run once, save the result mentally or in a scratch file:

```bash
python -m pytest tests/ -q --timeout=120 -p no:cacheprovider
ruff check .
mypy titan/ --ignore-missing-imports
wc -l titan/core/engine.py titan/ai/adaptive.py
git status --short
```

Expected: existing suite green or with only the pre-existing known failures; both
target files over 1000 LOC; no staged secrets.

## Step 1 — remove the four committed secret-looking literals (high impact)

**Files:**

- `local_lab/app.py`
- `deep_verify.py`
- `firebase_probe.py`
- `firebase_rtdb_probe.py`
- `firebase_surface.py`

**Edits:**

1. `local_lab/app.py` — replace
   `app.secret_key = "supersecretkey"` with
   ```python
   app.secret_key = os.environ.get("LOCAL_LAB_SECRET_KEY", secrets.token_hex(16))
   ```
   and add `import secrets` near the top if it is not already present. This keeps
   the lab runnable with zero config and removes the literal from committed source.

2. `deep_verify.py`, `firebase_probe.py`, `firebase_rtdb_probe.py`, `firebase_surface.py`
   — ensure the Firebase key is read exclusively from the environment. The current
   files already do `os.environ.get("FIREBASE_API_KEY", "")` in the probe entrypoints,
   so the change here is defensive and documentary:
   - add a module-level note that the key must be supplied via env, not committed;
   - if any file currently contains a literal `AIzaSy...` string anywhere, replace it
     with a placeholder comment or remove it;
   - keep the existing `FIREBASE_API_KEY not set` guard behavior.

**Tests to add:**

- `tests/test_local_lab.py` — one assertion that `local_lab.app.app.secret_key` is
  not the literal `"supersecretkey"` after import. This pins the fix so it cannot
  quietly regress.

**Verification after step 1:**

```bash
grep -RIn "supersecretkey\|AIzaSy" titan local_lab deep_verify.py firebase_probe.py firebase_rtdb_probe.py firebase_surface.py
python -m pytest tests/test_local_lab.py -q
```

Goal: zero matches for the literal strings in committed source; new test passes.

**Do not do in this step:**

- Do not delete `local_lab/app.py` or rename its endpoints.
- Do not change `deep_verify.py`'s intercept replay behavior.
- Do not alter the consent/ownership model of the Firebase probes.

## Step 2 — commit a lockfile and pin runtime deps (high impact)

**Current state:** `pyproject.toml` declares the package manifest; `requirements.txt`
pins only `playwright==1.49.1` and leaves `aiohttp`, `pyyaml`, `requests`, `flask`,
`PyJWT`, `cryptography`, `pytest`, `pytest-asyncio` unpinned.

**Choice to make once, then commit:**

Use **one** lockfile strategy and stick to it:

- **If you want simplest:** generate a fully pinned `requirements.txt` from
  `requirements.in` via `pip-compile`, commit it, and keep `pyproject.toml` as the
  metadata/manifest file.
- **If you want the toolchain already declared:** run `poetry lock`, commit
  `poetry.lock`, and treat `pyproject.toml` as the source of truth.

Either way, the committed artifact must:

- pin every runtime dependency to an exact version;
- be the file that a fresh clone installs from in CI;
- resolve cleanly with `pip install -r requirements.txt` or `poetry install`.

**CI alignment:**

Update `.github/workflows/tests.yml` install steps to install from the committed
lockfile rather than from the unpinned `requirements.txt`. Keep the existing
`pip install -e .` so the package remains editable in CI.

**Dependency bot (from DataFactor feedback email):** add `.github/dependabot.yml`
configuring the pip ecosystem on a weekly schedule, so the lockfile stays
current without manual tracking.

**Secret scanning (from DataFactor feedback email):** add a CI step running
`pip install detect-secrets && detect-secrets scan` in the lint job of
`.github/workflows/tests.yml` (or a pre-commit hook), so a re-introduced
literal fails the build instead of silently shipping again.

**Verification after step 2:**

```bash
# From a clean venv, with no network assumptions beyond what the lockfile needs:
python -m venv /tmp/titan-lock-check
source /tmp/titan-lock-check/bin/activate
pip install -r requirements.txt        # or: poetry install
python -m pytest tests/ -q --timeout=120 -p no:cacheprovider
```

Goal: fresh-clone install succeeds and the suite still passes.

**Do not do in this step:**

- Do not remove `pyproject.toml`.
- Do not introduce a second competing lockfile.
- Do not change dependency versions just to make the lockfile look newer; pin what
  currently resolves.

## Step 3 — split the two god files (medium impact, no behavior change)

This step is optional per session if time is short, but it is the single biggest
code-cleanliness win on the report.

### 3a. `titan/core/engine.py` — extract transport methods

**Current:** `_ensure_transport` and `_transport_send` live inline in
`TitanEngine`.

**Extraction:**

- create `titan/core/transport_mixin.py` with those two methods and any small
  helpers they need;
- import it into `TitanEngine` via mixin inheritance or direct import, whichever
  matches the existing style;
- keep the public surface identical: `engine._ensure_transport()` and
  `engine._transport_send(...)` must still exist and behave the same.

**Target:** `titan/core/engine.py` drops below 800 LOC without losing behavior.

### 3b. `titan/ai/adaptive.py` — extract WAF profile dictionaries

**Current:** `ResponseAnalyzer` owns large dictionaries
(`WAF_RULE_PATTERNS`, `WAF_FINGERPRINT_PAYLOADS`, `ERROR_DIALECT_PATTERNS`) inline.

**Extraction:**

- create `titan/ai/waf_profiles.py` with those dictionaries and any closely related
  constants;
- have `ResponseAnalyzer` import from there;
- keep the analyzer’s public API identical.

**Target:** `titan/ai/adaptive.py` drops below 800 LOC without losing behavior.

**Tests to add or update:**

- `tests/test_engine_transport.py` — cover the extracted transport helpers directly.
- `tests/test_waf_profiles.py` — cover the extracted WAF/dialect constants directly.

If those test files already exist, extend them; if they do not, create them as thin
coverage for the extracted modules.

**Verification after step 3:**

```bash
wc -l titan/core/engine.py titan/ai/adaptive.py
python -m pytest tests/test_engine_transport.py tests/test_waf_profiles.py tests/ -q --timeout=120 -p no:cacheprovider
```

Goal: both files under 800 LOC; full suite still green.

## Step 4 — make mypy gate instead of advisory (medium impact, CI truth)

**Current:** `.github/workflows/tests.yml` runs
`mypy titan/ --ignore-missing-imports` with `continue-on-error: true`.

**Edits:**

1. Fix the mypy errors that exist today, module by module, in small batches.
   Start with the modules that are already clean-ish, then move to the noisier ones.
   Each batch should be its own commit if it is more than a trivial pass.
2. Once `mypy titan/ --ignore-missing-imports` is clean locally, remove
   `continue-on-error: true` from the mypy step in `tests.yml`.

**Do not do in this step:**

- Do not silence real type errors with broad `# type: ignore` dumps.
- Do not weaken `pyproject.toml` mypy settings to make CI green.
- Do not touch runtime logic just to satisfy mypy unless the typing is genuinely
  wrong.

**Verification after step 4:**

```bash
mypy titan/ --ignore-missing-imports
# then push a branch and let CI run, or run the workflow locally with act if available
```

Goal: CI mypy step fails on a real type error and passes on the current code.

## Step 5 — structured logging for engine ops (medium impact, no scan logic loss)

**Current:** `titan/core/engine.py` emits operational status via `print(...)`.
The DataFactor feedback email names three files: `titan/core/engine.py`,
`titan/core/waf.py`, and `titan/reporting/__init__.py`.

**Edits:**

1. Create `titan/core/logging_setup.py` with:
   - a `get_logger(name)` helper;
   - a basic JSON or structured formatter configured once at import time;
   - sane defaults so existing modules do not need a big setup dance.
2. In `titan/core/engine.py`, replace the operational `print(...)` calls that report
   transport readiness, scan lifecycle, page processing progress, and report write
   status with `logger.info` / `logger.warning` calls from the new helper.
3. Apply the same migration to the operational prints in `titan/core/waf.py` and
   `titan/reporting/__init__.py` where they report scan/verification progress.
4. Leave CLI-facing output alone where it is intentionally human-readable; this step
   is about *operational* signals, not about silencing every print in the project.

**Tests to add:**

- `tests/test_logging_setup.py` — assert that a sample log call emits a record with
   the expected level and structured fields.

**Verification after step 5:**

```bash
grep -RIn "^print(" titan/core/engine.py
python -m pytest tests/test_logging_setup.py tests/ -q --timeout=120 -p no:cacheprovider
```

Goal: the operational print calls in `engine.py` are gone or intentionally migrated,
and the new logger test passes.

## Step 6 — complete `.env.example` and add SECURITY.md (low impact, credibility)

### 6a. `.env.example`

**Edit:** add the env vars that source actually reads but `.env.example` currently
omits:

- `FIREBASE_API_KEY=`
- `FIREBASE_PROJECT=`

with short placeholder comments explaining their use.

**Verification:**

```bash
# Confirm no source env var is missing from the example:
# (adjust the grep pattern to match however the codebase reads env vars)
grep -RhoP '(?<=os.environ\[)[A-Z_]+' titan local_lab deep_verify.py firebase_probe.py firebase_rtdb_probe.py firebase_surface.py \
  | sort -u > /tmp/used_envs.txt
grep -RhoP '^[A-Z_]+=' .env.example | cut -d= -f1 | sort -u > /tmp/example_envs.txt
comm -23 /tmp/used_envs.txt /tmp/example_envs.txt
```

Goal: the diff is empty or only contains vars that are genuinely optional and
documented as such.

### 6b. `SECURITY.md`

**Create:** `SECURITY.md` at repo root with at least:

- a short description of what Titan is;
- the disclosure email or contact path you actually want researchers to use;
- the consent/ownership model in one paragraph;
- what is in scope vs out of scope for testing Titan itself;
- a one-paragraph threat model (what Titan assumes about its operator, target
  consent, and network position — requested by DataFactor under
  "Secrets & Threat Modeling");
- a note that findings are stored locally under `findings/` and are not committed.

Keep it short. This is a hygiene doc, not a handbook.

### 6c. `README.md` (from DataFactor feedback email)

- Add an **Architecture** section (4-6 sentences) describing the module layout:
  `titan/core` (engine/crawl), `titan/modules` (attack detectors),
  `titan/ai` (payload mutation), `titan/verify` (evidence grading).
- Make the test command explicit (`python -m pytest tests/ -q`) so a fresh clone
  can verify the suite from the README alone.

## Step 7 — commit discipline, then re-score

**Commit shape:**

- Each step above should land as one or more small, named commits.
- Prefer: one commit per file group or per distinct fix.
- Do not bundle secrets cleanup + lockfile + god-file split + mypy + logging into one
  giant commit. That is exactly the “large mixed commit” the report penalizes.

**Recommended commit sequence:**

1. `fix(local_lab): read secret key from env, remove hardcoded literal`
2. `fix(deep-verify): load Firebase key from env only`
3. `test(local_lab): assert app secret key is not the old literal`
4. `build: commit pinned lockfile and install from it in CI`
5. `refactor(core): extract transport helpers into transport_mixin`
6. `refactor(ai): extract WAF profile data into waf_profiles`
7. `test: add coverage for extracted transport and WAF profile modules`
8. `ci(tests): make mypy a gating step after cleaning current errors`
9. `refactor(core): replace engine print ops with structured logger`
10. `test: add logging_setup coverage`
11. `docs: complete .env.example and add SECURITY.md`

**After commit:**

```bash
python -m pytest tests/ -q --timeout=120 -p no:cacheprovider
ruff check .
mypy titan/ --ignore-missing-imports
git status --short
git log --oneline -20
```

Then push and re-submit to DataFactor when ready.

## Optional future work, not part of this pass

Leave these for later unless a session explicitly picks them up:

- Enforce a coverage threshold in CI.
- Reduce the remaining 500+ LOC files beyond the two biggest.
- Add dependabot or renovate for automated dependency updates.
- Split or slim additional large modules if they become maintenance pain.
- Build a more deliberate commit cadence so the history stops looking like a single
  burst.

## Success criteria for this spec

- Committed source contains no `supersecretkey` literal and no hardcoded
  `AIzaSy...` Firebase key string.
- `local_lab/app.py`, `deep_verify.py`, and the Firebase probes still function as
  before, reading secrets from the environment.
- A fresh clone can install from a committed lockfile and pass the suite.
- `titan/core/engine.py` and `titan/ai/adaptive.py` are both under 800 LOC.
- `mypy titan/ --ignore-missing-imports` is clean and is a gating CI step.
- `titan/core/engine.py` operational status uses the structured logger.
- `.env.example` lists every env var used in source.
- `SECURITY.md` exists.
- The existing test suite still passes throughout.

That is the whole spec. Sleep first; the next agent session can pick it up from
Step 0.
