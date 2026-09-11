# Onboarding: first task = config validation

Welcome. Your first task is spec'd in `specs/config-validation-spec.md` —
read it fully before touching anything. This note covers the stuff that
isn't written anywhere else.

## Read order

1. `CONTRIBUTING.md` — setup, gates, commit rules. It is the law.
2. `specs/config-validation-spec.md` — your task, with design decisions
   already made. Don't relitigate them; if something in the spec conflicts
   with reality in the code, stop and ask.
3. `config.example.yaml` — the shape of the data you're validating.

## Step zero: make your own venv (before any `pip install`)

`pip install -r requirements.txt` only does the right thing inside a venv
created in this clone. Run it against a bare/global Python — or with another
project's venv still active on your PATH — and you get a broken hybrid:
packages silently resolve against a foreign site-packages and every later
command dies with `ModuleNotFoundError`. This exact failure happened on the
first external clone of this repo (a stale dependency pin also made the
install abort halfway on Windows Python 3.13/3.14; the pin is fixed, but the
venv rule stands on its own).

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

Sanity check before anything else — if this fails, the venv is not active or
the install did not finish; stop and fix that first:

```powershell
python -c "import titan; print('ok')"
```

## The rules that actually get enforced here

**One change, one commit, tests in the same commit.** The spec's §7 has your
five commits pre-planned — follow it. Your commits should carry your own git
identity (`git config user.name / user.email`), not anyone else's.

**Verify, then push. Every time.** The full gate from CONTRIBUTING, in
order, before any push:

```bash
ruff check .
mypy titan/ --ignore-missing-imports
python -m pytest tests/ -q
detect-secrets-hook --baseline .secrets.baseline $(git ls-files)
```

A push without a green local gate is how CI goes red and everyone loses an
hour. This rule exists because it was learned the hard way.

**Windows-specific (this repo is developed on Windows):**

- The venv interpreter is `venv/Scripts/python.exe`.
- Run `detect-secrets-hook` **after** `git add`, not before — it checks the
  staged tree.
- If the hook ever reports "The baseline file was updated... Please
  `git add .secrets.baseline`", do not just re-add and push. Regenerate the
  baseline (`detect-secrets scan $(git ls-files) > .secrets.baseline`) so
  path keys stay forward-slashed and line numbers match what CI's Linux
  runner sees. Cross-platform line-number drift has broken CI here before;
  the regeneration is the permanent fix.

## Traps specific to your task

- **Unknown config keys must pass through untouched.** Every shipped
  `config.*.yaml` profile has sections the schema doesn't model. If your
  validation drops or rejects them, real scans break. The spec's §5 tests 5
  and 7 exist to catch exactly this — write them first.
- **Check that code is actually wired before refactoring around it.** This
  repo has contained dead packages before (an entire module family was
  deleted for being never-imported). Grep for importers before assuming a
  caller exists.
- **Don't add dependencies beyond pydantic.** The manifests
  (`requirements.in`, `requirements.txt`, `uv.lock`, `pyproject.toml`) all
  need the pydantic entry in the same commit — all four, not one.

## When stuck

Ask. The spec was written so you shouldn't need to, but if reality
contradicts it, stop rather than improvise — a wrong validation layer on a
consent-gated scanner is worse than a late one.
