# Contributing to Titan Scanner

Thanks for helping build Titan. This document describes how to set up a
development environment and the standards every change is held to.

## Development setup

```bash
git clone https://github.com/Greenbird122/Titan-Scanner.git
cd Titan-Scanner

python -m venv venv
source venv/bin/activate        # Windows: venv/Scripts/activate

pip install -r requirements.txt
pip install -e .
playwright install chromium     # browser automation for scans and some tests
```

Copy `config.example.yaml` to `config.yaml` and `.env.example` to `.env` for
local configuration. Never commit either file.

## Running the tests

```bash
python -m pytest tests/ -q --cov=titan --cov-report=term --cov-fail-under=55
```

The suite must pass with coverage at or above the 55% floor, and it must do so
**fully offline**: no external accounts, no network access, no API keys. An
autouse guard in `tests/conftest.py` blocks any non-loopback socket from every
test (if a test genuinely needs the internet, mark it
`@pytest.mark.allow_network` — and expect scrutiny). `tests/test_offline_guard.py`
pins the guard itself. The only local dependency a test may need is the
deliberately vulnerable lab, `python local_lab/app.py` (loopback-bound); no
external service — no live target, no Ollama, no DeepSeek key — is ever required
 to pass the suite.

## Pre-push checklist

CI (`.github/workflows/tests.yml`) runs all of this on every push; run it
locally first:

```bash
ruff check .
mypy titan/ --ignore-missing-imports
detect-secrets-hook --baseline .secrets.baseline $(git ls-files)
python -m pytest tests/ -q
```

All four must be green. If `detect-secrets-hook` flags a line and it is a
false positive (test fixture, honeypot bait), mark it inline with
`# pragma: allowlist secret` and refresh the baseline in the same commit.

Do **not** refresh it with `detect-secrets scan > .secrets.baseline`. That mode
takes a fresh snapshot, so every entry it does not re-find is silently deleted,
and it records paths with the current host's separator. Use the supported path:

```bash
python scripts/secrets_baseline.py check       # scan-free canonical check
python scripts/secrets_baseline.py regenerate  # merges; refuses to drop entries
```

## Commit conventions

- One logical change per commit, with its tests in the same commit.
- Short, specific messages: `feat(graphql): ...`, `fix(engine): ...`,
  `docs: ...`, `refactor: ...`, `test: ...`.
- No formatting-only churn mixed into functional commits.
- New attack-surface code needs tests pinning its behavior, including the
  negative cases (what must *not* be flagged).

## Project rules

- **Consent gating is not optional.** Active scanning and exploitation stay
  behind signed consent enforcement. Do not weaken scope checks or the
  verification layer's evidence grading.
- **Findings need proof.** Detectors should flag on typed evidence (differentials,
  content leaks, parser errors), not on payload reflection alone.
- **Secrets stay out.** Credentials come from environment variables; see
  `.env.example`. Never hardcode key-like strings outside clearly marked
  fixtures.

## Reporting vulnerabilities in Titan

Do not open a public issue. Follow the disclosure process in
[SECURITY.md](SECURITY.md) via GitHub's private vulnerability reporting.
