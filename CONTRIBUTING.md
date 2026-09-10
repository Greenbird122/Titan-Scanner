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
python -m pytest tests/ -q --cov=titan --cov-report=term --cov-fail-under=45
```

The suite must pass with coverage at or above the 45% floor. Tests that need
a real browser or network are marked/skipped accordingly — do not add tests
that reach live hosts.

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
