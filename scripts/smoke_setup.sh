#!/usr/bin/env bash
# Fresh-clone smoke test: prove install, build, and test work end to end on a
# machine that has never seen this repository.
#
# Used by the `fresh-clone-smoke` CI job (no pip cache, fresh venv). Run it
# locally the same way:  bash scripts/smoke_setup.sh
#
# Exits non-zero on any failure so CI fails loudly instead of silently.

set -euo pipefail

COVERAGE_FLOOR="${COVERAGE_FLOOR:-45}"

python -m venv .venv-smoke
# shellcheck disable=SC1091
source .venv-smoke/bin/activate

trap 'rm -rf .venv-smoke' EXIT

python -m pip install --upgrade pip
pip install -r requirements.txt   # committed, pinned lockfile
pip install -e .
pip install pytest-timeout pytest-cov

echo "==> Running the full suite with coverage floor ${COVERAGE_FLOOR}%"
python -m pytest tests/ -q --timeout=120 -p no:cacheprovider \
    --cov=titan --cov-report=term --cov-fail-under="${COVERAGE_FLOOR}"