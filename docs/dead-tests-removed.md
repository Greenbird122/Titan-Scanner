# Dead Tests Removed in v0.1.0

These test files reference modules that were planned but never implemented. They cause collection errors and should not block CI or confuse users.

## Removed test files

| Test file | Missing dependency | Status |
|---|---|---|
| `tests/test_arena.py` | `purple/arena/engine.py` | Feature never built |
| `tests/test_arena_grounding.py` | `purple/arena/` modules | Feature never built |
| `tests/test_arena_ui.py` | `purple/arena/` modules | Feature never built |
| `tests/test_batch.py` | `purple/batch.py` | Feature never built |
| `tests/test_live.py` | `purple/batch.py` | Feature never built |
| `tests/test_scoreboard.py` | `purple/scoreboard.py` | Feature never built |
| `tests/test_warroom.py` | `purple/warroom.py` | Feature never built |

**Removal date:** 2026-08-27
**Removed in:** v0.1.0
**Reason:** These tests reference a "battle arena / scoreboard" feature that was specified but never implemented. They cause pytest collection errors (`FileNotFoundError`) and mask real test failures.

**Reinstatement condition:** If the `purple/` modules are ever implemented, these tests should be restored and updated.

## Pre-existing test collection issues (not removed)

| Test file | Issue | Status |
|---|---|---|
| `tests/test_lab_detection.py` | `ModuleNotFoundError: No module named 'jwt'` | Environment issue — `PyJWT` not installed in test venv |
| `tests/test_lab_fixtures.py` | Same `jwt` import error | Environment issue |
| `tests/test_shop_fixtures.py` | Same `jwt` import error | Environment issue |
| `tests/test_streaming_fixtures.py` | Same `jwt` import error | Environment issue |
| `tests/test_live.py` | `FileNotFoundError` | Pre-existing broken test |

These are **environment/dependency issues**, not dead code. They fail because the test venv is missing `PyJWT`, not because the referenced modules don't exist. Fix: install `PyJWT` in the test environment.

