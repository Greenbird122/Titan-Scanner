# Spec: Validate `config.yaml` before the engine starts

**Goal:** close DataFactor's `input_validation_patterns: empty` flag with a real
safety feature — Titan currently fails *silently* on misconfigured scans
(typo `crawl.profile: "depp"` quietly degrades to the fast profile; a negative
`timeout` is accepted and does who-knows-what downstream).

**Scope guard for the implementer:** this is an evening-sized task. The model
covers the sections listed below and nothing more. Do not enumerate every leaf
of every config section — that turns this into a week and breaks configs for
no gain. Unknown keys pass through untouched, by design.

---

## 1. Current state (verified facts, with references)

| Fact | Location |
|---|---|
| Loader does `yaml.safe_load(f) or {}` — zero validation | `run.py:39-43` |
| Loaded dict goes straight into `TitanEngine(config)` | `run.py:222-231` (`main()`) |
| Engine reads `config.get("crawl", {})`, then `profile`, `max_pages`, `max_apis`, `max_depth` | `titan/core/engine.py:68-77` |
| Legal crawl profiles are exactly `fast`, `deep`, `hostile` (anything else silently means fast) | `engine.py:70-71` |
| `aggression` defaults to `"passive"`, passed to governance approval as free text | `engine.py:147`, `titan/integrations/titan_gov.py:9` |
| Config sections the engine/core actually read: `aggression, ai, auth, clientside, crawl, governance, output_dir, proxy, reporting, stealth, exploit, modules, cloud, subdomain_takeover, llm, fleet, deep_audit, brain, headless, browser, browser_profile` | `git grep -o 'config.get("[a-z_]*"' titan/core/` |
| **pydantic is NOT currently a dependency** (0 hits in `requirements.in` and `uv.lock`) | — |
| Existing CLI-override tests use plain dicts, no YAML | `tests/test_run_cli.py` (5 tests, all on `apply_cli_overrides`) |
| There is **no** `titan/core/errors.py`; exception lives in the new module | — |

## 2. Design decisions (already made — follow them)

1. **pydantic v2** (`pydantic>=2.7,<3`). It gives typed models, precise error
   messages, and matches what static scanners grep for at input boundaries.
   Do not use `pydantic-settings` — config comes from YAML, not env.
2. **New module `titan/core/config_schema.py`.** Do not create a root
   `config.py` (nothing imports one today; the loader lives in `run.py`).
3. **Two severity tiers:**
   - **Hard fail** (`ConfigValidationError`): wrong types, negative/zero
     numeric bounds, unknown enum values (`crawl.profile`, `aggression`,
     `browser`).
   - **Warning only**: unknown top-level keys and unknown keys inside modeled
     sections. Configs carry many optional sections; rejecting unknown keys
     breaks forward compatibility for zero benefit. Use `extra="allow"`.
4. **Pure entry point:** `validate_config(data: dict) -> dict` — takes the
   parsed YAML dict, returns a normalized dict (defaults filled), raises
   `ConfigValidationError` on hard-fail problems. YAML reading stays in
   `run.py`. This keeps the whole thing unit-testable without files.
5. **Exception:** `class ConfigValidationError(ValueError)` — subclass
   `ValueError` so any existing broad handling keeps working. Its `str()`
   must contain every error with field path and the offending value
   (pydantic's built-in formatted error list is fine).
6. **Wiring point:** `load_config()` in `run.py` — validate *before*
   `apply_cli_overrides()` and before anything touches the network or
   browser. On failure: print an actionable message and `sys.exit(2)`.
   (`titan/cli.py` builds its own defaults dict at line ~108; leave it alone
   in this task — it doesn't load YAML. Note it as possible follow-up.)

## 3. Model sketch (adapt freely, keep the shape)

```python
# titan/core/config_schema.py
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field

class ConfigValidationError(ValueError):
    """Raised when config.yaml fails validation before a scan starts."""

class _Allow(BaseModel):
    model_config = ConfigDict(extra="allow")   # unknown keys pass + warn

class CrawlProfile(str, Enum):
    fast = "fast"; deep = "deep"; hostile = "hostile"

class Aggression(str, Enum):
    passive = "passive"; active = "active"; aggressive = "aggressive"; hostile = "hostile"

class Browser(str, Enum):
    auto = "auto"; system = "system"; bundled = "bundled"

class CrawlConfig(_Allow):
    profile: CrawlProfile = CrawlProfile.fast
    max_pages: int = Field(default=5, ge=1)
    max_apis: int = Field(default=15, ge=0)
    max_depth: int = Field(default=1, ge=0)
    timeout: int = Field(default=600, gt=0)

class StealthConfig(_Allow):
    adaptive: bool = True
    jitter: float = Field(default=0.3, ge=0, le=10)

class AuthConfig(_Allow):
    cookies: str = ""; url: str = ""; username: str = ""; password: str = ""

class ExploitConfig(_Allow):
    enabled: bool = False
    consent_dir: str = "consent"

class TitanConfig(_Allow):
    target: str | None = None
    aggression: Aggression = Aggression.passive
    headless: bool = True
    browser: Browser = Browser.auto
    browser_profile: str = ""
    output_dir: str = "findings"
    crawl: CrawlConfig = CrawlConfig()
    stealth: StealthConfig = StealthConfig()
    auth: AuthConfig = AuthConfig()
    exploit: ExploitConfig = ExploitConfig()
    # governance/brain/deep_audit/ai/reporting/proxy/... stay unmodeled:
    # extra="allow" passes them through untouched.

def validate_config(data: dict) -> dict:
    try:
        model = TitanConfig.model_validate(data)
    except Exception as exc:  # pydantic.ValidationError
        raise ConfigValidationError(str(exc)) from exc
    out = model.model_dump(mode="json", exclude_none=False)
    # re-attach unmodeled sections so nothing is lost:
    for k, v in data.items():
        out.setdefault(k, v)
    return out
```

Notes for the implementer:
- The `setdefault` re-attachment pass in `validate_config` is **required** —
  without it, unmodeled sections (governance, brain, ai, ...) would be
  silently dropped and scans would misbehave. Add a test proving a pass-through.
- Keep the enum values exactly as listed. They are the values the engine
  branches on today (`engine.py:70-71`, `config.example.yaml`).
- Sections left unmodeled on purpose: `governance`, `brain`, `deep_audit`,
  `ai`, `reporting`, `proxy`, `modules`, `cloud`, `subdomain_takeover`,
  `fleet`, `llm`, `clientside`. Modeling them is follow-up work, not this task.

## 4. Wiring (the entire `run.py` diff)

```python
# top of run.py, after existing imports
from titan.core.config_schema import ConfigValidationError, validate_config

def load_config(path: str = "config.yaml") -> dict:
    import yaml
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return validate_config(data)
```

```python
# in main(), replace the bare load_config call:
    config_path = _arg_value("--config", "config.yaml")
    try:
        config = load_config(config_path)
    except ConfigValidationError as exc:
        print(f"[!] Invalid configuration in {config_path}:\n{exc}")
        sys.exit(2)
```

## 5. Tests — `tests/test_config_schema.py`

Follow the plain-dict style of `tests/test_run_cli.py`. Required cases:

1. **`config.example.yaml` passes.** Load the real example file with yaml,
   run `validate_config`, assert no exception and that `out["crawl"]["profile"]`
   normalizes. *This test permanently pins the example config as valid — it
   is the most valuable test in the file.*
2. Unknown crawl profile raises: `{"crawl": {"profile": "depp"}}` →
   `pytest.raises(ConfigValidationError)`, and `"profile"` appears in the message.
3. Negative/zero bounds raise: `max_pages: 0`, `timeout: -5` → raises.
4. Wrong type raises: `{"crawl": {"max_pages": "lots"}}` → raises.
5. Unknown top-level key passes through: input has `"brand_new_section":
   {"x": 1}` → output contains it unchanged, no exception
   (assert the re-attachment pass works).
6. Defaults filled: `validate_config({})` → `aggression == "passive"`,
   `crawl.profile == "fast"`, `headless is True`, `exploit.enabled is False`.
7. Pass-through of an unmodeled section is byte-identical:
   `{"governance": {"enabled": True, "nested": {"a": [1,2]}}}` survives.
8. Integration with existing CLI layer: `apply_cli_overrides(validate_config(cfg))`
   still flips `exploit.enabled` on `--exploit` (import style from `test_run_cli.py`).
9. Exit-code contract (optional, if cheap): run `run.py` via
   `subprocess`/`main()` monkeypatch with a bad config file in `tmp_path`,
   assert `SystemExit` code 2 and the message names the field.

## 6. Dependency plumbing (its own commit, before the module)

- `requirements.in`: add `pydantic>=2.7,<3`
- Regenerate **both** lockfiles (the repo carries both workflows):
  `uv lock` and `pip-compile --output-file=requirements.txt requirements.in`
- `pyproject.toml [project] dependencies`: add pydantic with the same bound
- Install into the venv to verify the resolved version

## 7. Commit plan (repo convention: one change per commit, short messages)

| # | Commit | Contents |
|---|---|---|
| 1 | `feat: add pydantic dependency for config validation` | §6 plumbing |
| 2 | `feat: add config schema module with typed validation` | `titan/core/config_schema.py` |
| 3 | `test: pin config schema validation behavior` | `tests/test_config_schema.py` |
| 4 | `feat: validate config.yaml before engine start` | `run.py` wiring (§4) |
| 5 | `docs: document config validation in README` | one paragraph in README's config section |

Run the full gate before each push, not just the new tests:
`ruff check .` → `mypy titan/ --ignore-missing-imports` →
`pytest tests/ -q --cov=titan` → `detect-secrets-hook --baseline
.secrets.baseline $(git ls-files)` (run the hook **after** `git add`).

## 8. Traps (things that will bite you)

- **Do not reject unknown keys.** Every shipped `config.*.yaml` profile has
  sections this schema doesn't model; rejection would break real usage.
- **Do not drop unmodeled sections** in the returned dict (see the
  re-attachment note in §3 — test 5 and 7 exist to catch exactly this).
- **Enum drift:** the engine compares `crawl.profile` against the literal
  strings `fast`/`deep`/`hostile`. If you rename enum members, the engine's
  `_deep`/`_hostile` flags silently break. Don't touch them.
- **mypy:** pydantic models type-check cleanly; if the per-module
  `[[tool.mypy.overrides]]` list in `pyproject.toml` needs the new module,
  add it in the same commit as the module.
- **Don't validate env vars or secrets material** — this schema is for
  `config.yaml` structure only.
- **Windows note:** all file handling here is UTF-8 text; nothing
  platform-specific. The repo's local venv is `venv/Scripts/python.exe`.

## 9. Acceptance criteria

- [ ] `python run.py --config config.example.yaml --target <url>` behaves
      exactly as before on valid configs (no behavior change).
- [ ] A config with `crawl.profile: "depp"` exits with code 2 and an error
      naming the field — **before** any network or browser activity.
- [ ] `pytest tests/test_config_schema.py -q` green; full suite green;
      ruff/mypy/detect-secrets clean; CI green on push.
- [ ] `config.example.yaml` validity is now pinned by a test (§5 case 1).
- [ ] The scanner-visible surface exists: `config_schema.py` with a typed
      validation entry point wired at the config load boundary, plus a
      test file named for it.

## 10. Why this matters beyond the score

Every report since the first has flagged input validation as missing. But
the real justification is the bug class it kills: Titan's config is the
operator's intent — aggression level, exploit gating, budgets. Today a typo
silently changes what a scan does. After this task, it refuses to start and
says why. For a consent-gated offensive tool, that is not presentation —
that is the difference between "the operator chose passive" and "the
operator typed 'passve' and got active."
