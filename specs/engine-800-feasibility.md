# Engine <800 LOC — feasibility spec

**Goal:** get `titan/core/engine.py` from 1,979 LOC to **under 800** without
changing scan behavior, by turning `TitanEngine` into a thin facade that
composes delegate modules.

**Gate (unchanged from remediation spec):** the full pytest suite (currently
1,102 passed) must stay green after every phase. One commit per phase.

**Honest framing:** <800 is *feasible but is the last mile of a campaign*, not
one more slice. The class today is 1,979 LOC with ~78 methods spanning ~18
feature areas. Arithmetic: removing 1,180 LOC gets to 799. Every feature area
below is a clean seam; the reliable path lands at ~1,000–1,100 after six
gated phases, and the final push under 800 requires decomposing the scan
pipeline itself (the most-tested code in the file). A decision gate after
Phase 6 decides whether that last ~300 LOC is worth the risk.

---

## Current anatomy (measured)

Ranges from the method map (line numbers move as phases land):

| # | Range | Est. LOC | Feature area |
|---|-------|---------|--------------|
| 1 | 54–125 | 72 | `__init__` (wiring + state) |
| 2 | 126–177 | 52 | scope/auth helpers (`_is_in_scope`, consent, authorization) |
| 3 | 182–289 | ~110 | browser/crawler lifecycle (`_launch_crawler`, `_harden_page`, popup/dialog/download, `_record_redirect`, `_is_driver_death`) |
| 4 | 294–346 | ~53 | detection helpers (`_is_checkpoint`, `_finalize_coverage`, `_select_platform_brain`, `_prior_observed`, `_looks_like_api`) |
| 5 | 351–413 | 63 | `scan()` — public entry |
| 6 | 414–567 | 154 | `_run_scan_pipeline` — core orchestration |
| 7 | 572–766 | 195 | interaction phase (capture, forms, fill/submit) |
| 8 | 767–888 | 122 | SPA harness + route hydration |
| 9 | 893–961 | 69 | multi-role scan + session replay |
| 10 | 962–1169 | 208 | optional phases (LLM, storage, subdomain takeover, cloud IMDS, SBOM, deep audit) |
| 11 | 1174–1225 | 52 | post-scan phase orchestrator |
| 12 | 1226–1297 | 72 | hostile pass + anti-forensics |
| 13 | 1298–1441 | 144 | brain loop, variant/bypass, evolution engine |
| 14 | 1442–1554 | 113 | exploit modules / Track E |
| 15 | 1555–1609 | 55 | fleet scan |
| 16 | 1614–1691 | 78 | verification glue |
| 17 | 1696–1776 | 81 | browser-module dispatch + `_run_modules` |
| 18 | 1777–1868 | 92 | attack modules + discovery forwards |
| — | tail | ~110 | remaining helpers, gaps, section banners |

Sum of feature areas ≈ 1,775; everything else is init + helpers + glue.

---

## Two extraction patterns (use both, keep one style per module)

1. **Mixin inheritance** (proven by `transport_mixin`): methods move to a mixin,
   `TitanEngine` inherits it, every `self._x()` call site and every engine state
   attribute keeps working unchanged. Best for methods that reach into engine
   state heavily (browser lifecycle, phase runners).
2. **Delegate object** (proven by `modules_runner`): a plain class holding
   `self.engine`, called as `self._spa._run(...)`. Best for self-contained
   phases that only need `target`/`result`/`page` plus a few engine services.

Rule of thumb: if the code reads 5+ engine attributes, mixin it; if it takes
`(target, result)` and returns, delegate it.

---

## Phased plan

Each phase = one commit, suite gate, `wc -l` recorded.

### Phase A — dead & duplicate sweep (≈ −30 to −60 LOC, trivial risk)
- Delete the shadowed `_extract_forms` at ~718 (full JS-evaluate body; the
  later `DiscoveryEngine` forward at ~1828 wins, so 718 is unreachable).
- Grep for other duplicate method names (later defs shadowing earlier ones);
  delete the shadowed bodies only.
- No behavior change possible by definition — dead code is unreachable.

### Phase B — browser lifecycle mixin (≈ −110 LOC)
- Move rows 3 to `titan/core/browser_lifecycle.py` as `BrowserLifecycleMixin`:
  `_is_driver_death`, `_launch_crawler` (incl. `_persistent` closure),
  `_close_crawler`, `_harden_page`, `_close_popup`, `_dismiss_dialog`,
  `_suppress_download`, `_record_redirect`.
- Same mixin pattern as transport. These are self-contained Playwright
  plumbing; `_record_redirect` touches shared state (`redirect_chain`) which
  stays an engine attribute — the mixin just writes `self.redirect_chain`.

### Phase C — post-scan phase runners (≈ −210 LOC)
- Move rows 10 (optional phases) to `titan/core/post_scan_phases.py`:
  `_run_llm_channel`, `_run_storage_probe`, `_run_subdomain_takeover`,
  `_probe_cloud_imds`, `_run_sbom_analysis`, `_run_deep_audit`, plus row 11's
  `_run_post_scan_phases` orchestrator as the module's entry.
- Uniform `(target, result, ...)` signatures → delegate object
  (`PostScanPhases(engine)`), engine keeps a thin `_run_post_scan_phases`
  forward so the orchestration call site in `scan()` is unchanged.
- Highest-value single phase (208 LOC) and low risk: each sub-runner is
  already a leaf method that appends findings to `result`.

### Phase D — interaction + SPA harness (≈ −320 LOC)
- Move rows 7 + 8 to `titan/core/browser_interaction.py`:
  interaction capture, form extraction/fill/submit, `_run_spa_harness`,
  `_hydrate_spa_routes`.
- **Risk point:** `test_scan_quality` and `test_engine_cancellation` exercise
  these paths and monkey-patch some methods. The public `_`-method names they
  patch must survive on the engine as thin forwards (see risk register).

### Phase E — deep campaign phases (≈ −310 LOC)
- Move rows 12, 13, 14, 15 to `titan/core/campaign_phases.py`: hostile pass,
  anti-forensics, brain loop, variant/bypass detection, evolution engine,
  exploit/Track E (incl. its `guarded`/`record` closures), fleet scan.
- Least-tested of the areas (many are opt-in by config) — verify carefully
  that the config-gated paths still fire via the existing deep/hostile tests.

### Phase F — multi-role, module dispatch, discovery forwards (≈ −250 LOC)
- Move rows 9, 17, 18 to `titan/core/dispatch.py` / `titan/core/discovery.py`.
- **Risk point:** the discovery forwards (~1828–1868) exist *for test
  monkey-patching* (`test_scan_quality` patches `e._crawl_spa_routes`,
  `e._fuzz_paths`; cancellation tests patch `e._run_attack_modules`). Keep
  every patched name as a thin forward on the engine (1–2 lines each), or
  move the tests to patch the delegate instead — same commit.

### Phase G — helpers & auth scope (≈ −250 LOC) → lands ~900–1,000
- Move rows 2 + 4 (scope/consent/checkpoint/coverage/platform-brain helpers)
  to `titan/core/engine_helpers.py` or fold into the mixin layer.
- `_is_in_scope` is fail-closed and pinned by `tests/test_engine_scope.py` —
  moving it must keep the pinned semantics (tests import it off the engine,
  so keep a forward or keep it on the class).

### Phase H — the <800 push (≈ −250 to −300 LOC, decision gate)
- Decompose `scan()` + `_run_scan_pipeline` (rows 5 + 6, ~217 LOC) into a
  `ScanOrchestrator` delegate that owns pipeline sequencing, while `scan()`
  becomes a thin public wrapper (config load, target set, result init,
  delegate call, dedupe/scope filter).
- This touches the single most-tested orchestration path. It is where a
  regression would hurt most. **Decision gate:** after Phase G, measure —
  if at ~950 or below and the pipeline split looks clean, do it; if the
  remaining gap is small, stop and accept ~900–1,000 as the practical floor.

---

## Risk register (things that will break if not handled)

- **Monkey-patched names.** Tests patch engine methods directly:
  `_run_attack_modules`, `_run_modules`, `_crawl_spa_routes`, `_fuzz_paths`,
  `_extract_forms`, `_is_in_scope` (scope tests construct engines and call it).
  Any extracted name that a test patches must remain reachable on the engine
  (forward) or the test moves in the same commit.
- **Shared state attributes.** `visited`, `redirect_chain`, findings lists,
  `_transport_*`, `session_pool`, `_anomaly_tracker`, `_waf_tracker`,
  `config`, `_scan_target` are read across phases. With mixins they stay on
  `self` untouched; with delegates the delegate receives the engine — never
  duplicate state into the delegate.
- **Class-attribute vs module-constant.** If a phase references
  `cls.SOME_CONST`, extraction to a module constant changes nothing as long
  as the class re-exposes it (pattern from `waf_profiles`).
- **Config-gated paths.** Hostile/deep/Track-E/fleet code is opt-in; the suite
  may not execute it deeply. Keep the small config-gate tests that exist, and
  treat "imports cleanly" as the floor for those modules.
- **Coverage floor.** CI now fails below 44%. Extraction that moves code into
  new modules *increases* coverage pressure on the new modules' exercised
  lines — new modules under-exercised by tests will drag the metric. Expect
  the post-extraction coverage number to dip and adjust only by raising
  *test* coverage, never by lowering `fail_under` (spec Step 8 rule).

## Definition of done

- `wc -l titan/core/engine.py` < 800 after Phase H (or at the accepted floor
  from the Phase-H decision gate).
- Full suite green after every phase; new module files each carry direct tests
  where the suite doesn't already cover them.
- `TitanEngine` still exposes every name tests patch, directly or as a forward.
- No behavior change: same findings, same ordering guarantees, same console
  output via the Step 5 logger facade.
- Each phase is its own commit with the phase name (DataFactor discipline).

## Non-goals (this pass)

- Rewriting logic while moving it. Move verbatim; refactor later.
- Reducing the other 500+ LOC files (separate campaign).
- Changing the public CLI or `ScanResult` shape.
