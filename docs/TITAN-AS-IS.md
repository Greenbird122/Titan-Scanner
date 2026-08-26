# Titan — As-Is Master Documentation

> **Scope:** Full, current-state documentation of the **Titan Security Engine** and its
> supporting ecosystem (lab, brain/arena, fleet, bench, learn, hostile surface, and
> governance). Compiled from the repository tree on **2026-08-24**.
> Everything here reflects what is actually in the tree today, cross-referenced with
> the project's own living docs (`README.md`, `ARCHITECTURE.md`, `MASTER-PLAN.md`,
> `OPERATORS-MANUAL.md`, `QUICKSTART.md`, `RUNBOOK.md`, `WHERE-WE-ARE.md`,
> `docs/TITAN_SPECIFICATION.md`, and `learn/`).

---

## 0. TL;DR

Titan is an autonomous, evidence‑gated DAST (Dynamic Application Security Testing)
engine for authorized targets only. It crawls a target, fuzzes **every** parameter /
header / JSON‑AST node (zero whitelisting), runs a matrix of ~37 detection modules,
**verifies** each finding with deterministic oracles (diff, math, timing, OOB), scores
with CVSS, chains related findings, and (under signed consent) stages real exploit
sessions (RCE agents, webshells, SQLi dumps, SSRF pivots). Around the core scanner sit:

- **The Brain / Arena** (`purple/`) — red/blue AI agents that fight in the lab.
- **The Fleet** (`titan/fleet`, `fleet/`) — GitHub‑linked live‑site red rounds on push.
- **The Lab** (`local_lab/`) — deliberately vulnerable Flask app (firing range).
- **The Hostile surface** (Track G, `titan/hostile/`) — ad/clickbait/cloak profiling.
- **The Bench** (`bench/`) — official CTF benchmark rig (Juice Shop, WebGoat, DVWA).
- **The Learn system** (`learn/`) — 12 lessons + 10 simulations + attack quicksheet.
- **Governance** — Ed25519 signed consent + S5 fail‑closed authorization gate.

---

## 1. What Titan Is (and Is Not)

| | |
|---|---|
| **Purpose** | Find deep technical vulnerabilities in web apps, REST/GraphQL APIs, multi‑tenant cloud backends, and AI/LLM interfaces. |
| **Posture** | Grey‑hat: offensive capability, defensive purpose. Only against systems you **own** or have **explicit written authorization** to test. |
| **Core differentiators** | (1) Zero parameter whitelisting; (2) Strict verification oracles that demote false positives; (3) Consent‑gated, code‑enforced exploitation only. |
| **Not** | A black‑hat tool, an anonymity toolkit, or something to point at third parties. `WHERE-WE-ARE.md` documents a prior incident where third‑party hosts were scanned without consent and the resulting hard gates (S5). |

**Project identity:** `titan-scanner` v1.1.0 (MIT), Python ≥ 3.10. Repo originally cloned from `Greenbird122/Vuln-scanner`.

---

## 2. Repository Layout (annotated)

```
titan-lab/
├── run.py                      # CLI entry: scan, dashboard (S5)
├── titan_exploit_cli.py        # Track E/F/G CLI: consent, listener, session,
│                               #   reattach, redirect, archive, adprofile, intel
├── titan_fleet_cli.py          # Fleet CLI: sync/link/list/consent/round/watch/daemon
├── titan_learn_cli.py          # Learn CLI
├── titan_bench_cli.py          # Benchmark CLI
├── provider.py                 # AI provider abstraction entry
├── deep_verify.py              # Deep verification helper
├── extract_bundle.py / extract_keys.py / find_secret.py   # utility scrapers
├── firebase_probe.py / firebase_rtdb_probe.py / firebase_surface.py  # cloud probes
├── test_endpoints.py / test_graphql_attacks.py           # ad-hoc test harnesses
├── config.yaml                 # SINGLE SOURCE OF TRUTH for scan config
├── config.*.yaml               # variants: quick / omega / deep / dt-hostile /
│                               #   gv-hostile / mkulima / purple
├── _config.yml                 # (docs site config?)
├── ARCHITECTURE.md / MASTER-PLAN.md / OPERATORS-MANUAL.md
├── QUICKSTART.md / RUNBOOK.md / WHERE-WE-ARE.md / README.md
├── docs/TITAN_SPECIFICATION.md # Definitive 37-module spec + roadmap
├── titan/                      # THE ENGINE (see §4)
├── local_lab/                  # Deliberately vulnerable Flask lab (see §10)
├── purple/                     # Brain / Arena / War Room (see §8)
├── fleet/                      # Fleet registry + poller + red_round (see §9)
├── bench/                      # CTF benchmark rig (see §11)
├── learn/                      # 12 lessons + simulations + attack ref (see §12)
├── consent/                    # Signed ed25519 consent files + keypair (see §7)
├── findings/                   # Scan outputs, sessions, archives (see §13)
├── targets/                    # (empty) reserved target manifests
├── scripts/  docker/  dawn_integration/  titan-remote/  .agents/  .claude/  .crush/
├── tests/                      # ~77 test modules (see §14)
├── requirements.txt            # playwright, aiohttp, pyyaml, requests, flask,
│                               #   PyJWT, cryptography, pytest, pytest-asyncio
├── pyproject.toml             # build + [project.scripts] titan / titan-exploit
├── Dockerfile / docker-compose.yml   # containerized lab + C2 listener
├── LICENSE (MIT)  pytest.ini  _config.yml
└── purple/inbox/              # ~64k SPEC-*.json "blue tasks" (throttles war room)
```

---

## 3. Architecture & Data Flow

### 3.1 Design principles (from `ARCHITECTURE.md`)
- **Verification-first** — no finding without replay + diff confirmation.
- **Stealth by default** — jitter, header randomization, (optional) IP rotation.
- **Honest failure** — all errors surfaced; no fabricated results.
- **Modular core** — same `titan/` package drives the CLI, Dawn sub-command, and standalone.
- **Titan-ecosystem native** — reuses DeepSeek client, consent model, alerting patterns.

### 3.2 Pipeline
```
User / Dawn Agent
   │
   ▼
TitanEngine.scan()  ──►  S5 AUTHORIZATION GATE (loopback | consent | practice manifest)
   │                     fail-closed: refuses any host not authorized
   ▼
Crawler (Playwright + JS exec)
   ├─ static links/forms, JS click/scroll, Swagger/OpenAPI, GraphQL introspection
   └─ SPA harness: hydrate route table, capture XHR/fetch/WebSocket
   ▼
Surface extractor  ──►  query/body/header/JSON-AST nodes  (zero whitelisting)
   ▼
PayloadForge (DeepSeek + fallback + dictionaries, fingerprint-aware)
   ▼
Module matrix (~37 detectors, concurrent) ──► raw signals
   ▼
Verifier / Oracles  (baseline, differential, timing, OOB/Interactsh, multi-step replay)
   │   └─ unconfirmed → tiered (suspicious/indicative), never silently trusted
   ▼
Scorer (CVSS v3.1)  ──►  Chain Analyzer (flow-typed multi-hop)
   ▼
Reporter (report.md / findings.json / scan_meta.json / dashboard.html / hostile.json)
   ▼
(optional) Exploit phase (Track E) — only if signed consent + flags permit
   └─ RCE agent / webshell / sqlidump / ssrf-pivot sessions + reattach
```

### 3.3 Verification Oracles (the anti–false-positive core)
- **Inert echo suppression** — strips raw/URL/HTML-entity/JSON-escaped inputs so reflection ≠ execution.
- **Non-echo differential** — structural row-set / state change driven by logic, not input noise.
- **Math / token oracles** — `{{7*7}}→49`, unique `TITAN_<nonce>` command execution markers.
- **Statistical timing (`BlindDetector`)** — multi-sample baseline std-dev gating with declared-delay validation (`sleep`, `ping -n/-c`).
- **OOB (`Interactsh`)** — DNS/HTTP/LDAP callback correlation for blind SSRF/RCE/XXE/deserialization.

### 3.4 Evidence tiers (used throughout reporting)
```
Tier 0  Suspicion        (signal only)
Tier 1  Reflection+Pattern
Tier 2  Behavioral Anomaly (timing correlation)
Tier 3  Differential Verified
Tier 4  Flow-Typed Chain (multi-hop)
Tier 5  Kernel Observed (eBPF)
Tier 6  Exploit Confirmed (live)
```

---

## 4. The `titan/` Engine Package

```
titan/
├── __main__.py / __init__.py
├── core/         engine, models, cvss, poc, auth, authorization(S5),
│                 fingerprint, stealth, proxy, sessions, pathfuzz, spa,
│                 spec_ingest, route_scorer, waf, anomaly, osint,
│                 darkweb_map, engine.py.bak  (note: .bak present)
├── modules/      ~36 detector packages (see §5)
├── verify/       oracles, flows, chain_analyzer, repro, correlation,
│                 coverage, kernel, ai_escalation, identity_oracles,
│                 llm_oracles, network
├── exploit/      consent, planner, listener, repl, session, reattach,
│                 redirect_poc, sqli_extractor, sqlidump, ssrfpivot,
│                 upload_planner, webshell, atrest, vault.b64
├── hostile/      origins.json (intel taxonomy), intel, profiler,
│                 detectors, offense, __init__ (run_pass)
├── integrations/ dawn, deepseek, interactsh, titan_gov
├── ai/           payloadforge, payloadsmith, pg
├── brain/        loop, evolution, strategy, mutation_loop/
├── fleet/        agents, coordinator
├── stealth/      advanced
├── transport/    base, http_transport, tor, grpc, mqtt, ssh,
│                 websocket, test_omega, test_onion_scan
├── consent/      flags
├── reporting/    dashboard (S5)
├── archive/      archiver (S6 site mirror)
├── learn/        notes, trends
├── cli/          main
└── playbooks/    django-flask, firebase-supabase, moodle, nextjs-vercel,
                  rest-api-generic, spa-generic, wordpress  (.yml)
```

### 4.1 `titan/core` highlights
- **`engine.py`** — scan orchestration; owns every "track seam" (crawl → fuzz → detect → verify → score → report → exploit). Enforces the S5 gate at `scan()` entry.
- **`authorization.py`** — S5 fail-closed gate: target allowed iff loopback, covered by a signed consent file in `consent_dir`, or listed in the authorized-practice manifest (`findings/AUTHORIZED-PRACTICE.json`).
- **`models.py`** — `Finding`, `ScanResult` data types.
- **`cvss.py`** — CVSS v3.1 scoring.
- **`poc.py`** — PoC command generation.
- **`auth.py` / `sessions.py`** — `AuthEngine`, role-based identity, `SessionPool` (concurrent multi-role sessions for Track B differentials).
- **`stealth.py` / `stealth/advanced.py`** — jitter, adaptive delays, anti-forensics (decoy traffic, polymorphic payloads).
- **`pathfuzz.py`** — response-driven path fuzzer (random-marker 404 control, soft-404 filtering).
- **`spa.py`** — SPA route hydration + runtime XHR/fetch capture (closes the 0-finding-SPA gap).
- **`fingerprint.py`** — tech-stack detection (caveat: `WHERE-WE-ARE` notes it mislabels many stacks as "Play Framework").
- **`waf.py`**, **`anomaly.py`**, **`osint.py`**, **`darkweb_map.py`**, **`route_scorer.py`**, **`spec_ingest.py`**, **`proxy.py`**.

### 4.2 `titan/verify`
- **`oracles.py`** — differential / boolean / time / OOB evidence.
- **`chain_analyzer.py`** — flow-typed multi-hop attack chains (e.g., SSRF→metadata + hardcoded key = Cloud Credential Exposure).
- **`flows.py`** — capability typing for chains.
- **`repro.py`** — deterministic replay / reproduction.
- **`ai_escalation.py`**, **`identity_oracles.py`**, **`llm_oracles.py`**, **`correlation.py`**, **`coverage.py`**, **`kernel.py`**, **`network.py`**.

### 4.3 `titan/exploit` (Track E — consent-gated)
- **`consent.py`** — Ed25519 gate; signed, key-pinned, expiry-enforced.
- **`planner.py`** — decides what to stage per finding type.
- **`listener.py`** — C2 poll endpoint (default `127.0.0.1:8770`, unauthenticated by design; consent is the boundary).
- **`session.py` / `repl.py`** — interactive agent REPL.
- **`reattach.py`** — M5 survivor re-pointing after operator restart.
- **`sqli_extractor.py` / `sqlidump.py`** — structured SQLi extraction.
- **`ssrfpivot.py`** — S4 one-way internal relay through verified SSRF sink.
- **`upload_planner.py` / `webshell.py`** — webshell staging.
- **`redirect_poc.py`**, **`atrest.py`**, **`vault.b64`** (note: a binary-ish vault artifact is committed — review for secrets).

---

## 5. The Detection Module Matrix (Tracks A–G)

The spec (`docs/TITAN_SPECIFICATION.md`) enumerates **37 modules**. The `titan/modules/`
directory currently holds **36 detector packages** (the spec's #36 `clientside/domxss`
lives inside `clientside/`, and #37 `trackg` lives inside `hostile/`). Modules are grouped
into tracks:

### Track A — Client-Side & Browser (`titan/modules/clientside/`)
DOM XSS sink hooking, Prototype Pollution (`__proto__`, `constructor.prototype`), `postMessage` origin audits, third-party inventory, CSP evaluation.

### Track B — Identity & Access Control
`idor`, `bola` (3-way cross-tenant differential), `jwt` (200+ secret dict, `alg:none`, `kid`, RS256→HS256), `massassignment` (22-field privilege matrix + nested JSON AST), `sessionfix` (multi-framework cookie matrix), `auth` (auth-bypass, verb tampering, header spoofing, path normalization).

### Track C — LLM & AI Application Defense (`llm/`, `llm_deep/`)
Prompt injection (direct/indirect), system-prompt leakage, OOB data exfiltration via tools, agent tool-abuse consensus judging (≥N/ trials agreement), RAG poisoning, tool-use hijacking, training-data extraction.

### Track D — Cloud & Control Plane (`cloud/`, `cloud_control/`)
Public S3/GCS/Azure bucket discovery (evidence-referenced only), IMDSv1/v2 probing, IAM STS role extraction, privilege-escalation simulation.

### Track E — Exploitation Engine (consent-gated, §4.3)
Verified finding → benign PoC validation + interactive session management.

### Server-Side Injection & Misc (`titan/modules/`)
`sqli`, `xss`, `ssti` (7-engine discrimination), `rce` (multi-OS separators + timing), `ssrf`, `lfi`, `nosqli`, `xxe`, `deser` (Java/PHP/Py/.NET/Node), `cors`, `cache`, `smuggling` (CL.TE/TE.CL), `crypto` (secret scanner), `race` (microsecond barrier), `logic` (numeric tampering), `upload` (14-probe bypass), `redirect`, `headers`, `sourcesecret` (sourcemap/`.js.map`), `api`, `apixss` (static taint AST), `fuzzer` (18-variant mutation), `parserdiff` (encoding-disagreement/WAF bypass), `deep_audit` (estate mapping + Firebase/Supabase).

### Track G — Hostile & Supply-Chain Surface (`titan/hostile/`, `titan/modules/supplychain/`)
Ad-network redirect tracking, phishing-hop classification, browser cloaking, in-browser cryptominers, push-abuse, SRI audits, CI/CD PPE, npm/PyPI dependency confusion. Read-only analysis always runs; active probes (redirect chains, referrer gates) only under signed consent. Ad origins are scored **metadata**, never vulnerability rows.

### 5.1 Module capability snapshot (from spec)
| # | Module | Oracle method (short) |
|---|--------|------------------------|
|01|sqli|error sig + non-echo row diff|
|02|xss|unescaped breakout confirmation|
|03|ssti|math nonce + dialect string mult|
|04|rce|nonce + BlindDetector timing|
|05|ssrf|cloud metadata pattern + reflection strip|
|06|lfi|`root:x:0` marker + errno diff|
|07|idor|structural JSON + non-echo value change|
|08|nosqli|boolean differential pairing|
|09|xxe|file leak + parser error diff + OOB|
|10|jwt|unsigned/tampered claim acceptance|
|11|cors|reflected origin + `ACAC: true`|
|12|deser|gadget class sigs + JNDI/LDAP OOB|
|13|auth|401/403→200/302 escalation|
|14|redirect|`Location` dest + URL-bar hijack|
|15|headers|header/cookie directive analysis|
|16|cache|unkeyed poisoning reflection|
|17|smuggling|keyword echo peeling + timeout diff|
|18|crypto|pattern match + entropy verify|
|19|race|counter-divergence oracle|
|20|logic|negative/free/overflow reflection|
|21|upload|exec nonce + public retrieval|
|22|massassignment|structural field:value pairing|
|23|sourcesecret|verbatim client-accessible secret|
|24|sessionfix|pre→post auth cookie survival|
|25|bola|exclusive owner marker cross-tenant|
|26|fuzzer|error-class emergence diff|
|27|clientside|`Object.prototype` inheritance|
|28|api|schema parse + `__schema` types|
|29|apixss|taint-flow graph to DOM sink|
|30|cloud_control|valid IAM/STS tokens|
|31|deep_audit|estate inventory reconciliation|
|32|parserdiff|encoded variant reaches strong sink|
|33|supplychain|unregistered pkg + over-priv CI|
|34|llm|consensus across ≥N trials|
|35|llm_deep|doc override + tool hijack|
|36|clientside/domxss|marker at hooked sink|
|37|trackg|malicious sig + phishing chains|

---

## 6. The Brain / Evolution (`titan/brain/` + `titan/ai/`)
- **`brain/loop.py`** — autonomous reasoning loop (Thompson Sampling referenced in learn/07).
- **`brain/evolution.py`** — self-improvement; can persist generated detectors to disk (`config.brain.evolution.persist`).
- **`brain/strategy.py`**, **`brain/mutation_loop/`** — payload mutation / WAF-bypass discovery.
- **`ai/payloadforge.py`** + **`ai/payloadsmith.py`** + **`ai/pg.py`** — provider + fallback payload generation.

---

## 7. Consent & Authorization Model (the safety core)

Two layers, both **code-enforced**:

1. **Ed25519 signed consent** (`titan/exploit/consent.py`, `titan/consent/flags.py`)
   - `consent/<host>.json` pinned to the operator keypair (`consent/key.pem`, auto-created, 0600).
   - Carries a signed **authorization basis**: `ownership` | `authorization` | `program`.
   - Flags: `--write`, `--shells`, `--persistence` grant progressively more.
   - Expiry enforced (default 24h; refresh with `--expiry 7d`).
   - `consent add` without `--basis` is **refused (exit 2)**; a `SCOPE.md` template is written next to the file.
   - Docker vs bare-metal use **separate keys** — a consent signed in one mode is refused in the other.

2. **S5 hard authorization gate** (`titan/core/authorization.py`)
   - Sits at the top of `TitanEngine.scan()` **and** `purple/batch.py run_batch`.
   - A target is scanned only if it is **loopback**, covered by a **signed consent**, or on the **authorized-practice manifest** (`findings/AUTHORIZED-PRACTICE.json`).
   - **Fail-closed**: missing/malformed manifest authorizes nothing. No non-consented, non-listed host can be crawled.

> Per `WHERE-WE-ARE.md`, S5 was added after a retrospective found third‑party hosts
> (instagram/google/recordedfuture/…) had been scanned with no consent. Those scans were
> deleted; 12 true practice/CTF targets were manifested; owned-estate consents backfilled.

---

## 8. The Brain / Arena / War Room (`purple/`)

| Piece | What it is | Port |
|---|---|---|
| **Arena** (`purple/arena/`) | Red/blue AI agents that fight in the lab and absorb lessons. `start_arena.py` boots lab (:5000) + arena (:8778) idempotently. `server.py`, `engine.py`, `agents.py`, `llm.py`, `arena.html/js/css`, `state.json`, `install_startup.py` (boot autostart). | 8778 |
| **Batch** (`purple/batch.py`) | Drives rounds across estates; writes `batch-findings.json` / `batch-progress.json`; enforces S5. | — |
| **Scoreboard** (`scoreboard.py` + `scoreboard.json`) | Red/blue scoreboard; `taxonomy.json`, `scenarios.json`, `journal.md` (war journal). | — |
| **War Room** (`warroom.py` + `warroom.html`) | HTML dashboard (scoreboard, rounds, findings). **PAUSED** — rebuild parses the entire 64k+ `purple/inbox/` on every build, throttling batch runs. Re-enable with `warroom.py build` + `serve --port 8777`. | 8777 |
| **Blue skills** (`purple/blue_skills/`) | Reusable defensive playbooks: `account_privilege`, `card_exposure`, `order_bola`, `price_tamper`, `reset_token`, `review_xss`, `search_sqli`, `webhook` (+ `_harness.py`). | — |
| **Inbox** (`purple/inbox/`) | ~64,837 `SPEC-*.json` blue tasks (the spec backlog). | — |

Arena chat commands: `round <scenario>`, `/status`, `/help`. No `.env` → canned lines; with `DEEPSEEK_AUTH_TOKEN` or `OLLAMA_HOST` the agents think for real.

---

## 9. The Fleet (`titan/fleet/` + `fleet/` + `titan_fleet_cli.py`)

GitHub-linked "live-site red rounds on push":
- `fleet/registry.py` — `owned_sites.yaml` (repo → URL).
- `fleet/poller.py` — detects new commits (last SHAs in `state.json`).
- `fleet/red_round.py` — fires a scan round per repo.
- `titan/fleet/agents.py` + `coordinator.py` — specialized recon/identity/learning agents (read-only) and exploit/post-exploit agents (require consent).
- CLI: `sync`, `link <repo> <url>`, `list`, `consent <repo>`, `round <repo> [--profile hostile] [--scoreboard]`, `watch`, `daemon [--interval]`.
- `--profile hostile` = full arsenal + Track G; `--no-exploit` = detection only.

---

## 10. The Lab (`local_lab/`)

Deliberately vulnerable Flask app — the firing range. Seeded endpoints (from `learn/README`):
`/sqli`, `/sqli_mssql`, `/sqli_pg`, `/sqli_comment_bypass`, `/xss`, `/ssrf`, `/lfi`,
`/cmd`, `/upload`, `/api/user` (IDOR), `/api/login` (JWT none), `/api/data` (CORS),
`/hash` (MD5), `/config` (hardcoded creds), `/redirect-meta`, `/redirect-js`.
Plus `shop.py`, `streaming.py`, `scenario_fixtures.py`, `uploads/`.
Start: `python local_lab/app.py` (binds :5000). Full scan ≈ 10/10 verified coverage.

---

## 11. The Bench (`bench/`)

Official CTF benchmark rig (offensive regression against known targets):
- `benchmark.py`, `estate.py`, `scorecard.py` (writes `scorecard.json`/`scorecard.md`).
- `manifests/`: `estate.json`, `juice_shop.json`, `local_lab.json`, `webgoat.json`.
- `targets/`: `juice-shop/`, `webgoat/` run logs.
- `results/`: `127-0-0-1-5000/`, `juice-shop/`, `webgoat/`, `sites.json`, `lab.log`.
- Rig status (per OPERATORS-MANUAL §12): **Juice Shop** runnable via `npx juice-shop` (:3000); **WebGoat** needs Java 21 jar; **DVWA** blocked (no Docker/PHP on this box).

---

## 12. The Learn System (`learn/`)

Self-teaching material, not part of the runtime scanner:
- **12 lessons** (`01-…-12-*.md`): overview, engine, modules, evidence oracle, consent, transport, brain loop, evolution, fleet, anti-forensics, building a module, testing.
- **10 simulations** (`simulations/00-10-*.md`): lab setup + sqli/xss/ssrf/lfi/rce/upload/idor/jwt/cors/race.
- **`attack-reference.md`** — quicksheet (payloads, OWASP 2021 mapping, severity, defense checklist).
- **`notes.py` / `trends.py`** — support code.

---

## 13. Output Artifacts (`findings/`)

```
findings/<site-slug>/
├── report.md          # human-readable findings + PoCs + chains
├── findings.json      # machine-readable records (+ chains array)
├── scan_meta.json     # target, timestamps, config snapshot
├── dashboard.html     # interactive S5 HTML report
├── hostile.json       # Track G profile + findings
├── intel.json         # Track G observed third-party origins
├── archive/           # S6 consent-gated mirror
│   ├── index.html     # explorer
│   └── pages/ assets/ endpoints.json
├── sessions/<id>/     # Track E sessions
│   ├── session.json  transcript.log  data_samples/
└── AUTHORIZED-PRACTICE.json / .md   # S5 practice manifest
```

---

## 14. Test Suite (`tests/`)

~**77 test modules** / **1,120 collected** (per README badge) — oracle, detector, lab,
exploit, trackg, chain, authorization-gate, brain, fleet, bench, dashboard (S5),
archive (S6), spa-harness, scan-quality, etc. A few are `win32`-skipped where they pin
exact Windows timing (notably `test_lab_detection.py::TestLabLFI` — passes on Linux/macOS/WSL2).
Run: `python -m pytest -q` (bare metal) or `docker compose exec titan python -m pytest -q`.

---

## 15. Configuration Reference (`config.yaml`)

Top-level keys (single source of truth, consumed directly by `titan/core/engine.py`):
- `target` — default scan target.
- `aggression` — `passive | active`.
- `headless` — `true` (Playwright headless).
- `output_dir` — `findings`.
- `crawl.profile` — `fast | deep | hostile`. `fast` = content-derived only (no path/param guesses). `deep` = wordlist fuzzing + spec probing + method brute + SPA hash-route guessing. `hostile` = deep + Track G.
- `crawl.max_pages / max_depth / timeout / module_concurrency / interaction_timeout`.
- `crawl.spa` — hydration harness (`enabled`, `hydrate_budget`, `max_routes`, `per_route_budget`, `network_idle`).
- `crawl.supplychain` — read-only third-party/SRI/cleartext analysis under every profile.
- `crawl.fuzz` — response-driven path fuzzer (budget, seeds, depth, words, requests, concurrency).
- `stealth` — `jitter`, `min_delay`, `max_delay`, `adaptive` (auto-collapse on fast targets), `anti_forensics` (decoy/polymorphic).
- `governance.enabled` — `false` (Titan Gov proposal gate, off by default).
- `brain` — autonomous mutation (`enabled`, `budget`, `variants_per_finding`, `evolution.persist`).
- `deep_audit` — Firebase/Supabase cloud probing.
- `authorization.practice_manifest` — `findings/AUTHORIZED-PRACTICE.json` (S5).
- `auth` — pre-supplied `token`/`api_key`/`cookies` OR form-fill login; `roles: []` for Track B multi-identity.
- `ai` — `enabled`, `model` (`deepseek-chat`), `fallback` (`ollama`), `max_payloads_per_param`, `escalate`.
- `modules` — per-module `enabled` + `timeout` (rce/sqli default 60s for timing oracles; others 45s).
- `clientside` — Track A toggles (domxss/postmessage/prototype/third_party/csp).
- `llm` — Track C endpoints + `trials`/`min_agree` consensus.
- `cloud` — storage + `imds` probing.
- `fleet` — agent-based deep dives (disabled by default).
- `exploit` — Track E: `enabled`, `consent_dir`, `output_dir`, `max_per_type`, `budget`, `listener` (`host/port/start`).
- `dawn` — `memory`/`voice`/`gov` (off).

> **Note:** `config.yaml` currently targets `https://elearning.kibu.ac.ke` with a real
> username/password and `profile: deep`. Verify the target is authorized/consented before
> running it as-is; prefer `--target` + a scoped config.

---

## 16. Command Reference

### Scanning
```bash
python run.py --target <url>                       # fast profile scan
python run.py --target <url> --config my.yaml      # custom config
python run.py --target <url> --exploit --exploit-listener-start   # auto-stage (needs consent)
python run.py dashboard <slug>                      # render S5 HTML dashboard
```

### Consent (Track E/F/G gate)
```bash
python titan_exploit_cli.py consent add <url> --basis ownership --write --shells --persistence
python titan_exploit_cli.py consent list
python titan_exploit_cli.py consent revoke <url>
```

### Exploit sessions (Track E)
```bash
python titan_exploit_cli.py listener --port 8770
python titan_exploit_cli.py session <id>            # REPL (whoami, uname, /rows, /export, /pivot)
python titan_exploit_cli.py session <id> --listener-url http://127.0.0.1:8770
python titan_exploit_cli.py reattach <url> --store findings --verify
```

### Hostile surface (Track G)
```bash
python titan_exploit_cli.py adprofile <url> [--pages N]
python titan_exploit_cli.py intel list / add <host> <cat> / promote <observed.json>
```

### Fleet
```bash
python titan_fleet_cli.py sync / link <repo> <url> / list / consent <repo>
python titan_fleet_cli.py round <repo> --profile hostile --scoreboard purple/scoreboard.json
python titan_fleet_cli.py watch / daemon --interval 300
```

### Brain / Arena
```bash
python purple/arena/start_arena.py [--port 8778]    # idempotent
python purple/warroom.py build / serve --port 8777  # PAUSED by default
```

### Lab, Bench, Learn
```bash
python -c "from local_lab.app import app; app.run(host='127.0.0.1', port=5000)"
python titan_bench_cli.py ...        # benchmark rig
python titan_learn_cli.py ...        # learn system
python -m pytest -q                  # full suite
```

---

## 17. Current State, Known Gaps & Roadmap

### What holds (verified)
Evidence gate + demotion oracle · consent crypto (ed25519 + keypin) · **S5 fail-closed authorization** on read-only path · zero shell-injection surface · dashboard escaping · self-audit S1–S5 with passing tests · 1,120-test regression green.

### Known gaps (from `WHERE-WE-ARE.md` + `MASTER-PLAN.md`)
- **SPA crawl gap** — slow remote SPAs (e.g., Juice Shop demo) can yield 0 findings; the SPA hydration harness (`crawl.spa`) is the mitigation but coverage on heavy SPAs is still weak.
- **Fingerprint unreliability** — frequently mislabels stacks as "Play Framework."
- **Novel-class detection** — the tool detects what it has patterns for; parser-differential / fuzzer modules exist but are tiered/suspicious until confirmed.
- **Bookkeeping honesty** — prior scoreboard crossing labels were fixed; consent expiry (24h default) needs routine refresh.

### Roadmap (from `docs/TITAN_SPECIFICATION.md`)
- **Phase 1 (COMPLETED):** 37 modules hardened, zero-whitelisting, multi-dialect payloads, oracle enforcement, green regression.
- **Phase 2 (NEXT):** autonomous multi-step finding-chaining engine (`titan/ai/chain_engine.py`) + headless SPA route/GraphQL de-minifier.
- **Phase 3:** stateful multi-step workflow fuzzer (registration→invite→role→checkout).
- **Phase 4:** distributed estate + cloud asset graph (subdomain perm, CT-log monitoring).

### Operational guardrails (hard rules)
1. No download/clone/install without explicit operator OK.
2. One thread per session; 10-min timebox on detours; never escalate same failed approach.
3. State coverage limits **before** promising results.
4. The scan path requires consent (loopback / signed / practice manifest) — anything else is refused.
5. Bookkeeping tells the truth — a public host is never labeled `local-only`.

---

## 18. How to Run (5-minute)

```bash
# Bare metal (Windows uses ./venv/Scripts/python.exe; Linux/macOS venv/bin/python)
python -m venv venv
./venv/Scripts/python.exe -m pip install -r requirements.txt
./venv/Scripts/python.exe -m playwright install chromium
./venv/Scripts/python.exe -m pytest -q                 # sanity (green)

# Lab as firing range
./venv/Scripts/python.exe local_lab/app.py             # terminal 1, :5000
./venv/Scripts/python.exe titan_exploit_cli.py consent add http://127.0.0.1:5000 --write --shells --persistence
./venv/Scripts/python.exe run.py --target http://127.0.0.1:5000 --exploit --exploit-listener-start
```

Docker alternative: `docker compose up -d --build` (lab :5000, C2 :8770); run commands via `docker compose exec titan python <script> <args>`.

> **Authorization required.** Scan only systems you own or have explicit written
> permission to test. Track E exploitation is consent-gated; nothing stages without a
> signed, unexpired, in-scope consent file.

---

## 19. Pointer Index (existing living docs)
- `README.md` — feature overview, module ledgers, quick start.
- `ARCHITECTURE.md` — engine, oracles, chains, Track G, config schema.
- `MASTER-PLAN.md` — charter, capability gaps, roadmap, ethics, CTF rig.
- `OPERATORS-MANUAL.md` — full command surface, playbooks, troubleshooting, flywheel.
- `QUICKSTART.md` / `RUNBOOK.md` — install + first scan walkthroughs.
- `WHERE-WE-ARE.md` — unvarnished health check + Tier-0 incident resolution.
- `docs/TITAN_SPECIFICATION.md` — 37-module matrix + strategic roadmap.
- `learn/` — 12 lessons + 10 simulations + attack quicksheet.
