# Architecture: Next-Generation Vulnerability Scanner

## 1. Design Principles

- **Verification-first**: No finding is reported without replay + diff confirmation.
- **Stealth by default**: Human-like jitter, header randomization, IP rotation.
- **Honest failure**: All errors are surfaced; no fabricated results.
- **Modular core**: Same scanner package drives Dawn sub-command and standalone CLI.
- **Titan ecosystem native**: Uses existing DeepSeek client, Titan Gov approval, Dawn memory, and notification patterns.

## 2. Module Breakdown

```
vuln-scanner/
├── run.py                 # CLI entry: run.py [--target URL] [--config PATH]
│                          #   run.py dashboard <slug> (S5 HTML dashboard)
├── titan_exploit_cli.py   # Track E/F/G CLI: consent, listener, session (REPL),
│                          #   reattach, redirect, archive, adprofile, intel
├── config.yaml            # scan/crawl/stealth/modules/ai/exploit/auth/proxy
├── titan/
│   ├── core/              # engine.py (scan orchestration + every track seam),
│   │                      #   models.py (Finding/ScanResult), cvss.py, poc.py,
│   │                      #   auth.py (AuthEngine, roles), fingerprint.py,
│   │                      #   stealth.py, proxy.py, sessions.py (Identity/SessionPool),
│   │                      #   pathfuzz.py (response-driven path fuzzer)
│   ├── modules/           # 25 server-side detectors (sqli/, xss/, lfi/, rce/, …)
│   │                      #   + clientside/ (domxss, postmessage, prototype,
│   │                      #   thirdparty, csp), llm/, cloud/, redirect/
│   ├── verify/            # oracles.py (differential/boolean/time/OOB evidence),
│   │                      #   flows.py (capability typing), chain_analyzer.py
│   │                      #   (flow-typed multi-hop chains), ai_escalation.py,
│   │                      #   identity_oracles.py, llm_oracles.py
│   ├── exploit/           # Track E: consent.py (ed25519 gate), planner.py,
│   │                      #   listener.py (C2 poll endpoint), repl.py, session.py,
│   │                      #   sqli_extractor.py, upload_planner.py, webshell.py,
│   │                      #   reattach.py (M5 persistence)
│   ├── hostile/           # Track G: origins.json (intel DB), intel.py, profiler.py,
│   │                      #   detectors.py (cloaks/miners/push/clickbait), offense.py
│   ├── integrations/      # dawn.py, deepseek.py, interactsh.py, titan_gov.py
│   ├── ai/                # payloadsmith.py (provider + fallback payload generation)
│   ├── reporting/         # site report writer (report.md/findings.json/scan_meta.json
│   │                      #   + hostile.json/intel.json), dashboard.py
│   └── archive/           # S6 consent-gated site mirror + explorer
├── local_lab/             # deliberately vulnerable Flask lab (10 seeded vulns)
├── tests/                 # 1120+ tests collected (oracle, detector, lab, exploit, trackg, …)
├── Dockerfile / docker-compose.yml   # containerized lab + C2 listener
└── RUNBOOK.md / QUICKSTART.md       # 5-minute setup + command surface
```

## 3. Data Flow

```
User/Dawn Agent
    │
    ▼
ScanEngine
    │
    ├── TitanGov.propose(target, scope, aggression) ──► Human Review ──► Approved
    │
    ├── Crawler (Playwright + JS execution)
    │       ├── Static forms/links
    │       ├── JS-heavy click/scroll
    │       ├── Swagger/OpenAPI parse
    │       └── GraphQL introspection
    │
    ├── PayloadGenerator (DeepSeek + SecLists)
    │       ├── Tech-stack fingerprint
    │       ├── Parameter-type awareness
    │       └── Context-aware mutation
    │
    ├── Fuzzer (proxy-aware, stealthy)
    │       ├── Query params
    │       ├── Body (form, JSON, XML, multipart)
    │       ├── Headers (UA, X-Forwarded-For, etc.)
    │       ├── Cookies
    │       └── File uploads
    │
    ├── Verifier
    │       ├── Baseline request
    │       ├── Differential analysis (structural diff)
    │       ├── Time-based blind (sleep/delay detection)
    │       ├── OOB (Interactsh DNS/HTTP callbacks)
    │       └── Multi-step replay (reflect → redirect → cookie)
    │
    ├── Scorer (CVSS v3.1)
    │
    ├── Reporter
    │       ├── Markdown report
    │       ├── JSON findings
    │       ├── curl PoC commands
    │       └── HackerOne/Bugcrowd templates
    │
    └── Integrations
            ├── Dawn: append_daily(), MEMORIZE: vuln|..., findings table
            ├── Titan Gov: audit log (JSONL)
            └── Notify: tray toast for critical findings
```

## 4. Milestones

> **Historical plan (pre-rename).** The module names below (`fuzzer.py`,
> `crawler.py`, `verify.py`, `reporter.py`, `plugins.py`) are from the
> original `scanner/` package plan. In the current tree they landed inside
> `titan/`: `titan/core/engine.py` (orchestration), `titan/core/pathfuzz.py`
> (fuzzing), `titan/core/auth.py` + `titan/core/sessions.py` (auth flows),
> `titan/verify/oracles.py` (verification), `titan/reporting/` (reporting),
> and `titan/modules/*` (per-attack detectors). The milestone scope below is
> still the shape of what shipped.

### M1: Intelligent Fuzzer with DeepSeek (Weeks 1-2)
- Scanner package structure
- `payloads.py`: DeepSeek-powered dynamic payload generation
- `fuzzer.py`: Context-aware fuzzing with parameter-type detection
- `stealth.py`: Rate limiting + jitter + UA rotation
- Tests + config

### M2: Crawler + API Discovery (Weeks 3-4)
- `crawler.py`: Deep JS crawling, Swagger/GraphQL discovery
- `proxy.py`: Proxy rotation middleware
- Auth flow support (OAuth, 2FA fallback)

### M3: Verification Pipeline (Weeks 5-6)
- `verify.py`: Baseline/replay, differential DOM/JSON diff
- Time-based blind detection
- OOB integration (Interactsh)
- Multi-step verification

### M4: Dawn/Titan Integration (Weeks 7-8)
- `dawn_integration/`: TOOL:scan block, /scan command
- Titan Gov proposal pipeline
- Dawn memory (daily notes + SQLite findings table)
- TTS summaries

### M5: Reporting + Plugins (Weeks 9-10)
- `reporter.py`: CVSS scoring, PoC generation, export templates
- `plugins.py`: Plugin system for SSTI, SSRF, XXE
- Comprehensive test suite

## 5. Configuration Schema

The live schema is `config.yaml` (the single source of truth — every key is
consumed directly by `titan/core/engine.py`). Top-level keys:

```yaml
target: "https://example.com"   # default scan target
aggression: "passive"           # passive | active
headless: true
output_dir: "findings"
governance:                     # Titan Gov approval gate (when enabled)
auth:                           # login flow: url + username/password/selectors,
                                #   roles: [] for multi-role identity scans (Track B)
proxy:                          # optional rotation: enabled/list/rotation
crawl:
  profile: "fast"               # fast (default) | deep | hostile (Track G pass)
  max_pages / max_depth / timeout / module_concurrency / fuzz
stealth:
  jitter / min_delay / max_delay / adaptive
modules:                        # per-module toggles + timeouts (sqli, xss, lfi, …)
clientside:                     # Track A toggles (domxss, postmessage, prototype, …)
llm:                            # Track C endpoints + trial quota
cloud:                          # Track D storage probe
ai:                             # payload generation: enabled/model/fallback/
                                #   max_payloads_per_param + escalate (verdicts)
exploit:                        # Track E: enabled/consent_dir/output_dir/max_per_type/
                                #   budget/listener
```

## 6. Track G — Hostile & Ad-Monetized Surface

A fifth seam for **ad-heavy / clickbait / cloaked sites** (the zairaku family):
profiles the monetization stack as attack surface. Enabled via
`crawl.profile: hostile` in a scan (deep arsenal + hostile pass) or the
standalone `adprofile <url>` command. Pure aiohttp — runs even if the
Playwright driver died.

### Package: `titan/hostile/`

```
titan/hostile/
├── origins.json      # bundled curated taxonomy (ad_network / popunder /
│                     #   push_notif / tracker / miner / risky_ad)
├── intel.py          # IntelDB (bundled + ~/.titan/intel_user.json), ObservedIntel,
│                     #   domain_flux() — the DB grows only by operator action
├── profiler.py       # per-page monetization profile: third-party origins with
│                     #   category, cleartext-TLS, SRI-missing, risk score,
│                     #   monetization score 0-100; ad origins = metadata, never findings
├── detectors.py      # static JS/HTML signatures: anti-debug cloaks (F12/ctrl+U/
│                     #   context-menu, debugger-loop, devtools-size), miners,
│                     #   push abuse, clickbait index (words + mechanics)
├── offense.py        # deterministic findings (cleartext ad scripts, SRI-absent
│                     #   supply chain, domain flux) + consent-gated active probes
│                     #   (redirect-chain -> terminal classification, referrer gate)
└── __init__.py       # run_pass() orchestrator + findings_from_dicts()
```

### Engine seam

`scan()` runs `_run_hostile_pass(target, result)` **before** the CVSS/PoC loop so
hostile findings get scored. The pass fetches up to 3 in-scope pages over its own
aiohttp session, merges per-origin profiles, persists `hostile.json` + `intel.json`,
and appends rebuilt findings into `result.findings`. Read-only analysis always runs;
the **active probes only under a signed, unexpired consent file** for the target
(`_has_consent` — the same ed25519 gate as Track E). Page hardening (`_harden_page`)
closes popups/popunders, dismisses dialogs, suppresses downloads, and records 3xx
hops into a bounded redirect chain.

### Evidence discipline (the zairaku storm lesson)

Reflection / content-change is **never** evidence on ad-heavy SPAs. Every Track G
signal carries a named deterministic oracle (`adtech:tls`, `cloak:keyboard-block`,
`miner:host:coinhive.com`, `adtech:redirect_chain:phishing`, ...); the evidence gate
and root-cause dedup (SCAN-QUALITY M1) still apply. Ad origins are scored metadata,
not vulnerability rows.

### Active-probe safety

GET-only, no cookies, bounded (3 hops / 6 chains / 8s per request). Every hop is
resolved and **refused when any A/AAAA record is private / loopback / link-local /
reserved** (DNS-rebinding safe) — the scanner can never be turned into a fetch
oracle into the operator's own network. The referrer-gate probe fetches each Referer
twice and requires a stable baseline, so rotating ad content cannot self-verify.

---

## 7. Non-Negotiables

- **Honesty**: Every finding must have a verified PoC or be marked `unverified`.
- **Privacy**: No exfiltration; all requests logged locally.
- **Governance**: Every scan goes through Titan Gov approval.
- **Stealth**: Configurable delays, jitter, and IP rotation by default.
- **Quality**: Type hints, docstrings, 90%+ test coverage, linted.
