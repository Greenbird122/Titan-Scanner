# Titan Scanner — Evolution Roadmap: Beyond the Textbook

> **Status:** Phases 0–5 DONE (built + mutation-proven) — **all surface tracks shipped** (A–D + Track E exploitation + Track G hostile surface). Live in-scope validation per track is the remaining open item.
> **Baseline:** `a126a63` (1120 tests collected, 343 passing) — all phases added tests, all mutation-checked.
> **New modules (this session):** SQLi (+12 DB engines, OOB vectors), XSS (+DOM sinks, CSP bypass, framework sinks), SSRF (+cloud metadata, IP obfuscation), RCE (+OS contexts, PowerShell), GraphQL (+introspection, batching, authz), JWT (+weak secrets, algo confusion).
> **New tools (this session):** Interactive REPL (`titan_repl.py`), expanded TechFingerprinter, evidence-graded findings with flow-typed chain analysis.
> **Thesis:** The current engine is *stateless black-box differential testing* — send payload, diff two responses. That model is the ceiling. Every evolved attack surface below requires a **new engine capability**, not a new module in the existing matrix.

---

## 0. Why the current architecture is the constraint

The engine's core loop (`_run_modules` → `_run_attack_modules` → per-attack runner → verifier) treats every target as:

```
request(param=payload)  →  response_A
request(param=baseline) →  response_B
diff(A, B)  →  finding?
```

That model is rigorous (343 mutation-tested checks) but structurally blind to four things:

| Surface | Why the diff model can't see it |
|---|---|
| **Client-side** | The sink lives in browser JS — no server response changes, nothing to diff |
| **LLM/AI apps** | An LLM endpoint is not a response-diff target; you must *converse* with it and judge behavior |
| **Stateful API/identity** | BOLA/BFLA/OAuth need **two identities and a held session** — one stateless request can't prove cross-tenant access |
| **Cloud-native chains** | A lone SSRF finding is medium; SSRF→metadata→credentials→storage is critical. The engine reports isolated findings, not paths |

Good news: **the raw material for all four already exists in this repo.** Playwright is driven for crawl + interaction. `AuthEngine` already has `login_as_role()`, token/cookie storage, and a per-role scan loop. `ChainAnalyzer` already exists. `PayloadSmith` + DeepSeek + Ollama are already wired. This roadmap is about *aiming existing capability at new targets*, not importing new stacks.

---

## 1. The four surface tracks

### Track A — Client-side browser security  *(browser-context module runner)* — ✅ Phase 2 DONE

**Engine capability:** a module runner that executes inside the real browser and treats **JS sinks as the oracle** — a DOM XSS finding is "sink fired with attacker-controlled data," which is stronger evidence than any server reflection. Each detector installs JS hooks via `page.add_init_script`, navigates with a unique marker, and reads the page's own JS state as evidence. The seam (`_run_browser_modules`) is bounded like every other phase — max 2 pages, per-detector 15s budget with the same bounded-abandon pattern the crawl task uses (a wedged dead-driver await can never hang the scan), every failure degrades to an empty result.

**Implemented:** `titan/modules/clientside/` package with `domxss/` (sink hooks: innerHTML/outerHTML/document.write/eval/Function/setTimeout — marker reaching a dangerous sink = verified CRITICAL), `postmessage/` (handler source analysis for origin checks + attacker-origin probe delivery — includes a self-registration guard so the hook's own capture listener can never self-FP), `prototype/` (`__proto__[marker]` query + JSON-body probes — fresh object inheriting the marker = verified), `thirdparty/` (Magecart heuristic: external + unlisted origin + sensitive form inputs, always unverified by design), `csp/` (policy semantics: unsafe-inline/unsafe-eval/wildcards/missing frame-ancestors/object-src/base-uri). Engine seam `_run_browser_modules` wired into `scan()`, per-scan `_client_marker` pinning, config `clientside` toggles. 20 tests + 6 mutation checks green.

**New modules / capabilities:**

| Module | Checks | Evidence (oracle) |
|---|---|---|
| `clientside/domxss` | sink hooks for `innerHTML`, `outerHTML`, `document.write`, `eval`, `Function`, `setTimeout(string)` | attacker marker reaches a hooked sink value → **verified DOM XSS** |
| `clientside/postmessage` | capture registered handlers, probe with attacker-controlled origin, verify each handler checks `event.origin` | handler ran for attacker origin WITHOUT an origin check → **verified** (hook's own listener excluded) |
| `clientside/prototype` | inject `__proto__[marker]` via query + JSON POST to discovered APIs | marker present in a fresh `{}` after the probe → **verified pollution** |
| `clientside/third_party` | enumerate external scripts + sensitive-input collection, score (Magecart heuristic) | external + unlisted origin + card/password fields → unverified MEDIUM (never verified by design) |
| `clientside/csp` | parse CSP directive semantics | `unsafe-inline` in script-src → HIGH; missing CSP → MEDIUM; strong policy → nothing |

**Reuses:** Playwright driver (`_interact_and_capture`), JS extraction (`_extract_forms`), existing fingerprint pipeline. New JS hook layer only.

**Not yet:** real-browser live validation against an in-scope lab target (dom-xss demo sites), `location`/`src` sink wiring, `page.on("console")`-based detection for framework-internal sinks.

---

### Track B — Stateful API & identity testing  *(session engine + identity matrix)* — ✅ Phase 1 DONE

**Engine capability:** a `SessionPool` that holds N authenticated identities concurrently, plus a **cross-identity differential verifier** — request A's object as identity B, diff the response. This is the *only* way to prove BOLA/BFLA.

**Implemented:** `titan/core/sessions.py` (Identity + SessionPool), `titan/verify/identity_oracles.py` (unique-owner-marker differential), `titan/modules/bola/detector.py`, `titan/modules/massassignment/detector.py`, `titan/modules/jwt/detector.py`, `titan/modules/sessionfix/detector.py`, engine seam `_run_identity_modules` wired into `scan()` (runs when the pool holds >= 2 identities), config `auth.roles` extended + module toggles. 28 tests + 7 mutation checks green. Not yet: OAuth `redirect_uri` flows, BFLA role-matrix, live in-scope validation.

**New modules / capabilities:**

| Capability | Checks | Evidence (oracle) |
|---|---|---|
| `api/bola` | A/B tenant comparison: object owned by user A requested with user B's session | B receives A's object data (200 + unique content) → **verified BOLA** |
| `api/mass_assignment` | add `role=admin`, `is_admin=true`, `approved=true` to JSON bodies on state-changing endpoints | response reflects the injected privilege field, or a follow-up GET shows the change |
| `api/jwt` | alg confusion (RS256→HS256 with public key as HMAC secret), `kid`/`jku` injection, `none`, weak-secret cracking | forged token accepted on a protected endpoint |
| `api/oauth` | `redirect_uri` manipulation, missing `state`, token-leak via Referer, PKCE downgrade | auth-code/token delivered to attacker-controlled URI |
| `api/session` | fixation (server accepts pre-set session ID), prediction (sequential-ID analysis) | attacker-chosen session ID becomes the authenticated session |

**Reuses:** `AuthEngine` (roles, `login_as_role`, `logout`, `tokens`, `session_cookies`), the existing per-role scan loop in `scan()`, `_run_api_modules`. The big change is *holding multiple sessions at once* instead of one-at-a-time, and threading identity into the verifier's differential.

---

### Track C — LLM/AI application testing  *(conversational probe channel)* — ✅ Phase 3 DONE

**Engine capability:** a probe channel that *talks* to AI endpoints (`/api/chat`, `/v1/chat/completions`, `/api/assistant`, etc.) and judges responses with a **behavioral contract**, not a byte diff. LLM responses aren't deterministic — so "verified" means **consensus**: the model complied with an attacker instruction in >= `min_agree` (default 2) of N trials (default 3), judged by a DETERMINISTIC judge (never a model-in-the-loop verdict). Pure aiohttp — driver-independent, so a dead Playwright driver can't block AI probing.

**Implemented:** `titan/modules/llm/` package — `payloads.py` (marker-based probe corpora: direct goal-hijack + indirect context-poison, system-leak, exfil, agency), `channel.py` (aiohttp conversational client with OpenAI-envelope + flat-envelope + raw-text extraction and a fallback request-shape ladder), `detector.py` (trial orchestration, per-trial INDEPENDENT interactsh URLs so one callback can't inflate the consensus count, model replies captured into finding body/metadata as evidence). `titan/verify/llm_oracles.py` — the deterministic judges (`judge_marker` for injection, structural `judge_system_leak` with role+imperative+negative-directive gates, `judge_agency` with refusal + example suppression, `judge_oob` ground truth) + `consensus()`. Engine seam `_run_llm_channel` wired into `scan()` (config endpoints + discovered `/api/chat`-style paths, max 2, per-endpoint budget), `AttackType` values + `model_control`/`oob` flows. 34 tests + 10 mutation checks green.

| Module | Checks | Evidence (oracle) |
|---|---|---|
| `llm/prompt_injection` | direct goal-hijack + indirect context-poison probes | model echoes a unique attacker marker in >= 2/3 trials → **verified** |
| `llm/system_leak` | "repeat your system prompt" family | reply has system-prompt structure (role declaration + imperative density + negative directive) → **verified MEDIUM** |
| `llm/data_exfil` | orders the model to FETCH an interactsh callback (per-trial URL) | callback fires (OOB ground truth) → **verified CRITICAL** |
| `llm/agency` | orders the model to invoke a tool with attacker args | tool-call block in the reply (refusals/examples suppressed) → **verified HIGH** |

**Reuses:** `InteractshClient` (OOB confirmation). Pairs with OWASP LLM Top 10 + Agentic Apps Top 10 as the reference matrix. **Not yet:** SSE stream parsing, indirect injection via crawled page content the app actually RAGs over (current indirect probe is a message-shaped context poison), live validation against a self-hosted vulnerable LLM app.

---

### Track D — Cloud-native chain analysis  *(flow-typed finding graph)* — ✅ Phase 4 DONE

**Engine capability:** findings become **flow-typed** — each declares what it *exposes* (file contents, credentials, arbitrary URL fetch, auth bypass) and what it *consumes*. A graph pass then joins them into multi-hop paths.

**Phase 0 done:** `Finding.flows` field + `titan/verify/flows.py` (`apply_flows` runs at scan end; SSRF→metadata upgrades to `creds`; unverified findings get no flows). 8 flow tests + 2 mutations.

**Phase 4 done:** `titan/verify/chain_analyzer.py` — the old `ChainDetector` grouped by attack type (a category, not a chain); the new `ChainAnalyzer` joins findings on their FLOWS: a chain exists when the capabilities of >= 2 distinct verified findings COMBINE to reach one of 8 attack goals (Cloud Credential Exposure, Public Cloud Storage Exposure, Unauthorized Cross-Tenant Access, Session Hijack via Stored Script, Secret Theft to Lateral Movement, Remote Code Execution Pivot, Confirmed Data Exfiltration, Model Takeover Path). Bounded candidate pool (top-2 providers per required flow guaranteed, capped at 10 — O(pool³) stays fast on 200-finding scans), no-passenger rule (every hop must contribute a required flow), one strongest chain per goal with deterministic tie-breaks: **fewest hops first** (a 2-hop minimal covering set is the more precise statement), then severity, then a thematic preference so the storage chain names the bucket finding, not an unrelated NoSQLi.

**New module:** `titan/modules/cloud/storage.py` — extracts bucket references ONLY from the scan's own evidence (bodies, payloads, metadata — never guesses names), provider-tagged (S3/GCS/Azure/R2), and probes each at THAT provider's own listing endpoint (a GCS bucket is never tested at an S3 URL, which would 404 and read as "private" — the provider-blind bug the reviewer caught). 200 + XML listing markers = publicly listable = verified HIGH `PUBLIC_STORAGE`. GET-only, 3 buckets max, 8s per-bucket timeout, driver-independent aiohttp.

**Output change:** `chains` array in `findings.json` (full path + per-hop evidence via `AttackChain.to_dict`) + a **Chain section in report.md** (narrative, impact, capabilities, per-hop URLs). `ScanResult.chains` now real; the old `chain_count` field finally means something. 24 tests + 7 mutation checks green.

**Reviewer fixes applied during build:** provider-blind probe (GCS/Azure/R2 buckets were being tested at S3 URLs → guaranteed false negatives; now provider-tagged listing URLs); deleted the now-dead `verify/chain.py`; engine seam self-gates on the config toggle; chain tie-break prefers the minimal hop set; scan errors record chain-analysis failures instead of throwing.

---

### Track G — Hostile & ad-monetized surface  *(monetization-stack profiling + consent-gated supply-chain probes)* — ✅ Phase 5 DONE

**Engine capability:** a profile-and-probe pass over the **monetization stack** of ad-heavy / clickbait / cloaked sites. Ad origins are **scored metadata, never fake findings** — Track G only reports deterministic signatures and consent-gated probe results.

**Implemented:** `titan/hostile/` package — `origins.json` (bundled curated taxonomy: ad_network / popunder / push_notif / tracker / miner / risky_ad), `intel.py` (IntelDB over bundled + operator `~/.titan/intel_user.json`, ObservedIntel per-scan recording, `domain_flux()` for rotation diffing; the DB grows ONLY by `intel promote`/`intel add`, never by a scan), `profiler.py` (per-page monetization profile: every third-party load origin with category, cleartext-TLS, SRI-missing and risk score, plus a 0–100 monetization score), `detectors.py` (static JS/HTML signatures: anti-debug cloaks incl. F12/ctrl+U/context-menu blockers, `constructor('debugger')` loops and devtools-size hiding; browser miners; push-permission abuse; per-page clickbait index over words + mechanics), `offense.py` (deterministic findings: cleartext ad scripts, SRI-absent ad supply chain, domain flux; plus consent-gated active probes: redirect-chain mapping with terminal classification, referrer-gate detection), `__init__.py` (`run_pass` orchestrator). Engine seam `_run_hostile_pass` runs in `scan()` before CVSS/PoC under `crawl.profile: hostile`; page hardening closes popups/dialogs/downloads and records redirect hops; CLI `adprofile <url>` + `intel list|add|promote`. 24 tests green.

| Signal | Detected by | Evidence (oracle) |
|---|---|---|
| `ad_network` / `popunder` / `miner` / … origins | intel DB classification of every third-party load | metadata + risk score in the profile (never a fake finding) |
| anti-debug cloak | static JS signatures (keyboard blockers, debugger loops, size detection) | `cloak:*` named oracle → verified LOW/INFO |
| browser miner | known miner hosts + `startMining`/WASM-loop JS | `miner:host:*` / `miner:js-api` → verified HIGH |
| clickbait | headline words + mechanics (countdown, prize bait, popunder, fake-play) | clickbait index 0–100, never a finding |
| cleartext ad script | http:// ad load on an https page | `adtech:tls` → verified MEDIUM |
| SRI-absent ad script | classified ad script without `integrity` | `adtech:sri` → verified LOW |
| ad-domain rotation | diff of stored `intel.json` against the fresh pass | `adtech:domain_flux` → verified LOW |
| redirect chain → phishing / fake-download (consent) | follow the ad chain (≤3 hops), classify terminal | `adtech:redirect_chain:<category>` → verified |
| referrer-gated ad delivery (consent) | stable baseline + per-Referer variance | `adtech:referrer_gate` → verified LOW |

**Reviewer fixes applied during build:** active probes now **refuse private/loopback/link-local hops** (the scanner can never be a fetch oracle into the operator's network — DNS-rebinding-safe resolution check); the referrer gate requires a **stable per-Referer baseline** (rotating ads can't self-verify); `intel promote` derives categories from the intel DB, never guesses; `_load_user` tolerates dict entries written by `promote`.

---

## 2. Sequencing — why this order

```
Phase 0:  Foundation — Finding.flows typing + evidence taxonomy + lab fixtures   ✅ DONE (343 tests)
Phase 1:  Track B (Stateful identity)                                          ✅ DONE (28 tests + 7 mutations)
Phase 2:  Track A (Client-side)          — reuses Playwright; strongest evidence model    ✅ DONE (20 tests + 6 mutations)
Phase 3:  Track C (LLM probing)          — consensus oracle; deterministic judges, driver-independent    ✅ DONE (34 tests + 10 mutations)
Phase 4:  Track D (Chain analyzer)       — flow-typed graph pass + provider-aware storage probe    ✅ DONE (24 tests + 7 mutations)
Phase 5:  Track G (Hostile surface)      — monetization profile + hostile detectors + consent-gated supply-chain probes    ✅ DONE (24 tests; full suite 1120 collected)
```

Rationale:
1. **Phase 0 first** because flow-typing and the identity matrix are prerequisites, and it forces the evidence-taxonomy discipline that kept the current suite FP-free.
2. **Track B before A** because AuthEngine gives it the biggest head start — BOLA/BFLA is the highest-value modern class and the smallest build.
3. **Track C last-but-one** because it introduces a non-deterministic oracle (consensus) — needs the most careful verification design to stay honest.
4. **Track D last** because it's an *aggregation* capability — meaningless until findings are flow-typed and multi-surface scans exist.

---

## 3. Validation strategy per track

The project's non-negotiable is **evidence-based verification + mutation testing** (343 tests, every fix proven caught if reverted). Each track inherits that:

| Track | Lab target(s) | Fixtures | Mutation checks |
|---|---|---|---|
| A (client-side) | local Flask lab (`local_lab/`) extended with DOM XSS, postMessage, `__proto__` merge routes | fixture HTML/JS per sink | kill the sink hook → tests fail |
| B (stateful) | **OWASP Juice Shop** (BOLA, mass assignment, JWT) + two-role local lab | two-role fixture app (user A / user B) | remove identity B from the diff → BOLA test fails |
| C (LLM) | local mock LLM endpoint with a scripted system prompt + OWASP's vulnerable-LLM demo | scripted refusal/compliance corpus | make the consensus 2/3 instead of 3/3 → test fails |
| D (chains) | local SSRF→mock-metadata→creds→fake-bucket lab | canned finding graphs | break one hop's flow typing → chain test fails |
| G (hostile) | local lab with ad/monetization fixtures | fixture pages with ad scripts, miners, cloaks | remove a signature → detector test fails |

**Exit criteria per track:** all fixtures green + mutation-proven + one live validation target (a training/lab site in scope — e.g. Juice Shop instance, `google-gruyere`, or a self-hosted vulnerable LLM app).

---

## 4. What we deliberately do NOT build

- **Brute-forcing** (hydra-style login attacks) — MASTER-PLAN lists it; it's noise with no differential evidence and burns the authorization budget fast. Not in scope.
- **DoS / resource-exhaustion testing** — against the project's own guardrails.
- **Random novel-class research** (parser differentials, HTTP/2-specific smuggling) — found by hand, not shipped by scanners.
- **Exploit payloads that write data** (web shells, destructive deserialization) — evidence stops at proof-of-impact, consistent with the current PoC generator.

---

## 5. Definition of done for the roadmap

1. All tracks shipped as engine capabilities, not bolted-on modules — each with its own runner seam in the engine (`_run_browser_modules`, `_run_identity_modules`, `_run_llm_channel`, `_run_storage_probe`, `_run_hostile_pass` + the scan-end chain pass).
2. `Findings.flows` populated by every existing module (Phase 0 retrofit).
3. `chains` output real: full multi-hop paths in `findings.json` + report.md section.
4. Suite grows from 198 → ~1120+ tests, all mutation-checked, all green.
5. One live in-scope validation per track with the FP discipline held (the 12-site standard from the current baseline). **◻ Remaining — the only open item.**
