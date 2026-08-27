# Titan Scanner: Project Overview & Master Audit Ledger

![Tests](https://img.shields.io/badge/tests-1120%20collected%2C%20343%20passing-2ea44f)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)
![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)
![Status](https://img.shields.io/badge/engine-37%20modules%20exhausted-blue)
![Architecture](https://img.shields.io/badge/architecture-zero--whitelisting-purple)

**Titan** is an autonomous, high-precision security testing and vulnerability auditing engine engineered to uncover deep technical vulnerabilities across web applications, REST/GraphQL APIs, multi-tenant cloud backends, and AI/LLM interfaces.

> **Technical Specification & Architecture Reference:**  
> For the comprehensive 37-module specification matrix, verification oracle mechanics, and strategic engineering roadmap, see **[`docs/TITAN_SPECIFICATION.md`](docs/TITAN_SPECIFICATION.md)**.

---

## 1. Core Engine Highlights

* **37 Exhausted Detection Engines**: Complete coverage spanning Server-Side Injections, Identity/Access Control (BOLA, IDOR, JWT, Mass Assignment), State & Caching, Advanced API/GraphQL, Cloud Control Plane, LLM/AI Security, and Supply Chain.
* **Zero Parameter Whitelisting**: Every discovered query parameter, form input, JSON AST node, and ambient HTTP header is evaluated regardless of parameter naming.
* **Strict Verification Oracles**: Demotes false positives using inert echo suppression, multi-dialect math nonces, statistical timing baseline gates (`BlindDetector`), and out-of-band correlation (`Interactsh`).
* **Evidence-Graded Findings**: Every finding is tiered `confirmed` / `suspicious` / `none` with CVSS scoring, repro scripts, and PoC commands.
* **Flow-Typed Chain Analysis**: Multi-hop attack paths (SSRF + creds → Cloud Exposure, XSS + data leak → Session Hijack) with bounded candidate pools.
* **Interactive REPL**: Post-scan exploration with `ls`, `show`, `filter`, `repro`, `poc`, and `count` commands.
* **1120 automated regression tests** collected across all detector and oracle test suites.

---

## 2. Project Evolution & Specification Ledger

This ledger tracks the progression of architectural specifications, sprints, and milestones achieved across the project lifecycle:

| Specification / Document | Focus Area | Status | Key Milestones & Outcomes |
|:---|:---:|:---|:---|
| **[`docs/TITAN_SPECIFICATION.md`](docs/TITAN_SPECIFICATION.md)** | **Complete Engine Specification & Roadmap** | **ACTIVE / LIVING** | Definitive reference for all 38 modules, verification oracles, AST mechanics, and the strategic engineering roadmap. |
| **[`WHERE-WE-ARE.md`](WHERE-WE-ARE.md)** | **Project Audit & Health Check** | **HISTORICAL BASELINE** | Documents the baseline transition from early prototype testing to strict consent verification, S5 fail-closed authorization, and evidence gating. |
| **[`MASTER-PLAN.md`](MASTER-PLAN.md)** | **Charter, Ethics & Safety Gates** | **GOVERNING CHARTER** | Defines the operator keypair crypto consent model (Ed25519), strict authorization boundaries, and safe testing practices. |
| **[`OPERATORS-MANUAL.md`](OPERATORS-MANUAL.md)** | **CLI & Operation Workflow** | **ACTIVE REFERENCE** | Guide for running scans, managing consent tokens, configuring custom dictionaries, and interpreting tier reports. |
| **[`EVOLUTION-ROADMAP.md`](EVOLUTION-ROADMAP.md)** | **Strategic Roadmap** | **PHASES 0–5 COMPLETE** | All tracks shipped (A–G). Live in-scope validation per track is the remaining open item. |

---

## 3. Quick Start & Execution

```bash
# 1. Run full unit and detector verification suite
.\venv\Scripts\python.exe -m pytest tests/test_oracle_detectors.py tests/test_identity.py tests/test_lab_detection.py -v

# 2. Add signed consent for an authorized target
python titan_exploit_cli.py consent add http://target.local --write --expiry 7d

# 3. Launch an exhaustive scan against an authorized target
python run.py http://target.local --profile deep

# 4. Explore scan results interactively
python titan_repl.py findings/<site-slug>
```

---

## 4. AI Integration (Optional)

Titan includes an optional AI layer for payload mutation and edge-case generation. **The scanner works without AI** — all core detection, verification, and reporting functions operate with hardcoded payload sets. AI is a fallback for WAF bypass and unknown platforms, not a requirement.

### Option A: Free local model (recommended)

Run Ollama locally with a free model. No API keys, no accounts, no data leaving your machine.

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull a lightweight model suitable for 4-8GB RAM machines
ollama pull llama3:2b

# 3. Verify it works
ollama run llama3:2b "mutate this payload: ' OR 1=1-- - return only mutated payloads, one per line"
```

**Hardware guide:**

| Your RAM | Recommended model | Expected speed |
|----------|------------------|----------------|
| 4GB | `llama3:2b` (1.3GB) | ~15-25 tokens/sec |
| 8GB | `llama3:2b` or `llama3:8b` | ~2-5 tokens/sec (8B) |
| 16GB+ | `llama3:8b` or `mistral:7b` | ~10+ tokens/sec |

Then update `config.yaml`:

```yaml
ai:
  enabled: true
  model: "ollama/llama3:2b"
  fallback: "deepseek-chat"    # optional paid fallback
  ollama:
    host: "http://localhost:11434"
    model: "llama3:2b"
```

### Option B: Skip AI entirely

Set `ai.enabled: false` in `config.yaml`. The scanner uses only hardcoded payloads. All verification, baseline diffing, and reporting work without AI.

### Option C: Paid API with free tier

If you have API access to DeepSeek, OpenAI, or similar, configure:

```yaml
ai:
  enabled: true
  model: "deepseek-chat"
  api_key: "your-key-here"
  fallback: "ollama/llama3:2b"
```

### When AI actually helps

| Scenario | AI usefulness |
|----------|--------------|
| WAF bypass mutations | **High** — generates syntactic variants |
| Edge-case payloads when hardcoded sets return nothing | **Medium** — occasional novel variants |
| Unknown platform fallback | **Medium** — better than nothing |
| Verification decisions | **None** — use deterministic oracles |
| Business logic analysis | **None** — use platform brains |
| Cross-data inference | **None** — use deterministic algorithms |

### When AI does NOT help

AI is **not used** for:
- Verification or auto-demotion of findings
- Platform-specific test matrix generation
- Business logic reasoning
- CVE applicability checks
- Cross-data inference or access boundary analysis

These tasks require deterministic, reproducible logic. AI is non-deterministic and hallucinates. It is excluded from the analysis pipeline by design.

---

## 5. Attack Surface & Track Coverage

* **Track A (Client-Side & Browser)**: DOM XSS sink hooking, Prototype Pollution (`__proto__`, `constructor.prototype`), `postMessage` origin audits, CSP policy evaluation.
* **Track B (Identity & Access Control)**: BOLA 3-way cross-tenant differentials, Mass Assignment in JSON ASTs, JWT secret dictionary & `alg:none` cracking, Session Fixation lifecycle tracking.
* **Track C (LLM & AI Application Defense)**: Direct/Indirect prompt injection, system prompt extraction, OOB data exfiltration via tools, agent tool-abuse consensus judging.
* **Track D (Cloud & Control Plane)**: Public S3/GCS/Azure storage bucket discovery, IMDSv1/v2 probing, IAM STS role extraction, privilege escalation path simulation.
* **Track E (Exploitation Engine - Consent Gated)**: Verified finding → benign PoC validation and interactive session management.
* **Track G (Hostile & Supply Chain Surface)**: CI/CD Poisoned Pipeline Execution (PPE), npm/PyPI dependency confusion, ad redirect chains, browser cloaking, in-browser cryptominers.

---

## 6. Live Validation

Validated against authorized targets including:
* **OWASP Juice Shop** (local Docker instance)
* **Google Gruyere** (`google-gruyere.appspot.com`) — 8 findings in 6.6 min, including critical upload bypass and DOM XSS candidates
* **Local Lab** (`localhost:5000`) — 100% challenge pass rate

All scans use the evidence-gated verification pipeline: candidates → deterministic oracles → AI-assisted follow-up probes (optional) → confirmed/suspicious/false-positive tiering.

---

## 7. Repository Structure (Core)

```
titan-lab/
├── run.py                      # CLI entry: scan, dashboard (S5)
├── titan_exploit_cli.py        # Track E/F/G CLI: consent, listener, session
├── titan_repl.py               # Interactive REPL for scan exploration
├── config.yaml                 # Scan configuration
├── titan/                      # Core engine + 37 detection modules
├── tests/                      # 1120+ regression tests
├── local_lab/                  # Deliberately vulnerable Flask app
├── findings/                   # Scan output (gitignored)
├── consent/                    # Signed authorization files (gitignored)
├── docs/                       # Specification and deep-dive docs
├── learn/                      # 12-lesson educational content
└── bench/                      # Benchmark runner (results gitignored)
```

**Experimental / archived components** live on the `archive` branch: `purple/` (red/blue arena), `fleet/` (GitHub-linked red rounds), `titan-remote/` (phone remote control).

---

## 8. License & Ethics

**MIT License.** Use for authorized security testing only.

### Authorization Requirements

| Target Type | Authorization | Documentation |
|-------------|--------------|---------------|
| Own systems | None (owner) | System inventory |
| Client systems | Written contract | Signed agreement |
| Bug bounty | Platform terms | Program policy |
| CTF platforms | Implicit (designed for testing) | Platform rules |
| Public websites | **NONE** | **Do NOT scan** |

### Prohibited Actions

- Scanning targets without authorization
- Exfiltrating data beyond proof-of-concept
- Modifying/deleting data on target systems
- Disrupting service (DoS/DDoS)
- Bypassing security controls aggressively (stop on first block)

### Grey Hat Principles

| Principle | Application |
|-----------|-------------|
| **Own the systems** | Only test infrastructure you own or control |
| **Find everything** | Probe every parameter, every endpoint, every state |
| **Document everything** | Every finding, every PoC, every false positive |
| **Harden everything** | Every vulnerability found gets remediated |
| **Share knowledge** | Report to vendors, contribute to community |
| **Stay legal** | Written authorization before any scan |
| **Stay ethical** | No exfiltration, no destruction, no harm |

> **The goal is not to break things. The goal is to prove they can be broken — and then fix them.**
>
> The consent gate is code-enforced, but it cannot give you permission — only your authorization can. Scan only systems you own or have explicit written permission to test.
