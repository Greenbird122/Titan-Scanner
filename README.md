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

## 4. Attack Surface & Track Coverage

* **Track A (Client-Side & Browser)**: DOM XSS sink hooking, Prototype Pollution (`__proto__`, `constructor.prototype`), `postMessage` origin audits, CSP policy evaluation.
* **Track B (Identity & Access Control)**: BOLA 3-way cross-tenant differentials, Mass Assignment in JSON ASTs, JWT secret dictionary & `alg:none` cracking, Session Fixation lifecycle tracking.
* **Track C (LLM & AI Application Defense)**: Direct/Indirect prompt injection, system prompt extraction, OOB data exfiltration via tools, agent tool-abuse consensus judging.
* **Track D (Cloud & Control Plane)**: Public S3/GCS/Azure storage bucket discovery, IMDSv1/v2 probing, IAM STS role extraction, privilege escalation path simulation.
* **Track E (Exploitation Engine - Consent Gated)**: Verified finding → benign PoC validation and interactive session management.
* **Track G (Hostile & Supply Chain Surface)**: CI/CD Poisoned Pipeline Execution (PPE), npm/PyPI dependency confusion, ad redirect chains, browser cloaking, in-browser cryptominers.

---

## 5. Live Validation

Validated against authorized targets including:
* **OWASP Juice Shop** (local Docker instance)
* **Google Gruyere** (`google-gruyere.appspot.com`) — 8 findings in 6.6 min, including critical upload bypass and DOM XSS candidates
* **Local Lab** (`localhost:5000`) — 100% challenge pass rate

All scans use the evidence-gated verification pipeline: candidates → deterministic oracles → AI-assisted follow-up probes (optional) → confirmed/suspicious/false-positive tiering.

---

## 6. Repository Structure (Core)

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

## 7. License & Ethics

**MIT License.** Use for authorized security testing only. The consent gate is code-enforced, but it cannot give you permission — only your authorization can. Scan only systems you own or have explicit written permission to test.
