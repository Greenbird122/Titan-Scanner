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
├── scanner/
│   ├── __init__.py
│   ├── config.py           # YAML + env loading, typed settings
│   ├── models.py           # Finding, Severity, Target, ScanResult dataclasses
│   ├── engine.py           # ScanEngine: orchestrates crawl → fuzz → verify → report
│   ├── crawler.py          # Deep JS crawling, API discovery (Swagger/GraphQL), auth flows
│   ├── fuzzer.py           # Context-aware fuzzer with parameter-type awareness
│   ├── payloads.py         # Dynamic payload generation via DeepSeek + static SecLists
│   ├── proxy.py            # Proxy rotation middleware (round-robin, random, sticky)
│   ├── verify.py           # Verification pipeline: baseline/diff, time-based, OOB
│   ├── reporter.py         # Markdown + JSON report, CVSS scoring, HackerOne templates
│   ├── plugins.py          # Plugin system for custom checks (SSTI, SSRF, XXE)
│   ├── stealth.py          # Rate limiting with jitter, UA rotation, delayed spread
│   └── integrations/
│       ├── __init__.py
│       ├── dawn.py         # Dawn memory, daily notes, TTS summaries
│       ├── titan_gov.py    # Titan Gov proposal pipeline, is_protected() checks
│       ├── deepseek.py     # BaseChatClient wrapper for payload generation
│       └── interactsh.py   # OOB detection via public Interactsh
├── dawn_integration/
│   ├── __init__.py
│   ├── cli.py              # /scan, /findings, /vulns commands
│   ├── tool_block.py       # TOOL:scan:<target> parser and executor
│   └── voice.py            # findings_for_speech() for TTS
├── config.yaml             # Full scanner configuration
├── requirements.txt        # Python dependencies
├── pytest.ini
├── tests/
│   ├── test_fuzzer.py
│   ├── test_verify.py
│   ├── test_payloads.py
│   ├── test_crawler.py
│   ├── test_proxy.py
│   ├── test_integrations.py
│   └── conftest.py
└── README.md
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

```yaml
scanner:
  target: "https://example.com"
  scope:
    include: ["/api/*", "/search"]
    exclude: ["/logout", "/admin"]
  aggression: "passive"  # passive | active | aggressive
  concurrency: 5
  rate_limit: 20
  jitter: 0.3  # ±30% randomness
  headless: true
  output_dir: "findings"
  proxy:
    enabled: false
    rotation: round-robin  # round-robin | random | sticky
    list: ["http://proxy1:8080", "http://proxy2:8080"]
  auth:
    url: "https://example.com/login"
    username: null
    password: null
    selectors:
      user: 'input[name="username"], input[type="email"]'
      pass: 'input[name="password"], input[type="password"]'
      submit: 'button[type="submit"]'
  payloads_file: "payloads/default.json"
  deepseek:
    enabled: true
    model: "deepseek-chat"
    fallback: "ollama"
    max_payloads_per_param: 20
  verify:
    enabled: true
    timeout: 10
    baseline_samples: 1
    diff_threshold: 0.3
  oob:
    enabled: false
    provider: "interactsh"  # interactsh | burp
    server: "https://interactsh.com"
  plugins:
    enabled: ["ssti", "ssrf", "xxe"]
  cvss:
    enabled: true
    version: "3.1"
  reporting:
    format: ["markdown", "json", "hackerone"]
  dawn:
    enabled: true
    memory: true
    voice: true
    gov: true
```

## 6. Non-Negotiables

- **Honesty**: Every finding must have a verified PoC or be marked `unverified`.
- **Privacy**: No exfiltration; all requests logged locally.
- **Governance**: Every scan goes through Titan Gov approval.
- **Stealth**: Configurable delays, jitter, and IP rotation by default.
- **Quality**: Type hints, docstrings, 90%+ test coverage, linted.
