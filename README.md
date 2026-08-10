# Titan Scanner

Async Playwright-based web vulnerability scanner with AI-assisted payload generation,
oracle verification, and per-site reports. Crawls a target, runs 19 detection modules,
replays + diffs to confirm every finding, scores with CVSS, and generates PoCs.

> **Authorization required.** Only scan systems you own or have explicit written
> permission to test. See [MASTER-PLAN.md](MASTER-PLAN.md) for the project charter.

---

## Quick start

```bash
# 1. Install dependencies (Python 3.10+)
./venv/Scripts/python.exe -m pip install -r requirements.txt
./venv/Scripts/python.exe -m playwright install chromium

# 2. Start the vulnerable test lab (optional, for validation)
./venv/Scripts/python.exe local_lab/app.py

# 3. Scan a target
./venv/Scripts/python.exe run.py --target http://localhost:5000
```

Every scan writes a site report under `findings/<site-slug>/`:

```
findings/localhost-5000/
├── report.md          # human-readable findings + PoCs
├── findings.json      # machine-readable finding records
└── scan_meta.json     # target, timestamps, config snapshot
```

## Run modes

```bash
# Scan the target configured in config.yaml
./venv/Scripts/python.exe run.py

# Scan a specific target
./venv/Scripts/python.exe run.py --target https://example.com

# Use a different config file
./venv/Scripts/python.exe run.py --target https://example.com --config my-scan.yaml

# Run the test suite
./venv/Scripts/python.exe -m pytest -q
```

Other entry points:

| Command | Purpose |
|---|---|
| `run.py` | Standard scan (recommended) |
| `main.py` | Same engine, minimal output |
| `run_titan.py` | Verbose scan with per-finding diffs |

## Configuration (`config.yaml`)

### Crawl

```yaml
crawl:
  max_pages: 10             # page budget per scan
  max_depth: 1              # link-depth budget
  timeout: 300              # wall-clock crawl budget (seconds). Findings stream
                            # in as they're verified, so a timeout never loses
                            # already-confirmed evidence.
  module_concurrency: 8     # max parallel attack modules. Lower it (e.g. 4) for
                            # gentler scans, raise it for speed. The module
                            # matrix is the biggest cost center of a scan.
```

### Stealth

```yaml
stealth:
  jitter: 0.3               # jitter fraction applied to each delay
  min_delay: 0.15           # min delay before each module probe (seconds)
  max_delay: 0.6            # max delay before each module probe (seconds)
```

Delays apply once per module invocation (~475 invocations on a busy page). Tuning
them down (e.g. `min_delay: 0.05`, `max_delay: 0.2`) is the single biggest speed
lever, at the cost of being noisier on the network.

### Modules

```yaml
modules:
  sqli:
    enabled: true
    timeout: 30             # optional per-module budget (seconds). Defaults:
                            # 30s for rce/sqli (statistical timing oracles need
                            # 3 samples per payload), 15s for everything else.
```

Each of the 19 modules (sqli, xss, ssrf, auth, idor, lfi, rce, nosqli, ssti, xxe,
api, upload, logic, crypto, deser, race, cache, smuggling, cors, headers) can be
disabled or given its own timeout.

### AI payload generation

```yaml
ai:
  enabled: true
  model: "deepseek-chat"
  fallback: "ollama"
  max_payloads_per_param: 20
```

If no provider is reachable the scanner **fails fast** and uses the built-in
payload library — it never hangs waiting on an unreachable model.

### Other keys

```yaml
target: "https://example.com"   # default scan target
aggression: "passive"           # passive | active
headless: true                  # headless browser
output_dir: "findings"          # site report root
governance:
  enabled: false                # Titan Gov approval gate (when true)
auth:                           # login flow for authenticated scans
  url: "..."                    # + username/password/selectors, roles: []
proxy:                          # optional proxy rotation
  enabled: false
  list: []
  rotation: "round-robin"
```

## Performance

Validated against the local lab (`local_lab/app.py`, 10 seeded vulnerabilities):

| Metric | Before tuning | After tuning |
|---|---|---|
| Page 1 processing | ~421s | ~155s |
| Full scan duration | ~616s | ~324s |
| Findings | 22 verified | 22 verified |
| Lab coverage | 10/10 | 10/10 |

Key changes: configurable/lighter stealth delays, concurrent discovery probes
(forms/links/API/JS/SPA/Swagger/Postman/GraphQL/params/methods run in parallel),
concurrent GET + POST API discovery (POST-only endpoints like `/api/login` and
`/hash` are now discovered), higher module concurrency, and — most importantly —
in-flight work is cancelled when the crawl budget expires (previously orphaned
tasks kept hammering the target for minutes after the timeout).

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design and
[LIVE-TESTING-PLAN.md](LIVE-TESTING-PLAN.md) for the live-target test matrix.
