# Titan Scanner

![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)
![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)
![Status](https://img.shields.io/badge/status-v0.1.0%20alpha-green)

**Titan** is an evidence-first vulnerability scanner for modern web applications. Instead of reporting every suspicious pattern, it runs negative controls and evidence grading to produce findings with actual proof.

## What makes it different

- **Auto-verification:** Sends benign payloads alongside attack payloads. If both produce the same response, the finding is demoted. No more reflection-echo false positives.
- **BaaS-aware:** Detects Supabase/Firebase/AppWrite backends and audits RLS policies, auth settings, and anonymous access. Every other major scanner misses this entirely.
- **Evidence grading:** Every finding gets a tier (`confirmed`/`suspicious`/`none`) and an evidence grade. Only `confirmed` findings get CVSS scores and repro scripts.
- **Business logic testing:** Domain-specific detectors for price tampering, order manipulation, card exposure, review XSS, and more.

## Quick start

```bash
# 1. Clone
git clone https://github.com/Greenbird122/titan-lab.git
cd titan-lab

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install Playwright browsers
playwright install chromium

# 4. Copy config template
cp config.example.yaml config.yaml

# 5. Start the local test lab (optional, but recommended for first run)
python -m titan lab start

# 6. In another terminal, scan the lab
python -m titan scan http://localhost:5000
```

## Local lab

Titan ships with a deliberately vulnerable Flask app for testing. Start it with:

```bash
python -m titan lab start
```

Then scan `http://localhost:5000`. The lab contains SQL injection, XSS, SSRF, upload, and business-logic flaws.

Check if the lab is already running:
```bash
python -m titan lab status
```

## Configuration

Edit `config.yaml` before scanning. Key settings:

```yaml
target: "http://localhost:3000"
crawl:
  profile: fast    # fast | deep | hostile
  max_pages: 40
modules:
  sqli:
    enabled: true
    timeout: 60
  baas:
    enabled: true
```

See `config.example.yaml` for all options.

## Output

Findings are written to `findings/<site-slug>/`:
- `findings.json` — full machine-readable results
- `report.md` — human-readable report with executive summary, findings, attack chains, and business logic impact
- `repros/` — executable repro scripts for confirmed findings

## Requirements

- Python 3.10+
- Playwright browsers (`playwright install chromium`)
- **Windows users:** Install [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) before `pip install -r requirements.txt` (required for `greenlet` dependency)
- Optional: Ollama for AI payload mutation

## Proof of concept

Scanned a plain Python HTTP server on `localhost:3000` with zero intentional vulnerabilities. Result:

| Finding | Severity | Verified | Evidence |
|---------|----------|----------|----------|
| Missing security headers (HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy, Permissions-Policy) | HIGH | No | indicative |
| Content-Security-Policy weakness | MEDIUM | Yes | confirmed + repro script |

A scanner that finds real configuration issues against a vanilla server, with no fabricated findings.

See [REPRO.md](REPRO.md) for the full scan output.

## License

MIT
