# TITAN Scanner — Evidence-First Vulnerability Scanner

Titan crawls a web application like a real user and a real browser would, but instead of reporting every suspicious pattern it finds, it runs **negative controls** and **evidence grading** to produce findings with actual proof.

**One command:**
```bash
python -m titan scan http://localhost:3000
```

**What makes it different:**
- **Auto-verification:** Sends benign payloads alongside attack payloads. If both produce the same response, the finding is demoted. No more reflection-echo false positives.
- **BaaS-aware:** Detects Supabase/Firebase/AppWrite backends and audits RLS policies, auth settings, and anonymous access. Every other major scanner misses this entirely.
- **Evidence grading:** Every finding gets a tier (`confirmed`/`suspicious`/`none`) and an evidence grade. Only `confirmed` findings get CVSS scores and repro scripts.

## Proof of concept

Scanned a plain Python HTTP server on `localhost:3000` with zero intentional vulnerabilities. Result:

| Finding | Severity | Verified | Evidence |
|---------|----------|----------|----------|
| Missing security headers (HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy, Permissions-Policy) | HIGH | No | indicative |
| Content-Security-Policy weakness | MEDIUM | Yes | confirmed + repro script |

A scanner that finds real configuration issues against a vanilla server, with no fabricated findings.

## Quick start

```bash
git clone https://github.com/Greenbird122/titan-lab.git
cd titan-lab
pip install -r requirements.txt
cp config.example.yaml config.yaml
python -m titan scan http://localhost:3000
```

## Configuration

Edit `config.yaml` before scanning. Key settings:

```yaml
target: "http://localhost:3000"
crawl:
  profile: fast    # fast | deep | hostile
  max_pages: 40
  timeout: 600
modules:
  sqli:
    enabled: true
    timeout: 60
  xss:
    enabled: true
    timeout: 45
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
- Optional: Ollama for AI payload mutation

## License

MIT
