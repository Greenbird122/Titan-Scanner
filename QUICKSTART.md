# Titan Scanner — QUICKSTART

The command surface at a glance. For the full 5-minute clone → install →
first scan walkthrough see [RUNBOOK.md](RUNBOOK.md). For features and
`config.yaml` reference see [README.md](README.md). For design see
[ARCHITECTURE.md](ARCHITECTURE.md).

> **Authorization required.** Scan only systems you own or have explicit
> written permission to test. Track E exploitation is consent-gated — nothing
> stages without a signed consent file for the target.

---

## 1. Install

### Docker (zero local Python)

```bash
git clone https://github.com/Greenbird122/Vuln-scanner.git
cd Vuln-scanner
docker compose up -d --build
#   lab on :5000, C2 listener on :8770. Run any command inside the container:
#   docker compose exec titan python <script> <args>
```

### Bare metal (Python 3.10+)

```bash
python -m venv venv
./venv/Scripts/python.exe -m pip install -r requirements.txt   # Linux/macOS: pip install -r requirements.txt
./venv/Scripts/python.exe -m playwright install chromium
./venv/Scripts/python.exe -m pytest -q                          # sanity check: 1120+ tests collected
```

---

## 2. Scan

```bash
# Standard scan → findings/<site-slug>/ (report.md, findings.json, scan_meta.json)
./venv/Scripts/python.exe run.py --target https://example.com

# Custom config, or the default target from config.yaml
./venv/Scripts/python.exe run.py --config my-scan.yaml
./venv/Scripts/python.exe run.py

# Scan the bundled vulnerable lab (validated reference target)
./venv/Scripts/python.exe local_lab/app.py                       # terminal 1
./venv/Scripts/python.exe run.py --target http://localhost:5000  # terminal 2
```

---

## 3. Track E — exploitation (consent-gated)

```bash
# 1. Certify the target (scope = domain; covers subdomains + all paths)
./venv/Scripts/python.exe titan_exploit_cli.py consent add http://localhost:5000 --shells --expiry 24h
./venv/Scripts/python.exe titan_exploit_cli.py consent list
./venv/Scripts/python.exe titan_exploit_cli.py consent revoke http://localhost:5000

# 2. Scan with auto-staging (verified findings → agents / webshells / dumps)
./venv/Scripts/python.exe run.py --target http://localhost:5000 --exploit --exploit-listener-start

# 3. Drive the agent interactively (REPL)
./venv/Scripts/python.exe titan_exploit_cli.py session <session-id>
#   id, whoami, uname -a ...        run commands on the "compromised" host
#   /pivot <url>                    relay an internal URL through a verified SSRF sink
#   /rows /csv /transcript /files /export

# 4. Survive an operator restart (re-point survivors at a fresh listener)
./venv/Scripts/python.exe titan_exploit_cli.py reattach http://localhost:5000 --store findings --verify

# 5. Drive a survivor from another process (no port handoff)
./venv/Scripts/python.exe titan_exploit_cli.py session <session-id> --listener-url http://127.0.0.1:8770
```

Consent flags: `--write` (state changes), `--shells` (agent deployment),
`--persistence` (survivor re-pointing after an operator restart). No signed,
unexpired consent file with the required flag → the planner refuses before any
payload is sent.

---

## 4. Track G — hostile & ad-monetized surface

Profiles the **monetization stack** of ad-heavy / clickbait / cloaked sites (the
zairaku family): every third-party ad, popunder, push and miner origin with
TLS + SRI checks, a risk score, anti-debug cloaks, a per-page clickbait index,
and a 0–100 monetization score — delivered as `crawl.profile: hostile` in a
scan **and** as a standalone command.

```bash
# Standalone hostile profile (read-only) → findings/<slug>/hostile.json + intel.json
./venv/Scripts/python.exe titan_exploit_cli.py adprofile https://example.com [--pages N] [--output-dir DIR]

# Unlock the ACTIVE probes (redirect-chain → phishing mapping, referrer gates)
# with signed consent, exactly like Track E:
./venv/Scripts/python.exe titan_exploit_cli.py consent add https://example.com --expiry 24h
./venv/Scripts/python.exe titan_exploit_cli.py adprofile https://example.com

# Or run the full hostile scan profile (deep arsenal + hostile pass in one scan)
# crawl:
#   profile: hostile          # config.yaml
./venv/Scripts/python.exe run.py --target https://example.com

# Threat-intel DB (bundled taxonomy + your operator DB ~/.titan/intel_user.json)
./venv/Scripts/python.exe titan_exploit_cli.py intel list
./venv/Scripts/python.exe titan_exploit_cli.py intel add <host> <category>     # manual tag
./venv/Scripts/python.exe titan_exploit_cli.py intel promote <observed.json>   # merge observed origins (categories derived from the intel DB, never guessed)
```

Categories: `ad_network`, `popunder`, `push_notif`, `tracker`, `miner`,
`risky_ad`. Active probes are GET-only, bounded (3 hops / 6 chains), and
**refuse private/loopback/link-local destinations** — the scanner never
becomes a fetch oracle into your own network. Reference run: `adprofile
https://zairaku.rest` → monetization score 81/100, 3 ad origins, 6
anti-debug cloaks.

---

## 5. SHARPEN tools

```bash
# Interactive HTML dashboard of a scan you already ran (S5)
./venv/Scripts/python.exe run.py dashboard <site-slug-or-url>
# → findings/<slug>/dashboard.html

# Consent-gated read-only site mirror + hidden-endpoint map (S6)
./venv/Scripts/python.exe titan_exploit_cli.py archive https://example.com [--max-pages N] [--max-depth N]
# → findings/example-com/archive/index.html (explorer)

# One-shot SSRF relay through a verified sink (S4)
./venv/Scripts/python.exe titan_exploit_cli.py session <session-id> pivot http://192.168.1.10/secret
```

---

## 6. Command cheat-sheet

| Command | Purpose |
|---|---|
| `run.py --target <url>` | Standard scan → `findings/<site-slug>/` |
| `run.py --config <path>` | Scan with a custom config |
| `run.py --exploit --exploit-listener-start` | Scan + auto-stage verified findings (needs consent) |
| `run.py dashboard <slug>` | Render the interactive HTML dashboard (S5) |
| `titan_exploit_cli.py consent add/list/revoke <target>` | Sign / inspect / revoke consent |
| `titan_exploit_cli.py listener --port 8770` | Run the C2 listener (agent poll endpoint) |
| `titan_exploit_cli.py session <id>` | Interactive agent REPL (local listener) |
| `titan_exploit_cli.py session <id> --listener-url <url>` | Drive the agent through a remote listener |
| `titan_exploit_cli.py session <id> pivot <url>` | Relay an internal URL through a verified SSRF sink (S4) |
| `titan_exploit_cli.py session <id> rows/csv/transcript/dump/files/export` | Browse sqlidump evidence; export a session zip |
| `titan_exploit_cli.py reattach <target> [--listener-url ...]` | Re-point survivors after a restart (needs `--persistence`) |
| `titan_exploit_cli.py archive <target>` | Consent-gated mirror + endpoint map + explorer (S6) |
| `titan_exploit_cli.py adprofile <url>` | Hostile & ad-monetization profile (Track G) |
| `titan_exploit_cli.py intel list/add/promote` | Threat-intel DB: bundled taxonomy + operator origins |
| `python -m pytest -q` | Full test suite (1120+ tests collected) |

---

## 7. Where everything lands

```
findings/<site-slug>/
├── report.md          # human-readable findings + PoCs + attack chains
├── findings.json      # machine-readable finding records
├── scan_meta.json     # target, timestamps, config snapshot
├── dashboard.html     # interactive HTML dashboard (S5)
├── hostile.json       # Track G hostile profile + findings (adprofile / hostile scans)
├── intel.json         # Track G observed third-party origins (domain-flux input, M6)
├── archive/           # consent-gated site mirror (S6)
│   ├── index.html     # explorer
│   ├── pages/  assets/  endpoints.json
└── sessions/          # Track E sessions (<id>/session.json,
                       # transcript.log, data_samples/)
```

---

## 8. Going deeper

- [RUNBOOK.md](RUNBOOK.md) — full 5-minute walkthrough (Docker + bare metal, troubleshooting)
- [README.md](README.md) — feature overview, `config.yaml` reference
- [ARCHITECTURE.md](ARCHITECTURE.md) — engine, oracles, chains design
- [MASTER-PLAN.md](MASTER-PLAN.md) — project charter
