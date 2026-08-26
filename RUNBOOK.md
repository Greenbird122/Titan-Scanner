# Titan Scanner — RUNBOOK

> **Goal:** clone, install, and run your first scan in **~5 minutes**.
>
> Every command below was executed live and verified end-to-end (1120 tests
> collected, 343 passing, full M1→M5+ exploitation pipeline plus the S4–S6 SHARPEN tools and
> the Track G hostile-surface profile demonstrated). It is written
> **copy-paste first** — adjust only the `PY` placeholder below for your OS.

**Authorization required.** This scanner converts *verified* findings into
real access (agents, webshells, SQLi dumps). Scan **only systems you own or
have explicit written permission to test.** The consent gate is code-enforced,
but it cannot give you permission — only your authorization can.

---

## 0. Prerequisites

Pick **one** runtime:

| Requirement | Version / note |
|---|---|
| **Docker** (Method A) | Docker Desktop (Windows/macOS) or Docker Engine (Linux) — `docker --version` |
| **or** Python (Method B) | 3.10+ (`python --version`) |
| Git | any recent version |
| Network | outbound HTTPS (Playwright browser download, AI providers) |

**Method A (Docker)** needs no local Python at all. **Method B (bare metal)**
uses a `PY` placeholder below:

- **Windows (this repo's dev machine):** `PY=./venv/Scripts/python.exe`
- **Linux / macOS:** `PY=python3` (or activate a venv: `source venv/bin/activate`)

---

## 1. Setup (≈3 minutes)

### Method A — Docker (≈1 minute, recommended)

```bash
# 1. Clone
git clone https://github.com/Greenbird122/Vuln-scanner.git
cd Vuln-scanner

# 2. Build + start everything (lab on :5000, C2 listener on :8770)
#    First build downloads Chromium (~5 min once, layer-cached afterwards).
docker compose up -d --build

# 3. Verify
docker compose ps
```

That's the whole setup — no Python, no venv, no Playwright install on your
machine. **Every bare-metal command in this runbook maps to:**

```bash
docker compose exec titan python <script> <args>
```

e.g. the first scan is `docker compose exec titan python run.py --target
http://127.0.0.1:5000`. Scan output persists on your host in `./findings/`
and consent files in `./consent/`.

### Method B — bare metal (venv)

```bash
# 1. Clone
git clone https://github.com/Greenbird122/Vuln-scanner.git
cd Vuln-scanner

# 2. Create a venv (Windows PowerShell: python -m venv venv)
python -m venv venv

# 3. Install dependencies
./venv/Scripts/python.exe -m pip install -r requirements.txt      # (Linux/macOS: pip install -r requirements.txt)

# 4. Install the Playwright browser (needed for crawling + client-side checks)
./venv/Scripts/python.exe -m playwright install chromium

# 5. Sanity check — the test suite (fast subset first, ~1 min)
./venv/Scripts/python.exe -m pytest -q
```

> `requirements.txt` is tiny: `playwright`, `aiohttp`, `pyyaml`, `requests`,
> `flask`, `PyJWT`, `cryptography`, `pytest`, `pytest-asyncio`. No system
> services, no database, no external API keys required to scan.

> **Cross-platform heads-up (Linux/macOS):** every bare-metal command in the
> rest of this runbook uses `./venv/Scripts/python.exe` — the **Windows** venv
> layout. On Linux/macOS run the identical command with `venv/bin/python`
> (or `python3` if you didn't create a venv):
>
> ```bash
> # Windows                                 # Linux/macOS
> ./venv/Scripts/python.exe run.py ...      venv/bin/python run.py ...
> ./venv/Scripts/python.exe titan_exploit_cli.py consent add ...   venv/bin/python titan_exploit_cli.py consent add ...
> ```
>
> In Docker mode (Method A) the translation is `docker compose exec titan
> python <script> <args>` — no interpreter path at all. See
> [§9 Cross-platform notes](#9-cross-platform-notes) for what's verified.

---

## 2. Your first scan (≈2 minutes)

> **Docker mode** (Method A): the lab and listener are already running in the
> container — jump straight to the commands. The lab is reachable at
> `http://127.0.0.1:5000` *inside* the container (or `http://localhost:5000`
> from your host).

### 2a. Scan a live site

```bash
./venv/Scripts/python.exe run.py --target https://example.com
```

That's it. The scan crawls, runs 24+ detection modules across six tracks,
replays + diffs to confirm each finding, scores with CVSS, composes attack
chains, and writes a report:

```
findings/example-com/
├── report.md          # human-readable findings + PoCs + attack chains
├── findings.json      # machine-readable finding records
└── scan_meta.json     # target, timestamps, config snapshot
```

### 2b. Scan the bundled vulnerable lab (validated reference target)

Terminal 1 — start the lab (10 seeded vulnerabilities, binds `:5000`):

```bash
./venv/Scripts/python.exe local_lab/app.py
```

Terminal 2 — scan it:

```bash
./venv/Scripts/python.exe run.py --target http://localhost:5000
```

Expected: ~10 verified findings across SQLi/RCE/LFI/XSS/IDOR/CORS/crypto —
see `findings/localhost-5000/report.md`.

### 2c. Explore scan results interactively (REPL)

```bash
python titan_repl.py findings/localhost-5000
titan> ls
titan> show 0
titan> filter severity high
titan> repro 0
titan> count
```

The REPL loads `findings.json` and `scan_meta.json` from any scan directory.
Commands: `ls`, `show <id>`, `filter <severity|type>`, `reset`, `meta`,
`repro <id>`, `poc <id>`, `count`, `help`.

---

## 3. Configuring a scan

Everything lives in [`config.yaml`](config.yaml) (target, crawl budget,
stealth delays, per-module toggles/timeouts, AI provider, Track E exploit
settings). Run with a different config:

```bash
./venv/Scripts/python.exe run.py --target https://example.com --config my-scan.yaml
```

**The two knobs that matter most:**

- `crawl.timeout` (default 300 s) — findings stream in as they're verified, so
  hitting the budget never loses confirmed evidence.
- `stealth.min_delay` / `max_delay` — the biggest speed lever. Tuning down to
  `0.05`/`0.2` roughly halves scan time at the cost of network noise.

`config.yaml` is preconfigured with the fast/tuned defaults validated against
the lab (full scan ≈ 324 s, 10/10 lab coverage).

---

## 4. Track E — the exploitation pipeline (consent-gated)

> **Docker mode** (Method A): the container already runs the C2 listener on
> `:8770`, so use `--exploit` **without** `--exploit-listener-start` (the scan
> health-checks and reuses the running listener), and drive sessions via
> **remote join** — `session <id> --listener-url http://127.0.0.1:8770` —
> because the always-on listener holds the port (a local-REPL attempt prints
> the "port in use" message and queues only).
>
> Note: that always-on listener is **unauthenticated by design** — the consent
> gate is the boundary, not listener auth. Compose publishes it to the host on
> loopback only (`127.0.0.1:8770`), and it's reachable by other containers on
> the compose network. Keep the host binding loopback-only unless you intend
> otherwise.

> This is the offensive track: verified RCE → polling agent, verified upload →
> webshell, verified SQLi → structured dump, verified SSRF → one-way internal
> relay (§4g). **Nothing stages without a signed consent file for the target.**

### 4a. Sign consent for the target

```bash
# Certify the target (scope = domain; covers subdomains + all paths)
./venv/Scripts/python.exe titan_exploit_cli.py consent add http://localhost:5000 --shells --expiry 24h

# See what you've certified / revoke
./venv/Scripts/python.exe titan_exploit_cli.py consent list
./venv/Scripts/python.exe titan_exploit_cli.py consent revoke http://localhost:5000
```

Consent flags: `--write` (state changes), `--shells` (agent deployment),
`--persistence` (re-pointing survivors after an operator restart). Consent
files are ed25519-signed with your operator keypair (`~/.titan/consent.key`,
0600) and the gate pins the public key — consents signed by any other key are
refused.

> **Docker vs bare metal = separate operator keys.** In Docker mode the
> keypair lives in the `titan-keys` volume (`/root/.titan`); in bare metal it's
> your home dir. A consent signed under one mode is **refused** under the
> other — and `docker compose down -v` wipes the Docker keys. Pick one mode
> per target.

### 4b. Scan with auto-staging

```bash
# Scan runs its own C2 listener and tears it down after the exploit phase
./venv/Scripts/python.exe run.py --target http://localhost:5000 --exploit --exploit-listener-start
```

Expected output: verified RCE → `Track E: rce-agent session <session-id>
staged`. Sessions land under `findings/localhost-5000/sessions/<id>/`
(`session.json`, `transcript.log`, `data_samples/`). No consent for the
target → the phase stages nothing and records a note (never fails the scan).

### 4c. Drive the agent interactively (REPL)

```bash
./venv/Scripts/python.exe titan_exploit_cli.py session <session-id>
#   id, whoami, uname -a ...     run commands on the "compromised" host
#   /jobs /transcript /export    inspect evidence; export session zip
#   exit
```

REPL commands for sqli-dump sessions: `rows`, `csv`, `transcript`, `dump`,
`files`, `export`. For ssrf-pivot sessions: `/pivot <url>` (see §4g).

### 4d. Survive an operator restart — reattach (M5)

```bash
# Re-point surviving channels at a listener this command keeps up
./venv/Scripts/python.exe titan_exploit_cli.py reattach http://localhost:5000 --store findings --verify

# Or re-point at an external listener you already run
./venv/Scripts/python.exe titan_exploit_cli.py reattach http://localhost:5000 --listener-url http://127.0.0.1:8770

# Scope to one session / skip the liveness ping
./venv/Scripts/python.exe titan_exploit_cli.py reattach http://localhost:5000 --sid <session-id> --verify-timeout 10
```

Requires consent **with `--persistence`**; dead channels are recorded and
never abort the rest (fail-soft).

### 4e. Drive the survivor from a separate process (M5+, remote join)

```bash
# No port handoff — jobs/results travel over the listener's HTTP API
./venv/Scripts/python.exe titan_exploit_cli.py session <session-id> --listener-url http://127.0.0.1:8770
```

A dead remote listener fails soft: the REPL reports it and keeps running.

### 4f. Manual mode (alternative to 4b)

```bash
# Terminal 1 — run the C2 listener yourself (agents poll it)
./venv/Scripts/python.exe titan_exploit_cli.py listener --port 8770

# Terminal 2 — open a session REPL and queue commands
./venv/Scripts/python.exe titan_exploit_cli.py session <session-id>
```

### 4g. SSRF pivot — relay into the internal network (S4)

The fourth exploitation channel: a **verified** SSRF finding is consumed as a
one-way relay — give it an internal URL and the vulnerable endpoint fetches it
for you. Probes default to cloud-metadata endpoints
(`http://169.254.169.254/latest/meta-data/`) and the response is matched
against reflection-stripped content markers, so a server that merely mirrors
your input back can't fake a successful fetch.

Only verified SSRF findings stage a pivot session (same consent gate as every
other channel). Drive the stored session's sink from the REPL, or one-shot:

```bash
# Inside the session REPL — relay any internal URL through the verified sink
/pivot http://192.168.1.10/secret

# One-shot browse (no REPL), same shape as rows/csv
./venv/Scripts/python.exe titan_exploit_cli.py session <session-id> pivot http://192.168.1.10/secret
```

Each relay is recorded in the session transcript and the response is saved as
an evidence sample in `data_samples/`.

---

## 5. Verification & evidence

```bash
# Full test suite (1120+ tests collected — run this before reporting a bug)
./venv/Scripts/python.exe -m pytest -q

# Export a session as a zip for evidence handoff
./venv/Scripts/python.exe titan_exploit_cli.py session <session-id> export --out evidence.zip
```

Every finding is **verified before it is reported** — unconfirmed results are
flagged, never silently trusted.

---

## 6. SHARPEN extras — dashboard & site archive

### 6a. Interactive dashboard (S5)

Every scan persists `findings/<slug>/findings.json` + `scan_meta.json`. Render
them as a single self-contained HTML report — severity / attack / evidence
filters, full-text search, sortable rows, expandable findings with PoC copy
buttons, plus chains and exploitation sessions. No external assets; safe to
email as a file.

```bash
./venv/Scripts/python.exe run.py dashboard <site-slug-or-url>
#   e.g.  run.py dashboard localhost-5000  →  findings/localhost-5000/dashboard.html
```

### 6b. Site archive (S6)

A consent-gated, read-only mirror of an approved target: every visible page and
in-scope asset, plus the **invisible surface** — every referenced API path,
JSON endpoint, and form action — collected into an endpoint map. Mirrored
pages are link-rewritten so the whole mirror is clickable offline.

```bash
# Archive needs signed consent for the target (any flags — it is read-only)
./venv/Scripts/python.exe titan_exploit_cli.py consent add https://example.com --expiry 24h
./venv/Scripts/python.exe titan_exploit_cli.py archive https://example.com [--max-pages N] [--max-depth N]
```

Output: `findings/example-com/archive/` — `index.html` explorer, `pages/`,
`assets/`, `endpoints.json`.

### 6c. Hostile & ad-monetized surface profile (Track G)

For ad-heavy / clickbait / cloaked sites (the zairaku family), Track G profiles
the **monetization stack** as attack surface: every third-party ad/popunder/
push/miner origin with TLS + SRI checks and a risk score, anti-debug cloaks,
a per-page clickbait index, and a 0–100 monetization score — plus, under
signed consent, the bounded active probes (redirect-chain → phishing mapping,
referrer-gate detection). Active probes are GET-only, capped, and refuse
private/loopback/link-local destinations.

```bash
# Read-only hostile profile → findings/<slug>/hostile.json + intel.json
./venv/Scripts/python.exe titan_exploit_cli.py adprofile https://example.com

# Unlock the active probes with signed consent (same gate as Track E)
./venv/Scripts/python.exe titan_exploit_cli.py consent add https://example.com --expiry 24h

# Or bake the hostile pass into a scan: crawl.profile: hostile in config.yaml
# Threat-intel DB: bundled taxonomy + your operator DB
./venv/Scripts/python.exe titan_exploit_cli.py intel list
./venv/Scripts/python.exe titan_exploit_cli.py intel add <host> <category>
./venv/Scripts/python.exe titan_exploit_cli.py intel promote <observed.json>
```

Reference run: `adprofile https://zairaku.rest` → monetization score 81/100,
3 classified ad origins, 6 anti-debug cloaks.

---

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `docker: command not found` | Docker isn't installed — use Method B (venv), or install Docker Desktop/Engine. |
| `docker compose up` builds but the lab never answers | First build installs Chromium (~5 min). Check `docker compose logs titan`; then `curl localhost:5000`. |
| Stale code / rebuild needed | `docker compose build --no-cache` (or just `docker compose up -d --build` to use the cache). |
| `session <id>` prints "port in use" in Docker mode | Expected — the container's always-on listener holds 8770. Use remote join: `session <id> --listener-url http://127.0.0.1:8770`. |
| Scan reports land in the container, not on my host | `findings/` is a bind mount — they persist on the host as long as you run compose from the repo root. |
| Linux: `findings/`/`consent/` files owned by root after Docker runs | The container runs as root. `sudo chown -R $USER:$USER findings consent`, or just stick to one mode per target. |
| `playwright: executable doesn't exist` | `python -m playwright install chromium` |
| Scan hangs on AI payload gen | Provider unreachable → scanner fails fast to the built-in payload library. Check `ai.*` in config or set `ai.enabled: false`. |
| `[!] Track E staged nothing` | No signed/valid consent for the target. `consent list` to confirm; re-add with the flags the technique needs (`--shells` for RCE agents, `--write` for webshells). |
| `session` REPL can't connect | Listener isn't running (or wrong port). Start `listener --port 8770` or use `--listener-url`. |
| Agent answers nothing | The lab kills its subprocess at 5 s — `/cmd` on the local lab hard-terminates the piped bash. Use a target whose command sink isn't short-lived, or check `transcript.log` for timeouts. |
| Port 5000/8770 already in use | Old process from a prior run. `netstat -ano | grep :<port>` and kill the LISTENING PID. |
| Windows path weirdness in bash | Use `/c/Users/...` style paths in Git Bash, or run the `PY` commands in PowerShell/cmd. |

---

## 8. Command cheat-sheet

| Command | Purpose |
|---|---|
| `docker compose up -d --build` | Build + start the whole stack (Docker mode) |
| `docker compose exec titan python <script> <args>` | Run any CLI command inside the container |
| `docker compose exec titan python -m pytest -q` | Full test suite in the container |
| `run.py --target <url>` | Standard scan → `findings/<site-slug>/` |
| `run.py --config my-scan.yaml` | Scan with a custom config |
| `run.py --exploit --exploit-listener-start` | Scan + auto-stage verified findings (needs consent) |
| `titan_exploit_cli.py consent add/list/revoke <target>` | Sign / inspect / revoke consent |
| `titan_exploit_cli.py listener --port 8770` | Run the C2 listener (agent poll endpoint) |
| `titan_exploit_cli.py session <id>` | Interactive agent REPL (local listener) |
| `titan_exploit_cli.py session <id> --listener-url <url>` | Drive the agent through a remote listener |
| `titan_exploit_cli.py reattach <target> [--listener-url ...]` | Re-point survivors after a restart (needs `--persistence`) |
| `titan_exploit_cli.py session <id> pivot <url>` | Relay an internal URL through a verified SSRF sink (S4) |
| `titan_exploit_cli.py archive <target>` | Consent-gated mirror + endpoint map + explorer (S6) |
| `titan_exploit_cli.py adprofile <url>` | Hostile & ad-monetization profile (Track G) |
| `titan_exploit_cli.py intel list/add/promote` | Threat-intel DB: bundled taxonomy + operator origins (Track G) |
| `run.py dashboard <slug>` | Render the interactive HTML dashboard (S5) |
| `python -m pytest -q` | Full test suite (544 passing) |

---

## 9. Cross-platform notes

This runbook was audited for first-time Linux/macOS runs. What's verified and
what isn't:

- **CI runs Linux.** The 544-test suite is green on Linux runners; a few
  tests are `win32`-skipped only where they pin the Windows lab's exact ping
  timing (see `tests/test_lab_detection.py`).
- **Blind RCE timing works on any target OS.** The RCE detector's delay
  payloads ship both Windows (`ping -n 3 127.0.0.1`) and POSIX
  (`ping -c 3 127.0.0.1`) probes, so time-based verification measures a real
  delay on GNU/BSD ping targets — the Linux Docker lab included.
- **No hardcoded Windows paths in the scanner core.** All output paths use
  `pathlib`/forward slashes; the C2 listener serves the agent script as a
  string (no CRLF risk on Windows).
- **Consent files use sanitized hostnames** (`localhost-5000.json`), so
  `consent add`/`list`/`revoke` behave identically on Windows and POSIX — a
  raw `:` in a file name silently became an NTFS alternate data stream on
  Windows (`consent list` showed nothing); pre-sanitization consents are
  still honored.
- **Scratch files** (`tmp_*.py`) are gitignored and never ship.

---

## 10. Going deeper

- [README.md](README.md) — full feature overview, config reference, Track E docs
- [ARCHITECTURE.md](ARCHITECTURE.md) — design of the engine, oracles, chains
- [MASTER-PLAN.md](MASTER-PLAN.md) — project charter
