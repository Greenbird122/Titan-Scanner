# Titan Scanner — Operator's Manual

Everything you need to run the scanner — this is the human's manual. All commands run from the **titan-lab root**.

---

## 1. Stack map

| Piece | What it is | Starts with | Port |
|---|---|---|---|
| **The Lab** | Deliberately vulnerable local app (RCE/SQLi/SSRF/upload) — your firing range | `python local_lab/app.py` | 5000 |
| **The Scanner** | `run.py` — crawls, runs the detector matrix, writes findings | `python run.py --target <url>` | — |
| **The Exploit Engine** | Consent-gated staging: RCE agents, SQLi extraction, webshells, reattach, session REPL | `titan_exploit_cli.py` | 8770 |
| **The REPL** | Interactive scan explorer — browse findings, filter, replay PoCs | `python titan_repl.py <scan-dir>` | — |
| **Consent** | Signed, key-pinned authorization — the ONLY thing an exploit phase asks for. Carries a **signed authorization basis** (ownership / authorization / program) — REQUIRED on `consent add` | `titan_exploit_cli.py consent` | — |

Everything is `./venv/Scripts/python.exe <file>` (or `python <file>` if that works on your box).

---

## 2. First-time setup

```bash
cd C:\Users\HomePC\Desktop\ai-agents\titan-lab
./venv/Scripts/python.exe -m pip install -r requirements.txt
./venv/Scripts/python.exe -m playwright install chromium

# operator keypair is auto-created on your first consent add.
# --basis is REQUIRED (the authorization story, signed into the file):
./venv/Scripts/python.exe titan_exploit_cli.py consent add http://127.0.0.1:5000 --basis ownership --write --shells --persistence
#    ownership      you own the target (codebase / deploy / domain)
#    authorization  dated written authorization from the owner, pre-testing
#    program        bug bounty / VDP / authorized CTF scope
# consent add without --basis is REFUSED (exit 2). A SCOPE.md template is
# written next to the consent file — fill it in before the first probe.
```

---

## 3. Command surface at a glance

```bash
# ---- Scan ----
python run.py --target <url>                                    # fast profile
python run.py --target <url> --profile deep                     # exhaustive crawl + module matrix
python run.py --target <url> --profile hostile                  # + Track G hostile surface
python run.py --target <url> --exploit                          # auto-stage verified (needs consent)
python run.py --target <url> --exploit --exploit-listener-start # scan runs its own C2 listener

# ---- Consent ----
python titan_exploit_cli.py consent add <url> [--write] [--shells] [--persistence]
python titan_exploit_cli.py consent list
python titan_exploit_cli.py consent revoke <url>

# ---- Scan exploration (REPL) ----
python titan_repl.py findings/<site-slug>
titan> ls                    # list all findings
titan> show <id>             # show finding details
titan> filter severity high  # filter by severity or type
titan> repro <id>            # show/run repro script
titan> poc <id>              # show PoC commands
titan> count                 # finding counts by severity/type
titan> meta                  # scan metadata
titan> help                  # all commands

# ---- Exploit sessions ----
python titan_exploit_cli.py session <id>                  # open the REPL
python titan_exploit_cli.py session <id> rows|csv|dump|transcript|files|export
python titan_exploit_cli.py listener [--port 8770]        # run a C2 listener
python titan_exploit_cli.py reattach <target> --sid <id>  # re-point a survivor

# ---- The Lab ----
python -c "from local_lab.app import app; app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)"

# ---- Tests ----
./venv/Scripts/python.exe -m pytest -q
```

---

## 4. Playbooks — the four flows that matter

### A. Scan a site (detection only)

```bash
python run.py --target https://yoursite.com --profile fast
# findings land in findings/<site-slug>/ (findings.json, report.md, scan_meta.json)
```

### B. Explore scan results (REPL)

```bash
python titan_repl.py findings/<site-slug>
titan> ls
titan> show 0
titan> filter severity critical
titan> repro 0
```

### C. Exploit a site you own (full loop)

```bash
python titan_exploit_cli.py consent add https://yoursite.com --write --shells --persistence
python run.py --target https://yoursite.com --exploit --exploit-listener-start
#    note the session ids in the summary
python titan_exploit_cli.py reattach https://yoursite.com --sid <id> --store findings
python titan_exploit_cli.py session <id> --listener-url http://127.0.0.1:8770
#    type any shell command — the agent answers
python titan_exploit_cli.py session <id> rows     # sqlidump rows
python titan_exploit_cli.py session <id> export   # evidence zip
```

### D. The lab as a firing range

```bash
python -c "from local_lab.app import app; app.run(host='127.0.0.1', port=5000, debug=False, use_reloader=False)" &
python titan_exploit_cli.py consent add http://127.0.0.1:5000 --write --shells --persistence
python run.py --target http://127.0.0.1:5000 --exploit --exploit-listener-start
# then drive the agent (playbook C). Reset = kill + restart; it's disposable.
```

---

## 5. Consent — the only thing every exploit phase asks for

- A signed file (`consent/<host>.json`) pinned to **your** Ed25519 keypair
  (`~/.titan/consent.key`, auto-created on first use).
- The gate is code-enforced: no signed, unexpired file for the target → the
  planner refuses before anything is sent. You saw it live: a phase without
  consent prints `[blocked]` plus the exact command to fix it.
- Flags: `--write`, `--shells`, `--persistence` grant progressively more.
- **Docker vs bare metal = separate operator keys.** In Docker mode the
  keypair lives in the `titan-keys` volume (`/root/.titan`); in bare metal it's
  your home dir. A consent signed under one mode is **refused** under the
  other — and `docker compose down -v` wipes the Docker keys. Pick one mode
  per target.

---

## 6. Troubleshooting — errors you WILL hit, and the fixes

| Symptom | Cause | Fix |
|---|---|---|
| `No module named 'cryptography'` | venv not installed | `./venv/Scripts/python.exe -m pip install -r requirements.txt` |
| `[blocked] no consent file for <host>` | no consent for the target | run the `consent add` command the error prints |
| `port 8770 is already in use` | another listener holds the C2 port | `netstat -ano | findstr :8770`, `taskkill //F //PID <pid>`, retry |
| Lab won't start / port 5000 busy | old lab instance | kill the PID on :5000, restart |
| `ERR_INTERNET_DISCONNECTED` mid-scan | network hiccup; Playwright is sensitive | re-run — scans are deterministic (seeded RNG) |
| Target `403` after repeated scans | edge/WAF rate-limiting (Vercel does this) | wait a few minutes, use a browser UA |
| Agent staged but never answers | payload didn't land (wrong shell for the OS) | lab sink runs bash now; match real targets' OS |
| `The file cannot be accessed` with `python` | Windows App Store python stub | use `./venv/Scripts/python.exe` explicitly |

---

## 7. Where everything is written

```
findings/<site-slug>/            scan reports + exploit sessions (session.json,
                                 transcript.log, data_samples/)
consent/                         signed consent files + your keypair
```

You never need me to run any of this. Start with playbook D (the lab), then
A, then B, then C — each one proves the next.

---

## 8. Strategy — the flywheel

The tool and the operator are two ends of ONE loop, not competing tracks:

```
mechanism depth on known ground  ->  operator owns the boundary
         ^                                   |
         |                                   v
    new findings on fresh targets   <-  mutations harvested into detectors
```

Rules of the road:
1. **Depth beats breadth.** One bug class understood at mechanism level
   (parser, encoding layers, why the filter fails) beats ten classes at
   pattern level. Patterns give findings; mechanism predicts the next mutation.
2. **Evidence before report.** A finding without a replay + diff is a hint,
   not a result. The oracles are non-negotiable.
3. **Consent is not optional.** The ed25519 gate is the boundary between
   research and offense. No signed file → no exploitation. No exceptions.
