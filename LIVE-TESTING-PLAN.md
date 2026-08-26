# Live Testing Plan — Titan Scanner

## 0. Hard Rules (Non-Negotiable)

1. **Only test targets you own or have written authorization for.**
2. **Never run against production user data without explicit permission.**
3. **Log every target, date, and scope in `memory/live-tests.md`.**
4. **Stop immediately if a WAF/IDS blocks you — do not bypass.**
5. **All findings are unverified until replay + diff confirm them.**

---

## 1. Local Lab Setup (Do This First)

### 1.1 Spin up DVWA
```bash
# Pull and run DVWA
docker run --name dvwa -d -p 8080:80 vulnerables/web-dvwa

# Or use the included setup script if available
python scripts/setup_dvwa.py
```

### 1.2 Spin up WebGoat (optional, parallel)
```bash
docker run --name webgoat -d -p 8081:8080 webgoat/webgoat-8.0
```

### 1.3 Verify local targets respond
```powershell
curl http://localhost:8080
curl http://localhost:8081
```

### 1.4 Run scanner against local lab
```powershell
.\venv\Scripts\python run.py --target http://localhost:8080
.\venv\Scripts\python run.py --target http://localhost:8081
```

**Pass criteria:** Scanner finds known DVWA vulns (SQLi, XSS, LFI, command injection) within 5 minutes.

---

## 2. Target Acquisition (Authorized Targets Only)

### 2.1 Bug Bounty Platforms (Preferred)
- HackerOne, Bugcrowd, Intigriti — programs with web app scope
- Look for “web application”, “API”, “localhost”, “staging” in scope
- Read the policy carefully — some prohibit automated scanning

### 2.2 Capture The Flag (CTF) Platforms
- HackTheBox, TryHackMe, PortSwigger Web Security Academy
- These are designed for testing — zero legal risk
- Start with “Web Fundamentals” path, then “Advanced”

### 2.3 Vulnerable Apps (Self-Hosted)
- DVWA (already planned)
- WebGoat (already planned)
- Juice Shop (`docker run -p 3000:3000 bkimminich/juice-shop`)
- PWNJIT (`docker run -p 8000:8000 pwnjit/pwnjit`)

### 2.4 Staging Environments
- Your own projects with deliberate vulns
- Company internal apps with written permission
- Test environments from clients

---

## 3. Testing Workflow (Per Target)

### Step 1: Reconnaissance (Passive)
```powershell
.\venv\Scripts\python run.py --target <URL> --passive
```
- Technology fingerprinting
- API discovery
- SPA endpoint extraction
- **No payloads sent — only observation**

### Step 2: Light Active Scan
```powershell
.\venv\Scripts\python run.py --target <URL> --modules headers,cors,ssl
```
- Config-level checks only
- Low noise, low risk

### Step 3: Full Scan (With Authorization)
```powershell
.\venv\Scripts\python run.py --target <URL> --auth <creds-file>
```
- All modules enabled
- Authenticated if credentials provided
- OOB if Interactsh configured

### Step 4: Verification
- For each finding, replay manually
- Confirm with curl/python PoC
- Mark as `verified` or discard

### Step 5: Reporting
- Export JSON findings
- Generate markdown report
- Document in `memory/live-tests.md`

---

## 4. Target Prioritization Matrix

| Target Type | Priority | Why |
|-------------|----------|-----|
| DVWA local | P0 | Known vulns, instant feedback, safe |
| WebGoat local | P0 | Known vulns, different stack |
| Juice Shop | P1 | Modern SPA, realistic |
| CTF platforms | P1 | Designed for testing |
| Bug bounty programs | P2 | Real targets, but slower payback |
| Client staging | P2 | Realistic, authorized |

---

## 5. Daily Testing Routine

### Before Scanning
1. Check `memory/live-tests.md` for yesterday’s targets
2. Rotate proxy if configured
3. Ensure Interactsh client is registered
4. Set 240s max scan duration

### During Scanning
1. Monitor console output for timeouts
2. If >50% modules timeout, reduce `max_pages` to 10
3. If WAF blocks, stop — do not retry

### After Scanning
1. Review findings JSON
2. Manually verify top 3 findings
3. Update `memory/live-tests.md`:
   ```markdown
   ## 2026-08-09
   - Target: http://localhost:8080 (DVWA)
   - Duration: 4m 12s
   - Findings: 7 (3 verified)
   - Notes: SQLi timed out on security level high, XSS clean
   ```

---

## 6. Quick Start Commands

```powershell
# 1. Start local lab
docker run --name dvwa -d -p 8080:80 vulnerables/web-dvwa

# 2. Quick smoke test
.\venv\Scripts\python run.py --target http://localhost:8080

# 3. Full scan with auth
.\venv\Scripts\python run.py --target http://localhost:8080 --auth configs/dvwa_admin.yaml

# 4. Scan specific module only
.\venv\Scripts\python run.py --target http://localhost:8080 --modules sqli,xss

# 5. Export report
.\venv\Scripts\python run.py --target http://localhost:8080 --report md
```

---

## 7. Known Limitations (Honesty Checklist)

- **SPA targets** may yield only config findings (headers, CORS)
- **Authenticated scans** require valid credentials in `config.yaml`
- **OOB detection** needs outbound DNS/HTTP access
- **High-security targets** (Cloudflare, Akamai) will block scanner
- **Time-based blind** needs stable network (no 3G/spotty WiFi)

---

## 8. Success Metrics

| Metric | Target |
|--------|--------|
| Local lab detection rate | ≥80% of known DVWA vulns |
| False positive rate | ≤10% |
| Average scan duration | ≤5 min per target |
| Verified findings per scan | ≥2 on vulnerable targets |
| WAF blocks | 0 (stop immediately if blocked) |
