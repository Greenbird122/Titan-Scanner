# TGK Hub Engagement Retrospective — What Titan Learned

**Engagement:** TGK Hub (com.techgroupkenya.app) — Android app + WordPress backend
**Dates:** 2026-09-05 to 2026-09-06
**Duration:** ~15 hours
**Outcome:** 21 findings, 6 kill chains, 1 CRITICAL, disclosure drafted

---

## 1. What Worked

### The hybrid approach (eventually)
We started with static APK analysis, hit the emulator wall, pivoted to browser impersonation, and ended up with console session capture. The final path — console login → cookie replay → authenticated API testing — was the most productive. It should have been the **first** path, not the last.

### STATE.json as memory
The state file tracked everything across rounds: findings, chains, subdomains, people, infrastructure. Every session picked up where the last one left off. This is Titan's memory and it works.

### Consent files as boundaries
The SCOPE.md file answered every "can I do this?" question. Without it, we'd have been guessing at authorization boundaries. The format is solid.

### The disclosure email template
A professional, non-confrontational disclosure that leads with the CRITICAL, explains the attack chain, and offers to help fix. Reusable for any engagement.

### Kill chains as narrative
The deep-attacker analysis produced 6 chains that connect isolated findings into attack scenarios. "A single malicious page can drain the entire platform" is the line that makes developers fix things. Individual findings are noise; chains are signal.

---

## 2. What Didn't Work

### The emulator trap
We spent **hours** fighting:
- APKPure/apkeep only returning the base APK (not splits)
- AAS token exchange (Google Play delivery API)
- Playwright hardening (channel=chrome, webdriver patch)
- System image download (1.4GB on a slow connection)
- Split APK installation (adb install-multiple)
- Certificate pushing (Git Bash mangling /system paths)

**The lesson:** If the app can't run within 30 minutes, **pivot immediately** to backend-only testing. The emulator is a rabbit hole. The backend is where the real findings are.

### The GIS browser path dead end
We built a Google Identity Services harness to mint tokens with the leaked OAuth client ID. It failed with `origin_mismatch` — localhost isn't a registered JS origin. We spent time on this before discovering the console login path.

**The lesson:** Before building custom auth tools, check if the target has a **web login UI** that signs into the same backend. It almost always does, and it's the fastest path to an authenticated session.

### The X-WP-Nonce red herring
We discovered that sending `X-WP-Nonce` broke reads, and omitting it worked. We assumed the CSRF layer was broken. Later we found the real nonce header is `X-Upskill-Nonce` — a custom header the console JS injects.

**The lesson:** When reverse-engineering auth mechanisms, **read the frontend JS first**. The answer is usually in the page's inline scripts or loaded JS files. Don't guess at header names.

### The reference files never existed
The deep-attacker skill describes `references/methodology.md`, `references/chaining-rules.md`, and `references/cracking-rules.md`. None of them exist. The skill works from its own description, but the reference files would have加速 the analysis.

**The lesson:** Create the reference files. They're not optional.

---

## 3. What Should Change

### New skill: `app-engagement` (meta-playbook)
A hybrid playbook that recognizes app targets for what they are: static binary + live backend + auth boundary. Phases:

1. **Static (parallel):** APK manifest/components/secrets AND backend enumeration simultaneously
2. **Auth resolution (fork decision):** can the app run? → if yes, dynamic. If no, find the cheapest path to an authenticated session (console login > GIS > emulator)
3. **Kill-path construction:** chain static findings with authenticated-surface findings
4. **Report with exploit PoC chains**

### Update `deep-attacker` with the reference files
Create:
- `references/methodology.md` — the 8-phase kill chain
- `references/chaining-rules.md` — how to connect findings into chains
- `references/cracking-rules.md` — the "never trust" rules

### Add "console login pivot" to the auth playbook
When Google Sign-In is blocked (origin_mismatch, app-only gate), the standard pivot is:
1. Check if the target has a web login UI at `/console/auth/login` or similar
2. The web UI signs into the same backend (same user store, same session cookies)
3. Use Playwright headed + persistent profile to capture the session
4. Replay cookies with the correct nonce header (usually found in the page's inline JS)

### Add "orphaned subdomain" to the recon checklist
After subdomain enumeration, check each subdomain for:
- SSL cert mismatch (cert for a different domain)
- HTTP 503/502 (server running but backend down)
- DNS pointing to cloud IPs (AWS, Azure, GCP) not behind the main CDN
- These are potential takeover candidates and infrastructure disclosure

### Add "plugin route enumeration" to the WordPress playbook
For each WordPress instance:
1. Fetch `/wp-json/` and extract all routes
2. Filter by plugin namespaces (rankmath, litespeed, divi, etc.)
3. Count routes per plugin — high counts indicate admin-level API exposure
4. Test the most sensitive routes (settings, import/export, disconnect, reset)

### Formalize the session capture pattern
The Playwright headed + persistent profile + cookie dump pattern works. Document it:
1. Launch headed Chrome with persistent profile
2. Navigate to login page
3. Wait for human to complete auth (Turnstile, Google, etc.)
4. Poll `auth/me` until authenticated
5. Dump cookies to Netscape format + header string
6. Replay with `curl -H "Cookie: <header>"`

---

## 4. What Titan Is Now

Before this engagement, Titan was a scanner with aspirations. After 15 hours on TGK Hub, Titan is:

- **A manual testing partner** that can map an entire API surface, reverse-engineer auth protocols, and chain findings into kill paths
- **A persistence engine** that remembers everything across sessions (STATE.json) and picks up where it left off
- **A disclosure machine** that produces professional, actionable reports

What Titan is NOT yet:
- **Automated** — most of the work required human judgment and manual pivoting
- **Fast** — 15 hours for 21 findings is slow for a professional pentester
- **Self-directed** — the human made every strategic decision (pivot to console, register account B, send disclosure now)

The goal is to close those gaps. The app-engagement playbook, the reference files, and the session capture pattern are the next steps. One day this won't be a lab exercise — it'll be a product.

---

## 5. The Numbers

| Metric | Value |
|--------|-------|
| Total findings | 21 |
| CRITICAL | 1 (CORS wildcard) |
| HIGH | 5 (orphaned subdomain, OAuth client ID, service fingerprint, job PII, comment PII) |
| MEDIUM | 8 |
| LOW | 4 |
| INFO | 2 |
| Kill chains | 6 |
| Routes mapped | 809 |
| Subdomains | 8 |
| People identified | 2 |
| Hours invested | ~15 |
| Emulator hours wasted | ~6 |
| Most productive hours | Last 3 (authenticated surface + kill chains) |

---

*Retrospective generated: 2026-09-06*
*Engagement: TGK Hub (com.techgroupkenya.app)*
*Status: Disclosure drafted, ready to send*
