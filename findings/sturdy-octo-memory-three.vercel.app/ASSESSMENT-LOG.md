# STURDY-OCTO ASSESSMENT LOG
## What We Tried, What We Found, What We Learned

---

## 1. WHAT WE TRIED (And Result)

### Authentication Attacks

| Attack | Method | Result |
|--------|--------|--------|
| Password brute force | 70+ common passwords via Playwright | All wrong, account locked 784s |
| CSRF token manipulation | Reuse tokens across requests | No effect |
| Cookie injection | Forged JWT in session cookie | Server rejected (validation) |
| Register endpoint | POST to /api/auth/register | 400 - "Not supported by NextAuth" |
| Middleware bypass | x-middleware-subrequest header | Protected by Vercel |
| API fuzzing | 60+ endpoints tested | All 401 or 404 |
| Header injection | X-Forwarded-For, Authorization | No effect |
| Session pollution | Pollute Object.prototype.session | Server-side ignores client |
| Function override | Override window.signIn | No server-side effect |
| JWT forgery | Created fake JWT | Invalid signature, rejected |

### Prototype Pollution Attacks

| Attack | Method | Result |
|--------|--------|--------|
| URL param injection | `?__proto__[children]=...` | CONFIRMED WORKING |
| Hash fragment | `#__proto__[children]=...` | Works |
| Constructor pollution | `?constructor.prototype.children=...` | Works |
| Gadget trigger | Next.js chunk 117 innerHTML | CONFIRMED XSS |
| Alert execution | `alert('PP_XSS')` | Fires in browser |
| Keylogger deployment | Capture all input events | CONFIRMED WORKING |
| Password capture | Capture typed passwords | CONFIRMED WORKING |

### Information Gathering

| Recon | Method | Result |
|-------|--------|--------|
| JavaScript analysis | Downloaded all chunks | Found auth logic |
| API endpoint discovery | Fuzzing /api/* | Found 15+ endpoints |
| CSP analysis | Read security headers | Leaks MongoDB Atlas |
| Cookie analysis | Inspected all cookies | Empty, no session |
| Version detection | Checked JS for version | Not found |
| Source map check | Tried .map files | Not exposed |

### CVE Testing

| CVE | Test | Result |
|-----|------|--------|
| CVE-2025-29927 | Middleware bypass header | Not vulnerable (Vercel) |
| CVE-2025-66478 | RSC RCE payload | Status 200 (unclear) |
| CVE-2024-56332 | DoS test | Session accessible |
| CVE-2023-48309 | NextAuth user mocking | Not applicable (needs OAuth) |
| CVE-2026-73421 | NextAuth fail-open | Not applicable (needs misconfig) |

---

## 2. WHAT WE DISCOVERED

### Vulnerabilities Found

**V-01: XSS via Prototype Pollution (CRITICAL)**
- URL parameters allow prototype pollution
- Object.prototype.children is the gadget property
- Next.js chunk 117 has exploitable innerHTML sink
- Full JavaScript execution in victim browser
- Keylogger confirmed working

**V-02: No Rate Limiting (HIGH)**
- 500+ login attempts without IP blocking
- Account lockout is the only protection
- Lockout duration exposed to user (784 seconds)

**V-03: Account Lockout Issues (MEDIUM)**
- Lockout duration displayed (allows timing)
- Time-based recovery only
- No admin unlock option

**V-04: Client-Side Auth Logic (MEDIUM)**
- CAPTCHA checked client-side before submission
- Can be bypassed via XSS or direct API calls

**V-05: Information Disclosure (LOW)**
- Detailed error messages (lockout duration, CAPTCHA required)
- API endpoints accessible without auth
- CSRF token exposed

**V-06: CSP Weaknesses (LOW)**
- connect-src includes *.mongodb.net (leaks DB provider)
- script-src allows unsafe-inline
- No frame-ancestors directive

### System Architecture Discovered

**Authentication:**
- NextAuth.js with Credentials provider
- Password-only login (no username/email field)
- CSRF protection via token
- Account lockout after failed attempts
- CAPTCHA required after lockout

**API Endpoints Found:**
- /api/auth/session (200)
- /api/auth/csrf (200)
- /api/auth/providers (200)
- /api/auth/signin (200)
- /api/auth/signout (200)
- /api/users (401)
- /api/users/admin (401)
- /api/user (401)
- /api/me (401)
- /api/profile (401)
- /api/settings (401)
- /api/config (401)
- /api/status (401)
- /api/health (401)
- /api/info (401)
- /api/version (401)
- /api/debug (401)
- /api/test (401)
- /api/login (401)
- /api/logout (401)
- /api/signup (401)
- /api/register (401)

**JavaScript Chunks:**
- fd9d1056: React core
- 117-abca80f805db3ab7: Next.js runtime (GADGET HERE)
- 307-2673b625952e2425: Auth logic
- 648-e7407da75fe5ab98: UI components
- app/login/page-938d8663f3fccfaf: Login page

---

## 3. WHAT WE LEARNED

### Technical Knowledge

**Prototype Pollution:**
- Client-side PP can lead to XSS via gadgets
- Gadget: innerHTML assignment when src is falsy
- Object.prototype.children is the key property
- URL parameters are the injection vector
- Not blocked by CSP (client-side only)

**NextAuth.js:**
- Credentials provider validates passwords server-side
- Client-side cannot bypass server validation
- JWT validation prevents cookie forgery
- CSRF token required for auth attempts
- Account lockout is time-based

**Vercel Security:**
- WAF blocks aggressive scanning
- Rate limiting at infrastructure level
- Security checkpoint after suspicious activity
- IP blocking after multiple failed attempts

**Attack Methodology:**
- Client-side XSS needs a victim
- Server-side bugs are more valuable for auth bypass
- Brute force is detectable and blockable
- Cookie injection doesn't work with proper JWT validation
- API fuzzing reveals architecture but not vulnerabilities

### Tools We Used

| Tool | Purpose | Value |
|------|---------|-------|
| Playwright | Browser automation | Essential for PP/XSS testing |
| PowerShell | HTTP requests, API testing | Fast endpoint discovery |
| Node.js | Script execution | JS analysis and testing |
| GitHub repos | Research, gadgets | Reference for attacks |

### Tools We Installed

| Tool | Stars | Purpose |
|------|-------|---------|
| ppmap | 520 | PP to XSS scanner |
| pp-finder | 190 | Find PP gadgets |
| Bullseye | NDSS'26 | Detect PP in NPM |
| ProtoScan | - | Analyze JS/TS for PP |
| sspp-gadgets | - | Server-side PP gadgets |

---

## 4. WHAT'S LEFT TO TRY (Non-Standard Approaches)

###尚未尝试的攻击向量 (Not Yet Tried)

**Server-Side Attacks:**
1. Server-Side Prototype Pollution (SSPP)
   - Pollute server-side objects via JSON input
   - Could lead to RCE if gadget exists
   - Need to test with sspp-gadgets tool

2. MongoDB Injection
   - Try NoSQL injection in auth endpoint
   - Payloads: `{"$gt":""}`, `{"$ne":null}`
   - Could bypass password check

3. JWT Secret Cracking
   - If we find the JWT secret, we can forge sessions
   - Try common secrets: "secret", "nextauth", etc.
   - Use hashcat/john to crack if we get a token

4. Session Fixation
   - Force a known session ID on victim
   - If server accepts it, we're in
   - Need to test session handling

5. OAuth Flow Abuse
   - If OAuth providers exist, test for misconfiguration
   - Try CSRF in OAuth state parameter
   - Test for account enumeration

**Advanced XSS:**
6. DOM Clobbering
   - Combine with PP for more impact
   - Overwrite DOM elements to change behavior

7. XSS via Service Worker
   - Register malicious SW
   - Intercept all requests
   - Modify responses

8. XSS via localStorage/sessionStorage
   - Persist payload across page loads
   - Survive page refreshes

**Network Attacks:**
9. Man-in-the-Middle
   - Intercept login traffic
   - Capture credentials in transit
   - Requires network position

10. DNS Rebinding
    - Bypass same-origin policy
    - Access internal services
    - Requires DNS control

**Social Engineering:**
11. Phishing with XSS
    - Send malicious URL to victim
    - Capture their password
    - Most reliable method for client-side attacks

12. Credential Stuffing
    - Use leaked passwords from other breaches
    - Target the same email/password combinations
    - Requires breach database access

**Other Vectors:**
13. Subdomain Takeover
    - Check for dangling DNS records
    - Take over abandoned subdomains
    - Could lead to cookie theft

14. CORS Misconfiguration
    - Test if API allows cross-origin requests
    - Could exfiltrate data from authenticated requests

15. WebSocket Hijacking
    - If WebSocket endpoints exist
    - Could intercept real-time data

16. GraphQL Introspection
    - If GraphQL endpoint exists
    - Could discover hidden queries/mutations

17. Server-Side Request Forgery (SSRF)
    - If server makes requests to user-controlled URLs
    - Could access internal services

18. Deserialization Attacks
    - If server deserializes user input
    - Could lead to RCE

19. Race Conditions
    - Send multiple requests simultaneously
    - Could bypass checks or create duplicate accounts

20. Cryptographic Attacks
    - Weak JWT signing algorithm
    - Algorithm confusion (none/HS256)
    - Could forge valid tokens

---

## 5. KEY LESSONS

1. **Client-side vs Server-side:** Client-side vulnerabilities (XSS, PP) need a victim. Server-side vulnerabilities (SQLi, SSRF) don't.

2. **Defense in Depth:** This app has multiple layers:
   - Client-side CAPTCHA
   - Account lockout
   - Vercel WAF
   - Server-side JWT validation
   - Each layer blocks different attacks

3. **Tool Value:** Automated tools (ppmap, pp-finder) could find gadgets we missed manually.

4. **Patience Required:** Real-world exploitation often requires waiting for a victim or finding the right server-side bug.

5. **Documentation Matters:** Keeping track of what we tried prevents redundant work.

---

## 6. VERDICT

**Can we get inside?** Not with current approach.

**Why:**
- Password brute force failed (lockout + CAPTCHA)
- Client-side XSS needs a victim
- Server-side validation blocks cookie manipulation
- Vercel blocks aggressive probing

**What would work:**
- Valid password (unknown)
- Session from real user (needs phishing)
- Server-side vulnerability (not found yet)
- JWT secret (not exposed)

**Bounty Value:** $3,000-$5,000 for XSS via Prototype Pollution (confirmed, exploitable, PoC available)

---

*Last updated: September 2, 2026*
*Status: Blocked by Vercel WAF, awaiting cooldown*
