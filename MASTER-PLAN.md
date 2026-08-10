# Titan Scanner — Master Plan: Epitome of Grey-Hat DAST

## 0. Charter

**Mission:** Build the most comprehensive, aggressive, and intelligent DAST scanner possible.
**Mandate:** Probe every angle. Find every vulnerability. Any means possible.
**Constraint:** Only against systems you own or have explicit written authorization to test.
**Posture:** Grey hat — offensive capability, defensive purpose. Own the systems. Secure the systems.

---

## 1. Current State Assessment

| Tier | Components | Status |
|------|-----------|--------|
| Foundation | Playwright engine, SPA crawler, API discovery, auth engine, PayloadForge | ✅ Complete |
| Detection | 16 attack modules wired, verification, deduplication, adaptive timeouts | ✅ Complete |
| Infrastructure | Interactsh OOB, proxy rotation, stealth engine, CVSS, PoC generator | ✅ Complete |
| Validation | Unit tests (22 passing), local integration tests | ⚠️ Partial |
| Proof | Live validation against DVWA/WebGoat/Juice Shop | ❌ Not started |

**Overall Rating:** 8.5/10 — Lab-ready, not battle-tested.

---

## 2. Capability Gaps (What "Epitome" Requires)

### 2.1 Authentication & Session Attacks
- [ ] **Credential brute-forcing** — hydra/patator-style login attacks
- [ ] **JWT attacks** — weak secret cracking, algorithm confusion (RS256→HS256), kid injection, none algorithm
- [ ] **Session fixation** — force victim to use attacker-controlled session ID
- [ ] **Session prediction** — sequential/predictable session ID analysis
- [ ] **Token replay** — reuse captured tokens across endpoints/roles

### 2.2 Injection Exploits
- [ ] **SQLi** — blind boolean-based, time-based, OOB, error-based, UNION-based
- [ ] **NoSQLi** — MongoDB injection, operator abuse, $where bypass
- [ ] **SSTI** — Jinja2, Twig, Freemarker, Velocity code execution
- [ ] **XSS** — reflected, stored, DOM-based, mXSS, CSP bypass
- [ ] **LFI/RFI** — filter bypass, protocol wrappers, null byte, path truncation
- [ ] **Command Injection** — blind, time-based, OOB, chained escapes
- [ ] **Template Injection** — server-side template engines, client-side template injection
- [ ] **Header Injection** — CRLF, response splitting, header pollution
- [ ] **Path Traversal** — double encoding, unicode, bypass tricks

### 2.3 SSRF & Out-of-Band
- [ ] **Cloud metadata** — AWS/GCP/Azure IMDS endpoints (169.254.169.254)
- [ ] **Internal pivoting** — localhost services, internal APIs, Redis, Elasticsearch
- [ ] **Blind SSRF** — DNS rebinding, timing-based, OOB
- [ ] **Protocol smuggling** — gopher://, dict://, file://, ftp:// wrappers
- [ ] **XXE with OOB** — external entity retrieval, SSRF via XXE, error-based XXE

### 2.4 Deserialization & Object Injection
- [ ] **Java deserialization** — ysoserial payloads, Commons Collections, Spring
- [ ] **PHP deserialization** — magic methods, gadget chains
- [ ] **Python pickle** — __reduce__ exploitation, YAML deserialization
- [ ] **.NET deserialization** — BinaryFormatter, TypeConfuseDelegate
- [ ] **Node.js prototype pollution** — __proto__ pollution, gadget chains

### 2.5 Business Logic & Authorization
- [ ] **IDOR** — horizontal/vertical privilege escalation, mass assignment
- [ ] **Race conditions** — parallel request exploitation, timing optimization
- [ ] **Mass assignment** — hidden parameter pollution, object overrides
- [ ] **Workflow abuse** — state machine bypass, step-skipping, price manipulation
- [ ] **Rate limit bypass** — IP rotation, endpoint switching, header manipulation
- [ ] **Parameter pollution** — HPP/HPF, duplicate parameter exploitation
- [ ] **HTTP method override** — PUT/DELETE via headers, mass assignment via method switching

### 2.6 Caching & CDN
- [ ] **Cache poisoning** — unkeyed input, HTTP request smuggling, host header poisoning
- [ ] **Cache key manipulation** — parameter pollution, header injection
- [ ] **CDN-specific** — Cloudflare, Akamai, Fastly misconfigurations

### 2.7 Cryptographic Weaknesses
- [ ] **Weak algorithms** — MD5, SHA1, DES, RC4, ECB detection
- [ ] **JWT attacks** — weak secret brute-force, algorithm confusion, kid injection
- [ ] **Hardcoded credentials** — API keys, secrets, passwords in code/responses
- [ ] **TLS/SSL issues** — HSTS absence, weak ciphers, certificate issues

### 2.8 File Upload & Injection
- [ ] **Web shell upload** — PHP, JSP, ASPX, .NET shells
- [ ] **Filter bypass** — double extension, .htaccess, content-type tricks, null byte
- [ ] **Polyglot files** — files valid as multiple formats (image+PHP)
- [ ] **XXE via upload** — SVG/XML upload with embedded XXE

### 2.9 Advanced Web Techniques
- [ ] **CORS exploitation** — credentialed XSS, cookie stealing, origin reflection
- [ ] **Clickjacking** — UI redress, form overlay, drag-and-drop exploitation
- [ ] **Prototype pollution** — JavaScript prototype chain manipulation
- [ ] **GraphQL attacks** — batching, aliasing, depth-limited introspection, authorization bypass
- [ ] **WebSocket exploitation** — message injection, cross-site WebSocket hijacking

### 2.10 Infrastructure & Network
- [ ] **Port scanning** — via proxy, OOB, time-based
- [ ] **Service fingerprinting** — banner grabbing, version detection
- [ ] **DNS rebinding** — bypass same-origin policy
- [ ] **HTTP/2 smuggling** — request smuggling via HTTP/2 specific vectors

---

## 3. Implementation Roadmap

### Phase 1: Core Exploit Modules (Week 1-2)
**Goal:** Add the 15 missing high-impact detectors

| Priority | Module | Complexity | Impact |
|----------|--------|-----------|--------|
| P0 | JWT Attacks | Medium | CRITICAL |
| P0 | SSTI Full Exploitation | High | CRITICAL |
| P0 | Deserialization Gadget Chains | High | CRITICAL |
| P1 | SSRF Cloud Metadata | Medium | HIGH |
| P1 | Race Condition Exploitation | Medium | HIGH |
| P1 | Mass Assignment / HPP | Low | HIGH |
| P1 | Cache Poisoning Exploitation | Medium | HIGH |
| P2 | Prototype Pollution | High | MEDIUM |
| P2 | GraphQL Batching Attacks | Medium | MEDIUM |
| P2 | File Upload Exploitation | High | HIGH |
| P2 | CORS Exploitation | Low | MEDIUM |
| P3 | Clickjacking | Low | LOW |
| P3 | WebSocket Exploitation | Medium | MEDIUM |
| P3 | HTTP/2 Smuggling | High | MEDIUM |
| P3 | DNS Rebinding | Medium | LOW |

**Deliverable:** 31 total attack modules (16 current + 15 new)

### Phase 2: Payload Arsenal (Week 2-3)
**Goal:** Context-aware payload generation that adapts to defenses

- [ ] **WAF-aware payload mutation** — auto-detect Cloudflare, Akamai, ModSecurity, AWS WAF
- [ ] **Encoding engine** — URL, Unicode, base64, hex, mixed encoding, double encoding
- [ ] **Bypass generators** — comment-based, whitespace, case variation, null byte
- [ ] **AI-powered payload generation** — DeepSeek integration for context-aware payloads
- [ ] **Gadget chain library** — ysoserial, Java, PHP, .NET, Python pickle chains
- [ ] **Polyglot payloads** — files valid as multiple formats
- [ ] **Protocol wrappers** — gopher://, dict://, file://, ftp:// for SSRF

### Phase 3: Stealth & Evasion (Week 3-4)
**Goal:** Evade modern WAFs, IDS, and rate limiters

- [ ] **HTTP request smuggling** — CL.TE, TE.CL, TE.TE variants
- [ ] **HTTP/2 smuggling** — frame flooding, header compression attacks
- [ ] **Protocol-level obfuscation** — chunked encoding tricks, transfer-encoding confusion
- [ ] **IP rotation** — Tor integration, proxy chaining, header spoofing
- [ ] **Fingerprint randomization** — JA3/JA4 TLS fingerprint mutation
- [ ] **Rate limit evasion** — endpoint switching, parameter pollution, header manipulation
- [ ] **CAPTCHA bypass** — integration with solving services (optional, grey zone)

### Phase 4: Behavioral Analysis (Week 4-5)
**Goal:** Detect vulnerabilities through behavior, not just signatures

- [ ] **Differential fuzzing** — compare responses across roles, sessions, states
- [ ] **Stateful analysis** — multi-step attack chains, session tracking
- [ ] **Authorization matrix** — map accessible endpoints per role
- [ ] **Business logic fingerprinting** — detect race conditions, mass assignment, workflow abuse
- [ ] **Anomaly detection** — baseline vs. anomaly scoring, statistical analysis

### Phase 5: Reporting & Compliance (Week 5-6)
**Goal:** Enterprise-grade output that auditors and developers can act on

- [ ] **Markdown reporter** — human-readable reports with severity, CVSS, CWE, remediation
- [ ] **HTML reporter** — interactive reports with PoC, screenshots, evidence
- [ ] **SARIF output** — GitHub/GitLab/Azure DevOps integration
- [ ] **Jira/Linear tickets** — auto-create issues from findings
- [ ] **Compliance mapping** — PCI-DSS, HIPAA, SOC2, OWASP Top 10 2021
- [ ] **Executive summary** — non-technical risk overview for management

### Phase 6: Integration & Distribution (Week 6-7)
**Goal:** Make it usable by others, integrate with existing tools

- [ ] **Docker image** — one-command deployment
- [ ] **CLI improvements** — `titan scan`, `titan report`, `titan payload` commands
- [ ] **API server** — REST API for CI/CD integration
- [ ] **Plugin system** — community module support
- [ ] **SonarQube plugin** — import findings as security hotspots
- [ ] **GitHub Action** — scan PRs for vulnerabilities

---

## 4. Testing & Validation Strategy

### 4.1 Local Lab (Mandatory Before Any Live Testing)

| Target | Vulns | Purpose |
|--------|-------|---------|
| DVWA | 50+ | Core injection, auth, session, file upload |
| WebGoat | 100+ | Business logic, auth bypass, XXE, SSRF, deserialization |
| Juice Shop | 70+ | Modern SPA, API security, NoSQLi, JWT |
| PWNJIT | 20+ | Race conditions, JWT, crypto |
| PortSwigger Labs | 200+ | Industry-standard web security challenges |

**Pass criteria:**
- ≥90% detection rate on DVWA (security level low/medium)
- ≥80% detection rate on WebGoat
- ≥70% detection rate on Juice Shop
- Zero false negatives on OWASP Top 10

### 4.2 Authorized Live Targets

**Phase 1: CTF Platforms (Zero Risk)**
- HackTheBox Starting Point machines
- TryHackMe Web Fundamentals
- PortSwigger Web Security Academy
- OverTheWire

**Phase 2: Bug Bounty Programs**
- Programs with "web application" scope
- Start with low-severity programs (HackenProof, Synack Red Team)
- Document every finding, submit responsibly

**Phase 3: Client Environments**
- Internal staging environments
- Written authorization required
- Scheduled scans during maintenance windows

### 4.3 Continuous Validation

```powershell
# Daily validation against local DVWA
docker start dvwa
.\venv\Scripts\python run_titan.py --target http://localhost:8080 --quick

# Weekly validation against WebGoat
docker start webgoat
.\venv\Scripts\python run_titan.py --target http://localhost:8081 --quick

# Monthly full validation
.\venv\Scripts\python run_titan.py --target http://localhost:8080 --full
.\venv\Scripts\python run_titan.py --target http://localhost:8081 --full
```

---

## 5. Operational Procedures

### 5.1 Pre-Scan Checklist
- [ ] Target authorization confirmed (written/owned)
- [ ] Scope defined (URLs, IPs, exclusions)
- [ ] Proxy configured if needed
- [ ] Interactsh client registered
- [ ] Scan duration limit set (default: 240s)
- [ ] Output directory created

### 5.2 During Scan
- [ ] Monitor console for WAF blocks
- [ ] If blocked, stop immediately — do not retry
- [ ] Log all findings in real-time
- [ ] Take screenshots of vulnerable states

### 5.3 Post-Scan
- [ ] Review findings JSON
- [ ] Manually verify top 3 findings
- [ ] Generate report (JSON + Markdown + HTML)
- [ ] Update `memory/live-tests.md` with results
- [ ] Remediate verified findings on target systems

---

## 6. Legal & Ethical Guardrails

### 6.1 Authorization Requirements

| Target Type | Authorization | Documentation |
|-------------|--------------|---------------|
| Own systems | None (owner) | System inventory |
| Client systems | Written contract | Signed agreement |
| Bug bounty | Platform terms | Program policy |
| CTF platforms | Implicit (designed for testing) | Platform rules |
| Public websites | NONE | Do NOT scan |

### 6.2 Prohibited Actions
- Scanning targets without authorization
- Exfiltrating data beyond proof-of-concept
- Modifying/deleting data on target systems
- Disrupting service (DoS/DDoS)
- Bypassing security controls aggressively (stop on first block)

### 6.3 Incident Response
If scanner triggers an alert or block:
1. Stop immediately
2. Document the trigger
3. Notify target owner if authorized
4. Adjust scanner behavior (increase delays, change payloads)
5. Resume only with explicit permission

---

## 7. Success Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Total attack modules | 31 | 16 |
| Detection rate (DVWA) | ≥90% | TBD |
| Detection rate (WebGoat) | ≥80% | TBD |
| False positive rate | ≤10% | TBD |
| Average scan duration | ≤5 min | 4.5 min |
| Verified findings per scan | ≥2 on vuln targets | 1 |
| Unit test coverage | ≥90% | ~60% |
| Live targets validated | 10+ | 2 |
| WAF evasion rate | ≥70% | TBD |

---

## 8. Immediate Next Actions

1. **Spin up local lab:**
   ```powershell
   docker run --name dvwa -d -p 8080:80 vulnerables/web-dvwa
   docker run --name webgoat -d -p 8081:8080 webgoat/webgoat-8.0
   docker run --name juice-shop -d -p 3000:3000 bkimminich/juice-shop
   ```

2. **Run validation scans:**
   ```powershell
   .\venv\Scripts\python run_titan.py --target http://localhost:8080
   .\venv\Scripts\python run_titan.py --target http://localhost:8081
   .\venv\Scripts\python run_titan.py --target http://localhost:3000
   ```

3. **Compare results against known vulnerability lists:**
   - DVWA: https://github.com/digininja/DVWA
   - WebGoat: https://owasp.org/www-project-webgoat/
   - Juice Shop: https://github.com/juice-shop/juice-shop

4. **Close gaps where modules miss known vulns**

5. **Begin CTF platform testing:**
   - PortSwigger Web Security Academy
   - HackTheBox Starting Point
   - TryHackMe

---

## 9. Grey Hat Principles

> "The difference between a black hat and a grey hat is authorization."

| Principle | Application |
|-----------|-------------|
| **Own the systems** | Only test infrastructure you own or control |
| **Find everything** | Probe every parameter, every endpoint, every state |
| **Document everything** | Every finding, every PoC, every false positive |
| **Harden everything** | Every vulnerability found gets remediated |
| **Share knowledge** | Report to vendors, contribute to community |
| **Stay legal** | Written authorization before any scan |
| **Stay ethical** | No exfiltration, no destruction, no harm |

**The goal is not to break things. The goal is to prove they can be broken — and then fix them.**
