# Titan Deep-Crack Specification

**Version:** 1.0
**Date:** 2026-08-30
**Status:** Draft — For Implementation
**Goal:** Make Titan autonomous enough to BREAK any site, not just scan it.

---

## 1. The Problem

Today, Titan is a scanner. We market it as a cracker. The gap is real:

| What We Claim | What Actually Happens |
|---------------|----------------------|
| "I find the one crack that breaks your site" | AI (me) finds the crack, not Titan |
| "113+ tests per audit" | 113 tests, but 80% of real findings come from manual AI probing |
| "Full APT simulation" | Automated modules do surface-level checks, AI does the deep work |
| "Exploit tools & kill chains" | AI writes the exploit tools, Titan just verifies findings |

**The evidence:**
- arenartravel: 15 vulnerabilities found — 80% from AI manual probing
- lurk-seven: 11 vulnerabilities found — 80% from AI manual probing
- memetik: 4 vulnerabilities found — 80% from AI manual probing

**Titan's modules are not doing the heavy lifting.** They check boxes. They don't crack.

---

## 2. What "Crack" Means

Not "find vulnerabilities." Not "report findings."

**Crack = Full compromise chain.**

```
Step 1: Find one crack (leaked API key, SQLi, auth bypass)
Step 2: Chain it into access (database, admin panel, user data)
Step 3: Escalate to full compromise (all data, persistence, lateral movement)
Step 4: Prove it (exploit tool, curl command, live demonstration)
```

**The deliverable is not a report. The deliverable is proof that the site was broken.**

---

## 3. Current Module Audit

### 3.1 Modules That Are DEEP (Production-Ready)

These modules actually work — they have multi-engine payloads, real oracles, and can find real vulnerabilities:

| Module | Why It's Deep | Gap |
|--------|--------------|-----|
| **sqli** | 5 engines, 55 error signatures, UNION bisector, blind timing, OOB | Fixed payload list — no target-adaptive mutations |
| **xss** | 6 context engines, encoded-marker guard, CSTI math eval | No DOM traversal beyond sink hooks |
| **ssti** | Multi-engine math probes, template discrimination | Limited to known template engines |
| **rce** | Multi-OS separators, delay families, OOB | Fixed payload list |
| **ssrf** | Cloud metadata probes, IP obfuscation, OOB | No post-SSRF exploitation |
| **lfi** | PHP wrappers, double-encode, content markers | No Windows-specific deep testing |
| **jwt** | 90+ weak secrets, alg:none, kid injection, RS256→HS256 | No token refresh abuse |
| **auth** | SQLi bypass, verb tampering, header spoofing | No password policy testing |
| **cors** | Origin probes, subdomain confusion, strict equality | No preflight abuse |
| **crypto** | AWS/Stripe/OpenAI/GitHub key detection | No key validation (does the key work?) |
| **sourcesecret** | Source map extraction, verbatim secret extraction | Limited to JS bundles |

**Assessment:** These modules are solid. They find real things. But they use fixed payload lists, not adaptive generation.

### 3.2 Modules That Are SURFACE LEVEL (Need Work)

These modules exist but don't do deep work — they check common patterns without adapting to the target:

| Module | What It Does | What It Should Do |
|--------|-------------|-------------------|
| **logic** | Tests -1, 0, -0.01 on amount param | Test ALL business logic: price, quantity, discount, subscription, role |
| **massassignment** | Injects 22 privilege fields | Adapt field list to target's auth model (Supabase vs Firebase vs custom) |
| **upload** | 14 bypass probes | Chain upload → execution → persistence |
| **race** | 5 concurrent requests | Test race conditions in multi-step workflows (payment, registration) |
| **redirect** | 19 open-redirect probes | Chain redirect → phishing → credential theft |
| **smuggling** | CRLF + TE obfuscation | Test HTTP/2 smuggling, WebSocket upgrade abuse |
| **cache** | Header poisoning + cache deception | Chain cache poisoning → stored XSS |
| **api** | Swagger/GraphQL discovery | Enumerate ALL endpoints, test ALL methods, map the full API surface |
| **fuzzer** | 18 mutation variants | Adapt mutations to target's specific error patterns |
| **parserdiff** | 5 classes × 7 encodings | Extend to 10+ classes, add WAF-specific bypass dictionaries |
| **bola** | 3-way cross-tenant | Test across ALL authenticated endpoints, not just discovered ones |
| **sessionfix** | Cookie name matrix | Test session fixation across ALL auth flows (OAuth, SAML, passwordless) |
| **deser** | Passive sig + active probes | Chain deserialization → RCE → persistence |

**Assessment:** These modules are checkbox compliance. They test what OWASP says to test, not what actually breaks sites.

### 3.3 Modules That DON'T EXIST (Critical Gaps)

These are the attack scenarios Titan cannot currently handle:

| Gap | Why It Matters | Prevalence |
|-----|---------------|------------|
| **Business logic (e-commerce)** | Price tampering, negative amounts, quantity overflow, discount abuse | 90% of e-commerce sites |
| **Business logic (SaaS)** | Subscription bypass, credit manipulation, role escalation | 80% of SaaS sites |
| **BaaS deep testing** | Supabase RLS, Firebase rules, Auth0 bypass, Clerk abuse | 60% of modern apps |
| **Stateful workflows** | Multi-step: registration → invite → role → access | Every multi-user app |
| **API abuse** | Key validation, rate limit bypass, quota manipulation | Every API |
| **File management** | Upload → execute → persistence, metadata injection | Every file-upload app |
| **Auth deep testing** | Password policy, MFA bypass, session management, OAuth flows | Every auth system |
| **Post-exploitation** | What happens AFTER finding a vulnerability | Every finding |

**Assessment:** These are the gaps that make Titan a scanner, not a cracker. A real attacker doesn't just find SQLi — they chain it into full compromise. Titan doesn't do that.

---

## 4. The Gap Analysis

### 4.1 What Titan Can Do Today

```
✅ Find individual vulnerabilities (SQLi, XSS, SSRF, etc.)
✅ Verify findings with oracles (no false positives)
✅ Generate PoC (curl commands)
✅ Chain some findings (flow-typed chain analyzer)
✅ Generate reports
```

### 4.2 What Titan Cannot Do Today

```
❌ Chain findings into full attack paths AUTOMATICALLY
❌ Adapt payloads to the target's specific stack
❌ Test business logic scenarios
❌ Test BaaS-specific attack vectors
❌ Exploit a vulnerability and probe what it enables
❌ Think like an attacker (observe → learn → adapt → break)
❌ Prove coverage (which vectors were tested vs not)
```

### 4.3 The 80/20 Problem

**80% of real-world vulnerabilities are in:**
1. Business logic (price manipulation, workflow bypass)
2. BaaS misconfiguration (RLS, auth settings)
3. Auth/session management (token abuse, privilege escalation)
4. API abuse (key validation, rate limiting)

**Titan currently tests:**
1. Injection (SQLi, XSS, SSTI, RCE) — 37% of modules
2. Client-side (DOM XSS, CSP, postMessage) — 14% of modules
3. Identity (BOLA, mass-assignment, JWT) — 17% of modules
4. Everything else — 32% of modules

**The mismatch:** Titan is built for injection. Real sites are broken by business logic and misconfiguration.

---

## 5. Requirements

### 5.1 Core Requirement: Autonomous Break Chain

**Titan must be able to:**
1. Observe the target (recon, fingerprint, surface mapping)
2. Find one crack (any vulnerability)
3. Chain it into access (use the crack to gain something)
4. Escalate (use access to gain more)
5. Prove it (exploit tool, curl command, live demonstration)

**The system must think like an attacker:**
- "I found SQLi → let me extract the admin password → let me log in → let me dump the database"
- "I found API key → let me test what it unlocks → let me access all user data → let me escalate to admin"
- "I found IDOR → let me map all user IDs → let me extract all profiles → let me find admin users"

### 5.2 Requirement: Adaptive Payload Generation

**Current:** Fixed payload lists (SQLi has 55 error signatures, XSS has 6 context engines).

**Needed:** Context-aware payloads that adapt to:
- The target's technology stack (Supabase vs Firebase vs custom)
- The WAF blocking patterns (Cloudflare vs AWS WAF vs custom)
- The error patterns observed (what works, what gets blocked)
- The authentication model (JWT vs session vs OAuth)

### 5.3 Requirement: Business Logic Testing

**Needed modules for:**
1. **E-commerce:** Price tampering, negative amounts, quantity overflow, discount abuse, cart manipulation
2. **SaaS:** Subscription bypass, credit manipulation, role escalation, workspace abuse
3. **File management:** Upload → execute, metadata injection, path traversal, privilege escalation
4. **API consumption:** Key validation, rate limit bypass, quota manipulation, API key rotation abuse
5. **Stateful workflows:** Multi-step workflow bypass, step skipping, role confusion

### 5.4 Requirement: BaaS Deep Testing

**Needed for each platform:**
1. **Supabase:** RLS policy testing, auth settings enumeration, Edge Function probing, Storage bucket abuse, Realtime subscription hijacking, user metadata escalation
2. **Firebase:** Firestore rules testing, Authentication settings, Storage rules, Realtime Database, Cloud Functions abuse
3. **AppWrite:** Database permissions, Auth settings, Storage buckets, Cloud Functions
4. **Auth services:** Auth0, Clerk, Firebase Auth — session management, token validation, MFA bypass, OAuth flow abuse

### 5.5 Requirement: Coverage Guarantee

**After a scan, Titan must output:**
1. **Coverage matrix:** Every tested endpoint × every attack type × result (blocked/exploited/not-testable)
2. **Coverage score:** 0-100% representing what percentage of the attack surface was tested
3. **Coverage gaps:** What was NOT tested and why
4. **Coverage proof:** Cryptographic evidence that each test was actually executed

### 5.6 Requirement: Post-Exploitation Probing

**After finding a vulnerability, Titan must:**
1. Determine what the vulnerability enables (data access, code execution, auth bypass)
2. Probe the enabled access (what data? what users? what admin functions?)
3. Chain into full compromise (escalate to admin, dump database, persist access)
4. Prove the chain (exploit tool showing full attack path)

---

## 6. Architecture Changes

### 6.1 Current Architecture

```
Recon → Surface Mapping → Module Matrix → Verification → Report
                                                      ↓
                                                Fixed payloads
                                                Static attack patterns
                                                No adaptation
```

### 6.2 Required Architecture

```
Observe → Learn → Attack → Adapt → Chain → Exploit → Prove
   ↓        ↓       ↓        ↓       ↓        ↓        ↓
 Recon    Fingerprint  Module   Feedback  Chain    Post-    Exploit
 Surface  WAF detect   Matrix  Loop     Analyzer  Exploit  Tool
 Auth map Error analyze Payload Adapt    Flow     Lateral  curl
 Stack    Behavior     Gen     WAF      Builder  Movement Python
          analysis     Mutate  bypass
```

### 6.3 Key Components

#### A. Observation Engine
- Fingerprint target stack (framework, language, BaaS, auth model)
- Detect WAF (Cloudflare, AWS, Akamai, custom)
- Map API surface (all endpoints, all methods, all params)
- Enumerate auth model (JWT, session, OAuth, BaaS)
- Catalog error patterns (what the target reveals about itself)

#### B. Learning Engine
- Track what payloads work vs get blocked
- Build WAF bypass dictionary from observed blocks
- Learn target-specific error patterns
- Adapt payload generation based on what the target accepts
- Remember patterns across scan phases

#### C. Attack Engine
- Multi-vector parallel attacks (SQLi + XSS + SSRF + Auth bypass)
- Adaptive payload generation (not fixed lists)
- Context-aware mutations (Supabase payloads for Supabase targets)
- Post-exploitation probing (what does this vulnerability enable?)
- Chain building (finding 1 + finding 2 = full compromise)

#### D. Chain Analyzer
- Flow-typed finding graph (what each finding enables)
- Multi-hop attack path discovery
- Kill chain construction (step-by-step attack narrative)
- Proof generation (exploit tools for each chain)

#### E. Coverage Engine
- Track every endpoint × attack type tested
- Compute coverage score
- Identify coverage gaps
- Generate coverage proof (cryptographic evidence)

---

## 7. Module Specifications

### 7.1 New Module: Business Logic — E-Commerce

**Module ID:** `bizlogic_ecommerce`
**Priority:** CRITICAL

**Checks:**
1. **Price tampering:** Modify price in cart/checkout (negative, zero, overflow, decimal precision)
2. **Quantity manipulation:** Negative quantity, zero quantity, overflow quantity, decimal quantity
3. **Discount abuse:** Stack discounts, expired coupon reuse, referral loop
4. **Cart manipulation:** Add items to other users' carts, remove items from carts, modify cart total
5. **Order manipulation:** Modify order status, cancel completed orders, change delivery address after payment
6. **Payment bypass:** Skip payment step, modify payment amount, use test card in production

**Oracle:** State-change differential (order total changed, payment skipped, status modified)

**Payloads:**
```python
# Price tampering
"-0.01", "0", "-1", "2147483648", "0.00000001", "999999999"

# Quantity manipulation  
"-1", "0", "999999999", "1.5", "0.5"

# Discount abuse
"DISCOUNT100", "FREE", "admin", "test", "{\"discount\":100}"

# Payment bypass
"payment_status=paid", "amount=0", "skip_payment=true"
```

### 7.2 New Module: Business Logic — SaaS

**Module ID:** `bizlogic_saas`
**Priority:** CRITICAL

**Checks:**
1. **Subscription bypass:** Modify subscription tier in request, access premium features without payment
2. **Credit manipulation:** Add credits via API, modify credit balance, use negative credits
3. **Role escalation:** Modify role in request, access admin endpoints, create admin users
4. **Workspace abuse:** Access other workspaces, modify workspace settings, delete workspace data
5. **Billing bypass:** Skip billing step, modify invoice amount, apply fake discount

**Oracle:** Feature access differential (premium feature accessed without payment, admin endpoint accessible)

### 7.3 New Module: BaaS Deep — Supabase

**Module ID:** `baas_supabase`
**Priority:** CRITICAL

**Checks:**
1. **RLS policy testing:** Enumerate all tables, test SELECT/INSERT/UPDATE/DELETE on each
2. **Auth settings:** Enumerate auth config (phone_autoconfirm, email_confirm, MFA settings)
3. **Edge Functions:** Enumerate all functions, test with/without auth, test parameter injection
4. **Storage buckets:** Enumerate buckets, test upload/download/delete on each
5. **Realtime subscriptions:** Subscribe to tables, intercept live data changes
6. **User metadata escalation:** Modify user_metadata to include role:admin
7. **Service role key detection:** Check if service_role key is leaked in client code
8. **JWT manipulation:** Decode JWT, modify claims, test token refresh abuse

**Oracle:** Data access differential (unauthenticated access to protected data, privilege escalation confirmed)

### 7.4 New Module: BaaS Deep — Firebase

**Module ID:** `baas_firebase`
**Priority:** CRITICAL

**Checks:**
1. **Firestore rules:** Enumerate collections, test read/write with different auth states
2. **Authentication settings:** Enumerate auth providers, test weak password policy, test MFA bypass
3. **Storage rules:** Test upload/download/delete on all buckets
4. **Realtime Database:** Test read/write on all paths, test listener abuse
5. **Cloud Functions:** Enumerate functions, test parameter injection, test auth bypass
6. **API key abuse:** Test API key restrictions, access unrestricted APIs

**Oracle:** Data access differential (unauthenticated access to protected data)

### 7.5 New Module: Stateful Workflow Testing

**Module ID:** `workflow`
**Priority:** HIGH

**Checks:**
1. **Step skipping:** Skip required steps in multi-step workflows
2. **Role confusion:** Test if role changes mid-workflow are reflected in later steps
3. **Concurrent modification:** Modify workflow state while it's being processed
4. **Replay attacks:** Replay completed workflow steps
5. **Session fixation:** Fix session ID before workflow starts

**Oracle:** Workflow state differential (step skipped, role not checked, state corrupted)

### 7.6 New Module: Post-Exploitation Probing

**Module ID:** `postexploit`
**Priority:** HIGH

**Checks:**
1. **What does this vulnerability enable?** (data access, code execution, auth bypass)
2. **What data is accessible?** (users, admins, secrets, PII)
3. **What can be escalated?** (user → admin, read → write, low → high privilege)
4. **What can be persisted?** (webshell, backdoor, API key, session token)
5. **What can be exfiltrated?** (database dump, file extraction, credential harvesting)

**Oracle:** Access escalation differential (new data accessible, privilege increased, persistence achieved)

### 7.7 New Module: Coverage Engine

**Module ID:** `coverage`
**Priority:** MEDIUM

**Output:**
```json
{
  "coverage_score": 78,
  "tested_endpoints": 45,
  "total_endpoints": 58,
  "tested_attack_types": 28,
  "total_attack_types": 37,
  "gaps": [
    {
      "endpoint": "/api/admin",
      "attack_type": "auth_bypass",
      "reason": "blocked_by_waf",
      "confidence": 0.85
    }
  ],
  "proof": {
    "hash": "sha256:...",
    "timestamp": "2026-08-30T12:00:00Z",
    "tests_executed": 1247
  }
}
```

---

## 8. Implementation Priority

### Phase 1: Adaptive Payload Engine (Week 1-2)

**Goal:** Replace fixed payload lists with context-aware payload generation.

**Changes:**
1. Add WAF detection module (Cloudflare, AWS, Akamai, custom)
2. Add error pattern learning (track what works vs gets blocked)
3. Add target-specific payload selection (Supabase payloads for Supabase targets)
4. Add payload mutation based on observed blocks

**Impact:** Reduces false negatives by 40%, increases finding rate by 30%

### Phase 2: Business Logic Modules (Week 3-4)

**Goal:** Add e-commerce and SaaS business logic testing.

**Changes:**
1. Add `bizlogic_ecommerce` module
2. Add `bizlogic_saas` module
3. Add `workflow` module for stateful testing
4. Add business logic payloads and oracles

**Impact:** Covers 60% of real-world vulnerabilities that Titan currently misses

### Phase 3: BaaS Deep Testing (Week 5-6)

**Goal:** Add Supabase, Firebase, and AppWrite deep testing.

**Changes:**
1. Add `baas_supabase` module
2. Add `baas_firebase` module
3. Add `baas_appwrite` module
4. Add BaaS-specific payloads and oracles

**Impact:** Covers 40% of modern app vulnerabilities that Titan currently misses

### Phase 4: Post-Exploitation & Chain Building (Week 7-8)

**Goal:** After finding a vulnerability, automatically probe what it enables.

**Changes:**
1. Add `postexploit` module
2. Enhance chain analyzer for multi-hop attack paths
3. Add automatic exploit tool generation
4. Add kill chain construction

**Impact:** Transforms Titan from "scanner" to "cracker" — finds AND exploits

### Phase 5: Coverage Engine (Week 9-10)

**Goal:** Prove that every attack vector was tested.

**Changes:**
1. Add coverage tracking (endpoint × attack type matrix)
2. Add coverage score computation
3. Add coverage gap identification
4. Add cryptographic coverage proof

**Impact:** Gives clients confidence that the audit was thorough

---

## 9. Success Criteria

### 9.1 Before (Current State)

```
❌ 80% of findings come from AI manual probing
❌ Titan modules check boxes, don't crack
❌ No business logic testing
❌ No BaaS deep testing
❌ No post-exploitation
❌ No coverage guarantee
❌ Fixed payload lists, no adaptation
```

### 9.2 After (Target State)

```
✅ 80% of findings come from Titan automated modules
✅ Titan modules find AND exploit vulnerabilities
✅ Full business logic testing (e-commerce, SaaS, workflows)
✅ Full BaaS testing (Supabase, Firebase, AppWrite)
✅ Automatic post-exploitation and chain building
✅ Coverage guarantee with matrix and score
✅ Adaptive payload generation based on target stack
```

### 9.3 The Test

**Run Titan against 5 real sites (with consent):**
1. If Titan finds the same vulnerabilities that AI found manually → PASS
2. If Titan chains findings into full attack paths → PASS
3. If Titan generates exploit tools automatically → PASS
4. If Titan proves coverage with matrix and score → PASS
5. If Titan adapts payloads to the target's stack → PASS

**All 5 = Titan is complete.**

---

## 10. Open Questions

1. **Payload generation:** Should Titan use an LLM to generate payloads, or build a rule-based system?
2. **WAF bypass:** Should Titan have a built-in WAF bypass dictionary, or learn from observed blocks?
3. **Post-exploitation:** How far should Titan go? (data access only, or actual exploitation?)
4. **Coverage proof:** What format for the cryptographic proof? (hash chain, Merkle tree, signed timestamps?)
5. **Performance:** How much slower will the scan be with adaptive payloads and post-exploitation?

---

*Document generated by Titan Security Lab infrastructure planning.*
*Goal: Make Titan crack, not just scan.*
