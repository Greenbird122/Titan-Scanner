# Titan Reevaluation — September 2026

> "There are always zero days to crack, and under complex chunks lies a simple
> truth yet to be uncovered." — Titan doctrine seed

This document addresses the honest limitations identified after four bounty
engagements and ~40 target assessments. Not a roadmap — a diagnosis.

---

## 1. WHY NO HIGH/CRITICAL?

### Root cause: we're testing the wrong layer

Every engagement follows the same arc:
1. Map the perimeter (bundle mining, crt.sh, fingerprinting)
2. Probe the unauthenticated surface (API endpoints, auth pages, error pages)
3. Hit the auth wall
4. Archive with leads

The payable surface — the part that generates High/Critical findings — lives
**behind authentication**. IDOR on bookmarks is a Medium because bookmarks
aren't sensitive. The same IDOR pattern on a financial endpoint, a PII
profile, or an admin panel would be High/Critical. But we can't reach those
endpoints without an account.

### What High/Critical actually requires

| severity | what it needs | what we can reach |
|---|---|---|
| Critical | RCE, full DB access, mass PII | ❌ behind auth |
| High | Stored XSS, vertical priv-esc, access to PII | ❌ behind auth |
| Medium | IDOR on non-critical data, DOM XSS | ✅ this is our ceiling right now |
| Low | IDOR on UUIDs, open redirect, CSRF non-critical | ✅ easy to find |

**The ceiling isn't skill — it's access.** We've proven we can find Medium.
To find High/Critical, we need to get behind the wall.

### How to break through

**Option A: Target programs that provide test accounts.**
Some programs explicitly offer demo tenants (Varonis mentioned this in their
FAQ — "we currently don't offer any credentials to test user roles" — but
other programs do). Filter for programs that:
- Offer trial accounts (free tier, freemium)
- Provide researcher credentials on request
- Have self-service registration without corporate IdP

**Option B: Find the one door that's open.**
Every wall has a crack. The DPG auth platform (`login.dpgmedia.be`) has:
- Password reset flow (username enumeration surface)
- OIDC configuration (algorithm confusion potential)
- Token exchange grant (deprecated, but supported)
- Cross-brand auth (same token might work across brands)

One of these might yield authenticated access without a paid account.

**Option C: Chain unauthenticated findings into High.**
A single Medium finding isn't High. But:
- IDOR bookmarks (Medium) + SSRF via image proxy (untested) = ?
- OIDC algorithm confusion + token forgery = account takeover (High)
- WAF case bypass + admin endpoint discovery = vertical priv-esc (High)

The "simple truth under complex chunks" might be a **chain**, not a single bug.

**Option D: Target different vulnerability classes.**
We've focused on access control and auth. We haven't seriously tried:
- SSRF (server-side request forgery)
- Race conditions on financial operations
- Business logic flaws in subscription/payment flows
- Second-order injection (store now, trigger later)
- GraphQL-specific attacks (batching, depth abuse, alias injection)

These don't always require authentication.

---

## 2. CAN'T AUTHENTICATE

### The wall

| program | auth mechanism | blockage |
|---|---|---|
| Parool | DPG OIDC + SafeNet STA | Corporate IdP, no self-registration |
| Varonis | SafeNet STA + Okta SAML | Corporate IdP, no demo tenant |
| Humo | DPG OIDC + SafeNet STA | Same as Parool (shared platform) |
| ALSCO | Excluded most of what we test | Program design |

### Why we can't get accounts

1. **No reputation.** Programs prioritize researchers with history. We have none.
2. **No payment for test accounts.** Some programs require a subscription to test subscription features. We can't afford that.
3. **Corporate IdPs.** DPG, Varonis — their auth is designed for employees and paying customers. Researchers aren't in the identity pool.
4. **Slow response times.** Even when we ask (Varonis scope question), the answer comes in days — if at all.

### How to address

**Immediate (no money needed):**
- Filter programs by "free account available" or "trial available" in their scope
- Target programs on HackerOne/Intigriti that explicitly say "researcher accounts provided"
- Focus on programs where the target is a public-facing SaaS with free tier (Supabase, Firebase, Vercel apps)

**Medium-term (reputation building):**
- Submit the Humo Medium finding — even a Medium builds credibility
- Participate in CTF challenges on the same platforms (builds username recognition)
- Contribute to public security research (blog posts, tool releases) — programs notice

**Long-term (relationship building):**
- Contact program security teams directly with specific, technical questions (not "can I have an account?")
- Offer to test specific features in exchange for temporary access
- Build a reputation on one platform (Intigri or HackerOne) before spreading

---

## 3. SOLO BOTTLENECK

### The problem

- 134 commits, 1 human contributor
- Tool grows only when the human sits down
- DataFactor score of 67 reflects this
- No sustained development arc

### Why it matters for bounties

Bug bounty is a **race**. First to find, first to submit. A solo operator
can't compete with teams who have:
- Multiple researchers hitting the same program
- Automated scanners running 24/7
- Shared intelligence across engagements

### How to address

**Without API keys or external help:**
- Focus on **depth over breadth** — one well-hunted program beats ten shallow ones
- Build **reusable tooling** — every CDP script, every bundle miner, every auth probe is a force multiplier for the next engagement
- The skill system IS the answer — it's how a solo operator inherits their own past learning

**The human-in-the-loop question:**
Automation without human judgment = scanner output that programs reject.
Human without automation = too slow to compete.

The answer is **human-directed automation**:
- Human selects the target, makes the strategic decisions, evaluates findings
- Titan handles the mechanical work (fingerprinting, probing, evidence collection)
- The human reviews, verifies, and submits

This is exactly how we've been operating. The gap is that the mechanical
work still requires too much human intervention (launching Chrome, writing
probe scripts, parsing output). Each session should require LESS human input,
not more.

**What would change the game:**
- A headless browser pool that Titan can launch and control autonomously
- A findings database that grows automatically from each engagement
- A submission generator that produces Intigri/H1-ready reports from raw evidence
- A "bounty radar" that monitors new programs and alerts when a match is found

None of these require API keys. They require sustained development time.

---

## 4. NO SCANNER MODULES

### The gap

The knowledge exists in skills (ctf-escalation, deep-attacker) but not in
automated modules. Every time we test GraphQL, prototype pollution, or cache
poisoning, we write a one-off script. That script dies at the end of the
session.

### Why it matters

A skill tells the human what to test. A module tells Titan what to test
automatically. The difference is:
- **Skill:** "Test for IDOR by iterating userId parameters" → human writes curl
- **Module:** `titan/modules/idor/scanner.py` → Titan runs it automatically

### How to address

**Priority modules (from gap analysis + bounty experience):**

1. **GraphQL introspection + abuse** — we tested this manually on Parool and Humo. Package it.
2. **OAuth2 flow analysis** — we captured the DPG OIDC flow manually. Package it.
3. **Cache poisoning (ISR/SSG)** — we tested cache headers manually. Package it.
4. **Prototype Pollution scanner** — we tested PP manually on sturdy-octo and Humo. Package it.
5. **Rate limit analyzer** — we tested rate limits manually. Package it.

**The key insight:** every manual test we run in a bounty is a module waiting
to be written. The bounty engagements ARE the module development pipeline.

---

## 5. WAF RATE LIMITS

### The problem

- Akamai WAF blocks curl on all DPG sites
- Rate limiting kicks in after ~6 rapid requests
- Browser-only probing required for WAF-protected targets

### How we've addressed it (already working)

- CDP-browser probing bypasses Akamai (real browser fingerprint)
- Network-layer header injection keeps requests identified
- Paced requests (2-3s intervals) avoid rate limits

### What's still hard

- **IP-based rate limits** — we have one IP. No rotation.
- **Session-based rate limits** — browser sessions get flagged after burst
- **Challenge pages** — some WAFs present CAPTCHAs after threshold

### How to address (honestly)

- **Patience over speed.** Pace requests at 3-5s intervals. It's slower but avoids triggering limits.
- **Use the browser's own requests.** Navigate to pages and let the browser make its own API calls. The WAF trusts the browser's cookies and fingerprint.
- **Target selection.** Some programs have lighter WAFs. Prioritize those for quick wins.
- **Accept the constraint.** WAF rate limits are a reality of modern web security. The tooling we've built (CDP probing) is the right answer. It just needs to be packaged into a reusable module.

---

## 6. THE REEVALUATION

### What Titan is today

A **security research methodology with tooling support** — not an autonomous
scanner. The human does the thinking; Titan does the mechanical work. The
findings are real but low-yield because the methodology hits the same wall
(auth) at every engagement.

### What Titan needs to become

A **security research platform** where:
- The human selects targets and makes strategic decisions
- Titan handles reconnaissance, probing, evidence collection, and report generation
- Each engagement automatically updates the skills, modules, and findings database
- The system gets measurably better with each engagement (not just "we learned something" but "the next engagement requires 20% less human input")

### The honest gap

Between "methodology with tooling" and "research platform" is **sustained
development time** — which requires either:
1. The human dedicating regular time (not just bounty sessions)
2. Or the tool generating enough bounty revenue to justify the time investment

This is the chicken-and-egg problem: we need findings to get paid, we need
time to build better tools, we need money to justify the time.

### The way forward

**Short-term (next 2-3 engagements):**
- Submit the Humo Medium — build credibility
- Target programs with free accounts — break the auth wall
- Write 1-2 modules from the bounty scripts (GraphQL, IDOR)
- Focus on chaining findings, not finding single bugs

**Medium-term (next 10 engagements):**
- Build the bounty radar (automated program matching)
- Build the submission generator (evidence → report)
- Build the headless browser pool (autonomous probing)
- Reach 3-5 program relationships with test access

**Long-term (next 50 engagements):**
- Titan becomes the tool you point at a target and it produces findings
- The human reviews and submits, but the mechanical work is autonomous
- The findings corpus becomes a training set for finding patterns
- Revenue from bounties justifies the development investment

---

*"The goal isn't to find every bug. The goal is to become the kind of
researcher who finds the bugs nobody else sees. That requires both the
methodology to be thorough AND the creativity to look where others don't."*
