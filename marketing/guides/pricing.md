# Titan Security Lab — Pricing Guide

**Philosophy:** Charge for proof, not promises.

---

## Pricing Tiers

### Tier 1: Quick Scan — KES 5,000 / $50

**What:** Automated + manual testing of top 10 vulnerability classes
**Turnaround:** 1 day
**Deliverable:** Summary report with findings

**Includes:**
- OWASP Top 10 automated scan
- Manual verification of top findings
- 3-5 curl commands for proof
- Priority fix list

**Best for:** Small sites, personal projects, quick check before launch

---

### Tier 2: Deep Audit — KES 25,000 / $200

**What:** Full 8-phase APT methodology
**Turnaround:** 3-5 days
**Deliverable:** Full report with proof + exploit tools

**Includes:**
- Everything in Tier 1
- Full reconnaissance (JS bundles, email harvesting, subdomain mapping)
- Endpoint enumeration (every URL, every method)
- Injection testing (SQLi, NoSQLi, XSS, SSTI, XXE)
- Auth testing (brute force, session hijacking, IDOR, privilege escalation)
- CORS + header analysis
- Kill chain mapping
- Exploit tools (working PoCs)
- Honest false-positive correction

**Best for:** SaaS apps, e-commerce sites, fintech platforms

---

### Tier 3: APT Simulation — KES 75,000 / $500

**What:** Full attacker simulation — recon through cover-up
**Turnaround:** 5-7 days
**Deliverable:** APT-grade threat report + tools + walkthrough

**Includes:**
- Everything in Tier 2
- Social engineering analysis (email harvesting, phishing campaigns)
- Post-exploitation playbook (what happens AFTER getting in)
- Cover-up analysis (audit trail destruction, evidence cleanup)
- Business logic testing (race conditions, price tampering, workflow abuse)
- Developer walkthrough (1 hour)
- Retest after fixes

**Best for:** Fintech platforms, healthcare systems, enterprise apps

---

### Tier 4: Monthly Retainer — KES 20,000 / $150 per month

**What:** Continuous monitoring + quarterly audits
**Turnaround:** Ongoing

**Includes:**
- Monthly automated scan
- Quarterly deep audit
- New feature security review
- Priority support
- Slack/Discord channel

**Best for:** Sites that ship frequently, SaaS products, startups

---

## How to Quote

### Step 1: Ask these questions

1. "What's the target URL?"
2. "What's the tech stack?" (helps estimate complexity)
3. "Do you have authentication?" (adds testing surface)
4. "Are there payment endpoints?" (critical finding potential)
5. "What's your biggest fear?" (helps prioritize findings)

### Step 2: Estimate complexity

| Factor | Easy (-20%) | Standard | Hard (+30%) |
|--------|-------------|----------|-------------|
| Tech stack | Static site | SPA + API | Full stack + mobile |
| Auth | None | Basic login | SSO/MFA/role-based |
| Payments | None | Basic checkout | M-Pesa + webhooks + subscriptions |
| API | Simple CRUD | REST + search | GraphQL + real-time |

### Step 3: Apply the formula

```
Base price × Complexity multiplier × Urgency multiplier = Quote
```

**Urgency:**
- Standard (5-7 days): ×1.0
- Rush (2-3 days): ×1.5
- Emergency (24 hours): ×2.0

---

## Pricing Psychology

### Don't do this:
- "I'll scan your site for vulnerabilities" → Sounds generic
- "Security audit — $200" → No perceived value
- "How much do you charge?" → Race to the bottom

### Do this:
- "I'll find the ONE vulnerability that lets an attacker steal your data — and prove it with a working exploit"
- "Every finding comes with a curl command you can verify yourself"
- "I corrected 3 false positives — I only report what I can prove"

**Sell the outcome, not the process.**

---

## When to Work for Free

### YES (strategic free work):
- Your first 3-5 audits (portfolio building)
- Sites you personally use (you want them secure)
- Developers who are clearly building something important
- When they agree to a public testimonial

### NO (never free):
- When they ask "how much?" and you say "it depends"
- When they want "just a quick scan" (quick scans take real time)
- When they already have a security team (they should pay)
- When they say "I'll pay you after" (they won't)

---

## The Transition from Free to Paid

```
Audit 1-3:  Free (portfolio building)
Audit 4-5:  KES 5,000 (testing pricing)
Audit 6-10: KES 15,000-25,000 (standard pricing)
Audit 11+:  KES 25,000-75,000 (premium pricing)
```

**After 5 paid audits:** You can confidently charge KES 25,000+ for a deep audit.

---

## The One-Liner

> "I find the one vulnerability that lets an attacker steal your users' data — and I prove it with a working exploit. Every finding has proof. Every false positive is corrected. Total fix time: 4 hours."

That's your pitch. Everything else is details.
