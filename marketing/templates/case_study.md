# Case Study Template

*Copy this template for each new audit. Replace [BRACKETED] sections.*

---

# Case Study: [SITE NAME]

**Client:** [Who they are — developer, startup, enterprise]
**Stack:** [Tech stack — e.g., Python FastAPI + M-Pesa]
**Duration:** [How long the audit took]
**Date:** [When the audit was completed]

---

## The Challenge

[Client] wanted to know if their website was secure. They had:
- [What they had — e.g., "a payment system processing M-Pesa transactions"]
- [What they feared — e.g., "someone bypassing payment and getting free products"]
- [What they expected — e.g., "a basic scan with a PDF report"]

---

## What I Found

| Severity | Count | Highlights |
|----------|-------|------------|
| 🔴 Critical | [X] | [Top critical finding] |
| 🟠 High | [X] | [Top high finding] |
| 🟡 Medium | [X] | [Top medium finding] |
| 🟢 Low | [X] | [Top low finding] |

**Total:** [X] vulnerabilities, [Y] false positives corrected

---

## The Kill Chain

The most dangerous finding was [FINDING]. Here's how it chains:

```
Step 1: [What the attacker does first]
Step 2: [What this enables]
Step 3: [What the attacker achieves]
Impact: [Final impact — data theft, account takeover, etc.]
```

---

## What They Did Right

Every audit includes what's working. This builds trust:

- ✅ [Good control 1 — e.g., "3-secret admin authentication"]
- ✅ [Good control 2 — e.g., "Server-side price validation"]
- ✅ [Good control 3 — e.g., "Comprehensive security headers"]

---

## The Fix

| Priority | Finding | Fix | Effort |
|----------|---------|-----|--------|
| P0 | [Critical finding] | [What to do] | [Time] |
| P1 | [High finding] | [What to do] | [Time] |
| P2 | [Medium finding] | [What to do] | [Time] |

**Total fix time: [X hours]**

---

## The Result

After fixes:
- [X] critical vulnerabilities resolved
- [Y] attack chains broken
- [Site] is now [new score]/10

---

## Client Feedback

> "[Testimonial from the client]"

---

## Files Delivered

```
findings/[slug]/
├── FINDINGS.md          # Full report
├── KILL-CHAINS.md       # Attack path analysis
├── STATE.json           # Cross-session state
├── test_findings.py     # Verification script
└── exploits/            # Working exploit tools
```

---

## Lessons Learned

1. [What this audit taught you]
2. [What you'd do differently]
3. [What surprised you]

---

*Case study by Titan Security Lab. All findings verified with live HTTP proof.*
