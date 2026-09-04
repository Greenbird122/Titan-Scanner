# Portfolio: memetik.spaincityevo.site

**Client:** Independent developer
**Type:** E-commerce (digital products)
**Stack:** Python FastAPI + Railway + Hikari + M-Pesa
**Date:** August 2026
**Duration:** 2 hours
**Methodology:** APT-grade attacker simulation (8 phases)

---

## The Challenge

A developer built a meme storefront with M-Pesa payments. They wanted to know: is it secure?

## What We Found

| # | Finding | Severity | What It Means |
|---|---------|----------|---------------|
| F1 | Swagger UI + OpenAPI spec public | CRITICAL | Attacker gets full API surface before any attack |
| F2 | Payment callbacks accept any POST | CRITICAL | Payment manipulation possible without authentication |
| F3 | No rate limiting on admin login | HIGH | Brute force attacks possible indefinitely |
| F4 | Infrastructure disclosure in headers | MEDIUM | Hosting details leaked in response headers |

## What We Verified Works

- SQL injection: **BLOCKED** (parameterized queries)
- XSS: **BLOCKED** (HTML encoding)
- Path traversal: **BLOCKED** (404)
- CORS: **PROPER** (no wildcard)
- CSRF: **TOKENS PRESENT**
- Price tampering: **BLOCKED** (server uses DB price)

## The Proof

Every finding comes with a curl command the developer can run themselves:

```bash
# Verify the critical finding:
curl -s https://memetik.spaincityevo.site/openapi.json | python3 -m json.tool | head -5
# Returns: Full API spec with 33 endpoints
```

## What We Gave the Developer

- Full APT report with kill chains
- Working exploit tools (callback spoofer, brute forcer)
- 21/21 automated tests passing
- Copy-paste code fixes for every finding
- Honest assessment: "Your site is well-built. These are minor fixes."

## The Verdict

**Score: 7.5/10** — One of the better-built sites we've audited. The 3-secret admin auth is genuinely strong. Main issue: the Swagger UI hands attackers the full API on a silver platter.

## Total Fix Time: ~4 hours

| Fix | Effort |
|-----|--------|
| Restrict /docs and /openapi.json | 30 min |
| Authenticate payment callbacks | 2 hours |
| Rate limit admin login | 1 hour |
| Remove infrastructure headers | 15 min |
