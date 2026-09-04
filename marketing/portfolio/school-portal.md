# Portfolio: REDACTED_TARGET

**Client:** School administrator (authorized)
**Type:** School management portal (student records, fees, grades)
**Stack:** PHP + MySQL + Cloudflare
**Date:** August 2026
**Duration:** 3 hours
**Methodology:** Deep security audit with hostile mode enabled

---

## The Challenge

A school wanted to know: is the system that manages our students' data secure?

## What We Found

| # | Finding | Severity | What It Means |
|---|---------|----------|---------------|
| F1 | SQL injection in login form | CRITICAL | Database access possible via login bypass |
| F2 | Session fixation | HIGH | Session ID doesn't change after login |
| F3 | Missing security headers | HIGH | No CSP, no HSTS, no X-Frame-Options |
| F4 | Directory listing enabled | MEDIUM | File structure exposed |
| F5 | Verbose error messages | MEDIUM | Database structure leaked in errors |

## The Proof

```bash
# SQL injection proof:
curl -X POST https://REDACTED_TARGET/login.php \
  -d "username=admin'--&password=anything"
# Returns: Dashboard access (bypassed authentication)
```

## What We Verified Works

- SQL injection: **WORKING** (multiple payloads confirmed)
- Authentication bypass: **WORKING** (admin access without password)
- Session fixation: **WORKING** (session ID persists after login)

## The Impact

An attacker could:
- Access all student records
- View and modify grades
- Access financial records
- Download student personal information
- Modify school fees records

## Total Fix Time: ~8 hours

| Fix | Effort |
|-----|--------|
| Use parameterized queries | 4 hours |
| Regenerate session after login | 1 hour |
| Add security headers | 1 hour |
| Disable directory listing | 30 min |
| Suppress error messages | 30 min |
