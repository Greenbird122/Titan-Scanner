# Portfolio: portal.kibu.ac.ke

**Client:** Student (authorized testing)
**Type:** University student portal (grades, financial records, personal data)
**Stack:** ASP.NET Core + IIS 10.0 + ABNO Softwares
**Date:** August 2026
**Duration:** 4 hours
**Methodology:** APT-grade attacker simulation (8 phases)

---

## The Challenge

A student wanted to know: is the system that holds my grades, financial records, and personal information secure?

## What We Found

| # | Finding | Severity | What It Means |
|---|---------|----------|---------------|
| C0 | CSRF tokens NOT validated | CRITICAL | Forms accept requests without antiforgery tokens |
| C1 | No rate limiting on login | CRITICAL | Unlimited brute force attempts |
| C2 | API key in URL query parameter | CRITICAL | Key leaked in logs, browser history, Referer header |
| H0 | Logout does NOT invalidate session | HIGH | Cookie still works after logout |
| H1 | Cookie missing Secure flag | HIGH | Session hijacking over HTTP |
| H2 | No HTTP→HTTPS redirect | HIGH | SSL stripping possible |
| H3 | API leaks trace IDs | HIGH | Validation structure exposed |

## What We Verified Works

- SQL injection: **BLOCKED** (15 variants tested)
- XSS: **BLOCKED** (3 payloads)
- Path traversal: **BLOCKED**
- CORS: **PROPER** (no misconfiguration)
- User enumeration: **BLOCKED** (timing analysis, 50 attempts)
- Mass assignment: **BLOCKED**
- Open redirects: **BLOCKED** (10 parameters tested)
- Session fixation: **BLOCKED** (cookies rotate on every request)

## The Attack Chains

```
Chain 1: CSRF → Account Manipulation
  Attacker hosts evil.com with auto-submit form
  → Victim visits evil.com
  → Browser auto-submits to portal.kibu.ac.ke
  → No CSRF token needed
  → Account created without victim's knowledge

Chain 2: Brute Force → Account Takeover
  Attacker knows student number format (BJM/0018/19)
  → Runs credential stuffing (no rate limiting)
  → Gains access to grades, personal info, financial records

Chain 3: WiFi Phishing → Credential Theft
  Attacker on campus WiFi
  → Intercepts HTTP request (no HTTPS redirect)
  → Serves fake login page
  → Student enters credentials in plaintext

Chain 4: Session Theft → Persistent Access
  Attacker steals session cookie (no Secure flag)
  → Victim clicks Logout
  → Logout returns 500, session NOT invalidated
  → Attacker's stolen cookie STILL WORKS
```

## The Proof

We built 3 working exploit tools:
- `csrf_auto_register.html` — Auto-submit registration (no CSRF token needed)
- `session_hijack.html` — WiFi phishing page (fake login)
- `credential_stuffer.py` — Brute force tool (unlimited attempts)

## Total Fix Time: ~3 hours

| Fix | Effort |
|-----|--------|
| Enable antiforgery token validation | 1 line of code |
| Add rate limiting on login | 2 hours |
| Fix logout to invalidate sessions | 30 minutes |
| Add Secure flag to cookies | 30 minutes |
