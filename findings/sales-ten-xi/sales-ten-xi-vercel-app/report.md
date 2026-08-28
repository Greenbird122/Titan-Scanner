# Scan Report — https://sales-ten-xi.vercel.app

| | |
|---|---|
| **Site slug** | `sales-ten-xi-vercel-app` |
| **Scanned** | 2026-08-28T19:22:41.792113+00:00 |
| **Duration** | 45.07s |
| **Technologies** | Vercel, JSON API, XML API, Web App Manifest, HTTPS |

## Summary

| Total | Verified | Critical | High | Medium | Low | Unconfirmed | Chains |
|---|---|---|---|---|---|---|---|
| 2 | 1 | 0 | 1 | 1 | 0 | 0 | 0 |

## Executive summary

- **Risk posture** High-risk exposure — prioritize remediation.
- **Top risks:**
  1. [HIGH] Info Leak — `GET https://sales-ten-xi.vercel.app` param=`deep-audit` (conf 0.95)
  2. [MEDIUM] CSP Weakness — `GET https://sales-ten-xi.vercel.app` param=`Content-Security-Policy` (conf 0.70)
- **Est. remediation** ~1h 15m (critical=2h, high=1h, medium=15m, low=5m)
- **Counts** 2 findings · 1 verified · 1 confirmed · 1 suspicious · 0 critical · 1 high · 0 chains · 1 repro scripts
- **Coverage** `complete` — crawl queue drained; all discovered endpoints ran the module matrix · 1 URLs crawled · 0 endpoint groups × module matrix · 0 params · 0 duplicate bodies skipped
- **Evidence gate** 0 finding(s) auto-demoted for lacking a strong oracle marker (reflection never verifies)

## Findings

### 1. [HIGH] Info Leak — SUSPICION (not proven; review manually)

- **URL** `GET https://sales-ten-xi.vercel.app`
- **Param** `deep-audit` (cloud) · **Confidence** 0.95 · **Status** 200
- **Payload**

```text
The target is missing 5 security headers: X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, Referrer-Policy, Permissions-Policy
```

- **Tier** `suspicious` — behavioral signal, NOT confirmed; triage but do not treat as proven
- **Evidence grade** `indicative`
- **Tags** deep-audit, misconfiguration, DEEP-HEADERS-MISSING

---

### 2. [MEDIUM] CSP Weakness — verified

- **URL** `GET https://sales-ten-xi.vercel.app`
- **Param** `Content-Security-Policy` (header) · **Confidence** 0.70 · **Status** 200
- **CVSS** 7.5 — `CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:L`
- **Payload**

```text
CSP weakness: No Content-Security-Policy header or meta tag present
```

- **Tier** `confirmed`
- **Evidence grade** `confirmed`
- **Repro** `repros/repro_01.py` — executable Ground-Truth check (PASS = flaw still present, FAIL = fixed)
- **Evidence**

  - `csp:missing`

- **PoC (curl)**

```bash
curl -X GET -H "Referer: https://sales-ten-xi.vercel.app" "https://sales-ten-xi.vercel.app"
```

- **PoC (python)**

```python
import requests

url = "https://sales-ten-xi.vercel.app"
method = "GET"
headers = {
    "Referer": "https://sales-ten-xi.vercel.app",
}
response = requests.request(method, url, headers=headers)

print(response.status_code)
print(response.text[:2000])
```

---

## Low-confidence findings

> Weak evidence only (reflection/noise — not verified). Review manually before acting.

- `Info Leak` (indicative) — GET https://sales-ten-xi.vercel.app param=`deep-audit` conf=0.95

## Manual Analysis (Hostile Profile)

> Additional findings from manual JS/header analysis. These are NOT automated scan results.

### HIGH: Backend API URL exposed in client-side JS

- **Evidence:** `main.c3b98656.js` contains `baseURL: "https://project-diabolical.onrender.com/sales"`
- **Impact:** Attackers can target the backend directly. Combined with CORS wildcard, enables cross-origin attacks with stolen tokens.
- **Remediation:** Use relative URLs (`/api/...`) or proxy through the same origin. Never hardcode backend URLs in client bundles.

### HIGH: CORS wildcard (`Access-Control-Allow-Origin: *`)

- **Evidence:** Response header on all requests
- **Impact:** Any origin can make authenticated requests if a victim's Bearer token is stolen (XSS, phishing).
- **Remediation:** Restrict CORS to specific trusted origins. Never use `*` for authenticated APIs.

### INFO: Bearer tokens stored in localStorage

- **Evidence:** `localStorage.getItem("access_token")` → `Authorization: Bearer <token>`
- **Impact:** localStorage is vulnerable to XSS token theft.
- **Remediation:** Consider httpOnly, secure cookies instead.

### INFO: Basic authentication implementation present

- **Evidence:** `Authorization: Basic " + btoa(username + ":" + password)`
- **Impact:** Increases attack surface. Ensure HTTPS is enforced (HSTS is already present).
- **Remediation:** Remove if not strictly needed.

## Disclosure status

> Gate 5: every Critical/High finding must be disclosed to the owner (technical finding only — no victim PII). Mark each when done.

- [ ] **[HIGH] Info Leak** — GET https://sales-ten-xi.vercel.app — disclosed to owner: ____ (date)

## Business Logic Impact

### Reputation damage

- [MEDIUM] CSP Weakness — `GET https://sales-ten-xi.vercel.app` param=`Content-Security-Policy` (conf 0.70)

## Monetization & Hostile Surface (Track G)

- **Monetization score** 4/100
- **Third-party origins** 3 · **Categories** unknown: 3
- **Clickbait index** 0/100 (low) · **Cloaks** 0 · **Miners** 0 · **Push-abuse** 0 · **Clickbait mechanics** 0
- **Active probes** enabled (consent held)

### Third-party origins

| Host | Category | Kinds | Count | Cleartext | SRI | Risk |
|---|---|---|---|---|---|---|
| `agrimarket.example.com` | unknown | link | 1 | ok | ok | 3 |
| `fonts.googleapis.com` | unknown | link | 2 | ok | ok | 3 |
| `fonts.gstatic.com` | unknown | link | 1 | ok | ok | 3 |

## AI escalation

- Sent: 0 · Confirmed: 0 · Rejected: 0 · Failed: 0
