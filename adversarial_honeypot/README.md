# Adversarial Honeypot — for testing Titan Scanner's negative-control verifier

This is **not** a vulnerable app. This is an **adversarial** app — every endpoint is
designed to look vulnerable to a naive scanner, but is actually a trap. If Titan
Scanner reports confirmed findings on this app, those findings are **false positives**
that slipped through the negative-control verifier.

## What it does

The app serves a normal-looking Acme Store frontend (HTML + CSS + JS) that:

1. **Plants BaaS indicators** in the bundle (Supabase URL, Firebase config, anon key, RTDB URL)
2. **Soft-404s every unmatched route** with a 200 OK + canned JSON body
3. **Reflects payloads identically** to benign controls in `/api/sqli`, `/api/xss`
4. **Neutralizes timing oracles** — `sleep(5)` completes in ~50ms
5. **Lies about rate-limiting** — returns 200 with a "slow down" warning instead of 429
6. **Serves restrictive-looking CSP** that includes `'unsafe-inline'` so nothing is actually blocked
7. **Sets HSTS to max-age=0** — the header exists but does nothing
8. **Returns identical JSON for every fake Supabase table** — no diff between `users`, `admin`, `payments`, `settings`, etc.
9. **Returns canned Firebase responses** for every probe path

## Deploy

### Vercel (recommended — works with the `vercel.json` in this folder)

```bash
cd adversarial_honeypot
npx vercel --prod
```

This gives you a public URL like `https://acme-store-adversarial-username.vercel.app`.

### Netlify

If you want Netlify instead, you need a different `netlify.toml` and `netlify/functions/` structure. The current layout is Vercel-only.

### Run the scan

Once deployed, from the `titan-lab` directory:

```bash
# Authorize the new target first
echo '{"authorized": true, "scope": "adversarial-honeypot"}' > findings/AUTHORIZED-PRACTICE.json

# Or use config.deep.yaml and add a target override:
python run.py --target https://acme-store-adversarial-username.vercel.app \
              --config config.deep.yaml
```

Findings will land in `findings/<slug>/` where `<slug>` is the host with `.` replaced by `-`.

## What success looks like

A **good** Titan Scanner pass on this app:

- Reports 0-2 confirmed findings (because the app is genuinely not vulnerable)
- Demotes everything else to "suspicious" via the negative-control verifier
- Notes the planted BaaS indicators in the tech fingerprint but doesn't claim RLS bypass

A **bad** Titan Scanner pass:

- Reports 5+ "confirmed" findings
- Claims BaaS RLS bypass, SQLi, XSS, SSRF, LFI, IDOR, JWT alg=none — all of which are fake

The delta between the two is exactly what the negative-control verifier is worth.
