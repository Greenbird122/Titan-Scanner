# TRACK-G-HOSTILE-SURFACE — Spec

**Branch:** the ad-monetized / clickbait / cloaked site workstream ("Track G").
**Archetype target:** zairaku.rest (Next.js catch-all, Adsterra + effectivecpmnetwork +
highperformanceformat ad chains, popunder config, anti-debug cloak: F12/view-source blockers,
devtools-detection, infinite `debugger` loops).

**Decisions locked with the operator:**

| Question | Decision |
|---|---|
| Primary angle | **Offensive surface** — treat the ad-chain as attack surface (cleartext ad scripts, redirect-to-phishing chains, referrer/geo-gated delivery, supply-chain angles), consent-gated like Track E |
| Delivery form | **Both** — a `hostile` crawl profile inside normal scans AND a standalone recon command |
| Threat intel | **Built-in DB + learn-as-you-scan + export** — observed origins can be promoted into the bundled DB |
| Clickbait depth | **Mechanics + content scoring** — a per-page "clickbait index" (sensational headlines, thumbnail bait, fake play buttons, countdown timers) |

---

## 1. Problem statement

Sites like zairaku are a distinct ecosystem the current scanner treats with one eye closed:

- Their attack surface is **not** their app code (which is often a benign SPA catch-all — the
  21-CRITICAL-LFI storm proved reflection there is meaningless), it's their **monetization
  stack**: third-party ad scripts, redirect chains, popunders, push-notification abuse,
  miners, and cloaking.
- They are **hard to scan**: popups/redirects wedge crawls; anti-debug JS hides the page from
  humans and naive tooling; domain rotation invalidates findings.
- Their **real risk** is malvertising/supply-chain: an HTTP-loaded ad script, a redirect into a
  phishing chain, a miner dropped on load — none of which the vuln module matrix reports.

Track G profiles that surface, scans *through* it, and probes its exploitable properties —
**read-only by default, active probes only under signed consent** (Track E model).

## 2. Attack surface map

The offensive inventory Track G covers, per third-party origin discovered on the target:

| # | Surface | What makes it attackable / reportable | Read-only | Active (consent) |
|---|---|---|---|---|
| 1 | **Cleartext ad scripts** | Third-party JS loaded over `http://` on an `https://` page → MITM/downgrade/poisonable supply chain | Detect + score | — |
| 2 | **Redirect chains** | Ad → clickbait → phishing / fake-download chain; recorded hop-by-hop (status, URL, category) | Follow + classify | Drive chain variants |
| 3 | **Referrer/geo-gated delivery** | Ad content differs by `Referer` / `X-Forwarded-For` / geo — the gate itself is fingerprintable | Baseline + observe | Probe variants against the gate |
| 4 | **Domain flux / rotation** | Ad domain seen across scans changes; stale embedded domains become takeover/poison candidates | Record + diff over time | — |
| 5 | **SRI absence** | `integrity=` missing on third-party scripts → supply-chain tamper surface | Flag per script | — |
| 6 | **Popunder / popup as vector** | `window.open`/`top.location` juggling used for popunders or phishing overlays | Detect + document | Open + classify (sandboxed page) |
| 7 | **Push-notification abuse** | Service-worker push prompt patterns (fake "video ready" notifications) | Detect | — |
| 8 | **Miners** | Crypto-jacking scripts (CoinHive-style, wasm hashing loops) | Detect + score | — |
| 9 | **Cloaking / anti-debug** | F12/view-source blockers, devtools-detection, infinite `debugger`, `console.*` no-ops — OPSEC of the host, evidence of hostile intent | Detect + document | — |
| 10 | **Malvertising-chain risk** | Ad origin co-occurring with known-bad indicators (historical) → risk score | DB lookup + co-occurrence | — |
| 11 | **Clickbait index (content)** | Fake play buttons, countdown/"your download starts in…" timers, sensational headline patterns, thumbnail bait, mislabeled links | Per-page score | — |

## 3. Delivery

### 3a. Crawl profile
`config.yaml`:
```yaml
crawl:
  profile: hostile        # fast | deep | hostile
```
`hostile` = deep-level discovery **plus** Track G detectors, hardened crawl (popup/dialog
handling, redirect recorder), and the monetization profile in the report.

### 3b. Standalone command
```bash
titan_exploit_cli.py adprofile <url> [--deep] [--export-intel <path>] [--consent-dir DIR]
```
Pure monetization/hostile-surface recon: profile + clickbait index + redirect map + clean
archive — no vuln matrix unless `--deep` adds it.

### 3c. Report & dashboard
- New **"Monetization & Hostile Surface"** section in `report.md` and the S5 dashboard:
  origin table (origin, category, TLS, SRI, count, risk score), redirect map, clickbait index,
  cloak inventory.
- Ad origins are **metadata + risk scores**, never fake vuln findings (the weather.co.ke
  adsbygoogle-skimmer FP lesson, already documented in the third-party detector).

## 4. Threat-intel DB

- **Bundled DB** (`titan/intel/origins.json`): category-tagged origins
  (`ad_network`, `tracker`, `popunder`, `push_notif`, `miner`, `malvertising_history`,
  `phishing_chain`), with a low bar for inclusion and a provenance field.
- **Observed origins** captured per scan into `findings/<slug>/intel.json` — every third-party
  origin with behavior fingerprints (loads-on-click vs always, async/dynamic injection, size,
  popup usage).
- **Export/promote flow**: `adprofile --export-intel observed.json`; a `titan intel promote`
  command validates a candidate (name, category, evidence URL, no lookalike collision) and
  merges it into the bundled DB.

## 5. Milestones

| M | Deliverable | Builds on |
|---|---|---|
| **M1** | Intel DB + observed-origin capture + export/promote | `thirdparty/detector.py` risky-origin list |
| **M2** | Monetization profiler (read-only): ad/tracker/miner/redirect taxonomy per origin, standalone command + profile section | `fingerprint.py`, S6 archiver |
| **M3** | Hostile-content detectors: cloaks, miners, push-notif abuse, clickbait index (headlines, fake buttons, countdowns) | Track A module pattern |
| **M4** | Crawler hardening: popup/popunder dismissal, dialog handler, new-tab close, download suppression, **redirect-chain recorder** in `scan_meta.json` | `_run_interactions` bounds |
| **M5** | Offensive probes (consent-gated): cleartext ad script → MITM-risk findings; redirect-chain mapping to phishing; referrer/geo-gated delivery probing | Track E consent + S4 pivot relay |
| **M6** | Supply-chain angles: SRI-absence scoring, domain-flux diffing across scans, ad-behavior diffing across referrer/geo variants | M5 + intel DB |

**Offensive-first ordering** (operator's decision): M5's probes get the detector/storage seams
from M1–M2 but land early; M3/M4 harden the crawl so probes are reliable on hostile sites.

## 6. Consent & ethics guardrails

- **Read-only recon** (profile, clickbait index, redirect mapping, cloak inventory): no consent
  file required — the target is being *observed*, the same as any scan.
- **Active probes** (M5/M6: driving redirect chains, probing referrer/geo gates, sandboxed
  popup classification): require a signed, unexpired consent file for the target (Track E
  model, `--write`/`--shells` flags as appropriate).
- **Out of scope, always:** attacking the ad *network* or third-party origins themselves. The
  target of assessment is the scanned site's integration with them. Probes must not send
  crafted traffic to third-party origins beyond what a normal visitor triggers.
- **No persistence on the target.** Nothing staged; this branch observes and probes, it does
  not deploy.

## 7. Evidence model

The zairaku lesson applies everywhere in this branch: **reflection and content-change are not
evidence** on ad-heavy SPAs. Every Track G finding needs a typed oracle:

- `adtech:tls` / `adtech:sri` — deterministic header/attr inspection (no oracle ambiguity)
- `adtech:redirect_chain` — hop-by-hop recorded (status, location, category), terminal classified
- `adtech:referrer_gate` — response differential under referrer variants with baseline control
- `cloak:*` / `clickbait:*` — deterministic static/JS-behavior signatures (never "payload echoed")
- `miner:*` — script behavior fingerprint (wasm hashing loop detection is a heuristic →
  capped confidence, unverified unless corroborated)

Same discipline as SCAN-QUALITY M1: verified requires a named strong oracle marker; demotion
path exists; identical root-cause findings collapse.

## 8. Test plan

- **Fixtures** (no live third-party traffic in CI): a synthetic ad-heavy lab site with a
  fake ad origin, popunder stub, cloak scripts, redirect-chain stub, countdown/fake-button
  stub, miner-lookalike stub; a zairaku-shaped Next.js catch-all route (already partially
  covered by `test_evidence_gate` + `/lfi_encoded_echo`).
- **Suite:** `tests/test_trackg_*.py` — profiler taxonomy, cloak detection, clickbait index,
  redirect recorder, intel export/promote, consent gating of M5 probes, oracle demotion
  (hostile SPA must not self-verify).
- **Live sanity:** zairaku.rest and one other ad-heavy site, `--profile hostile`, asserting
  the monetization section renders with 0 fake CRITICALs.

## 9. Open questions / risks

- **Ad-origin co-occurrence DB** (item 10) needs a trusted "known-bad" source — vetted before
  inclusion; provenance mandatory (no scraped rumor lists).
- **Referrer/geo probing** on live targets has real-world blast radius — the active probes stay
  sandboxed (own page, own context, bounded) and consent-gated; probe volume budgeted.
- **Domain rotation** makes intel stale fast — `intel.json` per scan + flux-diff (M6) is the
  mitigation; the bundled DB is *curated*, the observed set is *ephemeral*.
