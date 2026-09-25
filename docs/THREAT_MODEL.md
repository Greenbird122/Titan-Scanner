# Threat Model

A structured model of what Titan protects, who it protects it from, and where
trust ends — as a standalone artifact, distinct from the consent-gating prose in
[SECURITY.md](SECURITY.md). Everything here maps to code that exists; where a
risk is accepted rather than mitigated, it says so.

## Scope

The tool itself and the operator's machine. Vulnerabilities found *by* Titan in
target applications follow the target's own disclosure process (see
[SECURITY.md](SECURITY.md) §Scope).

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Consent signing key | `~/.titan/consent.key` (operator-held, never committed) | Compromise lets an attacker forge authorizations for arbitrary targets |
| Operator credentials | Environment variables via `.env` (git-ignored) | Scan-time auth material for targets; leakage exposes the operator's accounts |
| Signed consent files | `consent/` (git-ignored) | Tampering could widen scope or resurrect expired authorizations |
| Scan findings & evidence | `findings/` (git-ignored) | Engagement data about third-party systems; disclosure harms targets and the operator |
| Exploit-artifact templates | `titan/exploit/vault.b64` (encoded at rest) | Abuse of shipped weaponized templates by non-authorized users |
| DAST payload corpus | `titan/ai/payloadforge.py` (highest-signal literals encoded, SHA-pinned) | Inert detection strings; exposure risk is antivirus-driven, not executable |
| Scan logs | `titan_logs/` | May contain target names and request traces |

## Actors

- **Operator** — the authorized tester running Titan. Holds the consent key and
  credentials. The only actor who can grant or widen authorization.
- **Target owner** — grants authorization via a signed consent (`consent add`,
  ed25519-signed, with basis, expiry, and the `scanning` automation policy).
- **Remote adversary** — may observe probe traffic, respond maliciously to the
  scanner, or attack Titan's own local listener.
- **External LLM provider** (optional, opt-in) — receives finding summaries only
  when AI escalation is explicitly enabled in config. Receives nothing by
  default.
- **Downstream cloner** — anyone who clones the public repository; must not
  receive engagement data, credentials, or executable exploit artifacts.

## Trust boundaries

1. **Operator host ↔ target network.** All egress crosses the transport layer.
   Private/link-local address ranges (including cloud metadata endpoints) are
   refused at egress regardless of payload content; additional operator-owned
   hosts can be allow-listed in config (`egress.allow_hosts`).
2. **Consent authority ↔ scanner.** `authorize_target()` (`titan/core/authorization.py`)
   verifies signature, key pin, scope, and expiry before any request; the signed
   `scanning` field gates the *automated* path specifically and fails closed on
   unreadable declarations. Loopback is always authorized (local testing).
3. **Scanner ↔ local lab.** `local_lab/app.py` is a deliberately vulnerable
   Flask app bound to `127.0.0.1` by default for safe self-testing; it trusts
   nothing and exists to be attacked.
4. **Scanner ↔ exploitation listener.** The Track E C2 listener authenticates
   every caller with a per-run nonce; an empty nonce is loopback-only testing.
5. **Operator ↔ LLM provider.** Optional, explicit, config-gated; sends finding
   summaries, never credentials or raw target data.
6. **Repository ↔ cloner machine.** Engagement data is excluded by `.gitignore`
   (with a pre-push surface audit, `scripts/audit_repo_surface.py`); payload
   literals are stored encoded so antivirus heuristics on fresh clones are
   answered rather than exploited; dependencies are pinned and audited in CI
   (`pip-audit`).

## Mitigations implemented

- Consent gate with signed authorization, expiry, scope, and the automated-
  scanning policy — enforced in `TitanEngine.scan()` / `scan_browserless()`
  before any request (`titan/core/authorization.py`, `titan/exploit/consent.py`).
- Egress policy engine: private-address refusal, allow-listing
  (`titan/core/egress.py`).
- Exploit templates base64-encoded at rest, decoded in memory only
  (`titan/exploit/atrest.py`); no plaintext weaponized artifact ships.
- Operator secrets via environment variables only (`.env.example`); never in
  the vault, never committed.
- `findings/`, `consent/`, `vendor/`, `intel/` git-ignored; pre-push repo
  surface audit.
- Test suite is hermetic by construction: an autouse runtime guard blocks any
  non-loopback socket from tests (`tests/conftest.py`), pinned by
  `tests/test_offline_guard.py`.
- CI gates: ruff, mypy, detect-secrets baseline, pip-audit, 55% coverage floor
  (`.github/workflows/tests.yml`).

## Residual risks (accepted, documented)

- **Consent key compromise.** The model's root of trust is a file on the
  operator's disk. Mitigation is rotation (revoke-and-rotate on disclosure, per
  the disclosure policy), not hardware protection.
- **The vault is at-rest hygiene, not a cryptographic boundary.** A determined
  local user with the repo can decode it; its purpose is to keep weaponized
  artifacts out of plaintext scans, caches, and antivirus verdicts.
- **Antivirus false positives** on the payload corpus may quarantine files on
  cloners' machines; integrity is SHA-pinned and recovery is documented in the
  README's "Antivirus note (Windows)".
- **AI escalation, when enabled**, shares finding summaries with the configured
  provider. Off by default; a security tool must not phone home silently.
- **The local lab is vulnerable by design.** It binds loopback by default;
  binding it to other interfaces is an explicit operator choice
  (`TITAN_LAB_HOST`).
