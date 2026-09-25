# Changelog

All notable changes to Titan Scanner are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/).

## [Unreleased]

### Added
- Declared input-validation pattern registry (`titan/core/validation_patterns.py`) — named, compiled patterns for every input class accepted at the attack-module boundary (`http_method`, `absolute_http_url`, `absolute_path`, `non_empty_text`, `non_empty_key`), enforced by `ScanParams` on top of the semantic `urlparse` checks; pattern lookups fail closed on an unknown name, and the boundary's grammar is declared data instead of inline logic only. Closes the DataFactor `input_validation_patterns` gap with enforced declarations rather than decoration
- Verdict classification in `titan.verify` (`Verdict`, `classify`, `VerdictLedger`) — validation errors and server faults are UNVERDICTED non-answers that never count as positives or negatives; coverage math separates verdicted from re-probe work and includes registered-but-never-probed operations in the denominator
- `normalize_volatile` and opt-in `normalize=True` for `BaselineAnalyzer.diff_responses` — scrubs trace contexts, request IDs, CSRF tokens, nonces, sessions, and timestamps before hash/length comparison so per-request nonces cannot manufacture a false "route differs" verdict; reflection and error-signature checks still run on original bodies
- GraphQL scanner emits a verdict-ledger coverage summary (`graphql:coverage_N_of_M`, INFO) — every probe outcome is classified, and non-answers (input-validation rejections, 5xx, dead requests) are recorded UNVERDICTED with an explicit re-probe list, never counted as positives or negatives
- GraphQL scanner triggers on technology fingerprint, not just URL path — catches GraphQL at nonstandard routes (`/gql`, `/query`, renamed endpoints)
- GraphQL depth-abuse and mutation-abuse engines, ported from the standalone detector (now removed in favour of the merged scanner)
- Batch/alias engine flags only servers that actually execute JSON-array batches
- Structured JSON logging via `python-json-logger` — JSON records on stderr and in `titan_logs/titan.log`; human console output unchanged
- Fresh-clone smoke-test job in CI (`scripts/smoke_setup.sh`)
- `pip-audit` dependency audit in CI
- `TITAN_LOG_LEVEL` environment variable for log level control
- `scripts/secrets_baseline.py` — platform-safe `.secrets.baseline` regeneration that merges instead of re-snapshotting and refuses to drop an entry, plus a scan-free canonical check gated in CI
- Config validation at load time via pydantic (`titan/core/config_schema.py`) — malformed `config.yaml` fails fast (exit 2) naming the offending field before any network activity; profile-aware engine defaults preserved for omitted keys
- `requirements.txt` regenerated directly from `pyproject.toml` via pip-compile — every direct dependency annotated `# via titan-scanner (pyproject.toml)`, guarded by `tests/test_dependency_manifest.py`
- Automated-scanning policy on the consent gate: an optional signed `scanning` field (`allowed`/`bounded`/`prohibited`) records whether the source of authorization permits automated tooling, set via `consent add --scanning`. `require_automation()` refuses the automated scan path on `prohibited` and fails closed on an unreadable declaration; enforced in `authorize_target()`, which `TitanEngine.scan()` and `scan_browserless()` return on before any request. A deliberate `prohibited` declaration outranks the authorized-practice manifest. The field is absent from pre-existing consents, which keep verifying (absent = allowed), and adding or relaxing it after signing invalidates the signature. 18 tests in `tests/test_scanning_policy.py`; the consent row in scan reports renders the declared policy (`(unset)` when absent — the report never claims a permission the consent did not make)
- `config.example.yaml` ships in the repo again — the `config.*.yaml` gitignore rule had been matching the example itself, so the README's `cp config.example.yaml config.yaml` step failed on every fresh clone; a `!config.example.yaml` negation unblocks it and the committed file validates against `config_schema` (23 top-level sections)
- `TITAN_SENTRY_DSN` documented in `.env.example` (opt-in error reporting, unset by default; the integration itself is a planned readiness item)
- README "Antivirus note (Windows)" — documents the Defender false-positive mode (symptom, mechanism, recovery steps) for downstream users of the repo
- `specs/titan-v2-skeleton-spec.md` — contracts-first greenfield design contract for the from-scratch v2 track (envelope schema as M0, consent as a first-class field, one-box profile, M0–M5 build order)- Structured standalone threat model (`docs/THREAT_MODEL.md`) — assets, actors, trust boundaries, mitigations mapped to code, and accepted residual risks; kept honest by `tests/test_threat_model_doc.py`, which fails the suite if the artifact or its cross-links from `SECURITY.md`/`README.md` rot
- `tests/test_offline_guard.py` pins the hermetic-suite guarantee: the autouse conftest guard blocks non-loopback sockets for every test, loopback stays allowed, and `@pytest.mark.allow_network` is the only escape hatch (marker registered in `pyproject.toml`)
- README and CONTRIBUTING now state the offline guarantee explicitly — zero external accounts, zero network, zero API keys; CONTRIBUTING's coverage-floor number corrected to the enforced 55%
- SECURITY.md gains a Secrets Management section (env-var table with production secret-manager guidance, rotation policy) and links the threat model

### Changed
- Silent exception swallows eliminated repo-wide; ruff `S110`/`S112` now enforced instead of ignored
- Technology signature tables extracted to `titan/core/fingerprint_signatures.py`
- Coverage gate raised from 44% to 45%
- Reporting subsystem split into focused modules (`remediation.py`, `estate.py`, `markdown_report.py`)
- God-file campaign: six oversized modules split into focused units with tests landed alongside — `subdomain_takeover/detector.py` (858→470, signature table to `services.py`), `logic/detector.py` (868→11 facade, probes to `probes.py`/`service.py`), `postexploit.py` (854→547, payload tables to `payloads.py`), `core/discovery.py` (820→528, spec/brute-force probes to `api_probes.py`), `deep_audit/prober.py` (826→385, dataclasses to `models.py`, network probes to `cloud_probes.py`), `core/modules_runner.py` (787→367, dispatch to `module_bindings.py`/`module_tracks.py`/`api_dispatch.py`); legacy attribute names preserved via delegators and mixins so engine seams and test monkey-patches keep working
- Coverage gate raised from 45% to 55% with new unit tests for `CoverageTracker`, `CoverageProof`, `CoverageReportGenerator`, `WAFFingerprinter`, `SpecIngestor`, and `APIDetector`
- Dead `titan/modules/bizlogic/` package removed (unwired fossil code duplicating the live `logic` module)
- `docs/ARCHITECTURE.md` states the monolith-by-design position up front and answers the external architecture review's points (fleet placement, active-verification direction, over-scoping) in a preamble

### Fixed
- GraphQL batch engine no longer flags servers that reject batched queries
- Business-logic detector baselines log failures instead of silently continuing
- Secrets gate no longer fails on a baseline regenerated with `detect-secrets scan`, which silently deleted entries for secrets still present in the tree and, by failing mid-job, prevented `mypy` and `pip-audit` from running at all
- Deep audit no longer crashes on every Firebase-bearing target: `audit()` called `_enum_firestore`, a method that never existed anywhere — the AttributeError was swallowed by the caller's except and ended the audit with no findings; the enumeration primitive now exists (`CloudProbes.enum_firestore`)
- Fresh-clone quick start repaired: the README's `python -m titan lab start/status` subcommands never existed (real entrypoint: `python local_lab/app.py`, host/port via `TITAN_LAB_*`); the consent step for non-loopback targets is now documented (loopback stays always-authorized); links to `docs/ARCHITECTURE.md`/`CONTRIBUTING.md` and a Docker section added
- `titan/ai/payloadforge.py` stores its highest-signal payload literals zlib+base85-encoded (`_z85`/`_z85b`), decoded at import byte-identically and pinned by SHA256 in `tests/test_payloadforge_encoding.py` — fresh clones no longer lose the file to antivirus quarantine (`OSError: [Errno 22]` on import)
- `TrafficShaper.calculate_delays` honors the budget exactly: the scale step's float rounding could leave `sum(delays)` a few ulps above budget (worst observed 3.6e-15, 14 hits in 3000 draws), flaking the contract test; the residue is now clamped onto the last delay

### Removed
- Engagement-specific scripts and fixtures untracked from the public tree — `vendor/` (23 per-engagement probe scripts against live third parties), `intel/` (4 proprietary research notes), and `adversarial_honeypot/` (the 11-file adversarial calibration app). `SECURITY.md` already listed all three as private and never-committed; the index now matches that claim. Files remain on disk and local deploys are unaffected.
- Dead `titan/modules/bizlogic/` package (4,400 LOC): never wired into the module matrix, incompatible with the current `Finding` model, and duplicated by the live `logic`, `idor`, `auth`, and `ratelimit` modules. SaaS-specific ideas (credit manipulation, trial abuse, feature gating) are backlog items for the live `logic` module with proper baseline-diff oracles.

### Security
- Repo-surface audit (`scripts/audit_repo_surface.py`) added — scans tracked files for engagement domains, operator handles, CDP ports, and engagement output paths before a push; wire it into CI to make it a gate rather than a habit.
- Four `.gitignore` rules repaired: `findings/`, `intel/`, `vendor/`, and `adversarial_honeypot/` each carried a trailing `#` comment, and gitignore only treats `#` as a comment at the start of a line — so the patterns matched nothing and engagement data was one `git add .` away from being published.

## [1.0.0] - 2026-08-27

### Added
- Evidence-first scanning core: crawl, fingerprinting, WAF adaptation, and the attack module matrix
- Verification layer with negative controls and evidence grading — findings without proof are demoted
- Consent-gated exploitation CLI with signed consent files and scope enforcement
- BaaS detection and auditing (Supabase, Firebase, Appwrite)
- Reporting: `findings.json`, `report.md`, and repro scripts for confirmed findings
- Docker / docker-compose packaging and a deliberately vulnerable local lab (`python -m titan lab start`)
