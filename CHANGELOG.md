# Changelog

All notable changes to Titan Scanner are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[SemVer](https://semver.org/).

## [Unreleased]

### Added
- GraphQL scanner triggers on technology fingerprint, not just URL path — catches GraphQL at nonstandard routes (`/gql`, `/query`, renamed endpoints)
- GraphQL depth-abuse and mutation-abuse engines, ported from the standalone detector (now removed in favour of the merged scanner)
- Batch/alias engine flags only servers that actually execute JSON-array batches
- Structured JSON logging via `python-json-logger` — JSON records on stderr and in `titan_logs/titan.log`; human console output unchanged
- Fresh-clone smoke-test job in CI (`scripts/smoke_setup.sh`)
- `pip-audit` dependency audit in CI
- `TITAN_LOG_LEVEL` environment variable for log level control

### Changed
- Silent exception swallows eliminated repo-wide; ruff `S110`/`S112` now enforced instead of ignored
- Technology signature tables extracted to `titan/core/fingerprint_signatures.py`
- Coverage gate raised from 44% to 45%

### Fixed
- GraphQL batch engine no longer flags servers that reject batched queries
- Business-logic detector baselines log failures instead of silently continuing

### Removed
- Dead `titan/modules/bizlogic/` package (4,400 LOC): never wired into the module matrix, incompatible with the current `Finding` model, and duplicated by the live `logic`, `idor`, `auth`, and `ratelimit` modules. SaaS-specific ideas (credit manipulation, trial abuse, feature gating) are backlog items for the live `logic` module with proper baseline-diff oracles.

## [1.0.0] - 2026-08-27

### Added
- Evidence-first scanning core: crawl, fingerprinting, WAF adaptation, and the attack module matrix
- Verification layer with negative controls and evidence grading — findings without proof are demoted
- Consent-gated exploitation CLI with signed consent files and scope enforcement
- BaaS detection and auditing (Supabase, Firebase, Appwrite)
- Reporting: `findings.json`, `report.md`, and repro scripts for confirmed findings
- Docker / docker-compose packaging and a deliberately vulnerable local lab (`python -m titan lab start`)
