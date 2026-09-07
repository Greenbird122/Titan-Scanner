# Security Policy

## What Titan Is

Titan is an evidence-first vulnerability scanner for modern web applications: it
crawls targets, runs attack detectors, mutates payloads (optionally with an LLM),
and grades every finding with negative controls and verification before reporting.
It is a consent-gated testing tool — active scanning and exploitation require a
signed consent file for the target.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Titan Scanner, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, use GitHub's private vulnerability reporting:

https://github.com/Greenbird122/Titan-Scanner/security/advisories

(or email the maintainer's private contact if you already have it).

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

You should receive a response within 48 hours. We will work with you to understand and address the issue before any public disclosure.

## Threat Model

Titan Scanner is a security testing tool. Key security considerations:

### Consent & Authorization
- All active scanning requires a signed consent file (see `consent/` directory)
- The S5 authorization gate enforces target scope before any request is sent
- Exploitation phases (Track E) require explicit consent flags per technique

### Credential Handling
- API keys and tokens must be provided via environment variables, never hardcoded
- Use `.env` files (git-ignored) for local development
- See `.env.example` for required variables

### Network Safety
- Stealth engine rate-limits requests to avoid denial-of-service
- Proxy rotation available for anonymized scanning
- Tor integration for privacy-preserving scans

### Data Handling
- Scan results are stored locally in `findings/`
- `findings/` and `consent/` are gitignored: engagement data (reports, session
  captures, consent files) is never committed to the repository
- No data is sent to external services without explicit configuration
- AI escalation (optional) sends only finding summaries to configured LLM providers

## Scope

This security policy covers the Titan Scanner tool itself. Vulnerabilities found
*by* Titan Scanner in target applications follow the target's own responsible
disclosure process.

### In scope (testing Titan itself)
- Core engine, crawl/spa handling, and transport layer (`titan/core/`)
- Attack detectors and verification (`titan/modules/`, `titan/verify/`)
- Payload generation and AI integration (`titan/ai/`)
- CLI entry points and configuration handling

### Out of scope
- `findings/` and `consent/` — local-only engagement data, never committed
- Target applications scanned with Titan — follow the target's disclosure process
- Credentials and API keys — report exposure immediately via the channel above
