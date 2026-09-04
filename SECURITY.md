# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Titan Scanner, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email: **security@titan-scanner.dev** (or the maintainer's private contact).

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
- No data is sent to external services without explicit configuration
- AI escalation (optional) sends only finding summaries to configured LLM providers

## Scope

This security policy covers the Titan Scanner tool itself. For vulnerabilities found *by* Titan Scanner in target applications, follow the target's own responsible disclosure process.
