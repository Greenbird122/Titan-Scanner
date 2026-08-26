#!/usr/bin/env python3
"""
CLI Runners for the Multi-AI Mutation Loop

Each function calls a real CLI tool in non-interactive/headless mode.
All tools read markdown files from the findings directory for context.
"""

import subprocess
import os
import tempfile
from pathlib import Path
from typing import Optional


def run_opencode(prompt: str, work_dir: str = None, timeout: int = 300) -> str:
    """
    Run OpenCode in headless mode.
    Usage: opencode run -p "prompt"
    """
    cmd = ["opencode", "run", "-p", prompt]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=work_dir or os.getcwd(),
            env={**os.environ, "NO_COLOR": "1"},
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] OpenCode did not respond in time"
    except FileNotFoundError:
        return "[ERROR] opencode not found in PATH"
    except Exception as e:
        return f"[ERROR] OpenCode failed: {e}"


def run_kilo(prompt: str, work_dir: str = None, timeout: int = 300) -> str:
    """
    Run Kilo Code in autonomous mode.
    Usage: kilo --auto "prompt"
    """
    cmd = ["kilo", "--auto", prompt]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=work_dir or os.getcwd(),
            env={**os.environ, "NO_COLOR": "1"},
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] Kilo did not respond in time"
    except FileNotFoundError:
        return "[ERROR] kilo not found in PATH"
    except Exception as e:
        return f"[ERROR] Kilo failed: {e}"


def run_claude(prompt: str, work_dir: str = None, timeout: int = 300) -> str:
    """
    Run Claude Code in headless mode.
    Usage: claude -p "prompt"
    """
    cmd = ["claude", "-p", prompt]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=work_dir or os.getcwd(),
            env={**os.environ, "NO_COLOR": "1"},
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] Claude did not respond in time"
    except FileNotFoundError:
        return "[ERROR] claude not found in PATH"
    except Exception as e:
        return f"[ERROR] Claude failed: {e}"


def run_gemini(prompt: str, work_dir: str = None, timeout: int = 300) -> str:
    """
    Run Gemini CLI in headless mode.
    Usage: gemini -p "prompt"
    """
    cmd = ["gemini", "-p", prompt]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=work_dir or os.getcwd(),
            env={**os.environ, "NO_COLOR": "1"},
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[TIMEOUT] Gemini did not respond in time"
    except FileNotFoundError:
        return "[ERROR] gemini not found in PATH"
    except Exception as e:
        return f"[ERROR] Gemini failed: {e}"


# ── Role-to-Model Mapping ─────────────────────────────────────────────────
# Each role uses a DIFFERENT model to avoid echo chamber

ROLE_RUNNERS = {
    "scanner":    run_opencode,   # OpenCode scans for vulns
    "mutator":    run_kilo,       # Kilo mutates payloads
    "verifier":   run_claude,     # Claude verifies findings
    "researcher": run_gemini,     # Gemini searches for new vectors
}


def run_phase(role: str, prompt: str, work_dir: str = None, timeout: int = 300) -> str:
    """Run a phase with the appropriate model."""
    runner = ROLE_RUNNERS.get(role)
    if not runner:
        return f"[ERROR] Unknown role: {role}"
    return runner(prompt, work_dir, timeout)


# ── Prompt Builder ─────────────────────────────────────────────────────────

CORE_RULES = """Core rules:
1. Grep every response for sensitive data (flags, tokens, keys, PII)
2. Check error messages for data leaks
3. Simple first (curl + grep), complex later
4. Three strikes then escalate
5. Validate your oracle before building on it
6. Source code read before blind extraction
7. Don't loop on dead ends (max 3 attempts per vector)
8. No finding exists until a live HTTP response proves it
9. There is always more — but know when to stop
10. Each iteration must produce NEW information or STOP
"""


def build_scanner_prompt(findings_dir: str) -> str:
    """Build the scanner phase prompt."""
    estate = Path(findings_dir) / "estate.md"
    hypotheses = Path(findings_dir) / "hypotheses.md"
    findings = Path(findings_dir) / "findings.md"

    return f"""{CORE_RULES}

You are the SCANNER in a security mutation loop.

Read these files for context:
- {estate} (target info)
- {hypotheses} (what to test next)
- {findings} (what's already been found)

Your job:
1. For each hypothesis, attempt exploitation against the live target
2. Use curl, web requests, or any tool available
3. ONLY report findings where a live HTTP response proves the vulnerability
4. Grep EVERY response for flags, tokens, keys, PII
5. If you find something, add it to findings.md
6. If you try something and it fails, add it to mutations.md

Output: Update the markdown files directly. Be specific and reproducible."""


def build_mutator_prompt(findings_dir: str) -> str:
    """Build the mutator phase prompt."""
    findings = Path(findings_dir) / "findings.md"
    mutations = Path(findings_dir) / "mutations.md"

    return f"""{CORE_RULES}

You are the MUTATOR in a security mutation loop.

Read these files:
- {findings} (confirmed vulnerabilities)
- {mutations} (what's been tried)

Your job:
1. For each confirmed finding, create 3-5 VARIANT payloads
2. Try: URL encoding, double encoding, unicode, hex, case variations
3. Try: parameter pollution, HTTP method variations, content-type tricks
4. Try: comment injection, boundary breaking, WAF bypasses
5. Write each new hypothesis as a concrete, testable HTTP request
6. Add new hypotheses to {findings_dir}/hypotheses.md

Output: Add new testable hypotheses to hypotheses.md. Be specific."""


def build_verifier_prompt(findings_dir: str) -> str:
    """Build the verifier phase prompt."""
    hypotheses = Path(findings_dir) / "hypotheses.md"
    estate = Path(findings_dir) / "estate.md"

    return f"""{CORE_RULES}

You are the VERIFIER in a security mutation loop.

Read these files:
- {estate} (target info)
- {hypotheses} (what to test)

Your job:
1. For each hypothesis, make the EXACT HTTP request against the live target
2. Record status code, headers, body
3. If it works → add to findings.md as CONFIRMED
4. If it fails → add to mutations.md as FAILED
5. If it returns interesting data → grep for secrets/flags/PII
6. Do NOT skip any hypothesis — test them ALL

Output: Update findings.md and mutations.md. Include full HTTP details."""


def build_researcher_prompt(findings_dir: str) -> str:
    """Build the researcher phase prompt."""
    findings = Path(findings_dir) / "findings.md"
    estate = Path(findings_dir) / "estate.md"

    return f"""{CORE_RULES}

You are the RESEARCHER in a security mutation loop.

Read these files:
- {estate} (target info, technology stack)
- {findings} (what's been found so far)

Your job:
1. Identify the target's technology stack (framework, language, version)
2. Search the web for known CVEs for that stack
3. Search for bypass techniques for defenses encountered
4. Search for similar applications and their vulnerabilities
5. Generate NEW hypotheses that haven't been tried yet
6. Add new hypotheses to {findings_dir}/hypotheses.md under "## New (from web search)"

Output: Add new hypotheses with source/reasoning. Prioritize by impact."""
