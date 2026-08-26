#!/usr/bin/env python3
"""
Spawn AI models in their own terminal windows.

Each phase:
1. Write prompt to a file
2. Open a new terminal window
3. Run the CLI tool with the prompt
4. The tool reads/writes markdown files in the project
5. When done, the terminal closes
6. Coordinator picks up the results from the markdown files
"""

import subprocess
import os
import sys
import time
from pathlib import Path
from typing import Optional


def spawn_terminal(command: str, title: str = "AI Phase", wait: bool = True) -> Optional[int]:
    """
    Spawn a new terminal window with a command.
    On Windows, uses 'start' to open a new cmd/PowerShell window.
    """
    if sys.platform == "win32":
        # Create a batch file that runs the command and pauses
        bat_path = Path(os.environ.get("TEMP", ".")) / f"mutation_{title.replace(' ', '_').lower()}.bat"

        bat_content = f"""@echo off
title {title}
cd /d "{os.getcwd()}"
echo ============================================
echo {title}
echo ============================================
echo.
{command}
echo.
echo ============================================
echo Phase complete. Closing in 3 seconds...
echo ============================================
timeout /t 3 /nobreak >nul
"""
        bat_path.write_text(bat_content)

        if wait:
            # Run and wait for completion
            proc = subprocess.Popen(
                ["cmd", "/c", str(bat_path)],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
            proc.wait()
            return proc.returncode
        else:
            # Just open the terminal
            subprocess.Popen(
                ["cmd", "/c", "start", "cmd", "/k", str(bat_path)],
            )
            return None
    else:
        # Linux/Mac: use xterm or similar
        print(f"[SPAWN] {title}: {command}")
        return None


def spawn_kilo(prompt_file: str, work_dir: str = None) -> Optional[int]:
    """Spawn Kilo in a new terminal."""
    cwd = work_dir or os.getcwd()
    cmd = f'kilo --auto "$(cat {prompt_file})"'
    return spawn_terminal(cmd, "Kilo - Mutator")


def spawn_opencode(prompt_file: str, work_dir: str = None) -> Optional[int]:
    """Spawn OpenCode in a new terminal."""
    cwd = work_dir or os.getcwd()
    cmd = f'opencode run -p "$(cat {prompt_file})"'
    return spawn_terminal(cmd, "OpenCode - Scanner")


def spawn_claude(prompt_file: str, work_dir: str = None) -> Optional[int]:
    """Spawn Claude in a new terminal."""
    cwd = work_dir or os.getcwd()
    cmd = f'claude -p "$(cat {prompt_file})"'
    return spawn_terminal(cmd, "Claude - Verifier")


def spawn_gemini(prompt_file: str, work_dir: str = None) -> Optional[int]:
    """Spawn Gemini in a new terminal."""
    cwd = work_dir or os.getcwd()
    cmd = f'gemini -p "$(cat {prompt_file})"'
    return spawn_terminal(cmd, "Gemini - Researcher")


# ── Phase Runner ───────────────────────────────────────────────────────────

PHASE_SPAWNERS = {
    "scanner":    spawn_opencode,
    "mutator":    spawn_kilo,
    "verifier":   spawn_claude,
    "researcher": spawn_gemini,
}


def run_phase_spawn(role: str, prompt: str, findings_dir: str) -> int:
    """Write prompt to file, spawn the CLI tool in a new terminal."""
    prompt_dir = Path(findings_dir) / "prompts"
    prompt_dir.mkdir(exist_ok=True)

    prompt_file = prompt_dir / f"{role}_prompt.md"
    prompt_file.write_text(prompt)

    spawner = PHASE_SPAWNERS.get(role)
    if not spawner:
        print(f"[ERROR] No spawner for role: {role}")
        return 1

    print(f"\n[SPAWNING] {role.upper()} in new terminal...")
    print(f"  Prompt: {prompt_file}")
    print(f"  Tool: {role}")

    rc = spawner(str(prompt_file), findings_dir)
    print(f"  Done. Exit code: {rc}")
    return rc or 0


# ── Prompt Builders (same as coordinator_v2) ───────────────────────────────

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


def build_prompt(role: str, target_url: str, findings_dir: str) -> str:
    """Build the prompt for a specific phase."""
    fd = Path(findings_dir)

    def read_file(name):
        p = fd / name
        return p.read_text() if p.exists() else "(empty)"

    estate = read_file("estate.md")
    findings = read_file("findings.md")
    mutations = read_file("mutations.md")
    hypotheses = read_file("hypotheses.md")

    if role == "scanner":
        return f"""{CORE_RULES}

You are the SCANNER. Target: {target_url}

Read these files in {findings_dir}/:
- estate.md (target info)
- hypotheses.md (what to test)
- findings.md (what's found)

YOUR JOB:
1. For each hypothesis in hypotheses.md, test it against the live target
2. Use curl to make HTTP requests
3. If a hypothesis works, add it to findings.md as CONFIRMED
4. If it fails, add it to mutations.md as FAILED
5. Grep EVERY response for flags, tokens, keys, PII
6. Write results directly to the markdown files in {findings_dir}/

Start by reading hypotheses.md and testing each one."""

    elif role == "mutator":
        return f"""{CORE_RULES}

You are the MUTATOR. Target: {target_url}

Read these files in {findings_dir}/:
- findings.md (confirmed vulnerabilities)
- mutations.md (what's been tried)

YOUR JOB:
1. For each confirmed finding, create 3-5 VARIANT payloads
2. Try: URL encoding, double encoding, unicode, hex, case variations
3. Try: parameter pollution, HTTP method variations, content-type tricks
4. Try: comment injection, boundary breaking, WAF bypasses
5. Write each new hypothesis as a concrete HTTP request
6. Add new hypotheses to hypotheses.md

Start by reading findings.md and creating variants."""

    elif role == "verifier":
        return f"""{CORE_RULES}

You are the VERIFIER. Target: {target_url}

Read these files in {findings_dir}/:
- hypotheses.md (what to test)
- estate.md (target info)

YOUR JOB:
1. For each hypothesis in hypotheses.md, make the EXACT HTTP request
2. Record status code, headers, body
3. If it works -> add to findings.md as CONFIRMED
4. If it fails -> add to mutations.md as FAILED
5. Grep EVERY response for secrets/flags/PII
6. Test ALL hypotheses, skip none

Start by reading hypotheses.md and testing each one."""

    elif role == "researcher":
        return f"""{CORE_RULES}

You are the RESEARCHER. Target: {target_url}

Read these files in {findings_dir}/:
- findings.md (what's been found)
- estate.md (target info)

YOUR JOB:
1. Identify the target's technology stack
2. Search the web for known CVEs for that stack
3. Search for bypass techniques for defenses encountered
4. Search for similar applications and their vulnerabilities
5. Generate NEW hypotheses not yet tried
6. Add new hypotheses to hypotheses.md under "## New (from web search)"

Start by reading estate.md and findings.md, then search the web."""

    return ""


# ── Termination Check ──────────────────────────────────────────────────────

def check_termination(findings_dir: str, max_iterations: int, iteration: int) -> tuple:
    if iteration >= max_iterations:
        return True, f"Max iterations ({max_iterations}) reached"

    hypotheses_path = Path(findings_dir) / "hypotheses.md"
    if hypotheses_path.exists():
        content = hypotheses_path.read_text()
        active = content.split("## Active")[-1].split("##")[0].strip()
        if not active:
            return True, "No active hypotheses remaining"

    return False, ""


# ── Main Loop ──────────────────────────────────────────────────────────────

def run_loop(target_url: str, consent_file: str, target_name: str = None,
             max_iterations: int = 10):
    if not target_name:
        target_name = target_url.replace("https://", "").replace("http://", "").replace("/", "_")

    findings_dir = f"findings/{target_name}"
    os.makedirs(findings_dir, exist_ok=True)

    # Initialize files
    for name, content in {
        "estate.md": f"# Target Estate\n\n## Target\n\n{target_url}\n\n## Scope\n\n## Known Endpoints\n\n",
        "findings.md": "# Findings\n\n## Confirmed\n\n## Candidates\n\n",
        "mutations.md": "# Mutations Log\n\n## Successful\n\n## Failed\n\n",
        "hypotheses.md": """# Hypotheses

## Active
1. Enumerate endpoints: /api, /admin, /login, /graphql, /.env, /config, /robots.txt
2. Check technology stack
3. Test authentication: default creds, SQLi on login
4. Check info disclosure: error messages, debug endpoints
5. Test injection: SQLi, XSS, SSRF on all inputs
6. Check CORS with different Origin headers
7. Test IDOR on sequential IDs
8. Check SSRF with internal IPs
9. Test file upload
10. Check command injection

## Exhausted

## New (from web search)
""",
    }.items():
        p = Path(findings_dir) / name
        if not p.exists():
            p.write_text(content)

    print(f"\n{'#'*60}")
    print(f"# MUTATION LOOP: {target_url}")
    print(f"# Findings: {findings_dir}/")
    print(f"# Max iterations: {max_iterations}")
    print(f"{'#'*60}")

    for i in range(max_iterations):
        print(f"\n{'─'*60}")
        print(f"ITERATION {i + 1}")
        print(f"{'─'*60}")

        for phase in ["scanner", "mutator", "verifier", "researcher"]:
            prompt = build_prompt(phase, target_url, findings_dir)
            run_phase_spawn(phase, prompt, findings_dir)

            # Pause between phases
            input(f"\n[PHASE COMPLETE] {phase.upper()} done. Press Enter to continue...")

        # Check termination
        should_stop, reason = check_termination(findings_dir, max_iterations, i + 1)
        if should_stop:
            print(f"\nTERMINATION: {reason}")
            break

        # Human gate
        print(f"\n{'='*60}")
        findings_path = Path(findings_dir) / "findings.md"
        if findings_path.exists():
            content = findings_path.read_text()
            print("Current findings:")
            print(content[:1000])
        response = input("\nContinue to next iteration? (y/n): ").strip().lower()
        if response != "y":
            break

    print(f"\n{'#'*60}")
    print(f"# LOOP COMPLETE")
    print(f"# Findings: {findings_dir}/findings.md")
    print(f"{'#'*60}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Mutation Loop - Terminal Spawner")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--consent", required=True, help="Consent file")
    parser.add_argument("--name", help="Target name")
    parser.add_argument("--max-iterations", type=int, default=10)
    args = parser.parse_args()

    run_loop(
        target_url=args.target,
        consent_file=args.consent,
        target_name=args.name,
        max_iterations=args.max_iterations,
    )


if __name__ == "__main__":
    main()
