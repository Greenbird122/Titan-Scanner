#!/usr/bin/env python3
"""
Mutation Loop Coordinator V2

Instead of calling broken CLI tools, this uses:
1. Direct file-based orchestration (markdown files as state)
2. A simple Python runner that the HUMAN executes each phase
3. Each phase reads markdown files, does work, writes results
4. The coordinator tracks progress and checks termination

The human is the orchestrator. The AI models are the workers.
"""

import json
import os
import sys
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

# ── Core Rules (always in every prompt) ────────────────────────────────────

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


# ── State Management ───────────────────────────────────────────────────────

class MutationState:
    """Manages markdown state files for a target."""

    def __init__(self, target_dir: str):
        self.dir = Path(target_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._init_files()

    def _init_files(self):
        defaults = {
            "estate.md": "# Target Estate\n\n## Target\n\n## Scope\n\n## Known Endpoints\n\n## Authentication\n\n",
            "findings.md": "# Findings\n\n## Confirmed\n\n## Candidates\n\n",
            "mutations.md": "# Mutations Log\n\n## Successful\n\n## Failed\n\n## Attempted\n\n",
            "hypotheses.md": "# Hypotheses\n\n## Active\n\n## Exhausted\n\n## New (from web search)\n\n",
            "log.md": "# Iteration Log\n\n",
        }
        for name, content in defaults.items():
            path = self.dir / name
            if not path.exists():
                path.write_text(content)

        iter_file = self.dir / "iteration.json"
        if not iter_file.exists():
            iter_file.write_text(json.dumps({
                "iteration": 0,
                "phase": "init",
                "started_at": datetime.now().isoformat(),
            }, indent=2))

    def read(self, filename: str) -> str:
        path = self.dir / filename
        return path.read_text() if path.exists() else ""

    def write(self, filename: str, content: str, append: bool = False):
        path = self.dir / filename
        if append:
            with open(path, "a") as f:
                f.write(content + "\n\n")
        else:
            path.write_text(content)

    def get_iteration(self) -> int:
        data = json.loads((self.dir / "iteration.json").read_text())
        return data["iteration"]

    def next_iteration(self):
        data = json.loads((self.dir / "iteration.json").read_text())
        data["iteration"] += 1
        data["started_at"] = datetime.now().isoformat()
        (self.dir / "iteration.json").write_text(json.dumps(data, indent=2))


# ── Phase Prompts (what each AI model should do) ──────────────────────────

def bootstrap_hypotheses(state: MutationState, target_url: str):
    """Generate initial hypotheses from the target URL."""
    hypotheses = f"""# Hypotheses

## Active
1. Enumerate endpoints: try common paths (/api, /admin, /login, /graphql, /.env, /config, /robots.txt, /sitemap.xml)
2. Check technology stack: what framework, language, database?
3. Test authentication: try default creds, SQLi on login, auth bypass
4. Check for info disclosure: error messages, debug endpoints, source code
5. Test for injection: SQLi, XSS, SSRF on all input parameters
6. Check CORS: test with different Origin headers
7. Check for IDOR: sequential IDs on API endpoints
8. Test file upload: try uploading different file types
9. Check for SSRF: test URL parameters with internal IPs
10. Check for command injection: test input in shell contexts

## Exhausted

## New (from web search)
"""
    state.write("hypotheses.md", hypotheses)


def build_phase_prompt(phase: str, state: MutationState, target_url: str) -> str:
    """Build the prompt for a specific phase."""
    estate = state.read("estate.md")
    findings = state.read("findings.md")
    mutations = state.read("mutations.md")
    hypotheses = state.read("hypotheses.md")

    if phase == "scanner":
        return f"""{CORE_RULES}

You are the SCANNER in a security mutation loop.
Target: {target_url}

## Target Estate
{estate}

## Current Hypotheses
{hypotheses}

## Existing Findings
{findings}

## Instructions
1. Read the target estate and hypotheses
2. For each hypothesis, attempt exploitation against the live target using curl or web requests
3. For each finding, verify it with a live HTTP request
4. Report ONLY confirmed findings (HTTP response proves the vulnerability)
5. Grep every response for sensitive data (flags, tokens, keys, PII)
6. If you find something, document it as a CONFIRMED finding
7. If you try something and it fails, document what you tried

Output: Write your findings to the findings.md file. Be specific and reproducible."""

    elif phase == "mutator":
        return f"""{CORE_RULES}

You are the MUTATOR in a security mutation loop.
Target: {target_url}

## Confirmed Findings
{findings}

## What's Been Tried
{mutations}

## Instructions
1. For each confirmed finding, create 3-5 VARIANT payloads
2. Try: URL encoding, double encoding, unicode, hex, case variations
3. Try: parameter pollution, HTTP method variations, content-type tricks
4. Try: comment injection, boundary breaking, WAF bypasses
5. Write each new hypothesis as a concrete, testable HTTP request
6. Add new hypotheses to the hypotheses.md file

Output: Add new testable hypotheses. Be specific about the exact HTTP request to test."""

    elif phase == "verifier":
        return f"""{CORE_RULES}

You are the VERIFIER in a security mutation loop.
Target: {target_url}

## Target Estate
{estate}

## Hypotheses to Test
{hypotheses}

## Instructions
1. For each hypothesis, make the EXACT HTTP request against the live target
2. Record status code, headers, body
3. If it works -> add to findings.md as CONFIRMED
4. If it fails -> add to mutations.md as FAILED
5. If it returns interesting data -> grep for secrets/flags/PII
6. Do NOT skip any hypothesis — test them ALL

Output: Update findings.md and mutations.md. Include full HTTP details."""

    elif phase == "researcher":
        return f"""{CORE_RULES}

You are the RESEARCHER in a security mutation loop.
Target: {target_url}

## Current Findings
{findings}

## Target Estate
{estate}

## Instructions
1. Identify the target's technology stack (framework, language, version)
2. Search the web for known CVEs for that stack
3. Search for bypass techniques for defenses encountered
4. Search for similar applications and their vulnerabilities
5. Generate NEW hypotheses that haven't been tried yet
6. Add new hypotheses to hypotheses.md

Output: Add new hypotheses with source/reasoning. Prioritize by impact."""

    return ""


# ── Termination Check ──────────────────────────────────────────────────────

def check_termination(state: MutationState, max_iterations: int) -> tuple:
    iteration = state.get_iteration()
    if iteration >= max_iterations:
        return True, f"Max iterations ({max_iterations}) reached"

    hypotheses = state.read("hypotheses.md")
    active = hypotheses.split("## Active")[-1].split("##")[0].strip()
    if not active or active == "(empty)":
        return True, "No active hypotheses remaining"

    return False, ""


# ── Main Loop ──────────────────────────────────────────────────────────────

def run_loop(target_url: str, consent_file: str, target_name: str = None,
             max_iterations: int = 10):
    if not target_name:
        target_name = target_url.replace("https://", "").replace("http://", "").replace("/", "_")

    findings_dir = f"findings/{target_name}"
    state = MutationState(findings_dir)

    # Set target in estate
    estate = state.read("estate.md")
    if "## Target\n\n" in estate:
        estate = estate.replace("## Target\n\n", f"## Target\n\n{target_url}\n\n")
        state.write("estate.md", estate)

    # Bootstrap hypotheses if empty
    active = state.read("hypotheses.md").split("## Active")[-1].split("##")[0].strip()
    if not active:
        print("[BOOTSTRAP] No hypotheses found — generating initial attack plan...")
        bootstrap_hypotheses(state, target_url)

    print(f"\n{'#'*60}")
    print(f"# MUTATION LOOP: {target_url}")
    print(f"# Findings: {findings_dir}/")
    print(f"# Max iterations: {max_iterations}")
    print(f"{'#'*60}")

    for i in range(max_iterations):
        iteration = state.get_iteration()
        state.next_iteration()

        print(f"\n{'─'*60}")
        print(f"ITERATION {iteration + 1}")
        print(f"{'─'*60}")

        for phase in ["scanner", "mutator", "verifier", "researcher"]:
            prompt = build_phase_prompt(phase, state, target_url)
            prompt_file = state.dir / f"prompt_{phase}.md"
            prompt_file.write_text(prompt)
            print(f"\n[Phase: {phase.upper()}]")
            print(f"  Prompt saved to: {prompt_file}")
            print(f"  -> Copy this prompt to your AI model (Kilo/OpenCode/Claude)")
            print(f"  -> Paste the AI's response into the findings/mutations/hypotheses files")
            print(f"  -> Press Enter when done")

            input("  Press Enter to continue to next phase...")

            state.write("log.md", f"## Iteration {iteration + 1} — {phase}\n\n(Completed)", append=True)

        # Check termination
        should_stop, reason = check_termination(state, max_iterations)
        if should_stop:
            print(f"\nTERMINATION: {reason}")
            break

        # Human gate
        print(f"\n{'='*60}")
        print("ITERATION COMPLETE — Review findings:")
        print(state.read("findings.md")[:1000])
        response = input("\nContinue? (y/n): ").strip().lower()
        if response != "y":
            print("Stopping by user request.")
            break

        state.write("log.md", "---", append=True)

    print(f"\n{'#'*60}")
    print(f"# LOOP COMPLETE")
    print(f"# Findings: {findings_dir}/findings.md")
    print(f"# Mutations: {findings_dir}/mutations.md")
    print(f"# Log: {findings_dir}/log.md")
    print(f"{'#'*60}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Mutation Loop Coordinator V2")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--consent", required=True, help="Consent file path")
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
