#!/usr/bin/env python3
"""
Multi-AI Mutation Loop Coordinator

Orchestrates multiple AI models in a security scanning loop:
1. Scanner finds vulns
2. Mutator creates variants
3. Verifier tests probes
4. Researcher finds new vectors (with web search)
5. Human approves or terminates

Each model reads/writes markdown files. The coordinator manages the flow.
"""

import json
import os
import sys
import time
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

# ── Configuration ──────────────────────────────────────────────────────────

CORE_RULES = """# Core rules for the mutation loop
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

# ── Model Configuration ────────────────────────────────────────────────────

MODELS = {
    "scanner": {
        "name": "Scanner",
        "description": "Finds vulnerabilities using known patterns",
        "tool": "opencode",      # CLI tool to call
        "max_time": 300,          # seconds per iteration
    },
    "mutator": {
        "name": "Mutator",
        "description": "Creates variant payloads from findings",
        "tool": "opencode",
        "max_time": 120,
    },
    "verifier": {
        "name": "Verifier",
        "description": "Tests hypotheses against live target",
        "tool": "opencode",
        "max_time": 180,
    },
    "researcher": {
        "name": "Researcher",
        "description": "Finds new attack vectors via web search",
        "tool": "opencode",
        "max_time": 120,
    },
}


# ── File Management ────────────────────────────────────────────────────────

class MutationState:
    """Manages the markdown state files for a target."""

    def __init__(self, target_dir: str):
        self.dir = Path(target_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.findings_file = self.dir / "findings.md"
        self.mutations_file = self.dir / "mutations.md"
        self.hypotheses_file = self.dir / "hypotheses.md"
        self.estate_file = self.dir / "estate.md"
        self.log_file = self.dir / "log.md"
        self.iteration_file = self.dir / "iteration.json"
        self._init_files()

    def _init_files(self):
        """Initialize empty files if they don't exist."""
        defaults = {
            self.estate_file: "# Target Estate\n\n## Target\n\n## Scope\n\n## Known Endpoints\n\n## Authentication\n\n",
            self.findings_file: "# Findings\n\n## Confirmed\n\n## Candidates\n\n",
            self.mutations_file: "# Mutations Log\n\n## Successful\n\n## Failed\n\n## Attempted\n\n",
            self.hypotheses_file: "# Hypotheses\n\n## Active\n\n## Exhausted\n\n## New (from web search)\n\n",
            self.log_file: "# Iteration Log\n\n",
        }
        for path, content in defaults.items():
            if not path.exists():
                path.write_text(content)

        if not self.iteration_file.exists():
            self.iteration_file.write_text(json.dumps({
                "iteration": 0,
                "phase": "init",
                "started_at": datetime.now().isoformat(),
                "findings_count": 0,
                "hypotheses_count": 0,
                "status": "ready",
            }, indent=2))

    def read(self, filename: str) -> str:
        """Read a state file."""
        path = self.dir / filename
        return path.read_text() if path.exists() else ""

    def write(self, filename: str, content: str):
        """Write to a state file (append mode for log, overwrite for others)."""
        path = self.dir / filename
        if filename == "log.md":
            with open(path, "a") as f:
                f.write(content + "\n\n")
        else:
            path.write_text(content)

    def get_iteration(self) -> int:
        data = json.loads(self.iteration_file.read_text())
        return data["iteration"]

    def increment_iteration(self):
        data = json.loads(self.iteration_file.read_text())
        data["iteration"] += 1
        data["started_at"] = datetime.now().isoformat()
        self.iteration_file.write_text(json.dumps(data, indent=2))

    def update_status(self, **kwargs):
        data = json.loads(self.iteration_file.read_text())
        data.update(kwargs)
        self.iteration_file.write_text(json.dumps(data, indent=2))


# ── Model Callers ──────────────────────────────────────────────────────────

from cli_runners import run_phase, build_scanner_prompt, build_mutator_prompt, build_verifier_prompt, build_researcher_prompt


def call_model(role: str, prompt: str, state: MutationState) -> str:
    """Call the appropriate model for a role via real CLI tools."""
    config = MODELS[role]
    return run_phase(role, prompt, work_dir=state.dir, timeout=config["max_time"])


# ── Phase Implementations ──────────────────────────────────────────────────

def phase_scanner(state: MutationState) -> str:
    """Phase 1: Scanner finds vulnerabilities."""
    prompt = build_scanner_prompt(str(state.dir))
    return call_model("scanner", prompt, state)


def phase_mutator(state: MutationState) -> str:
    """Phase 2: Mutator creates variant payloads."""
    prompt = build_mutator_prompt(str(state.dir))
    return call_model("mutator", prompt, state)


def phase_verifier(state: MutationState) -> str:
    """Phase 3: Verifier tests hypotheses against live target."""
    prompt = build_verifier_prompt(str(state.dir))
    return call_model("verifier", prompt, state)


def phase_researcher(state: MutationState) -> str:
    """Phase 4: Researcher finds new attack vectors via web search."""
    prompt = build_researcher_prompt(str(state.dir))
    return call_model("researcher", prompt, state)


# ── Termination Logic ──────────────────────────────────────────────────────

def check_termination(state: MutationState, max_iterations: int) -> tuple[bool, str]:
    """Check if the loop should terminate."""
    iteration = state.get_iteration()

    # Max iterations
    if iteration >= max_iterations:
        return True, f"Max iterations ({max_iterations}) reached"

    # Check if hypotheses are exhausted
    hypotheses = state.read("hypotheses.md")
    active_section = hypotheses.split("## Active")[-1].split("##")[0].strip()
    if not active_section or active_section == "(empty)":
        return True, "No active hypotheses remaining"

    # Check if no new findings in last 3 iterations
    log = state.read("log.md")
    recent_iterations = log.split("---")[-3:]  # Last 3 sections
    findings_count = 0
    for section in recent_iterations:
        if "NEW FINDING" in section.upper():
            findings_count += 1
    if len(recent_iterations) >= 3 and findings_count == 0:
        return True, "No new findings in last 3 iterations"

    return False, ""


# ── Human Gate ─────────────────────────────────────────────────────────────

def human_gate(state: MutationState) -> bool:
    """Pause for human approval. Returns True to continue, False to stop."""
    iteration = state.get_iteration()
    findings = state.read("findings.md")
    hypotheses = state.read("hypotheses.md")

    print(f"\n{'='*60}")
    print(f"ITERATION {iteration} COMPLETE")
    print(f"{'='*60}")
    print(f"\nCurrent findings:\n{findings[:500]}...")
    print(f"\nRemaining hypotheses:\n{hypotheses[:500]}...")

    while True:
        response = input("\nContinue? (y/n/budget=N): ").strip().lower()
        if response == "y":
            return True
        elif response == "n":
            return False
        elif response.startswith("budget="):
            # Update max iterations
            new_budget = int(response.split("=")[1])
            state.update_status(max_iterations=new_budget)
            print(f"Budget updated to {new_budget} iterations")
            return True
        else:
            print("Please enter y, n, or budget=N")


# ── Main Loop ──────────────────────────────────────────────────────────────

def run_mutation_loop(
    target_url: str,
    consent_file: str,
    target_name: str = None,
    max_iterations: int = 10,
    budget: float = 100.0,
):
    """Run the full mutation loop."""
    # Setup
    if not target_name:
        target_name = target_url.replace("https://", "").replace("http://", "").replace("/", "_")

    findings_dir = f"findings/{target_name}"
    state = MutationState(findings_dir)

    print(f"\n{'#'*60}")
    print(f"# MUTATION LOOP: {target_url}")
    print(f"# Findings dir: {findings_dir}")
    print(f"# Max iterations: {max_iterations}")
    print(f"# Budget: ${budget}")
    print(f"{'#'*60}\n")

    # Initialize estate
    estate = state.read("estate.md")
    if "## Target\n\n" in estate:
        estate = estate.replace(
            "## Target\n\n",
            f"## Target\n\n{target_url}\n\n"
        )
        state.write("estate.md", estate)

    # Main loop
    for i in range(max_iterations):
        iteration = state.get_iteration()
        state.increment_iteration()

        print(f"\n{'─'*60}")
        print(f"ITERATION {iteration + 1}")
        print(f"{'─'*60}")

        # Phase 1: Scanner
        print("\n[Phase 1] Scanner...")
        state.update_status(phase="scanner")
        scanner_output = phase_scanner(state)
        state.write("log.md", f"## Iteration {iteration + 1} — Scanner\n\n{scanner_output[:2000]}")
        print(f"  Scanner done: {len(scanner_output)} chars output")

        # Check termination after scanner
        should_stop, reason = check_termination(state, max_iterations)
        if should_stop:
            print(f"\n TERMINATION: {reason}")
            break

        # Phase 2: Mutator
        print("\n[Phase 2] Mutator...")
        state.update_status(phase="mutator")
        mutator_output = phase_mutator(state)
        state.write("log.md", f"## Iteration {iteration + 1} — Mutator\n\n{mutator_output[:2000]}")
        print(f"  Mutator done: {len(mutator_output)} chars output")

        # Phase 3: Verifier
        print("\n[Phase 3] Verifier...")
        state.update_status(phase="verifier")
        verifier_output = phase_verifier(state)
        state.write("log.md", f"## Iteration {iteration + 1} — Verifier\n\n{verifier_output[:2000]}")
        print(f"  Verifier done: {len(verifier_output)} chars output")

        # Phase 4: Researcher (only if stuck)
        should_stop, reason = check_termination(state, max_iterations)
        if should_stop:
            print(f"\n TERMINATION: {reason}")
            break

        print("\n[Phase 4] Researcher...")
        state.update_status(phase="researcher")
        researcher_output = phase_researcher(state)
        state.write("log.md", f"## Iteration {iteration + 1} — Researcher\n\n{researcher_output[:2000]}")
        print(f"  Researcher done: {len(researcher_output)} chars output")

        # Phase 5: Human gate
        state.update_status(phase="human_gate")
        if not human_gate(state):
            print("\n🛑 Human requested stop.")
            break

        # Separator
        state.write("log.md", "---")

    # Final report
    print(f"\n{'#'*60}")
    print(f"# LOOP COMPLETE")
    print(f"# Findings: {findings_dir}/findings.md")
    print(f"# Mutations: {findings_dir}/mutations.md")
    print(f"# Log: {findings_dir}/log.md")
    print(f"{'#'*60}")


# ── CLI ────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Multi-AI Mutation Loop Coordinator")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--consent", required=True, help="Consent file path")
    parser.add_argument("--name", help="Target name (auto-derived if omitted)")
    parser.add_argument("--max-iterations", type=int, default=10)
    parser.add_argument("--budget", type=float, default=100.0)
    args = parser.parse_args()

    run_mutation_loop(
        target_url=args.target,
        consent_file=args.consent,
        target_name=args.name,
        max_iterations=args.max_iterations,
        budget=args.budget,
    )


if __name__ == "__main__":
    main()
