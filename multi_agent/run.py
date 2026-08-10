"""Multi-agent orchestrator: OpenCode (planner) -> Kilo (reviewer) -> FreeBuff (executor).

Shared space: multi_agent/
  state.json   — single source of truth
  outbox/      — per-agent readable output
"""
import json
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).parent
STATE_FILE = BASE / "state.json"
OUTBOX = BASE / "outbox"


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {"intent": "", "history": [], "last_agent": None, "last_output": ""}


def save_state(state: dict):
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


def extract_text(json_events: str) -> str:
    """Pull only the assistant text from opencode/kilo --format json output."""
    texts = []
    for line in json_events.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "text" and "text" in event.get("part", {}):
            texts.append(event["part"]["text"])
    return "\n".join(texts).strip()


def run_agent(name: str, prompt: str, cwd: str) -> str:
    """Run a terminal agent and return its text output."""
    exe = {
        "opencode": r"C:\Users\HomePC\AppData\Roaming\npm\opencode.cmd",
        "kilo": r"C:\Users\HomePC\AppData\Roaming\npm\kilo.cmd",
    }.get(name, name)

    cmd = [
        exe,
        "run",
        "--format", "json",
        "--pure",
        "--dir", cwd,
        prompt,
    ]
    print(f"[*] Running {name}...")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=300,
        cwd=cwd,
    )
    if result.returncode != 0:
        print(f"[!] {name} stderr: {result.stderr[:500]}", file=sys.stderr)
    return extract_text(result.stdout)


def save_outbox(agent: str, text: str):
    (OUTBOX / f"{agent}.md").write_text(text, encoding="utf-8")


def main():
    intent = sys.argv[1] if len(sys.argv) > 1 else "Scan https://example.com for SQL injection and XSS"
    cwd = str(BASE.parent)  # run agents from the vuln-scanner project root

    state = load_state()
    state["intent"] = intent
    state.setdefault("history", [])
    save_state(state)

    # Step 1: OpenCode plans
    plan = run_agent(
        "opencode",
        f"Given this intent: {intent}\n"
        f"Read multi_agent/state.json for context.\n"
        f"Produce a concise step-by-step execution plan. "
        f"Return ONLY the plan, no preamble.",
        cwd,
    )
    save_outbox("opencode", plan)
    state["history"].append({"agent": "opencode", "output": plan})
    state["last_agent"] = "opencode"
    state["last_output"] = plan
    save_state(state)
    print(f"[opencode output saved to {OUTBOX / 'opencode.md'}]\n")

    # Step 2: Kilo reviews
    review = run_agent(
        "kilo",
        f"Review this execution plan and improve it:\n\n{plan}\n\n"
        f"Look for gaps, unsafe steps, missing verifications. "
        f"Return ONLY the reviewed plan, no preamble.",
        cwd,
    )
    save_outbox("kilo", review)
    state["history"].append({"agent": "kilo", "output": review})
    state["last_agent"] = "kilo"
    state["last_output"] = review
    save_state(state)
    print(f"[kilo review saved to {OUTBOX / 'kilo.md'}]\n")

    print("=== Final state ===")
    print(json.dumps(state, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
