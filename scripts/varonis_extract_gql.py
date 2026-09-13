"""Extract GraphQL call-site contexts from Varonis SPA bundles (local files only)."""
import re
from pathlib import Path

D = Path(__file__).parent.parent / "findings" / "bounties" / "varonis-h1"
for raw in sorted(D.glob("js_*.js")) + sorted(D.glob("js_*.bundle.js")):
    text = raw.read_text(encoding="utf-8", errors="replace")
    hits = list(re.finditer(r'url:\s*"graphql"', text))
    if not hits:
        continue
    print(f"### {raw.name} ({len(text)} bytes, {len(hits)} graphql call-sites)")
    for m in hits:
        s = max(0, m.start() - 250)
        e = min(len(text), m.end() + 900)
        print("=" * 80)
        print(text[s:e])
        print()
