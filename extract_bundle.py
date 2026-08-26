#!/usr/bin/env python3
"""Local extraction of secrets / URLs / sinks from archived JS bundles."""
import json
import re
from pathlib import Path

BUNDLES = [
    Path("findings/database-tulia-vercel-app/archive/assets/0002_database-tulia-vercel-app-assets-index-DEx6ECuL-js.js"),
    Path("findings/git-vizor-vercel-app/archive/assets/0002_git-vizor-vercel-app-js-gatekeeper-js.js"),
]

URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
AIZA_RE = re.compile(r"AIza[0-9A-Za-z_-]{20,}")
FIREBASE_RE = re.compile(r"(tulia-tag|firebaseio\.com|firestore\.googleapis|identitytoolkit|firebaseapp\.com|\.web\.app|railway\.app|googleapis\.com)", re.I)
SINK_RE = re.compile(r".{0,80}(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function|dangerouslySetInnerHTML).{0,80}")


def extract(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    urls = sorted(set(URL_RE.findall(text)))
    keys = sorted(set(AIZA_RE.findall(text)))
    fb = sorted(set(m.group(0) for m in FIREBASE_RE.finditer(text)))
    sinks = []
    for m in SINK_RE.finditer(text):
        snippet = m.group(0).replace("\n", " ")[:200]
        if snippet not in sinks:
            sinks.append(snippet)
        if len(sinks) >= 25:
            break
    return {
        "file": str(path),
        "bytes": len(text),
        "keys": keys,
        "firebase_hits": fb,
        "urls": urls[:80],
        "url_count": len(urls),
        "sinks": sinks,
    }


def main():
    out = [extract(p) for p in BUNDLES if p.exists()]
    dest = Path("findings/BUNDLE-EXTRACT.json")
    dest.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
    for item in out:
        print("=" * 70)
        print(item["file"], "bytes=", item["bytes"])
        print("keys:", item["keys"])
        print("firebase:", item["firebase_hits"])
        print("url_count:", item["url_count"])
        for u in item["urls"][:30]:
            print("  URL", u[:140])
        print("sinks:")
        for s in item["sinks"][:15]:
            print(" ", s[:180])
    print(f"\n[+] written to {dest}")


if __name__ == "__main__":
    main()
