"""Phase 1 helper: extract RSC payload from saved Next.js HTML pages."""

import re
import sys

from titan.core.logger import get_logger

logger = get_logger("probe_rsc")


URL_RE = re.compile(r'https?://[a-zA-Z0-9.\-]+[^\s"\'<>\\]{0,80}')
API_RE = re.compile(r"/api/[a-zA-Z0-9_/\-]+")
CALL_RE = re.compile(r"(?:fetch|axios|\.post|\.get|action)\([^)]{0,90}")


def extract(path: str) -> None:
    raw = open(path, encoding="utf-8", errors="replace").read()
    chunks = re.findall(r"self\.__next_f\.push\((\[.*?\])\)", raw, re.S)
    text = "".join(chunks)
    try:
        text = text.encode().decode("unicode_escape", errors="ignore")
    except Exception as exc:
        logger.debug(f"suppressed exception: {exc}")
        pass
    print(f"\n## {path} (rsc {len(text)}b)")
    for u in sorted(set(URL_RE.findall(text)))[:14]:
        print("  url:", u)
    for a in sorted(set(API_RE.findall(text)))[:20]:
        print("  api:", a)
    for c in sorted(set(CALL_RE.findall(text)))[:10]:
        print("  call:", c)


if __name__ == "__main__":
    for f in sys.argv[1:]:
        extract(f)
