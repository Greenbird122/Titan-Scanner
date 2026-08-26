"""Firebase RTDB + Storage probe.

Reads (no consent needed):
  - root and child-level .json reads across candidate paths
  - storage bucket existence (404 vs 403 with X-Firebase-Storage-Version: 2)

Writes (require flags=['write'] in consent):
  - RTDB PUT/PATCH a marker node, read back, then DELETE it
  - reports residue if DELETE is denied

Usage:
    python probe_firebase.py <project> <target-domain> \
        [--paths users helperCodes chats/stats] [--write]

Example:
    python probe_firebase.py database-tulia database-tulia.vercel.app
    python probe_firebase.py database-tulia database-tulia.vercel.app --write

Note: consent is keyed by the VERCEL/APP domain (what the operator signed),
not the firebase project name.
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from consent import load_consent, require_write  # noqa: E402

MARKER = "SECPROBE"
RTDB = "https://{project}.firebaseio.com"
STORE = "https://{project}.firebasestorage.app"


def http(method, url, data=None, headers=None, timeout=20):
    h = {"User-Agent": "Mozilla/5.0"}
    if headers:
        h.update(headers)
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        h["Content-Type"] = "application/json"
    r = urllib.request.Request(url, method=method, data=body, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def probe_reads(project, paths):
    print(f"[firebase] project={project} — READ surface (no consent needed)")
    for p in paths:
        url = f"{RTDB.format(project=project)}/{p}.json"
        st, body = http("GET", url)
        snippet = body[:120].replace("\n", " ") if st == 200 else ""
        print(f"  GET /{p}.json -> {st}  {snippet}")
    # storage buckets
    for bucket in (project, f"{project}.appspot.com"):
        url = f"{STORE.format(project=project)}/{bucket}/"
        st, _ = http("GET", url, headers={"X-Firebase-Storage-Version": "2"})
        # 404 = bucket does not exist (boilerplate config); 403 = exists, denied
        print(f"  storage bucket {bucket} -> {st} "
              f"({'does not exist' if st == 404 else 'exists' if st in (400, 403, 401) else '?'})")


def probe_write(project, target, paths):
    c = load_consent(target)
    require_write(c, "RTDB write probe")
    print(f"[firebase] project={project} — WRITE probe (consent flags={c.get('flags')})")
    for p in paths:
        # child-level write: the level the app itself writes at
        url = f"{RTDB.format(project=project)}/{p}/{MARKER}.json"
        st, _ = http("PUT", url, {"probe": MARKER, "ts": 0})
        print(f"  PUT /{p}/{MARKER}.json -> {st}")
        st2, body = http("GET", url)
        ok = st2 == 200 and MARKER in body
        print(f"  GET read-back -> {st2}  marker_visible={ok}")
        st3, _ = http("DELETE", url)
        print(f"  DELETE -> {st3}  "
              f"({'CLEAN' if st3 == 200 else 'RESIDUE — remove /{p}/{MARKER}.json manually'})")


def main():
    ap = argparse.ArgumentParser(description="Firebase RTDB/storage probe")
    ap.add_argument("project", help="firebase project id (from bundle firebaseConfig)")
    ap.add_argument("target", help="consent ledger domain, e.g. site.vercel.app")
    ap.add_argument("--paths", nargs="*", default=["users", "helperCodes", "chats/stats"])
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    probe_reads(args.project, args.paths)
    if args.write:
        probe_write(args.project, args.target, args.paths)
    return 0


if __name__ == "__main__":
    sys.exit(main())
