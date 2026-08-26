#!/usr/bin/env python
"""Titan Fleet CLI - link your public GitHub repos to the scanner.

The fleet is the *known* loop: pushes to your own deployed sites get a red
round (scan + consent-gated exploit) and findings land on the war-room
scoreboard for blue to absorb. Consent is the only thing asked - per repo,
signed against the site's deployed URL.

Usage:
    python titan_fleet_cli.py sync                # discover your public repos
    python titan_fleet_cli.py link <repo> <url>   # register a deployed site
    python titan_fleet_cli.py unlink <repo>
    python titan_fleet_cli.py list                # sites + consent status
    python titan_fleet_cli.py consent <repo>      # print the consent cmd
    python titan_fleet_cli.py round <repo>        # red round NOW (scan+exploit)
    python titan_fleet_cli.py watch               # one-shot: push -> red round
    python titan_fleet_cli.py daemon [--interval 300]
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from fleet.registry import Registry, discover_public_repos  # noqa: E402
from fleet.poller import PushWatcher  # noqa: E402
from fleet.red_round import run_red_round  # noqa: E402

CONSENT_DIR = "consent"


def _print_round(rec: dict) -> None:
    if rec["status"] == "blocked":
        print(f"    [blocked] {rec['reason']}")
        return
    print(
        f"    findings={rec['findings']} verified={rec['verified']} "
        f"critical={rec['critical']} high={rec['high']} "
        f"sessions={rec['sessions']} round={rec['round_id']}"
    )


def cmd_sync(args) -> int:
    reg = Registry.load()
    repos = discover_public_repos(reg.owner)
    linked = {s.repo for s in reg.sites}
    print(f"[+] {len(repos)} public repo(s) for {reg.owner}:")
    for r in repos:
        name = r.get("name", "?")
        mark = "linked" if name in linked else "-"
        print(f"    {name:24s} {mark}  {r.get('html_url', '')}")
    return 0


def cmd_link(args) -> int:
    reg = Registry.load()
    reg.link(args.repo, args.url)
    reg.save()
    print(f"[+] linked {args.repo} -> {args.url}")
    return 0


def cmd_unlink(args) -> int:
    reg = Registry.load()
    if reg.unlink(args.repo):
        reg.save()
        print(f"[-] unlinked {args.repo}")
        return 0
    print(f"[!] {args.repo} not in registry")
    return 1


def cmd_list(args) -> int:
    from titan.exploit.consent import consent_filename

    reg = Registry.load()
    print(f"[+] fleet owner: {reg.owner}")
    if not reg.sites:
        print("    no sites linked - use: python titan_fleet_cli.py link <repo> <url>")
        return 0
    for s in reg.sites:
        cf = Path(CONSENT_DIR) / f"{consent_filename(s.url)}.json"
        state = "signed" if cf.exists() else "MISSING"
        print(f"    {s.repo:24s} -> {s.url}   consent: {state}")
    return 0


def cmd_consent(args) -> int:
    reg = Registry.load()
    site = reg.get(args.repo)
    if not site:
        print(f"[!] {args.repo} not linked - link it first")
        return 1
    print(
        f"python titan_exploit_cli.py consent add {site.url} "
        "--write --shells --persistence"
    )
    return 0


def _fire(site, args) -> dict:
    return asyncio.run(
        run_red_round(
            site,
            exploit=not args.no_exploit,
            profile=getattr(args, "profile", None),
            consent_dir=CONSENT_DIR,
            scoreboard_store=args.scoreboard,
        )
    )


def cmd_round(args) -> int:
    reg = Registry.load()
    site = reg.get(args.repo)
    if not site:
        print(f"[!] {args.repo} not linked - link it first")
        return 1
    print(f"[+] red round on {site.repo} -> {site.url}")
    _print_round(_fire(site, args))
    return 0


def cmd_watch(args) -> int:
    reg = Registry.load()
    events = PushWatcher().check(reg)
    if not events:
        print("[+] no new pushes on linked sites")
        return 0
    for ev in events:
        print(f"[!] push on {ev.repo}: {ev.old_sha[:8]} -> {ev.new_sha[:8]}")
        site = reg.get(ev.repo)
        if site:
            _print_round(_fire(site, args))
    return 0


def cmd_daemon(args) -> int:
    print(f"[+] fleet daemon watching every {args.interval}s (Ctrl-C to stop)")
    while True:
        try:
            cmd_watch(args)
        except Exception as exc:  # keep the daemon alive
            print(f"[!] watch error: {exc}")
        time.sleep(args.interval)


def _round_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--no-exploit", action="store_true", help="detection only - no auto-staging")
    p.add_argument(
        "--profile",
        default=None,
        help="crawl profile: fast (default) | deep | hostile",
    )
    p.add_argument(
        "--scoreboard",
        default=None,
        help="scoreboard store path (default: purple/scoreboard.json)",
    )


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="titan-fleet", description=__doc__)
    sub = p.add_subparsers(dest="cmd")

    sub.add_parser("sync").set_defaults(fn=cmd_sync)
    lk = sub.add_parser("link")
    lk.add_argument("repo")
    lk.add_argument("url")
    lk.set_defaults(fn=cmd_link)
    ul = sub.add_parser("unlink")
    ul.add_argument("repo")
    ul.set_defaults(fn=cmd_unlink)
    sub.add_parser("list").set_defaults(fn=cmd_list)
    cns = sub.add_parser("consent")
    cns.add_argument("repo")
    cns.set_defaults(fn=cmd_consent)
    r = sub.add_parser("round")
    r.add_argument("repo")
    _round_opts(r)
    r.set_defaults(fn=cmd_round)
    w = sub.add_parser("watch")
    _round_opts(w)
    w.set_defaults(fn=cmd_watch)
    d = sub.add_parser("daemon")
    _round_opts(d)
    d.add_argument("--interval", type=int, default=300)
    d.set_defaults(fn=cmd_daemon)

    args = p.parse_args(argv)
    fn = getattr(args, "fn", None)
    if not fn:
        p.print_help()
        return 1
    return fn(args)


if __name__ == "__main__":
    sys.exit(main())
