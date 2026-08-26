"""Titan Omega — Unified CLI.

One command to rule them all:
    titan scan <target>                    # Quick scan
    titan scan <target> --transport tor    # .onion scan
    titan scan <target> --profile deep     # Deep scan with all modules
    titan brain <target>                   # Autonomous engagement
    titan fleet scan-all                   # Scan all registered sites
    titan consent add <target> --basis ownership
    titan transport list                   # List available transports
    titan report --estate                  # Cross-site rollup

Usage:
    python -m titan scan https://example.com
    python -m titan brain https://target.com --budget 600
    python -m titan consent add https://target.com --basis ownership --write
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Optional


def create_parser() -> argparse.ArgumentParser:
    """Build the unified CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="titan",
        description="Titan Omega — Autonomous Red-Team Operating System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  titan scan https://example.com                        # Quick scan
  titan scan http://xyz.onion --transport tor           # .onion scan
  titan scan https://api.example.com --profile deep     # Deep scan
  titan brain https://target.com --budget 600           # Autonomous engagement
  titan fleet scan-all                                  # Scan all registered sites
  titan consent add https://target.com --basis ownership
  titan transport list                                  # List transports
  titan report --estate                                 # Estate rollup
        """,
    )

    parser.add_argument("--version", action="version", version="Titan Omega 0.2.0")

    subparsers = parser.add_subparsers(dest="command", help="Command")

    # --- scan ---
    scan = subparsers.add_parser("scan", help="Scan a target")
    scan.add_argument("target", help="Target URL (HTTP, .onion, gRPC, etc.)")
    scan.add_argument("--transport", choices=["http", "tor", "grpc", "websocket", "mqtt", "ssh", "auto"],
                       default="auto", help="Transport protocol (default: auto-detect)")
    scan.add_argument("--profile", choices=["fast", "deep", "stealth", "hostile"],
                       default="fast", help="Scan profile (default: fast)")
    scan.add_argument("--exploit", action="store_true",
                       help="Auto-stage verified findings (requires consent)")
    scan.add_argument("--fleet", action="store_true",
                       help="Enable fleet multi-agent deep dive after main scan")
    scan.add_argument("--output", "-o", help="Output directory (default: findings/)")
    scan.add_argument("--timeout", type=int, default=300, help="Max scan duration in seconds")
    scan.add_argument("--config", default="config.yaml", help="Config file path")
    scan.add_argument("--quiet", "-q", action="store_true", help="Suppress verbose output")

    # --- brain ---
    brain = subparsers.add_parser("brain", help="Autonomous engagement (brain loop)")
    brain.add_argument("target", help="Target URL")
    brain.add_argument("--budget", type=float, default=300, help="Time budget in seconds")
    brain.add_argument("--max-iterations", type=int, default=100, help="Max brain loop iterations")
    brain.add_argument("--depth-ceiling", type=float, default=0.8, help="Depth ceiling (0-1)")
    brain.add_argument("--module-runner", action="store_true",
                        help="Use real detector modules (requires engine context)")

    # --- fleet ---
    fleet = subparsers.add_parser("fleet", help="Fleet management")
    fleet_sub = fleet.add_subparsers(dest="fleet_command")
    fleet_sub.add_parser("scan-all", help="Scan all registered sites")
    fleet_list = fleet_sub.add_parser("list", help="List registered sites")
    fleet_link = fleet_sub.add_parser("link", help="Register a site")
    fleet_link.add_argument("repo", help="GitHub repo name")
    fleet_link.add_argument("url", help="Site URL")

    # --- consent ---
    consent = subparsers.add_parser("consent", help="Manage consent files")
    consent_sub = consent.add_subparsers(dest="consent_command")
    consent_add = consent_sub.add_parser("add", help="Add consent for a target")
    consent_add.add_argument("target", help="Target URL")
    consent_add.add_argument("--basis", required=True, help="Authorization basis")
    consent_add.add_argument("--write", action="store_true", help="Allow state changes")
    consent_add.add_argument("--shells", action="store_true", help="Allow agent deployment")
    consent_add.add_argument("--persistence", action="store_true", help="Allow persistence")
    consent_sub.add_parser("list", help="List all consents")
    consent_revoke = consent_sub.add_parser("revoke", help="Revoke consent")
    consent_revoke.add_argument("target", help="Target URL")

    # --- transport ---
    transport = subparsers.add_parser("transport", help="Transport diagnostics")
    transport_sub = transport.add_subparsers(dest="transport_command")
    transport_sub.add_parser("list", help="List available transports")
    transport_check = transport_sub.add_parser("check", help="Check transport connectivity")
    transport_check.add_argument("name", help="Transport name (http, tor, grpc, etc.)")
    transport_check.add_argument("target", help="Target URL to check against")

    # --- report ---
    report = subparsers.add_parser("report", help="Generate reports")
    report.add_argument("--estate", action="store_true", help="Estate-wide rollup")
    report.add_argument("--target", help="Specific site slug or URL")
    report.add_argument("--format", choices=["executive", "technical", "remediation", "legal"],
                         default="technical", help="Report format")
    report.add_argument("--dashboard", action="store_true",
                         help="Generate interactive HTML dashboard")

    return parser


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

async def _handle_scan(args):
    """Handle scan command — runs a full Titan scan."""
    import yaml

    # Load config
    try:
        with open(args.config) as f:
            config = yaml.safe_load(f) or {}
    except FileNotFoundError:
        config = {}

    # Override config with CLI args
    config["target"] = args.target
    config["headless"] = True
    config.setdefault("crawl", {})
    config["crawl"]["profile"] = args.profile
    config["crawl"]["timeout"] = args.timeout

    if args.output:
        config["output_dir"] = args.output
    if args.exploit:
        config.setdefault("exploit", {})["enabled"] = True
    if args.fleet:
        config.setdefault("fleet", {})["enabled"] = True

    if not args.quiet:
        print(f"[+] Titan scan: {args.target}")
        print(f"    Profile: {args.profile} | Transport: {args.transport} | Fleet: {'on' if args.fleet else 'off'}")

    from titan.core.engine import TitanEngine
    engine = TitanEngine(config)
    result = await engine.scan(args.target)

    # Summary
    total = len(result.findings)
    verified = len([f for f in result.findings if getattr(f, "verified", False)])
    critical = sum(1 for f in result.findings
                   if getattr(f.severity, "value", str(f.severity)) == "critical")

    if not args.quiet:
        print(f"\n[+] Scan complete: {total} findings ({verified} verified, {critical} critical)")
        print(f"    Duration: {result.finished_at - result.started_at:.1f}s")
        if result.errors:
            print(f"    Errors: {len(result.errors)}")
        for err in result.errors[:3]:
            print(f"      - {err}")

    return 0


async def _handle_brain(args):
    """Handle brain command — runs the autonomous brain loop."""
    print(f"[+] Titan brain: {args.target}")
    print(f"    Budget: {args.budget}s | Max iterations: {args.max_iterations}")

    from titan.brain.loop import BrainLoop
    brain = BrainLoop(target=args.target, consent=None)
    result = await brain.run(
        max_iterations=args.max_iterations,
        budget=args.budget,
        depth_ceiling=args.depth_ceiling,
    )

    print(f"\n[+] Brain loop complete:")
    print(f"    Findings: {len(result.findings)}")
    print(f"    Chains: {len(result.chains)}")
    print(f"    Mutations: {len(result.mutations)}")
    print(f"    Iterations: {result.iterations}")
    print(f"    Duration: {result.duration:.1f}s")

    if result.module_stats:
        print(f"    Module stats:")
        for mod, stats in sorted(result.module_stats.items(), key=lambda x: x[1].get("success_rate", 0), reverse=True)[:5]:
            print(f"      {mod}: {stats['successes']}/{stats['attempts']} ({stats['success_rate']:.0%})")

    return 0


async def _handle_fleet(args):
    """Handle fleet command."""
    if args.fleet_command == "scan-all":
        from titan.fleet import FleetCoordinator
        try:
            from fleet.registry import Registry
        except ImportError:
            from titan.fleet.registry import Registry

        registry = Registry.load()
        if not registry.sites:
            print("[!] No sites registered. Use: titan fleet link <repo> <url>")
            return 1

        targets = [s.url for s in registry.sites if s.auto_scan]
        print(f"[+] Fleet scan-all: {len(targets)} registered site(s)")

        coordinator = FleetCoordinator(max_concurrent=5)
        result = await coordinator.scan_all(
            targets=targets,
            agent_types=["recon", "identity", "learning"],
            budget=300.0,
        )

        print(f"\n[+] Fleet scan complete:")
        print(f"    Targets: {len(targets)}")
        print(f"    Findings: {result.stats['findings']['total']}")
        print(f"    Corroborated: {result.stats['findings']['corroborated']}")
        print(f"    Duration: {result.elapsed:.1f}s")

    elif args.fleet_command == "list":
        try:
            from fleet.registry import Registry
        except ImportError:
            from titan.fleet.registry import Registry
        registry = Registry.load()
        if not registry.sites:
            print("[i] No sites registered")
        else:
            print(f"[+] {len(registry.sites)} registered site(s):")
            for site in registry.sites:
                auto = "auto" if site.auto_scan else "manual"
                print(f"    {site.repo:30s} {site.url:40s} [{auto}]")

    elif args.fleet_command == "link":
        try:
            from fleet.registry import Registry
        except ImportError:
            from titan.fleet.registry import Registry
        registry = Registry.load()
        site = registry.link(args.repo, args.url)
        registry.save()
        print(f"[+] Registered: {site.repo} -> {site.url}")

    else:
        print("[!] Usage: titan fleet {scan-all|list|link <repo> <url>}")
    return 0


async def _handle_consent(args):
    """Handle consent command."""
    if args.consent_command == "add":
        from titan.exploit.consent import add_consent
        flags = []
        if args.write: flags.append("write")
        if args.shells: flags.append("shells")
        if args.persistence: flags.append("persistence")
        if not flags: flags = ["read"]

        add_consent(args.target, basis=args.basis, flags=flags)
        print(f"[+] Consent added: {args.target}")
        print(f"    Basis: {args.basis}")
        print(f"    Flags: {', '.join(flags)}")

    elif args.consent_command == "list":
        from titan.exploit.consent import list_consents
        consents = list_consents()
        if not consents:
            print("[i] No consents registered")
        else:
            print(f"[+] {len(consents)} consent(s):")
            for c in consents:
                print(f"    {c}")

    elif args.consent_command == "revoke":
        from titan.exploit.consent import revoke_consent
        revoke_consent(args.target)
        print(f"[+] Consent revoked: {args.target}")

    else:
        print("[!] Usage: titan consent {add|list|revoke}")
    return 0


async def _handle_transport(args):
    """Handle transport command."""
    from titan.transport import TransportRegistry

    if args.transport_command == "list":
        registry = TransportRegistry()
        await registry.auto_register()
        print("[+] Available transports:")
        for name in registry.available:
            t = registry.get(name)
            protocols = [p.value for p in t.PROTOCOLS] if hasattr(t, "PROTOCOLS") else []
            print(f"    {name:12s} {', '.join(protocols)}")

    elif args.transport_command == "check":
        registry = TransportRegistry()
        await registry.auto_register()
        transport = registry.get(args.name)
        if not transport:
            print(f"[!] Transport '{args.name}' not available")
            return 1

        print(f"[+] Checking {args.name} -> {args.target}")
        from titan.transport.base import TargetDescriptor
        target = TargetDescriptor(url=args.target)
        await transport.connect(target)
        print(f"    Identity: {transport.identity}")

    else:
        print("[!] Usage: titan transport {list|check <name> <target>}")
    return 0


async def _handle_report(args):
    """Handle report command."""
    if args.dashboard:
        import subprocess
        cmd = [sys.executable, "run.py", "dashboard", args.target or ""]
        subprocess.run(cmd, cwd=".")
        return 0

    if args.estate:
        from pathlib import Path
        import json

        output_dir = Path("findings")
        sites = []
        for site_dir in output_dir.iterdir():
            if site_dir.is_dir() and (site_dir / "findings.json").exists():
                sites.append(site_dir.name)

        if not sites:
            print("[i] No site reports found in findings/")
            return 0

        print(f"[+] Estate report: {len(sites)} site(s)")
        total_findings = 0
        for site in sorted(sites):
            report_path = output_dir / site / "findings.json"
            try:
                data = json.loads(report_path.read_text(encoding="utf-8"))
                count = len(data.get("findings", []))
                total_findings += count
                print(f"    {site:30s} {count:4d} findings")
            except Exception:
                print(f"    {site:30s}    error reading report")

        print(f"\n    Total: {total_findings} findings across {len(sites)} sites")

    elif args.target:
        print(f"[+] Report for: {args.target}")
        print(f"    Format: {args.format}")
        # Delegate to existing report writer
        from titan.reporting import SiteReportWriter
        writer = SiteReportWriter("findings")
        print(f"    Report directory: findings/")

    else:
        print("[!] Specify --estate or --target <site-slug>")
    return 0


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None):
    """Unified CLI entry point."""
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    handlers = {
        "scan": _handle_scan,
        "brain": _handle_brain,
        "fleet": _handle_fleet,
        "consent": _handle_consent,
        "transport": _handle_transport,
        "report": _handle_report,
    }

    handler = handlers.get(args.command)
    if handler:
        return asyncio.run(handler(args))
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
