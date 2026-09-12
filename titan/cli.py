"""CLI Integration — run Titan from command line.

Usage:
    tscan scan --target https://example.com
    tscan scan --target https://example.com --deep
    tscan report --scan-id scan_123
    tscan list
"""

from __future__ import annotations

import os
import sys

from titan.core.logger import get_logger, install_crash_hook

# ── CWD SHADOW FIX ──────────────────────────────────────────────────────
# When tscan runs from a directory that contains a `titan/` folder (e.g.
# titan-lab), Python resolves ``import titan`` to the CWD copy instead of
# the pip-installed package.  Detect this and repoint sys.path so the
# installed package wins.
_this_file = os.path.normcase(os.path.abspath(__file__))
# site-packages/titan/cli.py → site-packages
_site_pkgs = os.path.dirname(os.path.dirname(_this_file))
if os.path.normcase(_site_pkgs) not in [os.path.normcase(p) for p in sys.path[:10]]:
    sys.path.insert(0, _site_pkgs)

# If titan is already loaded from the WRONG location, purge it so it
# reimports from the correct site-packages.
if "titan" in sys.modules:
    _loaded = os.path.normcase(os.path.abspath(getattr(sys.modules["titan"], "__file__", "") or ""))
    if _site_pkgs.lower() not in _loaded.lower():
        _to_rm = [k for k in sys.modules if k == "titan" or k.startswith("titan.")]
        for _k in _to_rm:
            del sys.modules[_k]
# ── END SHADOW FIX ──────────────────────────────────────────────────────

import argparse
import asyncio
import json
import time
from pathlib import Path

logger = get_logger("cli")


def _http_url(value: str) -> str:
    """Argparse type check: require an http(s) URL with a hostname."""
    from urllib.parse import urlparse

    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise argparse.ArgumentTypeError(f"target must be an http(s) URL, got {value!r}")
    return value


def create_parser() -> argparse.ArgumentParser:
    """Create CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="tscan",
        description="Titan — Autonomous Penetration Testing Platform",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run a security scan")
    scan_parser.add_argument("--target", "-t", required=True, type=_http_url, help="Target URL (http/https)")
    scan_parser.add_argument("--deep", "-d", action="store_true", help="Enable deep mode (full crawl + fuzzing)")
    scan_parser.add_argument("--hostile", action="store_true", help="Enable hostile mode (deep + ad/supply-chain)")
    scan_parser.add_argument("--config", "-c", help="Path to config.yaml (overrides defaults)")
    scan_parser.add_argument("--output", "-o", help="Output findings to JSON file")
    scan_parser.add_argument("--html", help="Output HTML report to file")
    scan_parser.add_argument("--markdown", help="Output Markdown report to file")
    scan_parser.add_argument("--scan-id", help="Resume previous scan")
    scan_parser.add_argument("--no-governance", action="store_true", help="Skip governance approval check")

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate report from scan")
    report_parser.add_argument("--scan-id", "-s", required=True, help="Scan ID")
    report_parser.add_argument(
        "--format", "-f", choices=["json", "html", "markdown", "csv"], default="json", help="Report format"
    )
    report_parser.add_argument("--output", "-o", help="Output file")

    # List command
    subparsers.add_parser("list", help="List all saved scans")

    # Status command
    status_parser = subparsers.add_parser("status", help="Show scan status")
    status_parser.add_argument("--scan-id", "-s", required=True, help="Scan ID")

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete a scan")
    delete_parser.add_argument("--scan-id", "-s", required=True, help="Scan ID")

    return parser


def _build_config(args: argparse.Namespace) -> dict:
    """Build a scan config from CLI arguments."""
    config = {
        "target": args.target,
        "aggression": "active",
        "headless": True,
        "output_dir": "findings",
        "governance": {
            "enabled": not getattr(args, "no_governance", False),
        },
        "crawl": {
            "profile": "fast",
            "max_pages": 5,
            "max_depth": 1,
            "timeout": 600,
            "module_concurrency": 8,
            "interaction_timeout": 90,
            "spa": {
                "enabled": True,
                "hydrate_budget": 10,
                "max_routes": 6,
                "per_route_budget": 30,
                "network_idle": 2500,
            },
            "supplychain": {"enabled": False},
            "fuzz": {"enabled": False, "budget": 50},
        },
        "stealth": {"adaptive": True, "jitter": 0.3, "min_delay": 0.15, "max_delay": 0.6},
        "brain": {
            "enabled": True,
            "budget": 60,
            "variants_per_finding": 3,
            "evolution": {"enabled": True, "persist": True},
        },
        "deep_audit": {"enabled": False},
    }

    config_path = getattr(args, "config", None)
    if config_path and os.path.exists(config_path):
        import yaml

        with open(config_path, encoding="utf-8") as f:
            file_config = yaml.safe_load(f) or {}
        config.update(file_config)
        config["target"] = args.target

    if getattr(args, "hostile", False):
        config["crawl"]["profile"] = "hostile"
        config["crawl"]["max_pages"] = 40
        config["crawl"]["max_depth"] = 4
        config["crawl"]["fuzz"]["enabled"] = True
        config["crawl"]["fuzz"]["budget"] = 120
        config["crawl"]["supplychain"]["enabled"] = True
        config["deep_audit"]["enabled"] = True
    elif getattr(args, "deep", False):
        config["crawl"]["profile"] = "deep"
        config["crawl"]["max_pages"] = 20
        config["crawl"]["max_depth"] = 2
        config["crawl"]["fuzz"]["enabled"] = True
        config["crawl"]["fuzz"]["budget"] = 80
        config["deep_audit"]["enabled"] = True

    if getattr(args, "no_governance", False):
        config["governance"]["enabled"] = False

    return config


async def run_scan(args: argparse.Namespace) -> None:
    """Run a security scan using the real TitanEngine."""
    from titan.core.engine import TitanEngine

    target = args.target
    scan_id = args.scan_id or f"scan_{int(time.time())}"

    print(f"[*] Titan — Starting scan of {target}")
    mode = "hostile" if getattr(args, "hostile", False) else ("deep" if getattr(args, "deep", False) else "fast")
    print(f"[*] Mode: {mode}")
    print(f"[*] Scan ID: {scan_id}")
    print()

    config = _build_config(args)
    engine = TitanEngine(config)

    t0 = time.time()
    try:
        result = await engine.scan(target)
    except Exception as e:
        print(f"[-] Scan crashed: {e}")
        import traceback

        traceback.print_exc()
        return
    duration = time.time() - t0

    print()
    print("=" * 70)
    print(f"  SCAN COMPLETE: {target}")
    print("=" * 70)
    print(f"  Scan ID:       {scan_id}")
    print(f"  Mode:          {mode}")
    print(f"  Duration:      {duration:.1f}s")
    print(f"  Findings:      {len(result.findings)}")
    print(f"  Critical:      {result.critical_count}")
    print(f"  High:          {result.high_count}")
    print(f"  Verified:      {result.verified_count}")
    print(f"  Chains:        {result.chain_count}")
    print(f"  Errors:        {len(result.errors)}")
    print("=" * 70)

    if result.findings:
        print()
        print("[+] FINDINGS:")
        print()
        for i, f in enumerate(result.findings, 1):
            sev = f.severity.value.upper() if hasattr(f.severity, "value") else str(f.severity).upper()
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}.get(sev, "⚪")
            verified = "✓ VERIFIED" if f.verified else "unverified"
            print(f"  {icon} [{sev}] {f.attack_type.value} ({verified})")
            print(f"     URL:    {f.method} {f.url}")
            if f.param:
                print(f"     Param:  {f.param} ({f.location})")
            print(f"     Payload: {f.payload[:120]}")
            if f.confidence:
                print(f"     Confidence: {f.confidence:.2f}")
            if f.chain:
                print(f"     Chain:  {f.chain}")
            print()

    if result.chains:
        print("[+] ATTACK CHAINS:")
        for chain in result.chains:
            print(f"  Chain: {chain.get('name', 'unnamed')}")
            for step in chain.get("steps", []):
                print(f"    → {step}")
            print()

    if result.errors:
        print("[!] ERRORS:")
        for err in result.errors:
            print(f"  - {err}")
        print()

    output_dir = Path(config.get("output_dir", "findings"))
    output_dir.mkdir(parents=True, exist_ok=True)

    findings_path = output_dir / f"{scan_id}.json"
    findings_data = {
        "target": target,
        "scan_id": scan_id,
        "mode": mode,
        "duration_seconds": duration,
        "findings": [f.to_dict() for f in result.findings],
        "chains": result.chains,
        "errors": result.errors,
        "fingerprint": result.fingerprint,
        "coverage": result.coverage,
        "exploit_sessions": result.exploit_sessions,
    }
    findings_path.write_text(json.dumps(findings_data, indent=2, default=str), encoding="utf-8")
    print(f"[+] Findings saved to {findings_path}")

    if args.output:
        out = Path(args.output)
        out.write_text(json.dumps(findings_data, indent=2, default=str), encoding="utf-8")
        print(f"[+] Output saved to {out}")

    if args.html:
        try:
            from titan.reporting.dashboard import build_dashboard

            site_dir = output_dir / f"tscan-{scan_id}"
            site_dir.mkdir(parents=True, exist_ok=True)
            (site_dir / "findings.json").write_text(json.dumps(findings_data, indent=2, default=str), encoding="utf-8")
            path = build_dashboard(site_dir)
            import shutil

            shutil.copy2(str(path), args.html)
            print(f"[+] HTML report saved to {args.html}")
        except Exception as e:
            print(f"[!] HTML report failed: {e}")

    if args.markdown:
        try:
            lines = [f"# Titan Scan Report: {target}\n"]
            lines.append(f"**Scan ID:** {scan_id}")
            lines.append(f"**Mode:** {mode}")
            lines.append(f"**Duration:** {duration:.1f}s")
            lines.append(f"**Findings:** {len(result.findings)}")
            lines.append(f"**Critical:** {result.critical_count} | **High:** {result.high_count}")
            lines.append("")
            lines.append("## Findings\n")
            for i, f in enumerate(result.findings, 1):
                sev = f.severity.value.upper() if hasattr(f.severity, "value") else str(f.severity).upper()
                verified = "✓" if f.verified else "✗"
                lines.append(f"### {i}. [{sev}] {f.attack_type.value} {verified}\n")
                lines.append(f"- **URL:** `{f.method} {f.url}`")
                if f.param:
                    lines.append(f"- **Param:** `{f.param}` ({f.location})")
                lines.append(f"- **Payload:** `{f.payload[:200]}`")
                lines.append(f"- **Confidence:** {f.confidence:.2f}")
                if f.chain:
                    lines.append(f"- **Chain:** {f.chain}")
                lines.append("")
            Path(args.markdown).write_text("\n".join(lines), encoding="utf-8")
            print(f"[+] Markdown report saved to {args.markdown}")
        except Exception as e:
            print(f"[!] Markdown report failed: {e}")

    print()
    print(f"[+] Done. {len(result.findings)} findings documented.")


def run_report(args: argparse.Namespace) -> None:
    """Generate report from scan."""
    output_dir = Path("findings")
    scan_file = output_dir / f"{args.scan_id}.json"
    if not scan_file.exists():
        print(f"[-] Scan {args.scan_id} not found at {scan_file}")
        return
    with open(scan_file, encoding="utf-8") as f:
        data = json.load(f)
    target = data.get("target", "unknown")
    if args.format == "html":
        try:
            from titan.reporting.dashboard import build_dashboard

            site_dir = output_dir / args.scan_id
            site_dir.mkdir(parents=True, exist_ok=True)
            (site_dir / "findings.json").write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
            path = build_dashboard(site_dir)
            if args.output:
                import shutil

                shutil.copy2(str(path), args.output)
                print(f"[+] HTML report saved to {args.output}")
            else:
                print(f"[+] HTML report: {path}")
        except Exception as e:
            print(f"[-] HTML report failed: {e}")
    elif args.format == "markdown":
        lines = [f"# Titan Scan Report: {target}\n"]
        lines.append(f"**Scan ID:** {args.scan_id}")
        lines.append(f"**Findings:** {len(data.get('findings', []))}\n")
        lines.append("## Findings\n")
        for i, f in enumerate(data.get("findings", []), 1):
            sev = f.get("severity", "info").upper()
            lines.append(f"### {i}. [{sev}] {f.get('attack_type', 'unknown')}\n")
            lines.append(f"- **URL:** `{f.get('method', 'GET')} {f.get('url', '')}`")
            lines.append(f"- **Payload:** `{f.get('payload', '')[:200]}`\n")
        content = "\n".join(lines)
        if args.output:
            Path(args.output).write_text(content, encoding="utf-8")
            print(f"[+] Markdown report saved to {args.output}")
        else:
            print(content)
    else:
        content = json.dumps(data, indent=2, default=str)
        if args.output:
            Path(args.output).write_text(content, encoding="utf-8")
            print(f"[+] JSON report saved to {args.output}")
        else:
            print(content)


def run_list(args: argparse.Namespace) -> None:
    """List all saved scans."""
    output_dir = Path("findings")
    if not output_dir.exists():
        print("[*] No saved scans found")
        return
    scans = []
    for f in sorted(output_dir.glob("scan_*.json")):
        try:
            with open(f, encoding="utf-8") as fh:
                data = json.load(fh)
            scans.append(data)
        except Exception as exc:
            logger.debug(f"variant failed, continuing: {exc}")
            continue
    if not scans:
        print("[*] No saved scans found")
        return
    print(f"[*] Found {len(scans)} saved scans:\n")
    for data in scans:
        print(f"  {data.get('scan_id', 'unknown')}")
        print(f"    Target:   {data.get('target', 'unknown')}")
        print(f"    Mode:     {data.get('mode', 'unknown')}")
        print(f"    Findings: {len(data.get('findings', []))}")
        print(f"    Duration: {data.get('duration_seconds', 0):.1f}s")
        print()


def run_status(args: argparse.Namespace) -> None:
    """Show scan status."""
    output_dir = Path("findings")
    scan_file = output_dir / f"{args.scan_id}.json"
    if not scan_file.exists():
        print(f"[-] Scan {args.scan_id} not found")
        return
    with open(scan_file, encoding="utf-8") as f:
        data = json.load(f)
    findings = data.get("findings", [])
    crit = sum(1 for f in findings if f.get("severity", "").upper() == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity", "").upper() == "HIGH")
    verified = sum(1 for f in findings if f.get("verified"))
    print(f"[*] Scan: {args.scan_id}")
    print(f"  Target:    {data.get('target', 'unknown')}")
    print(f"  Mode:      {data.get('mode', 'unknown')}")
    print(f"  Duration:  {data.get('duration_seconds', 0):.1f}s")
    print(f"  Findings:  {len(findings)}")
    print(f"  Critical:  {crit}")
    print(f"  High:      {high}")
    print(f"  Verified:  {verified}")
    print(f"  Chains:    {len(data.get('chains', []))}")
    print(f"  Errors:    {len(data.get('errors', []))}")


def run_delete(args: argparse.Namespace) -> None:
    """Delete a scan."""
    output_dir = Path("findings")
    scan_file = output_dir / f"{args.scan_id}.json"
    if scan_file.exists():
        scan_file.unlink()
        print(f"[+] Deleted scan {args.scan_id}")
    else:
        print(f"[-] Scan {args.scan_id} not found")


def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()
    if args.command == "scan":
        asyncio.run(run_scan(args))
    elif args.command == "report":
        run_report(args)
    elif args.command == "list":
        run_list(args)
    elif args.command == "status":
        run_status(args)
    elif args.command == "delete":
        run_delete(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    install_crash_hook()
    main()
