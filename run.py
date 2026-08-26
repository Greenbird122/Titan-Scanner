"""Titan Scanner — quick launcher.

Usage:
    python run.py                          # scan config.yaml's target
    python run.py --target <url>           # scan a specific site
    python run.py --target <url> --config <path>
    python run.py --target <url> --exploit # also auto-stage verified findings
                                           # (Track E; REQUIRES signed consent
                                           # for the target — see README)
    python run.py --exploit --exploit-listener-start   # scan runs its own C2
                                           # listener (binds config host:port)
    python run.py --consent-dir <path>     # where consent/<host>.json lives
    python run.py --doctor                 # dependency pre-flight (M4)
    python run.py dashboard <slug-or-url>  # render interactive HTML dashboard
                                           # (S5; default: latest scanned site)
    python run.py --report --estate        # estate-wide rollup report (Phase 8b)
    python run.py --report --remediation   # remediation patches report (Phase 8c)
    titan <same flags>                     # installed console command (M4)

Every scan is documented under findings/<site-slug>/ (report.md, findings.json,
scan_meta.json, dashboard.html) plus the sites.json index.
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from titan.core.engine import TitanEngine


def load_config(path: str = "config.yaml") -> dict:
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _arg_value(flag: str, default: str) -> str:
    if flag in sys.argv:
        idx = sys.argv.index(flag)
        if idx + 1 < len(sys.argv):
            return sys.argv[idx + 1]
    return default


def _has_flag(flag: str) -> bool:
    return flag in sys.argv


def apply_cli_overrides(config: dict) -> dict:
    """Layer Track E CLI flags onto the loaded config (mutates and returns it).

    ``--exploit`` enables auto-staging of verified findings; the consent gate
    stays code-enforced inside the planners, so enabling it without a signed
    consent file for the target stages nothing and records a note.
    ``--exploit-listener-start`` makes the scan run + tear down its own C2
    listener instead of expecting the operator's ``listener`` process.
    ``--consent-dir <path>`` overrides where consent/<host>.json is read.
    """
    if _has_flag("--exploit") or _has_flag("--exploit-listener-start"):
        exploit = config.setdefault("exploit", {})
        exploit["enabled"] = True
        if _has_flag("--exploit-listener-start"):
            exploit.setdefault("listener", {})["start"] = True
    if _has_flag("--consent-dir"):
        config.setdefault("exploit", {})["consent_dir"] = _arg_value("--consent-dir", "consent")
    return config


def doctor() -> int:
    """Dependency pre-flight (M4): verify every runtime dependency imports and
    the Playwright Chromium binary exists, then print an actionable report.

    This is the first command a fresh clone should run — the observed failure
    mode was a bare ``python`` resolving to a broken system interpreter that
    lacked ``cryptography`` while the project's own venv sat unused.
    """
    import importlib

    required = [
        "yaml", "playwright", "aiohttp", "flask", "jwt", "cryptography",
        "requests", "pytest",
    ]
    print("[+] Titan dependency pre-flight")
    bad = 0
    for mod in required:
        try:
            importlib.import_module(mod)
            print(f"    [ok] {mod:<22} loaded")
        except Exception as exc:
            bad += 1
            first = str(exc).splitlines()[0][:70]
            print(f"    [!!] {mod:<22} MISSING ({first})")
            print(f"         fix: python -m pip install {mod}")

    # Playwright browser binary (installed separately from the pip package).
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            exe = Path(p.chromium.executable_path)
        if exe.exists():
            print(f"    [ok] playwright-chromium   {exe.name} present")
        else:
            bad += 1
            print("    [!!] playwright-chromium   browser binary not installed")
            print("         fix: python -m playwright install chromium")
    except Exception as exc:
        bad += 1
        first = str(exc).splitlines()[0][:70]
        print(f"    [!!] playwright-chromium   MISSING ({first})")
        print("         fix: python -m playwright install chromium")

    if bad:
        print(f"\n[!] {bad} dependency issue(s) — fix with the commands above, then re-run.")
        return 1
    print("\n[+] All dependencies present. Ready to scan (python run.py --target <url>).")
    return 0


def cmd_dashboard(argv: list) -> int:
    """Render the interactive HTML dashboard for a scanned site (S5).

    ``python run.py dashboard <slug>`` renders findings/<slug>/dashboard.html
    from the persisted findings.json + scan_meta.json. ``dashboard <url>``
    resolves the URL to its slug first. No slug defaults to the most recently
    scanned site in the sites.json index.
    """
    from titan.reporting.dashboard import build_dashboard
    from titan.reporting import site_slug

    out_dir = Path(_arg_value("--output-dir", "findings"))
    slug = None
    if argv:
        candidate = argv[0]
        # A target URL (has a scheme) resolves to its slug; a bare token is
        # used as the slug directly (localhost-5000, repo-co-ke).
        if "://" in candidate:
            slug = site_slug(candidate)
        else:
            slug = candidate
    if slug is None:
        # Latest scanned site from the index.
        index_path = out_dir / "sites.json"
        if index_path.exists():
            try:
                import json
                index = json.loads(index_path.read_text(encoding="utf-8"))
                sites = index.get("sites") or []
                if sites:
                    slug = sites[-1].get("slug")
            except Exception:
                pass
    if not slug:
        print("[!] No site to render. Scan a target first or pass a slug: "
              "python run.py dashboard <slug>")
        return 1
    site_dir = out_dir / slug
    if not (site_dir / "findings.json").exists():
        print(f"[!] No findings for slug {slug} under {out_dir}/")
        return 1
    try:
        path = build_dashboard(site_dir)
    except Exception as exc:
        print(f"[!] dashboard render failed: {exc}")
        return 1
    print(f"[+] Dashboard written to {path}")
    return 0


def cmd_estate_rollup() -> int:
    """Generate the estate-wide rollup report (Phase 8b).

    python run.py --report --estate
    """
    from titan.reporting import estate_rollup
    out_dir = Path(_arg_value("--output-dir", "findings"))
    report = estate_rollup(str(out_dir))
    out_path = out_dir / "ESTATE-ROLLUP.md"
    out_path.write_text(report, encoding="utf-8")
    print(f"[+] Estate rollup written to {out_path}")
    return 0


def cmd_remediation() -> int:
    """Generate the remediation-focused report (Phase 8c).

    python run.py --report --remediation
    """
    from titan.reporting import remediation_rollup
    out_dir = Path(_arg_value("--output-dir", "findings"))
    report = remediation_rollup(str(out_dir))
    out_path = out_dir / "REMEDIATION-ROLLUP.md"
    out_path.write_text(report, encoding="utf-8")
    print(f"[+] Remediation rollup written to {out_path}")
    return 0


def entrypoint() -> None:
    """Console-script entry point (``titan`` command, M4)."""
    if _has_flag("--doctor") or _has_flag("doctor"):
        sys.exit(doctor())
    argv = sys.argv[1:]
    if argv and argv[0] == "dashboard":
        sys.exit(cmd_dashboard(argv[1:]))
    if _has_flag("--report") and _has_flag("--estate"):
        sys.exit(cmd_estate_rollup())
    if _has_flag("--report") and _has_flag("--remediation"):
        sys.exit(cmd_remediation())
    asyncio.run(main())


async def main():
    config_path = _arg_value("--config", "config.yaml")
    config = load_config(config_path)
    target = _arg_value("--target", config.get("target", ""))
    if not target:
        print("[!] No target. Set 'target' in config.yaml or pass --target <url>")
        sys.exit(1)

    config = apply_cli_overrides(config)
    if config.get("exploit", {}).get("enabled"):
        print("[+] Track E enabled: verified findings will be auto-staged "
              "(requires a signed consent file for the target — see README)")

    engine = TitanEngine(config)
    result = await engine.scan(target)

    print(f"\n[+] Scan complete: {len(result.findings)} findings ({result.verified_count} verified)")
    print(f"    Critical: {result.critical_count}, High: {result.high_count}, Chains: {result.chain_count}")
    print(f"    Duration: {result.duration_seconds}s")

    for f in result.findings:
        print(f"  [{f.severity.value.upper()}] {f.attack_type.value} conf={f.confidence:.2f} "
              f"verified={'Y' if f.verified else 'N'}")
        print(f"    {f.method} {f.url}  param={f.param} ({f.location})")
        print(f"    payload: {f.payload[:100]}")
        print()

    if result.exploit_sessions:
        print(f"[+] Track E: {len(result.exploit_sessions)} exploitation session(s) staged")
        for s in result.exploit_sessions:
            print(f"    [{s.get('channel')}] {s.get('session_id')}  {s.get('dir', '')}")
            if s.get("webshell_url"):
                print(f"      webshell: {s['webshell_url']}")
            if s.get("dump"):
                d = s["dump"]
                print(f"      dump: {d.get('technique')} on {d.get('table')} ({d.get('rows')} rows)")

    if result.errors:
        print(f"\n[!] Errors: {len(result.errors)}")
        for err in result.errors:
            print(f"    - {err}")

    from titan.reporting import site_slug
    print(f"[+] Findings documented under findings/{site_slug(target)}/")


if __name__ == "__main__":
    entrypoint()
