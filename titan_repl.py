"""Titan REPL — post-scan exploration and triage.

Usage:
    python titan_repl.py <scan-dir>
    python titan_repl.py findings/localhost-5000

Loads findings.json + scan_meta.json from the given scan directory and
enters an interactive session for browsing, filtering, and replaying findings.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).parent))

from titan.core.models import Finding, ScanResult


def _load_finding(raw: Dict[str, Any]) -> Finding:
    def _to_enum(cls, val):
        if isinstance(val, str):
            try:
                return cls(val)
            except ValueError:
                return None
        return val

    def _to_severity(val):
        if isinstance(val, str):
            try:
                from titan.core.models import Severity
                return Severity(val)
            except ValueError:
                return Severity.UNCONFIRMED
        return val

    def _to_attack_type(val):
        if isinstance(val, str):
            try:
                from titan.core.models import AttackType
                return AttackType(val)
            except ValueError:
                return None
        return val

    return Finding(
        target=raw.get("target", ""),
        url=raw.get("url", ""),
        method=raw.get("method", ""),
        param=raw.get("param", ""),
        location=raw.get("location", ""),
        payload=raw.get("payload", ""),
        attack_type=_to_attack_type(raw.get("attack_type")),
        severity=_to_severity(raw.get("severity", "unconfirmed")),
        verified=raw.get("verified", False),
        confidence=raw.get("confidence", 0.0),
        status=raw.get("status"),
        headers=raw.get("headers", {}),
        body=raw.get("body", ""),
        diffs=raw.get("diffs", []),
        baseline_body=raw.get("baseline_body", ""),
        baseline_status=raw.get("baseline_status"),
        verification_body=raw.get("verification_body", ""),
        verification_status=raw.get("verification_status"),
        cvss_score=raw.get("cvss_score"),
        cvss_vector=raw.get("cvss_vector", ""),
        poc_curl=raw.get("poc_curl", ""),
        poc_python=raw.get("poc_python", ""),
        screenshot_path=raw.get("screenshot_path"),
        notes=raw.get("notes", ""),
        metadata=raw.get("metadata", {}),
        chain=raw.get("chain", []),
        tags=raw.get("tags", []),
        flows=raw.get("flows", []),
        evidence=raw.get("evidence", ""),
        tier=raw.get("tier", ""),
    )


def _load_scan(dir_path: Path) -> tuple[ScanResult, Dict[str, Any]]:
    findings_path = dir_path / "findings.json"
    meta_path = dir_path / "scan_meta.json"

    if not findings_path.exists():
        raise FileNotFoundError(f"no findings.json in {dir_path}")

    with open(findings_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    raw_findings = data.get("findings", [])
    findings = [_load_finding(r) for r in raw_findings]

    meta = {}
    if meta_path.exists():
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

    result = ScanResult(
        target=meta.get("target", data.get("target", "")),
        started_at=meta.get("started_at", 0),
        finished_at=meta.get("finished_at", 0),
        findings=findings,
        errors=data.get("errors", []),
        fingerprint=data.get("fingerprint", {}),
        config_snapshot=data.get("config_snapshot", {}),
        ai_escalation=data.get("ai_escalation", {}),
        chains=data.get("chains", []),
        exploit_sessions=data.get("exploit_sessions", []),
        hostile=data.get("hostile", {}),
        coverage=data.get("coverage", {}),
    )
    return result, meta


class TitanREPL:
    PROMPT = "titan> "

    def __init__(self, scan_dir: Path):
        self.scan_dir = scan_dir
        self.result, self.meta = _load_scan(scan_dir)
        self.findings = self.result.findings
        self._filtered: List[Finding] = list(self.findings)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _refresh_filtered(self) -> None:
        self._filtered = list(self.findings)

    def _print_finding(self, idx: int, f: Finding) -> None:
        verified = "Y" if f.verified else "N"
        print(
            f"[{idx:03d}] [{f.severity.value.upper():8s}] {f.attack_type.value if f.attack_type else '?':20s} "
            f"conf={f.confidence:.2f} verified={verified} tier={f.tier or '?'}"
        )
        print(f"        {f.method} {f.url}  param={f.param} ({f.location})")
        print(f"        payload: {f.payload[:120]}")
        if f.diffs:
            print(f"        diffs: {', '.join(f.diffs[:5])}")
        if f.chain:
            print(f"        chain: {', '.join(f.chain)}")
        if f.poc_curl:
            print(f"        poc: {f.poc_curl[:120]}")

    def _finding_by_id(self, raw: str) -> Optional[Finding]:
        try:
            idx = int(raw)
        except ValueError:
            return None
        if 0 <= idx < len(self._filtered):
            return self._filtered[idx]
        return None

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def cmd_help(self, _args: List[str]) -> None:
        print("Commands:")
        print("  ls, list               list all findings")
        print("  show <id>              show finding details")
        print("  filter <severity>      filter by severity (critical/high/medium/low/info)")
        print("  filter <type>          filter by attack type (sqli/xss/ssrf/...)")
        print("  reset                  reset filters")
        print("  meta                   show scan metadata")
        print("  repro <id>             show/run repro script for confirmed finding")
        print("  poc <id>               show PoC commands")
        print("  count                  show finding counts")
        print("  quit, exit             exit")

    def cmd_list(self, _args: List[str]) -> None:
        if not self._filtered:
            print("[i] no findings (check filters)")
            return
        for i, f in enumerate(self._filtered):
            self._print_finding(i, f)

    def cmd_show(self, args: List[str]) -> None:
        if not args:
            print("[!] usage: show <id>")
            return
        f = self._finding_by_id(args[0])
        if not f:
            print("[!] invalid finding id")
            return
        print(f"target:    {f.target}")
        print(f"url:       {f.method} {f.url}")
        print(f"param:     {f.param}  location: {f.location}")
        print(f"payload:   {f.payload}")
        print(f"type:      {f.attack_type.value if f.attack_type else '?'}")
        print(f"severity:  {f.severity.value}")
        print(f"verified:  {f.verified}  confidence: {f.confidence:.2f}")
        print(f"tier:      {f.tier or '?'}  evidence: {f.evidence or '?'}")
        print(f"status:    {f.status}")
        if f.diffs:
            print(f"diffs:     {', '.join(f.diffs)}")
        if f.flows:
            print(f"flows:     {', '.join(f.flows)}")
        if f.chain:
            print(f"chain:     {', '.join(f.chain)}")
        if f.poc_curl:
            print(f"poc_curl:  {f.poc_curl}")
        if f.poc_python:
            print(f"poc_python: {f.poc_python}")
        if f.metadata:
            print(f"metadata:  {json.dumps(f.metadata, indent=2)}")
        if f.notes:
            print(f"notes:     {f.notes}")

    def cmd_filter(self, args: List[str]) -> None:
        if not args:
            print("[!] usage: filter <severity|type> <value>")
            return
        key = args[0].lower()
        value = args[1].lower() if len(args) > 1 else ""

        if key in ("severity", "sev"):
            self._filtered = [
                f for f in self.findings
                if f.severity.value.lower() == value
            ]
        elif key in ("type", "attack", "module"):
            self._filtered = [
                f for f in self.findings
                if f.attack_type and f.attack_type.value.lower() == value
            ]
        elif key in ("verified",):
            self._filtered = [
                f for f in self.findings
                if f.verified == (value not in ("false", "0", "no"))
            ]
        elif key in ("tier",):
            self._filtered = [
                f for f in self.findings
                if (f.tier or "").lower() == value
            ]
        else:
            print(f"[!] unknown filter key: {key}")
            return
        print(f"[+] filtered to {len(self._filtered)} findings")

    def cmd_reset(self, _args: List[str]) -> None:
        self._refresh_filtered()
        print(f"[+] reset ({len(self._filtered)} findings)")

    def cmd_meta(self, _args: List[str]) -> None:
        print(f"target:    {self.meta.get('target', '?')}")
        print(f"duration:  {self.meta.get('duration_seconds', '?')}s")
        print(f"findings:  {self.meta.get('findings', '?')}")
        print(f"verified:  {self.meta.get('verified', '?')}")
        print(f"critical:  {self.meta.get('critical', '?')}")
        print(f"high:      {self.meta.get('high', '?')}")
        print(f"chains:    {self.meta.get('chains', '?')}")
        print(f"errors:    {len(self.meta.get('errors', []))}")
        cov = self.meta.get("coverage", {})
        if cov:
            print(f"coverage:  {cov.get('status', '?')} — {cov.get('reason', '')}")
        hostile = self.meta.get("hostile", {})
        if hostile:
            print(f"hostile:   monetization_score={hostile.get('monetization_score')} "
                  f"origins={hostile.get('origins', 0)} "
                  f"findings={hostile.get('hostile_findings', 0)}")

    def cmd_repro(self, args: List[str]) -> None:
        if not args:
            print("[!] usage: repro <id>")
            return
        f = self._finding_by_id(args[0])
        if not f:
            print("[!] invalid finding id")
            return
        repro_path = f.metadata.get("repro")
        if not repro_path:
            print(f"[i] no repro script for finding {args[0]} (tier={f.tier or '?'})")
            return
        full_path = self.scan_dir / repro_path
        if not full_path.exists():
            print(f"[!] repro file missing: {full_path}")
            return
        print(f"[+] repro: {full_path}")
        print("-" * 60)
        print(full_path.read_text(encoding="utf-8"))
        print("-" * 60)
        run = input("run it now? [y/N] ").strip().lower()
        if run == "y":
            try:
                proc = subprocess.run(
                    [sys.executable, str(full_path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                print(f"exit: {proc.returncode}")
                if proc.stdout:
                    print(proc.stdout[:2000])
                if proc.stderr:
                    print(proc.stderr[:500])
            except Exception as e:
                print(f"[!] repro failed: {e}")

    def cmd_poc(self, args: List[str]) -> None:
        if not args:
            print("[!] usage: poc <id>")
            return
        f = self._finding_by_id(args[0])
        if not f:
            print("[!] invalid finding id")
            return
        if f.poc_curl:
            print(f"curl: {f.poc_curl}")
        else:
            print("[i] no PoC stored for this finding")
        if f.poc_python:
            print(f"python: {f.poc_python}")

    def cmd_count(self, _args: List[str]) -> None:
        from collections import Counter
        sev = Counter(f.severity.value for f in self.findings)
        types = Counter(f.attack_type.value for f in self.findings if f.attack_type)
        print("by severity:")
        for k, v in sorted(sev.items(), key=lambda x: -x[1]):
            print(f"  {k:10s}: {v}")
        print("by type:")
        for k, v in sorted(types.items(), key=lambda x: -x[1]):
            print(f"  {k:20s}: {v}")

    # ------------------------------------------------------------------
    # Loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        print(f"[+] Titan REPL — {self.scan_dir}")
        print(f"[+] {len(self.findings)} findings loaded")
        print(f"[+] type 'help' for commands, 'quit' to exit\n")

        while True:
            try:
                line = input(self.PROMPT).strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[+] bye")
                return

            if not line:
                continue
            parts = line.split()
            cmd = parts[0].lower()
            args = parts[1:]

            if cmd in ("quit", "exit", "q"):
                print("[+] bye")
                return
            elif cmd in ("help", "?", "h"):
                self.cmd_help(args)
            elif cmd in ("ls", "list", "l"):
                self.cmd_list(args)
            elif cmd == "show":
                self.cmd_show(args)
            elif cmd == "filter":
                self.cmd_filter(args)
            elif cmd == "reset":
                self.cmd_reset(args)
            elif cmd == "meta":
                self.cmd_meta(args)
            elif cmd == "repro":
                self.cmd_repro(args)
            elif cmd == "poc":
                self.cmd_poc(args)
            elif cmd == "count":
                self.cmd_count(args)
            else:
                print(f"[!] unknown command: {cmd}  (type 'help')")


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python titan_repl.py <scan-dir>")
        return 1

    scan_dir = Path(sys.argv[1])
    if not scan_dir.is_dir():
        print(f"[!] not a directory: {scan_dir}")
        return 1

    try:
        repl = TitanREPL(scan_dir)
    except Exception as e:
        print(f"[!] failed to load scan: {e}")
        return 1

    repl.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
