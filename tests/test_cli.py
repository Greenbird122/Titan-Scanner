"""Tests for the Titan CLI (tscan).

Covers the current unified CLI surface:
  - Parser construction (prog, subcommands, required args)
  - scan: --target required, mode flags, output options
  - report: --scan-id required, format choices
  - list / status / delete handlers
  - Help output
"""

from __future__ import annotations

import pytest

from titan.cli import create_parser, main


class TestCLIParser:
    def test_parser_creates(self):
        parser = create_parser()
        assert parser.prog == "tscan"

    def test_no_command_shows_help(self, capsys):
        parser = create_parser()
        parser.parse_args([])
        # No crash — parser handles empty args

    def test_scan_requires_target(self):
        parser = create_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["scan"])
        assert exc_info.value.code == 2

    def test_scan_subcommand(self):
        parser = create_parser()
        args = parser.parse_args(["scan", "--target", "https://example.com"])
        assert args.command == "scan"
        assert args.target == "https://example.com"
        assert args.deep is False
        assert args.hostile is False
        assert args.no_governance is False

    def test_scan_with_options(self):
        parser = create_parser()
        args = parser.parse_args([
            "scan", "--target", "https://example.com",
            "--deep",
            "--config", "config.yaml",
            "--output", "out.json",
            "--html", "report.html",
            "--markdown", "report.md",
            "--scan-id", "scan_abc",
            "--no-governance",
        ])
        assert args.target == "https://example.com"
        assert args.deep is True
        assert args.config == "config.yaml"
        assert args.output == "out.json"
        assert args.html == "report.html"
        assert args.markdown == "report.md"
        assert args.scan_id == "scan_abc"
        assert args.no_governance is True

    def test_scan_hostile_mode(self):
        parser = create_parser()
        args = parser.parse_args(["scan", "--target", "https://example.com", "--hostile"])
        assert args.hostile is True
        assert args.deep is False

    def test_report_requires_scan_id(self):
        parser = create_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["report"])
        assert exc_info.value.code == 2

    def test_report_subcommand(self):
        parser = create_parser()
        args = parser.parse_args(["report", "--scan-id", "scan_abc", "--format", "html", "--output", "r.html"])
        assert args.command == "report"
        assert args.scan_id == "scan_abc"
        assert args.format == "html"
        assert args.output == "r.html"

    def test_report_default_format_is_json(self):
        parser = create_parser()
        args = parser.parse_args(["report", "--scan-id", "scan_abc"])
        assert args.format == "json"

    def test_list_subcommand(self):
        parser = create_parser()
        args = parser.parse_args(["list"])
        assert args.command == "list"

    def test_status_requires_scan_id(self):
        parser = create_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["status"])
        assert exc_info.value.code == 2

    def test_status_subcommand(self):
        parser = create_parser()
        args = parser.parse_args(["status", "--scan-id", "scan_abc"])
        assert args.command == "status"
        assert args.scan_id == "scan_abc"

    def test_delete_requires_scan_id(self):
        parser = create_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["delete"])
        assert exc_info.value.code == 2

    def test_delete_subcommand(self):
        parser = create_parser()
        args = parser.parse_args(["delete", "--scan-id", "scan_abc"])
        assert args.command == "delete"
        assert args.scan_id == "scan_abc"


class TestCLIHelp:
    def test_main_help(self, capsys):
        parser = create_parser()
        parser.print_help()
        captured = capsys.readouterr()
        assert "usage" in captured.out.lower()
        assert "scan" in captured.out
        assert "report" in captured.out

    def test_main_dispatches_scan(self, monkeypatch):
        """main() with a scan argv must dispatch to run_scan (which then
        attempts a real scan — we only assert it gets past dispatch)."""
        import asyncio

        seen = {}

        def fake_run_scan(args):
            seen["args"] = args
            return asyncio.sleep(0)

        import titan.cli
        monkeypatch.setattr(titan.cli, "run_scan", fake_run_scan)
        monkeypatch.setattr("sys.argv", ["tscan", "scan", "--target", "https://example.com"])
        main()
        assert seen["args"].target == "https://example.com"


class TestCLIHandlers:
    def test_run_report_missing_scan(self, capsys):
        """Report for a nonexistent scan must print a clear error, not crash."""
        from titan.cli import run_report
        run_report(_Args(scan_id="scan_does_not_exist_xyz", format="json", output=None))
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower() or "not found" in captured.err.lower()

    def test_run_list_empty(self, capsys, tmp_path, monkeypatch):
        """List with an empty findings dir must say no scans, not crash."""
        from titan.cli import run_list
        monkeypatch.chdir(tmp_path)
        run_list(_Args())
        captured = capsys.readouterr()
        assert "no saved scans" in captured.out.lower()

    def test_run_status_missing_scan(self, capsys):
        from titan.cli import run_status
        run_status(_Args(scan_id="scan_does_not_exist_xyz"))
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower() or "not found" in captured.err.lower()

    def test_run_delete_missing_scan(self, capsys):
        from titan.cli import run_delete
        run_delete(_Args(scan_id="scan_does_not_exist_xyz"))
        captured = capsys.readouterr()
        assert "not found" in captured.out.lower() or "not found" in captured.err.lower()

    def test_run_status_reads_real_scan(self, tmp_path, monkeypatch, capsys):
        """status must read a real scan file from the findings dir."""
        import json

        from titan.cli import run_status
        (tmp_path / "findings").mkdir()
        (tmp_path / "findings" / "scan_real_123.json").write_text(json.dumps({
            "scan_id": "scan_real_123",
            "target": "https://example.com",
            "mode": "fast",
            "duration_seconds": 3.5,
            "findings": [{"severity": "CRITICAL", "verified": True}],
            "chains": [],
            "errors": [],
        }), encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        run_status(_Args(scan_id="scan_real_123"))
        captured = capsys.readouterr()
        assert "scan_real_123" in captured.out
        assert "Critical:  1" in captured.out
        assert "Verified:  1" in captured.out


class _Args:
    """Minimal argparse.Namespace stand-in for handler unit tests."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
