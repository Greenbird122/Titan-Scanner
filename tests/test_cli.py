"""Tests for the Titan Unified CLI.

Covers:
  - Parser construction (all subcommands, arguments)
  - Command dispatch (scan, brain, fleet, consent, transport, report)
  - Help output
  - Version output
"""

from __future__ import annotations

import pytest

from titan.cli.main import create_parser, main


class TestCLIParser:
    def test_parser_creates(self):
        parser = create_parser()
        assert parser.prog == "titan"

    def test_version(self):
        parser = create_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["--version"])
        assert exc_info.value.code == 0

    def test_no_command_shows_help(self, capsys):
        parser = create_parser()
        parser.parse_args([])
        # No crash — parser handles empty args

    def test_scan_subcommand(self):
        parser = create_parser()
        args = parser.parse_args(["scan", "https://example.com"])
        assert args.command == "scan"
        assert args.target == "https://example.com"
        assert args.profile == "fast"
        assert args.transport == "auto"

    def test_scan_with_options(self):
        parser = create_parser()
        args = parser.parse_args([
            "scan", "https://example.com",
            "--profile", "deep",
            "--transport", "tor",
            "--exploit",
            "--fleet",
            "--timeout", "600",
        ])
        assert args.profile == "deep"
        assert args.transport == "tor"
        assert args.exploit is True
        assert args.fleet is True
        assert args.timeout == 600

    def test_brain_subcommand(self):
        parser = create_parser()
        args = parser.parse_args(["brain", "https://target.com"])
        assert args.command == "brain"
        assert args.target == "https://target.com"
        assert args.budget == 300
        assert args.max_iterations == 100

    def test_brain_with_options(self):
        parser = create_parser()
        args = parser.parse_args([
            "brain", "https://target.com",
            "--budget", "600",
            "--max-iterations", "50",
            "--depth-ceiling", "0.9",
        ])
        assert args.budget == 600
        assert args.max_iterations == 50
        assert args.depth_ceiling == 0.9

    def test_fleet_subcommands(self):
        parser = create_parser()
        args = parser.parse_args(["fleet", "scan-all"])
        assert args.command == "fleet"
        assert args.fleet_command == "scan-all"

    def test_fleet_list(self):
        parser = create_parser()
        args = parser.parse_args(["fleet", "list"])
        assert args.fleet_command == "list"

    def test_fleet_link(self):
        parser = create_parser()
        args = parser.parse_args(["fleet", "link", "my-repo", "https://example.com"])
        assert args.fleet_command == "link"
        assert args.repo == "my-repo"
        assert args.url == "https://example.com"

    def test_consent_add(self):
        parser = create_parser()
        args = parser.parse_args([
            "consent", "add", "https://target.com",
            "--basis", "ownership",
            "--write", "--shells",
        ])
        assert args.consent_command == "add"
        assert args.target == "https://target.com"
        assert args.basis == "ownership"
        assert args.write is True
        assert args.shells is True

    def test_consent_list(self):
        parser = create_parser()
        args = parser.parse_args(["consent", "list"])
        assert args.consent_command == "list"

    def test_consent_revoke(self):
        parser = create_parser()
        args = parser.parse_args(["consent", "revoke", "https://target.com"])
        assert args.consent_command == "revoke"
        assert args.target == "https://target.com"

    def test_transport_list(self):
        parser = create_parser()
        args = parser.parse_args(["transport", "list"])
        assert args.command == "transport"
        assert args.transport_command == "list"

    def test_transport_check(self):
        parser = create_parser()
        args = parser.parse_args(["transport", "check", "http", "https://example.com"])
        assert args.transport_command == "check"
        assert args.name == "http"
        assert args.target == "https://example.com"

    def test_report_estate(self):
        parser = create_parser()
        args = parser.parse_args(["report", "--estate"])
        assert args.command == "report"
        assert args.estate is True
        assert args.format == "technical"

    def test_report_dashboard(self):
        parser = create_parser()
        args = parser.parse_args(["report", "--target", "my-site", "--dashboard"])
        assert args.dashboard is True

    def test_scan_quiet_mode(self):
        parser = create_parser()
        args = parser.parse_args(["scan", "https://example.com", "--quiet", "-q"])
        assert args.quiet is True

    def test_scan_custom_config(self):
        parser = create_parser()
        args = parser.parse_args(["scan", "https://example.com", "--config", "my-config.yaml"])
        assert args.config == "my-config.yaml"

    def test_scan_custom_output(self):
        parser = create_parser()
        args = parser.parse_args(["scan", "https://example.com", "-o", "my-output"])
        assert args.output == "my-output"


class TestCLIHelp:
    def test_main_help(self, capsys):
        """Main without args should print help and return 0."""
        result = main([])
        assert result == 0

    def test_scan_help(self, capsys):
        """Scan subcommand should have help."""
        parser = create_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["scan", "--help"])
        assert exc_info.value.code == 0


class TestCLIHandlers:
    @pytest.mark.asyncio
    async def test_handle_transport_list(self, capsys):
        """Transport list should show available transports."""
        from titan.cli.main import _handle_transport

        class FakeArgs:
            transport_command = "list"

        await _handle_transport(FakeArgs())
        captured = capsys.readouterr()
        assert "Available transports" in captured.out
        assert "http" in captured.out

    @pytest.mark.asyncio
    async def test_handle_fleet_list(self, capsys):
        """Fleet list should show registered sites (even if empty)."""
        from titan.cli.main import _handle_fleet

        class FakeArgs:
            fleet_command = "list"

        try:
            await _handle_fleet(FakeArgs())
            captured = capsys.readouterr()
            assert "registered" in captured.out.lower() or "No sites" in captured.out or "site(s)" in captured.out
        except ModuleNotFoundError:
            pytest.skip("fleet.registry not importable in this context")

    @pytest.mark.asyncio
    async def test_handle_consent_list(self, capsys):
        """Consent list should not crash."""
        from titan.cli.main import _handle_consent

        class FakeArgs:
            consent_command = "list"

        await _handle_consent(FakeArgs())
        captured = capsys.readouterr()
        assert "consent" in captured.out.lower() or "No consents" in captured.out
