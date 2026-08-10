"""Regression tests for checkpoint detection.

Covers the false-positive fix: training/CTF sites serve "challenge" etc. on a
200 and must NOT be aborted, while real WAF walls (403/202/401) still are.
"""

import pytest

from titan.core.engine import TitanEngine


@pytest.fixture
def engine():
    return TitanEngine({})


class TestCheckpointDetection:
    def test_200_page_with_challenge_word_is_not_a_wall(self, engine):
        """CTF/training sites mention 'challenge' on a 200 — not a wall."""
        cases = [
            ("Hack This Site", "hackthissite mission challenge basic"),
            ("Home - CTFlearn - CTF Challenges", "ctf practice challenge problems"),
            ("Web Application Exploits and Defenses", "google gruyere challenge codelab"),
            ("REPAIR-AI | Maternal Health", "maternal reproductive health platform"),
            ("KIBABII UNIVERSITY", "student portal login"),
        ]
        for title, body in cases:
            assert engine._is_checkpoint(title, body, {}, 200) is False, title

    def test_cloudflare_wall_detected(self, engine):
        """403 + CF interstitial must abort."""
        assert engine._is_checkpoint(
            "Just a moment...",
            "<html>challenge checking your browser</html>",
            {"server": "cloudflare"},
            403,
        ) is True

    def test_202_antibot_wall_detected(self, engine):
        """Anti-bot 'accepted for processing' (202) wall must abort."""
        assert engine._is_checkpoint(
            "", "<html>security challenge</html>", {}, 202
        ) is True

    def test_403_access_denied_detected(self, engine):
        """403 + generic wall words (status-gated) must abort."""
        assert engine._is_checkpoint(
            "Access denied",
            "<html>cloudflare ray id: 123 security check</html>",
            {"server": "cloudflare"},
            403,
        ) is True

    def test_strong_fingerprint_wins_regardless_of_status(self, engine):
        """'just a moment' is a wall even if served as 200 (CF quirk)."""
        assert engine._is_checkpoint(
            "Just a moment...", "<html>challenge</html>", {}, 200
        ) is True

    def test_200_blocked_word_is_not_a_wall(self, engine):
        """A 200 page containing the word 'blocked' is not a wall."""
        assert engine._is_checkpoint(
            "Some Article", "this content is not blocked, please read on", {}, 200
        ) is False

    def test_200_ddos_protection_marketing_is_not_a_wall(self, engine):
        """Hosting vendors say 'DDoS protection' on legit 200 pages."""
        assert engine._is_checkpoint(
            "Acme Hosting", "we offer DDoS protection on all plans", {}, 200
        ) is False

    def test_blocking_status_with_cloudflare_server_is_a_wall(self, engine):
        """Empty-body CF 403 (server header) is a wall even with no body text."""
        assert engine._is_checkpoint(
            "", "", {"server": "cloudflare"}, 403
        ) is True
