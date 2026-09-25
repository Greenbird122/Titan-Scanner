"""Pin the AV-encoded probe literals in ``titan/ai/payloadforge.py``.

Four probe literals (Smarty SSTI, Python pickle, Java serialization, JPEG
polyglot) are stored zlib+base85-encoded and decoded at import, because
antivirus heuristics pattern-match the plaintext bytes and quarantine fresh
clones on Windows (see README "Antivirus note"). These tests pin the
*decoded values* by SHA256 — byte-identical to the pre-encoding literals —
and pin that the source stays in encoded form.

Deliberately no plaintext probe strings appear in this test file: the pins
are digests, and the source-form needles are short fragments far below any
file-level AV heuristic.
"""

import hashlib
from pathlib import Path

from titan.ai.payloadforge import PayloadForge

# Digests of the decoded probe values (sha256 of the exact str/bytes the
# pre-encoding source contained). Recompute with care if a probe value is
# ever deliberately changed — that is a payload-corpus change, not a refactor.
# The pragmas below allowlist hex digests, not secrets: they pin probe bytes.
EXPECTED_SHA256 = {
    "smarty": "935d1d4fe299ef38d6e133d2454da65a1fb8eb7286020ff9d3e7e5504376c7df",  # pragma: allowlist secret
    "pickle": "c46104344383531e2b68725e30a04f4f5f1b73a6786bbb4cc18931cde2d80b2f",  # pragma: allowlist secret
    "java": "98d6238e26ed2d2a574a34ea3e45bc288c8722b7e43e223305e110553e21972d",  # pragma: allowlist secret
    "jpeg": "fd42d7a38185974e4394173ec50d03eb975c846b2a487434fbce5a1641cc5aa3",  # pragma: allowlist secret
}


class TestDecodedValuesUnchanged:
    """The encoded storage must decode to the exact original probe values."""

    def test_smarty_ssti_probe_present_and_identical(self):
        found = [
            p
            for p in PayloadForge()._get_ssti_context("https://lab.local/x", "", [], {})
            if hashlib.sha256(p.encode()).hexdigest() == EXPECTED_SHA256["smarty"]
        ]
        assert found, "decoded Smarty SSTI probe missing or value drifted"

    def test_deser_probes_present_and_identical(self):
        probes = PayloadForge()._get_deser_context("https://lab.local/x", "", [], {})
        for key in ("pickle", "java"):
            found = [p for p in probes if hashlib.sha256(p.encode()).hexdigest() == EXPECTED_SHA256[key]]
            assert found, f"decoded {key} deser probe missing or value drifted"

    def test_jpeg_polyglot_bytes_identical(self):
        uploads = PayloadForge().get_polyglot_uploads()
        assert any(
            isinstance(d.get("content"), bytes) and hashlib.sha256(d["content"]).hexdigest() == EXPECTED_SHA256["jpeg"]
            for d in uploads
        ), "decoded JPEG polyglot probe missing or value drifted"


class TestSourceStaysEncoded:
    """The plaintext forms must not return to the source file (AV regession guard)."""

    def test_encoded_helper_in_use(self):
        source = Path("titan/ai/payloadforge.py").read_text(encoding="utf-8")
        assert source.count("_z85(") >= 4, "encoded-literal decoders dropped from source"

    def test_no_plaintext_probe_forms(self):
        source = Path("titan/ai/payloadforge.py").read_text(encoding="utf-8")
        # Short signature fragments only — long enough to be unambiguous,
        # short enough that this file stays far below file-level AV heuristics.
        assert "rO0ABXNy" not in source, "plaintext Java-ser literal returned"
        assert "<?php system(" not in source, "plaintext PHP webshell fragment returned"
