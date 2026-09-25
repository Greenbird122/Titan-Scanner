"""Documentation the CI can verify.

Keeps the standalone threat model present, structured, and cross-linked: if a
section header disappears or a link is dropped, the suite fails rather than the
doc silently rotting.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DOC = ROOT / "docs" / "THREAT_MODEL.md"

REQUIRED_SECTIONS = (
    "# Threat Model",
    "## Scope",
    "## Assets",
    "## Actors",
    "## Trust boundaries",
    "## Mitigations implemented",
    "## Residual risks",
)


def test_threat_model_exists_with_required_sections():
    assert DOC.exists(), "docs/THREAT_MODEL.md is missing"
    text = DOC.read_text(encoding="utf-8")
    for header in REQUIRED_SECTIONS:
        assert header in text, f"threat model lost its {header!r} section"


def test_threat_model_maps_mitigations_to_code():
    # The model's discipline: every claimed mitigation names real code.
    text = DOC.read_text(encoding="utf-8")
    for anchor in (
        "titan/core/authorization.py",
        "titan/core/egress.py",
        "titan/exploit/atrest.py",
        "tests/conftest.py",
    ):
        assert anchor in text, f"mitigation anchor missing: {anchor}"


def test_threat_model_is_cross_linked():
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/THREAT_MODEL.md" in security, "SECURITY.md does not link the threat model"
    assert "docs/THREAT_MODEL.md" in readme, "README does not link the threat model"
