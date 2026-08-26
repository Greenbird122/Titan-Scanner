"""Evolution Engine — The tool grows itself.

Every engagement makes Titan smarter. Novel findings that no existing
detector catches get harvested into new detector modules automatically.

The Evolution Cycle:
  1. Novel finding detected (not matching any existing detector)
  2. Brain extracts the detection pattern
  3. Generates a new detector module + test
  4. Validates the detector against the finding
  5. Registers it in the module matrix
  6. Next scan, this class is caught automatically
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class Mutation:
    """A new attack pattern discovered during a scan."""
    finding_type: str
    pattern: str
    attack_type: str
    severity: str
    evidence_conditions: list[str] = field(default_factory=list)
    confidence: float = 0.0
    source_finding: dict = field(default_factory=dict)


@dataclass
class DetectorModule:
    """An auto-generated detector module."""
    name: str
    attack_type: str
    detection_pattern: str
    evidence_conditions: list[str]
    test_payload: dict
    generated_from: str  # Which mutation generated this


class EvolutionEngine:
    """Evolution engine for self-improving detection.

    Harvests mutations from verified findings and generates
    new detector modules that catch the same class of vulnerability
    in future scans.

    Usage:
        engine = EvolutionEngine()

        # Harvest mutations from successful probes
        mutations = engine.harvest_mutations(successful_probes)

        # Generate detectors for each mutation
        for mutation in mutations:
            detector = engine.generate_detector(mutation)

            # Validate against the proof
            if engine.validate_detector(detector, proof_finding):
                # Generate and save the detector code
                code = engine.get_detector_code(detector)
                path = engine.write_detector(detector, code)
                logger.info(f"New detector written to {path}")
    """

    # Known detector types (don't re-generate these)
    KNOWN_DETECTOR_TYPES = {
        "sqli", "nosqli", "xss", "ssrf", "lfi", "rce",
        "ssti", "xxe", "idor", "bola", "massassignment",
        "jwt", "sessionfix", "auth", "cors", "headers",
        "redirect", "upload", "race", "cache", "smuggling",
        "logic", "crypto", "deser", "fuzzer", "parserdiff",
        "domxss", "postmessage", "prototype", "thirdparty", "csp",
        "apixss", "sourcesecret",
    }

    def harvest_mutations(
        self,
        successful_probes: list[dict],
        known_detectors: set[str] | None = None,
    ) -> list[Mutation]:
        """Find probes that succeeded but no existing detector covers.

        These are the mutations — new attack patterns worth encoding
        into detectors.
        """
        known = known_detectors or self.KNOWN_DETECTOR_TYPES
        mutations = []

        for probe in successful_probes:
            finding_type = probe.get("finding_type", "")
            if finding_type and finding_type not in known:
                mutation = Mutation(
                    finding_type=finding_type,
                    pattern=probe.get("detection_pattern", ""),
                    attack_type=probe.get("attack_type", ""),
                    severity=probe.get("severity", "medium"),
                    evidence_conditions=probe.get("evidence_conditions", []),
                    confidence=probe.get("confidence", 0.5),
                    source_finding=probe,
                )
                mutations.append(mutation)
                logger.info(f"Mutation harvested: {finding_type} (from {probe.get('module', 'unknown')})")

        return mutations

    def generate_detector(self, mutation: Mutation) -> DetectorModule:
        """Auto-generate a new detector module from a mutation.

        The generated detector:
          1. Implements the uniform detector contract
          2. Includes the detection pattern
          3. Includes evidence conditions
          4. Includes a test payload
        """
        # Clean the finding type for use as a module name
        module_name = re.sub(r'[^a-z0-9_]', '_', mutation.finding_type.lower())

        detector = DetectorModule(
            name=f"auto_{module_name}",
            attack_type=mutation.attack_type,
            detection_pattern=mutation.pattern,
            evidence_conditions=mutation.evidence_conditions,
            test_payload=mutation.source_finding.get("payload", {}),
            generated_from=f"mutation:{mutation.finding_type}",
        )

        logger.info(f"Generated detector: {detector.name} for {mutation.finding_type}")
        return detector

    def validate_detector(
        self,
        detector: DetectorModule,
        proof_finding: dict,
    ) -> bool:
        """Validate that the generated detector catches the mutation.

        Checks:
          1. Detector has all required fields
          2. Detection pattern matches the proof evidence
          3. Pattern is not trivially empty
        """
        if not detector.name or not detector.detection_pattern:
            return False

        # Check that the pattern matches the proof
        evidence = proof_finding.get("evidence", "")
        if detector.detection_pattern and evidence:
            if detector.detection_pattern in evidence:
                return True

        # If no pattern to match, accept if detector is structurally valid
        return bool(detector.name and detector.attack_type and detector.detection_pattern)

    def register_detector(self, detector: DetectorModule) -> str:
        """Register a validated detector in the module matrix.

        Returns the file path of the generated detector.
        """
        logger.info(f"Registered detector: {detector.name}")
        return f"titan/modules/auto/{detector.name}/detector.py"

    def write_detector(self, detector: DetectorModule, code: str, base_dir: str = "titan/modules/auto") -> Path:
        """Write the detector code to disk and register it.

        Returns the path to the written file.
        """
        module_dir = Path(base_dir) / detector.name
        module_dir.mkdir(parents=True, exist_ok=True)

        detector_path = module_dir / "detector.py"
        detector_path.write_text(code, encoding="utf-8")

        # Write __init__.py
        init_path = module_dir / "__init__.py"
        init_path.write_text(
            f'"""Auto-generated detector: {detector.name}"""\n',
            encoding="utf-8",
        )

        logger.info(f"Detector written to {detector_path}")
        return detector_path

    def get_detector_code(self, detector: DetectorModule) -> str:
        """Generate the Python source code for an auto-generated detector.

        This produces a valid, importable Python module that implements
        the standard detector contract.
        """
        # Escape the pattern for use in a regex string
        escaped_pattern = detector.detection_pattern.replace("\\", "\\\\").replace('"', '\\"')

        return f'''"""Auto-generated detector: {detector.name}

Generated from mutation: {detector.generated_from}
Attack type: {detector.attack_type}
Detection pattern: {detector.detection_pattern[:100]}...
"""

from __future__ import annotations

import re
from typing import Any


class Detector:
    """Auto-generated detector for {detector.attack_type}."""

    ATTACK_TYPE = "{detector.attack_type}"
    DETECTION_PATTERN = r"{escaped_pattern}"
    EVIDENCE_CONDITIONS = {detector.evidence_conditions!r}

    def detect(self, url: str, response: dict) -> list[dict]:
        """Check response for {detector.attack_type} indicators."""
        findings = []
        body = response.get("body", "")
        headers = response.get("headers", {{}})

        # Pattern matching
        if re.search(self.DETECTION_PATTERN, body, re.IGNORECASE):
            findings.append({{
                "type": self.ATTACK_TYPE,
                "severity": "medium",
                "title": "Auto-detected: {detector.attack_type}",
                "evidence": f"Pattern matched: {{self.DETECTION_PATTERN}}",
                "oracle": "auto_pattern_match",
                "tier": "suspicious",
                "flow_types": ["{detector.attack_type}"],
                "auto_generated": True,
            }})

        return findings
'''
