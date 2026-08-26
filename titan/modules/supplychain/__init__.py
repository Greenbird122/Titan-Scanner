"""Supply Chain Detector — Probe CI/CD pipelines, dependencies, SBOM.

Detects poisoned pipeline execution, dependency confusion, secret leakage
in CI/CD workflows, SRI violations, cleartext loading, and known CVEs.

Components:
  - SupplyChainDetector: CI/CD workflow analysis, dependency confusion, typosquatting
  - SBOMAnalyzer: SRI checking, cleartext detection, vulnerability matching
"""

from titan.modules.supplychain.detector import SupplyChainDetector
from titan.modules.supplychain.sbom import SBOMAnalyzer, SBOMReport, KNOWN_VULNERABLE

__all__ = ["SupplyChainDetector", "SBOMAnalyzer", "SBOMReport", "KNOWN_VULNERABLE"]
