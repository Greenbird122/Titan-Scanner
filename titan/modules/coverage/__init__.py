"""Coverage Engine — prove every vector was tested."""

from titan.modules.coverage.tracker import CoverageTracker
from titan.modules.coverage.scorer import CoverageScorer
from titan.modules.coverage.gapidentifier import GapIdentifier
from titan.modules.coverage.proof import CoverageProof
from titan.modules.coverage.report import CoverageReportGenerator
from titan.modules.coverage.gate import CoverageGate
from titan.modules.coverage.comparison import ScanComparator
from titan.modules.coverage.retest import AutoRetester
from titan.modules.coverage.surfacemapper import AttackSurfaceMapper
from titan.modules.coverage.pipeline import CoveragePipeline

__all__ = [
    "CoverageTracker",
    "CoverageScorer",
    "GapIdentifier",
    "CoverageProof",
    "CoverageReportGenerator",
    "CoverageGate",
    "ScanComparator",
    "AutoRetester",
    "AttackSurfaceMapper",
    "CoveragePipeline",
]
