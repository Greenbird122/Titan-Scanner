"""State Persistence — save/load scan state between sessions.

A real attacker doesn't start from scratch every time.
They save their progress and resume where they left off.

This module:
1. Saves scan state to disk (JSON)
2. Loads previous state on startup
3. Merges new findings with old ones
4. Tracks scan history
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from titan.core.models import Finding


@dataclass
class ScanState:
    """Complete scan state for persistence."""
    scan_id: str
    target: str
    started_at: str
    updated_at: str
    status: str  # "running", "paused", "completed", "failed"
    phase: str  # current phase
    findings: List[Dict[str, Any]]
    coverage_summary: Dict[str, Any]
    endpoints_discovered: List[str]
    attack_types_tested: List[str]
    notes: str
    errors: List[str]


class StateManager:
    """Manage scan state persistence."""

    DEFAULT_STATE_DIR = "titan_states"

    def __init__(self, state_dir: Optional[str] = None):
        self.state_dir = state_dir or self.DEFAULT_STATE_DIR
        os.makedirs(self.state_dir, exist_ok=True)

    def save(self, state: ScanState) -> str:
        """Save state to disk."""
        filepath = self._get_filepath(state.scan_id)
        data = asdict(state)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return filepath

    def load(self, scan_id: str) -> Optional[ScanState]:
        """Load state from disk."""
        filepath = self._get_filepath(scan_id)
        if not os.path.exists(filepath):
            return None
        with open(filepath, "r") as f:
            data = json.load(f)
        return ScanState(**data)

    def exists(self, scan_id: str) -> bool:
        """Check if state exists."""
        return os.path.exists(self._get_filepath(scan_id))

    def list_scans(self) -> List[str]:
        """List all saved scan IDs."""
        scans = []
        for filename in os.listdir(self.state_dir):
            if filename.endswith(".json"):
                scans.append(filename.replace(".json", ""))
        return sorted(scans)

    def delete(self, scan_id: str) -> bool:
        """Delete a scan state."""
        filepath = self._get_filepath(scan_id)
        if os.path.exists(filepath):
            os.remove(filepath)
            return True
        return False

    def merge_findings(
        self,
        scan_id: str,
        new_findings: List[Finding],
    ) -> ScanState:
        """Merge new findings with existing state."""
        state = self.load(scan_id)
        if state is None:
            state = ScanState(
                scan_id=scan_id,
                target="",
                started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                updated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                status="running",
                phase="scanning",
                findings=[],
                coverage_summary={},
                endpoints_discovered=[],
                attack_types_tested=[],
                notes="",
                errors=[],
            )

        # Merge findings
        for finding in new_findings:
            finding_dict = {
                "target": finding.target,
                "url": finding.url,
                "method": finding.method,
                "param": finding.param,
                "severity": str(finding.severity),
                "confidence": finding.confidence,
                "status": finding.status,
                "notes": finding.notes,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            state.findings.append(finding_dict)

        state.updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.save(state)
        return state

    def _get_filepath(self, scan_id: str) -> str:
        return os.path.join(self.state_dir, f"{scan_id}.json")

    def create_state(
        self,
        scan_id: str,
        target: str,
    ) -> ScanState:
        """Create a new scan state."""
        state = ScanState(
            scan_id=scan_id,
            target=target,
            started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            updated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            status="running",
            phase="recon",
            findings=[],
            coverage_summary={},
            endpoints_discovered=[],
            attack_types_tested=[],
            notes="",
            errors=[],
        )
        self.save(state)
        return state
