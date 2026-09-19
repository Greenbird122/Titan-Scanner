"""Data models for the deep auditor: cloud configs, findings, results.

Extracted from ``prober.py`` so orchestration (``prober.py``) and the
network probes (``cloud_probes.py``) can share them without a circular
import. ``prober.py`` re-exports the names for backwards compatibility.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CloudConfig:
    """Extracted cloud service configuration."""

    provider: str  # "firebase", "supabase", "aws"
    project_id: str = ""
    api_key: str = ""
    auth_domain: str = ""
    storage_bucket: str = ""
    messaging_sender_id: str = ""
    app_id: str = ""
    region: str = "us-central1"
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditFinding:
    """A finding from the deep audit."""

    id: str
    severity: str  # "critical", "high", "medium", "low", "info"
    title: str
    description: str
    proof: str  # HTTP request/response or code evidence
    impact: str
    remediation: str
    category: str  # "pii_exposure", "auth_bypass", "misconfiguration", etc.
    cvss: float = 0.0
    verified: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditResult:
    """Complete audit results."""

    target: str
    findings: list[AuditFinding] = field(default_factory=list)
    cloud_config: CloudConfig | None = None
    collections: list[dict[str, Any]] = field(default_factory=list)
    attack_chain: list[str] = field(default_factory=list)
    positive_controls: list[str] = field(default_factory=list)
    duration: float = 0.0
