"""Cloud Control Plane Detector — Probe IAM, secrets, cross-account paths.

Detects SSRF to cloud metadata, credential extraction, privilege escalation,
and cross-account attack paths in cloud environments (AWS, GCP, Azure).

Components:
  - CloudControlDetector: Analyzes HTTP responses for cloud indicators
  - IMDSProber: Probes IMDS endpoints through an SSRF sink
"""

from titan.modules.cloud_control.detector import CloudControlDetector
from titan.modules.cloud_control.imds import IMDSProber, IMDSReport, IMDSEndpoint

__all__ = ["CloudControlDetector", "IMDSProber", "IMDSReport", "IMDSEndpoint"]
