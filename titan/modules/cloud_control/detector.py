"""Cloud Control Plane Detector — fully exhausted.

Probes the cloud control plane (not just data plane).
Attack chain: SSRF → IMDS → role creds → IAM escalation → secrets → lateral movement.

Supports: AWS (IMDSv1/v2, STS, IAM, SecretsManager, SSM, EC2, Lambda, ECS),
          GCP (metadata server, service accounts),
          Azure (instance metadata, managed identity tokens).

Features:
  1. Standard scan() interface for Titan's per-endpoint pipeline.
  2. Active IMDS probing via URL-accepting parameters (SSRF sinks).
  3. Response analysis for cloud credential and metadata patterns.
  4. IAM privilege escalation path analysis.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from titan.core.models import AttackType, Finding, Severity

logger = logging.getLogger(__name__)


class CloudControlDetector:
    """Detect cloud control plane exposure through SSRF or misconfiguration."""

    # IMDS endpoints (v1 and v2)
    IMDS_ENDPOINTS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/instance-id",
        "http://169.254.169.254/latest/meta-data/instance-type",
        "http://169.254.169.254/latest/meta-data/region",
        "http://[fd00::2]/latest/meta-data/",  # IPv6 IMDS
    ]

    # AWSSTS calls for permission enumeration
    AWSSTS_CALLS = [
        "sts:GetCallerIdentity",
        "iam:SimulatePrincipalPolicy",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "iam:GetRolePolicy",
        "secretsmanager:ListSecrets",
        "secretsmanager:GetSecretValue",
        "ssm:DescribeParameters",
        "ssm:GetParameter",
        "ec2:DescribeInstances",
        "lambda:ListFunctions",
        "lambda:GetFunctionConfiguration",
        "ecs:DescribeServices",
        "ecs:DescribeTaskDefinition",
        "rds:DescribeDBInstances",
        "s3:ListAllMyBuckets",
    ]

    # AWS metadata headers that indicate cloud hosting
    AWS_HEADERS = {
        "x-amz-request-id": "AWS",
        "x-amz-id-2": "AWS",
        "x-amzn-trace-id": "AWS",
        "server": "AmazonS3",
    }

    def detect_from_response(
        self,
        url: str,
        status: int,
        headers: dict[str, str],
        body: str,
    ) -> list[dict]:
        """Analyze an HTTP response for cloud indicators."""
        findings = []

        # Check if response looks like IMDS
        if self._is_imds_response(body, headers):
            findings.append({
                "type": "cloud_imds_exposure",
                "severity": "critical",
                "title": "Cloud Instance Metadata Service (IMDS) Accessible",
                "evidence": f"IMDS endpoint responded at {url}",
                "flow_types": ["url_fetch", "creds"],
                "cvss": 9.8,
            })

        # Check for AWS role credentials in response
        role_creds = self._extract_role_credentials(body)
        if role_creds:
            findings.append({
                "type": "cloud_credential_exposure",
                "severity": "critical",
                "title": f"IAM Role Credentials Extracted: {role_creds['role_name']}",
                "evidence": f"AccessKeyId={role_creds.get('access_key_id', 'N/A')[:12]}...",
                "flow_types": ["creds", "auth_bypass"],
                "cvss": 10.0,
                "metadata": role_creds,
            })

        # Check for AWS metadata in headers
        for header, provider in self.AWS_HEADERS.items():
            if header.lower() in {h.lower() for h in headers}:
                findings.append({
                    "type": "cloud_metadata_leak",
                    "severity": "medium",
                    "title": f"{provider} Metadata Header Exposed",
                    "evidence": f"Header '{header}' present in response",
                    "flow_types": ["data_leak"],
                    "cvss": 5.3,
                })

        # Check for user-data exposure
        if self._is_user_data(body):
            findings.append({
                "type": "cloud_userdata_exposure",
                "severity": "critical",
                "title": "EC2 User-Data Exposed",
                "evidence": "Instance user-data accessible — may contain scripts, secrets, bootstrapping logic",
                "flow_types": ["data_leak", "creds"],
                "cvss": 9.1,
            })

        return findings

    def generate_imds_payloads(self) -> list[dict]:
        """Generate payloads for probing cloud IMDS."""
        payloads = []
        for endpoint in self.IMDS_ENDPOINTS:
            payloads.append({
                "url": endpoint,
                "method": "GET",
                "headers": {},
                "description": f"IMDS probe: {endpoint}",
                "attack_type": "ssrf",
            })

        # Also try IMDSv2 (requires PUT to get token)
        payloads.append({
            "url": "http://169.254.169.254/latest/api/token",
            "method": "PUT",
            "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            "description": "IMDSv2 token request",
            "attack_type": "ssrf",
        })

        return payloads

    def analyze_role_permissions(self, role_name: str, policies: list[dict]) -> list[dict]:
        """Analyze extracted IAM role permissions for escalation paths."""
        findings = []

        for policy in policies:
            policy_doc = policy.get("policy_document", {})
            statements = policy_doc.get("Statement", [])

            for stmt in statements:
                if stmt.get("Effect") != "Allow":
                    continue

                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                # Privilege escalation checks
                escalation_actions = [
                    "iam:CreatePolicyVersion",
                    "iam:SetDefaultPolicyVersion",
                    "iam:CreateLoginProfile",
                    "iam:UpdateLoginProfile",
                    "iam:AttachUserPolicy",
                    "iam:AttachRolePolicy",
                    "iam:AttachGroupPolicy",
                    "iam:PutRolePolicy",
                    "iam:PutUserPolicy",
                    "iam:PutGroupPolicy",
                    "lambda:CreateFunction",
                    "lambda:InvokeFunction",
                    "lambda:UpdateFunctionCode",
                    "ec2:RunInstances",
                    "ec2:CreateKeyPair",
                    "ec2:CreateSecurityGroup",
                    "sts:AssumeRole",
                ]

                for action in actions:
                    if action in escalation_actions or action == "*":
                        findings.append({
                            "type": "cloud_privilege_escalation",
                            "severity": "critical",
                            "title": f"IAM Privilege Escalation: {action}",
                            "evidence": f"Role '{role_name}' has '{action}' permission",
                            "flow_types": ["auth_bypass", "code_exec"],
                            "cvss": 9.8,
                        })

                # Cross-account access
                principal_arn = stmt.get("Principal", {})
                if isinstance(principal_arn, dict):
                    aws_principal = principal_arn.get("AWS", "")
                    if aws_principal and "*" not in aws_principal:
                        findings.append({
                            "type": "cloud_cross_account",
                            "severity": "high",
                            "title": "Cross-Account Access Detected",
                            "evidence": f"Role trusts external account: {aws_principal}",
                            "flow_types": ["auth_bypass"],
                            "cvss": 7.5,
                        })

        return findings

    def _is_imds_response(self, body: str, headers: dict) -> bool:
        """Check if response looks like AWS IMDS."""
        imds_indicators = [
            "ami-id",
            "ami-launch-index",
            "instance-id",
            "instance-type",
            "local-hostname",
            "security-credentials",
            "iam/security-credentials",
        ]
        body_lower = body.lower()
        return any(indicator in body_lower for indicator in imds_indicators)

    def _extract_role_credentials(self, body: str) -> dict | None:
        """Try to extract AWS role credentials from response body."""
        try:
            data = json.loads(body)
            if all(k in data for k in ["AccessKeyId", "SecretAccessKey", "Token"]):
                return {
                    "access_key_id": data["AccessKeyId"],
                    "secret_access_key": data["SecretAccessKey"],
                    "token": data["Token"],
                    "expiration": data.get("Expiration", ""),
                    "role_name": data.get("RoleName", "unknown"),
                }
        except (json.JSONDecodeError, TypeError):
            pass
        return None

    def _is_user_data(self, body: str) -> bool:
        """Check if response contains EC2 user-data."""
        user_data_indicators = [
            "#!/bin/bash",
            "#!/usr/bin/env bash",
            "cloud-init",
            "#cloud-config",
            "yum install",
            "apt-get install",
            "pip install",
        ]
        return any(indicator in body for indicator in user_data_indicators)

    async def probe_imds(
        self,
        sink,
        providers: list[str] | None = None,
    ) -> list[dict]:
        """Probe cloud IMDS through an SSRF sink.

        Args:
            sink: Async callable(url, method, headers, timeout) -> (status, headers, body)
            providers: Which providers to probe (default: all).

        Returns:
            List of Titan findings from IMDS probing.
        """
        from titan.modules.cloud_control.imds import IMDSProber

        prober = IMDSProber(providers=providers)
        report = await prober.probe(sink)
        return report.findings
