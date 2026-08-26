"""Supply Chain Detector.

Probes the software supply chain from source to runtime:
  1. CI/CD workflow poisoning (GitHub Actions, GitLab CI, Jenkins)
  2. Dependency confusion (private packages on public registries)
  3. Secret leakage in CI/CD configs
  4. Container image provenance
  5. Typosquatting in dependencies
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

logger = logging.getLogger(__name__)


class SupplyChainDetector:
    """Detect supply chain vulnerabilities."""

    # Dangerous GitHub Actions patterns
    DANGEROUS_ACTIONS = [
        "pull_request_target",
        "workflow_run",
        "repository_dispatch",
    ]

    DANGEROUS_ACTIONS_WITH_CHECKOUT = [
        "actions/checkout",
        "actions/checkout@v",
    ]

    # Secret leakage patterns in CI/CD configs
    SECRET_PATTERNS = [
        (r"echo\s+.*\$\{\{.*secret.*\}\}", "secret_echo"),
        (r"printenv.*secret", "secret_printenv"),
        (r"\.\/secrets", "secrets_file"),
        (r"GITHUB_TOKEN", "github_token"),
        (r"AWS_ACCESS_KEY_ID", "aws_key"),
        (r"DOCKER_PASSWORD", "docker_password"),
        (r"NPM_TOKEN", "npm_token"),
        (r"DEPLOY_KEY", "deploy_key"),
    ]

    def detect_from_github_actions(self, workflows: list[dict]) -> list[dict]:
        """Analyze GitHub Actions workflows for supply chain risks."""
        findings = []

        for workflow in workflows:
            name = workflow.get("name", "unknown")
            content = workflow.get("content", "")

            # Check for pull_request_target misuse
            if "pull_request_target" in content:
                # Check if it also checks out code
                has_checkout = any(
                    checkout in content
                    for checkout in self.DANGEROUS_ACTIONS_WITH_CHECKOUT
                )

                if has_checkout:
                    findings.append({
                        "type": "supply_chain_ppe",
                        "severity": "critical",
                        "title": "Poisoned Pipeline Execution Risk",
                        "evidence": (
                            f"Workflow '{name}' uses pull_request_target "
                            f"with actions/checkout — attacker-controlled PRs "
                            f"can execute code with repo secrets"
                        ),
                        "flow_types": ["code_exec", "creds"],
                        "cvss": 9.8,
                        "remediation": (
                            "Remove actions/checkout from pull_request_target jobs, "
                            "or use explicit ref: ${{ github.event.pull_request.head.sha }}"
                        ),
                    })

            # Check for secret leakage
            for pattern, secret_type in self.SECRET_PATTERNS:
                matches = re.findall(pattern, content)
                if matches:
                    findings.append({
                        "type": "supply_chain_secret_leak",
                        "severity": "high",
                        "title": f"CI/CD Secret Leakage: {secret_type}",
                        "evidence": f"Workflow '{name}' exposes secrets via {pattern}",
                        "flow_types": ["creds"],
                        "cvss": 7.5,
                    })

            # Check for write permissions
            if "permissions:" in content:
                if "contents: write" in content or "packages: write" in content:
                    findings.append({
                        "type": "supply_chain_over_permission",
                        "severity": "medium",
                        "title": "CI/CD Workflow Has Write Permissions",
                        "evidence": f"Workflow '{name}' requests write access",
                        "flow_types": ["code_exec"],
                        "cvss": 5.3,
                    })

            # Check for unpinned actions (mutable refs)
            unpinned = re.findall(r"uses:\s+(\w+/[\w-]+)@(?!(v\d|[0-9a-f]{40}))([\w-]+)", content)
            if unpinned:
                findings.append({
                    "type": "supply_chain_unpinned_action",
                    "severity": "medium",
                    "title": "Unpinned GitHub Actions (Mutable Refs)",
                    "evidence": f"Workflow '{name}' uses unpinned actions: {[u[0]+'@'+u[2] for u in unpinned]}",
                    "flow_types": ["code_exec"],
                    "cvss": 6.5,
                    "remediation": "Pin actions to full SHA commit hashes",
                })

        return findings

    def detect_dependency_confusion(self, package_json: dict, registry: str = "npm") -> list[dict]:
        """Check for dependency confusion vulnerabilities.

        If a private package name doesn't exist on the public registry,
        an attacker could publish a malicious version that takes precedence.
        """
        findings = []
        dependencies = package_json.get("dependencies", {})
        dev_dependencies = package_json.get("devDependencies", {})

        all_deps = {**dependencies, **dev_dependencies}

        for name, version in all_deps.items():
            # Check if package exists on public registry
            if not self._check_registry_exists(name, registry):
                findings.append({
                    "type": "supply_chain_dependency_confusion",
                    "severity": "high",
                    "title": f"Dependency Confusion Risk: '{name}'",
                    "evidence": f"Package '{name}' not found on {registry} — could be replaced by attacker-published version",
                    "flow_types": ["code_exec", "data_leak"],
                    "cvss": 8.1,
                    "remediation": f"Publish '{name}' to {registry} as a private/empty package to reserve the name",
                })

        return findings

    def detect_typosquatting(self, package_json: dict) -> list[dict]:
        """Check for common typosquatting targets in dependencies."""
        findings = []
        known_packages = {
            "express", "lodash", "react", "axios", "webpack",
            "moment", "chalk", "commander", "debug", "semver",
            "minimist", "glob", "rimraf", "mkdirp", "uuid",
        }

        dependencies = package_json.get("dependencies", {})
        for name in dependencies:
            # Check for levenshtein distance < 2 from known packages
            for known in known_packages:
                if name != known and self._levenshtein(name, known) <= 2:
                    findings.append({
                        "type": "supply_chain_typosquatting",
                        "severity": "high",
                        "title": f"Possible Typosquatting: '{name}' ≈ '{known}'",
                        "evidence": f"Package name is close to popular package '{known}'",
                        "flow_types": ["code_exec"],
                        "cvss": 7.5,
                    })

        return findings

    def _check_registry_exists(self, package_name: str, registry: str) -> bool:
        """Check if a package exists on the public registry."""
        import urllib.request
        import urllib.error

        try:
            if registry == "npm":
                url = f"https://registry.npmjs.org/{package_name}"
            elif registry == "pypi":
                url = f"https://pypi.org/pypi/{package_name}/json"
            else:
                return True  # Unknown registry, assume exists

            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except urllib.error.HTTPError:
            return False
        except Exception:
            return True  # Assume exists on error

    def _levenshtein(self, s1: str, s2: str) -> int:
        """Compute Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)

        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row

        return prev_row[-1]
