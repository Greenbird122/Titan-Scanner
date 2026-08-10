"""PoC generator for Titan Scanner findings."""

from __future__ import annotations

from typing import Any, Dict, Optional

from titan.core.models import Finding


class PoCGenerator:
    @staticmethod
    def generate(finding: Finding) -> Dict[str, str]:
        return {
            "curl": PoCGenerator._generate_curl(finding),
            "python": PoCGenerator._generate_python(finding),
        }

    @staticmethod
    def _generate_curl(finding: Finding) -> str:
        url = finding.url
        method = finding.method.upper()
        headers = dict(finding.headers)
        headers["Referer"] = finding.target

        parts = [f"curl -X {method}"]

        for key, value in headers.items():
            safe_value = str(value).replace('"', '\\"')
            parts.append(f'-H "{key}: {safe_value}"')

        safe_payload = str(finding.payload).replace('"', '\\"')

        if finding.location == "query" and method == "GET":
            parts.append(f'"{url}&{finding.param}={safe_payload}"')
        elif finding.location == "body":
            parts.append(f'-d "{finding.param}={safe_payload}"')
            parts.append(f'"{url}"')
        else:
            parts.append(f'"{url}"')

        return " ".join(parts)

    @staticmethod
    def _generate_python(finding: Finding) -> str:
        url = finding.url
        method = finding.method.upper()
        headers = dict(finding.headers)
        headers["Referer"] = finding.target

        lines = [
            "import requests",
            "",
            f'url = "{url}"',
            f"method = \"{method}\"",
            "headers = {",
        ]
        for key, value in headers.items():
            safe_value = str(value).replace('"', '\\"')
            lines.append(f'    "{key}": "{safe_value}",')
        lines.append("}")

        safe_payload = str(finding.payload).replace('"', '\\"')

        if finding.location == "query" and method == "GET":
            lines.append(f'params = {{"{finding.param}": "{safe_payload}"}}')
            lines.append("response = requests.request(method, url, headers=headers, params=params)")
        elif finding.location == "body":
            lines.append(f'data = {{"{finding.param}": "{safe_payload}"}}')
            lines.append("response = requests.request(method, url, headers=headers, data=data)")
        else:
            lines.append("response = requests.request(method, url, headers=headers)")

        lines.extend([
            "",
            "print(response.status_code)",
            'print(response.text[:2000])',
        ])
        return "\n".join(lines)
