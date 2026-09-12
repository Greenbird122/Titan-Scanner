"""Config Manager — YAML/JSON target configuration.

Usage:
    titan scan --config targets.yaml
    titan scan --config targets.json
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TargetConfig:
    """Configuration for a single target."""

    url: str
    name: str = ""
    auth_headers: dict[str, str] = field(default_factory=dict)
    scope: list[str] = field(default_factory=list)  # endpoints to test
    exclude: list[str] = field(default_factory=list)  # endpoints to skip
    deep: bool = False
    max_tests: int = 1000
    timeout: int = 30
    tags: list[str] = field(default_factory=list)


@dataclass
class TitanConfig:
    """Full Titan configuration."""

    targets: list[TargetConfig]
    global_auth: dict[str, str] = field(default_factory=dict)
    coverage_threshold: float = 70.0
    parallel: bool = False
    verbose: bool = False
    output_dir: str = "titan_output"


class ConfigManager:
    """Manage Titan configuration."""

    def load(self, filepath: str) -> TitanConfig:
        """Load config from file."""
        ext = os.path.splitext(filepath)[1].lower()

        with open(filepath) as f:
            if ext in (".yaml", ".yml"):
                return self._load_yaml(f.read())
            elif ext == ".json":
                return self._load_json(f.read())
            else:
                raise ValueError(f"Unsupported config format: {ext}")

    def save(self, config: TitanConfig, filepath: str) -> None:
        """Save config to file."""
        ext = os.path.splitext(filepath)[1].lower()
        data = self._config_to_dict(config)

        with open(filepath, "w") as f:
            if ext in (".yaml", ".yml"):
                f.write(self._dict_to_yaml(data))
            elif ext == ".json":
                json.dump(data, f, indent=2)

    def _load_yaml(self, content: str) -> TitanConfig:
        """Load config from YAML string.

        PyYAML is a declared runtime dependency, so a missing install must fail
        loudly here. A previous hand-rolled fallback silently returned zero
        targets and string-typed values, which reads as "no work to do"
        instead of "your environment is broken".
        """
        import yaml

        data = yaml.safe_load(content)
        return self._dict_to_config(data)

    def _load_json(self, content: str) -> TitanConfig:
        """Load config from JSON string."""
        data = json.loads(content)
        return self._dict_to_config(data)

    def _dict_to_config(self, data: dict[str, Any]) -> TitanConfig:
        """Convert dict to TitanConfig."""
        targets = []
        for t in data.get("targets", []):
            targets.append(
                TargetConfig(
                    url=t["url"],
                    name=t.get("name", ""),
                    auth_headers=t.get("auth_headers", {}),
                    scope=t.get("scope", []),
                    exclude=t.get("exclude", []),
                    deep=t.get("deep", False),
                    max_tests=t.get("max_tests", 1000),
                    timeout=t.get("timeout", 30),
                    tags=t.get("tags", []),
                )
            )

        return TitanConfig(
            targets=targets,
            global_auth=data.get("global_auth", {}),
            coverage_threshold=data.get("coverage_threshold", 70.0),
            parallel=data.get("parallel", False),
            verbose=data.get("verbose", False),
            output_dir=data.get("output_dir", "titan_output"),
        )

    def _config_to_dict(self, config: TitanConfig) -> dict[str, Any]:
        """Convert TitanConfig to dict."""
        return {
            "targets": [
                {
                    "url": t.url,
                    "name": t.name,
                    "auth_headers": t.auth_headers,
                    "scope": t.scope,
                    "exclude": t.exclude,
                    "deep": t.deep,
                    "max_tests": t.max_tests,
                    "timeout": t.timeout,
                    "tags": t.tags,
                }
                for t in config.targets
            ],
            "global_auth": config.global_auth,
            "coverage_threshold": config.coverage_threshold,
            "parallel": config.parallel,
            "verbose": config.verbose,
            "output_dir": config.output_dir,
        }

    def _dict_to_yaml(self, data: dict[str, Any]) -> str:
        """Convert dict to YAML string.

        PyYAML is a declared runtime dependency; see `_load_yaml`.
        """
        import yaml

        yaml_text: str = yaml.dump(data, default_flow_style=False)
        return yaml_text

    def create_example_config(self) -> str:
        """Create example configuration."""
        example = {
            "targets": [
                {
                    "url": "https://example.com",
                    "name": "Example Site",
                    "auth_headers": {"Authorization": "Bearer <token>"},
                    "scope": ["/api/*", "/admin/*"],
                    "exclude": ["/api/health"],
                    "deep": True,
                    "max_tests": 500,
                    "timeout": 30,
                    "tags": ["production", "web-app"],
                }
            ],
            "global_auth": {},
            "coverage_threshold": 70.0,
            "parallel": False,
            "verbose": False,
            "output_dir": "titan_output",
        }
        return json.dumps(example, indent=2)
