"""Tests for titan.core.config — target configuration loading and saving.

This module sat at 0% coverage: nothing in the suite imported it, so neither
the JSON/YAML round trip nor the default-filling was ever exercised.
"""
import json

import pytest

from titan.core.config import ConfigManager, TargetConfig, TitanConfig


def _full_config() -> TitanConfig:
    return TitanConfig(
        targets=[
            TargetConfig(
                url="https://example.com",
                name="Example Site",
                auth_headers={"Authorization": "Bearer t0ken"},
                scope=["/api/*"],
                exclude=["/api/health"],
                deep=True,
                max_tests=500,
                timeout=15,
                tags=["production"],
            ),
            TargetConfig(url="https://second.test"),
        ],
        global_auth={"X-Api-Key": "abc"},
        coverage_threshold=88.5,
        parallel=True,
        verbose=True,
        output_dir="custom_output",
    )


class TestDataclasses:
    def test_target_defaults(self):
        target = TargetConfig(url="https://a.test")
        assert target.name == ""
        assert target.auth_headers == {}
        assert target.scope == []
        assert target.exclude == []
        assert target.deep is False
        assert target.max_tests == 1000
        assert target.timeout == 30
        assert target.tags == []

    def test_target_defaults_are_not_shared_between_instances(self):
        first = TargetConfig(url="https://a.test")
        second = TargetConfig(url="https://b.test")
        first.auth_headers["Authorization"] = "Bearer leak"
        first.scope.append("/x")
        assert second.auth_headers == {}
        assert second.scope == []

    def test_titan_defaults(self):
        config = TitanConfig(targets=[])
        assert config.global_auth == {}
        assert config.coverage_threshold == 70.0
        assert config.parallel is False
        assert config.verbose is False
        assert config.output_dir == "titan_output"


class TestLoadJson:
    def test_minimal_config_fills_defaults(self, tmp_path):
        path = tmp_path / "min.json"
        path.write_text(json.dumps({"targets": [{"url": "https://x.test"}]}))
        config = ConfigManager().load(str(path))
        assert len(config.targets) == 1
        assert config.targets[0].url == "https://x.test"
        assert config.targets[0].max_tests == 1000
        assert config.coverage_threshold == 70.0

    def test_full_config_is_preserved(self, tmp_path):
        path = tmp_path / "full.json"
        path.write_text(
            json.dumps(
                {
                    "targets": [
                        {
                            "url": "https://a.test",
                            "name": "A",
                            "auth_headers": {"H": "v"},
                            "scope": ["/api/*"],
                            "exclude": ["/skip"],
                            "deep": True,
                            "max_tests": 7,
                            "timeout": 3,
                            "tags": ["t"],
                        }
                    ],
                    "global_auth": {"K": "V"},
                    "coverage_threshold": 42.0,
                    "parallel": True,
                    "verbose": True,
                    "output_dir": "out",
                }
            )
        )
        config = ConfigManager().load(str(path))
        assert config.targets[0].name == "A"
        assert config.targets[0].deep is True
        assert config.targets[0].max_tests == 7
        assert config.global_auth == {"K": "V"}
        assert config.coverage_threshold == 42.0
        assert config.parallel is True
        assert config.output_dir == "out"

    def test_unsupported_extension_raises(self, tmp_path):
        path = tmp_path / "config.toml"
        path.write_text("targets = []")
        with pytest.raises(ValueError, match="Unsupported config format"):
            ConfigManager().load(str(path))


class TestLoadYaml:
    def test_yaml_config_loads(self, tmp_path):
        path = tmp_path / "targets.yaml"
        path.write_text(
            "targets:\n"
            "  - url: https://yaml.test\n"
            "    name: From YAML\n"
            "    deep: true\n"
            "coverage_threshold: 65.0\n"
        )
        config = ConfigManager().load(str(path))
        assert config.targets[0].name == "From YAML"
        assert config.targets[0].deep is True
        assert config.coverage_threshold == 65.0

    def test_yml_extension_is_accepted(self, tmp_path):
        path = tmp_path / "targets.yml"
        path.write_text("targets:\n  - url: https://yml.test\n")
        assert ConfigManager().load(str(path)).targets[0].url == "https://yml.test"


class TestYamlIsRequired:
    def test_missing_pyyaml_raises_instead_of_returning_empty(self, tmp_path, monkeypatch):
        """PyYAML is a declared runtime dependency, so its absence must fail
        loudly. A hand-rolled fallback here once returned zero targets and
        string-typed numbers, which reads as "nothing to scan"."""
        import sys

        path = tmp_path / "targets.yaml"
        path.write_text("targets:\n  - url: https://yaml.test\n")
        monkeypatch.setitem(sys.modules, "yaml", None)
        with pytest.raises(ImportError):
            ConfigManager().load(str(path))

    def test_missing_pyyaml_raises_on_save_too(self, tmp_path, monkeypatch):
        import sys

        path = tmp_path / "out.yaml"
        monkeypatch.setitem(sys.modules, "yaml", None)
        with pytest.raises(ImportError):
            ConfigManager().save(_full_config(), str(path))


class TestSave:
    def test_json_round_trip(self, tmp_path):
        path = tmp_path / "out.json"
        manager = ConfigManager()
        manager.save(_full_config(), str(path))
        assert manager.load(str(path)) == _full_config()

    def test_yaml_round_trip(self, tmp_path):
        path = tmp_path / "out.yaml"
        manager = ConfigManager()
        manager.save(_full_config(), str(path))
        assert manager.load(str(path)) == _full_config()

    def test_saved_json_is_valid_json(self, tmp_path):
        path = tmp_path / "valid.json"
        ConfigManager().save(_full_config(), str(path))
        data = json.loads(path.read_text())
        assert isinstance(data["targets"], list)
        assert data["targets"][0]["url"] == "https://example.com"


class TestExampleConfig:
    def test_example_config_is_valid_and_complete(self):
        raw = ConfigManager().create_example_config()
        data = json.loads(raw)
        assert data["targets"][0]["url"] == "https://example.com"
        assert data["coverage_threshold"] == 70.0
        assert set(data) == {
            "targets",
            "global_auth",
            "coverage_threshold",
            "parallel",
            "verbose",
            "output_dir",
        }

    def test_example_config_loads_back(self, tmp_path):
        path = tmp_path / "example.json"
        path.write_text(ConfigManager().create_example_config())
        config = ConfigManager().load(str(path))
        assert config.targets[0].auth_headers["Authorization"] == "Bearer <token>"
        assert config.targets[0].tags == ["production", "web-app"]
