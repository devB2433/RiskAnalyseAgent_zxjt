"""
配置管理系统单元测试
"""
import os
import pytest
import tempfile
import yaml
from src.config.settings import (
    Settings, DatabaseConfig, SchedulerConfig, AnalysisConfig,
    ThreatIntelConfig, NotificationConfig, LoggingConfig, StorageConfig,
    get_settings, reload_settings, _deep_merge, _apply_env_overrides,
)


class TestDatabaseConfig:
    def test_defaults(self):
        cfg = DatabaseConfig()
        assert "sqlite" in cfg.url
        assert cfg.echo is False
        assert cfg.pool_size == 5

    def test_from_dict(self):
        cfg = DatabaseConfig.from_dict({"url": "postgresql://localhost/test", "echo": True})
        assert cfg.url == "postgresql://localhost/test"
        assert cfg.echo is True

    def test_from_dict_ignores_unknown(self):
        cfg = DatabaseConfig.from_dict({"url": "test", "unknown_field": 123})
        assert cfg.url == "test"


class TestSchedulerConfig:
    def test_defaults(self):
        cfg = SchedulerConfig()
        assert cfg.timezone == "Asia/Shanghai"
        assert cfg.max_workers == 10


class TestAnalysisConfig:
    def test_defaults(self):
        cfg = AnalysisConfig()
        assert cfg.default_model == "gpt-4"
        assert len(cfg.enabled_analyzers) == 8
        assert "compromised_host" in cfg.enabled_analyzers


class TestNotificationConfig:
    def test_defaults(self):
        cfg = NotificationConfig()
        assert cfg.feishu.enabled is False
        assert cfg.wecom.enabled is False
        assert cfg.email.enabled is False
        assert cfg.min_severity == "medium"

    def test_from_dict(self):
        data = {
            "min_severity": "high",
            "feishu": {"enabled": True, "webhook_url": "https://example.com"},
            "wecom": {"enabled": True, "webhook_url": "https://wecom.example.com"},
        }
        cfg = NotificationConfig.from_dict(data)
        assert cfg.min_severity == "high"
        assert cfg.feishu.enabled is True
        assert cfg.feishu.webhook_url == "https://example.com"
        assert cfg.wecom.enabled is True


class TestDeepMerge:
    def test_simple_merge(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_nested_merge(self):
        base = {"db": {"url": "sqlite:///test", "echo": False}}
        override = {"db": {"echo": True}}
        result = _deep_merge(base, override)
        assert result["db"]["url"] == "sqlite:///test"
        assert result["db"]["echo"] is True


class TestEnvOverrides:
    def test_env_override(self):
        os.environ["RISK_AGENT_ENV"] = "production"
        data = {"env": "development"}
        result = _apply_env_overrides(data)
        assert result["env"] == "production"
        del os.environ["RISK_AGENT_ENV"]

    def test_nested_env_override(self):
        os.environ["RISK_AGENT_DB_URL"] = "postgresql://prod/db"
        data = {}
        result = _apply_env_overrides(data)
        assert result["database"]["url"] == "postgresql://prod/db"
        del os.environ["RISK_AGENT_DB_URL"]

    def test_bool_conversion(self):
        os.environ["RISK_AGENT_DEBUG"] = "true"
        data = {}
        result = _apply_env_overrides(data)
        assert result["debug"] is True
        del os.environ["RISK_AGENT_DEBUG"]


class TestSettings:
    def test_from_dict(self):
        data = {
            "app_name": "TestApp",
            "env": "test",
            "database": {"url": "sqlite:///test.db"},
        }
        settings = Settings.from_dict(data)
        assert settings.app_name == "TestApp"
        assert settings.env == "test"
        assert settings.database.url == "sqlite:///test.db"

    def test_load_from_yaml(self):
        config_data = {
            "app_name": "YAMLTest",
            "env": "staging",
            "database": {"url": "sqlite:///staging.db"},
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            f.flush()
            settings = Settings.load(f.name)
            assert settings.app_name == "YAMLTest"
            assert settings.env == "staging"
        os.unlink(f.name)
