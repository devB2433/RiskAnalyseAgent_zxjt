"""
配置管理系统

基于Pydantic的类型安全配置，支持YAML文件加载和环境变量覆盖
优先级: 环境变量 > 自定义配置文件 > 默认配置文件
"""
import os
import yaml
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

# 项目根目录
PROJECT_ROOT = Path(__file__).parent.parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "default.yaml"


@dataclass
class DatabaseConfig:
    """数据库配置"""
    url: str = "sqlite:///data/security_analysis.db"
    async_url: str = "sqlite+aiosqlite:///data/security_analysis.db"
    echo: bool = False
    pool_size: int = 5
    max_overflow: int = 10
    pool_recycle: int = 3600

    @classmethod
    def from_dict(cls, data: dict) -> "DatabaseConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class SchedulerConfig:
    """调度器配置"""
    timezone: str = "Asia/Shanghai"
    max_workers: int = 10
    job_defaults_coalesce: bool = True
    job_defaults_max_instances: int = 3
    misfire_grace_time: int = 60

    @classmethod
    def from_dict(cls, data: dict) -> "SchedulerConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class AnalysisConfig:
    """分析引擎配置"""
    default_model: str = "gpt-4"
    fallback_model: str = "gpt-3.5-turbo"
    temperature: float = 0.1
    max_tokens: int = 4096
    confidence_threshold: float = 0.7
    alert_threshold: float = 0.8
    batch_size: int = 50
    enabled_analyzers: List[str] = field(default_factory=lambda: [
        "compromised_host", "anomalous_login", "data_exfiltration",
        "malware_detection", "insider_threat", "ddos_detection",
        "lateral_movement", "phishing_detection"
    ])

    @classmethod
    def from_dict(cls, data: dict) -> "AnalysisConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ThreatIntelConfig:
    """威胁情报配置"""
    enabled: bool = True
    cache_ttl: int = 3600
    cache_dir: str = "data/threat_intel_cache"
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    use_mock: bool = True

    @classmethod
    def from_dict(cls, data: dict) -> "ThreatIntelConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class FeishuNotificationConfig:
    """飞书通知配置"""
    enabled: bool = False
    webhook_url: str = ""
    secret: str = ""
    at_all_on_critical: bool = True

    @classmethod
    def from_dict(cls, data: dict) -> "FeishuNotificationConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class WeComNotificationConfig:
    """企业微信通知配置"""
    enabled: bool = False
    webhook_url: str = ""
    mentioned_list: List[str] = field(default_factory=list)
    mentioned_mobile_list: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "WeComNotificationConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class EmailNotificationConfig:
    """邮件通知配置"""
    enabled: bool = False
    smtp_host: str = "smtp.example.com"
    smtp_port: int = 587
    smtp_use_tls: bool = True
    username: str = ""
    password: str = ""
    from_addr: str = ""
    to_addrs: List[str] = field(default_factory=list)
    cc_addrs: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "EmailNotificationConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class NotificationConfig:
    """通知总配置"""
    feishu: FeishuNotificationConfig = field(default_factory=FeishuNotificationConfig)
    wecom: WeComNotificationConfig = field(default_factory=WeComNotificationConfig)
    email: EmailNotificationConfig = field(default_factory=EmailNotificationConfig)
    min_severity: str = "medium"
    cooldown_minutes: int = 30
    batch_interval_seconds: int = 60

    @classmethod
    def from_dict(cls, data: dict) -> "NotificationConfig":
        feishu = FeishuNotificationConfig.from_dict(data.get("feishu", {}))
        wecom = WeComNotificationConfig.from_dict(data.get("wecom", {}))
        email = EmailNotificationConfig.from_dict(data.get("email", {}))
        top_level = {k: v for k, v in data.items() if k not in ("feishu", "wecom", "email") and k in cls.__dataclass_fields__}
        return cls(feishu=feishu, wecom=wecom, email=email, **top_level)


@dataclass
class LoggingConfig:
    """日志配置"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file: str = "logs/security_analysis.log"
    max_bytes: int = 10485760  # 10MB
    backup_count: int = 5
    console_output: bool = True

    @classmethod
    def from_dict(cls, data: dict) -> "LoggingConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class StorageConfig:
    """存储配置"""
    data_retention_days: int = 90
    export_dir: str = "data/exports"
    auto_cleanup: bool = True
    cleanup_cron: str = "0 2 * * *"  # 每天凌晨2点

    @classmethod
    def from_dict(cls, data: dict) -> "StorageConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class Settings:
    """全局配置"""
    app_name: str = "RiskAnalyseAgent"
    env: str = "development"
    debug: bool = False
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    scheduler: SchedulerConfig = field(default_factory=SchedulerConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    notification: NotificationConfig = field(default_factory=NotificationConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)

    @classmethod
    def from_dict(cls, data: dict) -> "Settings":
        return cls(
            app_name=data.get("app_name", "RiskAnalyseAgent"),
            env=data.get("env", "development"),
            debug=data.get("debug", False),
            database=DatabaseConfig.from_dict(data.get("database", {})),
            scheduler=SchedulerConfig.from_dict(data.get("scheduler", {})),
            analysis=AnalysisConfig.from_dict(data.get("analysis", {})),
            threat_intel=ThreatIntelConfig.from_dict(data.get("threat_intel", {})),
            notification=NotificationConfig.from_dict(data.get("notification", {})),
            logging=LoggingConfig.from_dict(data.get("logging", {})),
            storage=StorageConfig.from_dict(data.get("storage", {})),
        )

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> "Settings":
        """加载配置，优先级: 环境变量 > 自定义配置 > 默认配置"""
        # 1. 加载默认配置
        data = {}
        if DEFAULT_CONFIG_PATH.exists():
            with open(DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}

        # 2. 合并自定义配置
        custom_path = config_path or os.environ.get("RISK_AGENT_CONFIG")
        if custom_path and Path(custom_path).exists():
            with open(custom_path, "r", encoding="utf-8") as f:
                custom = yaml.safe_load(f) or {}
            data = _deep_merge(data, custom)

        # 3. 环境变量覆盖
        data = _apply_env_overrides(data)

        settings = cls.from_dict(data)
        logger.info(f"配置加载完成 [env={settings.env}]")
        return settings


def _deep_merge(base: dict, override: dict) -> dict:
    """深度合并两个字典"""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


# 环境变量映射: ENV_VAR -> config path
_ENV_MAPPINGS = {
    "RISK_AGENT_ENV": "env",
    "RISK_AGENT_DEBUG": "debug",
    "RISK_AGENT_DB_URL": "database.url",
    "RISK_AGENT_DB_ASYNC_URL": "database.async_url",
    "RISK_AGENT_MODEL": "analysis.default_model",
    "RISK_AGENT_FALLBACK_MODEL": "analysis.fallback_model",
    "VIRUSTOTAL_API_KEY": "threat_intel.virustotal_api_key",
    "ABUSEIPDB_API_KEY": "threat_intel.abuseipdb_api_key",
    "RISK_AGENT_LOG_LEVEL": "logging.level",
    "FEISHU_WEBHOOK_URL": "notification.feishu.webhook_url",
    "FEISHU_SECRET": "notification.feishu.secret",
    "WECOM_WEBHOOK_URL": "notification.wecom.webhook_url",
    "SMTP_HOST": "notification.email.smtp_host",
    "SMTP_PORT": "notification.email.smtp_port",
    "SMTP_USERNAME": "notification.email.username",
    "SMTP_PASSWORD": "notification.email.password",
    "SMTP_FROM": "notification.email.from_addr",
}


def _apply_env_overrides(data: dict) -> dict:
    """应用环境变量覆盖"""
    for env_var, config_path in _ENV_MAPPINGS.items():
        value = os.environ.get(env_var)
        if value is not None:
            # 类型转换
            if value.lower() in ("true", "false"):
                value = value.lower() == "true"
            elif value.isdigit():
                value = int(value)
            # 设置嵌套值
            keys = config_path.split(".")
            d = data
            for key in keys[:-1]:
                d = d.setdefault(key, {})
            d[keys[-1]] = value
    return data


# 全局单例
_settings: Optional[Settings] = None


def get_settings(config_path: Optional[str] = None) -> Settings:
    """获取全局配置单例"""
    global _settings
    if _settings is None:
        _settings = Settings.load(config_path)
    return _settings


def reload_settings(config_path: Optional[str] = None) -> Settings:
    """重新加载配置"""
    global _settings
    _settings = Settings.load(config_path)
    return _settings
