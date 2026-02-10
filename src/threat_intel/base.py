"""
威胁情报基础类定义
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class IOCType(Enum):
    """IOC类型"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"


class ThreatLevel(Enum):
    """威胁级别"""
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ThreatIntelConfig:
    """威胁情报配置"""
    provider_name: str
    api_key: Optional[str] = None
    api_url: Optional[str] = None
    timeout: int = 30
    max_retries: int = 3
    enable_cache: bool = True
    cache_ttl: int = 3600  # 缓存时间（秒）
    use_mock: bool = False  # 是否使用Mock模式
    rate_limit: Optional[int] = None  # 每分钟请求限制
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatIntelResult:
    """威胁情报查询结果"""
    ioc_value: str
    ioc_type: IOCType
    provider: str
    is_malicious: bool
    threat_level: ThreatLevel
    threat_score: float  # 0-100
    threat_types: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    sources: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    timestamp: datetime = field(default_factory=datetime.now)
    cached: bool = False
    error: Optional[str] = None


class ThreatIntelProvider(ABC):
    """威胁情报提供商基类"""

    def __init__(self, config: ThreatIntelConfig):
        self.config = config
        self.provider_name = config.provider_name

    @abstractmethod
    async def query_ip(self, ip: str) -> ThreatIntelResult:
        """查询IP"""
        pass

    @abstractmethod
    async def query_domain(self, domain: str) -> ThreatIntelResult:
        """查询域名"""
        pass

    @abstractmethod
    async def query_url(self, url: str) -> ThreatIntelResult:
        """查询URL"""
        pass

    @abstractmethod
    async def query_file_hash(self, file_hash: str) -> ThreatIntelResult:
        """查询文件哈希"""
        pass

    async def query(self, ioc_value: str, ioc_type: IOCType) -> ThreatIntelResult:
        """统一查询接口"""
        if ioc_type == IOCType.IP:
            return await self.query_ip(ioc_value)
        elif ioc_type == IOCType.DOMAIN:
            return await self.query_domain(ioc_value)
        elif ioc_type == IOCType.URL:
            return await self.query_url(ioc_value)
        elif ioc_type == IOCType.FILE_HASH:
            return await self.query_file_hash(ioc_value)
        else:
            raise ValueError(f"不支持的IOC类型: {ioc_type}")

    def _create_error_result(
        self,
        ioc_value: str,
        ioc_type: IOCType,
        error: str
    ) -> ThreatIntelResult:
        """创建错误结果"""
        return ThreatIntelResult(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            provider=self.provider_name,
            is_malicious=False,
            threat_level=ThreatLevel.CLEAN,
            threat_score=0.0,
            error=error
        )
