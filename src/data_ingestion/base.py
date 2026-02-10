"""
数据接入层基础类定义
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, AsyncIterator, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class DataSourceType(Enum):
    """数据源类型"""
    DATABASE = "database"
    FILE = "file"
    API = "api"
    STREAM = "stream"
    CLOUD_STORAGE = "cloud_storage"


class DataFormat(Enum):
    """数据格式"""
    CSV = "csv"
    JSON = "json"
    XML = "xml"
    EXCEL = "excel"
    PARQUET = "parquet"
    LOG = "log"
    RAW = "raw"


@dataclass
class ConnectorConfig:
    """连接器配置"""
    source_type: DataSourceType
    connection_params: Dict[str, Any] = field(default_factory=dict)
    retry_count: int = 3
    timeout: int = 30
    batch_size: int = 1000
    enable_cache: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataSource:
    """数据源定义"""
    name: str
    source_type: DataSourceType
    format: DataFormat
    location: str  # 文件路径、数据库连接字符串、API端点等
    config: Optional[ConnectorConfig] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DataBatch:
    """数据批次"""
    source: DataSource
    data: List[Dict[str, Any]]
    batch_id: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.data)


class BaseConnector(ABC):
    """连接器基类"""

    def __init__(self, config: ConnectorConfig):
        self.config = config
        self.is_connected = False
        self._connection = None

    @abstractmethod
    async def connect(self) -> bool:
        """建立连接"""
        pass

    @abstractmethod
    async def disconnect(self) -> bool:
        """断开连接"""
        pass

    @abstractmethod
    async def fetch_data(
        self,
        query: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None
    ) -> DataBatch:
        """获取数据"""
        pass

    @abstractmethod
    async def fetch_stream(
        self,
        query: Optional[Dict[str, Any]] = None
    ) -> AsyncIterator[DataBatch]:
        """流式获取数据"""
        pass

    async def test_connection(self) -> bool:
        """测试连接"""
        try:
            await self.connect()
            await self.disconnect()
            return True
        except Exception:
            return False

    async def __aenter__(self):
        """异步上下文管理器入口"""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器退出"""
        await self.disconnect()


class BaseParser(ABC):
    """解析器基类"""

    def __init__(self, format: DataFormat):
        self.format = format

    @abstractmethod
    async def parse(
        self,
        raw_data: Union[str, bytes, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """解析数据"""
        pass

    @abstractmethod
    def validate_format(self, raw_data: Union[str, bytes, Any]) -> bool:
        """验证数据格式"""
        pass


class BaseTransformer(ABC):
    """转换器基类"""

    @abstractmethod
    async def transform(
        self,
        data: List[Dict[str, Any]],
        schema: Optional[Dict[str, Any]] = None
    ) -> List[Any]:
        """转换数据到目标格式"""
        pass

    @abstractmethod
    def validate_schema(self, data: Dict[str, Any]) -> bool:
        """验证数据模式"""
        pass

    def transform_single(self, item: Dict[str, Any]) -> Any:
        """转换单条数据"""
        raise NotImplementedError("子类需要实现此方法")
