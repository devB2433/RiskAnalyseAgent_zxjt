"""
数据接入层
提供统一的数据接入接口，支持多种数据源
"""
from .base import (
    BaseConnector,
    BaseParser,
    BaseTransformer,
    DataSource,
    DataBatch,
    ConnectorConfig
)
from .manager import DataIngestionManager
from .connectors import (
    DatabaseConnector,
    FileConnector,
    APIConnector,
    StreamConnector
)
from .parsers import (
    CSVParser,
    JSONParser,
    XMLParser,
    ExcelParser,
    LogParser
)
from .transformers import (
    SecurityLogTransformer,
    GenericTransformer
)

__all__ = [
    # Base classes
    'BaseConnector',
    'BaseParser',
    'BaseTransformer',
    'DataSource',
    'DataBatch',
    'ConnectorConfig',

    # Manager
    'DataIngestionManager',

    # Connectors
    'DatabaseConnector',
    'FileConnector',
    'APIConnector',
    'StreamConnector',

    # Parsers
    'CSVParser',
    'JSONParser',
    'XMLParser',
    'ExcelParser',
    'LogParser',

    # Transformers
    'SecurityLogTransformer',
    'GenericTransformer',
]
