"""
存储系统模块

提供数据库模型、连接管理和数据访问层
"""
from .models import (
    Base,
    AnalysisResult,
    Alert,
    TaskHistory,
    IOCRecord,
    SystemConfig,
    AnalysisStatus,
    SeverityLevel
)

from .database import (
    Database,
    AsyncDatabase,
    get_database,
    get_async_database
)

from .repository import (
    AnalysisResultRepository,
    AlertRepository,
    TaskHistoryRepository,
    IOCRecordRepository,
    SystemConfigRepository
)

from .service import StorageService

__all__ = [
    # Models
    "Base",
    "AnalysisResult",
    "Alert",
    "TaskHistory",
    "IOCRecord",
    "SystemConfig",
    "AnalysisStatus",
    "SeverityLevel",
    # Database
    "Database",
    "AsyncDatabase",
    "get_database",
    "get_async_database",
    # Repositories
    "AnalysisResultRepository",
    "AlertRepository",
    "TaskHistoryRepository",
    "IOCRecordRepository",
    "SystemConfigRepository",
]
