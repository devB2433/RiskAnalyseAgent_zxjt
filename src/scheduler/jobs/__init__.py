"""
调度任务模块

提供各种预定义的调度任务
"""
from .fetch_jobs import (
    BaseFetchJob,
    DatabaseFetchJob,
    APIFetchJob,
    FileFetchJob,
    BatchFetchJob
)

from .analysis_jobs import (
    AnalysisJob,
    BatchAnalysisJob,
    DataFetchAndAnalysisJob
)

from .persistent_analysis_job import PersistentAnalysisJob

__all__ = [
    # 数据拉取Job
    "BaseFetchJob",
    "DatabaseFetchJob",
    "APIFetchJob",
    "FileFetchJob",
    "BatchFetchJob",
    # 分析Job
    "AnalysisJob",
    "BatchAnalysisJob",
    "DataFetchAndAnalysisJob",
    # 持久化分析Job
    "PersistentAnalysisJob",
]
