"""
调度系统基础类和接口定义
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Callable
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field


class JobStatus(Enum):
    """任务状态枚举"""
    PENDING = "pending"      # 等待执行
    RUNNING = "running"      # 正在执行
    SUCCESS = "success"      # 执行成功
    FAILED = "failed"        # 执行失败
    RETRYING = "retrying"    # 重试中
    CANCELLED = "cancelled"  # 已取消


@dataclass
class JobResult:
    """任务执行结果"""
    job_id: str
    status: JobStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    result: Optional[Any] = None
    error: Optional[str] = None
    retry_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration(self) -> Optional[float]:
        """执行时长（秒）"""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    @property
    def is_success(self) -> bool:
        """是否执行成功"""
        return self.status == JobStatus.SUCCESS

    @property
    def is_failed(self) -> bool:
        """是否执行失败"""
        return self.status == JobStatus.FAILED


class BaseJob(ABC):
    """
    任务基类

    所有调度任务都应该继承此类并实现execute方法
    """

    def __init__(
        self,
        job_id: str,
        name: str,
        description: str = "",
        max_retries: int = 3,
        retry_delay: int = 60,
        timeout: int = 3600
    ):
        """
        初始化任务

        Args:
            job_id: 任务唯一标识
            name: 任务名称
            description: 任务描述
            max_retries: 最大重试次数
            retry_delay: 重试延迟（秒）
            timeout: 超时时间（秒）
        """
        self.job_id = job_id
        self.name = name
        self.description = description
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.timeout = timeout
        self.retry_count = 0

    @abstractmethod
    async def execute(self, context: Dict[str, Any]) -> Any:
        """
        执行任务

        Args:
            context: 执行上下文，包含任务执行所需的参数

        Returns:
            任务执行结果

        Raises:
            Exception: 任务执行失败时抛出异常
        """
        pass

    async def on_success(self, result: Any, context: Dict[str, Any]):
        """
        任务执行成功时的回调

        Args:
            result: 任务执行结果
            context: 执行上下文
        """
        pass

    async def on_failure(self, error: Exception, context: Dict[str, Any]):
        """
        任务执行失败时的回调

        Args:
            error: 异常信息
            context: 执行上下文
        """
        pass

    async def on_retry(self, error: Exception, retry_count: int, context: Dict[str, Any]):
        """
        任务重试时的回调

        Args:
            error: 异常信息
            retry_count: 当前重试次数
            context: 执行上下文
        """
        pass

    def should_retry(self, error: Exception) -> bool:
        """
        判断是否应该重试

        Args:
            error: 异常信息

        Returns:
            是否应该重试
        """
        return self.retry_count < self.max_retries

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(id={self.job_id}, name={self.name})>"


class JobExecutor:
    """
    任务执行器

    负责执行任务并处理重试逻辑
    """

    def __init__(self):
        self.running_jobs: Dict[str, BaseJob] = {}

    async def execute_job(
        self,
        job: BaseJob,
        context: Optional[Dict[str, Any]] = None
    ) -> JobResult:
        """
        执行任务

        Args:
            job: 要执行的任务
            context: 执行上下文

        Returns:
            任务执行结果
        """
        if context is None:
            context = {}

        job_result = JobResult(
            job_id=job.job_id,
            status=JobStatus.PENDING,
            start_time=datetime.now()
        )

        # 标记任务为运行中
        self.running_jobs[job.job_id] = job
        job_result.status = JobStatus.RUNNING

        try:
            # 执行任务
            result = await job.execute(context)

            # 执行成功
            job_result.status = JobStatus.SUCCESS
            job_result.result = result
            job_result.end_time = datetime.now()

            # 调用成功回调
            await job.on_success(result, context)

        except Exception as e:
            # 执行失败
            job_result.error = str(e)
            job_result.retry_count = job.retry_count

            # 判断是否需要重试
            if job.should_retry(e):
                job.retry_count += 1
                job_result.status = JobStatus.RETRYING

                # 调用重试回调
                await job.on_retry(e, job.retry_count, context)
            else:
                job_result.status = JobStatus.FAILED
                job_result.end_time = datetime.now()

                # 调用失败回调
                await job.on_failure(e, context)

        finally:
            # 移除运行中的任务
            if job.job_id in self.running_jobs:
                del self.running_jobs[job.job_id]

        return job_result

    def is_job_running(self, job_id: str) -> bool:
        """检查任务是否正在运行"""
        return job_id in self.running_jobs

    def get_running_jobs(self) -> Dict[str, BaseJob]:
        """获取所有正在运行的任务"""
        return self.running_jobs.copy()
