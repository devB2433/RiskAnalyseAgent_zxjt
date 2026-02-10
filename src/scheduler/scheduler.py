"""
调度器主类 - 基于APScheduler实现
"""
import asyncio
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.job import Job as APJob

from .base import BaseJob, JobExecutor, JobResult, JobStatus


class Scheduler:
    """
    调度器主类

    基于APScheduler实现，支持Cron表达式、间隔触发和一次性任务
    """

    def __init__(self):
        """初始化调度器"""
        self.scheduler = AsyncIOScheduler()
        self.executor = JobExecutor()
        self.jobs: Dict[str, BaseJob] = {}
        self.job_history: List[JobResult] = []
        self._running = False

    def start(self):
        """启动调度器"""
        if not self._running:
            self.scheduler.start()
            self._running = True

    def shutdown(self, wait: bool = True):
        """
        关闭调度器

        Args:
            wait: 是否等待正在执行的任务完成
        """
        if self._running:
            self.scheduler.shutdown(wait=wait)
            self._running = False

    def add_job(
        self,
        job: BaseJob,
        trigger_type: str = "cron",
        **trigger_kwargs
    ) -> str:
        """
        添加任务

        Args:
            job: 要添加的任务
            trigger_type: 触发器类型 ("cron", "interval", "date")
            **trigger_kwargs: 触发器参数

        Returns:
            任务ID

        Examples:
            # Cron触发器
            scheduler.add_job(
                job,
                trigger_type="cron",
                hour=0,
                minute=0
            )

            # 间隔触发器
            scheduler.add_job(
                job,
                trigger_type="interval",
                minutes=30
            )

            # 一次性任务
            scheduler.add_job(
                job,
                trigger_type="date",
                run_date=datetime(2024, 1, 1, 0, 0, 0)
            )
        """
        # 保存任务
        self.jobs[job.job_id] = job

        # 创建触发器
        if trigger_type == "cron":
            trigger = CronTrigger(**trigger_kwargs)
        elif trigger_type == "interval":
            trigger = IntervalTrigger(**trigger_kwargs)
        elif trigger_type == "date":
            trigger = DateTrigger(**trigger_kwargs)
        else:
            raise ValueError(f"Unsupported trigger type: {trigger_type}")

        # 添加到APScheduler
        self.scheduler.add_job(
            func=self._execute_job_wrapper,
            trigger=trigger,
            args=[job.job_id],
            id=job.job_id,
            name=job.name,
            replace_existing=True
        )

        return job.job_id

    def remove_job(self, job_id: str):
        """
        移除任务

        Args:
            job_id: 任务ID
        """
        if job_id in self.jobs:
            del self.jobs[job_id]

        try:
            self.scheduler.remove_job(job_id)
        except Exception:
            pass

    def pause_job(self, job_id: str):
        """
        暂停任务

        Args:
            job_id: 任务ID
        """
        self.scheduler.pause_job(job_id)

    def resume_job(self, job_id: str):
        """
        恢复任务

        Args:
            job_id: 任务ID
        """
        self.scheduler.resume_job(job_id)

    def get_job(self, job_id: str) -> Optional[BaseJob]:
        """
        获取任务

        Args:
            job_id: 任务ID

        Returns:
            任务对象，如果不存在则返回None
        """
        return self.jobs.get(job_id)

    def get_all_jobs(self) -> Dict[str, BaseJob]:
        """获取所有任务"""
        return self.jobs.copy()

    def get_job_history(
        self,
        job_id: Optional[str] = None,
        limit: int = 100
    ) -> List[JobResult]:
        """
        获取任务执行历史

        Args:
            job_id: 任务ID，如果为None则返回所有任务的历史
            limit: 返回的最大记录数

        Returns:
            任务执行历史列表
        """
        if job_id:
            history = [h for h in self.job_history if h.job_id == job_id]
        else:
            history = self.job_history

        return history[-limit:]

    async def _execute_job_wrapper(self, job_id: str):
        """
        任务执行包装器

        Args:
            job_id: 任务ID
        """
        job = self.jobs.get(job_id)
        if not job:
            return

        # 执行任务
        result = await self.executor.execute_job(job)

        # 保存执行历史
        self.job_history.append(result)

        # 限制历史记录数量
        if len(self.job_history) > 10000:
            self.job_history = self.job_history[-5000:]

        # 如果需要重试，重新调度
        if result.status == JobStatus.RETRYING:
            self.scheduler.add_job(
                func=self._execute_job_wrapper,
                trigger=DateTrigger(
                    run_date=datetime.now().timestamp() + job.retry_delay
                ),
                args=[job_id],
                id=f"{job_id}_retry_{result.retry_count}"
            )

    def is_running(self) -> bool:
        """检查调度器是否正在运行"""
        return self._running

    def get_running_jobs(self) -> Dict[str, BaseJob]:
        """获取正在运行的任务"""
        return self.executor.get_running_jobs()

    def __repr__(self) -> str:
        return f"<Scheduler(running={self._running}, jobs={len(self.jobs)})>"
