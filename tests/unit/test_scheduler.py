"""
调度系统单元测试
"""
import pytest
import asyncio
from datetime import datetime
from src.scheduler import BaseJob, Scheduler, JobStatus, JobResult


class TestJob(BaseJob):
    """测试用的简单任务"""

    def __init__(self, job_id: str, should_fail: bool = False):
        super().__init__(
            job_id=job_id,
            name=f"Test Job {job_id}",
            description="A test job"
        )
        self.should_fail = should_fail
        self.executed = False
        self.execution_count = 0

    async def execute(self, context: dict) -> str:
        """执行任务"""
        self.executed = True
        self.execution_count += 1

        if self.should_fail:
            raise Exception("Test job failed")

        return f"Job {self.job_id} executed successfully"


class TestBaseJob:
    """测试BaseJob基类"""

    @pytest.mark.asyncio
    async def test_job_creation(self):
        """测试任务创建"""
        job = TestJob("test_1")

        assert job.job_id == "test_1"
        assert job.name == "Test Job test_1"
        assert job.max_retries == 3
        assert job.retry_count == 0
        assert not job.executed

    @pytest.mark.asyncio
    async def test_job_execution_success(self):
        """测试任务执行成功"""
        job = TestJob("test_2")
        result = await job.execute({})

        assert job.executed
        assert job.execution_count == 1
        assert result == "Job test_2 executed successfully"

    @pytest.mark.asyncio
    async def test_job_execution_failure(self):
        """测试任务执行失败"""
        job = TestJob("test_3", should_fail=True)

        with pytest.raises(Exception) as exc_info:
            await job.execute({})

        assert str(exc_info.value) == "Test job failed"
        assert job.executed
        assert job.execution_count == 1

    def test_should_retry(self):
        """测试重试判断"""
        job = TestJob("test_4")

        # 初始状态应该可以重试
        assert job.should_retry(Exception("test"))

        # 达到最大重试次数后不应该重试
        job.retry_count = 3
        assert not job.should_retry(Exception("test"))


class TestScheduler:
    """测试Scheduler调度器"""

    def test_scheduler_creation(self):
        """测试调度器创建"""
        scheduler = Scheduler()

        assert not scheduler.is_running()
        assert len(scheduler.get_all_jobs()) == 0

    def test_add_job(self):
        """测试添加任务"""
        scheduler = Scheduler()
        job = TestJob("test_5")

        # 添加间隔任务（每小时执行一次）
        job_id = scheduler.add_job(
            job,
            trigger_type="interval",
            hours=1
        )

        assert job_id == "test_5"
        assert scheduler.get_job("test_5") is not None
        assert len(scheduler.get_all_jobs()) == 1

    def test_remove_job(self):
        """测试移除任务"""
        scheduler = Scheduler()
        job = TestJob("test_6")

        scheduler.add_job(job, trigger_type="interval", hours=1)
        assert len(scheduler.get_all_jobs()) == 1

        scheduler.remove_job("test_6")
        assert len(scheduler.get_all_jobs()) == 0
        assert scheduler.get_job("test_6") is None

    def test_get_job(self):
        """测试获取任务"""
        scheduler = Scheduler()
        job = TestJob("test_7")

        scheduler.add_job(job, trigger_type="interval", hours=1)

        retrieved_job = scheduler.get_job("test_7")
        assert retrieved_job is not None
        assert retrieved_job.job_id == "test_7"

        # 获取不存在的任务
        assert scheduler.get_job("nonexistent") is None

    @pytest.mark.asyncio
    async def test_scheduler_start_stop(self):
        """测试调度器启动和停止"""
        scheduler = Scheduler()

        assert not scheduler.is_running()

        scheduler.start()
        assert scheduler.is_running()

        # 等待一小段时间
        await asyncio.sleep(0.1)

        scheduler.shutdown()
        assert not scheduler.is_running()

    @pytest.mark.asyncio
    async def test_job_execution_through_scheduler(self):
        """测试通过调度器执行任务"""
        scheduler = Scheduler()
        job = TestJob("test_8")

        # 添加一次性任务（立即执行）
        scheduler.add_job(
            job,
            trigger_type="date",
            run_date=datetime.now()
        )

        scheduler.start()

        # 等待任务执行
        await asyncio.sleep(1)

        # 检查任务是否执行
        assert job.executed
        assert job.execution_count == 1

        # 检查执行历史
        history = scheduler.get_job_history("test_8")
        assert len(history) > 0
        assert history[0].job_id == "test_8"
        assert history[0].is_success

        scheduler.shutdown()


class TestJobResult:
    """测试JobResult"""

    def test_job_result_creation(self):
        """测试任务结果创建"""
        start_time = datetime.now()
        result = JobResult(
            job_id="test_9",
            status=JobStatus.SUCCESS,
            start_time=start_time
        )

        assert result.job_id == "test_9"
        assert result.status == JobStatus.SUCCESS
        assert result.start_time == start_time
        assert result.end_time is None
        assert result.result is None
        assert result.error is None
        assert result.retry_count == 0

    def test_job_result_duration(self):
        """测试任务执行时长计算"""
        start_time = datetime.now()
        result = JobResult(
            job_id="test_10",
            status=JobStatus.SUCCESS,
            start_time=start_time
        )

        # 没有结束时间，时长应该为None
        assert result.duration is None

        # 设置结束时间
        import time
        time.sleep(0.1)
        result.end_time = datetime.now()

        # 时长应该大于0
        assert result.duration is not None
        assert result.duration > 0

    def test_job_result_status_checks(self):
        """测试任务状态检查"""
        result_success = JobResult(
            job_id="test_11",
            status=JobStatus.SUCCESS,
            start_time=datetime.now()
        )

        assert result_success.is_success
        assert not result_success.is_failed

        result_failed = JobResult(
            job_id="test_12",
            status=JobStatus.FAILED,
            start_time=datetime.now()
        )

        assert not result_failed.is_success
        assert result_failed.is_failed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
