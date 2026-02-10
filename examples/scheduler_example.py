"""
调度系统使用示例
"""
import asyncio
from datetime import datetime
from src.scheduler import BaseJob, Scheduler


class HelloWorldJob(BaseJob):
    """简单的Hello World任务"""

    def __init__(self):
        super().__init__(
            job_id="hello_world",
            name="Hello World Job",
            description="A simple hello world job"
        )

    async def execute(self, context: dict) -> str:
        """执行任务"""
        print(f"[{datetime.now()}] Hello World!")
        return "Hello World executed"


class DataFetchJob(BaseJob):
    """模拟数据拉取任务"""

    def __init__(self):
        super().__init__(
            job_id="data_fetch",
            name="Data Fetch Job",
            description="Fetch data from source"
        )

    async def execute(self, context: dict) -> dict:
        """执行数据拉取"""
        print(f"[{datetime.now()}] Fetching data...")

        # 模拟数据拉取
        await asyncio.sleep(1)

        data = {
            "records": 100,
            "timestamp": datetime.now().isoformat()
        }

        print(f"[{datetime.now()}] Data fetched: {data}")
        return data


async def main():
    """主函数"""
    print("=" * 60)
    print("调度系统示例")
    print("=" * 60)

    # 创建调度器
    scheduler = Scheduler()

    # 示例1：添加间隔任务（每30秒执行一次）
    print("\n示例1：添加间隔任务")
    hello_job = HelloWorldJob()
    scheduler.add_job(
        hello_job,
        trigger_type="interval",
        seconds=30
    )
    print(f"已添加任务: {hello_job.name}")

    # 示例2：添加Cron任务（每小时的第0分钟执行）
    print("\n示例2：添加Cron任务")
    data_job = DataFetchJob()
    scheduler.add_job(
        data_job,
        trigger_type="cron",
        minute=0
    )
    print(f"已添加任务: {data_job.name}")

    # 示例3：添加一次性任务（立即执行）
    print("\n示例3：添加一次性任务")
    immediate_job = HelloWorldJob()
    immediate_job.job_id = "immediate_hello"
    scheduler.add_job(
        immediate_job,
        trigger_type="date",
        run_date=datetime.now()
    )
    print(f"已添加任务: {immediate_job.name}")

    # 启动调度器
    print("\n启动调度器...")
    scheduler.start()
    print(f"调度器状态: {'运行中' if scheduler.is_running() else '已停止'}")

    # 显示所有任务
    print("\n当前任务列表:")
    for job_id, job in scheduler.get_all_jobs().items():
        print(f"  - {job_id}: {job.name}")

    # 运行一段时间
    print("\n运行10秒...")
    await asyncio.sleep(10)

    # 显示执行历史
    print("\n任务执行历史:")
    history = scheduler.get_job_history(limit=10)
    for result in history:
        status = "✓" if result.is_success else "✗"
        duration = f"{result.duration:.2f}s" if result.duration else "N/A"
        print(f"  {status} {result.job_id} - {result.status.value} ({duration})")

    # 关闭调度器
    print("\n关闭调度器...")
    scheduler.shutdown()
    print("调度器已关闭")

    print("\n" + "=" * 60)
    print("示例完成")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
