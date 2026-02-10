"""
完整的数据拉取和分析示例

演示如何使用调度系统自动拉取数据并执行安全分析
"""
import asyncio
import json
from datetime import datetime
from pathlib import Path

from src.scheduler import Scheduler
from src.scheduler.jobs import (
    FileFetchJob,
    AnalysisJob,
    DataFetchAndAnalysisJob
)
from security_analysis.architecture_v2 import AnalysisType


async def create_sample_logs():
    """创建示例日志文件"""
    sample_logs = [
        {
            "log_type": "firewall",
            "timestamp": datetime.now().isoformat(),
            "source_ip": "192.168.1.100",
            "dest_ip": "10.0.0.5",
            "source_port": 54321,
            "dest_port": 443,
            "protocol": "TCP",
            "action": "ALLOW",
            "raw_data": {}
        },
        {
            "log_type": "ids",
            "timestamp": datetime.now().isoformat(),
            "source_ip": "192.168.1.100",
            "dest_ip": "8.8.8.8",
            "source_port": 12345,
            "dest_port": 53,
            "protocol": "UDP",
            "action": "ALERT",
            "raw_data": {"alert_type": "suspicious_dns"}
        },
        {
            "log_type": "firewall",
            "timestamp": datetime.now().isoformat(),
            "source_ip": "192.168.1.50",
            "dest_ip": "192.168.1.100",
            "source_port": 22,
            "dest_port": 22,
            "protocol": "TCP",
            "action": "ALLOW",
            "raw_data": {}
        }
    ]

    # 创建临时目录
    temp_dir = Path("temp_data")
    temp_dir.mkdir(exist_ok=True)

    # 保存日志文件
    log_file = temp_dir / "security_logs.json"
    with open(log_file, "w") as f:
        json.dump(sample_logs, f, indent=2)

    print(f"创建示例日志文件: {log_file}")
    return str(log_file)


async def example_1_simple_fetch_and_analysis():
    """示例1：简单的数据拉取和分析"""
    print("\n" + "=" * 60)
    print("示例1：简单的数据拉取和分析")
    print("=" * 60)

    # 创建示例日志
    log_file = await create_sample_logs()

    # 创建调度器
    scheduler = Scheduler()

    # 创建数据拉取Job
    fetch_job = FileFetchJob(
        job_id="fetch_logs",
        file_path=log_file,
        file_type="json",
        name="拉取安全日志"
    )

    # 创建分析Job
    analysis_job = AnalysisJob(
        job_id="analyze_compromised_host",
        analysis_type=AnalysisType.COMPROMISED_HOST.value,
        use_mock=True,
        name="失陷主机检测"
    )

    # 添加任务（立即执行）
    scheduler.add_job(fetch_job, trigger_type="date", run_date=datetime.now())

    # 启动调度器
    scheduler.start()

    # 等待拉取完成
    await asyncio.sleep(2)

    # 获取拉取结果
    fetch_history = scheduler.get_job_history("fetch_logs")
    if fetch_history and fetch_history[0].is_success:
        fetch_result = fetch_history[0].result

        # 使用拉取的数据执行分析
        context = {"logs": fetch_result["data"]}
        analysis_result = await analysis_job.execute(context)

        print("\n分析结果:")
        print(f"  - 分析类型: {analysis_result['analysis_type']}")
        print(f"  - 日志数量: {analysis_result['log_count']}")
        print(f"  - 置信度: {analysis_result['confidence']}")
        print(f"  - 执行时长: {analysis_result['duration']:.2f}秒")

    scheduler.shutdown()


async def example_2_combined_job():
    """示例2：使用组合Job自动拉取和分析"""
    print("\n" + "=" * 60)
    print("示例2：使用组合Job自动拉取和分析")
    print("=" * 60)

    # 创建示例日志
    log_file = await create_sample_logs()

    # 创建调度器
    scheduler = Scheduler()

    # 创建数据拉取Job
    fetch_job = FileFetchJob(
        job_id="fetch_logs_2",
        file_path=log_file,
        file_type="json"
    )

    # 创建组合Job（拉取+分析）
    combined_job = DataFetchAndAnalysisJob(
        job_id="fetch_and_analyze",
        fetch_job=fetch_job,
        analysis_types=[
            AnalysisType.COMPROMISED_HOST.value,
            AnalysisType.MALWARE_DETECTION.value
        ],
        use_mock=True,
        name="拉取并分析安全日志"
    )

    # 添加任务（立即执行）
    scheduler.add_job(combined_job, trigger_type="date", run_date=datetime.now())

    # 启动调度器
    scheduler.start()

    # 等待执行完成
    await asyncio.sleep(5)

    # 查看执行历史
    history = scheduler.get_job_history("fetch_and_analyze")
    if history and history[0].is_success:
        result = history[0].result
        print("\n执行结果:")
        print(f"  - 拉取记录数: {result['fetch_result']['record_count']}")
        print(f"  - 分析类型数: {len(result['analysis_types'])}")
        print(f"  - 分析时长: {result['analysis_duration']:.2f}秒")

        for analysis_type, analysis_result in result['analysis_results'].items():
            print(f"  - {analysis_type}: 置信度 {analysis_result.confidence}")

    scheduler.shutdown()


async def example_3_scheduled_analysis():
    """示例3：定时自动分析"""
    print("\n" + "=" * 60)
    print("示例3：定时自动分析（每30秒执行一次）")
    print("=" * 60)

    # 创建示例日志
    log_file = await create_sample_logs()

    # 创建调度器
    scheduler = Scheduler()

    # 创建数据拉取Job
    fetch_job = FileFetchJob(
        job_id="fetch_logs_3",
        file_path=log_file,
        file_type="json"
    )

    # 创建组合Job
    combined_job = DataFetchAndAnalysisJob(
        job_id="scheduled_analysis",
        fetch_job=fetch_job,
        analysis_types=[AnalysisType.COMPROMISED_HOST.value],
        use_mock=True,
        name="定时安全分析"
    )

    # 添加定时任务（每30秒执行一次）
    scheduler.add_job(
        combined_job,
        trigger_type="interval",
        seconds=30
    )

    # 启动调度器
    scheduler.start()

    print("\n调度器已启动，将每30秒执行一次分析...")
    print("运行60秒后停止...")

    # 运行60秒
    await asyncio.sleep(60)

    # 查看执行历史
    history = scheduler.get_job_history("scheduled_analysis")
    print(f"\n共执行了 {len(history)} 次分析")

    for i, result in enumerate(history, 1):
        status = "✓" if result.is_success else "✗"
        duration = f"{result.duration:.2f}s" if result.duration else "N/A"
        print(f"  {status} 第{i}次执行 - {result.status.value} ({duration})")

    scheduler.shutdown()


async def example_4_cron_scheduled():
    """示例4：使用Cron表达式定时分析"""
    print("\n" + "=" * 60)
    print("示例4：使用Cron表达式定时分析")
    print("=" * 60)

    # 创建示例日志
    log_file = await create_sample_logs()

    # 创建调度器
    scheduler = Scheduler()

    # 创建数据拉取Job
    fetch_job = FileFetchJob(
        job_id="fetch_logs_4",
        file_path=log_file,
        file_type="json"
    )

    # 创建组合Job
    combined_job = DataFetchAndAnalysisJob(
        job_id="cron_analysis",
        fetch_job=fetch_job,
        analysis_types=[
            AnalysisType.COMPROMISED_HOST.value,
            AnalysisType.MALWARE_DETECTION.value,
            AnalysisType.PHISHING_DETECTION.value
        ],
        use_mock=True,
        name="Cron定时分析"
    )

    # 添加Cron任务（每小时的第0分钟执行）
    # 注意：这里为了演示，我们使用每分钟执行
    scheduler.add_job(
        combined_job,
        trigger_type="cron",
        minute="*"  # 每分钟执行
    )

    print("\n已配置Cron任务：每分钟执行一次")
    print("实际生产环境可以配置为：")
    print("  - 每小时: minute=0")
    print("  - 每天凌晨: hour=0, minute=0")
    print("  - 每周一: day_of_week='mon', hour=0, minute=0")

    # 启动调度器
    scheduler.start()

    print("\n调度器已启动，运行3分钟后停止...")
    await asyncio.sleep(180)

    # 查看执行历史
    history = scheduler.get_job_history("cron_analysis")
    print(f"\n共执行了 {len(history)} 次分析")

    scheduler.shutdown()


async def main():
    """主函数"""
    print("=" * 60)
    print("数据拉取和分析完整示例")
    print("=" * 60)

    # 运行示例
    await example_1_simple_fetch_and_analysis()
    await example_2_combined_job()
    await example_3_scheduled_analysis()
    # await example_4_cron_scheduled()  # 这个示例需要运行较长时间

    print("\n" + "=" * 60)
    print("所有示例完成！")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
