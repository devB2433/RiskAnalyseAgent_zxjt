"""
RiskAnalyseAgent 主应用

端到端安全分析管道：
配置加载 → 日志初始化 → 数据库初始化 → 调度器启动 → 分析 → 存储 → 告警通知

完全自动化运行，无需人工干预
"""
import asyncio
import logging
import signal
import sys
from datetime import datetime
from typing import Optional

from src.config import get_settings, Settings
from src.logging_config import setup_logging_from_config, get_logger
from src.storage import (
    Database, get_database,
    StorageService,
    AnalysisResult, Alert, AnalysisStatus, SeverityLevel,
)
from src.notification import (
    NotificationManager,
    NotificationMessage,
    NotificationLevel,
)
from src.scheduler import Scheduler
from src.scheduler.jobs import PersistentAnalysisJob

logger = get_logger(__name__)


class RiskAnalyseApp:
    """主应用类"""

    def __init__(self, config_path: Optional[str] = None):
        self.settings: Optional[Settings] = None
        self.db: Optional[Database] = None
        self.storage: Optional[StorageService] = None
        self.notification_mgr: Optional[NotificationManager] = None
        self.scheduler: Optional[Scheduler] = None
        self._running = False
        self._config_path = config_path

    async def initialize(self) -> None:
        """初始化所有组件"""
        # 1. 加载配置
        self.settings = get_settings(self._config_path)
        logger.info(f"应用配置加载完成 [env={self.settings.env}]")

        # 2. 初始化日志
        setup_logging_from_config(self.settings.logging)

        # 3. 初始化数据库
        self.db = get_database(self.settings.database.url)
        self.db.create_tables()
        self.storage = StorageService(self.db)
        logger.info("数据库初始化完成")

        # 4. 初始化通知管理器
        self.notification_mgr = NotificationManager.from_config(self.settings.notification)
        logger.info(f"通知管理器初始化完成 [channels={list(self.notification_mgr.channels.keys())}]")

        # 5. 初始化调度器
        self.scheduler = Scheduler(
            timezone=self.settings.scheduler.timezone,
            max_workers=self.settings.scheduler.max_workers,
        )
        logger.info("调度器初始化完成")

    def _setup_default_jobs(self) -> None:
        """配置默认调度任务"""
        if not self.scheduler or not self.settings:
            return

        # 定期安全分析任务（每小时执行）
        for analyzer_type in self.settings.analysis.enabled_analyzers:
            job = PersistentAnalysisJob(
                job_id=f"analysis_{analyzer_type}",
                analysis_type=analyzer_type,
                db_url=self.settings.database.url,
                confidence_threshold=self.settings.analysis.alert_threshold,
            )
            self.scheduler.add_job(
                job=job,
                trigger_type="interval",
                hours=1,
                job_id=f"analysis_{analyzer_type}",
            )
            logger.info(f"注册分析任务: {analyzer_type}")

    async def _process_alerts(self) -> None:
        """处理未通知的告警"""
        if not self.storage or not self.notification_mgr:
            return

        try:
            with self.db.get_session() as session:
                from src.storage.repository import AlertRepository
                alert_repo = AlertRepository(session)
                unnotified = alert_repo.get_unnotified()

                for alert in unnotified:
                    msg = NotificationMessage(
                        title=f"安全告警: {alert.alert_type}",
                        content=alert.description or "检测到安全威胁",
                        level=NotificationLevel(alert.severity.value),
                        source=alert.source or "RiskAnalyseAgent",
                        alert_id=str(alert.id),
                        details=alert.details if isinstance(alert.details, dict) else {},
                    )
                    results = await self.notification_mgr.notify(msg)
                    if any(results.values()):
                        alert_repo.mark_as_notified(alert.id)
                        logger.info(f"告警已通知: {alert.id} -> {results}")

        except Exception as e:
            logger.error(f"处理告警通知失败: {e}")

    async def _alert_check_loop(self) -> None:
        """告警检查循环"""
        interval = self.settings.notification.batch_interval_seconds if self.settings else 60
        while self._running:
            await self._process_alerts()
            await asyncio.sleep(interval)

    async def _cleanup_loop(self) -> None:
        """数据清理循环（每天执行一次）"""
        while self._running:
            await asyncio.sleep(86400)  # 24小时
            if self.storage and self.settings:
                try:
                    self.storage.cleanup_old_data(self.settings.storage.data_retention_days)
                    logger.info("数据清理完成")
                except Exception as e:
                    logger.error(f"数据清理失败: {e}")

    async def run(self) -> None:
        """启动应用"""
        await self.initialize()
        self._setup_default_jobs()
        self._running = True

        logger.info("=" * 60)
        logger.info("RiskAnalyseAgent 启动完成")
        logger.info(f"环境: {self.settings.env}")
        logger.info(f"分析器: {self.settings.analysis.enabled_analyzers}")
        logger.info(f"通知渠道: {list(self.notification_mgr.channels.keys())}")
        logger.info("=" * 60)

        # 启动调度器
        self.scheduler.start()

        # 启动后台任务
        tasks = [
            asyncio.create_task(self._alert_check_loop()),
            asyncio.create_task(self._cleanup_loop()),
        ]

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("应用正在关闭...")
        finally:
            await self.shutdown()

    async def shutdown(self) -> None:
        """优雅关闭"""
        self._running = False
        if self.scheduler:
            self.scheduler.stop()
        logger.info("RiskAnalyseAgent 已关闭")


def main(config_path: Optional[str] = None):
    """入口函数"""
    app = RiskAnalyseApp(config_path)

    def signal_handler(sig, frame):
        logger.info(f"收到信号 {sig}，正在关闭...")
        app._running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    asyncio.run(app.run())


if __name__ == "__main__":
    config = sys.argv[1] if len(sys.argv) > 1 else None
    main(config)
