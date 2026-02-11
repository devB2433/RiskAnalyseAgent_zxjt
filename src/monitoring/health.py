"""
健康检查

检查系统各组件运行状态
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Optional, Any

logger = logging.getLogger(__name__)


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class ComponentHealth:
    name: str
    status: HealthStatus = HealthStatus.HEALTHY
    message: str = ""
    checked_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "checked_at": self.checked_at.isoformat() if self.checked_at else None,
        }


class HealthChecker:
    """系统健康检查器"""

    def __init__(self, db=None, scheduler=None):
        self._db = db
        self._scheduler = scheduler

    def check_database(self) -> ComponentHealth:
        """检查数据库连接"""
        h = ComponentHealth(name="database", checked_at=datetime.now())
        if not self._db:
            h.status = HealthStatus.UNHEALTHY
            h.message = "数据库未初始化"
            return h
        try:
            with self._db.get_session() as session:
                session.execute("SELECT 1")
            h.message = "连接正常"
        except Exception as e:
            h.status = HealthStatus.UNHEALTHY
            h.message = f"连接失败: {e}"
        return h

    def check_scheduler(self) -> ComponentHealth:
        """检查调度器状态"""
        h = ComponentHealth(name="scheduler", checked_at=datetime.now())
        if not self._scheduler:
            h.status = HealthStatus.UNHEALTHY
            h.message = "调度器未初始化"
            return h
        if self._scheduler.running:
            h.message = f"运行中, {len(self._scheduler.jobs)}个任务"
        else:
            h.status = HealthStatus.DEGRADED
            h.message = "调度器未运行"
        return h

    def check_all(self) -> Dict[str, Any]:
        """执行全部健康检查"""
        components = [
            self.check_database(),
            self.check_scheduler(),
        ]
        overall = HealthStatus.HEALTHY
        for c in components:
            if c.status == HealthStatus.UNHEALTHY:
                overall = HealthStatus.UNHEALTHY
                break
            if c.status == HealthStatus.DEGRADED:
                overall = HealthStatus.DEGRADED

        return {
            "status": overall.value,
            "checked_at": datetime.now().isoformat(),
            "components": {c.name: c.to_dict() for c in components},
        }
