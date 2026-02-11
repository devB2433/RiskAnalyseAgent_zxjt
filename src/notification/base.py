"""
通知渠道基类

定义通知渠道的抽象接口和通用数据结构
"""
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class NotificationLevel(str, Enum):
    """通知级别"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class NotificationMessage:
    """通知消息"""
    title: str
    content: str
    level: NotificationLevel = NotificationLevel.MEDIUM
    source: str = ""
    alert_id: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    details: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    @property
    def level_emoji(self) -> str:
        return {
            NotificationLevel.INFO: "ℹ️",
            NotificationLevel.LOW: "🟢",
            NotificationLevel.MEDIUM: "🟡",
            NotificationLevel.HIGH: "🟠",
            NotificationLevel.CRITICAL: "🔴",
        }.get(self.level, "⚪")


class BaseNotificationChannel(ABC):
    """通知渠道抽象基类"""

    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled
        self._send_count = 0
        self._error_count = 0

    @abstractmethod
    async def send(self, message: NotificationMessage) -> bool:
        """发送通知，返回是否成功"""
        pass

    async def send_batch(self, messages: List[NotificationMessage]) -> Dict[str, bool]:
        """批量发送通知"""
        results = {}
        for msg in messages:
            key = msg.alert_id or msg.title
            results[key] = await self.send(msg)
        return results

    @property
    def stats(self) -> Dict[str, int]:
        return {"sent": self._send_count, "errors": self._error_count}
