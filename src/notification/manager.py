"""
通知管理器

统一管理所有通知渠道，支持告警去重、冷却期、批量发送
"""
import asyncio
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from .base import BaseNotificationChannel, NotificationMessage, NotificationLevel

logger = logging.getLogger(__name__)

# 级别优先级映射
_LEVEL_PRIORITY = {
    NotificationLevel.INFO: 0,
    NotificationLevel.LOW: 1,
    NotificationLevel.MEDIUM: 2,
    NotificationLevel.HIGH: 3,
    NotificationLevel.CRITICAL: 4,
}


class NotificationManager:
    """通知管理器"""

    def __init__(
        self,
        min_severity: str = "medium",
        cooldown_minutes: int = 30,
    ):
        self.channels: Dict[str, BaseNotificationChannel] = {}
        self.min_level = NotificationLevel(min_severity)
        self.cooldown = timedelta(minutes=cooldown_minutes)
        self._last_sent: Dict[str, datetime] = {}
        self._total_sent = 0
        self._total_filtered = 0

    def add_channel(self, channel: BaseNotificationChannel) -> None:
        """注册通知渠道"""
        self.channels[channel.name] = channel
        logger.info(f"注册通知渠道: {channel.name} (enabled={channel.enabled})")

    def remove_channel(self, name: str) -> None:
        """移除通知渠道"""
        self.channels.pop(name, None)

    def _should_send(self, message: NotificationMessage) -> bool:
        """判断是否应该发送（级别过滤 + 冷却期）"""
        # 级别过滤
        msg_priority = _LEVEL_PRIORITY.get(message.level, 0)
        min_priority = _LEVEL_PRIORITY.get(self.min_level, 0)
        if msg_priority < min_priority:
            return False

        # 冷却期检查（基于alert_id去重）
        if message.alert_id:
            last = self._last_sent.get(message.alert_id)
            if last and (datetime.now() - last) < self.cooldown:
                return False

        return True

    async def notify(self, message: NotificationMessage) -> Dict[str, bool]:
        """发送通知到所有启用的渠道"""
        if not self._should_send(message):
            self._total_filtered += 1
            logger.debug(f"通知被过滤: {message.title} (level={message.level.value})")
            return {}

        results = {}
        tasks = []

        for name, channel in self.channels.items():
            if channel.enabled:
                tasks.append((name, channel.send(message)))

        for name, coro in tasks:
            try:
                results[name] = await coro
            except Exception as e:
                logger.error(f"渠道 {name} 发送失败: {e}")
                results[name] = False

        # 更新冷却期记录
        if message.alert_id and any(results.values()):
            self._last_sent[message.alert_id] = datetime.now()
            self._total_sent += 1

        return results

    async def notify_batch(self, messages: List[NotificationMessage]) -> List[Dict[str, bool]]:
        """批量发送通知"""
        results = []
        for msg in messages:
            result = await self.notify(msg)
            results.append(result)
        return results

    @property
    def stats(self) -> Dict:
        """获取统计信息"""
        channel_stats = {name: ch.stats for name, ch in self.channels.items()}
        return {
            "total_sent": self._total_sent,
            "total_filtered": self._total_filtered,
            "channels": channel_stats,
        }

    @classmethod
    def from_config(cls, config) -> "NotificationManager":
        """从配置创建NotificationManager"""
        manager = cls(
            min_severity=config.min_severity,
            cooldown_minutes=config.cooldown_minutes,
        )

        # 飞书
        if config.feishu.enabled and config.feishu.webhook_url:
            from .feishu import FeishuChannel
            manager.add_channel(FeishuChannel(
                webhook_url=config.feishu.webhook_url,
                secret=config.feishu.secret,
                at_all_on_critical=config.feishu.at_all_on_critical,
            ))

        # 企业微信
        if config.wecom.enabled and config.wecom.webhook_url:
            from .wecom import WeComChannel
            manager.add_channel(WeComChannel(
                webhook_url=config.wecom.webhook_url,
                mentioned_list=config.wecom.mentioned_list,
                mentioned_mobile_list=config.wecom.mentioned_mobile_list,
            ))

        # 邮件
        if config.email.enabled and config.email.smtp_host:
            from .email_channel import EmailChannel
            manager.add_channel(EmailChannel(
                smtp_host=config.email.smtp_host,
                smtp_port=config.email.smtp_port,
                use_tls=config.email.smtp_use_tls,
                username=config.email.username,
                password=config.email.password,
                from_addr=config.email.from_addr,
                to_addrs=config.email.to_addrs,
                cc_addrs=config.email.cc_addrs,
            ))

        return manager
