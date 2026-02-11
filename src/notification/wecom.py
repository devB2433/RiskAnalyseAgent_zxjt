"""
企业微信通知渠道

通过企业微信群机器人Webhook发送告警通知
文档: https://developer.work.weixin.qq.com/document/path/91770
"""
import logging
import aiohttp
from typing import List

from .base import BaseNotificationChannel, NotificationMessage, NotificationLevel

logger = logging.getLogger(__name__)


class WeComChannel(BaseNotificationChannel):
    """企业微信通知渠道"""

    def __init__(
        self,
        webhook_url: str,
        mentioned_list: List[str] = None,
        mentioned_mobile_list: List[str] = None,
        enabled: bool = True,
    ):
        super().__init__(name="wecom", enabled=enabled)
        self.webhook_url = webhook_url
        self.mentioned_list = mentioned_list or []
        self.mentioned_mobile_list = mentioned_mobile_list or []

    def _build_markdown(self, message: NotificationMessage) -> dict:
        """构建Markdown消息"""
        lines = [
            f"## {message.level_emoji} {message.title}",
            f"> **级别:** {message.level.value.upper()}",
            f"> **来源:** {message.source or 'RiskAnalyseAgent'}",
            f"> **时间:** {message.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            message.content,
        ]

        if message.details:
            lines.append("")
            for k, v in message.details.items():
                lines.append(f"- **{k}:** {v}")

        if message.tags:
            lines.append(f"\n**标签:** {', '.join(message.tags)}")

        if message.alert_id:
            lines.append(f"\n`Alert ID: {message.alert_id}`")

        # @提醒
        mentions = []
        is_critical = message.level in (NotificationLevel.HIGH, NotificationLevel.CRITICAL)
        if is_critical and self.mentioned_list:
            mentions = self.mentioned_list
        if is_critical and self.mentioned_mobile_list:
            for mobile in self.mentioned_mobile_list:
                lines.append(f"<@{mobile}>")

        content = "\n".join(lines)

        payload = {
            "msgtype": "markdown",
            "markdown": {"content": content},
        }
        if mentions:
            payload["markdown"]["mentioned_list"] = mentions

        return payload

    async def send(self, message: NotificationMessage) -> bool:
        """发送企业微信通知"""
        if not self.enabled:
            return False

        try:
            payload = self._build_markdown(message)

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    result = await resp.json()
                    if result.get("errcode") == 0:
                        self._send_count += 1
                        logger.info(f"企业微信通知发送成功: {message.title}")
                        return True
                    else:
                        self._error_count += 1
                        logger.error(f"企业微信通知发送失败: {result}")
                        return False

        except Exception as e:
            self._error_count += 1
            logger.error(f"企业微信通知发送异常: {e}")
            return False
