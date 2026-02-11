"""
飞书通知渠道

通过飞书自定义机器人Webhook发送告警通知
文档: https://open.feishu.cn/document/client-docs/bot-v3/add-custom-bot
"""
import json
import time
import hmac
import hashlib
import base64
import logging
import aiohttp
from typing import Optional

from .base import BaseNotificationChannel, NotificationMessage, NotificationLevel

logger = logging.getLogger(__name__)


class FeishuChannel(BaseNotificationChannel):
    """飞书通知渠道"""

    def __init__(
        self,
        webhook_url: str,
        secret: str = "",
        at_all_on_critical: bool = True,
        enabled: bool = True,
    ):
        super().__init__(name="feishu", enabled=enabled)
        self.webhook_url = webhook_url
        self.secret = secret
        self.at_all_on_critical = at_all_on_critical

    def _gen_sign(self) -> tuple:
        """生成签名"""
        if not self.secret:
            return {}, 0
        timestamp = str(int(time.time()))
        string_to_sign = f"{timestamp}\n{self.secret}"
        hmac_code = hmac.new(
            string_to_sign.encode("utf-8"),
            digestmod=hashlib.sha256,
        ).digest()
        sign = base64.b64encode(hmac_code).decode("utf-8")
        return sign, timestamp

    def _build_card(self, message: NotificationMessage) -> dict:
        """构建飞书卡片消息"""
        level_color = {
            NotificationLevel.INFO: "blue",
            NotificationLevel.LOW: "green",
            NotificationLevel.MEDIUM: "yellow",
            NotificationLevel.HIGH: "orange",
            NotificationLevel.CRITICAL: "red",
        }.get(message.level, "grey")

        elements = [
            {
                "tag": "div",
                "text": {
                    "tag": "lark_md",
                    "content": message.content,
                },
            },
            {
                "tag": "div",
                "text": {
                    "tag": "lark_md",
                    "content": (
                        f"**级别:** {message.level_emoji} {message.level.value.upper()}\n"
                        f"**来源:** {message.source or 'RiskAnalyseAgent'}\n"
                        f"**时间:** {message.timestamp.strftime('%Y-%m-%d %H:%M:%S')}"
                    ),
                },
            },
        ]

        # 详情字段
        if message.details:
            detail_lines = [f"**{k}:** {v}" for k, v in message.details.items()]
            elements.append({
                "tag": "div",
                "text": {"tag": "lark_md", "content": "\n".join(detail_lines)},
            })

        # 标签
        if message.tags:
            elements.append({
                "tag": "div",
                "text": {"tag": "lark_md", "content": "**标签:** " + ", ".join(message.tags)},
            })

        # 分割线
        elements.append({"tag": "hr"})
        elements.append({
            "tag": "note",
            "elements": [{"tag": "plain_text", "content": f"Alert ID: {message.alert_id or 'N/A'}"}],
        })

        card = {
            "header": {
                "title": {"tag": "plain_text", "content": message.title},
                "template": level_color,
            },
            "elements": elements,
        }
        return card

    async def send(self, message: NotificationMessage) -> bool:
        """发送飞书通知"""
        if not self.enabled:
            return False

        try:
            payload = {
                "msg_type": "interactive",
                "card": self._build_card(message),
            }

            # 签名
            if self.secret:
                sign, timestamp = self._gen_sign()
                payload["timestamp"] = timestamp
                payload["sign"] = sign

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    result = await resp.json()
                    if result.get("code") == 0:
                        self._send_count += 1
                        logger.info(f"飞书通知发送成功: {message.title}")
                        return True
                    else:
                        self._error_count += 1
                        logger.error(f"飞书通知发送失败: {result}")
                        return False

        except Exception as e:
            self._error_count += 1
            logger.error(f"飞书通知发送异常: {e}")
            return False
