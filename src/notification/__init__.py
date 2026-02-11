"""
通知系统模块

支持飞书、企业微信、邮件三种通知渠道
"""
from .base import (
    BaseNotificationChannel,
    NotificationMessage,
    NotificationLevel,
)
from .feishu import FeishuChannel
from .wecom import WeComChannel
from .email_channel import EmailChannel
from .manager import NotificationManager

__all__ = [
    "BaseNotificationChannel",
    "NotificationMessage",
    "NotificationLevel",
    "FeishuChannel",
    "WeComChannel",
    "EmailChannel",
    "NotificationManager",
]
