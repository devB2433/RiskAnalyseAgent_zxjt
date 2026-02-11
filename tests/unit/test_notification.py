"""
通知系统单元测试
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime

from src.notification.base import (
    NotificationMessage, NotificationLevel, BaseNotificationChannel,
)
from src.notification.manager import NotificationManager


class TestNotificationMessage:
    def test_create_message(self):
        msg = NotificationMessage(
            title="Test Alert",
            content="Something happened",
            level=NotificationLevel.HIGH,
        )
        assert msg.title == "Test Alert"
        assert msg.level == NotificationLevel.HIGH

    def test_level_emoji(self):
        msg = NotificationMessage(title="t", content="c", level=NotificationLevel.CRITICAL)
        assert msg.level_emoji == "🔴"

        msg2 = NotificationMessage(title="t", content="c", level=NotificationLevel.LOW)
        assert msg2.level_emoji == "🟢"


class MockChannel(BaseNotificationChannel):
    """测试用Mock渠道"""
    def __init__(self, name="mock", enabled=True, should_succeed=True):
        super().__init__(name=name, enabled=enabled)
        self.should_succeed = should_succeed
        self.sent_messages = []

    async def send(self, message: NotificationMessage) -> bool:
        self.sent_messages.append(message)
        if self.should_succeed:
            self._send_count += 1
            return True
        self._error_count += 1
        return False


class TestNotificationManager:
    @pytest.fixture
    def manager(self):
        mgr = NotificationManager(min_severity="medium", cooldown_minutes=30)
        return mgr

    @pytest.fixture
    def mock_channel(self):
        return MockChannel(name="test_channel")

    def test_add_channel(self, manager, mock_channel):
        manager.add_channel(mock_channel)
        assert "test_channel" in manager.channels

    def test_remove_channel(self, manager, mock_channel):
        manager.add_channel(mock_channel)
        manager.remove_channel("test_channel")
        assert "test_channel" not in manager.channels

    @pytest.mark.asyncio
    async def test_notify_sends_to_channel(self, manager, mock_channel):
        manager.add_channel(mock_channel)
        msg = NotificationMessage(
            title="Test", content="Content",
            level=NotificationLevel.HIGH, alert_id="alert-1",
        )
        results = await manager.notify(msg)
        assert results["test_channel"] is True
        assert len(mock_channel.sent_messages) == 1

    @pytest.mark.asyncio
    async def test_notify_filters_low_severity(self, manager, mock_channel):
        manager.add_channel(mock_channel)
        msg = NotificationMessage(
            title="Low", content="Low priority",
            level=NotificationLevel.LOW,
        )
        results = await manager.notify(msg)
        assert results == {}
        assert len(mock_channel.sent_messages) == 0

    @pytest.mark.asyncio
    async def test_notify_cooldown(self, manager, mock_channel):
        manager.add_channel(mock_channel)
        msg = NotificationMessage(
            title="Test", content="Content",
            level=NotificationLevel.HIGH, alert_id="alert-dup",
        )
        # 第一次发送
        await manager.notify(msg)
        assert len(mock_channel.sent_messages) == 1

        # 第二次应被冷却期过滤
        results = await manager.notify(msg)
        assert results == {}
        assert len(mock_channel.sent_messages) == 1

    @pytest.mark.asyncio
    async def test_notify_disabled_channel(self, manager):
        disabled = MockChannel(name="disabled", enabled=False)
        manager.add_channel(disabled)
        msg = NotificationMessage(
            title="Test", content="Content",
            level=NotificationLevel.HIGH,
        )
        results = await manager.notify(msg)
        assert results == {}

    @pytest.mark.asyncio
    async def test_notify_multiple_channels(self, manager):
        ch1 = MockChannel(name="ch1")
        ch2 = MockChannel(name="ch2")
        manager.add_channel(ch1)
        manager.add_channel(ch2)
        msg = NotificationMessage(
            title="Multi", content="Content",
            level=NotificationLevel.CRITICAL, alert_id="multi-1",
        )
        results = await manager.notify(msg)
        assert results["ch1"] is True
        assert results["ch2"] is True

    def test_stats(self, manager, mock_channel):
        manager.add_channel(mock_channel)
        stats = manager.stats
        assert "total_sent" in stats
        assert "channels" in stats
        assert "test_channel" in stats["channels"]
