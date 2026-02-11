"""
邮件通知渠道

通过SMTP发送告警邮件，支持异步发送
"""
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List

from .base import BaseNotificationChannel, NotificationMessage, NotificationLevel

logger = logging.getLogger(__name__)


class EmailChannel(BaseNotificationChannel):
    """邮件通知渠道"""

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int = 587,
        use_tls: bool = True,
        username: str = "",
        password: str = "",
        from_addr: str = "",
        to_addrs: List[str] = None,
        cc_addrs: List[str] = None,
        enabled: bool = True,
    ):
        super().__init__(name="email", enabled=enabled)
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.use_tls = use_tls
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_addrs = to_addrs or []
        self.cc_addrs = cc_addrs or []

    def _build_html(self, message: NotificationMessage) -> str:
        """构建HTML邮件内容"""
        color_map = {
            NotificationLevel.INFO: "#2196F3",
            NotificationLevel.LOW: "#4CAF50",
            NotificationLevel.MEDIUM: "#FFC107",
            NotificationLevel.HIGH: "#FF9800",
            NotificationLevel.CRITICAL: "#F44336",
        }
        color = color_map.get(message.level, "#9E9E9E")

        details_html = ""
        if message.details:
            rows = "".join(
                f"<tr><td style='padding:4px 8px;font-weight:bold'>{k}</td>"
                f"<td style='padding:4px 8px'>{v}</td></tr>"
                for k, v in message.details.items()
            )
            details_html = f"<table style='border-collapse:collapse;margin:10px 0'>{rows}</table>"

        tags_html = ""
        if message.tags:
            tags = " ".join(
                f"<span style='background:#e0e0e0;padding:2px 8px;border-radius:4px;margin:2px'>{t}</span>"
                for t in message.tags
            )
            tags_html = f"<p>{tags}</p>"

        return f"""
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
            <div style="background:{color};color:white;padding:15px;border-radius:4px 4px 0 0">
                <h2 style="margin:0">{message.level_emoji} {message.title}</h2>
            </div>
            <div style="border:1px solid #ddd;padding:15px;border-radius:0 0 4px 4px">
                <p><strong>级别:</strong> {message.level.value.upper()}</p>
                <p><strong>来源:</strong> {message.source or 'RiskAnalyseAgent'}</p>
                <p><strong>时间:</strong> {message.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <hr>
                <div>{message.content}</div>
                {details_html}
                {tags_html}
                <hr>
                <p style="color:#999;font-size:12px">Alert ID: {message.alert_id or 'N/A'}</p>
            </div>
        </div>
        """

    async def send(self, message: NotificationMessage) -> bool:
        """发送邮件通知（同步SMTP，在线程池中执行）"""
        if not self.enabled:
            return False

        try:
            import asyncio
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, self._send_sync, message)
        except Exception as e:
            self._error_count += 1
            logger.error(f"邮件通知发送异常: {e}")
            return False

    def _send_sync(self, message: NotificationMessage) -> bool:
        """同步发送邮件"""
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[{message.level.value.upper()}] {message.title}"
            msg["From"] = self.from_addr
            msg["To"] = ", ".join(self.to_addrs)
            if self.cc_addrs:
                msg["Cc"] = ", ".join(self.cc_addrs)

            html_content = self._build_html(message)
            msg.attach(MIMEText(html_content, "html", "utf-8"))

            all_recipients = self.to_addrs + self.cc_addrs

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.sendmail(self.from_addr, all_recipients, msg.as_string())

            self._send_count += 1
            logger.info(f"邮件通知发送成功: {message.title}")
            return True

        except Exception as e:
            self._error_count += 1
            logger.error(f"邮件发送失败: {e}")
            return False
