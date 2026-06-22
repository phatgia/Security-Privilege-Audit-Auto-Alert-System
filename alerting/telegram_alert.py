"""
=============================================================
  📢 Telegram Alerting Module
  Gửi cảnh báo bảo mật qua Telegram Bot API
=============================================================
"""

import logging
import urllib.request
import urllib.parse
import json
from datetime import datetime

logger = logging.getLogger(__name__)


class TelegramAlerter:
    """
    Gửi cảnh báo qua Telegram Bot
    
    Cách lấy Bot Token và Chat ID:
    1. Tìm @BotFather trên Telegram
    2. Gõ /newbot và làm theo hướng dẫn
    3. Copy Bot Token được cấp
    4. Gửi tin nhắn cho bot, sau đó truy cập:
       https://api.telegram.org/bot<TOKEN>/getUpdates
       để lấy chat_id
    """

    API_BASE = "https://api.telegram.org/bot{token}/{method}"

    # Emoji map cho risk levels
    RISK_EMOJI = {
        "CRITICAL": "🔴",
        "HIGH":     "🟠",
        "MEDIUM":   "🟡",
        "LOW":      "🟢",
    }

    SYSTEM_EMOJI = {
        "linux":            "🐧",
        "active_directory": "🏢",
        "aws_iam":          "☁️",
    }

    def __init__(self, config: dict):
        self.bot_token = config.get("bot_token", "")
        self.chat_id = config.get("chat_id", "")
        self.enabled = config.get("enabled", False) and bool(self.bot_token) and bool(self.chat_id)

        if self.enabled:
            logger.info(f"[Telegram] ✅ Alerter khởi tạo thành công (chat_id: {self.chat_id})")
        else:
            logger.warning("[Telegram] ⚠️ Disabled hoặc thiếu cấu hình bot_token/chat_id")

    def send_message(self, text: str, parse_mode: str = "Markdown") -> bool:
        """Gửi tin nhắn thô qua Telegram"""
        if not self.enabled:
            logger.info(f"[Telegram] (DISABLED) Sẽ gửi: {text[:100]}...")
            return True  # Return True để test flow mà không cần token thật

        url = self.API_BASE.format(token=self.bot_token, method="sendMessage")
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        }

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                result = json.loads(response.read())
                if result.get("ok"):
                    logger.info("[Telegram] ✅ Tin nhắn gửi thành công")
                    return True
                else:
                    logger.error(f"[Telegram] ❌ Lỗi API: {result}")
                    return False
        except Exception as e:
            logger.error(f"[Telegram] ❌ Lỗi kết nối: {e}")
            return False

    def send_test_message(self) -> bool:
        """Gửi tin nhắn test để kiểm tra kết nối"""
        text = (
            "🔐 *Privilege Auditor - Test Alert*\n"
            "━━━━━━━━━━━━━━━━━━━━━\n"
            "✅ Kết nối Telegram thành công!\n"
            f"🕐 Thời gian: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n"
            "\nHệ thống sẵn sàng gửi cảnh báo bảo mật. 🛡️"
        )
        return self.send_message(text)

    def send_audit_summary(self, all_reports: list) -> bool:
        """Gửi tóm tắt kết quả audit cho tất cả hệ thống"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Tính tổng
        total_critical = 0
        total_inactive = 0
        system_lines = []

        for report in all_reports:
            system = report.get("system", "unknown")
            summary = report.get("summary", {})
            critical = summary.get("critical_users", 0)
            inactive = summary.get("inactive_users", summary.get("inactive_privileged_users", 0))

            total_critical += critical
            total_inactive += inactive

            emoji = self.SYSTEM_EMOJI.get(system, "🖥️")
            system_name = {
                "linux": "Linux Servers",
                "active_directory": "Active Directory",
                "aws_iam": "AWS IAM"
            }.get(system, system.upper())

            system_lines.append(
                f"{emoji} *{system_name}*: {critical} critical, {inactive} inactive"
            )

        # Header based on severity
        if total_critical > 0:
            header = f"🚨 *CẢNH BÁO BẢO MẬT - AUDIT REPORT*"
            severity_line = f"⛔ Tìm thấy *{total_critical} vấn đề CRITICAL*!"
        elif total_inactive > 0:
            header = f"⚠️ *Báo Cáo Kiểm Tra Quyền*"
            severity_line = f"🟡 Tìm thấy *{total_inactive} tài khoản inactive*"
        else:
            header = f"✅ *Audit Report - Không Phát Hiện Vấn Đề*"
            severity_line = "Tất cả tài khoản admin đang hoạt động bình thường"

        text = (
            f"{header}\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"🕐 `{now}`\n\n"
            f"{severity_line}\n\n"
            f"📊 *Tóm tắt theo hệ thống:*\n"
            + "\n".join(system_lines) +
            f"\n\n💡 Xem chi tiết trong dashboard hoặc báo cáo HTML"
        )

        return self.send_message(text)

    def send_critical_user_alert(self, user_info: dict, system: str) -> bool:
        """Gửi cảnh báo chi tiết cho một user có rủi ro cao"""
        risk_level = user_info.get("risk_level", "HIGH")
        risk_emoji = self.RISK_EMOJI.get(risk_level, "⚠️")
        system_emoji = self.SYSTEM_EMOJI.get(system, "🖥️")

        system_name = {
            "linux": "Linux Server",
            "active_directory": "Active Directory",
            "aws_iam": "AWS IAM"
        }.get(system, system.upper())

        username = user_info.get("username") or user_info.get("sam_account", "Unknown")
        days_inactive = user_info.get("days_inactive", 0)
        alerts = user_info.get("alerts", [])

        # Tạo danh sách cảnh báo
        alert_lines = "\n".join([f"  • {a}" for a in alerts[:5]])  # Max 5 alerts
        if len(alerts) > 5:
            alert_lines += f"\n  _(+{len(alerts)-5} cảnh báo khác)_"

        text = (
            f"{risk_emoji} *{risk_level} - Tài Khoản Đặc Quyền Cần Xem Xét*\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"{system_emoji} *Hệ thống:* {system_name}\n"
            f"👤 *User:* `{username}`\n"
            f"⏱️ *Không hoạt động:* {days_inactive} ngày\n\n"
            f"📋 *Chi tiết rủi ro:*\n{alert_lines}\n\n"
            f"🔧 *Hành động đề xuất:*\n"
            f"  • Xác nhận với chủ tài khoản còn cần quyền không\n"
            f"  • Nếu không cần: thu hồi quyền hoặc disable tài khoản\n"
            f"  • Ghi nhật ký hành động vào ticket bảo mật\n\n"
            f"_🤖 Tự động phát hiện bởi Privilege Auditor_"
        )

        return self.send_message(text)

    def send_inactive_admins_batch(self, inactive_users: list, system: str, threshold: int = 30) -> bool:
        """Gửi danh sách tóm tắt các admin không hoạt động"""
        if not inactive_users:
            return True

        system_emoji = self.SYSTEM_EMOJI.get(system, "🖥️")
        system_name = {
            "linux": "Linux Servers",
            "active_directory": "Active Directory",
            "aws_iam": "AWS IAM"
        }.get(system, system.upper())

        lines = []
        for u in inactive_users[:10]:  # Max 10 users per message
            username = u.get("username") or u.get("sam_account", "?")
            days = u.get("days_inactive", 0)
            risk = u.get("risk_level", "?")
            emoji = self.RISK_EMOJI.get(risk, "⚠️")
            lines.append(f"  {emoji} `{username}` — {days} ngày inactive")

        if len(inactive_users) > 10:
            lines.append(f"  _... và {len(inactive_users) - 10} tài khoản khác_")

        text = (
            f"⚠️ *Admin Không Hoạt Động > {threshold} Ngày*\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"{system_emoji} *{system_name}* — {len(inactive_users)} tài khoản:\n\n"
            + "\n".join(lines) +
            f"\n\n🕐 `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
        )

        return self.send_message(text)
