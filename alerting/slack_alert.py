"""
=============================================================
  💬 Slack Alerting Module
  Gửi cảnh báo bảo mật qua Slack Incoming Webhooks
=============================================================
"""

import logging
import urllib.request
import json
from datetime import datetime

logger = logging.getLogger(__name__)


class SlackAlerter:
    """
    Gửi cảnh báo qua Slack Incoming Webhook
    
    Cách thiết lập:
    1. Vào https://api.slack.com/apps
    2. Tạo App → Incoming Webhooks → Activate
    3. Add to Workspace, chọn channel
    4. Copy Webhook URL vào config.yaml
    """

    # Color map cho risk levels (sidebar color của Slack message)
    RISK_COLOR = {
        "CRITICAL": "#FF0000",  # Đỏ
        "HIGH":     "#FF6600",  # Cam
        "MEDIUM":   "#FFB300",  # Vàng
        "LOW":      "#00CC44",  # Xanh lá
    }

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
        self.webhook_url = config.get("webhook_url", "")
        self.channel = config.get("channel", "#security-alerts")
        self.username = config.get("username", "PrivilegeAuditor Bot")
        self.icon_emoji = config.get("icon_emoji", ":shield:")
        self.enabled = config.get("enabled", False) and bool(self.webhook_url)

        if self.enabled:
            logger.info(f"[Slack] ✅ Alerter khởi tạo (channel: {self.channel})")
        else:
            logger.warning("[Slack] ⚠️ Disabled hoặc thiếu webhook_url")

    def _send_payload(self, payload: dict) -> bool:
        """Gửi payload JSON đến Slack Webhook"""
        if not self.enabled:
            logger.info(f"[Slack] (DISABLED) Sẽ gửi payload đến {self.channel}")
            return True

        payload["username"] = self.username
        payload["icon_emoji"] = self.icon_emoji
        payload["channel"] = self.channel

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as response:
                body = response.read().decode()
                if body == "ok":
                    logger.info("[Slack] ✅ Tin nhắn gửi thành công")
                    return True
                else:
                    logger.error(f"[Slack] ❌ Phản hồi lạ: {body}")
                    return False
        except Exception as e:
            logger.error(f"[Slack] ❌ Lỗi kết nối: {e}")
            return False

    def send_test_message(self) -> bool:
        """Gửi tin nhắn test"""
        payload = {
            "text": "🔐 *Privilege Auditor - Test Message*",
            "attachments": [{
                "color": "#00CC44",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                "✅ *Kết nối Slack thành công!*\n"
                                f"🕐 Thời gian: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`\n"
                                "Hệ thống sẵn sàng gửi cảnh báo bảo mật. 🛡️"
                            )
                        }
                    }
                ]
            }]
        }
        return self._send_payload(payload)

    def send_audit_summary(self, all_reports: list) -> bool:
        """Gửi tóm tắt audit cho tất cả hệ thống"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        total_critical = 0
        total_inactive = 0
        fields = []

        for report in all_reports:
            system = report.get("system", "unknown")
            summary = report.get("summary", {})
            critical = summary.get("critical_users", 0)
            inactive = summary.get("inactive_users",
                                   summary.get("inactive_privileged_users", 0))
            total = summary.get("total_privileged_users", 0)

            total_critical += critical
            total_inactive += inactive

            emoji = self.SYSTEM_EMOJI.get(system, "🖥️")
            system_name = {
                "linux": "Linux Servers",
                "active_directory": "Active Directory",
                "aws_iam": "AWS IAM"
            }.get(system, system.upper())

            fields.append({
                "type": "mrkdwn",
                "text": (
                    f"*{emoji} {system_name}*\n"
                    f"Privileged: {total} | Inactive: {inactive} | 🔴 Critical: {critical}"
                )
            })

        color = "#FF0000" if total_critical > 0 else ("#FFB300" if total_inactive > 0 else "#00CC44")
        header = (
            f"🚨 CẢNH BÁO: {total_critical} critical issues!" if total_critical > 0
            else f"⚠️ {total_inactive} tài khoản admin không hoạt động" if total_inactive > 0
            else "✅ Không phát hiện vấn đề bảo mật"
        )

        payload = {
            "text": f"🔐 *Security Privilege Audit Report* — `{now}`",
            "attachments": [{
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": "🔐 Privilege Audit Report", "emoji": True}
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*{header}*\n🕐 `{now}`"}
                    },
                    {"type": "divider"},
                    {
                        "type": "section",
                        "fields": fields
                    },
                    {
                        "type": "context",
                        "elements": [{
                            "type": "mrkdwn",
                            "text": "🤖 _Tự động phát hiện bởi Privilege Auditor_ | Xem chi tiết trong dashboard"
                        }]
                    }
                ]
            }]
        }

        return self._send_payload(payload)

    def send_critical_user_alert(self, user_info: dict, system: str) -> bool:
        """Gửi cảnh báo chi tiết cho một user critical"""
        risk_level = user_info.get("risk_level", "HIGH")
        color = self.RISK_COLOR.get(risk_level, "#FF6600")
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
        alert_text = "\n".join([f"• {a}" for a in alerts[:5]])

        payload = {
            "text": f"{risk_emoji} *{risk_level} Alert: Tài khoản `{username}` ({system_name})*",
            "attachments": [{
                "color": color,
                "blocks": [
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*{system_emoji} Hệ thống:*\n{system_name}"},
                            {"type": "mrkdwn", "text": f"*👤 User:*\n`{username}`"},
                            {"type": "mrkdwn", "text": f"*⏱️ Inactive:*\n{days_inactive} ngày"},
                            {"type": "mrkdwn", "text": f"*{risk_emoji} Risk Level:*\n{risk_level}"},
                        ]
                    },
                    {"type": "divider"},
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*📋 Chi tiết rủi ro:*\n{alert_text}"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                "*🔧 Hành động đề xuất:*\n"
                                "• Liên hệ chủ tài khoản xác nhận còn cần quyền không\n"
                                "• Thu hồi quyền hoặc disable nếu không cần\n"
                                "• Ghi nhật ký vào security ticket"
                            )
                        }
                    }
                ]
            }]
        }

        return self._send_payload(payload)

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

        rows = []
        for u in inactive_users[:10]:
            username = u.get("username") or u.get("sam_account", "?")
            days = u.get("days_inactive", 0)
            risk = u.get("risk_level", "?")
            emoji = self.RISK_EMOJI.get(risk, "⚠️")
            rows.append(f"{emoji} `{username}` — {days} ngày")

        if len(inactive_users) > 10:
            rows.append(f"_... và {len(inactive_users) - 10} tài khoản khác_")

        payload = {
            "text": f"⚠️ *{system_name}: {len(inactive_users)} Admin Không Hoạt Động > {threshold} Ngày*",
            "attachments": [{
                "color": "#FF6600",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"{system_emoji} *{system_name}* — "
                                f"Tìm thấy {len(inactive_users)} tài khoản không hoạt động:\n\n"
                                + "\n".join(rows)
                            )
                        }
                    }
                ]
            }]
        }

        return self._send_payload(payload)
