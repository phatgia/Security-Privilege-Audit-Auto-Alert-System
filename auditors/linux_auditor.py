"""
=============================================================
  🔐 Linux Privilege Auditor
  Phân tích /etc/sudoers, /etc/group (wheel/sudo groups)
  và kiểm tra last login để phát hiện admin không hoạt động
=============================================================
"""

import re
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class LinuxPrivilegedUser:
    """Đại diện cho một user Linux có quyền đặc biệt"""
    username: str
    privilege_source: list = field(default_factory=list)  # sudoers, wheel, sudo group
    sudo_rules: list = field(default_factory=list)
    nopasswd: bool = False
    full_access: bool = False  # ALL=(ALL) ALL
    last_login: Optional[datetime] = None
    last_sudo: Optional[datetime] = None
    email: Optional[str] = None
    account_enabled: bool = True
    days_inactive: int = 0
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    alerts: list = field(default_factory=list)
    notes: str = ""


class LinuxAuditor:
    """
    Auditor cho hệ thống Linux
    - Parse /etc/sudoers để tìm users/groups có quyền sudo
    - Parse /etc/group để tìm thành viên wheel/sudo group
    - Kiểm tra last login để phát hiện tài khoản không hoạt động
    """

    PRIVILEGED_GROUPS = ["wheel", "sudo", "admin", "root", "adm"]
    INACTIVE_THRESHOLD = 30   # ngày
    CRITICAL_THRESHOLD = 60   # ngày

    def __init__(self, config: dict):
        self.config = config
        self.sudoers_file = config.get("sudoers_file", "data/sample_sudoers")
        self.group_file = config.get("group_file", "data/sample_group")
        self.lastlog_file = config.get("lastlog_file", "data/sample_lastlog.json")
        self.inactive_threshold = config.get("inactive_days", self.INACTIVE_THRESHOLD)
        self.critical_threshold = config.get("critical_inactive_days", self.CRITICAL_THRESHOLD)
        self.privileged_users = {}  # username -> LinuxPrivilegedUser

    def run_audit(self) -> dict:
        """Chạy toàn bộ quá trình kiểm tra"""
        logger.info("[Linux] 🐧 Bắt đầu kiểm tra Linux privileges...")

        # Thu thập thông tin
        self._parse_sudoers()
        self._parse_group_file()
        self._load_lastlog()
        self._calculate_risk()

        result = self._build_report()
        logger.info(f"[Linux] ✅ Hoàn thành: {len(self.privileged_users)} privileged users tìm thấy")
        return result

    def _parse_sudoers(self):
        """Parse file /etc/sudoers để trích xuất quyền sudo"""
        logger.info(f"[Linux] Đang parse sudoers: {self.sudoers_file}")
        try:
            with open(self.sudoers_file, "r") as f:
                content = f.read()
        except FileNotFoundError:
            logger.error(f"[Linux] Không tìm thấy file sudoers: {self.sudoers_file}")
            return

        for line in content.splitlines():
            line = line.strip()
            # Bỏ qua comment và dòng trống
            if not line or line.startswith("#"):
                continue
            # Bỏ qua %group entries (xử lý qua group file)
            if line.startswith("%"):
                group_match = re.match(r'^%(\S+)\s+', line)
                if group_match:
                    logger.debug(f"[Linux] Sudoers group rule: {line}")
                continue
            # Bỏ qua các directives (Defaults, Cmnd_Alias, etc.)
            if re.match(r'^(Defaults|Cmnd_Alias|User_Alias|Host_Alias|Runas_Alias)\s', line):
                continue
            # Bỏ qua root
            if line.startswith("root"):
                continue

            # Parse user entry: username HOST=(RUNAS) [NOPASSWD:] commands
            user_match = re.match(
                r'^([A-Za-z_][A-Za-z0-9_.\-]*)\s+(\S+)\s*=\s*\(([^)]+)\)\s*(NOPASSWD:\s*)?(.+)$',
                line
            )
            if user_match:
                username = user_match.group(1)
                host = user_match.group(2)
                runas = user_match.group(3)
                nopasswd = bool(user_match.group(4))
                commands = user_match.group(5).strip()

                if username not in self.privileged_users:
                    self.privileged_users[username] = LinuxPrivilegedUser(username=username)

                user = self.privileged_users[username]
                user.privilege_source.append("sudoers")

                rule = {
                    "host": host,
                    "runas": runas,
                    "nopasswd": nopasswd,
                    "commands": commands
                }
                user.sudo_rules.append(rule)

                if nopasswd:
                    user.nopasswd = True
                if runas.strip() in ["ALL:ALL", "ALL"] and commands.strip() == "ALL":
                    user.full_access = True

                logger.debug(f"[Linux] Sudoers entry: {username} | NOPASSWD={nopasswd} | Full={user.full_access}")

    def _parse_group_file(self):
        """Parse /etc/group để tìm thành viên của privileged groups"""
        logger.info(f"[Linux] Đang parse group file: {self.group_file}")
        try:
            with open(self.group_file, "r") as f:
                content = f.read()
        except FileNotFoundError:
            logger.error(f"[Linux] Không tìm thấy group file: {self.group_file}")
            return

        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            parts = line.split(":")
            if len(parts) < 4:
                continue

            group_name = parts[0]
            members_str = parts[3]

            if group_name.lower() not in self.PRIVILEGED_GROUPS:
                continue

            members = [m.strip() for m in members_str.split(",") if m.strip()]
            logger.info(f"[Linux] Nhóm đặc quyền '{group_name}': {len(members)} thành viên")

            for username in members:
                if username not in self.privileged_users:
                    self.privileged_users[username] = LinuxPrivilegedUser(username=username)

                user = self.privileged_users[username]
                source_label = f"group:{group_name}"
                if source_label not in user.privilege_source:
                    user.privilege_source.append(source_label)

    def _load_lastlog(self):
        """Load thông tin last login từ JSON (thay thế cho lastlog command)"""
        logger.info(f"[Linux] Đang load lastlog data: {self.lastlog_file}")
        try:
            with open(self.lastlog_file, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            logger.warning(f"[Linux] Không tìm thấy lastlog file: {self.lastlog_file}")
            return

        now = datetime.now()
        user_data_map = {u["username"]: u for u in data.get("users", [])}

        for username, user in self.privileged_users.items():
            if username in user_data_map:
                ud = user_data_map[username]
                user.email = ud.get("email")
                user.account_enabled = ud.get("account_enabled", True)
                user.notes = ud.get("notes", "")

                last_login_str = ud.get("last_login")
                if last_login_str:
                    try:
                        user.last_login = datetime.fromisoformat(last_login_str)
                        user.days_inactive = (now - user.last_login).days
                    except ValueError:
                        pass

                last_sudo_str = ud.get("last_sudo")
                if last_sudo_str:
                    try:
                        user.last_sudo = datetime.fromisoformat(last_sudo_str)
                    except ValueError:
                        pass
            else:
                # User có trong sudoers/group nhưng không có lastlog
                logger.warning(f"[Linux] Không có dữ liệu lastlog cho: {username}")
                user.days_inactive = -1  # Unknown

    def _calculate_risk(self):
        """Tính toán mức độ rủi ro cho mỗi user"""
        for username, user in self.privileged_users.items():
            alerts = []
            risk_score = 0

            # Kiểm tra không hoạt động
            if user.days_inactive > self.critical_threshold:
                risk_score += 40
                alerts.append(f"⛔ Không hoạt động {user.days_inactive} ngày (vượt ngưỡng critical {self.critical_threshold} ngày)")
            elif user.days_inactive > self.inactive_threshold:
                risk_score += 25
                alerts.append(f"⚠️ Không hoạt động {user.days_inactive} ngày (vượt ngưỡng {self.inactive_threshold} ngày)")
            elif user.days_inactive == -1:
                risk_score += 15
                alerts.append("❓ Không có dữ liệu last login")

            # Full sudo access
            if user.full_access:
                risk_score += 20
                alerts.append("🔑 Có full sudo access (ALL=(ALL) ALL)")

            # NOPASSWD
            if user.nopasswd:
                risk_score += 15
                alerts.append("🔓 NOPASSWD sudo - không cần mật khẩu")

            # Multiple privilege sources
            if len(user.privilege_source) > 2:
                risk_score += 10
                alerts.append(f"📋 Đặc quyền từ {len(user.privilege_source)} nguồn: {', '.join(user.privilege_source)}")

            # Determine risk level
            if risk_score >= 60:
                user.risk_level = "CRITICAL"
            elif risk_score >= 40:
                user.risk_level = "HIGH"
            elif risk_score >= 20:
                user.risk_level = "MEDIUM"
            else:
                user.risk_level = "LOW"

            user.alerts = alerts

    def _build_report(self) -> dict:
        """Tạo report kết quả audit"""
        now = datetime.now()
        inactive_users = [
            u for u in self.privileged_users.values()
            if u.days_inactive > self.inactive_threshold or u.days_inactive == -1
        ]
        critical_users = [u for u in inactive_users if u.risk_level == "CRITICAL"]

        report = {
            "system": "linux",
            "timestamp": now.isoformat(),
            "summary": {
                "total_privileged_users": len(self.privileged_users),
                "inactive_users": len(inactive_users),
                "critical_users": len(critical_users),
                "inactive_threshold_days": self.inactive_threshold,
            },
            "users": []
        }

        for user in sorted(self.privileged_users.values(),
                           key=lambda u: u.days_inactive, reverse=True):
            report["users"].append({
                "username": user.username,
                "privilege_source": user.privilege_source,
                "full_access": user.full_access,
                "nopasswd": user.nopasswd,
                "last_login": user.last_login.isoformat() if user.last_login else None,
                "last_sudo": user.last_sudo.isoformat() if user.last_sudo else None,
                "days_inactive": user.days_inactive,
                "risk_level": user.risk_level,
                "email": user.email,
                "account_enabled": user.account_enabled,
                "alerts": user.alerts,
                "notes": user.notes,
            })

        # Log tóm tắt
        logger.info(f"[Linux] 📊 Kết quả: {len(self.privileged_users)} users đặc quyền, "
                    f"{len(inactive_users)} không hoạt động, {len(critical_users)} critical")
        return report
