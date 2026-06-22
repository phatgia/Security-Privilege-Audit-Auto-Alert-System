"""
=============================================================
  🏢 Active Directory Auditor (Giả lập)
  Phân tích dữ liệu AD từ JSON để phát hiện
  tài khoản Domain Admins không hoạt động 30 ngày
=============================================================
"""

import json
import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ADUser:
    """Đại diện cho một user Active Directory"""
    sam_account: str
    display_name: str
    email: Optional[str]
    dn: str
    member_of: list = field(default_factory=list)
    last_logon: Optional[datetime] = None
    pwd_last_set: Optional[datetime] = None
    account_enabled: bool = True
    admin_count: int = 0
    days_inactive: int = 0
    risk_level: str = "LOW"
    alerts: list = field(default_factory=list)
    notes: str = ""
    privilege_groups: list = field(default_factory=list)


class ADauditor:
    """
    Auditor cho Active Directory (giả lập)
    - Đọc dữ liệu từ JSON thay vì LDAP thật
    - Phát hiện Domain Admins không hoạt động
    - Kiểm tra privilege group membership
    """

    PRIVILEGED_GROUPS = [
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Backup Operators",
        "Account Operators",
        "Print Operators",
        "Server Operators"
    ]

    def __init__(self, config: dict):
        self.config = config
        self.data_file = config.get("data_file", "data/sample_ad_users.json")
        self.privileged_groups = config.get("privileged_groups", self.PRIVILEGED_GROUPS)
        self.inactive_threshold = config.get("inactive_days", 30)
        self.critical_threshold = config.get("critical_inactive_days", 60)
        self.users = []
        self.domain = "CORP.LOCAL"

    def run_audit(self) -> dict:
        """Chạy toàn bộ quá trình kiểm tra AD"""
        logger.info("[AD] 🏢 Bắt đầu kiểm tra Active Directory...")

        self._load_data()
        self._calculate_risk()

        result = self._build_report()
        privileged = [u for u in self.users if u.privilege_groups]
        logger.info(f"[AD] ✅ Hoàn thành: {len(privileged)} privileged users tìm thấy")
        return result

    def _load_data(self):
        """Load dữ liệu AD từ JSON file"""
        logger.info(f"[AD] Đang load dữ liệu từ: {self.data_file}")
        try:
            with open(self.data_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            logger.error(f"[AD] Không tìm thấy file: {self.data_file}")
            return

        self.domain = data.get("domain", "CORP.LOCAL")
        now = datetime.now()

        for ud in data.get("users", []):
            user = ADUser(
                sam_account=ud["sAMAccountName"],
                display_name=ud["displayName"],
                email=ud.get("mail"),
                dn=ud.get("distinguishedName", ""),
                member_of=ud.get("memberOf", []),
                account_enabled=ud.get("accountEnabled", True),
                admin_count=ud.get("adminCount", 0),
                notes=ud.get("description", "")
            )

            # Parse lastLogon
            last_logon_str = ud.get("lastLogon") or ud.get("lastLogonTimestamp")
            if last_logon_str:
                try:
                    user.last_logon = datetime.fromisoformat(last_logon_str)
                    user.days_inactive = (now - user.last_logon).days
                except ValueError:
                    pass

            # Parse pwdLastSet
            pwd_last_set_str = ud.get("pwdLastSet")
            if pwd_last_set_str:
                try:
                    user.pwd_last_set = datetime.fromisoformat(pwd_last_set_str)
                except ValueError:
                    pass

            # Xác định privileged groups
            user.privilege_groups = [
                g for g in user.member_of
                if g in self.privileged_groups
            ]

            self.users.append(user)
            logger.debug(f"[AD] User loaded: {user.sam_account} | Groups: {user.privilege_groups}")

    def _calculate_risk(self):
        """Tính toán mức độ rủi ro cho mỗi AD user"""
        for user in self.users:
            if not user.privilege_groups:
                continue  # Chỉ đánh giá privileged users

            alerts = []
            risk_score = 0

            # Kiểm tra inactive
            if user.days_inactive > self.critical_threshold:
                risk_score += 40
                alerts.append(f"⛔ Không hoạt động {user.days_inactive} ngày")
            elif user.days_inactive > self.inactive_threshold:
                risk_score += 25
                alerts.append(f"⚠️ Không hoạt động {user.days_inactive} ngày")

            # Multiple high-privilege groups
            high_priv = ["Domain Admins", "Enterprise Admins", "Schema Admins"]
            high_priv_count = sum(1 for g in user.privilege_groups if g in high_priv)
            if high_priv_count >= 2:
                risk_score += 30
                alerts.append(f"🚨 Thành viên của {high_priv_count} nhóm đặc quyền cao: {', '.join(user.privilege_groups)}")
            elif high_priv_count == 1:
                risk_score += 20
                alerts.append(f"🔑 Domain Admin / Enterprise Admin: {', '.join(user.privilege_groups)}")

            # Account có adminCount (tiered admin model)
            if user.admin_count > 0:
                risk_score += 10
                alerts.append("📌 adminCount=1 (được bảo vệ bởi AdminSDHolder)")

            # Password cũ
            if user.pwd_last_set:
                pwd_age = (datetime.now() - user.pwd_last_set).days
                if pwd_age > 180:
                    risk_score += 15
                    alerts.append(f"🔐 Mật khẩu chưa đổi {pwd_age} ngày")
                elif pwd_age > 90:
                    risk_score += 5
                    alerts.append(f"🔐 Mật khẩu đã {pwd_age} ngày tuổi")

            # Tài khoản không được disable dù inactive lâu
            if not user.account_enabled:
                alerts.append("✅ Tài khoản đã bị disable")
            elif user.days_inactive > self.critical_threshold:
                risk_score += 15
                alerts.append("⚡ Tài khoản vẫn ENABLED dù inactive lâu")

            # Determine risk level
            if risk_score >= 70:
                user.risk_level = "CRITICAL"
            elif risk_score >= 45:
                user.risk_level = "HIGH"
            elif risk_score >= 25:
                user.risk_level = "MEDIUM"
            else:
                user.risk_level = "LOW"

            user.alerts = alerts

    def _build_report(self) -> dict:
        """Tạo report kết quả audit AD"""
        now = datetime.now()
        privileged_users = [u for u in self.users if u.privilege_groups]
        inactive_users = [
            u for u in privileged_users
            if u.days_inactive > self.inactive_threshold
        ]
        critical_users = [u for u in privileged_users if u.risk_level == "CRITICAL"]

        report = {
            "system": "active_directory",
            "domain": self.domain,
            "timestamp": now.isoformat(),
            "summary": {
                "total_privileged_users": len(privileged_users),
                "total_users": len(self.users),
                "inactive_users": len(inactive_users),
                "critical_users": len(critical_users),
                "inactive_threshold_days": self.inactive_threshold,
            },
            "users": []
        }

        for user in sorted(privileged_users,
                           key=lambda u: u.days_inactive, reverse=True):
            report["users"].append({
                "username": user.sam_account,
                "display_name": user.display_name,
                "email": user.email,
                "dn": user.dn,
                "privilege_groups": user.privilege_groups,
                "last_logon": user.last_logon.isoformat() if user.last_logon else None,
                "days_inactive": user.days_inactive,
                "risk_level": user.risk_level,
                "account_enabled": user.account_enabled,
                "alerts": user.alerts,
                "notes": user.notes,
            })

        logger.info(f"[AD] 📊 Kết quả: {len(privileged_users)} privileged users, "
                    f"{len(inactive_users)} inactive, {len(critical_users)} critical")
        return report
