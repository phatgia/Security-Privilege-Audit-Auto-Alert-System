"""
=============================================================
  ☁️ AWS IAM Auditor
  Phân tích IAM users, access keys, policies
  Phát hiện admin không hoạt động, không có MFA,
  và policies quá rộng quyền
=============================================================
"""

import json
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class IAMUser:
    """Đại diện cho một AWS IAM User"""
    user_name: str
    arn: str
    created_at: Optional[datetime] = None
    password_last_used: Optional[datetime] = None
    mfa_active: bool = False
    access_key_1_active: bool = False
    access_key_1_last_used: Optional[datetime] = None
    access_key_1_last_service: str = ""
    access_key_1_last_rotated: Optional[datetime] = None
    access_key_2_active: bool = False
    access_key_2_last_used: Optional[datetime] = None
    access_key_2_last_rotated: Optional[datetime] = None
    groups: list = field(default_factory=list)
    attached_policies: list = field(default_factory=list)
    inline_policies: list = field(default_factory=list)
    is_privileged: bool = False
    has_admin_access: bool = False
    days_inactive: int = 0
    key_age_days: int = 0
    risk_level: str = "LOW"
    alerts: list = field(default_factory=list)
    notes: str = ""


class AWSIAMAuditor:
    """
    Auditor cho AWS IAM
    - Phân tích IAM users từ credential report hoặc JSON sample
    - Phát hiện admin không dùng access key 30+ ngày
    - Kiểm tra MFA, key rotation, overly permissive policies
    """

    ADMIN_POLICIES = [
        "AdministratorAccess",
        "PowerUserAccess",
        "IAMFullAccess",
    ]

    def __init__(self, config: dict):
        self.config = config
        self.data_file = config.get("data_file", "data/sample_iam_data.json")
        self.use_real_aws = config.get("use_real_aws", False)
        self.inactive_threshold = config.get("inactive_days", 30)
        self.critical_threshold = config.get("critical_inactive_days", 60)
        self.key_rotation_threshold = 90  # ngày key không được rotate
        self.users = []
        self.overly_permissive_policies = []

    def run_audit(self) -> dict:
        """Chạy toàn bộ quá trình kiểm tra IAM"""
        logger.info("[AWS] ☁️ Bắt đầu kiểm tra AWS IAM...")

        if self.use_real_aws:
            self._collect_real_aws()
        else:
            self._load_sample_data()

        self._calculate_risk()
        result = self._build_report()

        privileged = [u for u in self.users if u.is_privileged]
        logger.info(f"[AWS] ✅ Hoàn thành: {len(self.users)} users, {len(privileged)} có quyền admin")
        return result

    def _load_sample_data(self):
        """Load dữ liệu IAM từ JSON file mẫu"""
        logger.info(f"[AWS] Đang load dữ liệu từ: {self.data_file}")
        try:
            with open(self.data_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            logger.error(f"[AWS] Không tìm thấy file: {self.data_file}")
            return

        # Load overly permissive policies
        for policy in data.get("policies", []):
            if policy.get("is_overly_permissive"):
                self.overly_permissive_policies.append(policy["policy_name"])

        admin_policy_set = set(self.ADMIN_POLICIES + self.overly_permissive_policies)
        now = datetime.now()

        for ud in data.get("users", []):
            user = IAMUser(
                user_name=ud["user_name"],
                arn=ud["arn"],
                mfa_active=ud.get("mfa_active", False),
                access_key_1_active=ud.get("access_key_1_active", False),
                access_key_1_last_service=ud.get("access_key_1_last_used_service", ""),
                access_key_2_active=ud.get("access_key_2_active", False),
                groups=ud.get("groups", []),
                attached_policies=ud.get("attached_policies", []),
                inline_policies=ud.get("inline_policies", []),
                notes=ud.get("notes", "")
            )

            # Parse dates
            def parse_dt(s):
                if not s or s == "N/A":
                    return None
                try:
                    return datetime.fromisoformat(s)
                except ValueError:
                    return None

            user.created_at = parse_dt(ud.get("user_creation_time"))
            user.password_last_used = parse_dt(ud.get("password_last_used"))
            user.access_key_1_last_used = parse_dt(ud.get("access_key_1_last_used_date"))
            user.access_key_1_last_rotated = parse_dt(ud.get("access_key_1_last_rotated"))
            user.access_key_2_last_used = parse_dt(ud.get("access_key_2_last_used_date"))
            user.access_key_2_last_rotated = parse_dt(ud.get("access_key_2_last_rotated"))

            # Xác định last activity (password hoặc access key)
            activity_dates = [d for d in [
                user.password_last_used,
                user.access_key_1_last_used,
                user.access_key_2_last_used
            ] if d is not None]

            if activity_dates:
                last_activity = max(activity_dates)
                user.days_inactive = (now - last_activity).days
            else:
                user.days_inactive = -1

            # Key age
            if user.access_key_1_last_rotated:
                user.key_age_days = (now - user.access_key_1_last_rotated).days

            # Kiểm tra có admin access không
            all_policies = set(user.attached_policies + user.inline_policies)
            user.has_admin_access = bool(all_policies & admin_policy_set)
            user.is_privileged = user.has_admin_access or bool(
                set(user.groups) & {"Administrators", "AdminGroup"}
            )

            self.users.append(user)

    def _collect_real_aws(self):
        """Kết nối AWS thật để lấy IAM credential report"""
        try:
            import boto3
            logger.info("[AWS] Đang kết nối AWS thật...")
            
            session = boto3.Session(
                aws_access_key_id=self.config.get("aws_access_key_id"),
                aws_secret_access_key=self.config.get("aws_secret_access_key"),
                region_name=self.config.get("aws_region", "us-east-1")
            )
            iam = session.client("iam")

            # Generate credential report
            logger.info("[AWS] Generating IAM credential report...")
            iam.generate_credential_report()
            import time
            time.sleep(5)  # Chờ report được tạo
            
            report = iam.get_credential_report()
            content = report["Content"].decode("utf-8")
            
            # Parse CSV credential report
            import csv
            import io
            reader = csv.DictReader(io.StringIO(content))
            now = datetime.now()
            
            for row in reader:
                if row.get("user") == "<root_account>":
                    continue
                    
                user = IAMUser(
                    user_name=row["user"],
                    arn=row["arn"],
                    mfa_active=row.get("mfa_active") == "true",
                    access_key_1_active=row.get("access_key_1_active") == "true",
                    access_key_2_active=row.get("access_key_2_active") == "true",
                )
                
                def parse_aws_dt(s):
                    if not s or s in ["N/A", "no_information", "not_supported"]:
                        return None
                    try:
                        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
                    except ValueError:
                        return None
                
                user.password_last_used = parse_aws_dt(row.get("password_last_used"))
                user.access_key_1_last_used = parse_aws_dt(row.get("access_key_1_last_used_date"))
                user.access_key_1_last_rotated = parse_aws_dt(row.get("access_key_1_last_rotated"))
                user.access_key_2_last_used = parse_aws_dt(row.get("access_key_2_last_used_date"))
                user.access_key_2_last_rotated = parse_aws_dt(row.get("access_key_2_last_rotated"))
                
                # Get user groups and policies
                try:
                    groups_resp = iam.list_groups_for_user(UserName=user.user_name)
                    user.groups = [g["GroupName"] for g in groups_resp.get("Groups", [])]
                    
                    policies_resp = iam.list_attached_user_policies(UserName=user.user_name)
                    user.attached_policies = [p["PolicyName"] for p in policies_resp.get("AttachedPolicies", [])]
                except Exception as e:
                    logger.warning(f"[AWS] Không lấy được groups/policies cho {user.user_name}: {e}")
                
                # Calculate days inactive
                activity_dates = [d for d in [
                    user.password_last_used, user.access_key_1_last_used
                ] if d is not None]
                if activity_dates:
                    user.days_inactive = (now - max(activity_dates)).days
                    
                admin_policy_set = set(self.ADMIN_POLICIES)
                user.has_admin_access = bool(set(user.attached_policies) & admin_policy_set)
                user.is_privileged = user.has_admin_access
                
                if user.access_key_1_last_rotated:
                    user.key_age_days = (now - user.access_key_1_last_rotated).days
                
                self.users.append(user)
                
            logger.info(f"[AWS] Loaded {len(self.users)} IAM users từ AWS thật")
            
        except ImportError:
            logger.error("[AWS] boto3 chưa được cài đặt. Chạy: pip install boto3")
            self._load_sample_data()
        except Exception as e:
            logger.error(f"[AWS] Lỗi kết nối AWS: {e}")
            logger.info("[AWS] Fallback sang sample data...")
            self._load_sample_data()

    def _calculate_risk(self):
        """Tính toán rủi ro cho mỗi IAM user"""
        for user in self.users:
            if not user.is_privileged:
                continue

            alerts = []
            risk_score = 0

            # Kiểm tra không hoạt động
            if user.days_inactive == -1:
                risk_score += 20
                alerts.append("❓ Không có dữ liệu activity")
            elif user.days_inactive > self.critical_threshold:
                risk_score += 40
                alerts.append(f"⛔ Không hoạt động {user.days_inactive} ngày")
            elif user.days_inactive > self.inactive_threshold:
                risk_score += 25
                alerts.append(f"⚠️ Không hoạt động {user.days_inactive} ngày")

            # Không có MFA
            if not user.mfa_active:
                risk_score += 30
                alerts.append("🔓 KHÔNG có MFA - rủi ro cao!")

            # Admin access
            if user.has_admin_access:
                risk_score += 20
                alerts.append(f"👑 Có AdministratorAccess policy: {', '.join(user.attached_policies)}")

            # Access key quá cũ chưa rotate
            if user.access_key_1_active and user.key_age_days > self.key_rotation_threshold:
                risk_score += 15
                alerts.append(f"🗝️ Access key chưa rotate {user.key_age_days} ngày")

            # 2 access keys đều active
            if user.access_key_1_active and user.access_key_2_active:
                risk_score += 10
                alerts.append("🔑🔑 Có 2 active access keys cùng lúc")

            # Determine risk level
            if risk_score >= 75:
                user.risk_level = "CRITICAL"
            elif risk_score >= 50:
                user.risk_level = "HIGH"
            elif risk_score >= 25:
                user.risk_level = "MEDIUM"
            else:
                user.risk_level = "LOW"

            user.alerts = alerts

    def _build_report(self) -> dict:
        """Tạo report kết quả audit IAM"""
        now = datetime.now()
        privileged_users = [u for u in self.users if u.is_privileged]
        inactive_users = [
            u for u in privileged_users
            if u.days_inactive > self.inactive_threshold or u.days_inactive == -1
        ]
        critical_users = [u for u in privileged_users if u.risk_level == "CRITICAL"]
        no_mfa_users = [u for u in privileged_users if not u.mfa_active]

        report = {
            "system": "aws_iam",
            "timestamp": now.isoformat(),
            "summary": {
                "total_iam_users": len(self.users),
                "total_privileged_users": len(privileged_users),
                "inactive_privileged_users": len(inactive_users),
                "critical_users": len(critical_users),
                "admins_without_mfa": len(no_mfa_users),
                "inactive_threshold_days": self.inactive_threshold,
                "overly_permissive_policies": self.overly_permissive_policies,
            },
            "users": []
        }

        for user in sorted(privileged_users,
                           key=lambda u: u.days_inactive, reverse=True):
            report["users"].append({
                "username": user.user_name,
                "arn": user.arn,
                "has_admin_access": user.has_admin_access,
                "mfa_active": user.mfa_active,
                "access_key_1_active": user.access_key_1_active,
                "access_key_2_active": user.access_key_2_active,
                "key_age_days": user.key_age_days,
                "password_last_used": user.password_last_used.isoformat() if user.password_last_used else None,
                "access_key_1_last_used": user.access_key_1_last_used.isoformat() if user.access_key_1_last_used else None,
                "days_inactive": user.days_inactive,
                "attached_policies": user.attached_policies,
                "groups": user.groups,
                "risk_level": user.risk_level,
                "alerts": user.alerts,
                "notes": user.notes,
            })

        logger.info(f"[AWS] 📊 Kết quả: {len(privileged_users)} admins, "
                    f"{len(inactive_users)} inactive, {len(no_mfa_users)} không có MFA")
        return report
