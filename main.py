"""
=============================================================
  🚀 Privilege Auditor - Main Entry Point
  
  Sử dụng:
    python main.py                    # Chạy audit đầy đủ (demo mode)
    python main.py --system linux     # Chỉ kiểm tra Linux
    python main.py --system ad        # Chỉ kiểm tra Active Directory
    python main.py --system aws       # Chỉ kiểm tra AWS IAM
    python main.py --alert-test       # Test gửi alert
    python main.py --days 45          # Ngưỡng inactive (mặc định 30)
    python main.py --no-alert         # Chạy mà không gửi alert
=============================================================
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

# Fix Windows encoding for emoji/Vietnamese output
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf-8-sig'):
    try:
        import io
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass

# Thêm project root vào path
sys.path.insert(0, str(Path(__file__).parent))


def setup_logging(level: str = "INFO", log_file: str = "logs/auditor.log"):
    """Cấu hình logging"""
    Path("logs").mkdir(exist_ok=True)

    handlers = [logging.StreamHandler(sys.stdout)]
    try:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    except Exception:
        pass

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers
    )


def load_config(config_path: str = "config.yaml") -> dict:
    """Load cấu hình từ YAML file"""
    try:
        import yaml
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except ImportError:
        logging.warning("PyYAML chưa được cài. Dùng cấu hình mặc định. (pip install pyyaml)")
        return _default_config()
    except FileNotFoundError:
        logging.warning(f"Không tìm thấy {config_path}. Dùng cấu hình mặc định.")
        return _default_config()


def _default_config() -> dict:
    """Cấu hình mặc định nếu không có file config"""
    return {
        "thresholds": {
            "inactive_days": 30,
            "critical_inactive_days": 60,
        },
        "telegram": {
            "enabled": False,
            "bot_token": "",
            "chat_id": "",
        },
        "slack": {
            "enabled": False,
            "webhook_url": "",
        },
        "audit_targets": {
            "linux": {
                "enabled": True,
                "sudoers_file": "data/sample_sudoers",
                "group_file": "data/sample_group",
                "lastlog_file": "data/sample_lastlog.json",
                "auth_log": "data/sample_auth.log",
            },
            "active_directory": {
                "enabled": True,
                "data_file": "data/sample_ad_users.json",
            },
            "aws_iam": {
                "enabled": True,
                "data_file": "data/sample_iam_data.json",
                "use_real_aws": False,
            },
        },
        "reports": {
            "output_dir": "reports",
        },
        "logging": {
            "level": "INFO",
            "log_file": "logs/auditor.log",
        }
    }


def run_audits(config: dict, systems: list = None) -> list:
    """Chạy audit cho các hệ thống được chỉ định"""
    from auditors.linux_auditor import LinuxAuditor
    from auditors.ad_auditor import ADauditor
    from auditors.aws_iam_auditor import AWSIAMAuditor

    thresholds = config.get("thresholds", {})
    targets = config.get("audit_targets", {})
    reports = []

    # Merge threshold vào từng target config
    def merge_thresholds(target_config):
        merged = dict(target_config)
        merged["inactive_days"] = thresholds.get("inactive_days", 30)
        merged["critical_inactive_days"] = thresholds.get("critical_inactive_days", 60)
        return merged

    # Linux
    if systems is None or "linux" in systems:
        linux_cfg = targets.get("linux", {})
        if linux_cfg.get("enabled", True):
            auditor = LinuxAuditor(merge_thresholds(linux_cfg))
            report = auditor.run_audit()
            reports.append(report)

    # Active Directory
    if systems is None or "ad" in systems:
        ad_cfg = targets.get("active_directory", {})
        if ad_cfg.get("enabled", True):
            auditor = ADauditor(merge_thresholds(ad_cfg))
            report = auditor.run_audit()
            reports.append(report)

    # AWS IAM
    if systems is None or "aws" in systems:
        aws_cfg = targets.get("aws_iam", {})
        if aws_cfg.get("enabled", True):
            auditor = AWSIAMAuditor(merge_thresholds(aws_cfg))
            report = auditor.run_audit()
            reports.append(report)

    return reports


def send_alerts(config: dict, all_reports: list, inactive_threshold: int = 30):
    """Gửi cảnh báo qua Telegram và Slack"""
    from alerting.telegram_alert import TelegramAlerter
    from alerting.slack_alert import SlackAlerter

    telegram = TelegramAlerter(config.get("telegram", {}))
    slack = SlackAlerter(config.get("slack", {}))

    logger = logging.getLogger(__name__)

    # Gửi summary cho tất cả hệ thống
    logger.info("[Alert] Đang gửi audit summary...")
    telegram.send_audit_summary(all_reports)
    slack.send_audit_summary(all_reports)

    # Gửi cảnh báo chi tiết cho từng critical/high user
    for report in all_reports:
        system = report.get("system", "unknown")
        users = report.get("users", [])

        # Lọc inactive users
        inactive = [u for u in users if u.get("days_inactive", 0) > inactive_threshold]
        if inactive:
            logger.info(f"[Alert] Gửi danh sách {len(inactive)} inactive admins cho {system}...")
            telegram.send_inactive_admins_batch(inactive, system, inactive_threshold)
            slack.send_inactive_admins_batch(inactive, system, inactive_threshold)

        # Gửi chi tiết cho từng critical user
        critical_users = [u for u in users if u.get("risk_level") in ("CRITICAL", "HIGH")]
        for user in critical_users[:5]:  # Giới hạn 5 để tránh spam
            logger.info(f"[Alert] Cảnh báo chi tiết: {user.get('username', '?')} ({system})")
            telegram.send_critical_user_alert(user, system)
            slack.send_critical_user_alert(user, system)


def print_summary(all_reports: list):
    """In tóm tắt ra console"""
    print("\n" + "═" * 60)
    print("  🔐 PRIVILEGE AUDIT REPORT SUMMARY")
    print("═" * 60)

    total_critical = 0
    total_inactive = 0

    for report in all_reports:
        system = report.get("system", "?")
        summary = report.get("summary", {})

        system_name = {
            "linux": "🐧 Linux Servers",
            "active_directory": "🏢 Active Directory",
            "aws_iam": "☁️  AWS IAM"
        }.get(system, f"🖥️  {system.upper()}")

        priv = summary.get("total_privileged_users", 0)
        inactive = summary.get("inactive_users",
                               summary.get("inactive_privileged_users", 0))
        critical = summary.get("critical_users", 0)

        total_critical += critical
        total_inactive += inactive

        print(f"\n  {system_name}")
        print(f"  ├─ Tổng tài khoản đặc quyền : {priv}")
        print(f"  ├─ Không hoạt động          : {inactive}")
        print(f"  └─ Critical                  : {critical}")

        # Top critical users
        critical_users = [u for u in report.get("users", [])
                          if u.get("risk_level") == "CRITICAL"]
        for u in critical_users[:3]:
            username = u.get("username") or u.get("sam_account", "?")
            days = u.get("days_inactive", 0)
            print(f"     🔴 {username} ({days} ngày inactive)")

    print("\n" + "─" * 60)
    print(f"  📊 TỔNG KẾT: {total_critical} CRITICAL | {total_inactive} INACTIVE")
    print("═" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="🔐 Privilege Auditor - Tự động rà soát quyền truy cập",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ví dụ:
  python main.py                         # Audit tất cả hệ thống
  python main.py --system linux          # Chỉ Linux
  python main.py --system ad aws         # AD và AWS IAM  
  python main.py --days 45               # Ngưỡng 45 ngày
  python main.py --alert-test            # Test Telegram/Slack
  python main.py --no-alert              # Không gửi alert
        """
    )
    parser.add_argument(
        "--system", nargs="+", choices=["linux", "ad", "aws"],
        help="Hệ thống cần kiểm tra (mặc định: tất cả)"
    )
    parser.add_argument(
        "--days", type=int, default=None,
        help="Ngưỡng ngày không hoạt động (mặc định từ config.yaml)"
    )
    parser.add_argument(
        "--config", default="config.yaml",
        help="Đường dẫn file cấu hình"
    )
    parser.add_argument(
        "--alert-test", action="store_true",
        help="Chỉ gửi tin nhắn test đến Telegram/Slack"
    )
    parser.add_argument(
        "--no-alert", action="store_true",
        help="Không gửi cảnh báo, chỉ tạo báo cáo"
    )
    parser.add_argument(
        "--no-report", action="store_true",
        help="Không tạo file báo cáo HTML/JSON"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Verbose logging (DEBUG level)"
    )

    args = parser.parse_args()

    # Setup
    config = load_config(args.config)
    log_level = "DEBUG" if args.verbose else config.get("logging", {}).get("level", "INFO")
    log_file = config.get("logging", {}).get("log_file", "logs/auditor.log")
    setup_logging(log_level, log_file)

    logger = logging.getLogger(__name__)
    logger.info("=" * 50)
    logger.info("🔐 Privilege Auditor khởi động")
    logger.info(f"   Thời gian: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("=" * 50)

    # Override threshold nếu được chỉ định
    if args.days:
        config.setdefault("thresholds", {})["inactive_days"] = args.days
        logger.info(f"⚙️  Ngưỡng inactive: {args.days} ngày")

    inactive_threshold = config.get("thresholds", {}).get("inactive_days", 30)

    # Alert test mode
    if args.alert_test:
        logger.info("🧪 Chế độ test alert...")
        from alerting.telegram_alert import TelegramAlerter
        from alerting.slack_alert import SlackAlerter

        tg = TelegramAlerter(config.get("telegram", {}))
        sl = SlackAlerter(config.get("slack", {}))

        tg_ok = tg.send_test_message()
        sl_ok = sl.send_test_message()

        print(f"\n📱 Telegram: {'✅ Thành công' if tg_ok else '❌ Thất bại'}")
        print(f"💬 Slack:    {'✅ Thành công' if sl_ok else '❌ Thất bại'}")
        return

    # Run audits
    logger.info(f"🔍 Bắt đầu audit hệ thống: {args.system or 'tất cả'}")
    all_reports = run_audits(config, args.system)

    if not all_reports:
        logger.warning("⚠️ Không có kết quả audit nào!")
        return

    # Print summary
    print_summary(all_reports)

    # Collect logs
    from collectors.log_collector import LogCollector
    auth_log = config.get("audit_targets", {}).get("linux", {}).get("auth_log", "data/sample_auth.log")
    log_collector = LogCollector(auth_log)
    log_summary = log_collector.collect()

    # Generate reports
    if not args.no_report:
        from reports.report_generator import ReportGenerator
        output_dir = config.get("reports", {}).get("output_dir", "reports")
        generator = ReportGenerator(output_dir)
        report_paths = generator.generate(all_reports, log_summary)
        logger.info(f"📄 Báo cáo HTML: {report_paths['html_path']}")
        logger.info(f"📄 Báo cáo JSON: {report_paths['json_path']}")
        print(f"\n📊 Báo cáo đã tạo:\n   → {report_paths['html_path']}")

    # Send alerts
    if not args.no_alert:
        logger.info("📢 Đang gửi cảnh báo...")
        send_alerts(config, all_reports, inactive_threshold)
    else:
        logger.info("⏩ Bỏ qua gửi cảnh báo (--no-alert)")

    logger.info("✅ Hoàn thành audit!")


if __name__ == "__main__":
    main()
