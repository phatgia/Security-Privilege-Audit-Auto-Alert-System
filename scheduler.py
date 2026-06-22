"""
=============================================================
  ⏰ Scheduler - Lập lịch kiểm tra tự động
  
  Chạy audit theo lịch định kỳ (mỗi ngày, mỗi giờ, v.v.)
  Sử dụng:
    python scheduler.py              # Chạy theo config (mặc định: mỗi ngày 08:00)
    python scheduler.py --interval 6 # Mỗi 6 giờ
    python scheduler.py --cron       # Cron-style (dùng với crontab)
=============================================================
"""

import logging
import sys
import time
import threading
import subprocess
import argparse
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

# ANSI colors cho terminal
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    PURPLE = "\033[95m"


def run_audit_now(config_path: str = "config.yaml", extra_args: list = None):
    """Chạy một lần audit ngay bây giờ"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logger.info(f"🔄 Chạy audit lúc {timestamp}")

    cmd = [sys.executable, "main.py", "--config", config_path]
    if extra_args:
        cmd.extend(extra_args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=False,
            timeout=300,  # Timeout 5 phút
            cwd=str(Path(__file__).parent)
        )
        if result.returncode == 0:
            logger.info(f"✅ Audit hoàn thành thành công lúc {timestamp}")
        else:
            logger.error(f"❌ Audit thất bại (exit code: {result.returncode})")
    except subprocess.TimeoutExpired:
        logger.error("⏰ Audit bị timeout sau 5 phút!")
    except Exception as e:
        logger.error(f"❌ Lỗi khi chạy audit: {e}")


class AuditScheduler:
    """Lập lịch chạy audit định kỳ"""

    def __init__(self, interval_hours: float = 24, config_path: str = "config.yaml",
                 run_at_hour: int = None, extra_args: list = None):
        self.interval_hours = interval_hours
        self.config_path = config_path
        self.run_at_hour = run_at_hour  # None = interval-based, số = run at that hour daily
        self.extra_args = extra_args or []
        self._running = False
        self._thread = None

    def _next_run_time(self) -> datetime:
        """Tính thời điểm chạy tiếp theo"""
        now = datetime.now()

        if self.run_at_hour is not None:
            # Chạy vào giờ cố định mỗi ngày
            next_run = now.replace(hour=self.run_at_hour, minute=0, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
            return next_run
        else:
            # Interval-based
            return now + timedelta(hours=self.interval_hours)

    def _schedule_loop(self):
        """Vòng lặp lập lịch chính"""
        logger.info(f"{C.CYAN}⏰ Scheduler đã khởi động{C.RESET}")

        # Chạy ngay lần đầu
        logger.info(f"{C.GREEN}▶ Chạy audit ngay lần đầu...{C.RESET}")
        run_audit_now(self.config_path, self.extra_args)

        while self._running:
            next_run = self._next_run_time()
            wait_secs = (next_run - datetime.now()).total_seconds()

            logger.info(
                f"{C.YELLOW}⏳ Lần chạy tiếp theo: {next_run.strftime('%Y-%m-%d %H:%M:%S')} "
                f"(sau {wait_secs/3600:.1f} giờ){C.RESET}"
            )

            # Chờ, nhưng có thể interrupt mỗi 60 giây để check _running
            while self._running and datetime.now() < next_run:
                remaining = (next_run - datetime.now()).total_seconds()
                sleep_time = min(60, remaining)
                if sleep_time > 0:
                    time.sleep(sleep_time)

            if self._running:
                logger.info(f"{C.GREEN}▶ Bắt đầu audit theo lịch...{C.RESET}")
                run_audit_now(self.config_path, self.extra_args)

    def start(self):
        """Bắt đầu scheduler trong background thread"""
        self._running = True
        self._thread = threading.Thread(target=self._schedule_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Dừng scheduler"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("⏹️ Scheduler đã dừng")


def print_banner():
    """In banner khởi động"""
    print(f"\n{C.PURPLE}{C.BOLD}")
    print("╔══════════════════════════════════════════════╗")
    print("║   🔐 PRIVILEGE AUDITOR SCHEDULER             ║")
    print("║   Tự động rà soát quyền admin định kỳ        ║")
    print("╚══════════════════════════════════════════════╝")
    print(f"{C.RESET}")


def main():
    parser = argparse.ArgumentParser(
        description="⏰ Privilege Auditor Scheduler - Lập lịch kiểm tra tự động"
    )
    parser.add_argument(
        "--interval", type=float, default=24,
        help="Khoảng thời gian giữa các lần audit (giờ, mặc định: 24)"
    )
    parser.add_argument(
        "--at-hour", type=int, default=None,
        help="Chạy vào giờ cố định hàng ngày (VD: 8 = 08:00 AM)"
    )
    parser.add_argument(
        "--config", default="config.yaml",
        help="Đường dẫn file cấu hình"
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Chỉ chạy một lần và thoát (không lập lịch)"
    )
    parser.add_argument(
        "--no-alert", action="store_true",
        help="Chạy không gửi cảnh báo"
    )
    parser.add_argument(
        "--system", nargs="+", choices=["linux", "ad", "aws"],
        help="Chỉ kiểm tra các hệ thống này"
    )

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("logs/scheduler.log", encoding="utf-8")
        ]
    )

    Path("logs").mkdir(exist_ok=True)
    print_banner()

    # Build extra args
    extra_args = []
    if args.no_alert:
        extra_args.append("--no-alert")
    if args.system:
        extra_args.extend(["--system"] + args.system)

    if args.once:
        print(f"{C.GREEN}▶ Chạy audit một lần...{C.RESET}\n")
        run_audit_now(args.config, extra_args)
        return

    # Start scheduler
    mode = f"giờ {args.at_hour:02d}:00 hàng ngày" if args.at_hour is not None else f"mỗi {args.interval} giờ"
    print(f"{C.CYAN}📅 Lịch kiểm tra: {mode}{C.RESET}")
    print(f"{C.YELLOW}💡 Nhấn Ctrl+C để dừng{C.RESET}\n")

    scheduler = AuditScheduler(
        interval_hours=args.interval,
        config_path=args.config,
        run_at_hour=args.at_hour,
        extra_args=extra_args
    )

    scheduler.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}⚠️ Nhận tín hiệu dừng...{C.RESET}")
        scheduler.stop()
        print(f"{C.GREEN}✅ Scheduler đã dừng an toàn.{C.RESET}\n")


if __name__ == "__main__":
    main()
