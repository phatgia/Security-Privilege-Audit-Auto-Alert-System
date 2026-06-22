"""
=============================================================
  📜 Log Collector - Thu thập và phân tích auth logs
=============================================================
"""

import re
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)


class LogCollector:
    """
    Thu thập và phân tích logs từ:
    - /var/log/auth.log (Debian/Ubuntu)
    - /var/log/secure (RHEL/CentOS)
    - Sample auth log file (demo)
    """

    # Regex patterns để parse auth log
    SUDO_PATTERN = re.compile(
        r'(\w{3}\s+\d+\s[\d:]+)\s+\S+\s+sudo:\s+(\S+)\s+:.*COMMAND=(.+)'
    )
    SSH_LOGIN_PATTERN = re.compile(
        r'(\w{3}\s+\d+\s[\d:]+)\s+\S+\s+sshd\[.*\]:\s+Accepted\s+\S+\s+for\s+(\S+)\s+from\s+([\d.]+)'
    )
    SSH_FAIL_PATTERN = re.compile(
        r'(\w{3}\s+\d+\s[\d:]+)\s+\S+\s+sshd\[.*\]:\s+Failed\s+\S+\s+for\s+(\S+)\s+from\s+([\d.]+)'
    )
    SU_PATTERN = re.compile(
        r'(\w{3}\s+\d+\s[\d:]+)\s+\S+\s+su\[.*\]:\s+Successful su for (\S+) by (\S+)'
    )

    def __init__(self, log_file: str = None):
        self.log_file = log_file or "data/sample_auth.log"
        self.events = []
        self.sudo_activity = defaultdict(list)    # username -> [timestamps]
        self.ssh_activity = defaultdict(list)     # username -> [timestamps]
        self.failed_attempts = defaultdict(int)   # username -> count

    def collect(self) -> dict:
        """Thu thập và phân tích logs"""
        logger.info(f"[LogCollector] 📜 Đang parse log file: {self.log_file}")

        try:
            with open(self.log_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except FileNotFoundError:
            logger.warning(f"[LogCollector] Không tìm thấy {self.log_file}, dùng dữ liệu demo")
            lines = self._generate_demo_logs()

        for line in lines:
            self._parse_line(line.strip())

        return self._build_summary()

    def _parse_line(self, line: str):
        """Parse một dòng log"""
        # Sudo events
        m = self.SUDO_PATTERN.search(line)
        if m:
            timestamp_str, username, command = m.groups()
            self.sudo_activity[username].append({
                "timestamp": timestamp_str,
                "command": command.strip()
            })
            return

        # SSH successful login
        m = self.SSH_LOGIN_PATTERN.search(line)
        if m:
            timestamp_str, username, ip = m.groups()
            self.ssh_activity[username].append({
                "timestamp": timestamp_str,
                "ip": ip,
                "status": "success"
            })
            return

        # SSH failed login
        m = self.SSH_FAIL_PATTERN.search(line)
        if m:
            timestamp_str, username, ip = m.groups()
            self.failed_attempts[username] += 1
            return

        # Su events
        m = self.SU_PATTERN.search(line)
        if m:
            timestamp_str, target_user, from_user = m.groups()
            self.sudo_activity[from_user].append({
                "timestamp": timestamp_str,
                "command": f"su to {target_user}"
            })

    def _generate_demo_logs(self) -> list:
        """Tạo sample auth log data để demo"""
        now = datetime.now()

        def ts(days_ago, hour=10):
            dt = now - timedelta(days=days_ago)
            return dt.strftime(f"%b %d {hour:02d}:00:00")

        demo_lines = [
            # john.doe - active
            f"{ts(1)} server01 sudo: john.doe : TTY=pts/0 ; PWD=/home/john.doe ; USER=root ; COMMAND=/usr/bin/apt update",
            f"{ts(1)} server01 sshd[1234]: Accepted publickey for john.doe from 192.168.1.10 port 22 ssh2",
            f"{ts(2)} server01 sudo: john.doe : TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",

            # jane.smith - active
            f"{ts(3)} server01 sshd[2345]: Accepted publickey for jane.smith from 192.168.1.20 port 22 ssh2",
            f"{ts(3)} server01 sudo: jane.smith : TTY=pts/2 ; PWD=/opt ; USER=root ; COMMAND=/usr/bin/docker ps",

            # michael.lee - inactive (52+ days)
            f"{ts(52)} server01 sshd[3456]: Accepted publickey for michael.lee from 10.0.0.5 port 22 ssh2",
            f"{ts(52)} server01 sudo: michael.lee : TTY=pts/0 ; PWD=/etc ; USER=root ; COMMAND=/usr/bin/vim /etc/nginx/nginx.conf",

            # admin_old - very inactive
            f"{ts(202)} server01 sshd[4567]: Accepted password for admin_old from 192.168.100.1 port 22 ssh2",
            f"{ts(202)} server01 sudo: admin_old : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash",

            # Failed SSH attempts (suspicious)
            f"{ts(0)} server01 sshd[5678]: Failed password for sysadmin2019 from 203.0.113.1 port 22 ssh2",
            f"{ts(0)} server01 sshd[5679]: Failed password for sysadmin2019 from 203.0.113.1 port 22 ssh2",
            f"{ts(0)} server01 sshd[5680]: Failed password for sysadmin2019 from 203.0.113.1 port 22 ssh2",
            f"{ts(0)} server01 sshd[5681]: Failed password for root from 198.51.100.1 port 22 ssh2",

            # test_admin - inactive
            f"{ts(103)} server01 sudo: test_admin : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash",
            f"{ts(103)} server01 sshd[6789]: Accepted password for test_admin from 172.16.0.10 port 22 ssh2",

            # devops01 - active service account
            f"{ts(0, 1)} server01 sudo: devops01 : TTY=? ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker pull nginx:latest",
            f"{ts(0, 4)} server01 sudo: devops01 : TTY=? ; PWD=/ ; USER=root ; COMMAND=/usr/bin/systemctl restart app",
        ]

        return demo_lines

    def _build_summary(self) -> dict:
        """Tóm tắt kết quả phân tích log"""
        summary = {
            "log_file": self.log_file,
            "total_sudo_events": sum(len(v) for v in self.sudo_activity.values()),
            "total_ssh_logins": sum(len(v) for v in self.ssh_activity.values()),
            "failed_login_accounts": dict(self.failed_attempts),
            "sudo_activity": {
                user: {
                    "event_count": len(events),
                    "last_activity": events[-1]["timestamp"] if events else None,
                    "sample_commands": [e["command"] for e in events[-3:]]
                }
                for user, events in self.sudo_activity.items()
            },
            "ssh_activity": {
                user: {
                    "login_count": len(events),
                    "last_login": events[-1]["timestamp"] if events else None,
                    "ips": list(set(e["ip"] for e in events))
                }
                for user, events in self.ssh_activity.items()
            },
            "suspicious_accounts": [
                user for user, count in self.failed_attempts.items()
                if count >= 3
            ]
        }

        if summary["suspicious_accounts"]:
            logger.warning(
                f"[LogCollector] 🚨 Phát hiện brute force: {summary['suspicious_accounts']}"
            )

        logger.info(
            f"[LogCollector] ✅ Phân tích xong: {summary['total_sudo_events']} sudo events, "
            f"{summary['total_ssh_logins']} SSH logins, "
            f"{len(summary['suspicious_accounts'])} suspicious accounts"
        )

        return summary
