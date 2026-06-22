<div align="center">

#  Privilege Auditor

**Tự động hóa rà soát quyền truy cập trên Linux, Active Directory và AWS IAM**  
Cảnh báo tức thì qua Telegram / Slack khi phát hiện admin không hoạt động ≥ 30 ngày

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)]()
[![Telegram](https://img.shields.io/badge/Alert-Telegram%20Bot-blue?logo=telegram)](https://core.telegram.org/bots)
[![Slack](https://img.shields.io/badge/Alert-Slack%20Webhook-purple?logo=slack)](https://api.slack.com/messaging/webhooks)

</div>

---

##  Mục Lục

- [Giới thiệu](#-giới-thiệu)
- [Tính năng](#-tính-năng)
- [Cấu trúc dự án](#-cấu-trúc-dự-án)
- [Cài đặt](#-cài-đặt)
- [Cấu hình](#-cấu-hình)
- [Sử dụng](#-sử-dụng)
- [Web Dashboard](#-web-dashboard)
- [Cảnh báo Telegram / Slack](#-cảnh-báo-telegram--slack)
- [Lập lịch tự động](#-lập-lịch-tự-động)
- [Kết nối AWS thật](#-kết-nối-aws-thật)
- [Ví dụ kết quả](#-ví-dụ-kết-quả)

---

##  Giới thiệu

**Privilege Auditor** là công cụ bảo mật viết bằng Python giúp:

-  **Phân tích Linux** — Parse `/etc/sudoers` và nhóm `wheel`/`sudo` để tìm tài khoản admin không hoạt động
-  **Kiểm tra Active Directory** — Rà soát Domain Admins, Enterprise Admins theo `lastLogon`
-  **Audit AWS IAM** — Phân tích credential report, access keys, MFA, và overly-permissive policies
-  **Thu thập logs** — Parse `auth.log` / `secure` để theo dõi sudo events và phát hiện brute force
-  **Cảnh báo tự động** — Gửi alert qua **Telegram Bot** và **Slack Webhook** khi phát hiện vi phạm
-  **Web Dashboard** — Giao diện trực quan với Chart.js, bảng filter/search, modal chi tiết
-  **Lập lịch** — Tự động kiểm tra định kỳ (mỗi ngày, mỗi giờ, hoặc theo cron)

---

##  Tính năng

| Tính năng | Mô tả |
|-----------|-------|
|  Multi-platform audit | Linux, AD giả lập, AWS IAM trong một lần chạy |
|  Risk scoring | Tự động tính điểm rủi ro: CRITICAL / HIGH / MEDIUM / LOW |
|  Inactive detection | Cảnh báo admin không login trong 30 ngày (tùy chỉnh được) |
|  NOPASSWD detection | Phát hiện sudo không cần mật khẩu |
|  MFA check | Phát hiện admin AWS không bật MFA |
|  Key rotation | Cảnh báo access key AWS quá cũ chưa rotate |
|  Brute force | Phát hiện tài khoản bị tấn công SSH brute force |
|  HTML + JSON report | Tự động tạo báo cáo chi tiết sau mỗi lần audit |
|  Telegram alert | Gửi tin nhắn Markdown đẹp với emoji theo severity |
|  Slack Block Kit | Rich message với màu sắc, fields, và attachments |
|  Web dashboard | Dark mode, Chart.js, filter/sort/search, export JSON |
|  Auto scheduler | Chạy nền với interval hoặc giờ cố định |

---

##  Cấu trúc dự án

```
privilege-auditor/
│
├── auditors/                       # Core audit engines
│   ├── __init__.py
│   ├── linux_auditor.py            # Parse /etc/sudoers + wheel/sudo group
│   ├── ad_auditor.py               # Active Directory (JSON/LDAP)
│   └── aws_iam_auditor.py          # AWS IAM credential report
│
├── alerting/                       # Notification modules
│   ├── __init__.py
│   ├── telegram_alert.py           # Telegram Bot API
│   └── slack_alert.py              # Slack Incoming Webhooks
│
├── collectors/                     # Log collection
│   ├── __init__.py
│   └── log_collector.py            # Parse auth.log, detect brute force
│
├── reports/                        # Report generation
│   ├── __init__.py
│   ├── report_generator.py         # HTML + JSON report builder
│   ├── audit_report.html           # ← Generated report (tự động tạo)
│   └── audit_YYYYMMDD_HHMMSS.json  # ← Generated report (tự động tạo)
│
├── dashboard/                      # Web UI
│   ├── index.html                  # Dashboard chính
│   ├── style.css                   # Dark mode + Glassmorphism
│   └── app.js                      # Chart.js + interactive table
│
├── data/                           # Sample data (dùng để demo/test)
│   ├── sample_sudoers              # /etc/sudoers mẫu
│   ├── sample_group                # /etc/group mẫu
│   ├── sample_lastlog.json         # Lastlog data mẫu
│   ├── sample_ad_users.json        # Active Directory giả lập
│   └── sample_iam_data.json        # AWS IAM giả lập
│
├── logs/                           # Log files (tự động tạo)
│   └── auditor.log
│
├── main.py                         #  Entry point chính
├── scheduler.py                    #  Lập lịch tự động
├── config.yaml                     #  Cấu hình
└── requirements.txt
```

---

##  Cài đặt

### Yêu cầu

- Python **3.8+**
- Windows / Linux / macOS

### Bước 1 — Clone / tải về

```bash
cd privilege-auditor
```

### Bước 2 — Cài dependencies

```bash
python -m pip install -r requirements.txt
```

> **requirements.txt** bao gồm:
> - `pyyaml` — đọc file cấu hình YAML
> - `boto3` *(tùy chọn)* — kết nối AWS thật
> - `ldap3` *(tùy chọn)* — kết nối AD thật

### Bước 3 — Chạy thử ngay

```bash
# Linux / macOS
python main.py --no-alert

# Windows (cần flag -X utf8 cho emoji)
python -X utf8 main.py --no-alert
```

---

##  Cấu hình

Mở file `config.yaml` và chỉnh sửa theo môi trường của bạn:

```yaml
# ─── Ngưỡng cảnh báo ─────────────────────────────────────
thresholds:
  inactive_days: 30           # Không dùng 30 ngày → cảnh báo
  critical_inactive_days: 60  # Không dùng 60 ngày → critical

# ─── Telegram Bot ────────────────────────────────────────
telegram:
  enabled: true
  bot_token: "7123456789:AAHxxxxxxxxxxxxxxxxxxxxxx"  # Từ @BotFather
  chat_id: "-1001234567890"                           # Group/Channel ID

# ─── Slack Webhook ───────────────────────────────────────
slack:
  enabled: true
  webhook_url: "https://hooks.slack.com/services/T.../B.../xxxx"
  channel: "#security-alerts"

# ─── Hệ thống cần kiểm tra ───────────────────────────────
audit_targets:
  linux:
    enabled: true
    sudoers_file: "data/sample_sudoers"   # Thay bằng /etc/sudoers trên Linux thật
    group_file: "data/sample_group"        # Thay bằng /etc/group
    lastlog_file: "data/sample_lastlog.json"
    auth_log: "/var/log/auth.log"          # Hoặc /var/log/secure (RHEL)

  active_directory:
    enabled: true
    data_file: "data/sample_ad_users.json"

  aws_iam:
    enabled: true
    use_real_aws: false                    # Đổi thành true để dùng AWS thật
    data_file: "data/sample_iam_data.json"
```

###  Lấy Telegram Bot Token

1. Mở Telegram, tìm **@BotFather**
2. Gõ `/newbot` → đặt tên → lấy **token**
3. Gửi một tin nhắn cho bot của bạn
4. Truy cập URL để lấy `chat_id`:
   ```
   https://api.telegram.org/bot<TOKEN>/getUpdates
   ```
5. Điền `bot_token` và `chat_id` vào `config.yaml`

###  Lấy Slack Webhook URL

1. Vào [api.slack.com/apps](https://api.slack.com/apps) → **Create New App**
2. Chọn **Incoming Webhooks** → Activate
3. **Add New Webhook to Workspace** → chọn channel
4. Copy **Webhook URL** vào `config.yaml`

---

##  Sử dụng

### Lệnh cơ bản

```bash
# Audit tất cả hệ thống (Linux + AD + AWS IAM)
python -X utf8 main.py

# Chỉ audit Linux
python -X utf8 main.py --system linux

# Chỉ audit Active Directory
python -X utf8 main.py --system ad

# Audit AD và AWS, không gửi alert
python -X utf8 main.py --system ad aws --no-alert

# Đổi ngưỡng inactive thành 45 ngày
python -X utf8 main.py --days 45

# Test kết nối Telegram / Slack
python -X utf8 main.py --alert-test

# Verbose (log DEBUG)
python -X utf8 main.py --verbose

# Chỉ in ra console, không tạo file report
python -X utf8 main.py --no-report --no-alert
```

### Toàn bộ tùy chọn CLI

```
usage: main.py [-h] [--system {linux,ad,aws} [...]] [--days DAYS]
               [--config CONFIG] [--alert-test] [--no-alert]
               [--no-report] [--verbose]

Options:
  --system     Hệ thống cần kiểm tra (mặc định: tất cả)
  --days       Ngưỡng ngày không hoạt động (mặc định từ config.yaml)
  --config     Đường dẫn file cấu hình (mặc định: config.yaml)
  --alert-test Chỉ gửi tin nhắn test đến Telegram/Slack
  --no-alert   Chạy không gửi cảnh báo
  --no-report  Không tạo file HTML/JSON report
  --verbose    Bật DEBUG logging
```

---

##  Web Dashboard

Mở file `dashboard/index.html` trực tiếp trên trình duyệt:

```
privilege-auditor/dashboard/index.html
```

Dashboard bao gồm:

| Widget | Mô tả |
|--------|-------|
| **Stats Cards** | Tổng số critical issues, inactive admins, privileged accounts |
| **Risk Donut Chart** | Phân bố Critical / High / Medium / Low |
| **Inactive Bar Chart** | Histogram ngày không hoạt động |
| **System Comparison** | So sánh Linux vs AD vs AWS |
| **User Table** | Bảng full với sort / filter / search |
| **Risk Filter Chips** | Lọc nhanh theo mức độ rủi ro |
| **User Detail Modal** | Click "Chi tiết" xem đầy đủ |
| **Auth Log Panel** | Số sudo events, SSH logins, brute force |
| **Export JSON** | Tải xuống dữ liệu audit |

>  Dashboard tự động đọc `reports/dashboard_data.json` nếu có. Nếu không có, nó hiển thị dữ liệu demo.

---

##  Cảnh báo Telegram / Slack

### Telegram — Ví dụ tin nhắn

```
 CRITICAL - Tài Khoản Đặc Quyền Cần Xem Xét
━━━━━━━━━━━━━━━━━━━━━
 Hệ thống: Linux Server
 User: sysadmin2019
 Không hoạt động: 736 ngày

 Chi tiết rủi ro:
  •  Không hoạt động 736 ngày (vượt ngưỡng critical 60 ngày)
  •  Có full sudo access (ALL=(ALL) ALL)
  •  Tài khoản vẫn ENABLED dù inactive lâu

 Hành động đề xuất:
  • Xác nhận với chủ tài khoản còn cần quyền không
  • Nếu không cần: thu hồi quyền hoặc disable tài khoản
  • Ghi nhật ký hành động vào ticket bảo mật

 Tự động phát hiện bởi Privilege Auditor
```

### Các loại alert được gửi

| Alert | Khi nào |
|-------|---------|
| **Summary** | Tóm tắt toàn bộ hệ thống sau mỗi lần audit |
| **Batch Inactive** | Danh sách admin inactive theo từng system |
| **Critical Detail** | Chi tiết từng user CRITICAL/HIGH |
| **Test Message** | Khi chạy `--alert-test` |

---

##  Lập lịch tự động

```bash
# Chạy mỗi ngày lúc 08:00 sáng
python -X utf8 scheduler.py --at-hour 8

# Chạy mỗi 6 giờ
python -X utf8 scheduler.py --interval 6

# Chạy mỗi 12 giờ, chỉ Linux, không gửi alert
python -X utf8 scheduler.py --interval 12 --system linux --no-alert

# Chạy một lần ngay và thoát
python -X utf8 scheduler.py --once

# Tất cả tùy chọn
python -X utf8 scheduler.py --help
```

### Tích hợp với Crontab (Linux thật)

```bash
# Chỉnh crontab:
crontab -e

# Thêm dòng sau — chạy mỗi ngày lúc 8:00 AM:
0 8 * * * /usr/bin/python3 /opt/privilege-auditor/main.py >> /var/log/privilege-auditor.log 2>&1

# Hoặc dùng systemd timer:
# /etc/systemd/system/privilege-auditor.timer
```

---

##  Kết nối AWS thật

1. Cài boto3:
   ```bash
   python -m pip install boto3
   ```

2. Cấp quyền IAM tối thiểu cho user/role:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "iam:GenerateCredentialReport",
           "iam:GetCredentialReport",
           "iam:ListUsers",
           "iam:ListGroupsForUser",
           "iam:ListAttachedUserPolicies",
           "iam:GetAccountAuthorizationDetails"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

3. Cập nhật `config.yaml`:
   ```yaml
   aws_iam:
     enabled: true
     use_real_aws: true
     aws_access_key_id: "AKIAIOSFODNN7EXAMPLE"
     aws_secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
     aws_region: "us-east-1"
   ```

---

##  Ví dụ kết quả

```
════════════════════════════════════════════════════════════
   PRIVILEGE AUDIT REPORT SUMMARY
════════════════════════════════════════════════════════════

   Linux Servers
  ├─ Tổng tài khoản đặc quyền : 12
  ├─ Không hoạt động          : 5
  └─ Critical                  : 3
      sysadmin2019 (736 ngày inactive)
      admin_old (202 ngày inactive)
      test_admin (103 ngày inactive)

   Active Directory
  ├─ Tổng tài khoản đặc quyền : 8
  ├─ Không hoạt động          : 4
  └─ Critical                  : 3
      admin_temp2024 (536 ngày inactive)
      charlie.pham (324 ngày inactive)
      bob.tran (67 ngày inactive)

    AWS IAM
  ├─ Tổng tài khoản đặc quyền : 5
  ├─ Không hoạt động          : 4
  └─ Critical                  : 4
      root-backup-2021 (1467 ngày inactive!)
      charlie-admin (232 ngày inactive)
      erik-temp (77 ngày inactive)

────────────────────────────────────────────────────────────
   TỔNG KẾT: 10 CRITICAL | 13 INACTIVE
════════════════════════════════════════════════════════════

 Báo cáo đã tạo:
   → reports/audit_report.html
```

---

##  Lưu ý bảo mật

> [!CAUTION]
> - **Không commit** `config.yaml` chứa token/key thật lên git
> - Thêm vào `.gitignore`: `config.yaml`, `logs/`, `reports/`
> - AWS credentials nên dùng **IAM Role** hoặc **AWS Secrets Manager** thay vì key tĩnh
> - File report HTML/JSON chứa thông tin nhạy cảm — hạn chế truy cập

---

##  Đóng góp

Pull requests và issues đều được chào đón.  
Để thêm support cho hệ thống mới (ví dụ: GCP IAM, Azure AD), tạo file `auditors/gcp_auditor.py` theo cùng interface với các auditor hiện có.

---

##  License

MIT License — tự do sử dụng, chỉnh sửa và phân phối.
"# Security-Privilege-Audit-Auto-Alert-System" 
"# Security-Privilege-Audit-Auto-Alert-System" 
