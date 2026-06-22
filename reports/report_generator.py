"""
=============================================================
  📊 Report Generator
  Tạo báo cáo HTML và JSON từ kết quả audit
=============================================================
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Tạo báo cáo audit dưới dạng HTML và JSON"""

    RISK_COLORS = {
        "CRITICAL": ("#FF3B3B", "#2D0808"),
        "HIGH":     ("#FF8C00", "#2D1500"),
        "MEDIUM":   ("#FFD700", "#2D2500"),
        "LOW":      ("#00D26A", "#002214"),
    }

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, all_reports: list, log_summary: dict = None) -> dict:
        """Tạo toàn bộ báo cáo"""
        timestamp = datetime.now()
        ts_str = timestamp.strftime("%Y%m%d_%H%M%S")

        # Save JSON
        json_path = self.output_dir / f"audit_{ts_str}.json"
        combined = {
            "generated_at": timestamp.isoformat(),
            "systems": all_reports,
            "log_analysis": log_summary or {}
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(combined, f, ensure_ascii=False, indent=2)

        # Save HTML report
        html_path = self.output_dir / "audit_report.html"
        html_content = self._build_html(all_reports, log_summary, timestamp)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        # Save JSON data for dashboard
        dashboard_data_path = self.output_dir / "dashboard_data.json"
        with open(dashboard_data_path, "w", encoding="utf-8") as f:
            json.dump(combined, f, ensure_ascii=False, indent=2)

        logger.info(f"[Report] 📄 Báo cáo HTML: {html_path}")
        logger.info(f"[Report] 📄 Báo cáo JSON: {json_path}")

        return {
            "html_path": str(html_path),
            "json_path": str(json_path),
            "timestamp": timestamp.isoformat()
        }

    def _build_html(self, all_reports: list, log_summary: dict, timestamp: datetime) -> str:
        """Build HTML report content"""

        # Tính tổng số liệu
        total_privileged = 0
        total_inactive = 0
        total_critical = 0
        system_cards = ""

        for report in all_reports:
            system = report.get("system", "unknown")
            summary = report.get("summary", {})
            users = report.get("users", [])

            priv = summary.get("total_privileged_users", 0)
            inactive = summary.get("inactive_users",
                                   summary.get("inactive_privileged_users", 0))
            critical = summary.get("critical_users", 0)

            total_privileged += priv
            total_inactive += inactive
            total_critical += critical

            system_emoji = {"linux": "🐧", "active_directory": "🏢", "aws_iam": "☁️"}.get(system, "🖥️")
            system_name = {
                "linux": "Linux Servers",
                "active_directory": "Active Directory",
                "aws_iam": "AWS IAM"
            }.get(system, system.upper())

            # Users table rows
            rows = ""
            for u in users:
                username = u.get("username") or u.get("sam_account", "?")
                days = u.get("days_inactive", 0)
                risk = u.get("risk_level", "LOW")
                fg, bg = self.RISK_COLORS.get(risk, ("#888", "#111"))
                alerts_html = "<br>".join(u.get("alerts", [])[:3])
                last_login = u.get("last_login") or u.get("last_logon", "N/A")
                if last_login and last_login != "N/A":
                    try:
                        last_login = datetime.fromisoformat(last_login).strftime("%Y-%m-%d")
                    except Exception:
                        pass

                rows += f"""
                <tr>
                    <td><code>{username}</code></td>
                    <td>{last_login}</td>
                    <td class="days-inactive">{days if days >= 0 else "Unknown"}</td>
                    <td><span class="badge" style="background:{bg};color:{fg};border:1px solid {fg}">{risk}</span></td>
                    <td class="alerts-cell">{alerts_html}</td>
                </tr>"""

            system_cards += f"""
            <div class="system-card">
                <div class="system-header">
                    <span class="system-icon">{system_emoji}</span>
                    <h2>{system_name}</h2>
                    <div class="system-stats">
                        <div class="stat">
                            <div class="stat-val">{priv}</div>
                            <div class="stat-label">Privileged</div>
                        </div>
                        <div class="stat">
                            <div class="stat-val warn">{inactive}</div>
                            <div class="stat-label">Inactive</div>
                        </div>
                        <div class="stat">
                            <div class="stat-val critical">{critical}</div>
                            <div class="stat-label">Critical</div>
                        </div>
                    </div>
                </div>
                <div class="table-wrapper">
                    <table>
                        <thead>
                            <tr>
                                <th>Username</th>
                                <th>Last Login</th>
                                <th>Days Inactive</th>
                                <th>Risk Level</th>
                                <th>Alerts</th>
                            </tr>
                        </thead>
                        <tbody>{rows}</tbody>
                    </table>
                </div>
            </div>"""

        # Log analysis section
        log_section = ""
        if log_summary:
            suspicious = log_summary.get("suspicious_accounts", [])
            sudo_events = log_summary.get("total_sudo_events", 0)
            ssh_logins = log_summary.get("total_ssh_logins", 0)
            failed = log_summary.get("failed_login_accounts", {})

            suspicious_html = ""
            for acc in suspicious:
                count = failed.get(acc, 0)
                suspicious_html += f'<div class="suspicious-item">⚠️ <code>{acc}</code> — {count} lần thất bại</div>'

            log_section = f"""
            <div class="log-section">
                <h2>📜 Phân Tích Auth Log</h2>
                <div class="log-stats">
                    <div class="log-stat">
                        <span class="log-stat-val">{sudo_events}</span>
                        <span class="log-stat-label">Sudo Events</span>
                    </div>
                    <div class="log-stat">
                        <span class="log-stat-val">{ssh_logins}</span>
                        <span class="log-stat-label">SSH Logins</span>
                    </div>
                    <div class="log-stat">
                        <span class="log-stat-val warn">{len(suspicious)}</span>
                        <span class="log-stat-label">Brute Force</span>
                    </div>
                </div>
                {f'<div class="suspicious-section"><h3>🚨 Tài Khoản Bị Brute Force:</h3>{suspicious_html}</div>' if suspicious else ''}
            </div>"""

        ts_display = timestamp.strftime("%d/%m/%Y %H:%M:%S")

        return f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔐 Privilege Audit Report — {ts_display}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

        :root {{
            --bg-primary: #0a0e1a;
            --bg-secondary: #111827;
            --bg-card: #141c2e;
            --bg-table: #0d1525;
            --accent: #6366f1;
            --accent-2: #8b5cf6;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --border: #1e2d45;
            --critical: #ff3b3b;
            --high: #ff8c00;
            --warning: #ffd700;
            --success: #00d26a;
        }}

        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        body {{
            font-family: 'Inter', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            background-image: radial-gradient(ellipse at top, #1a1040 0%, #0a0e1a 60%);
        }}

        .report-header {{
            background: linear-gradient(135deg, #1a0533 0%, #0d1040 50%, #001a33 100%);
            border-bottom: 1px solid #2a1a4a;
            padding: 40px;
            text-align: center;
        }}

        .report-header h1 {{
            font-size: 2.4rem;
            font-weight: 700;
            background: linear-gradient(135deg, #a78bfa, #60a5fa, #34d399);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
        }}

        .report-meta {{
            color: var(--text-secondary);
            font-size: 0.95rem;
        }}

        .container {{ max-width: 1400px; margin: 0 auto; padding: 30px 20px; }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 20px;
            margin-bottom: 40px;
        }}

        .summary-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 28px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}

        .summary-card::before {{
            content: '';
            position: absolute;
            top: 0; left: 0; right: 0;
            height: 3px;
            background: var(--gradient, linear-gradient(90deg, var(--accent), var(--accent-2)));
        }}

        .summary-card.critical {{ --gradient: linear-gradient(90deg, #ff3b3b, #ff6b6b); }}
        .summary-card.warning  {{ --gradient: linear-gradient(90deg, #ff8c00, #ffd700); }}
        .summary-card.info     {{ --gradient: linear-gradient(90deg, #6366f1, #8b5cf6); }}

        .summary-value {{
            font-size: 3.5rem;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            line-height: 1;
            margin-bottom: 8px;
        }}

        .summary-card.critical .summary-value {{ color: var(--critical); }}
        .summary-card.warning  .summary-value {{ color: var(--warning); }}
        .summary-card.info     .summary-value {{ color: var(--accent); }}

        .summary-label {{ color: var(--text-secondary); font-size: 0.9rem; font-weight: 500; }}

        .system-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            margin-bottom: 30px;
            overflow: hidden;
        }}

        .system-header {{
            display: flex;
            align-items: center;
            gap: 16px;
            padding: 24px 28px;
            border-bottom: 1px solid var(--border);
            background: linear-gradient(90deg, rgba(99,102,241,0.05), transparent);
        }}

        .system-icon {{ font-size: 2rem; }}
        .system-header h2 {{ font-size: 1.4rem; font-weight: 600; flex: 1; }}

        .system-stats {{
            display: flex;
            gap: 24px;
        }}

        .stat {{
            text-align: center;
            min-width: 70px;
        }}

        .stat-val {{
            font-size: 1.8rem;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
        }}

        .stat-val.warn     {{ color: var(--warning); }}
        .stat-val.critical {{ color: var(--critical); }}
        .stat-label {{ font-size: 0.75rem; color: var(--text-secondary); }}

        .table-wrapper {{ overflow-x: auto; }}

        table {{
            width: 100%;
            border-collapse: collapse;
        }}

        thead tr {{
            background: var(--bg-table);
            border-bottom: 1px solid var(--border);
        }}

        th {{
            padding: 14px 20px;
            text-align: left;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
        }}

        td {{
            padding: 14px 20px;
            border-bottom: 1px solid rgba(30,45,69,0.5);
            font-size: 0.9rem;
            vertical-align: top;
        }}

        tbody tr:hover {{ background: rgba(99,102,241,0.05); }}
        tbody tr:last-child td {{ border-bottom: none; }}

        code {{
            font-family: 'JetBrains Mono', monospace;
            background: rgba(99,102,241,0.1);
            color: #a78bfa;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.85em;
        }}

        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.05em;
        }}

        .days-inactive {{ font-family: 'JetBrains Mono', monospace; font-weight: 600; }}
        .alerts-cell {{ font-size: 0.82rem; color: var(--text-secondary); line-height: 1.6; }}

        .log-section {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 28px;
            margin-top: 30px;
        }}

        .log-section h2 {{ font-size: 1.3rem; margin-bottom: 20px; }}

        .log-stats {{
            display: flex;
            gap: 24px;
            margin-bottom: 24px;
        }}

        .log-stat {{
            display: flex;
            flex-direction: column;
            align-items: center;
            background: var(--bg-table);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 16px 24px;
            min-width: 120px;
        }}

        .log-stat-val {{
            font-size: 2rem;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
            color: var(--accent);
        }}

        .log-stat-val.warn {{ color: var(--warning); }}
        .log-stat-label {{ font-size: 0.8rem; color: var(--text-secondary); }}

        .suspicious-section h3 {{ margin-bottom: 12px; color: var(--critical); }}
        .suspicious-item {{
            background: rgba(255,59,59,0.08);
            border: 1px solid rgba(255,59,59,0.2);
            border-radius: 8px;
            padding: 10px 16px;
            margin-bottom: 8px;
            font-size: 0.9rem;
        }}

        .report-footer {{
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.85rem;
            border-top: 1px solid var(--border);
            margin-top: 40px;
        }}

        @media (max-width: 768px) {{
            .summary-grid {{ grid-template-columns: 1fr; }}
            .system-stats {{ gap: 12px; }}
            .log-stats {{ flex-wrap: wrap; }}
        }}
    </style>
</head>
<body>
    <div class="report-header">
        <h1>🔐 Privilege Audit Report</h1>
        <p class="report-meta">Tự động tạo bởi Privilege Auditor · {ts_display}</p>
    </div>

    <div class="container">
        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="summary-value">{total_critical}</div>
                <div class="summary-label">🔴 Vấn đề Critical</div>
            </div>
            <div class="summary-card warning">
                <div class="summary-value">{total_inactive}</div>
                <div class="summary-label">⚠️ Admin Không Hoạt Động</div>
            </div>
            <div class="summary-card info">
                <div class="summary-value">{total_privileged}</div>
                <div class="summary-label">👑 Tổng Tài Khoản Đặc Quyền</div>
            </div>
        </div>

        {system_cards}
        {log_section}
    </div>

    <div class="report-footer">
        🔐 Security Privilege Auditor · Tự động tạo lúc {ts_display} · Báo cáo này chứa thông tin bảo mật nhạy cảm
    </div>
</body>
</html>"""
