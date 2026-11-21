"""Reporting, formatting, and incident export tools for AuthLog Lens."""

import json
from authlog_lens.models import AnalysisReport, ThreatLevel

COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"
COLOR_GRAY = "\033[90m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"


def format_terminal(report: AnalysisReport, use_color: bool = True) -> str:
    lines = []
    c_bold = COLOR_BOLD if use_color else ""
    c_reset = COLOR_RESET if use_color else ""
    c_red = COLOR_RED if use_color else ""
    c_yellow = COLOR_YELLOW if use_color else ""
    c_green = COLOR_GREEN if use_color else ""
    c_gray = COLOR_GRAY if use_color else ""

    lines.append(f"{c_bold}AuthLog Lens: Authentication Log Security Analysis{c_reset}")
    lines.append(f"{c_gray}Log File:{c_reset}         {report.log_file}")
    lines.append(f"{c_gray}Lines Processed:{c_reset}  {report.total_lines} (Parsed events: {report.parsed_events})")
    lines.append(f"{c_gray}Unique IPs / Users:{c_reset} {report.unique_source_ips} source IPs | {report.unique_targeted_users} usernames")
    lines.append(f"{c_gray}Failed / Success:{c_reset}    {report.failed_logins_total} failed | {report.successful_logins_total} successful\n")

    if not report.threat_alerts:
        lines.append(f"{c_green}[✓] No high-severity authentication attacks or anomalies detected.{c_reset}\n")
    else:
        lines.append(f"{c_bold}Detected Threat Alerts ({len(report.threat_alerts)}):{c_reset}")
        lines.append("-" * 75)
        for idx, alert in enumerate(report.threat_alerts, 1):
            col = c_red if alert.threat_level == ThreatLevel.CRITICAL else c_yellow
            lines.append(f"{idx}. [{col}{alert.threat_level.value}{c_reset}] {c_bold}{alert.title}{c_reset}")
            if alert.ip_address:
                lines.append(f"   Source IP:      {alert.ip_address}")
            lines.append(f"   Details:        {alert.description}")
            lines.append(f"   Recommendation: {alert.recommendation}")
            lines.append("")

    if report.top_offending_ips:
        lines.append(f"{c_bold}Top Offending Source IPs:{c_reset}")
        lines.append("-" * 75)
        lines.append(f"{'Source IP':<18} | {'Failed':<8} | {'Success':<8} | {'Targeted Users'}")
        lines.append("-" * 75)
        for ip_m in report.top_offending_ips:
            users_preview = ", ".join(sorted(list(ip_m.targeted_users))[:4])
            lines.append(f"{ip_m.ip:<18} | {ip_m.failed_logins:<8} | {ip_m.successful_logins:<8} | {users_preview}")
        lines.append("")

    return "\n".join(lines)


def format_json(report: AnalysisReport) -> str:
    data = {
        "log_file": report.log_file,
        "total_lines": report.total_lines,
        "parsed_events": report.parsed_events,
        "failed_logins_total": report.failed_logins_total,
        "successful_logins_total": report.successful_logins_total,
        "unique_source_ips": report.unique_source_ips,
        "unique_targeted_users": report.unique_targeted_users,
        "scan_timestamp": report.scan_timestamp,
        "alerts": [
            {
                "type": a.alert_type,
                "title": a.title,
                "threat_level": a.threat_level.value,
                "ip": a.ip_address,
                "description": a.description,
                "evidence_count": a.evidence_count,
                "recommendation": a.recommendation,
            }
            for a in report.threat_alerts
        ],
        "top_offending_ips": [
            {
                "ip": m.ip,
                "failed_logins": m.failed_logins,
                "successful_logins": m.successful_logins,
                "invalid_users": m.invalid_user_attempts,
                "targeted_users": sorted(list(m.targeted_users)),
            }
            for m in report.top_offending_ips
        ],
    }
    return json.dumps(data, indent=2)


def format_markdown(report: AnalysisReport) -> str:
    lines = [
        "# AuthLog Lens Security Analysis Report",
        f"- **Log File:** `{report.log_file}`",
        f"- **Parsed Events:** {report.parsed_events} / {report.total_lines} lines",
        f"- **Total Failed Logins:** {report.failed_logins_total}",
        f"- **Total Successful Logins:** {report.successful_logins_total}",
        f"- **Scan Date:** {report.scan_timestamp}",
        "",
        "## Threat Alerts",
        "| Level | Type | Source IP | Details | Recommendation |",
        "|---|---|---|---|---|",
    ]
    for a in report.threat_alerts:
        lines.append(f"| `{a.threat_level.value}` | {a.alert_type} | `{a.ip_address or 'N/A'}` | {a.description} | {a.recommendation} |")

    lines.append("")
    lines.append("## Top Offending IPs")
    lines.append("| IP Address | Failed Attempts | Successful | Targeted Users |")
    lines.append("|---|---|---|---|")
    for m in report.top_offending_ips:
        users_str = ", ".join(f"`{u}`" for u in sorted(list(m.targeted_users))[:4])
        lines.append(f"| `{m.ip}` | {m.failed_logins} | {m.successful_logins} | {users_str} |")

    return "\n".join(lines)
