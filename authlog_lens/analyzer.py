"""Threat detection heuristics and security metrics aggregator for AuthLog Lens."""

from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict
from authlog_lens.models import (
    AnalysisReport,
    AuthEvent,
    EventType,
    IPMetrics,
    ThreatAlert,
    ThreatLevel,
)


def analyze_events(events: List[AuthEvent], log_file_path: str, total_lines: int) -> AnalysisReport:
    """Processes authentication events, identifies attacks, and generates threat alerts."""
    ip_stats: Dict[str, IPMetrics] = defaultdict(lambda: IPMetrics(ip=""))
    failed_total = 0
    success_total = 0
    all_users = set()

    for ev in events:
        if ev.username:
            all_users.add(ev.username)

        if not ev.ip_address:
            continue

        ip = ev.ip_address
        metrics = ip_stats[ip]
        metrics.ip = ip
        metrics.total_events += 1

        if ev.username:
            metrics.targeted_users.add(ev.username)

        if ev.event_type in (EventType.FAILED_LOGIN, EventType.INVALID_USER, EventType.ROOT_LOGIN):
            metrics.failed_logins += 1
            failed_total += 1
            if ev.event_type == EventType.INVALID_USER:
                metrics.invalid_user_attempts += 1
        elif ev.event_type == EventType.SUCCESSFUL_LOGIN:
            metrics.successful_logins += 1
            success_total += 1

    alerts: List[ThreatAlert] = []

    # Heuristic 1: SSH Brute Force Detection
    for ip, m in ip_stats.items():
        if m.failed_logins >= 5:
            severity = ThreatLevel.CRITICAL if m.failed_logins >= 20 else ThreatLevel.HIGH
            alerts.append(
                ThreatAlert(
                    alert_type="BRUTE_FORCE_SSH",
                    title=f"SSH Brute Force Attack Detected from {ip}",
                    threat_level=severity,
                    ip_address=ip,
                    description=f"IP generated {m.failed_logins} failed login attempts targeting {len(m.targeted_users)} user account(s).",
                    evidence_count=m.failed_logins,
                    recommendation="Block source IP via iptables / firewall and verify fail2ban configuration.",
                )
            )

    # Heuristic 2: Credential Stuffing / Username Enumeration
    for ip, m in ip_stats.items():
        if len(m.targeted_users) >= 4:
            alerts.append(
                ThreatAlert(
                    alert_type="CREDENTIAL_STUFFING",
                    title=f"Credential Stuffing / User Enumeration from {ip}",
                    threat_level=ThreatLevel.HIGH,
                    ip_address=ip,
                    description=f"IP attempted authenticating as {len(m.targeted_users)} distinct usernames ({', '.join(sorted(list(m.targeted_users))[:5])}...).",
                    evidence_count=len(m.targeted_users),
                    recommendation="Implement rate limiting and verify unprivileged account lockouts.",
                )
            )

    # Heuristic 3: Successful Login After Multiple Failures (Account Compromise Indicator)
    for ip, m in ip_stats.items():
        if m.failed_logins >= 3 and m.successful_logins >= 1:
            alerts.append(
                ThreatAlert(
                    alert_type="SUCCESS_AFTER_FAILURE",
                    title=f"Suspicious Successful Login After Failures from {ip}",
                    threat_level=ThreatLevel.CRITICAL,
                    ip_address=ip,
                    description=f"IP had {m.failed_logins} failed attempts before successfully logging into an account.",
                    evidence_count=m.successful_logins,
                    recommendation="Immediately investigate targeted user sessions, revoke tokens/keys, and enforce password resets.",
                )
            )

    # Heuristic 4: Direct Root Login Attempts
    root_attempts = [ev for ev in events if ev.username == "root" and ev.event_type in (EventType.FAILED_LOGIN, EventType.ROOT_LOGIN)]
    if len(root_attempts) >= 2:
        offending_ips = list({ev.ip_address for ev in root_attempts if ev.ip_address})
        alerts.append(
            ThreatAlert(
                alert_type="ROOT_LOGIN_TARGETING",
                title=f"Targeted Direct Root Login Attempts ({len(root_attempts)} events)",
                threat_level=ThreatLevel.HIGH,
                ip_address=offending_ips[0] if offending_ips else None,
                description=f"Multiple attempts were detected targeting the 'root' superuser directly from {len(offending_ips)} IP(s).",
                evidence_count=len(root_attempts),
                recommendation="Ensure 'PermitRootLogin no' is configured in /etc/ssh/sshd_config.",
            )
        )

    # Sort offending IPs by failed attempts descending
    sorted_ips = sorted(ip_stats.values(), key=lambda x: x.failed_logins, reverse=True)[:10]

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return AnalysisReport(
        log_file=log_file_path,
        total_lines=total_lines,
        parsed_events=len(events),
        failed_logins_total=failed_total,
        successful_logins_total=success_total,
        unique_source_ips=len(ip_stats),
        unique_targeted_users=len(all_users),
        top_offending_ips=sorted_ips,
        threat_alerts=alerts,
        scan_timestamp=now_str,
    )
