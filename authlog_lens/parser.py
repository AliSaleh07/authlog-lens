"""Authentication log parser for Linux syslog (auth.log / secure) formats."""

import re
from typing import Optional, List
from authlog_lens.models import AuthEvent, EventType

# Standard Syslog format: Oct 24 12:30:15 hostname sshd[1234]: message
SYSLOG_PATTERN = re.compile(
    r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\s+(\S+)\s+([^\[:]+)(?:\[\d+\])?:\s+(.*)$"
)

# SSH Event Patterns
FAILED_INVALID_USER_PATTERN = re.compile(
    r"Failed password for invalid user (\S+) from (\d{1,3}(?:\.\d{1,3}){3}) port (\d+)", re.IGNORECASE
)
FAILED_USER_PATTERN = re.compile(
    r"Failed password for (\S+) from (\d{1,3}(?:\.\d{1,3}){3}) port (\d+)", re.IGNORECASE
)
ACCEPTED_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from (\d{1,3}(?:\.\d{1,3}){3}) port (\d+)", re.IGNORECASE
)
INVALID_USER_NOTICE = re.compile(
    r"Invalid user (\S+) from (\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE
)
SUDO_PATTERN = re.compile(
    r"(\S+) : TTY=\S+ ; PWD=\S+ ; USER=(\S+) ; COMMAND=(.*)"
)


def parse_line(line: str) -> Optional[AuthEvent]:
    """Parses a single syslog line into an AuthEvent object."""
    clean_line = line.strip()
    if not clean_line:
        return None

    match = SYSLOG_PATTERN.match(clean_line)
    if not match:
        return None

    timestamp, hostname, service, message = match.groups()
    service = service.strip()

    # 1. Failed password for invalid user
    m_inv_fail = FAILED_INVALID_USER_PATTERN.search(message)
    if m_inv_fail:
        user, ip, port = m_inv_fail.groups()
        return AuthEvent(
            timestamp=timestamp,
            hostname=hostname,
            service=service,
            event_type=EventType.INVALID_USER,
            username=user,
            ip_address=ip,
            port=int(port),
            raw_message=message,
        )

    # 2. Failed password for legitimate user
    m_fail = FAILED_USER_PATTERN.search(message)
    if m_fail:
        user, ip, port = m_fail.groups()
        event_type = EventType.ROOT_LOGIN if user == "root" else EventType.FAILED_LOGIN
        return AuthEvent(
            timestamp=timestamp,
            hostname=hostname,
            service=service,
            event_type=event_type,
            username=user,
            ip_address=ip,
            port=int(port),
            raw_message=message,
        )

    # 3. Accepted login (password or key)
    m_acc = ACCEPTED_PATTERN.search(message)
    if m_acc:
        user, ip, port = m_acc.groups()
        return AuthEvent(
            timestamp=timestamp,
            hostname=hostname,
            service=service,
            event_type=EventType.SUCCESSFUL_LOGIN,
            username=user,
            ip_address=ip,
            port=int(port),
            raw_message=message,
        )

    # 4. Invalid user attempt notice
    m_inv = INVALID_USER_NOTICE.search(message)
    if m_inv:
        user, ip = m_inv.groups()
        return AuthEvent(
            timestamp=timestamp,
            hostname=hostname,
            service=service,
            event_type=EventType.INVALID_USER,
            username=user,
            ip_address=ip,
            port=None,
            raw_message=message,
        )

    # 5. Sudo command execution
    if "sudo" in service.lower():
        m_sudo = SUDO_PATTERN.search(message)
        if m_sudo:
            caller, run_as, cmd = m_sudo.groups()
            return AuthEvent(
                timestamp=timestamp,
                hostname=hostname,
                service=service,
                event_type=EventType.SUDO_COMMAND,
                username=caller,
                ip_address=None,
                port=None,
                raw_message=message,
            )

    return AuthEvent(
        timestamp=timestamp,
        hostname=hostname,
        service=service,
        event_type=EventType.OTHER,
        username=None,
        ip_address=None,
        port=None,
        raw_message=message,
    )


def parse_log_file(file_path: str) -> List[AuthEvent]:
    """Reads and parses an authentication log file into structured events."""
    events = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)
    return events
