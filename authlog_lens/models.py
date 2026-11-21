"""Data structures for authentication logs, threat alerts, and metrics."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Set


class EventType(str, Enum):
    FAILED_LOGIN = "FAILED_LOGIN"
    SUCCESSFUL_LOGIN = "SUCCESSFUL_LOGIN"
    INVALID_USER = "INVALID_USER"
    ROOT_LOGIN = "ROOT_LOGIN"
    SUDO_COMMAND = "SUDO_COMMAND"
    OTHER = "OTHER"


class ThreatLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class AuthEvent:
    timestamp: str
    hostname: str
    service: str
    event_type: EventType
    username: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    raw_message: str = ""


@dataclass
class ThreatAlert:
    alert_type: str
    title: str
    threat_level: ThreatLevel
    ip_address: Optional[str]
    description: str
    evidence_count: int
    recommendation: str


@dataclass
class IPMetrics:
    ip: str
    total_events: int = 0
    failed_logins: int = 0
    successful_logins: int = 0
    invalid_user_attempts: int = 0
    targeted_users: Set[str] = field(default_factory=set)


@dataclass
class AnalysisReport:
    log_file: str
    total_lines: int
    parsed_events: int
    failed_logins_total: int
    successful_logins_total: int
    unique_source_ips: int
    unique_targeted_users: int
    top_offending_ips: List[IPMetrics] = field(default_factory=list)
    threat_alerts: List[ThreatAlert] = field(default_factory=list)
    scan_timestamp: str = ""

    @property
    def has_critical_threats(self) -> bool:
        return any(a.threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH) for a in self.threat_alerts)
