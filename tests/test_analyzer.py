"""Tests for threat detection heuristics."""

import os
import pytest
from authlog_lens.parser import parse_log_file
from authlog_lens.analyzer import analyze_events


def test_analyze_normal_log():
    path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "auth_sample_normal.log")
    events = parse_log_file(path)
    report = analyze_events(events, path, len(events))
    assert report.failed_logins_total == 0
    assert report.successful_logins_total == 3
    assert len(report.threat_alerts) == 0
    assert report.has_critical_threats is False


def test_analyze_attack_log():
    path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "auth_sample_attack.log")
    events = parse_log_file(path)
    report = analyze_events(events, path, len(events))
    assert report.failed_logins_total >= 8
    assert report.has_critical_threats is True

    alert_types = {a.alert_type for a in report.threat_alerts}
    # Should catch credential stuffing from 203.0.113.45 (admin, oracle, test, guest, root)
    assert "CREDENTIAL_STUFFING" in alert_types
    # Should catch success after failures from 198.51.100.80
    assert "SUCCESS_AFTER_FAILURE" in alert_types
    # Should catch root targeting
    assert "ROOT_LOGIN_TARGETING" in alert_types
