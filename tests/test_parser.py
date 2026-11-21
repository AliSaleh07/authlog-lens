"""Unit tests for syslog parsing rules."""

import pytest
from authlog_lens.models import EventType
from authlog_lens.parser import parse_line


def test_parse_failed_invalid_user():
    line = "Oct 24 02:00:01 srv1 sshd[2001]: Failed password for invalid user admin from 203.0.113.45 port 39121 ssh2"
    ev = parse_line(line)
    assert ev is not None
    assert ev.event_type == EventType.INVALID_USER
    assert ev.username == "admin"
    assert ev.ip_address == "203.0.113.45"
    assert ev.port == 39121


def test_parse_accepted_login():
    line = "Oct 24 08:15:01 srv1 sshd[1001]: Accepted publickey for ali from 192.168.1.10 port 52341 ssh2"
    ev = parse_line(line)
    assert ev is not None
    assert ev.event_type == EventType.SUCCESSFUL_LOGIN
    assert ev.username == "ali"
    assert ev.ip_address == "192.168.1.10"


def test_parse_iso8601_timestamp_format():
    line = "2026-10-24T12:00:00+00:00 srv1 sshd[3001]: Accepted password for deployer from 10.0.0.9 port 49152 ssh2"
    ev = parse_line(line)
    assert ev is not None
    assert ev.event_type == EventType.SUCCESSFUL_LOGIN
    assert ev.username == "deployer"
    assert ev.ip_address == "10.0.0.9"


def test_parse_sudo_command():
    line = "Oct 24 08:16:30 srv1 sudo[1040]: ali : TTY=pts/0 ; PWD=/home/ali ; USER=root ; COMMAND=/bin/systemctl status nginx"
    ev = parse_line(line)
    assert ev is not None
    assert ev.event_type == EventType.SUDO_COMMAND
    assert ev.username == "ali"


def test_parse_malformed_line_returns_none():
    assert parse_line("") is None
    assert parse_line("not a valid syslog line") is None
