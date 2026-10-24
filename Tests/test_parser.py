"""tests/test_parser.py"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from log_parser import parse_line, parse_text


def test_parse_line_returns_none_for_blank():
    assert parse_line("") is None
    assert parse_line("   ") is None


def test_parse_line_extracts_syslog_timestamp():
    line = "Jan 15 08:12:01 server01 sshd[1234]: Failed password for root"
    event = parse_line(line)
    assert event is not None
    assert "Jan 15 08:12:01" in event.timestamp


def test_parse_line_extracts_iso_timestamp():
    line = "2024-01-15T09:05:00Z server02 auditd: EXECVE argc=3"
    event = parse_line(line)
    assert event is not None
    assert "2024-01-15T09:05:00Z" in event.timestamp


def test_parse_line_extracts_source_ip():
    line = "Jan 15 08:12:01 server01 sshd[1234]: Failed password for root from 192.168.1.105 port 22"
    event = parse_line(line)
    assert "192.168.1.105" in event.source_ips


def test_parse_line_extracts_multiple_ips():
    line = "connection from 10.0.0.1 to 10.0.0.2 blocked"
    event = parse_line(line)
    assert "10.0.0.1" in event.source_ips
    assert "10.0.0.2" in event.source_ips


def test_parse_line_no_ip():
    line = "Jan 15 09:00:11 server01 systemd: Started Daily apt download activities."
    event = parse_line(line)
    assert event is not None
    assert event.source_ips == []


def test_parse_text_skips_blank_lines():
    text = "line one\n\n\nline two\n"
    events = parse_text(text)
    assert len(events) == 2


def test_parse_text_returns_list_of_events():
    text = (
        "Jan 15 08:12:01 server01 sshd[1234]: Failed password for root from 1.2.3.4\n"
        "Jan 15 08:15:44 server01 kernel: [UFW BLOCK] IN=eth0 SRC=5.6.7.8 DPT=3389\n"
    )
    events = parse_text(text)
    assert len(events) == 2
    assert events[0].source_ips == ["1.2.3.4"]
