"""tests/test_analyzer.py"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from analyzer import LogAnalyzer


SAMPLE_LOGS = """\
Jan 15 08:12:01 server01 sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Jan 15 08:12:03 server01 sshd[1234]: Failed password for root from 192.168.1.105 port 22 ssh2
Jan 15 08:15:44 server01 kernel: [UFW BLOCK] IN=eth0 SRC=203.0.113.47 DPT=3389
Jan 15 08:30:00 server01 sshd[5001]: Accepted publickey for deploy from 10.0.0.5 port 44100 ssh2
Jan 15 09:00:11 server01 systemd: Started Daily apt download activities.
2024-01-15T09:05:00Z server02 auditd: EXECVE argc=3 a0="/bin/nc" a1="-e" a2="/bin/bash"
"""


def test_analyze_text_returns_correct_total():
    result = LogAnalyzer().analyze_text(SAMPLE_LOGS)
    assert result.total_lines == 6


def test_analyze_text_detects_critical():
    result = LogAnalyzer().analyze_text(SAMPLE_LOGS)
    assert result.severity_counts["CRITICAL"] >= 2  # 2x root brute force + nc shell


def test_analyze_text_threat_level_critical():
    result = LogAnalyzer().analyze_text(SAMPLE_LOGS)
    assert result.threat_level == "CRITICAL"


def test_analyze_text_threat_level_clean_on_benign():
    benign = "Jan 15 09:00:11 server01 systemd: Started Daily apt download activities.\n"
    result = LogAnalyzer().analyze_text(benign)
    assert result.threat_level == "CLEAN"


def test_analyze_text_ip_counting():
    result = LogAnalyzer().analyze_text(SAMPLE_LOGS)
    assert result.ip_counts["192.168.1.105"] == 2


def test_analyze_text_top_ips():
    result = LogAnalyzer().analyze_text(SAMPLE_LOGS)
    top = result.top_ips(1)
    assert top[0][0] == "192.168.1.105"


def test_events_sorted_by_severity():
    result = LogAnalyzer().analyze_text(SAMPLE_LOGS)
    sevs = [e.severity for e in result.events]
    from rule_engine import SEVERITY_RANK
    ranks = [SEVERITY_RANK[s] for s in sevs]
    assert ranks == sorted(ranks, reverse=True)


def test_filter_by_severity():
    result = LogAnalyzer().analyze_text(SAMPLE_LOGS)
    high_plus = result.filter_by_severity("HIGH")
    for event in high_plus:
        assert event.severity in ("CRITICAL", "HIGH")


def test_analyze_file(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text(SAMPLE_LOGS)
    result = LogAnalyzer().analyze_file(str(log_file))
    assert result.total_lines == 6
    assert result.threat_level == "CRITICAL"
