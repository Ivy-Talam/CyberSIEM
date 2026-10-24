"""tests/test_rules.py"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from rule_engine import classify


def test_brute_force_root_is_critical():
    line = "Failed password for root from 192.168.1.105 port 22 ssh2"
    sev, etype = classify(line)
    assert sev == "CRITICAL"
    assert etype == "Brute Force"


def test_reverse_shell_nc_is_critical():
    line = 'auditd: EXECVE argc=3 a0="/bin/nc" a1="-e" a2="/bin/bash"'
    sev, etype = classify(line)
    assert sev == "CRITICAL"
    assert etype == "Malware/C2"


def test_failed_password_non_root_is_high():
    line = "Failed password for alice from 10.0.0.5 port 22 ssh2"
    sev, etype = classify(line)
    assert sev == "HIGH"
    assert etype == "Auth Failure"


def test_invalid_user_is_high():
    line = "Invalid user postgres from 45.33.32.156 port 22312"
    sev, etype = classify(line)
    assert sev == "HIGH"
    assert etype == "Auth Failure"


def test_sudo_bash_is_high_priv_escalation():
    line = "sudo: alice : command not allowed ; USER=root ; COMMAND=/bin/bash"
    sev, etype = classify(line)
    assert sev == "HIGH"
    assert etype == "Priv Escalation"


def test_rdp_block_is_high():
    line = "[UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.47 PROTO=TCP DPT=3389"
    sev, etype = classify(line)
    assert sev == "HIGH"
    assert etype == "RDP Attempt"


def test_smb_scan_is_high():
    line = "[UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.8 PROTO=TCP DPT=445"
    sev, etype = classify(line)
    assert sev == "HIGH"
    assert etype == "SMB Scan"


def test_web_recon_env_is_high():
    line = '185.220.101.33 - - "GET /.env HTTP/1.1" 403 214'
    sev, etype = classify(line)
    assert sev == "HIGH"
    assert etype == "Web Recon"


def test_ufw_block_generic_is_medium():
    line = "[UFW BLOCK] IN=eth0 OUT= SRC=1.2.3.4 PROTO=TCP DPT=8080"
    sev, etype = classify(line)
    assert sev == "MEDIUM"
    assert etype == "Firewall Block"


def test_sudo_normal_is_medium():
    line = "sudo: alice : TTY=pts/1 ; USER=root ; COMMAND=/usr/bin/apt update"
    sev, etype = classify(line)
    assert sev == "MEDIUM"
    assert etype == "Sudo Usage"


def test_auth_success_is_low():
    line = "Accepted publickey for deploy from 10.0.0.5 port 44100 ssh2"
    sev, etype = classify(line)
    assert sev == "LOW"
    assert etype == "Auth Success"


def test_systemd_is_info():
    line = "systemd: Started Daily apt download activities."
    sev, etype = classify(line)
    assert sev == "INFO"
    assert etype == "System Event"


def test_generic_line_is_info():
    line = "some random log line with no known pattern"
    sev, etype = classify(line)
    assert sev == "INFO"
    assert etype == "Generic"


def test_case_insensitive_matching():
    line = "FAILED PASSWORD FOR ROOT from 1.2.3.4"
    sev, _ = classify(line)
    assert sev == "CRITICAL"
