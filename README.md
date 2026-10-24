# CyberSIEM

A lightweight SIEM-style log analyzer written in pure Python.
Parses raw log files, classifies events by threat severity, and
prints a colour-coded terminal report — no third-party dependencies.

Built as a portfolio project by Ivy | Zero Day Diary

---

## Project structure

```
CyberSIEM/
├── src/
│   ├── log_parser.py    ← extracts timestamps, IPs, and raw messages
│   ├── rule_engine.py   ← regex-based threat detection rules
│   ├── analyzer.py      ← LogAnalyzer class + AnalysisResult dataclass
│   └── report.py        ← ANSI terminal report formatter
├── tests/
│   ├── test_parser.py
│   ├── test_rules.py
│   └── test_analyzer.py
├── sample_logs/
│   └── sample.log
├── main.py              ← CLI entry point
└── requirements.txt
```

---

## Quickstart

```bash
# 1. Clone the repo and enter the folder
cd CyberSIEM

# 2. Create and activate a virtual environment (Windows)
python -m venv venv
venv\Scripts\activate

# 3. Install pytest (only dev dependency)
pip install pytest

# 4. Run against the sample log
python main.py sample_logs/sample.log

# 5. Run tests
pytest tests/ -v
```

---

## CLI usage

```bash
# Analyze a log file (shows all severities)
python main.py sample_logs/sample.log

# Show only HIGH and CRITICAL events
python main.py sample_logs/sample.log --min HIGH

# Disable colours (e.g. for piping to a file)
python main.py sample_logs/sample.log --no-colour > report.txt

# List all detection rules
python main.py rules
```

---

## Supported log formats

| Format | Example |
|--------|---------|
| syslog / auth.log | `Jan 15 08:12:01 server01 sshd[1234]: ...` |
| ISO 8601 syslog | `2024-01-15T09:05:00Z hostname service: ...` |
| Apache / Nginx CLF | `1.2.3.4 - - [15/Jan/2024:08:25:00 +0000] "GET /..." 200 512` |
| UFW firewall | `[UFW BLOCK] IN=eth0 SRC=1.2.3.4 DPT=3389` |
| auditd | `EXECVE argc=3 a0="/bin/nc" a1="-e" a2="/bin/bash"` |

---

## Severity levels

| Level | Meaning |
|-------|---------|
| CRITICAL | Active threat (brute force on root, reverse shell, ransomware) |
| HIGH | Strong indicator (auth failure, priv escalation, web recon, RDP/SMB) |
| MEDIUM | Suspicious activity (firewall blocks, sudo usage, path traversal) |
| LOW | Routine with context (auth success, session events) |
| INFO | Normal operations (cron, systemd, apt) |

---

## Exit codes (useful in CI/CD pipelines)

| Code | Meaning |
|------|---------|
| 0 | No HIGH or CRITICAL events found |
| 1 | HIGH events detected |
| 2 | CRITICAL events detected |
