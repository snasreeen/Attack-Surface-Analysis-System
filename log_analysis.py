"""
log_analysis.py
Reads a sample log file and detects suspicious patterns:
- Failed login attempts
- Port scans
- Unauthorized access attempts
- Suspicious IPs
"""

import re
import os
from datetime import datetime

LOG_FILE = "sample.log"

# ─── Pattern Definitions ───────────────────────────────────────────────────────
PATTERNS = {
    "failed_login":   (re.compile(r"(Failed|FAILED|invalid|Invalid|authentication failure)", re.I), "warning"),
    "root_login":     (re.compile(r"(root|admin)\s+login", re.I),                                  "critical"),
    "port_scan":      (re.compile(r"(port scan|nmap|masscan|SYN flood)", re.I),                     "critical"),
    "brute_force":    (re.compile(r"(brute.?force|too many|repeated login)", re.I),                 "critical"),
    "sql_injection":  (re.compile(r"(sql.?inject|UNION SELECT|1=1|OR '1'='1')", re.I),             "critical"),
    "xss_attempt":    (re.compile(r"(<script|javascript:|onerror=)", re.I),                        "warning"),
    "unauthorized":   (re.compile(r"(unauthorized|403|forbidden|access denied)", re.I),            "warning"),
    "malware":        (re.compile(r"(malware|trojan|ransomware|backdoor|reverse.?shell)", re.I),   "critical"),
    "data_exfil":     (re.compile(r"(exfiltrat|data transfer|large POST|wget|curl)", re.I),       "warning"),
}

SUSPICIOUS_IPS = {"192.168.1.100", "10.0.0.254", "172.16.0.200"}


def _create_sample_log():
    """Creates a demo log file if none exists."""
    sample = """
2024-01-15 08:12:34 INFO  192.168.1.50  - GET /index.html HTTP/1.1 200 OK
2024-01-15 08:13:01 WARN  192.168.1.100 - Failed password for root from 192.168.1.100 port 22
2024-01-15 08:13:05 WARN  192.168.1.100 - Failed password for admin from 192.168.1.100 port 22
2024-01-15 08:13:09 WARN  192.168.1.100 - Failed password for root from 192.168.1.100 port 22
2024-01-15 08:13:14 CRIT  192.168.1.100 - Too many repeated login failures - possible brute force
2024-01-15 08:15:22 INFO  10.0.0.5      - GET /api/users HTTP/1.1 200 OK
2024-01-15 08:16:01 WARN  10.0.0.254    - Port scan detected from 10.0.0.254 (nmap fingerprint)
2024-01-15 08:17:45 CRIT  10.0.0.254    - SQL injection attempt: GET /search?q=1 UNION SELECT * FROM users
2024-01-15 08:18:03 INFO  192.168.1.20  - POST /login HTTP/1.1 200 OK
2024-01-15 08:19:00 WARN  172.16.0.200  - Unauthorized access attempt on /admin - 403 Forbidden
2024-01-15 08:20:11 CRIT  172.16.0.200  - Malware/reverse shell attempt detected from 172.16.0.200
2024-01-15 08:21:33 WARN  10.0.0.254    - XSS attempt: GET /comment?text=<script>alert(1)</script>
2024-01-15 08:22:00 INFO  192.168.1.1   - System health check OK
2024-01-15 08:23:15 WARN  192.168.1.100 - authentication failure; user=admin
2024-01-15 08:24:07 INFO  192.168.1.30  - GET /dashboard HTTP/1.1 200 OK
2024-01-15 08:25:55 CRIT  10.0.0.254    - Nmap SYN scan detected - possible reconnaissance
2024-01-15 08:26:10 WARN  172.16.0.200  - Data exfiltration attempt: large POST 15MB to external IP
2024-01-15 08:27:00 INFO  192.168.1.5   - User session expired normally
2024-01-15 08:28:45 WARN  192.168.1.100 - root login attempt from untrusted IP
2024-01-15 08:29:00 INFO  10.0.0.10     - Scheduled backup completed successfully
"""
    with open(LOG_FILE, "w") as f:
        f.write(sample.strip())


def analyze_logs() -> dict:
    """Reads the log file and returns detected threats."""
    if not os.path.exists(LOG_FILE):
        _create_sample_log()

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    events         = []
    threat_counts  = {"critical": 0, "warning": 0, "info": 0}
    suspicious_ips_found = set()
    failed_logins  = 0

    for line in lines:
        line = line.strip()
        if not line:
            continue

        severity   = "info"
        matched_type = None

        # Check each pattern
        for ptype, (pattern, sev) in PATTERNS.items():
            if pattern.search(line):
                severity     = sev
                matched_type = ptype
                break

        # Count failed logins separately
        if matched_type == "failed_login":
            failed_logins += 1

        # Detect suspicious IPs in the line
        for ip in SUSPICIOUS_IPS:
            if ip in line:
                suspicious_ips_found.add(ip)

        threat_counts[severity] = threat_counts.get(severity, 0) + 1

        events.append({
            "line":     line,
            "severity": severity,
            "type":     matched_type or "normal"
        })

    # Build summary
    summary = {
        "total_lines":       len(events),
        "critical_events":   threat_counts.get("critical", 0),
        "warning_events":    threat_counts.get("warning", 0),
        "normal_events":     threat_counts.get("info", 0),
        "failed_logins":     failed_logins,
        "suspicious_ips":    list(suspicious_ips_found),
        "threat_detected":   threat_counts.get("critical", 0) > 0,
    }

    return {
        "events":  events,
        "summary": summary
    }
