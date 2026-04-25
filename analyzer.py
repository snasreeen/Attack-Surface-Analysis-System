"""
analyzer.py
Maps open ports/services to known vulnerabilities and MITRE ATT&CK techniques.
Generates attack paths and calculates a risk score.
"""

# ─── Vulnerability Database ────────────────────────────────────────────────────
VULNERABILITY_DB = {
    21:   {"name": "FTP",    "cve": "CVE-2015-3306", "desc": "Anonymous FTP login or ProFTPd exploit",         "severity": "high"},
    22:   {"name": "SSH",    "cve": "CVE-2016-6210", "desc": "OpenSSH username enumeration",                   "severity": "medium"},
    23:   {"name": "Telnet", "cve": "CVE-2020-10188","desc": "Telnet cleartext credential exposure",           "severity": "critical"},
    25:   {"name": "SMTP",   "cve": "CVE-2014-3566", "desc": "Open relay / POODLE downgrade attack",          "severity": "medium"},
    80:   {"name": "HTTP",   "cve": "CVE-2021-41773","desc": "Apache path traversal / RCE vulnerability",     "severity": "critical"},
    110:  {"name": "POP3",   "cve": "CVE-2007-1349", "desc": "POP3 plaintext credential sniffing",            "severity": "medium"},
    135:  {"name": "RPC",    "cve": "CVE-2003-0352", "desc": "MS03-026 DCOM RPC buffer overflow",             "severity": "critical"},
    139:  {"name": "NetBIOS","cve": "CVE-2017-0144", "desc": "EternalBlue SMB exploit (WannaCry)",            "severity": "critical"},
    143:  {"name": "IMAP",   "cve": "CVE-2021-38647","desc": "IMAP OMIGOD remote code execution",            "severity": "high"},
    443:  {"name": "HTTPS",  "cve": "CVE-2014-0160", "desc": "Heartbleed OpenSSL memory disclosure",         "severity": "high"},
    445:  {"name": "SMB",    "cve": "CVE-2017-0144", "desc": "EternalBlue SMB RCE (MS17-010)",                "severity": "critical"},
    3306: {"name": "MySQL",  "cve": "CVE-2012-2122", "desc": "MySQL authentication bypass via timing attack", "severity": "high"},
    3389: {"name": "RDP",    "cve": "CVE-2019-0708", "desc": "BlueKeep RDP pre-auth RCE",                    "severity": "critical"},
    5900: {"name": "VNC",    "cve": "CVE-2015-8228", "desc": "VNC no-authentication or weak password",        "severity": "high"},
    8080: {"name": "HTTP-Alt","cve":"CVE-2020-1938", "desc": "Apache Ghostcat AJP file inclusion",           "severity": "high"},
    8443: {"name": "HTTPS-Alt","cve":"CVE-2021-44228","desc":"Log4Shell JNDI injection (Log4j2)",             "severity": "critical"},
}

# ─── MITRE ATT&CK Technique Mapping ───────────────────────────────────────────
MITRE_MAPPING = {
    21:   [{"id": "T1190",  "name": "Exploit Public-Facing Application",  "tactic": "Initial Access"},
           {"id": "T1078",  "name": "Valid Accounts",                      "tactic": "Defense Evasion"}],
    22:   [{"id": "T1110",  "name": "Brute Force",                        "tactic": "Credential Access"},
           {"id": "T1021.004","name":"Remote Services: SSH",               "tactic": "Lateral Movement"}],
    23:   [{"id": "T1040",  "name": "Network Sniffing",                   "tactic": "Credential Access"},
           {"id": "T1078",  "name": "Valid Accounts",                      "tactic": "Persistence"}],
    25:   [{"id": "T1566",  "name": "Phishing",                           "tactic": "Initial Access"},
           {"id": "T1071",  "name": "Application Layer Protocol",          "tactic": "Command & Control"}],
    80:   [{"id": "T1190",  "name": "Exploit Public-Facing Application",  "tactic": "Initial Access"},
           {"id": "T1059.007","name":"Command and Scripting: JavaScript",  "tactic": "Execution"},
           {"id": "T1505.003","name":"Web Shell",                          "tactic": "Persistence"}],
    110:  [{"id": "T1040",  "name": "Network Sniffing",                   "tactic": "Credential Access"}],
    135:  [{"id": "T1021.003","name":"Remote Services: DCOM",             "tactic": "Lateral Movement"},
           {"id": "T1543",  "name": "Create/Modify System Process",        "tactic": "Privilege Escalation"}],
    139:  [{"id": "T1021.002","name":"Remote Services: SMB",              "tactic": "Lateral Movement"},
           {"id": "T1486",  "name": "Data Encrypted for Impact",           "tactic": "Impact"}],
    143:  [{"id": "T1078",  "name": "Valid Accounts",                      "tactic": "Persistence"}],
    443:  [{"id": "T1573",  "name": "Encrypted Channel",                   "tactic": "Command & Control"},
           {"id": "T1190",  "name": "Exploit Public-Facing Application",  "tactic": "Initial Access"}],
    445:  [{"id": "T1021.002","name":"Remote Services: SMB",              "tactic": "Lateral Movement"},
           {"id": "T1486",  "name": "Data Encrypted for Impact",           "tactic": "Impact"},
           {"id": "T1003",  "name": "OS Credential Dumping",               "tactic": "Credential Access"}],
    3306: [{"id": "T1190",  "name": "Exploit Public-Facing Application",  "tactic": "Initial Access"},
           {"id": "T1005",  "name": "Data from Local System",             "tactic": "Collection"}],
    3389: [{"id": "T1021.001","name":"Remote Services: RDP",              "tactic": "Lateral Movement"},
           {"id": "T1110",  "name": "Brute Force",                        "tactic": "Credential Access"}],
    5900: [{"id": "T1021.005","name":"Remote Services: VNC",              "tactic": "Lateral Movement"},
           {"id": "T1110",  "name": "Brute Force",                        "tactic": "Credential Access"}],
    8080: [{"id": "T1190",  "name": "Exploit Public-Facing Application",  "tactic": "Initial Access"},
           {"id": "T1505.003","name":"Web Shell",                          "tactic": "Persistence"}],
    8443: [{"id": "T1190",  "name": "Exploit Public-Facing Application",  "tactic": "Initial Access"},
           {"id": "T1059",  "name": "Command and Scripting Interpreter",  "tactic": "Execution"}],
}

# ─── Attack Path Templates ────────────────────────────────────────────────────
def generate_attack_path(open_ports: list, vulnerabilities: list) -> list:
    """Generates a step-by-step attack path based on open ports."""
    path = []
    severity_map = {v["port"]: v["severity"] for v in vulnerabilities}

    # Step 1 – Reconnaissance
    path.append({
        "step": 1,
        "phase": "Reconnaissance",
        "action": f"Attacker performs Nmap scan, discovers {len(open_ports)} open ports: {', '.join(map(str, open_ports))}",
        "technique": "T1595 – Active Scanning",
        "risk": "low"
    })

    # Step 2 – Initial access vector
    entry_port = _pick_entry_port(open_ports)
    if entry_port:
        vuln = VULNERABILITY_DB.get(entry_port, {})
        path.append({
            "step": 2,
            "phase": "Initial Access",
            "action": f"Exploit {vuln.get('name','service')} on port {entry_port} using {vuln.get('cve','known CVE')}",
            "technique": "T1190 – Exploit Public-Facing Application",
            "risk": vuln.get("severity", "medium")
        })

    # Step 3 – Credential / Lateral if SMB/RDP/SSH open
    lateral_port = _pick_lateral_port(open_ports)
    if lateral_port:
        path.append({
            "step": 3,
            "phase": "Lateral Movement",
            "action": f"Use compromised credentials or pass-the-hash via port {lateral_port}",
            "technique": "T1021 – Remote Services",
            "risk": "high"
        })

    # Step 4 – Privilege Escalation
    if any(p in open_ports for p in [135, 445, 3389]):
        path.append({
            "step": 4,
            "phase": "Privilege Escalation",
            "action": "Exploit misconfigured service or DCOM/RPC to gain SYSTEM-level access",
            "technique": "T1068 – Exploitation for Privilege Escalation",
            "risk": "critical"
        })

    # Step 5 – Exfiltration or Impact
    if any(p in open_ports for p in [3306, 5900, 21]):
        path.append({
            "step": len(path) + 1,
            "phase": "Exfiltration",
            "action": "Extract sensitive database records or files via open data-transfer service",
            "technique": "T1041 – Exfiltration Over C2 Channel",
            "risk": "critical"
        })

    return path


def _pick_entry_port(ports):
    """Picks the most exploitable entry port."""
    priority = [80, 8080, 8443, 443, 21, 23, 25]
    for p in priority:
        if p in ports:
            return p
    return ports[0] if ports else None


def _pick_lateral_port(ports):
    """Picks a lateral movement port."""
    for p in [445, 3389, 22, 5900]:
        if p in ports:
            return p
    return None


# ─── Risk Scoring ─────────────────────────────────────────────────────────────
SEVERITY_SCORES = {"critical": 40, "high": 20, "medium": 10, "low": 3}

def calculate_risk(vulnerabilities: list) -> dict:
    """Computes overall risk level from vulnerability severities."""
    if not vulnerabilities:
        return {"level": "Low", "score": 0, "color": "green"}

    score = sum(SEVERITY_SCORES.get(v["severity"], 0) for v in vulnerabilities)
    num_critical = sum(1 for v in vulnerabilities if v["severity"] == "critical")

    if score >= 80 or num_critical >= 2:
        return {"level": "Critical", "score": min(score, 100), "color": "red",
                "description": "Immediate action required. Multiple critical vulnerabilities detected."}
    elif score >= 40 or num_critical == 1:
        return {"level": "High", "score": min(score, 100), "color": "orange",
                "description": "High risk. Critical CVEs present — patch and isolate affected services."}
    elif score >= 20:
        return {"level": "Medium", "score": min(score, 100), "color": "yellow",
                "description": "Moderate risk. Review exposed services and apply patches."}
    else:
        return {"level": "Low", "score": score, "color": "green",
                "description": "Low risk. Minimal exposure detected."}


# ─── Main Analysis Function ────────────────────────────────────────────────────
def analyze_results(scan_data: dict) -> dict:
    """
    Given scan_data (open_ports + services), returns:
    - vulnerabilities list
    - mitre_techniques list
    - attack_path list
    - risk dict
    """
    open_ports = scan_data.get("open_ports", [])

    # Build vulnerability list
    vulnerabilities = []
    for port in open_ports:
        if port in VULNERABILITY_DB:
            vuln = dict(VULNERABILITY_DB[port])
            vuln["port"] = port
            vulnerabilities.append(vuln)

    # Build MITRE techniques list (deduplicated by technique ID)
    seen_ids     = set()
    all_techniques = []
    for port in open_ports:
        for tech in MITRE_MAPPING.get(port, []):
            if tech["id"] not in seen_ids:
                seen_ids.add(tech["id"])
                all_techniques.append(tech)

    # Generate attack path
    attack_path = generate_attack_path(open_ports, vulnerabilities)

    # Calculate risk
    risk = calculate_risk(vulnerabilities)

    return {
        "vulnerabilities":  vulnerabilities,
        "mitre_techniques": all_techniques,
        "attack_path":      attack_path,
        "risk":             risk
    }
