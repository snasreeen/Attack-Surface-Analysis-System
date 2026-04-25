# CyberScan — Attack Surface Analysis System
### MITRE ATT&CK-mapped vulnerability scanner with animated dashboard

---

## 📁 Project Structure

```
project/
├── app.py              ← Flask app (routes, auth, session)
├── scanner.py          ← Nmap scanner (python-nmap)
├── analyzer.py         ← CVE mapping + MITRE ATT&CK + attack path generation
├── log_analysis.py     ← Log file threat detection
├── requirements.txt    ← Python dependencies
├── users.json          ← Auto-created on first registration
├── sample.log          ← Auto-created demo log file
├── templates/
│   └── index.html      ← Single-page frontend
└── static/
    ├── style.css        ← Full UI styles + animations
    └── script.js        ← All JS: auth, scan, rendering
```

---

## 🚀 Quick Start

### 1. Install Python dependencies
```bash
cd project
pip install -r requirements.txt
```

### 2. Install Nmap (required for real scans)
- **Ubuntu/Debian:** `sudo apt install nmap`
- **macOS:** `brew install nmap`
- **Windows:** Download from https://nmap.org/download.html

> ⚠️ If Nmap is not installed, the app falls back to realistic **demo scan data** automatically — so the full UI still works.

### 3. Run the Flask server
```bash
python app.py
```

### 4. Open in browser
```
http://localhost:5000
```

---

## 🔐 Demo Login

A demo account is pre-described in the UI hint:
```
Email:    demo@test.com
Password: password
```

**Or register a new account** via the "Create Account" section.

---

## 🎯 How to Use

1. **Login** or **Register** on the first screen
2. Go to **Dashboard** — enter a target IP (e.g. `127.0.0.1` or `192.168.1.1`)
3. Click **Launch Scan** — watch the animated progress
4. View **Vulnerability Report** — cards for ports, services, CVEs, attack paths
5. See **Log Analysis** — suspicious activity from log file
6. Review **Risk Assessment** — final score + remediation tips

---

## ⚠️ Legal Notice

**Only scan systems you own or have explicit written permission to test.**  
Unauthorized scanning is illegal. This tool is for educational purposes only.

---

## 🛠️ Customization

- **Add more CVEs:** Edit `VULNERABILITY_DB` in `analyzer.py`
- **Add MITRE techniques:** Edit `MITRE_MAPPING` in `analyzer.py`
- **Use real log files:** Change `LOG_FILE = "sample.log"` in `log_analysis.py`
- **Change theme colors:** Edit CSS variables in `static/style.css`
