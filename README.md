cat << 'EOF' > README.md
# 🛡️ Cowrie SSH Threat Intelligence & MITRE ATT&CK Pipeline

A lightweight, automated Cyber Threat Intelligence (CTI) and telemetry ingestion engine built to capture, parse, and analyze real-world SSH brute-force and post-exploitation activity.

![Dashboard Preview](docs/dashboard_overview.png)

---

## 📌 Architecture Overview

[ External / Local Network ]
                               │
                               ▼
             [ iptables / Port Forwarding: 22 -> 22222 ]
                               │
                               ▼
                [ Cowrie Medium-Interaction SSH ]
                 (Fakes filesystem & user shell)
                               │
                               ▼
               [ Raw JSON Telemetry Ingestion ]
                (Event filtering & Session ID)
                               │
                               ▼
                 [ Threat Engine Enrichment ]
                 (MITRE ATT&CK Technique Mapping)
                               │
                               ▼
               [ Streamlit Analytics Dashboard ]
                 (Interactive KPIs & Visuals)

---

## 🚀 Key Features

- **SSH Honeypot Ingestion:** Real-time collection and session re-assembly from Cowrie medium-interaction honeypot JSON logs.
- **Credential Stuffing Analysis:** Aggregates and tracks targeted usernames, dictionary passwords, and source IP frequencies.
- **MITRE ATT&CK Behavioral Mapping:** Maps intercepted shell commands directly to ATT&CK Enterprise techniques:
  - `T1033` (User Discovery: `whoami`, `id`)
  - `T1082` (System Information Discovery: `uname`)
  - `T1087.001` (Local Accounts: `cat /etc/passwd`)
  - `T1105` (Ingress Tool Transfer: `wget`, `curl`)
  - `T1222.002` (Linux File Permissions Modification: `chmod`)
  - `T1053.003` (Cron Persistence: `crontab`)
- **Interactive Security Operations UI:** Built with Streamlit and Plotly for high-level KPI tracking and granular command timeline triage.

![MITRE Mapping](docs/dashboard_previw_2.png)

---

## 🛠️ Tech Stack

- **Operating System:** Ubuntu Linux / Debian
- **Language & Runtime:** Python 3.10+
- **Telemetry Source:** Cowrie SSH / Telnet Honeypot
- **Data Engineering & Analytics:** Pandas, Plotly Express
- **Dashboard Framework:** Streamlit
- **Framework Alignment:** MITRE ATT&CK Enterprise Matrix

---

## ⚙️ Installation & Usage

### 1. Clone the Repository
git clone https://github.com/vvanshaj-goel/ssh-threat-pipeline.git

cd ssh-threat-pipeline

python3 -m venv venvv
source venvv/bin/activate
pip install -r requirements.txt

python3 scripts/threat_engine.py data/sample_cowrie.json

streamlit run scripts/app.py

