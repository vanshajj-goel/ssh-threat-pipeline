import json
import os
import sys

MITRE_TECHNIQUES = {
    "whoami": ("T1033", "User Discovery", "Discovery"),
    "id": ("T1033", "User Discovery", "Discovery"),
    "uname": ("T1082", "System Info Discovery", "Discovery"),
    "cat /etc/passwd": ("T1087.001", "Local Accounts", "Discovery"),
    "wget": ("T1105", "Ingress Tool Transfer", "Command & Control"),
    "curl": ("T1105", "Ingress Tool Transfer", "Command & Control"),
    "chmod": ("T1222.002", "Permissions Modification", "Defense Evasion"),
    "crontab": ("T1053.003", "Scheduled Task: Cron", "Persistence"),
    "bash": ("T1059.004", "Unix Shell Execution", "Execution"),
}

class ThreatIntelPipeline:
    def __init__(self, log_path):
        self.log_path = log_path

    def parse(self):
        if not os.path.exists(self.log_path):
            print(f"[!] Log file not found: {self.log_path}")
            print(f"[*] Hint: Ensure you ran the script from ~/ssh-threat-pipeline")
            return {}, [], []

        sessions = {}
        auth_attempts = []
        executed_commands = []

        with open(self.log_path, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    event = json.loads(stripped)
                except Exception:
                    continue

                session_id = event.get("session")
                event_id = event.get("eventid")
                src_ip = event.get("src_ip", "Unknown")
                timestamp = event.get("timestamp", "")

                if not session_id:
                    continue

                if session_id not in sessions:
                    sessions[session_id] = {"src_ip": src_ip, "timestamp": timestamp}

                if event_id in ("cowrie.login.failed", "cowrie.login.success"):
                    auth_attempts.append({
                        "session": session_id,
                        "src_ip": src_ip,
                        "username": event.get("username", "<none>"),
                        "password": event.get("password", "<none>"),
                        "status": "Success" if event_id == "cowrie.login.success" else "Failed"
                    })

                elif event_id == "cowrie.command.input":
                    cmd = event.get("input", "").strip()
                    if cmd:
                        mitre_hits = [
                            f"{tech_id}: {name}"
                            for sig, (tech_id, name, _) in MITRE_TECHNIQUES.items()
                            if sig in cmd
                        ]
                        executed_commands.append({
                            "session": session_id,
                            "timestamp": timestamp,
                            "command": cmd,
                            "mitre_tags": mitre_hits
                        })

        return sessions, auth_attempts, executed_commands

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "/home/sukuna/Desktop/ssh-threat-pipeline/data/sample_cowrie.json"
    pipeline = ThreatIntelPipeline(target)
    sessions, auths, cmds = pipeline.parse()
    print("\n" + "="*50)
    print("        SSH THREAT INTELLIGENCE SUMMARY")
    print("="*50)
    print(f"[*] Total Attack Sessions: {len(sessions)}")
    print(f"[*] Total Credential Attempts: {len(auths)}")
    print(f"[*] Intercepted Shell Commands: {len(cmds)}")

    print("\n[+] Top Attempted Credentials:")
    cred_counts = {}
    for a in auths:
        pair = f"{a['username']}:{a['password']}"
        cred_counts[pair] = cred_counts.get(pair, 0) + 1
    for pair, count in sorted(cred_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"    - {pair:<25} ({count} attempts)")

    print("\n[+] Intercepted Commands & MITRE ATT&CK Mapping:")
    for c in cmds:
        tags = ", ".join(c['mitre_tags']) if c['mitre_tags'] else "Unclassified"
        print(f"    > {c['command']}")
        print(f"      └── ATT&CK: {tags}")
    print("="*50 + "\n")

