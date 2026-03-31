import os
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse

from models import LogTriageAction, LogTriageObservation, LogTriageState, DifficultyTier
from server.environment import SocLogTriageEnvironment
from server.grader import grade, GraderResult

app = FastAPI(
    title="SOC Log Triage Environment API",
    description=(
        "Autonomous SOC Endpoint Log Triage — OpenEnv-compliant RL environment. "
        "Agent investigates Windows Sysmon log bundles and classifies incidents."
    ),
    version="2.0.0",
)


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/docs")


_ENV: Optional[SocLogTriageEnvironment] = None


@app.get("/health")
def health():
    return {
        "status": "ok",
        "environment": "soc-log-triage-env",
        "version": "2.0.0",
    }


@app.post("/reset", response_model=LogTriageObservation)
def reset(tier_filter: Optional[str] = None):
    """
    Start a new episode by sampling an incident bundle.

    Optional query param `tier_filter`: Easy | Medium | Hard
    If omitted, a random tier is selected.
    """
    global _ENV
    actual_filter = None if tier_filter in (None, "all") else tier_filter
    _ENV = SocLogTriageEnvironment(tier_filter=actual_filter)
    obs = _ENV.reset()
    return obs


@app.post("/step")
def step(action: LogTriageAction):
    """Submit one agent action (tool call or verdict)."""
    global _ENV
    if not _ENV:
        raise HTTPException(status_code=400, detail="No active episode. Call /reset first.")
    result = _ENV.step(action)
    return {
        "observation": result.observation.model_dump(),
        "reward":      result.reward,
        "done":        result.done,
        "info":        result.info,
    }


@app.get("/state", response_model=LogTriageState)
def state():
    """Return current episode state (includes ground truth for graders/eval harnesses)."""
    global _ENV
    if not _ENV:
        raise HTTPException(status_code=400, detail="No active episode.")
    return _ENV.state()


@app.get("/grader")
def grader():
    """Return the deterministic grader score for the current episode."""
    global _ENV
    if not _ENV:
        raise HTTPException(status_code=400, detail="No active episode.")
    current_state = _ENV.state()
    res = grade(current_state)
    data = res.to_dict()
    data.update({
        "incident_id":          current_state.incident_id,
        "tier":                 current_state.difficulty_tier.value if current_state.difficulty_tier else "Unknown",
        "step_count":           current_state.step_count,
        "expected_verdict":     current_state.expected_verdict.value,
        "expected_attack_type": current_state.expected_attack_type.value,
        "tools_used":           current_state.tools_used,
        "backup_triggered_hosts": current_state.backup_triggered_hosts,
        "final_verdict":        current_state.final_verdict.value if current_state.final_verdict else None,
        "final_attack_type":    current_state.final_attack_type.value if current_state.final_attack_type else None,
    })
    return data


@app.get("/tasks")
def tasks():
    """Describe the 3 tasks and the action/observation space."""
    return {
        "tasks": [
            {
                "id":          "easy",
                "name":        "Easy — Obvious C2 Beacon or Persistence",
                "tier":        "Easy",
                "description": (
                    "~50 Sysmon logs from 1 host. PowerShell -EncodedCommand beaconing "
                    "to a C2 domain, OR a registry Run key written by a suspicious process. "
                    "Signal is detectable from query_logs alone."
                ),
                "max_steps":       20,
                "ideal_steps":     6,
                "required_tools":  ["query_logs", "analyze_process", "get_host_summary"],
                "possible_verdicts": ["malicious", "benign"],
                "possible_attack_types": ["c2_beacon", "persistence"],
            },
            {
                "id":          "medium",
                "name":        "Medium — Registry Persistence + Outbound IP Exfil",
                "tier":        "Medium",
                "description": (
                    "~100 Sysmon logs from 1–2 hosts. Attacker wrote to HKCU Run key and "
                    "exfiltrated via curl/rclone. Agent must correlate process tree with "
                    "IP reputation to confirm malicious intent. Requires 2+ tool groups."
                ),
                "max_steps":       28,
                "ideal_steps":     9,
                "required_tools":  ["analyze_process", "check_ip_reputation", "query_logs"],
                "possible_verdicts": ["malicious", "benign"],
                "possible_attack_types": ["persistence", "data_exfil", "c2_beacon", "ransomware", "lateral_movement"],
            },
            {
                "id":          "hard",
                "name":        "Hard — Multi-Host Lateral Movement / Ransomware / LOLBins",
                "tier":        "Hard",
                "description": (
                    "~200 Sysmon logs across 2–4 hosts. Attacker uses living-off-the-land "
                    "binaries (wmic, mshta, regsvr32, certutil) or ransomware kill-chain "
                    "(vssadmin, bcdedit, wbadmin). No obvious malware name. Must correlate "
                    "process trees across hosts, check IP/hash IOCs, trigger backup before verdict."
                ),
                "max_steps":       40,
                "ideal_steps":     14,
                "required_tools":  ["analyze_process", "query_logs", "check_ip_reputation", "trigger_backup"],
                "possible_verdicts": ["malicious", "benign"],
                "possible_attack_types": ["lateral_movement", "ransomware", "data_exfil", "c2_beacon", "persistence"],
            },
        ],
        "action_schema":    LogTriageAction.model_json_schema(),
        "verdict_values":   ["malicious", "benign", "escalate"],
        "attack_types":     ["c2_beacon", "ransomware", "lateral_movement", "persistence", "data_exfil"],
        "tool_count":       7,
        "tools": {
            "query_logs": {
                "description": "Keyword search over the incident log bundle (process, commandline, domain, IP, details).",
                "required_params": {"query": "str — keyword or phrase to search"},
                "returns": "QueryLogsResult with matches list and total_found",
            },
            "analyze_process": {
                "description": "Get all log entries for a given process name (across all hosts in the incident).",
                "required_params": {"process_name": "str — partial process name, e.g. 'powershell' or 'vssadmin'"},
                "returns": "AnalyzeProcessResult with process tree and hosts_seen_on",
            },
            "check_ip_reputation": {
                "description": "Query the threat-intel DB for an IP address reputation.",
                "required_params": {"ip": "str — IPv4 address"},
                "returns": "IPReputationResult with score 0.0–1.0, category, malware family",
            },
            "check_file_hash": {
                "description": "Look up a file hash (SHA-256 or MD5) in the IOC database.",
                "required_params": {"hash": "str — SHA-256 or MD5 hash"},
                "returns": "FileHashResult with is_malicious flag and malware family",
            },
            "get_host_summary": {
                "description": "List all distinct processes, IPs, and domains active on a specific host.",
                "required_params": {"host": "str — hostname from the incident logs"},
                "returns": "HostSummaryResult with event_types, processes_seen, ips_contacted",
            },
            "trigger_backup": {
                "description": "Trigger emergency snapshot of a compromised host. REQUIRED for full score on malicious episodes.",
                "required_params": {"host": "str — hostname to back up"},
                "returns": "BackupResult with backup_id and status",
            },
            "submit_verdict": {
                "description": "Submit final classification. For malicious: include attack_type and affected_hosts.",
                "required_params": {
                    "verdict":        "malicious | benign | escalate",
                    "attack_type":    "[required if malicious] c2_beacon | ransomware | lateral_movement | persistence | data_exfil",
                    "affected_hosts": "[required if malicious] list of host names",
                },
                "returns": "Episode ends, grader score computed.",
            },
        },
        "reward_shaping": {
            "_note":              "Per-step training signal (not grader). Different from 0.0-1.0 grader score.",
            "correct_verdict":    +1.0,
            "wrong_verdict":      -1.0,
            "escalate_clear":     -0.2,
            "unique_tool_call":   +0.05,
            "tool_error":         -0.05,
            "per_step_penalty":   -0.02,
            "timeout":            -0.30,
        },
        "grader_components": {
            "_note":              "Final 0.0-1.0 score. Components sum to 1.0 for perfect episode.",
            "verdict":            0.30,
            "tools_malicious":    0.25,
            "tools_benign":       0.35,
            "attack_type":        0.20,
            "backup_malicious":   0.15,
            "no_false_backup":    0.25,
            "efficiency":         0.10,
        },
        "grader_penalties": {
            "wrong_verdict":      -0.25,
            "no_investigation":   -0.20,
            "rush_verdict":       -0.10,
            "false_backup":       -0.10,
            "backup_wrong_host":  -0.08,
            "excess_steps":       -0.05,
        },
    }


def main():
    import uvicorn
    port = int(os.environ.get("PORT", 7860))
    uvicorn.run("server.app:app", host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
