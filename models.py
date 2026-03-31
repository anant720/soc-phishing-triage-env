"""
All Pydantic schemas for the SOC Log Triage Environment.

The environment presents the agent with a bundle of Windows Sysmon endpoint
logs and asks it to:
  1. Investigate using log-analysis tools.
  2. Trigger a backup on compromised host(s) if malicious.
  3. Submit a verdict: malicious | benign | escalate
     with an attack_type classification when malicious.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import AliasChoices, BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# OpenEnv base class shim
# ---------------------------------------------------------------------------
try:
    from openenv.core.models import Action, Observation, State  # type: ignore
except ImportError:
    class Action(BaseModel):  # type: ignore
        """openenv not installed — stand-in base."""

    class Observation(BaseModel):  # type: ignore
        """openenv not installed — stand-in base."""

    class State(BaseModel):  # type: ignore
        """openenv not installed — stand-in base."""


# ===========================================================================
# Enumerations
# ===========================================================================

class ToolName(str, Enum):
    """All actions available to the agent.

    Investigation tools
    -------------------
    QUERY_LOGS          — keyword / regex search over the incident log bundle.
    ANALYZE_PROCESS     — retrieve process tree rooted at a given process name or host.
    CHECK_IP_REPUTATION — query threat-intel DB for an IP address.
    CHECK_FILE_HASH     — look up a SHA-256 / MD5 hash against the IOC database.
    GET_HOST_SUMMARY    — list all distinct events / processes seen on one host.

    Response actions
    ----------------
    TRIGGER_BACKUP  — immediately back up a compromised host (required for full score).
    SUBMIT_VERDICT  — emit final classification and end the episode.
    """
    QUERY_LOGS          = "query_logs"
    ANALYZE_PROCESS     = "analyze_process"
    CHECK_IP_REPUTATION = "check_ip_reputation"
    CHECK_FILE_HASH     = "check_file_hash"
    GET_HOST_SUMMARY    = "get_host_summary"
    TRIGGER_BACKUP      = "trigger_backup"
    SUBMIT_VERDICT      = "submit_verdict"

    @classmethod
    def valid_values(cls) -> list[str]:
        return [t.value for t in cls]


class AttackType(str, Enum):
    """Classification label required when verdict == 'malicious'."""
    C2_BEACON        = "c2_beacon"
    RANSOMWARE       = "ransomware"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE      = "persistence"
    DATA_EXFIL       = "data_exfil"
    BENIGN           = "benign"      # used internally; not a valid submit_verdict attack_type


class LogVerdict(str, Enum):
    """Top-level verdict the agent submits."""
    MALICIOUS = "malicious"
    BENIGN    = "benign"
    ESCALATE  = "escalate"


class DifficultyTier(str, Enum):
    EASY   = "Easy"
    MEDIUM = "Medium"
    HARD   = "Hard"


# ===========================================================================
# Action schema
# ===========================================================================

_VALID_COMMANDS: frozenset[str] = frozenset(ToolName.valid_values())

_REQUIRED_PARAMS: dict[str, list[str]] = {
    "query_logs":          ["query"],
    "analyze_process":     ["process_name"],
    "check_ip_reputation": ["ip"],
    "check_file_hash":     ["hash"],
    "get_host_summary":    ["host"],
    "trigger_backup":      ["host"],
    "submit_verdict":      ["verdict"],
}


class LogTriageAction(Action):
    """
    Type-safe action contract for every agent step.

    Examples
    --------
    Query logs::

        LogTriageAction(command="query_logs", params={"query": "powershell -EncodedCommand"})

    Check an IP::

        LogTriageAction(command="check_ip_reputation", params={"ip": "185.220.101.45"})

    Trigger backup before submitting::

        LogTriageAction(command="trigger_backup", params={"host": "DESKTOP-X9Y8Z7"})

    Submit verdict (required when malicious)::

        LogTriageAction(command="submit_verdict", params={
            "verdict": "malicious",
            "attack_type": "c2_beacon",
            "affected_hosts": ["DESKTOP-X9Y8Z7"]
        })
    """

    command: str = Field(
        ...,
        validation_alias=AliasChoices("command", "tool"),
        description=f"Tool to invoke. Must be one of: {sorted(_VALID_COMMANDS)}",
    )
    params: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("params", "parameters"),
        description="Tool-specific key-value parameters.",
    )
    model_config = {"populate_by_name": True}

    @field_validator("command", mode="before")
    @classmethod
    def validate_command(cls, v: Any) -> str:
        if isinstance(v, ToolName):
            return v.value
        normalised = str(v).strip().lower().replace("-", "_").replace(" ", "_")
        if normalised not in _VALID_COMMANDS:
            raise ValueError(
                f"Unknown command '{v}'. Valid: {sorted(_VALID_COMMANDS)}"
            )
        return normalised

    @model_validator(mode="after")
    def validate_required_params(self) -> "LogTriageAction":
        required = _REQUIRED_PARAMS.get(self.command, [])
        missing = [k for k in required if k not in self.params]
        if missing:
            raise ValueError(
                f"Command '{self.command}' requires params: {missing}. "
                f"Provide them and re-submit."
            )
        return self

    @property
    def tool(self) -> ToolName:
        return ToolName(self.command)

    @property
    def parameters(self) -> dict[str, Any]:
        return self.params

    @classmethod
    def from_legacy(cls, tool: str | ToolName, parameters: dict[str, Any]) -> "LogTriageAction":
        cmd = tool.value if isinstance(tool, ToolName) else str(tool)
        return cls(command=cmd, params=parameters)


# ===========================================================================
# Tool result sub-models
# ===========================================================================

class LogEntry(BaseModel):
    """A single sanitised Sysmon log row returned to the agent."""
    id:             int
    host_id:        str
    timestamp:      str
    event_type:     str
    process:        str | None = None
    commandline:    str | None = None
    target_ip:      str | None = None
    target_domain:  str | None = None
    parent_process: str | None = None
    details:        str | None = None   # JSON blob (is_malicious NEVER included)


class QueryLogsResult(BaseModel):
    """Output of query_logs."""
    query:          str
    matches:        list[LogEntry] = Field(default_factory=list)
    total_found:    int
    query_time_ms:  int
    note:           str = "Results capped at 20. Refine query if needed."


class ProcessTreeNode(BaseModel):
    """One node in a process tree."""
    host_id:        str
    process:        str
    commandline:    str | None = None
    parent_process: str | None = None
    timestamp:      str
    children:       list["ProcessTreeNode"] = Field(default_factory=list)


class AnalyzeProcessResult(BaseModel):
    """Output of analyze_process."""
    process_name:   str
    hosts_seen_on:  list[str]
    tree:           list[ProcessTreeNode] = Field(default_factory=list)
    total_events:   int


class IPReputationResult(BaseModel):
    """Output of check_ip_reputation."""
    ip:               str
    found:            bool
    reputation_score: float = Field(0.0, ge=0.0, le=1.0,
                                    description="0.0 = clean, 1.0 = known malicious")
    category:         str | None = None
    country:          str | None = None
    asn:              str | None = None
    known_malware:    str | None = None
    first_seen:       str | None = None
    last_seen:        str | None = None


class FileHashResult(BaseModel):
    """Output of check_file_hash."""
    hash:        str
    found:       bool
    filename:    str | None = None
    is_malicious: bool = False
    family:      str | None = None
    severity:    str | None = None


class HostSummaryResult(BaseModel):
    """Output of get_host_summary."""
    host:           str
    total_events:   int
    event_types:    dict[str, int]       # event_type → count
    processes_seen: list[str]
    ips_contacted:  list[str]
    domains_contacted: list[str]
    sample_logs:    list[LogEntry] = Field(default_factory=list)


class BackupResult(BaseModel):
    """Output of trigger_backup."""
    host:      str
    status:    str     # "initiated" | "already_backed_up"
    backup_id: str
    timestamp: str
    message:   str = ""


# ===========================================================================
# Observation schema
# ===========================================================================

class LogTriageObservation(Observation):
    """
    Structured feedback returned to the agent after every step.

    On reset() : initial_logs populated, tool_result=None.
    On tool call: tool_result populated, success=True (or error_message set).
    On verdict  : verdict fields populated, episode ends.
    """

    # ── Incident metadata (always present) ────────────────────────────────
    incident_id:    str
    alert_summary:  str  = Field(..., description="One-line SIEM alert that triggered this episode.")
    host_count:     int  = Field(..., description="Number of hosts in this incident bundle.")
    log_count:      int  = Field(..., description="Total log entries in this incident bundle.")
    primary_host:   str  = Field(..., description="Host where the alert originated.")

    # ── Initial view (first 10 logs shown on reset, no tool needed) ───────
    initial_logs:   list[LogEntry] = Field(
        default_factory=list,
        description="First 10 log entries from the bundle, sorted by timestamp.",
    )

    # ── Step result ───────────────────────────────────────────────────────
    success:        bool               = True
    tool_used:      ToolName | None    = None
    tool_result:    dict[str, Any] | None = None
    error_message:  str | None         = None

    # ── Episode progress ──────────────────────────────────────────────────
    step_number:    int           = Field(..., ge=0)
    max_steps:      int           = Field(..., ge=1)
    available_tools: list[ToolName] = Field(default_factory=list)
    tools_used:     list[ToolName]  = Field(default_factory=list)

    # ── Backup tracking ───────────────────────────────────────────────────
    backup_triggered_hosts: list[str] = Field(
        default_factory=list,
        description="Hosts for which trigger_backup has been called this episode.",
    )

    # ── Verdict fields (after submit_verdict) ─────────────────────────────
    verdict_submitted:   bool               = False
    final_verdict:       LogVerdict | None  = None
    final_attack_type:   AttackType | None  = None
    final_affected_hosts: list[str]         = Field(default_factory=list)
    correct_verdict:     LogVerdict | None  = None   # revealed after submission
    correct_attack_type: AttackType | None  = None   # revealed after submission
    reward:              float | None        = None


# ===========================================================================
# State schema (server-side ground truth)
# ===========================================================================

class LogTriageState(State):
    """
    Server-side episode state — returned by GET /state.
    Contains ground truth used by the grader (never sent to agent during episode).
    """

    # ── Identity ──────────────────────────────────────────────────────────
    episode_id:      str
    incident_id:     str
    alert_summary:   str
    primary_host:    str
    affected_hosts:  list[str] = Field(default_factory=list)

    # ── Progress ──────────────────────────────────────────────────────────
    step_count:      int  = 0
    max_steps:       int  = 12

    # ── Grader contract (ground truth, never exposed to agent) ────────────
    expected_verdict:     LogVerdict   = Field(..., description="Ground truth verdict.")
    expected_attack_type: AttackType   = Field(..., description="Ground truth attack classification.")
    difficulty_tier:      DifficultyTier | None = None

    # ── Agent decisions ───────────────────────────────────────────────────
    tools_used:          list[str]          = Field(default_factory=list)
    backup_triggered_hosts: list[str]       = Field(default_factory=list)
    verdict_submitted:   bool               = False
    final_verdict:       LogVerdict | None  = None
    final_attack_type:   AttackType | None  = None
    final_affected_hosts: list[str]         = Field(default_factory=list)
    cumulative_reward:   float              = 0.0

    @property
    def tools_invoked(self) -> list[str]:
        return self.tools_used
