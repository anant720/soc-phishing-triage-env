"""
All the Pydantic schemas live here — Action, Observation, State, and every
sub-model the tools return. If you want to know what shape the data takes
at any point in the environment, this is where to look.

Everything is strictly typed. If an agent sends a bad command name or forgets
a required parameter, Pydantic catches it here before it ever reaches the
environment logic.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Try to use real OpenEnv base classes if installed, otherwise fall back
# to plain BaseModel so the code still runs without the full SDK
# ---------------------------------------------------------------------------
try:
    from openenv.core.models import Action, Observation, State  # type: ignore
except ImportError:  # pragma: no cover
    class Action(BaseModel):  # type: ignore
        """openenv not installed — using plain BaseModel as stand-in"""

    class Observation(BaseModel):  # type: ignore
        """openenv not installed — using plain BaseModel as stand-in"""

    class State(BaseModel):  # type: ignore
        """openenv not installed — using plain BaseModel as stand-in"""


# ===========================================================================
# Enumerations
# ===========================================================================

class ToolName(str, Enum):
    """
    The five things an agent can do. That's it. Anything else gets
    rejected by the validator before it touches the environment.
    """
    ANALYZE_HEADERS     = "analyze_headers"
    LOOKUP_THREAT_INTEL = "lookup_threat_intel"
    SANDBOX_URL         = "sandbox_url"
    WHOIS_LOOKUP        = "whois_lookup"
    SUBMIT_VERDICT      = "submit_verdict"

    @classmethod
    def valid_values(cls) -> list[str]:
        return [t.value for t in cls]


class Verdict(str, Enum):
    """What the agent can submit as its final call on the email."""
    PHISHING = "phishing"
    BENIGN   = "benign"
    ESCALATE = "escalate"   # not sure? pass it up to a Tier-2 analyst


class DifficultyTier(str, Enum):
    """The three tiers in the database — Easy for warm-up, Hard to actually stress the model."""
    EASY   = "Easy"
    MEDIUM = "Medium"
    HARD   = "Hard"


class AdversarialPayloadType(str, Enum):
    """What kind of nasty payload we injected into a Hard-tier phishing email."""
    NONE             = "none"
    IDPI_HTML        = "idpi_html"        # hidden HTML span that tries to override the model
    IDPI_WHITESPACE  = "idpi_whitespace"  # zero-width chars — invisible to humans, visible to LLMs
    URL_TYPOSQUAT    = "url_typosquat"    # domain that looks like a real one at a glance
    URL_IP_BASED     = "url_ip_based"     # bare IP to dodge domain reputation checks
    URL_PADDED       = "url_padded"       # lots of redirect noise to hide where it actually goes
    COMBINED         = "combined"         # both IDPI and URL tricks at once


# ===========================================================================
# Action Schema
# ===========================================================================

# the allowed commands — anything not in here gets rejected immediately
_VALID_COMMANDS: frozenset[str] = frozenset(ToolName.valid_values())

# what parameters each command actually needs — validated after the command check
_REQUIRED_PARAMS: dict[str, list[str]] = {
    "analyze_headers":     ["email_id"],
    "lookup_threat_intel": ["domain"],
    "sandbox_url":         ["url"],
    "whois_lookup":        ["domain"],
    "submit_verdict":      ["verdict"],
}


class TriageAction(Action):
    """
    Type-safe contract for every agent action.

    The ``command`` field (aliased as ``tool`` for API backward-compatibility)
    must be one of the five predefined SOC tools.  Pydantic enforces this before
    any environment logic is invoked, intercepting hallucinated or malformed
    LLM outputs at the schema boundary.

    Examples
    --------
    Invoke a tool::

        TriageAction(command="analyze_headers", params={"email_id": "42"})

    Backward-compatible alias::

        TriageAction(tool="sandbox_url", parameters={"url": "http://evil.com"})

    Submit a verdict::

        TriageAction(command="submit_verdict", params={"verdict": "phishing"})
    """

    # Primary field names (new canonical API)
    command: str = Field(
        ...,
        validation_alias=AliasChoices("command", "tool"),
        description=(
            f"SOC tool to invoke. Must be one of: {sorted(_VALID_COMMANDS)}"
        ),
        examples=["analyze_headers", "submit_verdict"],
    )
    params: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("params", "parameters"),
        description="Tool-specific key-value parameters.",
    )

    # Backward-compatibility aliases accepted from the existing API surface
    # (tool → command,  parameters → params)
    model_config = {"populate_by_name": True}

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @field_validator("command", mode="before")
    @classmethod
    def validate_command(cls, v: Any) -> str:
        """
        Strictly validate that ``command`` is a known SOC tool.

        Applies case-insensitive normalisation so that an LLM emitting
        "Analyze_Headers" instead of "analyze_headers" is corrected rather
        than rejected outright.
        """
        if isinstance(v, ToolName):
            return v.value
        normalised = str(v).strip().lower().replace("-", "_").replace(" ", "_")
        if normalised not in _VALID_COMMANDS:
            raise ValueError(
                f"Unknown command '{v}'. "
                f"Valid commands: {sorted(_VALID_COMMANDS)}. "
                f"Check your spelling — this error prevents environment crashes."
            )
        return normalised

    @model_validator(mode="after")
    def validate_required_params(self) -> "TriageAction":
        """
        Verify that all required parameters for the chosen command are present.

        Returns the model unchanged when valid; raises ValueError with a
        self-correcting hint when required params are missing.
        """
        required = _REQUIRED_PARAMS.get(self.command, [])
        missing  = [k for k in required if k not in self.params]
        if missing:
            raise ValueError(
                f"Command '{self.command}' requires parameter(s): {missing}. "
                f"Full required params: {required}. "
                f"Please re-issue the action with the missing fields."
            )
        return self

    # ------------------------------------------------------------------
    # Backward-compatibility properties
    # ------------------------------------------------------------------

    @property
    def tool(self) -> ToolName:
        """Legacy alias: returns ``command`` as a ToolName enum."""
        return ToolName(self.command)

    @property
    def parameters(self) -> dict[str, Any]:
        """Legacy alias: returns ``params``."""
        return self.params

    @classmethod
    def from_legacy(cls, tool: str | ToolName, parameters: dict[str, Any]) -> "TriageAction":
        """Construct from the old (tool, parameters) API surface."""
        cmd = tool.value if isinstance(tool, ToolName) else str(tool)
        return cls(command=cmd, params=parameters)


# ===========================================================================
# Tool result sub-models (unchanged structure, added docstring clarity)
# ===========================================================================

class HeaderAnalysisResult(BaseModel):
    """
    Output of the ``analyze_headers`` tool.

    Fields matching the triage_scenarios.db ``spf_status`` / ``dkim_status``
    columns so results are always consistent with the ground-truth metadata.
    """
    spf_status:        str  = Field(..., description="SPF check result: Pass | Fail | Neutral | none")
    dkim_status:       str  = Field(..., description="DKIM check result: Pass | Fail | none")
    dmarc_status:      str  = Field(..., description="DMARC policy result: Pass | Fail | none")
    reply_to_mismatch: bool = Field(..., description="True when Return-Path domain ≠ From domain")
    originating_ip:    str  = Field(..., description="Sending mail-server IP address")
    ip_geolocation:    str  = Field(..., description="Country/city of originating IP")
    suspicious_flags:  list[str] = Field(
        default_factory=list,
        description="Anomaly flags: SPF_FAIL, DKIM_FAIL, DMARC_FAIL, REPLY_TO_MISMATCH, etc.",
    )


class ThreatIntelResult(BaseModel):
    """Output of the ``lookup_threat_intel`` tool."""
    domain:                  str
    reputation_score:        float = Field(..., ge=0.0, le=1.0,
                                           description="0.0 = clean, 1.0 = known malicious")
    known_malware_families:  list[str] = Field(default_factory=list)
    first_seen:              str  = Field(..., description="ISO-8601 date first observed")
    last_seen:               str  = Field(..., description="ISO-8601 date last observed")
    tags:                    list[str] = Field(default_factory=list)


class SandboxResult(BaseModel):
    """Output of the ``sandbox_url`` tool."""
    url:                           str
    redirects_to:                  list[str] = Field(default_factory=list)
    page_title:                    str  = ""
    credential_harvesting_detected: bool = False
    malware_download_detected:      bool = False
    risk_level:                    str  = Field(
        ...,
        description="low | medium | high | critical",
    )

    @field_validator("risk_level")
    @classmethod
    def validate_risk_level(cls, v: str) -> str:
        allowed = {"low", "medium", "high", "critical"}
        if v.lower() not in allowed:
            raise ValueError(f"risk_level must be one of {allowed}, got '{v}'")
        return v.lower()


class WhoisResult(BaseModel):
    """Output of the ``whois_lookup`` tool."""
    domain:              str
    registrar:           str
    creation_date:       str  = Field(..., description="ISO-8601 registration date")
    expiry_date:         str  = Field(..., description="ISO-8601 expiry date")
    registrant_country:  str
    privacy_protected:   bool = Field(..., description="True when WHOIS privacy is active")
    age_days:            int  = Field(..., description="Domain age in days at time of lookup")


# ===========================================================================
# Observation Schema
# ===========================================================================

class TriageObservation(Observation):
    """
    Structured feedback returned to the agent after every step.

    The ``success`` flag and ``error_message`` field implement the
    **error-handling loop** required by the hackathon spec: if the agent
    triggers a schema validation error (e.g., missing URL for sandbox_url),
    the environment catches it and echoes the exact error back so the agent
    can self-correct on the next turn without crashing the episode.

    Flow
    ----
    1. On ``reset()``: email metadata only; success=True, tool_result=None.
    2. On successful tool call: success=True, tool_result populated, error_message=None.
    3. On validation/tool error: success=False, tool_result=None, error_message set.
    4. After ``submit_verdict``: verdict fields populated, episode ends.
    """

    # ── Email metadata (always present) ────────────────────────────────────
    email_id:           str
    email_subject:      str
    email_sender:       str
    email_body_snippet: str  = Field(..., description="First 400 chars of email body")

    # ── Adversarial metadata (never revealed to agent directly) ────────────
    difficulty_tier:         DifficultyTier | None = Field(
        default=None,
        description="Revealed only after verdict — used by grader, not agent.",
        exclude=True,   # hidden from agent JSON serialisation
    )
    adversarial_payload_type: AdversarialPayloadType | None = Field(
        default=None,
        description="Type of adversarial payload injected (hidden from agent).",
        exclude=True,
    )

    # ── Step result ─────────────────────────────────────────────────────────
    success:       bool               = Field(True,  description="False when a tool or validation error occurred.")
    tool_used:     ToolName | None    = None
    tool_result:   dict[str, Any] | None = None
    error_message: str | None         = Field(
        None,
        description=(
            "Set when success=False. Contains the exact validation or tool error "
            "so the agent can self-correct on the next step."
        ),
    )

    # ── Episode progress ─────────────────────────────────────────────────────
    step_number:          int          = Field(..., ge=0)
    max_steps:            int          = Field(..., ge=1)
    available_tools:      list[ToolName] = Field(default_factory=list)
    tools_used:           list[ToolName] = Field(
        default_factory=list,
        description="Ordered list of tools the agent has successfully invoked this episode.",
    )

    # ── Verdict fields (populated only after submit_verdict) ────────────────
    verdict_submitted: bool          = False
    final_verdict:     Verdict | None = None
    correct_label:     Verdict | None = None  # revealed only after verdict submission
    reward:            float | None   = None

    # Backward-compatible alias
    @property
    def tools_invoked_so_far(self) -> list[ToolName]:
        return self.tools_used


# ===========================================================================
# State Schema
# ===========================================================================

class TriageState(State):
    """
    Server-side episode state — returned by ``GET /state``.

    The ``expected_verdict`` and ``tools_used`` fields are the **grader
    contract**: the deterministic reward function uses them to penalise
    agents that submit verdicts without performing the required investigative
    steps (e.g., submitting without calling analyze_headers or sandbox_url).

    ``expected_verdict`` is never sent to the agent during an episode;
    it is used internally by the environment and can be inspected by
    evaluation harnesses.
    """

    # ── Identity ─────────────────────────────────────────────────────────────
    episode_id:      str
    current_email_id: str   = Field(..., description="DB row id of the active scenario.")
    email_subject:   str

    # ── Progress counters ────────────────────────────────────────────────────
    step_count:      int   = 0
    max_steps:       int   = 10

    # ── Grader contract ──────────────────────────────────────────────────────
    expected_verdict: bool = Field(
        ...,
        description=(
            "Ground-truth is_phishing flag from the DB (True=phishing, False=benign). "
            "Used by the reward function; never exposed to the agent."
        ),
    )
    tools_used: list[str] = Field(
        default_factory=list,
        description=(
            "Ordered list of tool names the agent has successfully invoked. "
            "The grader requires at least one of [analyze_headers, sandbox_url, "
            "lookup_threat_intel, whois_lookup] before a verdict is accepted "
            "for full reward credit."
        ),
    )
    min_tools_required: int = Field(
        default=1,
        description="Minimum distinct tool calls required for full reward credit.",
    )

    # ── Verdict tracking ──────────────────────────────────────────────────────
    verdict_submitted: bool          = False
    final_verdict:     Verdict | None = None
    cumulative_reward: float         = 0.0

    # ── Difficulty metadata (for evaluation reporting) ────────────────────────
    difficulty_tier:         DifficultyTier | None      = None
    adversarial_payload_type: AdversarialPayloadType | None = None

    @property
    def investigation_complete(self) -> bool:
        """True if the agent has called the minimum required number of tools."""
        return len(set(self.tools_used)) >= self.min_tools_required

    # Backward-compat alias
    @property
    def email_id(self) -> str:
        return self.current_email_id

    @property
    def tools_invoked(self) -> list[str]:
        return self.tools_used
