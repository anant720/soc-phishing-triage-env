"""
Core environment logic for the SOC Triage Environment.
Phase 4 update: reward shaping finalised, per-step penalty added,
OpenEnv HTTPEnvServer integration confirmed.

SocTriageEnvironment extends the OpenEnv Environment base class and
implements the three required methods:
  - reset()  → TriageObservation
  - step()   → StepResult
  - state()  → TriageState

Reward design
-------------
  +1.0   correct final verdict
  -1.0   wrong final verdict
  -0.2   escalating a clear-cut case
  +0.1   each successful unique tool call
  -0.1   schema / tool error (hallucinated param, bad tool call)
  -0.05  per-step penalty (applied every turn to prevent infinite loops)
  -0.5   episode timeout (no verdict within max_steps)
"""

from __future__ import annotations

import random
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from models import (
    ToolName,
    TriageAction,
    TriageObservation,
    TriageState,
    Verdict,
)
from server.tools import run_tool

# ---------------------------------------------------------------------------
# OpenEnv base classes — import with graceful shim fallback
# ---------------------------------------------------------------------------
try:
    from openenv.core.env_server.interfaces import Environment  # type: ignore
    from openenv.core.env_server.types import StepResult         # type: ignore
except ImportError:
    try:
        from openenv.core.env_base import Environment            # type: ignore
        from openenv.core.models import StepResult               # type: ignore
    except ImportError:  # pragma: no cover
        class StepResult(BaseModel):  # type: ignore
            observation: Any
            reward: float
            done: bool
            info: dict[str, Any] = {}

        class Environment:  # type: ignore
            def reset(self) -> Any: ...
            def step(self, action: Any) -> Any: ...
            def state(self) -> Any: ...


# ---------------------------------------------------------------------------
# Reward constants  (all referenced in openenv.yaml and README)
# ---------------------------------------------------------------------------
REWARD_CORRECT_VERDICT   =  1.0    # agent verdict matches ground truth
REWARD_INCORRECT_VERDICT = -1.0    # wrong verdict
REWARD_ESCALATE_CLEAR    = -0.2    # escalating a clear-cut email
REWARD_TOOL_SUCCESS      =  0.1    # each successful, *unique* tool call
REWARD_TOOL_ERROR        = -0.1    # schema violation / bad params / hallucinated tool
REWARD_STEP_PENALTY      = -0.05   # applied every step to discourage infinite loops
REWARD_TIMEOUT_PENALTY   = -0.5    # no verdict within max_steps

MAX_STEPS_DEFAULT = 10

# Use absolute data path relative to execution root to circumvent pip editable __file__ wrappers
_DATA_DIR = Path("data").resolve()
_DB_PATH  = _DATA_DIR / "triage_scenarios.db"

AVAILABLE_TOOLS = [t for t in ToolName if t != ToolName.SUBMIT_VERDICT]


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------

def _row_to_email_dict(row: sqlite3.Row) -> dict[str, Any]:
    """
    Convert a DB row into the email dict shape used by the rest of the env.

    DB columns (by index):
        0   id
        1   subject
        2   email_body
        3   from_address
        4   return_path
        5   spf_status
        6   dkim_status
        7   difficulty_tier
        8   is_phishing
        9   adversarial_payload_type
    """
    is_phishing     = bool(row[8])
    adversarial_type = row[9] if len(row) > 9 else "none"
    return {
        "id":             str(row[0]),
        "subject":        row[1],
        "body":           row[2],
        "sender":         row[3],
        "return_path":    row[4],
        "spf_status":     row[5],
        "dkim_status":    row[6],
        "difficulty_tier": row[7],
        "adversarial_payload_type": adversarial_type,
        # Ground-truth label mapped to Verdict enum values
        "correct_label":  "phishing" if is_phishing else "benign",
        "is_phishing":    is_phishing,
        # Pre-build the header_data dict that tools.py expects
        "header_data": {
            "spf_status":        row[5],
            "dkim_status":       row[6],
            "dmarc_status":      "Pass" if (row[5] == "Pass" and row[6] == "Pass") else "Fail",
            "reply_to_mismatch": row[3] != row[4],
            "originating_ip":    _fake_ip(row[3]),
            "ip_geolocation":    _fake_geo(row[5]),
            "suspicious_flags":  _derive_flags(row[5], row[6], row[3], row[4]),
        },
        # Extract URLs from body for sandbox tool
        "urls": _extract_urls(row[2]),
    }


def _fake_ip(sender: str) -> str:
    """Generate a plausible fake IP seeded on the sender string."""
    seed = abs(hash(sender)) % (254 ** 3)
    a, seed = seed % 254 + 1, seed // 254
    b, seed = seed % 254 + 1, seed // 254
    c = seed % 254 + 1
    return f"{a}.{b}.{c}.1"


def _fake_geo(spf_status: str) -> str:
    clean = ["United States, Virginia", "United States, Oregon",
             "Ireland, Dublin", "Singapore, Singapore"]
    dirty = ["Russia, Moscow", "Nigeria, Lagos", "China, Beijing",
             "Ukraine, Kyiv", "Romania, Bucharest", "Netherlands, Amsterdam"]
    return random.choice(clean) if spf_status == "Pass" else random.choice(dirty)


def _derive_flags(spf: str, dkim: str, from_addr: str, return_path: str) -> list[str]:
    flags: list[str] = []
    if spf  != "Pass":  flags.append("SPF_FAIL")
    if dkim != "Pass":  flags.append("DKIM_FAIL")
    if from_addr != return_path:
        flags.append("REPLY_TO_MISMATCH")
    return flags


def _extract_urls(body: str) -> list[str]:
    """Simple URL extractor using a conservative regex."""
    import re
    return re.findall(r"https?://[^\s\"\'\)>]+", body)


def _sample_db_row(
    conn: sqlite3.Connection,
    tier_filter: str | None = None,
) -> dict[str, Any]:
    """
    Randomly sample one row from triage_scenarios.
    Optionally filter by difficulty_tier ('Easy', 'Medium', 'Hard').
    """
    if tier_filter:
        row = conn.execute(
            "SELECT * FROM triage_scenarios WHERE difficulty_tier=? ORDER BY RANDOM() LIMIT 1",
            (tier_filter,),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM triage_scenarios ORDER BY RANDOM() LIMIT 1"
        ).fetchone()
    if row is None:
        raise RuntimeError("triage_scenarios table is empty. Run data/build_db.py first.")
    return _row_to_email_dict(row)


# ===========================================================================
# Environment
# ===========================================================================

class SocTriageEnvironment(Environment):
    """
    Simulates a Tier-1 SOC analyst triage workflow.

    Each episode randomly samples one email scenario from the SQLite
    database (triage_scenarios.db) across Easy / Medium / Hard tiers.
    The agent must invoke SOC tools iteratively before submitting a
    final verdict: phishing | benign | escalate.
    """

    def __init__(
        self,
        max_steps: int = MAX_STEPS_DEFAULT,
        db_path: Path | None = None,
        tier_filter: str | None = None,
    ) -> None:
        self._max_steps   = max_steps
        self._db_path     = db_path or _DB_PATH
        self._tier_filter = tier_filter        # None = all tiers; or 'Easy'/'Medium'/'Hard'
        self._conn        = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._episodes: dict[str, dict[str, Any]] = {}
        self._current_episode_id: str = ""

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _new_episode(self, override_tier: str | None = None) -> dict[str, Any]:
        tier = override_tier or self._tier_filter
        email      = _sample_db_row(self._conn, tier)
        
        was_spoofed = False
        if email.get("difficulty_tier") == "Hard" and email.get("correct_label") == "benign" and random.random() < 0.5:
            was_spoofed = True
            email["return_path"] = f"bounces@{random.choice(['malicious-domain.ru', 'login-verify.com', 'secure-it-alert.net'])}"
            email["spf_status"] = "Fail"
            email["dkim_status"] = "Fail"
            email["header_data"]["spf_status"] = "Fail"
            email["header_data"]["dkim_status"] = "Fail"
            email["header_data"]["dmarc_status"] = "Fail"
            email["header_data"]["reply_to_mismatch"] = True
            email["header_data"]["suspicious_flags"] = _derive_flags(email["spf_status"], email["dkim_status"], email["sender"], email["return_path"])

        episode_id = str(uuid.uuid4())
        ep: dict[str, Any] = {
            "episode_id":        episode_id,
            "email":             email,
            "step_count":        0,
            "tools_invoked":     [],
            "verdict_submitted": False,
            "final_verdict":     None,
            "cumulative_reward": 0.0,
            "done":              False,
            "was_spoofed":       was_spoofed,
        }
        self._episodes[episode_id] = ep
        self._current_episode_id   = episode_id
        return ep

    def _get_ep(self) -> dict[str, Any]:
        if not self._current_episode_id:
            raise RuntimeError("No active episode. Call reset() first.")
        return self._episodes[self._current_episode_id]

    def _build_observation(
        self,
        ep: dict[str, Any],
        tool_used: ToolName | None = None,
        tool_result: dict[str, Any] | None = None,
        reward: float | None = None,
        success: bool = True,
        error_message: str | None = None,
    ) -> TriageObservation:
        email = ep["email"]
        from models import DifficultyTier, AdversarialPayloadType
        try:
            tier = DifficultyTier(email.get("difficulty_tier", "Hard"))
        except ValueError:
            tier = None
        try:
            adv = AdversarialPayloadType(email.get("adversarial_payload_type", "none"))
        except ValueError:
            adv = None
        return TriageObservation(
            email_id=email["id"],
            email_subject=email["subject"],
            email_sender=email["sender"],
            email_body_snippet=email["body"][:400],
            difficulty_tier=tier,
            adversarial_payload_type=adv,
            success=success,
            tool_used=tool_used,
            tool_result=tool_result,
            error_message=error_message,
            step_number=ep["step_count"],
            max_steps=self._max_steps,
            available_tools=AVAILABLE_TOOLS,
            tools_used=list(ep["tools_invoked"]),
            verdict_submitted=ep["verdict_submitted"],
            final_verdict=ep["final_verdict"],
            correct_label=Verdict(email["correct_label"]) if ep["verdict_submitted"] else None,
            reward=reward,
        )

    def _compute_reward(
        self,
        agent_verdict: Verdict,
        correct_label: Verdict,
        tools_used: list[ToolName],
    ) -> float:
        """Compute the final verdict reward, including tool-breadth bonus."""
        if agent_verdict == correct_label:
            reward = REWARD_CORRECT_VERDICT
        elif agent_verdict == Verdict.ESCALATE:
            reward = REWARD_ESCALATE_CLEAR
        else:
            reward = REWARD_INCORRECT_VERDICT

        # Bonus per *unique* tool called (encourages broad investigation)
        reward += len(set(tools_used)) * REWARD_TOOL_SUCCESS
        return round(reward, 4)

    # -----------------------------------------------------------------------
    # OpenEnv interface
    # -----------------------------------------------------------------------

    def reset(self, tier_filter: str | None = None) -> TriageObservation:
        """Sample a new scenario from the DB and start a fresh episode."""
        ep = self._new_episode(override_tier=tier_filter)
        return self._build_observation(ep)

    def step(self, action: TriageAction) -> StepResult:
        """
        Execute one agent action and return (observation, reward, done, info).

        Reward shaping per step
        -----------------------
        Every step incurs a -0.05 step penalty (REWARD_STEP_PENALTY) to
        penalise infinite loops and reward fast, accurate triage.
        On top of that:
          +0.1  successful, unique tool call
          -0.1  schema/tool error (self-correction loop)
          ±1.0  correct / incorrect final verdict
        """
        ep = self._get_ep()

        if ep["done"]:
            obs = self._build_observation(ep, success=True)
            return StepResult(observation=obs, reward=0.0, done=True,
                              info={"error": "Episode already done."})

        ep["step_count"] += 1
        # ── Per-step penalty (applied unconditionally) ─────────────────────
        step_penalty = REWARD_STEP_PENALTY
        ep["cumulative_reward"] += step_penalty

        tool_used   = action.tool
        tool_result = None
        reward      = step_penalty   # base reward for this step
        done        = False
        info: dict[str, Any] = {"step_penalty": step_penalty}

        # ── Case 1: Submit Verdict ─────────────────────────────────────────
        if tool_used == ToolName.SUBMIT_VERDICT:
            raw_verdict = action.parameters.get("verdict", "")
            try:
                agent_verdict = Verdict(raw_verdict)
            except ValueError:
                info["error"] = (
                    f"Invalid verdict '{raw_verdict}'. "
                    f"Choose from: {[v.value for v in Verdict]}"
                )
                obs = self._build_observation(
                    ep, success=False,
                    error_message=info["error"]
                )
                return StepResult(observation=obs, reward=-0.1, done=False, info=info)

            correct_label = Verdict(ep["email"]["correct_label"])
            verdict_reward = self._compute_reward(agent_verdict, correct_label, ep["tools_invoked"])
            reward += verdict_reward   # add to step_penalty base

            ep["verdict_submitted"] = True
            ep["final_verdict"]     = agent_verdict
            ep["cumulative_reward"] += verdict_reward
            ep["done"]              = True
            done                    = True
            info["verdict_reward"]          = verdict_reward
            info["difficulty_tier"]         = ep["email"]["difficulty_tier"]
            info["adversarial_payload_type"] = ep["email"]["adversarial_payload_type"]

            obs = self._build_observation(ep, tool_used=tool_used, reward=reward, success=True)

        # ── Case 2: Invoke a SOC Tool ──────────────────────────────────────
        else:
            # Inject DB-derived email metadata so tools can use it
            # (tools.py still reads from JSON for the legacy path; override
            #  header_data inside action.parameters when tool is analyze_headers)
            params = dict(action.parameters)

            # Transparently pass the email's pre-built header_data to the tool
            if tool_used == ToolName.ANALYZE_HEADERS:
                params.setdefault("email_id", ep["email"]["id"])
                # Override tool's JSON lookup with DB data
                params["_header_override"] = ep["email"]["header_data"]

            try:
                tool_result = run_tool(tool_used.value, params)
                # Only reward the first use of each unique tool
                is_new_tool = tool_used not in ep["tools_invoked"]
                ep["tools_invoked"].append(tool_used)
                tool_reward = REWARD_TOOL_SUCCESS if is_new_tool else 0.0
                
                # Granular Verification Reward: reward the agent highly for successfully 
                # running analyze_headers on dynamically spoofed anomalies
                if is_new_tool and tool_used == ToolName.ANALYZE_HEADERS and ep.get("was_spoofed"):
                    tool_reward += 0.2
                    
                reward += tool_reward
                ep["cumulative_reward"] += tool_reward
                info["tool_reward"] = tool_reward
            except (ValueError, KeyError) as exc:
                err_msg = str(exc)
                info["error"] = err_msg
                # Schema / tool error penalty
                error_reward = REWARD_TOOL_ERROR
                reward += error_reward
                ep["cumulative_reward"] += error_reward
                obs = self._build_observation(
                    ep,
                    tool_used=tool_used,
                    success=False,
                    error_message=(
                        f"Tool '{tool_used.value}' failed: {err_msg}. "
                        f"Re-issue the action with corrected parameters."
                    ),
                    reward=reward,
                )
                return StepResult(observation=obs, reward=reward, done=False, info=info)

            # Auto-terminate on max-steps timeout
            if ep["step_count"] >= self._max_steps and not ep["verdict_submitted"]:
                reward += REWARD_TIMEOUT_PENALTY
                ep["cumulative_reward"] += REWARD_TIMEOUT_PENALTY
                ep["done"] = True
                done       = True
                info["timeout"] = True

            obs = self._build_observation(
                ep, tool_used=tool_used, tool_result=tool_result,
                reward=reward, success=True
            )

        return StepResult(observation=obs, reward=reward, done=done, info=info)

    def state(self) -> TriageState:
        """Return current episode metadata."""
        ep    = self._get_ep()
        email = ep["email"]
        from models import DifficultyTier, AdversarialPayloadType
        try:
            tier = DifficultyTier(email.get("difficulty_tier", "Hard"))
        except ValueError:
            tier = None
        try:
            adv = AdversarialPayloadType(email.get("adversarial_payload_type", "none"))
        except ValueError:
            adv = None
        return TriageState(
            episode_id=ep["episode_id"],
            current_email_id=email["id"],
            email_subject=email["subject"],
            step_count=ep["step_count"],
            max_steps=self._max_steps,
            expected_verdict=email["is_phishing"],
            tools_used=[t.value for t in ep["tools_invoked"]],
            verdict_submitted=ep["verdict_submitted"],
            final_verdict=ep["final_verdict"],
            cumulative_reward=ep["cumulative_reward"],
            difficulty_tier=tier,
            adversarial_payload_type=adv,
        )

    def close(self) -> None:
        """Release the SQLite connection."""
        self._conn.close()
