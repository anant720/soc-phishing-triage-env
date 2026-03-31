"""
Core environment logic for the SOC Log Triage Environment.

Each episode:
  1. Randomly samples one incident_bundle row from SQLite.
  2. Loads the associated Sysmon log IDs.
  3. Exposes the OpenEnv interface: reset() / step() / state().

Reward design
-------------
  +1.0   correct verdict (malicious/benign/escalate-on-ambiguous)
  -1.0   wrong verdict
  -0.2   escalate on a clear-cut case
  +0.1   each successful, *unique* tool call
  -0.1   schema / tool error
  -0.05  per-step penalty (every turn)
  -0.5   episode timeout (no verdict within max_steps)

  Attack type bonus (applied on top of correct verdict):
  +0.3   correct attack_type classification (c2_beacon/ransomware/etc.)
  -0.2   wrong attack_type (still correct verdict)

  Backup bonus:
  +0.2   trigger_backup called on a host that IS in affected_hosts before/at verdict
  +0.0   no backup triggered on malicious episode (no deduction, partial credit only)
"""
from __future__ import annotations

import json
import random
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from models import (
    AttackType,
    DifficultyTier,
    LogEntry,
    LogTriageAction,
    LogTriageObservation,
    LogTriageState,
    LogVerdict,
    ToolName,
)
from server.tools import run_tool

# ---------------------------------------------------------------------------
# OpenEnv base class shim
# ---------------------------------------------------------------------------
try:
    from openenv.core.env_server.interfaces import Environment  # type: ignore
    from openenv.core.env_server.types import StepResult         # type: ignore
except ImportError:
    try:
        from openenv.core.env_base import Environment            # type: ignore
        from openenv.core.models import StepResult               # type: ignore
    except ImportError:
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
# Reward constants  (kept small so episode cumulative stays in [-1.0, +1.0])
# ---------------------------------------------------------------------------
# Terminal verdict rewards — use the grader score directly (0.0–1.0 range)
# Wrong verdict always = -1.0 so the agent is strongly penalised.
REWARD_WRONG_VERDICT     = -1.0  # wrong verdict = strong negative signal
REWARD_ESCALATE_CLEAR    = -0.2  # escalating a clear-cut case

# Per-step shaping rewards — small so they don't dominate the terminal signal
REWARD_TOOL_SUCCESS      =  0.05  # each new unique tool call
REWARD_TOOL_ERROR        = -0.05  # schema / bad-param error
REWARD_STEP_PENALTY      = -0.02  # per-step penalty (anti-loop)
REWARD_TIMEOUT_PENALTY   = -0.30  # no verdict within max_steps

# Max steps per tier — higher log volumes need more investigation steps
MAX_STEPS: dict[str, int] = {
    "Easy":   20,   # ~50 logs
    "Medium": 28,   # ~100 logs
    "Hard":   40,   # ~200 logs
}
MAX_STEPS_DEFAULT = 28

_DATA_DIR = Path("data").resolve()
_DB_PATH  = _DATA_DIR / "triage_scenarios.db"

INVESTIGATION_TOOLS = [t for t in ToolName if t not in (
    ToolName.SUBMIT_VERDICT, ToolName.TRIGGER_BACKUP
)]
ALL_AVAILABLE_TOOLS = [t for t in ToolName if t != ToolName.SUBMIT_VERDICT] + [ToolName.SUBMIT_VERDICT]


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------

_SAFE_LOG_COLS = (
    "id", "host_id", "timestamp", "event_type", "process",
    "commandline", "target_ip", "target_domain", "parent_process", "details"
)


def _load_incident(conn: sqlite3.Connection, tier_filter: str | None) -> dict[str, Any]:
    """Sample one incident_bundle row from the DB."""
    if tier_filter:
        row = conn.execute(
            "SELECT * FROM incident_bundles WHERE difficulty_tier=? ORDER BY RANDOM() LIMIT 1",
            (tier_filter,),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT * FROM incident_bundles ORDER BY RANDOM() LIMIT 1"
        ).fetchone()

    if row is None:
        raise RuntimeError("incident_bundles table is empty. Run data/build_incidents.py first.")

    cols = ["id", "incident_id", "alert_summary", "difficulty_tier",
            "is_malicious", "attack_type", "primary_host", "affected_hosts", "log_ids"]
    d = dict(zip(cols, row))
    d["affected_hosts"] = json.loads(d["affected_hosts"])
    d["log_ids"]        = json.loads(d["log_ids"])
    return d


def _load_initial_logs(conn: sqlite3.Connection, log_ids: list[int]) -> list[LogEntry]:
    """Fetch ALL logs from the bundle sorted by timestamp (no is_malicious exposed)."""
    if not log_ids:
        return []
    sel    = ", ".join(_SAFE_LOG_COLS)
    ids_ph = ",".join("?" * len(log_ids))
    rows   = conn.execute(
        f"SELECT {sel} FROM sysmon_endpoint_logs WHERE id IN ({ids_ph}) ORDER BY timestamp",
        log_ids,
    ).fetchall()
    return [LogEntry(**dict(zip(_SAFE_LOG_COLS, r))) for r in rows]


# ===========================================================================
# Environment
# ===========================================================================

class SocLogTriageEnvironment(Environment):
    """
    Simulates a Tier-1 SOC analyst triage workflow using endpoint logs.

    Each episode randomly samples one incident bundle (a correlated set of
    Windows Sysmon logs). The agent must investigate using log-analysis tools,
    trigger a backup on compromised hosts, and submit a verdict with an
    attack type classification.
    """

    def __init__(
        self,
        db_path: Path | None = None,
        tier_filter: str | None = None,
    ) -> None:
        self._db_path     = db_path or _DB_PATH
        self._tier_filter = tier_filter
        self._conn        = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._episodes: dict[str, dict[str, Any]] = {}
        self._current_episode_id: str = ""

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _new_episode(self, override_tier: str | None = None) -> dict[str, Any]:
        tier = override_tier or self._tier_filter
        incident = _load_incident(self._conn, tier)
        log_ids  = incident["log_ids"]
        initial  = _load_initial_logs(self._conn, log_ids)

        episode_id = str(uuid.uuid4())
        tier_str   = incident.get("difficulty_tier", "Medium")
        max_steps  = MAX_STEPS.get(tier_str, MAX_STEPS_DEFAULT)
        ep: dict[str, Any] = {
            "episode_id":        episode_id,
            "incident":          incident,
            "log_ids":           log_ids,
            "initial_logs":      initial,
            "step_count":        0,
            "max_steps":         max_steps,
            "tools_invoked":     [],
            "backup_hosts":      [],        # hosts for which trigger_backup was called
            "verdict_submitted": False,
            "final_verdict":     None,
            "final_attack_type": None,
            "final_affected_hosts": [],
            "cumulative_reward": 0.0,
            "done":              False,
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
    ) -> LogTriageObservation:
        inc = ep["incident"]
        try:
            tier = DifficultyTier(inc.get("difficulty_tier", "Hard"))
        except ValueError:
            tier = None

        return LogTriageObservation(
            incident_id=inc["incident_id"],
            alert_summary=inc["alert_summary"],
            host_count=len(inc["affected_hosts"]),
            log_count=len(ep["log_ids"]),
            primary_host=inc["primary_host"],
            initial_logs=ep["initial_logs"],
            success=success,
            tool_used=tool_used,
            tool_result=tool_result,
            error_message=error_message,
            step_number=ep["step_count"],
            max_steps=ep["max_steps"],
            available_tools=list(ToolName),
            tools_used=list(ep["tools_invoked"]),
            backup_triggered_hosts=list(ep["backup_hosts"]),
            verdict_submitted=ep["verdict_submitted"],
            final_verdict=ep["final_verdict"],
            final_attack_type=ep["final_attack_type"],
            final_affected_hosts=ep["final_affected_hosts"],
            correct_verdict=LogVerdict("malicious" if ep["incident"]["is_malicious"] else "benign")
                             if ep["verdict_submitted"] else None,
            correct_attack_type=AttackType(ep["incident"]["attack_type"])
                                 if ep["verdict_submitted"] else None,
            reward=reward,
        )

    def _compute_verdict_reward(
        self,
        agent_verdict: LogVerdict,
        agent_attack_type: AttackType | None,
        agent_affected_hosts: list[str],
        ep: dict[str, Any],
    ) -> tuple[float, dict[str, Any]]:
        """
        Terminal reward for submit_verdict.

        Uses the same logic as the grader so the training signal is consistent
        with the evaluation score.  Result is always in [-1.0, +1.0].
        """
        from server.grader import grade
        inc = ep["incident"]
        expected_verdict = LogVerdict("malicious" if inc["is_malicious"] else "benign")
        breakdown: dict[str, Any] = {}

        # Wrong verdict → strong negative
        if agent_verdict != expected_verdict:
            if agent_verdict == LogVerdict.ESCALATE:
                return REWARD_ESCALATE_CLEAR, {"verdict": REWARD_ESCALATE_CLEAR}
            return REWARD_WRONG_VERDICT, {"verdict": REWARD_WRONG_VERDICT}

        # Build a temporary state object and run the actual grader
        from models import DifficultyTier
        try:
            tier = DifficultyTier(inc.get("difficulty_tier", "Hard"))
        except ValueError:
            tier = None

        from models import LogTriageState
        temp_state = LogTriageState(
            episode_id=ep["episode_id"],
            incident_id=inc["incident_id"],
            alert_summary=inc["alert_summary"],
            primary_host=inc["primary_host"],
            affected_hosts=inc["affected_hosts"],
            step_count=ep["step_count"],
            max_steps=ep["max_steps"],
            expected_verdict=expected_verdict,
            expected_attack_type=AttackType(inc["attack_type"]),
            difficulty_tier=tier,
            tools_used=[t.value for t in ep["tools_invoked"]],
            backup_triggered_hosts=list(ep["backup_hosts"]),
            verdict_submitted=True,
            final_verdict=agent_verdict,
            final_attack_type=agent_attack_type,
            final_affected_hosts=agent_affected_hosts,
            cumulative_reward=0.0,
        )
        result = grade(temp_state)
        # Grader score is 0.0–1.0; map to reward space [-1, +1] is already
        # handled by wrong-verdict guard above. Just return the score directly.
        breakdown = result.breakdown
        return round(result.score, 4), breakdown

    # -----------------------------------------------------------------------
    # OpenEnv interface
    # -----------------------------------------------------------------------

    def reset(self, tier_filter: str | None = None) -> LogTriageObservation:
        """Start a new episode by sampling a fresh incident bundle."""
        ep = self._new_episode(override_tier=tier_filter)
        return self._build_observation(ep)

    def step(self, action: LogTriageAction) -> StepResult:
        """
        Execute one agent action and return (observation, reward, done, info).
        """
        ep = self._get_ep()

        if ep["done"]:
            obs = self._build_observation(ep, success=True)
            return StepResult(observation=obs, reward=0.0, done=True,
                              info={"error": "Episode already done."})

        ep["step_count"] += 1
        step_penalty = REWARD_STEP_PENALTY
        ep["cumulative_reward"] += step_penalty

        tool_used   = action.tool
        tool_result = None
        reward      = step_penalty
        done        = False
        info: dict[str, Any] = {"step_penalty": step_penalty}

        # ── Case 1: Submit Verdict ─────────────────────────────────────────
        if tool_used == ToolName.SUBMIT_VERDICT:
            # Validate verdict
            raw_verdict = action.params.get("verdict", "")
            try:
                agent_verdict = LogVerdict(raw_verdict)
            except ValueError:
                msg = (f"Invalid verdict '{raw_verdict}'. "
                       f"Choose from: {[v.value for v in LogVerdict]}")
                obs = self._build_observation(ep, success=False, error_message=msg)
                return StepResult(observation=obs, reward=-0.1, done=False,
                                  info={"error": msg})

            # Parse optional attack_type (required if verdict == malicious)
            raw_attack = action.params.get("attack_type")
            agent_attack_type: AttackType | None = None
            if raw_attack:
                try:
                    agent_attack_type = AttackType(raw_attack)
                except ValueError:
                    msg = (f"Invalid attack_type '{raw_attack}'. "
                           f"Valid: {[a.value for a in AttackType if a != AttackType.BENIGN]}")
                    obs = self._build_observation(ep, success=False, error_message=msg)
                    return StepResult(observation=obs, reward=-0.1, done=False,
                                      info={"error": msg})

            affected_hosts = action.params.get("affected_hosts", [])
            if isinstance(affected_hosts, str):
                affected_hosts = [affected_hosts]

            verdict_reward, breakdown = self._compute_verdict_reward(
                agent_verdict, agent_attack_type, affected_hosts, ep
            )
            reward += verdict_reward

            ep["verdict_submitted"]    = True
            ep["final_verdict"]        = agent_verdict
            ep["final_attack_type"]    = agent_attack_type
            ep["final_affected_hosts"] = affected_hosts
            ep["cumulative_reward"]   += verdict_reward
            ep["done"] = True
            done       = True

            info["verdict_reward"]   = verdict_reward
            info["breakdown"]        = breakdown
            info["difficulty_tier"]  = ep["incident"]["difficulty_tier"]
            info["attack_type_gt"]   = ep["incident"]["attack_type"]

            obs = self._build_observation(ep, tool_used=tool_used, reward=reward, success=True)

        # ── Case 2: Invoke a Tool ──────────────────────────────────────────
        else:
            params = dict(action.params)

            try:
                tool_result = run_tool(
                    tool_used.value, params,
                    db_conn=self._conn,
                    log_ids=ep["log_ids"],
                )
                is_new = tool_used not in ep["tools_invoked"]
                ep["tools_invoked"].append(tool_used)
                tool_reward = REWARD_TOOL_SUCCESS if is_new else 0.0

                # Track backup calls
                if tool_used == ToolName.TRIGGER_BACKUP:
                    host = params.get("host", "")
                    if host and host not in ep["backup_hosts"]:
                        ep["backup_hosts"].append(host)

                reward += tool_reward
                ep["cumulative_reward"] += tool_reward
                info["tool_reward"] = tool_reward

            except (ValueError, KeyError) as exc:
                err_msg = str(exc)
                info["error"] = err_msg
                reward += REWARD_TOOL_ERROR
                ep["cumulative_reward"] += REWARD_TOOL_ERROR
                obs = self._build_observation(
                    ep, tool_used=tool_used, success=False,
                    error_message=f"Tool '{tool_used.value}' failed: {err_msg}",
                    reward=reward,
                )
                return StepResult(observation=obs, reward=reward, done=False, info=info)

            # Auto-terminate on timeout
            if ep["step_count"] >= ep["max_steps"] and not ep["verdict_submitted"]:
                reward += REWARD_TIMEOUT_PENALTY
                ep["cumulative_reward"] += REWARD_TIMEOUT_PENALTY
                ep["done"] = True
                done       = True
                info["timeout"] = True

            obs = self._build_observation(
                ep, tool_used=tool_used, tool_result=tool_result,
                reward=reward, success=True,
            )

        return StepResult(observation=obs, reward=reward, done=done, info=info)

    def state(self) -> LogTriageState:
        """Return current episode metadata (includes ground truth for grader)."""
        ep  = self._get_ep()
        inc = ep["incident"]
        try:
            tier = DifficultyTier(inc.get("difficulty_tier", "Hard"))
        except ValueError:
            tier = None

        return LogTriageState(
            episode_id=ep["episode_id"],
            incident_id=inc["incident_id"],
            alert_summary=inc["alert_summary"],
            primary_host=inc["primary_host"],
            affected_hosts=inc["affected_hosts"],
            step_count=ep["step_count"],
            max_steps=ep["max_steps"],
            expected_verdict=LogVerdict("malicious" if inc["is_malicious"] else "benign"),
            expected_attack_type=AttackType(inc["attack_type"]),
            difficulty_tier=tier,
            tools_used=[t.value for t in ep["tools_invoked"]],
            backup_triggered_hosts=list(ep["backup_hosts"]),
            verdict_submitted=ep["verdict_submitted"],
            final_verdict=ep["final_verdict"],
            final_attack_type=ep["final_attack_type"],
            final_affected_hosts=ep["final_affected_hosts"],
            cumulative_reward=ep["cumulative_reward"],
        )

    def close(self) -> None:
        """Release the SQLite connection."""
        self._conn.close()
