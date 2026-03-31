"""
SOC Log Triage Grader — v4.0

Score is always CLAMPED to [0.0, 1.0] at the end.
A PERFECT run earns exactly 1.00.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MALICIOUS episode — perfect = 1.00
  +0.30  correct verdict
  +0.25  investigation tools  (proportional; 0 coverage → penalty)
  +0.20  attack type correct
  +0.15  backup on correct host
  +0.10  step efficiency
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
BENIGN episode — perfect = 1.00
  +0.30  correct verdict
  +0.35  tools  (proportional; 0 coverage → penalty)
  +0.25  did NOT trigger backup
  +0.10  step efficiency
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PENALTIES (applied AFTER components, can push score lower; clamped at 0):
  −0.25  wrong verdict
  −0.20  zero investigation (no required tool group checked at all)
  −0.10  rush verdict (steps < ideal AND coverage < 50%)
  −0.10  backup on benign (false positive)
  −0.08  backup on wrong host (malicious)
  −0.05  excess steps beyond hard bracket
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Score is clamped to [0.0, 1.0]. All breakdown values are PRE-CLAMP.
"""
from __future__ import annotations

from models import AttackType, DifficultyTier, LogTriageState, LogVerdict

# ---------------------------------------------------------------------------
# Component weights — each path sums to exactly 1.00 for perfect behavior
# ---------------------------------------------------------------------------
W_VERDICT          = 0.30
W_TOOLS_MALICIOUS  = 0.25
W_TOOLS_BENIGN     = 0.35
W_ATTACK_TYPE      = 0.20
W_BACKUP_MALICIOUS = 0.15
W_NO_BAD_BACKUP    = 0.25
W_EFFICIENCY       = 0.10

# Active penalties (always negative, applied after components)
PENALTY_WRONG_VERDICT      = -0.25   # wrong verdict (on top of 0 verdict bonus)
PENALTY_NO_INVESTIGATION   = -0.20   # zero required tool groups covered
PENALTY_RUSH               = -0.10   # steps < ideal AND tool coverage < 50%
PENALTY_FALSE_BACKUP       = -0.10   # backup triggered on benign incident
PENALTY_BACKUP_WRONG_HOST  = -0.08   # backup on wrong host (malicious)

# Alias kept for test compatibility
PENALTY_INVESTIGATION = W_TOOLS_MALICIOUS  # max bonus lost on no tools

# ---------------------------------------------------------------------------
# Required tool groups per tier
# ---------------------------------------------------------------------------
REQUIRED_TOOLS: dict[str, list[frozenset[str]]] = {
    "Easy": [
        frozenset({"query_logs", "analyze_process", "get_host_summary"}),
    ],
    "Medium": [
        frozenset({"analyze_process", "get_host_summary"}),
        frozenset({"check_ip_reputation", "check_file_hash", "query_logs"}),
    ],
    "Hard": [
        frozenset({"analyze_process", "get_host_summary"}),
        frozenset({"check_ip_reputation", "check_file_hash"}),
        frozenset({"query_logs"}),
    ],
}

# Step budgets: (ideal_max, mild_warn, hard_warn)
STEP_BRACKETS: dict[str, tuple[int, int, int]] = {
    "Easy":   (6,  12, 17),   # max_steps=20
    "Medium": (9,  18, 25),   # max_steps=28
    "Hard":   (14, 28, 37),   # max_steps=40
}


# ---------------------------------------------------------------------------
# Result object
# ---------------------------------------------------------------------------
class GraderResult:
    def __init__(self, score: float, correct: bool,
                 deductions: list[str], breakdown: dict) -> None:
        self.score      = score
        self.correct    = correct
        self.deductions = deductions
        self.breakdown  = breakdown

    def to_dict(self) -> dict:
        return {
            "score":      self.score,
            "correct":    self.correct,
            "deductions": self.deductions,
            "breakdown":  self.breakdown,
        }


# ---------------------------------------------------------------------------
# Main grader
# ---------------------------------------------------------------------------
def grade(state: LogTriageState) -> GraderResult:
    """
    Grade a completed episode.
    Score = sum of components + penalties, clamped to [0.0, 1.0].
    All pre-clamp values are preserved in breakdown for display.
    """
    deductions: list[str] = []
    breakdown:  dict      = {}
    score = 0.0

    # ── 0. Must have verdict ─────────────────────────────────────────────────
    if not state.verdict_submitted or state.final_verdict is None:
        return GraderResult(
            score=0.0, correct=False,
            deductions=["No verdict submitted — episode incomplete."],
            breakdown={"final_score": 0.0},
        )

    tier         = state.difficulty_tier.value if state.difficulty_tier else "Hard"
    tools_used   = frozenset(state.tools_used or [])
    backed_up    = set(state.backup_triggered_hosts or [])
    affected     = set(state.affected_hosts or [])
    steps        = state.step_count

    # ── 1. Investigation tools (computed early — needed for rush penalty) ────
    required_groups = REQUIRED_TOOLS.get(tier, [])
    n_groups        = len(required_groups) or 1
    groups_covered  = sum(1 for g in required_groups if tools_used & g)
    coverage_ratio  = groups_covered / n_groups

    # ── 2. Verdict ───────────────────────────────────────────────────────────
    correct = (state.final_verdict == state.expected_verdict)
    if correct:
        score += W_VERDICT
        breakdown["verdict"] = W_VERDICT
    else:
        # No verdict bonus + active penalty for wrong verdict
        breakdown["verdict"] = 0.0
        score += PENALTY_WRONG_VERDICT
        breakdown["wrong_verdict_penalty"] = PENALTY_WRONG_VERDICT
        sub = state.final_verdict.value if state.final_verdict else "?"
        exp = state.expected_verdict.value
        deductions.append(
            f"Wrong verdict: submitted '{sub}', expected '{exp}'. "
            f"({PENALTY_WRONG_VERDICT:+.2f} penalty)"
        )

    is_malicious = (state.expected_verdict == LogVerdict.MALICIOUS)

    # ── 3. Proportional tool score + no-investigation penalty ────────────────
    tool_weight = W_TOOLS_MALICIOUS if is_malicious else W_TOOLS_BENIGN
    tool_score  = round(coverage_ratio * tool_weight, 4)
    score      += tool_score
    breakdown["tools"] = tool_score

    if coverage_ratio == 0.0:
        # Zero investigation — active penalty on top of zero tool score
        score += PENALTY_NO_INVESTIGATION
        breakdown["no_investigation_penalty"] = PENALTY_NO_INVESTIGATION
        deductions.append(
            f"No investigation tools used — zero required tool groups covered. "
            f"({PENALTY_NO_INVESTIGATION:+.2f} penalty)"
        )
    elif coverage_ratio < 1.0:
        missing = [sorted(g) for g in required_groups if not (tools_used & g)]
        deductions.append(
            f"Tools: covered {groups_covered}/{n_groups} required groups. "
            f"Missing: {missing}. Earned {tool_score:.2f}/{tool_weight:.2f}."
        )

    # ── 4. Attack type (malicious only) ─────────────────────────────────────
    if is_malicious:
        attack_ok = (
            state.final_attack_type is not None
            and state.final_attack_type == state.expected_attack_type
        )
        if attack_ok:
            score += W_ATTACK_TYPE
            breakdown["attack_type"] = W_ATTACK_TYPE
        else:
            sub_atk = (state.final_attack_type.value
                       if state.final_attack_type else "not provided")
            breakdown["attack_type"] = 0.0
            deductions.append(
                f"Wrong/missing attack type: submitted '{sub_atk}', "
                f"expected '{state.expected_attack_type.value}'. "
                f"(+{W_ATTACK_TYPE:.2f} not earned)"
            )

    # ── 5. Backup handling ───────────────────────────────────────────────────
    if is_malicious:
        correct_backups = backed_up & affected
        if correct_backups:
            score += W_BACKUP_MALICIOUS
            breakdown["backup"] = W_BACKUP_MALICIOUS
        else:
            breakdown["backup"] = 0.0
            if backed_up:
                score += PENALTY_BACKUP_WRONG_HOST
                breakdown["backup_wrong_host_penalty"] = PENALTY_BACKUP_WRONG_HOST
                deductions.append(
                    f"Backup on wrong host(s) {sorted(backed_up)}, "
                    f"expected one of {sorted(affected)}. "
                    f"({PENALTY_BACKUP_WRONG_HOST:+.2f})"
                )
            else:
                deductions.append(
                    f"No backup on affected host(s) {sorted(affected)}. "
                    f"(+{W_BACKUP_MALICIOUS:.2f} not earned)"
                )
    else:
        if not backed_up:
            score += W_NO_BAD_BACKUP
            breakdown["backup"] = W_NO_BAD_BACKUP
        else:
            breakdown["backup"] = 0.0
            score += PENALTY_FALSE_BACKUP
            breakdown["false_backup_penalty"] = PENALTY_FALSE_BACKUP
            deductions.append(
                f"Backup triggered on benign incident — false positive! "
                f"({PENALTY_FALSE_BACKUP:+.2f})"
            )

    # ── 6. Step efficiency ───────────────────────────────────────────────────
    ideal, warn_mild, warn_hard = STEP_BRACKETS.get(tier, (9, 18, 25))

    # Rush penalty: submitted verdict too quickly without enough investigation
    if steps < ideal and coverage_ratio < 0.5:
        score += PENALTY_RUSH
        breakdown["rush_penalty"] = PENALTY_RUSH
        deductions.append(
            f"Rush penalty: submitted in {steps} steps (ideal ≥ {ideal} for thorough "
            f"investigation) with only {groups_covered}/{n_groups} tool groups covered. "
            f"({PENALTY_RUSH:+.2f})"
        )

    if steps <= ideal:
        eff_score = W_EFFICIENCY
    elif steps <= warn_mild:
        eff_score = round(W_EFFICIENCY * 0.5, 4)
    elif steps <= warn_hard:
        eff_score = 0.0
    else:
        eff_score = -0.05      # excess steps
        deductions.append(
            f"Excess steps: {steps} steps on {tier} tier "
            f"(hard limit = {warn_hard}). ({eff_score:+.2f})"
        )

    score += eff_score
    breakdown["efficiency"] = eff_score
    if 0.0 < eff_score < W_EFFICIENCY:
        deductions.append(
            f"Step efficiency: {steps} steps on {tier} "
            f"(ideal ≤ {ideal}). Earned {eff_score:.2f}/{W_EFFICIENCY:.2f}."
        )

    # ── 7. Clamp and store ───────────────────────────────────────────────────
    breakdown["raw_score"] = round(score, 4)   # pre-clamp, can be negative
    score = max(0.0, min(1.0, round(score, 4)))
    breakdown["final_score"] = score

    return GraderResult(
        score=score,
        correct=correct,
        deductions=deductions,
        breakdown=breakdown,
    )
