"""
Unit tests for grader v4.0
"""
import pytest
from models import AttackType, DifficultyTier, LogTriageState, LogVerdict
from server.grader import (
    grade,
    W_VERDICT, W_TOOLS_MALICIOUS, W_TOOLS_BENIGN,
    W_ATTACK_TYPE, W_BACKUP_MALICIOUS, W_NO_BAD_BACKUP, W_EFFICIENCY,
    PENALTY_WRONG_VERDICT, PENALTY_NO_INVESTIGATION, PENALTY_RUSH,
    PENALTY_FALSE_BACKUP, PENALTY_BACKUP_WRONG_HOST,
    STEP_BRACKETS,
)


def _state(
    verdict: str | None = None,
    attack_type: str | None = None,
    expected_verdict: str = "malicious",
    expected_attack: str = "c2_beacon",
    step_count: int = 6,
    tier: str = "Easy",
    tools: list[str] | None = None,
    backup_hosts: list[str] | None = None,
    affected_hosts: list[str] | None = None,
) -> LogTriageState:
    return LogTriageState(
        episode_id="ep-test",
        incident_id="INC-TEST",
        alert_summary="Test incident",
        primary_host="HOST-A",
        affected_hosts=affected_hosts or ["HOST-A"],
        step_count=step_count,
        max_steps=20,
        expected_verdict=LogVerdict(expected_verdict),
        expected_attack_type=AttackType(expected_attack),
        difficulty_tier=DifficultyTier(tier),
        tools_used=tools or [],
        backup_triggered_hosts=backup_hosts or [],
        verdict_submitted=verdict is not None,
        final_verdict=LogVerdict(verdict) if verdict else None,
        final_attack_type=AttackType(attack_type) if attack_type else None,
        cumulative_reward=0.0,
    )


# ---------------------------------------------------------------------------
# Gate: no verdict
# ---------------------------------------------------------------------------

def test_no_verdict_scores_zero():
    r = grade(_state(verdict=None))
    assert r.score == 0.0
    assert r.correct is False


# ---------------------------------------------------------------------------
# Wrong verdict — PENALTY_WRONG_VERDICT applied, score clamped to 0
# ---------------------------------------------------------------------------

def test_wrong_verdict_lowers_score_significantly():
    """Wrong verdict = PENALTY_WRONG_VERDICT applied; score still above 0 if investigation was good."""
    r = grade(_state(verdict="benign", expected_verdict="malicious",
                     tools=["query_logs"], backup_hosts=["HOST-A"]))
    assert r.correct is False
    # Penalty is in breakdown
    assert r.breakdown.get("wrong_verdict_penalty") == PENALTY_WRONG_VERDICT
    # Score is much lower than a correct verdict would give
    r_correct = grade(_state(verdict="malicious", attack_type="c2_beacon",
                              tools=["query_logs"], backup_hosts=["HOST-A"]))
    assert r.score < r_correct.score


def test_wrong_verdict_shows_penalty_in_breakdown():
    r = grade(_state(verdict="benign", expected_verdict="malicious",
                     tools=["query_logs"], backup_hosts=["HOST-A"]))
    assert r.breakdown.get("wrong_verdict_penalty") == PENALTY_WRONG_VERDICT
    assert any("Wrong verdict" in d for d in r.deductions)


def test_wrong_verdict_raw_score_is_negative():
    """Raw score (pre-clamp) should be negative when wrong verdict is given."""
    r = grade(_state(verdict="benign", expected_verdict="malicious",
                     tools=[], backup_hosts=[]))
    # wrong_verdict_penalty (-0.25) + no_investigation_penalty (-0.20) = -0.45 raw
    raw = r.breakdown.get("raw_score", 0.0)
    assert raw < 0.0


# ---------------------------------------------------------------------------
# Verdict component
# ---------------------------------------------------------------------------

def test_verdict_component_awarded_correct():
    r = grade(_state(verdict="malicious", attack_type="c2_beacon",
                     tools=["query_logs"], backup_hosts=["HOST-A"]))
    assert r.breakdown.get("verdict") == W_VERDICT


def test_verdict_component_zero_on_wrong():
    r = grade(_state(verdict="malicious", expected_verdict="benign",
                     expected_attack="benign", tools=["query_logs"],
                     backup_hosts=[]))
    assert r.breakdown.get("verdict") == 0.0


# ---------------------------------------------------------------------------
# No investigation penalty
# ---------------------------------------------------------------------------

def test_no_tools_penalty_applied():
    """Zero investigation = −0.20 penalty on top of 0 tool score."""
    r = grade(_state(verdict="malicious", attack_type="c2_beacon",
                     tier="Easy", tools=[],   # no investigation tools
                     backup_hosts=["HOST-A"]))
    assert r.breakdown.get("no_investigation_penalty") == PENALTY_NO_INVESTIGATION
    assert any("No investigation" in d for d in r.deductions)


def test_partial_tools_no_no_investigation_penalty():
    """Partial coverage → proportional score, no no-investigation penalty."""
    r = grade(_state(verdict="malicious", attack_type="c2_beacon",
                     tier="Easy", tools=["query_logs"],
                     backup_hosts=["HOST-A"]))
    assert "no_investigation_penalty" not in r.breakdown


def test_no_tools_lowers_score():
    # With tools fully covered
    r_good = grade(_state(verdict="malicious", attack_type="c2_beacon",
                           tools=["query_logs", "analyze_process"],
                           backup_hosts=["HOST-A"]))
    # With no tools
    r_bad = grade(_state(verdict="malicious", attack_type="c2_beacon",
                          tools=[], backup_hosts=["HOST-A"]))
    assert r_bad.score < r_good.score


# ---------------------------------------------------------------------------
# Rush penalty
# ---------------------------------------------------------------------------

def test_rush_penalty_when_too_fast_with_low_coverage():
    """Steps < ideal AND coverage < 50% → rush penalty."""
    ideal = STEP_BRACKETS["Easy"][0]  # 6
    r = grade(_state(verdict="malicious", attack_type="c2_beacon",
                     tier="Easy",
                     step_count=ideal - 1,   # too fast
                     tools=[],               # 0% coverage
                     backup_hosts=["HOST-A"]))
    assert r.breakdown.get("rush_penalty") == PENALTY_RUSH
    assert any("Rush" in d for d in r.deductions)


def test_no_rush_penalty_with_good_coverage():
    """Good tool coverage even in few steps = no rush penalty."""
    ideal = STEP_BRACKETS["Easy"][0]
    r = grade(_state(verdict="malicious", attack_type="c2_beacon",
                     tier="Easy",
                     step_count=ideal - 1,
                     tools=["query_logs"],  # 100% easy group coverage
                     backup_hosts=["HOST-A"]))
    assert "rush_penalty" not in r.breakdown


def test_no_rush_penalty_with_normal_steps():
    """Enough steps → no rush penalty regardless of tool coverage."""
    ideal = STEP_BRACKETS["Easy"][0]
    r = grade(_state(verdict="malicious", attack_type="c2_beacon",
                     tier="Easy",
                     step_count=ideal,      # exactly ideal
                     tools=[],             # still no tools
                     backup_hosts=["HOST-A"]))
    assert "rush_penalty" not in r.breakdown


# ---------------------------------------------------------------------------
# Tool investigation proportional
# ---------------------------------------------------------------------------

def test_easy_full_tool_credit():
    r = grade(_state(verdict="malicious", attack_type="c2_beacon",
                     tier="Easy", tools=["query_logs"],
                     backup_hosts=["HOST-A"]))
    assert r.breakdown.get("tools") == W_TOOLS_MALICIOUS


def test_medium_partial_tool_credit():
    r = grade(_state(verdict="malicious", attack_type="persistence",
                     tier="Medium", step_count=9,
                     tools=["analyze_process"],      # 1 of 2 groups
                     backup_hosts=["HOST-A"]))
    assert r.breakdown.get("tools") == round(W_TOOLS_MALICIOUS * 0.5, 4)


def test_medium_full_tool_credit():
    r = grade(_state(verdict="malicious", attack_type="persistence",
                     tier="Medium", step_count=9,
                     tools=["analyze_process", "check_ip_reputation"],
                     backup_hosts=["HOST-A"]))
    assert r.breakdown.get("tools") == W_TOOLS_MALICIOUS


def test_benign_tools_higher_weight():
    r = grade(_state(verdict="benign", expected_verdict="benign",
                     expected_attack="benign", tier="Easy",
                     tools=["query_logs"], backup_hosts=[]))
    assert r.breakdown.get("tools") == W_TOOLS_BENIGN


# ---------------------------------------------------------------------------
# Attack type
# ---------------------------------------------------------------------------

def test_correct_attack_type():
    r = grade(_state(verdict="malicious", attack_type="c2_beacon",
                     expected_attack="c2_beacon",
                     tools=["query_logs"], backup_hosts=["HOST-A"]))
    assert r.breakdown.get("attack_type") == W_ATTACK_TYPE


def test_wrong_attack_type_zero():
    r = grade(_state(verdict="malicious", attack_type="ransomware",
                     expected_attack="c2_beacon",
                     tools=["query_logs"], backup_hosts=["HOST-A"]))
    assert r.breakdown.get("attack_type") == 0.0


def test_attack_type_not_in_benign():
    r = grade(_state(verdict="benign", expected_verdict="benign",
                     expected_attack="benign", tools=["query_logs"],
                     backup_hosts=[]))
    assert "attack_type" not in r.breakdown


# ---------------------------------------------------------------------------
# Backup handling
# ---------------------------------------------------------------------------

def test_malicious_backup_correct():
    r = grade(_state(verdict="malicious", attack_type="c2_beacon",
                     tools=["query_logs"], backup_hosts=["HOST-A"],
                     affected_hosts=["HOST-A"]))
    assert r.breakdown.get("backup") == W_BACKUP_MALICIOUS


def test_malicious_no_backup_zero():
    r = grade(_state(verdict="malicious", attack_type="c2_beacon",
                     tools=["query_logs"], backup_hosts=[],
                     affected_hosts=["HOST-A"]))
    assert r.breakdown.get("backup") == 0.0


def test_malicious_backup_wrong_host_penalty():
    r = grade(_state(verdict="malicious", attack_type="c2_beacon",
                     tools=["query_logs"], backup_hosts=["HOST-B"],
                     affected_hosts=["HOST-A"]))
    assert r.breakdown.get("backup_wrong_host_penalty") == PENALTY_BACKUP_WRONG_HOST


def test_benign_no_backup_full_credit():
    r = grade(_state(verdict="benign", expected_verdict="benign",
                     expected_attack="benign", tools=["query_logs"],
                     backup_hosts=[]))
    assert r.breakdown.get("backup") == W_NO_BAD_BACKUP


def test_benign_with_backup_penalty():
    r = grade(_state(verdict="benign", expected_verdict="benign",
                     expected_attack="benign", tools=["query_logs"],
                     backup_hosts=["HOST-A"]))
    assert r.breakdown.get("false_backup_penalty") == PENALTY_FALSE_BACKUP


# ---------------------------------------------------------------------------
# Step efficiency
# ---------------------------------------------------------------------------

def test_efficiency_ideal_full():
    ideal = STEP_BRACKETS["Easy"][0]
    r = grade(_state(verdict="malicious", attack_type="c2_beacon",
                     tier="Easy", step_count=ideal,
                     tools=["query_logs"], backup_hosts=["HOST-A"]))
    assert r.breakdown.get("efficiency") == W_EFFICIENCY


def test_efficiency_mild_half():
    mild = STEP_BRACKETS["Easy"][1]
    r = grade(_state(verdict="malicious", attack_type="c2_beacon",
                     tier="Easy", step_count=mild,
                     tools=["query_logs"], backup_hosts=["HOST-A"]))
    assert r.breakdown.get("efficiency") == round(W_EFFICIENCY * 0.5, 4)


def test_efficiency_hard_zero():
    hard = STEP_BRACKETS["Easy"][2]
    r = grade(_state(verdict="malicious", attack_type="c2_beacon",
                     tier="Easy", step_count=hard,
                     tools=["query_logs"], backup_hosts=["HOST-A"]))
    assert r.breakdown.get("efficiency") == 0.0


def test_efficiency_excess_negative():
    r = grade(_state(verdict="malicious", attack_type="c2_beacon",
                     tier="Easy", step_count=19,
                     tools=["query_logs"], backup_hosts=["HOST-A"]))
    assert r.breakdown.get("efficiency") == -0.05


# ---------------------------------------------------------------------------
# Score bounds and raw_score
# ---------------------------------------------------------------------------

def test_score_never_below_zero():
    r = grade(_state(verdict="benign", expected_verdict="malicious",
                     tools=[], backup_hosts=["HOST-B"],
                     affected_hosts=["HOST-A"], step_count=19, tier="Hard"))
    assert r.score >= 0.0


def test_score_never_above_one():
    r = grade(_state(verdict="malicious", attack_type="c2_beacon",
                     tools=["query_logs", "analyze_process"],
                     backup_hosts=["HOST-A"], step_count=2))
    assert r.score <= 1.0


def test_raw_score_can_be_negative():
    """raw_score (pre-clamp) is stored so UI can show negatives."""
    r = grade(_state(verdict="benign", expected_verdict="malicious",
                     tools=[], backup_hosts=[]))
    assert "raw_score" in r.breakdown
    assert r.breakdown["raw_score"] < 0.0


# ---------------------------------------------------------------------------
# Perfect score = exactly 1.0
# ---------------------------------------------------------------------------

def test_perfect_malicious_score():
    """0.30+0.25+0.20+0.15+0.10 = 1.00"""
    ideal = STEP_BRACKETS["Easy"][0]
    r = grade(_state(
        verdict="malicious", attack_type="c2_beacon",
        expected_verdict="malicious", expected_attack="c2_beacon",
        tier="Easy", step_count=ideal,
        tools=["query_logs"],
        backup_hosts=["HOST-A"], affected_hosts=["HOST-A"],
    ))
    assert r.score == 1.0
    assert r.correct is True
    assert r.deductions == []


def test_perfect_benign_score():
    """0.30+0.35+0.25+0.10 = 1.00"""
    ideal = STEP_BRACKETS["Easy"][0]
    r = grade(_state(
        verdict="benign", expected_verdict="benign", expected_attack="benign",
        tier="Easy", step_count=ideal,
        tools=["query_logs"],
        backup_hosts=[],
    ))
    assert r.score == 1.0
    assert r.correct is True
    assert r.deductions == []


def test_grader_result_to_dict():
    r = grade(_state(verdict="malicious", attack_type="c2_beacon",
                     tools=["query_logs"], backup_hosts=["HOST-A"]))
    d = r.to_dict()
    assert "score" in d and "correct" in d
    assert "breakdown" in d and "deductions" in d
    assert 0.0 <= d["score"] <= 1.0
