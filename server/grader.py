"""
This is the grader — it looks at a finished episode and spits out a score between 0.0 and 1.0.

The whole point is to reward agents that actually *investigate* before guessing,
not just ones that happened to get lucky. Here's the logic:

1. If the verdict is wrong (or never submitted), score is 0.0. Full stop.

2. Start at 1.0 if the verdict was correct.

3. Two kinds of deductions can bring that down:

   a) Investigation shortcut penalty
      If you got the right answer on Medium/Hard but never called the tools
      that would've let you *know* it was right, that's suspicious. You probably
      just guessed. We knock off 0.5 for that.

      What each tier actually requires you to check:
        Easy   → sandbox_url or lookup_threat_intel (there's an obvious URL, use it)
        Medium → analyze_headers (the whole trick is in the headers)
        Hard   → analyze_headers + sandbox_url or lookup_threat_intel (need both angles)

   b) Too many steps penalty
      A good analyst doesn't spend 10 steps on a 2-step problem. We deduct
      if you burn through more steps than needed:

        tier   optimal   first warning   hard cap
        Easy      2           6              9
        Medium    2           6              9
        Hard      4           8             12

4. Score can never go below 0.0.
"""

from __future__ import annotations

from models import DifficultyTier, Verdict, TriageState

# ---------------------------------------------------------------------------
# What tools each tier actually requires you to have used
# ---------------------------------------------------------------------------

# If you skipped these, you were probably guessing. Don't guess.
REQUIRED_TOOLS: dict[str, frozenset[str]] = {
    "Easy": frozenset({"sandbox_url", "lookup_threat_intel"}),
    "Medium": frozenset({"analyze_headers"}),
    "Hard": frozenset({"analyze_headers"}),      # plus a URL tool — see check below
}

# Hard tier also needs at least one URL-side tool on top of headers
_HARD_URL_TOOLS: frozenset[str] = frozenset({"sandbox_url", "lookup_threat_intel"})

# Step count brackets per tier: (ideal, first_warning, second_warning)
# Going over the first threshold docks -0.1, going over both docks -0.2 total
STEP_BRACKETS: dict[str, tuple[int, int, int]] = {
    "Easy":   (2, 5, 8),
    "Medium": (2, 5, 8),
    "Hard":   (4, 7, 11),
}

# How much we dock for each type of infraction
PENALTY_NO_INVESTIGATION  = -0.5
PENALTY_EXCESS_STEPS_MILD = -0.1
PENALTY_EXCESS_STEPS_HARD = -0.1   # stacks on top if you hit both thresholds


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class GraderResult:
    """
    Everything the grader knows about a finished episode, packaged up nicely.
    score is the final number. deductions tells you what hurt it. breakdown
    gives the raw math. correct is just a quick yes/no at the top.
    """

    def __init__(
        self,
        score: float,
        correct: bool,
        deductions: list[str],
        breakdown: dict[str, float],
    ) -> None:
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


def grade(state: TriageState) -> GraderResult:
    """
    Takes the episode state after it ends and returns a score.
    This is called by GET /grader. The state object has everything
    we need: what verdict was submitted, what tools were used, how many steps.
    """
    deductions: list[str] = []
    breakdown: dict[str, float] = {}

    # ── 1. Correctness gate ──────────────────────────────────────────────────
    if not state.verdict_submitted or state.final_verdict is None:
        return GraderResult(
            score=0.0,
            correct=False,
            deductions=["No verdict submitted — episode incomplete."],
            breakdown={"base": 0.0},
        )

    # did the model actually get it right?
    agent_phishing  = (state.final_verdict.value == "phishing")
    correct         = (agent_phishing == state.expected_verdict)

    if not correct:
        return GraderResult(
            score=0.0,
            correct=False,
            deductions=[
                f"Wrong verdict (predicted={'phishing' if agent_phishing else 'benign'}, "
                f"expected={'phishing' if state.expected_verdict else 'benign'})."
            ],
            breakdown={"base": 0.0},
        )

    # ── 2. Base score ────────────────────────────────────────────────────────
    score = 1.0
    breakdown["base"] = 1.0

    # Determine tier name (fallback to Hard for unknown)
    tier = state.difficulty_tier.value if state.difficulty_tier else "Hard"
    tools_used: frozenset[str] = frozenset(state.tools_used or [])

    # ── 3a. Investigation penalty ────────────────────────────────────────────
    investigation_penalty = _check_investigation(tier, tools_used)
    if investigation_penalty < 0.0:
        label = f"Investigation short-cut on {tier} tier (no required tools called)."
        deductions.append(label)
        breakdown["investigation_penalty"] = investigation_penalty
        score += investigation_penalty

    # ── 3b. Efficiency / step-count penalty ──────────────────────────────────
    step_penalty = _check_steps(tier, state.step_count)
    if step_penalty < 0.0:
        deductions.append(
            f"Excessive steps: {state.step_count} steps on a {tier} task "
            f"(optimal ≤ {STEP_BRACKETS.get(tier, (4, 7, 11))[0]})."
        )
        breakdown["step_penalty"] = step_penalty
        score += step_penalty

    # ── 4. Floor ─────────────────────────────────────────────────────────────
    score = max(0.0, round(score, 4))

    return GraderResult(
        score=score,
        correct=True,
        deductions=deductions,
        breakdown=breakdown,
    )


# ---------------------------------------------------------------------------
# Helper functions — keep grade() readable
# ---------------------------------------------------------------------------

def _check_investigation(tier: str, tools_used: frozenset[str]) -> float:
    """
    Returns how much to dock for skipping investigation tools.
    Returns 0.0 if the agent did the right thing.
    """
    if tier == "Easy":
        # on Easy the malicious URL is right there — just run sandbox or threat intel
        if not (tools_used & REQUIRED_TOOLS["Easy"]):
            return PENALTY_NO_INVESTIGATION
        return 0.0

    if tier == "Medium":
        # the whole signal on Medium is broken auth headers — you have to check them
        if "analyze_headers" not in tools_used:
            return PENALTY_NO_INVESTIGATION
        return 0.0

    if tier == "Hard":
        # Hard needs both: the header check AND a URL tool to cover both attack surfaces
        has_headers   = "analyze_headers" in tools_used
        has_url_tool  = bool(tools_used & _HARD_URL_TOOLS)
        if not (has_headers and has_url_tool):
            return PENALTY_NO_INVESTIGATION
        return 0.0

    return 0.0    # unknown tier — no penalty


def _check_steps(tier: str, step_count: int) -> float:
    """
    Returns how much to dock for taking too long.
    Two thresholds — hit the first and lose 0.1, hit both and lose 0.2.
    """
    _, warn_at, hard_at = STEP_BRACKETS.get(tier, (4, 7, 11))
    penalty = 0.0
    if step_count > hard_at:
        penalty += PENALTY_EXCESS_STEPS_HARD   # hit the second threshold too
    if step_count > warn_at:
        penalty += PENALTY_EXCESS_STEPS_MILD   # always included if you hit either
    return penalty
