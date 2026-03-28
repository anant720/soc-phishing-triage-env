"""
Tests for the /tasks endpoint and the grader — both the HTTP API and the
grade() function directly. This is where I verify the scoring rules are
actually working the way we designed them.
"""
import pytest
from fastapi.testclient import TestClient
from server.app import app
from server.grader import grade, GraderResult
from models import TriageState, DifficultyTier, Verdict

client = TestClient(app)


# ---------------------------------------------------------------------------
# /tasks endpoint
# ---------------------------------------------------------------------------

def test_tasks_structure():
    resp = client.get("/tasks")
    assert resp.status_code == 200
    data = resp.json()

    # the expected top-level keys
    assert "tasks" in data
    assert "action_schema" in data
    assert "verdict_values" in data
    assert "max_steps" in data
    assert data["max_steps"] > 0

    # we have exactly three difficulty levels
    tiers = {t["tier"] for t in data["tasks"]}
    assert tiers == {"Easy", "Medium", "Hard"}


def test_tasks_action_schema():
    resp = client.get("/tasks")
    schema = resp.json()["action_schema"]

    # the schema should expose both field names
    assert "properties" in schema
    props = schema["properties"]
    # canonical field names from TriageAction
    assert "command" in props
    assert "params" in props


def test_tasks_verdict_values():
    resp = client.get("/tasks")
    verdicts = resp.json()["verdict_values"]
    assert set(verdicts) >= {"phishing", "benign"}


def test_tasks_required_tools_per_tier():
    resp = client.get("/tasks")
    tasks = {t["tier"]: t for t in resp.json()["tasks"]}

    assert "analyze_headers" in tasks["Medium"]["required_tools"]
    assert "analyze_headers" in tasks["Hard"]["required_tools"]
    assert any(t in tasks["Easy"]["required_tools"]
               for t in ("sandbox_url", "lookup_threat_intel"))


# ===========================================================================
# GET /grader
# ===========================================================================

def test_grader_no_episode_in_progress():
    """Grader should still return even before an episode — wraps state() error."""
    # /grader calls _ENV.state() which may raise RuntimeError if no episode
    resp = client.get("/grader")
    # Either 200 (episode already active from previous test) or 400 (no episode)
    assert resp.status_code in (200, 400)


def test_grader_before_verdict():
    """Grader called immediately after reset (no verdict) should return score=0."""
    client.post("/reset")
    resp = client.get("/grader")
    assert resp.status_code == 200
    data = resp.json()
    assert data["score"] == 0.0
    assert data["correct"] is False
    assert any("No verdict" in d for d in data["deductions"])


def test_grader_wrong_verdict():
    """Wrong verdict must score 0.0."""
    obs = client.post("/reset").json()
    # submit opposite of expected (infer from email text heuristic)
    # We just submit a specific wrong verdict pattern by forcing a verdic then
    # using the grader's expected_verdict field from state
    state = client.get("/state").json()
    expected_phishing = state["expected_verdict"]
    wrong = "benign" if expected_phishing else "phishing"

    client.post("/step", json={"command": "submit_verdict", "params": {"verdict": wrong}})

    resp = client.get("/grader")
    assert resp.status_code == 200
    data = resp.json()
    assert data["score"] == 0.0
    assert data["correct"] is False


def test_grader_correct_verdict_with_tools():
    """Correct verdict + required tools used on Easy tier should score 1.0."""
    # Force Easy tier test environment
    from server.environment import SocTriageEnvironment
    from server.grader import grade
    from models import TriageAction

    env = SocTriageEnvironment(max_steps=10, tier_filter="Easy")
    obs = env.reset()
    email_id = obs.email_id

    # Use a URL tool (satisfies Easy requirement)
    env.step(TriageAction(command="sandbox_url", params={"url": "https://test.com"}))

    state = env.state()
    is_phishing = state.expected_verdict
    verdict = "phishing" if is_phishing else "benign"
    env.step(TriageAction(command="submit_verdict", params={"verdict": verdict}))

    state = env.state()
    result = grade(state)

    assert result.correct is True
    assert result.score == 1.0, f"Expected 1.0 but got {result.score}; deductions: {result.deductions}"
    env.close()


def test_grader_investigation_penalty_medium():
    """Guessing on Medium without analyze_headers should subtract 0.5."""
    from server.environment import SocTriageEnvironment
    from server.grader import grade
    from models import TriageAction

    env = SocTriageEnvironment(max_steps=10, tier_filter="Medium")
    env.reset()

    state = env.state()
    is_phishing = state.expected_verdict
    verdict = "phishing" if is_phishing else "benign"
    # Submit WITHOUT calling analyze_headers
    env.step(TriageAction(command="submit_verdict", params={"verdict": verdict}))

    state = env.state()
    result = grade(state)

    assert result.correct is True
    # Should have the investigation penalty
    assert result.score == pytest.approx(0.5)
    assert any("Investigation" in d for d in result.deductions)
    env.close()


def test_grader_score_bounded_at_zero():
    """Score must never go below 0.0."""
    from server.environment import SocTriageEnvironment
    from server.grader import grade
    from models import TriageAction

    env = SocTriageEnvironment(max_steps=30, tier_filter="Hard")
    env.reset()

    state = env.state()
    is_phishing = state.expected_verdict
    verdict = "phishing" if is_phishing else "benign"
    # Correct verdict, many steps, no required tools — max penalties applied
    for _ in range(12):  # exceed hard_at bracket
        env.step(TriageAction(command="analyze_headers",
                              params={"email_id": state.current_email_id}))
    env.step(TriageAction(command="submit_verdict", params={"verdict": verdict}))

    result = grade(env.state())
    assert result.score >= 0.0
    env.close()


def test_grader_response_is_strict_float():
    """The score field must be a strict float, not int."""
    obs = client.post("/reset").json()
    state_before = client.get("/state").json()
    expected = state_before["expected_verdict"]
    verdict = "phishing" if expected else "benign"

    client.post("/step", json={"command": "sandbox_url",
                                "params": {"url": "https://test.org"}})
    client.post("/step", json={"command": "submit_verdict",
                                "params": {"verdict": verdict}})

    resp = client.get("/grader")
    data = resp.json()
    # Must deserialise as float
    assert isinstance(data["score"], float)
    assert 0.0 <= data["score"] <= 1.0


def test_grader_full_response_schema():
    """Verify GraderResponse schema: all expected keys present."""
    client.post("/reset")
    client.post("/step", json={"command": "submit_verdict",
                                "params": {"verdict": "phishing"}})
    resp = client.get("/grader")
    data = resp.json()

    required_keys = {"score", "correct", "deductions", "breakdown",
                     "episode_id", "tier", "step_count", "tools_used"}
    assert required_keys.issubset(data.keys())
