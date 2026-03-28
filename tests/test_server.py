"""
End-to-end tests for every endpoint in the server.
I test both the new (command/params) and old (tool/parameters) API shapes
because we promised backwards compatibility and I want to make sure we didn't break it.
"""
import pytest
from fastapi.testclient import TestClient
from server.app import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == "0.1.0"


def test_reset_returns_email_metadata():
    resp = client.post("/reset")
    assert resp.status_code == 200
    obs = resp.json()
    assert "email_id" in obs
    assert "email_subject" in obs
    assert obs["step_number"] == 0
    assert obs["success"] is True
    assert obs["error_message"] is None
    assert obs["tools_used"] == []


def test_step_new_api():
    """Use the current API shape (command + params) and make sure it works end to end."""
    client.post("/reset")
    obs = client.post("/reset").json()
    email_id = obs["email_id"]

    # call a tool using the canonical API
    resp = client.post("/step", json={
        "command": "analyze_headers",
        "params": {"email_id": email_id}
    })
    assert resp.status_code == 200
    result = resp.json()
    # normal tool call = step penalty (-0.05) + tool success (+0.1) = +0.05
    # but if the email was Hard-tier with dynamic spoofing we also get the +0.2 verifier bonus
    assert result["reward"] == pytest.approx(0.05) or result["reward"] == pytest.approx(0.25), \
        f"Unexpected tool reward: {result['reward']}"
    assert result["done"] is False
    assert result["observation"]["success"] is True
    assert result["observation"]["tool_used"] == "analyze_headers"
    assert result["observation"]["tool_result"] is not None
    assert "analyze_headers" in result["observation"]["tools_used"]


def test_step_legacy_api():
    """Old API shape (tool + parameters) should still work — we support both."""
    client.post("/reset")
    obs = client.post("/reset").json()
    email_id = obs["email_id"]

    # same tool call but using the old key names
    resp = client.post("/step", json={
        "tool": "analyze_headers",
        "parameters": {"email_id": email_id}
    })
    assert resp.status_code == 200
    result = resp.json()
    assert result["observation"]["success"] is True
    assert result["observation"]["tool_result"] is not None


def test_step_submit_verdict():
    """Submit a verdict and check the episode actually ends and the label is revealed."""
    client.post("/reset")

    resp = client.post("/step", json={
        "command": "submit_verdict",
        "params": {"verdict": "phishing"}
    })
    assert resp.status_code == 200
    result = resp.json()
    assert result["done"] is True
    assert result["observation"]["verdict_submitted"] is True
    assert result["observation"]["final_verdict"] == "phishing"
    assert result["observation"]["correct_label"] is not None


def test_step_invalid_command_rejected():
    """If the model hallucinates a tool name, the API should reject it immediately."""
    client.post("/reset")
    resp = client.post("/step", json={
        "command": "hack_the_planet",
        "params": {}
    })
    assert resp.status_code == 422  # Pydantic validation error, not a crash


def test_step_missing_param_rejected():
    """Calling sandbox_url without a URL should fail validation, not crash the environment."""
    client.post("/reset")
    resp = client.post("/step", json={
        "command": "sandbox_url",
        "params": {}   # forgot the url
    })
    assert resp.status_code == 422


def test_state():
    """GET /state should have everything the grader needs to score the episode."""
    client.post("/reset")
    resp = client.get("/state")
    assert resp.status_code == 200
    state = resp.json()
    assert "step_count" in state
    assert "expected_verdict" in state
    assert "tools_used" in state
    assert isinstance(state["tools_used"], list)
    assert isinstance(state["expected_verdict"], bool)


def test_full_episode_cycle():
    """Full loop: reset → call a tool → submit verdict → check state updated correctly."""
    # start fresh
    obs = client.post("/reset").json()
    email_id = obs["email_id"]
    assert obs["step_number"] == 0

    # run a tool
    r1 = client.post("/step", json={
        "command": "analyze_headers",
        "params": {"email_id": email_id}
    }).json()
    assert r1["observation"]["tool_result"] is not None

    # submit a verdict to end the episode
    r2 = client.post("/step", json={
        "command": "submit_verdict",
        "params": {"verdict": "benign"}
    }).json()
    assert r2["done"] is True

    # check the state reflects what just happened
    state = client.get("/state").json()
    assert state["verdict_submitted"] is True
    assert len(state["tools_used"]) >= 1
