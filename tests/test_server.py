"""
Integration tests for the SOC Log Triage Environment API endpoints.
All tests use FastAPI TestClient (no live server needed).
"""
import pytest
from fastapi.testclient import TestClient

from server.app import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "soc-log-triage-env" in data["environment"]


# ---------------------------------------------------------------------------
# /reset
# ---------------------------------------------------------------------------

def test_reset_returns_incident_metadata():
    resp = client.post("/reset")
    assert resp.status_code == 200
    obs = resp.json()
    assert "incident_id" in obs
    assert "alert_summary" in obs
    assert "primary_host" in obs
    assert obs["host_count"] >= 1
    assert obs["log_count"] > 0
    assert obs["step_number"] == 0
    assert obs["max_steps"] > 0
    assert isinstance(obs["initial_logs"], list)
    # All logs are returned now (no cap) — count must match log_count field
    assert len(obs["initial_logs"]) == obs["log_count"]


def test_reset_tier_filter_easy():
    resp = client.post("/reset?tier_filter=Easy")
    assert resp.status_code == 200


def test_reset_tier_filter_medium():
    resp = client.post("/reset?tier_filter=Medium")
    assert resp.status_code == 200


def test_reset_tier_filter_hard():
    resp = client.post("/reset?tier_filter=Hard")
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /step — tool calls
# ---------------------------------------------------------------------------

def test_step_query_logs():
    client.post("/reset")
    resp = client.post("/step", json={
        "command": "query_logs",
        "params": {"query": "powershell"},
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "observation" in data
    assert "reward" in data
    assert data["done"] is False


def test_step_get_host_summary():
    client.post("/reset")
    # First get the primary_host from reset
    obs_resp = client.post("/reset")
    primary = obs_resp.json()["primary_host"]

    resp = client.post("/step", json={
        "command": "get_host_summary",
        "params": {"host": primary},
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["observation"]["tool_used"] == "get_host_summary"


def test_step_analyze_process():
    client.post("/reset")
    resp = client.post("/step", json={
        "command": "analyze_process",
        "params": {"process_name": "powershell"},
    })
    assert resp.status_code == 200


def test_step_check_ip_reputation():
    client.post("/reset")
    resp = client.post("/step", json={
        "command": "check_ip_reputation",
        "params": {"ip": "185.220.101.45"},
    })
    assert resp.status_code == 200
    data = resp.json()
    tool_result = data["observation"]["tool_result"]
    assert tool_result is not None
    assert "reputation_score" in tool_result


def test_step_check_file_hash():
    client.post("/reset")
    resp = client.post("/step", json={
        "command": "check_file_hash",
        "params": {"hash": "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
    })
    assert resp.status_code == 200


def test_step_trigger_backup():
    obs_resp = client.post("/reset")
    primary = obs_resp.json()["primary_host"]
    resp = client.post("/step", json={
        "command": "trigger_backup",
        "params": {"host": primary},
    })
    assert resp.status_code == 200
    data = resp.json()
    obs = data["observation"]
    assert primary in obs["backup_triggered_hosts"]


# ---------------------------------------------------------------------------
# /step — invalid actions
# ---------------------------------------------------------------------------

def test_step_invalid_command_rejected():
    client.post("/reset")
    resp = client.post("/step", json={"command": "hack_the_planet", "params": {}})
    assert resp.status_code == 422   # Pydantic validation error


def test_step_missing_required_param():
    client.post("/reset")
    resp = client.post("/step", json={
        "command": "query_logs",
        "params": {},  # missing 'query'
    })
    assert resp.status_code == 422


def test_step_invalid_verdict():
    client.post("/reset")
    resp = client.post("/step", json={
        "command": "submit_verdict",
        "params": {"verdict": "destroy_everything"},
    })
    assert resp.status_code == 200  # env catches it, returns error_message
    data = resp.json()
    assert data["observation"]["success"] is False
    assert data["done"] is False


# ---------------------------------------------------------------------------
# /state
# ---------------------------------------------------------------------------

def test_state_before_reset():
    # Fresh client — no episode
    from fastapi.testclient import TestClient
    from server.app import app as fresh_app
    import server.app as app_module
    app_module._ENV = None
    c = TestClient(fresh_app)
    resp = c.get("/state")
    assert resp.status_code == 400


def test_state_after_reset():
    client.post("/reset")
    resp = client.get("/state")
    assert resp.status_code == 200
    st = resp.json()
    assert "incident_id" in st
    assert "expected_verdict" in st
    assert "expected_attack_type" in st
    assert st["step_count"] == 0


# ---------------------------------------------------------------------------
# /grader
# ---------------------------------------------------------------------------

def test_grader_before_verdict():
    client.post("/reset")
    resp = client.get("/grader")
    assert resp.status_code == 200
    data = resp.json()
    assert data["score"] == 0.0
    assert data["correct"] is False


def test_grader_score_in_range():
    client.post("/reset?tier_filter=Easy")
    resp = client.get("/grader")
    assert resp.status_code == 200
    score = resp.json()["score"]
    assert 0.0 <= score <= 1.0


# ---------------------------------------------------------------------------
# /tasks
# ---------------------------------------------------------------------------

def test_tasks_structure():
    resp = client.get("/tasks")
    assert resp.status_code == 200
    data = resp.json()
    tasks = data["tasks"]
    assert len(tasks) == 3
    tiers = {t["tier"] for t in tasks}
    assert tiers == {"Easy", "Medium", "Hard"}


def test_tasks_attack_types():
    resp = client.get("/tasks")
    data = resp.json()
    attack_types = data["attack_types"]
    assert "c2_beacon" in attack_types
    assert "ransomware" in attack_types
    assert "lateral_movement" in attack_types
    assert "persistence" in attack_types
    assert "data_exfil" in attack_types


def test_tasks_action_schema():
    resp = client.get("/tasks")
    data = resp.json()
    assert "action_schema" in data
    schema = data["action_schema"]
    assert "properties" in schema


# ---------------------------------------------------------------------------
# Full episode cycle
# ---------------------------------------------------------------------------

def test_full_easy_episode():
    """Complete Easy episode: reset → tool call → backup → verdict → grader."""
    obs_resp = client.post("/reset?tier_filter=Easy")
    obs = obs_resp.json()
    primary = obs["primary_host"]

    # Tool call
    client.post("/step", json={
        "command": "query_logs",
        "params": {"query": "powershell"},
    })

    # Trigger backup
    client.post("/step", json={
        "command": "trigger_backup",
        "params": {"host": primary},
    })

    # Submit verdict
    verdict_resp = client.post("/step", json={
        "command": "submit_verdict",
        "params": {
            "verdict": "malicious",
            "attack_type": "c2_beacon",
            "affected_hosts": [primary],
        },
    })
    data = verdict_resp.json()
    assert data["done"] is True
    assert data["reward"] is not None

    # Grader
    grade_resp = client.get("/grader")
    assert grade_resp.status_code == 200
    gdata = grade_resp.json()
    assert 0.0 <= gdata["score"] <= 1.0
    assert "expected_verdict" in gdata
    assert "expected_attack_type" in gdata
