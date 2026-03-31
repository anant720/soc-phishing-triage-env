---
title: Autonomous SOC Endpoint Log Triage (OpenEnv)
emoji: 🔍
colorFrom: red
colorTo: yellow
sdk: docker
pinned: true
tags:
  - openenv
  - reinforcement-learning
  - cybersecurity
  - siem
  - endpoint-security
---

# 🔍 Autonomous SOC Endpoint Log Triage

[![OpenEnv](https://img.shields.io/badge/OpenEnv-2.0.0-blue)](https://github.com/huggingface/openenv)
[![Python](https://img.shields.io/badge/Python-3.11-green)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-56%2F56%20passing-brightgreen)](#testing)
[![openenv validate](https://img.shields.io/badge/openenv_validate-✅_passing-brightgreen)](#openenv-validation)

> An **OpenEnv-compliant** reinforcement learning environment where an AI agent acts as a
> real Tier-1 SOC analyst. The agent investigates **Windows Sysmon endpoint log bundles**
> (50–200 logs per incident), identifies threats by attack type, triggers emergency backups
> on compromised hosts, and submits a classified verdict — scored 0.0–1.0 by a deterministic grader.

Built for the **Meta × Hugging Face OpenEnv Hackathon**.

---

## 🎯 Why This Environment

Most threat-detection benchmarks give you labeled log samples to classify. That is not how
SOC analysts actually work.

This environment simulates the **real Tier-1 triage workflow**:

1. A SIEM alert fires → the agent receives a bundle of correlated Windows endpoint logs
2. The agent **investigates** using security tools (query logs, analyze processes, check IPs, check file hashes)
3. If malicious, the agent **triggers a backup** on compromised host(s) before ransomware can encrypt data
4. The agent submits a **verdict** (`malicious` / `benign`) with an **attack type classification**
5. Score is based on correctness + attack classification + backup + investigation depth + efficiency

The domain is real: security operations centers process millions of alerts daily with severe
under-staffing. Training agents to perform Tier-1 triage is commercially valuable and
immediately deployable.

---

## 📁 Project Structure

```text
soc-log-triage-env/
├── openenv.yaml           # OpenEnv deployment manifest
├── pyproject.toml         # Package config & dependencies
├── Dockerfile             # Container (FastAPI on 7860; set GRADIO_DEMO=1 for UI)
├── README.md
│
├── models.py              # All Pydantic v2 schemas (Action, Observation, State)
├── client.py              # HTTP client helper for agent code
├── inference.py           # Baseline ReAct agent (OpenAI API-compatible)
├── train.py               # In-context RL training loop (ICPG)
│
├── data/
│   └── triage_scenarios.db# SQLite: 340 pre-generated incidents, 53,645 Sysmon log rows
│
├── server/
│   ├── app.py             # FastAPI routes (reset/step/state/grader/tasks/health)
│   ├── environment.py     # Core episode logic + reward shaping
│   ├── grader.py          # Deterministic scorer (v4, component-based)
│   ├── tools.py           # 6 log-analysis tools + submit_verdict
│   └── requirements.txt
│
└── tests/
    ├── test_server.py     # 34 endpoint integration tests
    └── test_grader.py     # 22 grader unit tests
```

---

## 🗄️ Dataset

**53,645 Windows Sysmon log events** across **340 incident bundles**:

| Tier | Incidents | Logs/Incident | Benign | Malicious |
|------|----------:|:---:|-------:|----------:|
| Easy | 85 | ~50 | 40 | 45 |
| Medium | 120 | ~100 | 45 | 75 |
| Hard | 135 | ~200 | 40 | 95 |

Attack types: `c2_beacon` · `ransomware` · `lateral_movement` · `persistence` · `data_exfil`

Log fields: `timestamp`, `host_id`, `event_type`, `process`, `commandline`,
`target_domain`, `target_ip`, `details` (EventID + Severity JSON)

---

## 🎯 Three Difficulty Tiers

### 🟢 Easy — Obvious C2 Beacon or Persistence
**~50 logs · 1 host · max_steps=20 · ideal_steps=6**

PowerShell with `-EncodedCommand` beaconing to a C2 domain, or a registry `Run` key written
by a suspicious process. Signal is detectable from `query_logs` alone.

### 🟡 Medium — Registry Persistence + IP Exfil
**~100 logs · 1–2 hosts · max_steps=28 · ideal_steps=9**

Attacker wrote to `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, exfiltrated via
`curl`/`rclone`. Agent must correlate the process tree with IP reputation. Requires 2+ tool
groups for full credit.

### 🔴 Hard — Multi-Host Lateral Movement / Ransomware / LOLBins
**~200 logs · 2–4 hosts · max_steps=40 · ideal_steps=14**

Attacker uses living-off-the-land binaries (`wmic`, `mshta`, `regsvr32`, `certutil`) or
ransomware kill-chain (`vssadmin delete shadows`, `bcdedit /set recoveryenabled No`,
`wbadmin delete catalog`). No obvious malware name. Agent must correlate process trees across
hosts, check IP/hash IOCs, trigger a backup _before_ submitting verdict.

---

## 🔧 Action Space (7 tools)

| Tool | Key Parameter | Returns |
|------|--------------|---------|
| `query_logs` | `query: str` | Keyword search over all bundle logs |
| `analyze_process` | `process_name: str` | Process tree with parent/child chain |
| `check_ip_reputation` | `ip: str` | Reputation score 0.0–1.0, malware family |
| `check_file_hash` | `hash: str` | IOC match, malware family, severity |
| `get_host_summary` | `host: str` | All processes, IPs, domains on a host |
| `trigger_backup` | `host: str` | Emergency snapshot (required for malicious verdict) |
| `submit_verdict` | `verdict, attack_type, affected_hosts` | Ends episode |

All actions encoded as JSON: `{"command": "<tool>", "params": {...}}`

---

## 📊 Observation Space

```json
{
  "incident_id":             "INC-A1B2C3D4",
  "alert_summary":           "Suspicious PowerShell encoded beacon on DESKTOP-X9Y8Z7",
  "primary_host":            "DESKTOP-X9Y8Z7",
  "host_count":              1,
  "log_count":               52,
  "initial_logs":            [...],
  "tool_used":               "query_logs",
  "tool_result":             {...},
  "step_number":             2,
  "max_steps":               20,
  "available_tools":         ["query_logs", "analyze_process", ...],
  "tools_used":              ["query_logs"],
  "backup_triggered_hosts":  [],
  "verdict_submitted":       false,
  "success":                 true,
  "error_message":           null
}
```

---

## 🎖️ Reward Design

### Per-Step Training Signal (shapes trajectory)

| Event | Reward |
|-------|:------:|
| Correct final verdict | **+1.00** |
| Wrong verdict | **−1.00** |
| Escalate on clear case | −0.20 |
| Each unique tool call (new) | +0.05 |
| Tool/schema error | −0.05 |
| Per-step penalty (anti-loop) | −0.02 |
| Episode timeout | −0.30 |

### Grader Score (final 0.0–1.0)

Component-based — each contributes proportionally, total = 1.0 for a perfect episode:

| Component | Malicious | Benign |
|-----------|:---------:|:------:|
| Correct verdict | 0.30 | 0.30 |
| Investigation tools | 0.25 | 0.35 |
| Attack type correct | 0.20 | — |
| Backup on correct host | 0.15 | — |
| No false backup | — | 0.25 |
| Step efficiency | 0.10 | 0.10 |

Penalties (pre-clamp, can take score negative, clamped to [0, 1]):

| Penalty | Amount |
|---------|:------:|
| Wrong verdict | −0.25 |
| Zero investigation (no tools) | −0.20 |
| Rush verdict (fast + no tools) | −0.10 |
| Backup on benign (false positive) | −0.10 |
| Backup on wrong host | −0.08 |
| Steps beyond hard limit | −0.05 |

---

## 🚀 Quick Start

```bash
git clone <repo-url> && cd soc-log-triage-env

# Start the environment server (FastAPI, port 7860)
PYTHONPATH=. uvicorn server.app:app --host 0.0.0.0 --port 7860
```

### 🎨 Running the Interactive UI

To protect `openenv validate` compatibility, this environment serves the raw REST API by default. We have also built a beautiful **fully-featured Gradio frontend** for humans to watch the agent work in real-time. 

To launch the UI locally:
```bash
PYTHONPATH=. python gradio_demo.py
# → http://localhost:7860
```

To launch the UI via Docker:
```bash
docker build -t soc-env .
docker run -p 7860:7860 -e GRADIO_DEMO=1 soc-env
```


### Environment Variables

| Variable | Required | Description |
|----------|:--------:|-------------|
| `OPENAI_API_KEY` | ✅ | API key (OpenAI, Groq, Together, or any compatible) |
| `API_BASE_URL` | ○ | API endpoint (default: OpenAI; Groq: `https://api.groq.com/openai/v1`) |
| `MODEL_NAME` | ○ | Model name (default: `gpt-4o-mini`) |
| `HF_TOKEN` | ○ | Alternative API key (fallback if OPENAI_API_KEY not set) |
| `SOC_SERVER_URL` | ○ | Environment server URL (default: `http://localhost:7860`) |

### Run Baseline Agent

```bash
export OPENAI_API_KEY=sk-...          # or Groq key
export API_BASE_URL=https://api.groq.com/openai/v1   # optional
export MODEL_NAME=llama-3.1-8b-instant               # optional

python inference.py --server-url http://localhost:7860
```

### Run In-Context RL Training Loop

```bash
# 3 episodes on Easy tier — injects high-score trajectories as few-shot examples
python train.py --tier Easy --episodes 3

# All tiers, 5 episodes each — prints learning curve
python train.py --tier all --episodes 5 --save
```

---

## 🧪 Baseline Scores

Measured with `llama-3.1-8b-instant` via Groq API (1 episode per tier, ~10 min total):

| Tier | Grader Score | Verdict | Attack Type | Steps | Notes |
|------|:------------:|:-------:|:-----------:|:-----:|-------|
| 🟢 Easy | **1.00 / 1.00** | ✅ correct | ✅ correct | 5 | Perfect: all components earned |
| 🟡 Medium | **0.80 / 1.00** | ✅ correct | ❌ wrong | 7 | Lost 0.20 on attack type |
| 🔴 Hard | **0.80 / 1.00** | ✅ correct | ❌ wrong | 6 | Lost 0.20 on attack type |

**Average across tiers: 0.867**

All 3 verdicts were correct — the agent correctly identified malicious incidents and triggered
backup before submitting. Attack type classification is where headroom remains (GPT-4o scores higher).

```bash
# Reproduce these scores:
export OPENAI_API_KEY=<your-groq-key>
export API_BASE_URL=https://api.groq.com/openai/v1
export MODEL_NAME=llama-3.1-8b-instant
python inference.py
```

---

## 📡 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Liveness probe |
| `POST` | `/reset?tier_filter=Easy` | Start new episode (Easy / Medium / Hard) |
| `POST` | `/step` | Submit one action |
| `GET` | `/state` | Episode state with ground truth (for graders) |
| `GET` | `/grader` | Deterministic 0.0–1.0 score for current episode |
| `GET` | `/tasks` | Task descriptions + full action/reward schema |

---

## 🧪 Testing

```bash
PYTHONPATH=. pytest tests/ -v
# 56 passed in ~4s

openenv validate
# [OK] soc_triage: Ready for multi-mode deployment
```

---

## 🐳 Docker

```bash
# Build
docker build -t soc-log-triage-env .

# Run FastAPI (for agents / validators):
docker run -p 7860:7860 soc-log-triage-env

# Run Gradio demo (interactive UI):
docker run -p 7860:7860 -e GRADIO_DEMO=1 soc-log-triage-env

# With API key:
docker run -p 7860:7860 -e OPENAI_API_KEY=sk-... soc-log-triage-env
```

---

## 🔗 In-Context Reinforcement Learning

`train.py` implements **In-Context Policy Gradient (ICPG)**:

1. Episode N runs → produces full trajectory (observations, actions, rewards, grader score)
2. Successful high-score trajectories are stored as few-shot demonstrations
3. Episode N+1 receives these demonstrations in its system prompt → the policy improves
4. Grader scores are the RL signal; the environment's `step()` reward shapes the trajectory

This is a valid form of in-context RL — no weight updates required; improvement comes from
the environment's reward signal selecting which demonstrations to keep.

```
Episode 1: score=0.40 (random exploration)
Episode 2: score=0.55 (1 good demo injected)
Episode 3: score=0.70 (2 good demos injected)
```
