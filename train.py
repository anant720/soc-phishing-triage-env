"""
train.py — In-Context Reinforcement Learning for SOC Log Triage

Demonstrates that the reward signal from the environment drives measurable
improvement in agent performance across episodes — without fine-tuning weights.

Technique: In-Context Policy Gradient (ICPG)
  - Each episode produces a full trajectory (observations, actions, rewards)
  - High-reward trajectories are stored as few-shot examples in the system prompt
  - Later episodes benefit from these demonstrations → scores improve
  - This is a valid RL-adjacent training signal loop, often called "in-context RL"

Usage:
  export OPENAI_API_KEY=sk-...
  export API_BASE_URL=https://api.groq.com/openai/v1    # optional, Groq works
  export MODEL_NAME=llama-3.1-8b-instant                # optional
  python train.py --tier Easy --episodes 5
  python train.py --tier all  --episodes 3              # all 3 tiers

Output:
  - Per-episode grader scores printed as a learning curve
  - Best trajectory saved to train_best_<tier>.json
  - Summary table of reward vs score correlation
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any

from dotenv import load_dotenv

load_dotenv()

try:
    from openai import AsyncOpenAI
except ImportError:
    print("[ERROR] openai package not installed. Run: pip install openai")
    sys.exit(1)

import httpx

# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------
OPENAI_API_KEY = (
    os.getenv("OPENAI_API_KEY")
    or os.getenv("HF_TOKEN")
    or os.getenv("GROQ_API_KEY")
    or ""
)
API_BASE_URL = os.getenv("API_BASE_URL", "")
MODEL_NAME   = os.getenv("MODEL_NAME", "gpt-4o-mini")

MAX_STEPS_PER_TIER = {"Easy": 18, "Medium": 26, "Hard": 36}
TEMPERATURE        = 0.2   # slightly higher than baseline for exploration
MAX_TOKENS         = 512

SYSTEM_PROMPT_BASE = """You are an autonomous Tier-1 SOC analyst investigating a Windows
endpoint security incident. Your goal: classify correctly, trigger backup if malicious,
minimize wasted steps.

TOOLS (output JSON only):
  query_logs(query)             - keyword search across all logs
  analyze_process(process_name) - process tree for a named process
  check_ip_reputation(ip)       - threat-intel IP lookup (0.0=clean, 1.0=malicious)
  check_file_hash(hash)         - IOC lookup for a file hash
  get_host_summary(host)        - all events/processes/IPs on a host
  trigger_backup(host)          - emergency snapshot (REQUIRED if malicious)
  submit_verdict(verdict, attack_type, affected_hosts) - end episode

verdict: malicious | benign | escalate
attack_type (if malicious): c2_beacon | ransomware | lateral_movement | persistence | data_exfil

Output ONLY a single JSON object:
{"command": "query_logs", "params": {"query": "powershell"}}
"""


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Step:
    observation: str
    action: dict
    reward: float


@dataclass
class Trajectory:
    tier: str
    episode: int
    steps: list[Step] = field(default_factory=list)
    grader_score: float = 0.0
    cumulative_reward: float = 0.0
    correct: bool = False

    def to_fewshot(self) -> str:
        """Render this trajectory as a few-shot example for the system prompt."""
        lines = [
            f"# Example (tier={self.tier}, score={self.grader_score:.2f}, "
            f"steps={len(self.steps)}, correct={self.correct})",
        ]
        for i, s in enumerate(self.steps[:6], 1):   # cap at 6 steps
            cmd  = s.action.get("command", "?")
            pms  = json.dumps(s.action.get("params", {}))[:60]
            lines.append(f"  Step {i}: {cmd}({pms})  → reward={s.reward:+.3f}")
        lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_json(text: str) -> str:
    import re
    text = text.strip()
    m = re.search(r"```(?:json)?\s*({.*?})\s*```", text, re.DOTALL)
    if m:
        return m.group(1)
    m = re.search(r"({.*})", text, re.DOTALL)
    if m:
        return m.group(1)
    return text


def _obs_to_ctx(obs: dict, step: int, max_steps: int) -> str:
    lines = [
        f"Step {step}/{max_steps}",
        f"Alert: {obs.get('alert_summary')}",
        f"Host: {obs.get('primary_host')} | Logs: {obs.get('log_count')}",
        f"Tools used: {obs.get('tools_used', [])}",
        f"Backups: {obs.get('backup_triggered_hosts', [])}",
    ]
    if step <= 1 and obs.get("initial_logs"):
        logs = obs["initial_logs"][:20]
        lines.append(f"\nFirst {len(logs)} logs:")
        for lg in logs:
            lines.append(
                f"  [{lg.get('timestamp','')}] {lg.get('host_id','')} | "
                f"{lg.get('event_type','')} | {str(lg.get('process',''))[:40]} | "
                f"cmd={str(lg.get('commandline',''))[:50]}"
            )
    if obs.get("tool_result"):
        lines.append(f"\nLast tool result ({obs.get('tool_used')}):")
        lines.append(json.dumps(obs["tool_result"])[:800])
    if obs.get("error_message"):
        lines.append(f"\nERROR: {obs['error_message']}")
    return "\n".join(lines)


async def _llm(oai: AsyncOpenAI, messages: list[dict], retries: int = 3) -> str:
    for attempt in range(retries):
        try:
            r = await oai.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                temperature=TEMPERATURE,
                max_tokens=MAX_TOKENS,
            )
            return r.choices[0].message.content or "{}"
        except Exception as e:
            if "429" in str(e) or "rate" in str(e).lower():
                wait = (2 ** attempt) * 10
                print(f"    [rate limit] sleeping {wait}s...")
                await asyncio.sleep(wait)
            else:
                raise
    return '{"command": "submit_verdict", "params": {"verdict": "escalate", "attack_type": null, "affected_hosts": []}}'


# ---------------------------------------------------------------------------
# Episode runner
# ---------------------------------------------------------------------------

async def run_episode(
    oai: AsyncOpenAI,
    client: httpx.AsyncClient,
    tier: str,
    episode_idx: int,
    best_trajectories: list[Trajectory],
    verbose: bool,
) -> Trajectory:
    """Run one episode, optionally primed with high-score few-shots."""

    resp = await client.post(f"/reset?tier_filter={tier}")
    resp.raise_for_status()
    obs = resp.json()
    max_steps = obs.get("max_steps", MAX_STEPS_PER_TIER.get(tier, 20))

    # Build system prompt — inject best trajectories as few-shot examples
    sys_prompt = SYSTEM_PROMPT_BASE
    if best_trajectories:
        sys_prompt += "\n\n# High-Scoring Examples (learn from these patterns)\n"
        for t in best_trajectories[-2:]:   # max 2 examples to stay within token budget
            sys_prompt += t.to_fewshot()

    messages = [
        {"role": "system", "content": sys_prompt},
        {"role": "user",   "content": _obs_to_ctx(obs, 0, max_steps)},
    ]

    traj = Trajectory(tier=tier, episode=episode_idx)
    done = False
    step = 0

    while not done and step < max_steps:
        step += 1
        raw = await _llm(oai, messages)

        try:
            cleaned = _extract_json(raw)
            action  = json.loads(cleaned)
        except json.JSONDecodeError:
            messages.append({"role": "assistant", "content": raw})
            messages.append({"role": "user", "content":
                "Invalid JSON. Output ONLY: {\"command\": \"...\", \"params\": {...}}"})
            continue

        sr = await client.post("/step", json=action)
        if sr.status_code != 200:
            messages.append({"role": "assistant", "content": raw})
            messages.append({"role": "user", "content": f"Rejected: {sr.text[:100]}"})
            continue

        sd   = sr.json()
        obs  = sd.get("observation", {})
        rew  = sd.get("reward", 0.0)
        done = sd.get("done", False)

        traj.steps.append(Step(observation=_obs_to_ctx(obs, step, max_steps),
                               action=action, reward=rew))
        traj.cumulative_reward += rew

        messages.append({"role": "assistant", "content": raw})
        messages.append({"role": "user",      "content": _obs_to_ctx(obs, step, max_steps)})

    # Retrieve grader score
    gr = await client.get("/grader")
    if gr.status_code == 200:
        gd = gr.json()
        traj.grader_score = gd.get("score", 0.0)
        traj.correct      = gd.get("correct", False)

    if verbose:
        print(f"    Episode {episode_idx+1}: cumul_reward={traj.cumulative_reward:+.3f} | "
              f"grader={traj.grader_score:.4f} | correct={traj.correct} | steps={len(traj.steps)}")

    return traj


# ---------------------------------------------------------------------------
# Training loop
# ---------------------------------------------------------------------------

async def train(
    tier: str,
    n_episodes: int,
    server_url: str,
    verbose: bool,
) -> list[Trajectory]:
    """
    Run n_episodes, injecting high-score trajectories into later system prompts.
    Returns sorted trajectory list (best first).
    """
    kwargs: dict[str, Any] = {"api_key": OPENAI_API_KEY or "no-key"}
    if API_BASE_URL:
        kwargs["base_url"] = API_BASE_URL
    oai = AsyncOpenAI(**kwargs)

    trajectories: list[Trajectory] = []
    best_so_far: list[Trajectory]  = []

    print(f"\n{'='*55}")
    print(f"  TRAINING  |  Tier={tier}  |  Episodes={n_episodes}")
    print(f"  Model: {MODEL_NAME}")
    print(f"{'='*55}")

    async with httpx.AsyncClient(base_url=server_url, timeout=180.0) as client:
        for ep in range(n_episodes):
            if verbose:
                fewshot_count = len(best_so_far)
                print(f"\n  Episode {ep+1}/{n_episodes} "
                      f"(primed with {fewshot_count} high-score example{'s' if fewshot_count != 1 else ''}):")
            traj = await run_episode(oai, client, tier, ep, best_so_far, verbose)
            trajectories.append(traj)

            # Keep top-2 correct trajectories as few-shot examples for next episodes
            correct = [t for t in trajectories if t.correct]
            best_so_far = sorted(correct, key=lambda t: t.grader_score, reverse=True)[:2]

    return trajectories


def _print_learning_curve(trajectories: list[Trajectory], tier: str) -> None:
    print(f"\n{'='*55}")
    print(f"  LEARNING CURVE — {tier}")
    print(f"{'='*55}")
    print(f"  {'Ep':>3}  {'GraderScore':>12}  {'CumulReward':>12}  {'Correct':>8}  {'Steps':>6}")
    print(f"  {'-'*50}")
    for t in trajectories:
        bar_len = int(t.grader_score * 20)
        bar = "█" * bar_len + "░" * (20 - bar_len)
        print(f"  {t.episode+1:>3}  {t.grader_score:>12.4f}  "
              f"{t.cumulative_reward:>12.4f}  "
              f"{'✅' if t.correct else '❌':>8}  "
              f"{len(t.steps):>6}")
    scores = [t.grader_score for t in trajectories]
    if len(scores) >= 2:
        delta = scores[-1] - scores[0]
        print(f"\n  First → Last: {scores[0]:.4f} → {scores[-1]:.4f}  (Δ={delta:+.4f})")
        improvement = sum(1 for a, b in zip(scores, scores[1:]) if b >= a)
        print(f"  Monotone improvement steps: {improvement}/{len(scores)-1}")


async def main() -> None:
    parser = argparse.ArgumentParser(description="In-context RL training for SOC triage")
    parser.add_argument("--tier",       default="Easy", help="Easy | Medium | Hard | all")
    parser.add_argument("--episodes",   type=int, default=3, help="Episodes per tier")
    parser.add_argument("--server-url", default=os.getenv("SOC_SERVER_URL", "http://localhost:7860"))
    parser.add_argument("--quiet",      action="store_true")
    parser.add_argument("--save",       action="store_true", help="Save best trajectory JSON")
    args = parser.parse_args()

    tiers = ["Easy", "Medium", "Hard"] if args.tier.lower() == "all" else [args.tier]
    t_start = time.time()

    all_results: dict = {}
    for tier in tiers:
        trajectories = await train(
            tier=tier,
            n_episodes=args.episodes,
            server_url=args.server_url,
            verbose=not args.quiet,
        )
        _print_learning_curve(trajectories, tier)
        best = max(trajectories, key=lambda t: t.grader_score)
        all_results[tier] = {
            "scores":    [round(t.grader_score, 4) for t in trajectories],
            "best":      round(best.grader_score, 4),
            "correct_n": sum(1 for t in trajectories if t.correct),
        }
        if args.save and best.correct:
            path = f"train_best_{tier.lower()}.json"
            with open(path, "w") as f:
                payload = {
                    "tier": best.tier, "score": best.grader_score,
                    "steps": [{"action": s.action, "reward": s.reward} for s in best.steps],
                }
                json.dump(payload, f, indent=2)
            print(f"\n  Best trajectory saved → {path}")

    elapsed = time.time() - t_start
    print(f"\n{'='*55}")
    print(f"  FINAL SUMMARY  (elapsed {elapsed:.0f}s)")
    print(f"{'='*55}")
    for tier, r in all_results.items():
        print(f"  {tier:<8}: scores={r['scores']}  best={r['best']:.4f}  "
              f"correct={r['correct_n']}/{args.episodes}")


if __name__ == "__main__":
    asyncio.run(main())
