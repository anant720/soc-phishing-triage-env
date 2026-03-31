"""
Baseline ReAct Agent for the SOC Log Triage Environment (OpenEnv-compliant).

Reads API credentials from environment variables:
  OPENAI_API_KEY   Primary API key (OpenAI / Groq / Together / any compatible)
  API_BASE_URL     API endpoint override (default: OpenAI; Groq: https://api.groq.com/openai/v1)
  MODEL_NAME       Model identifier (default: gpt-4o-mini)
  HF_TOKEN         Alternative API key (fallback if OPENAI_API_KEY not set)
  SOC_SERVER_URL   OpenEnv server URL (default: http://localhost:7860)

Produces reproducible baseline scores on all 3 tasks (Easy / Medium / Hard).
Runtime: < 20 minutes on a 2-vCPU / 8 GB machine.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
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
# Configuration — all from environment variables as required by hackathon spec
# ---------------------------------------------------------------------------
OPENAI_API_KEY = (
    os.getenv("OPENAI_API_KEY")
    or os.getenv("HF_TOKEN")
    or os.getenv("GROQ_API_KEY")
    or ""
)
API_BASE_URL = os.getenv("API_BASE_URL", "")       # blank = OpenAI default
MODEL_NAME   = os.getenv("MODEL_NAME", "gpt-4o-mini")

# Max steps per tier — must stay below hackathon 20-min runtime limit
MAX_STEPS: dict[str, int] = {
    "Easy":   18,   # ~50 logs
    "Medium": 26,   # ~100 logs
    "Hard":   36,   # ~200 logs
}

TEMPERATURE = 0.1
MAX_TOKENS  = 512


def _extract_json(text: str) -> str:
    """Extract JSON from model output that may be wrapped in markdown fences."""
    text = text.strip()
    import re
    match = re.search(r"```(?:json)?\s*({.*?})\s*```", text, re.DOTALL)
    if match:
        return match.group(1)
    brace_match = re.search(r"({.*})", text, re.DOTALL)
    if brace_match:
        return brace_match.group(1)
    return text


SYSTEM_PROMPT = """You are an autonomous Tier-1 SOC analyst. You are investigating a
SIEM incident bundle — a correlated set of Windows endpoint logs from one or more hosts.

Your objective: investigate the logs, identify the threat, trigger a backup on any
compromised host, and submit a final verdict.

AVAILABLE TOOLS (output JSON only):
1. query_logs(query)            - keyword search across all logs in this incident
2. analyze_process(process_name)- get process tree for a named process
3. check_ip_reputation(ip)      - threat-intel lookup for an IP address
4. check_file_hash(hash)        - IOC lookup for a file hash
5. get_host_summary(host)       - all events/processes/IPs seen on a host
6. trigger_backup(host)         - snapshot a compromised host (REQUIRED for malicious verdict)
7. submit_verdict(verdict, attack_type, affected_hosts) - end episode

VERDICT VALUES: malicious | benign | escalate
ATTACK TYPES (required when verdict=malicious):
  c2_beacon | ransomware | lateral_movement | persistence | data_exfil

OUTPUT FORMAT — ONLY valid JSON, no markdown, no explanation:
{"command": "query_logs", "params": {"query": "powershell"}}
{"command": "trigger_backup", "params": {"host": "DESKTOP-X9Y8Z7"}}
{"command": "submit_verdict", "params": {"verdict": "malicious", "attack_type": "c2_beacon", "affected_hosts": ["DESKTOP-X9Y8Z7"]}}

STRATEGY:
1. Start with query_logs for suspicious keywords (powershell, EncodedCommand, vssadmin, wmic, curl, rclone)
2. Use analyze_process on any suspicious process names you find
3. Check IPs or domains with check_ip_reputation
4. If malicious: trigger_backup on the affected host(s) BEFORE submitting verdict
5. Submit verdict with correct attack_type

Never output anything except a single JSON object.
"""


def _obs_to_context(obs: dict[str, Any], step: int, max_steps: int) -> str:
    lines = [
        "=== INCIDENT BUNDLE ===",
        f"Alert   : {obs.get('alert_summary')}",
        f"Hosts   : {obs.get('host_count')}   Logs: {obs.get('log_count')}",
        f"Primary : {obs.get('primary_host')}",
        f"Step    : {step}/{max_steps}",
        f"Tools used: {obs.get('tools_used', [])}",
        f"Backups : {obs.get('backup_triggered_hosts', [])}",
    ]
    # Show initial logs on first step (cap at 30 to control token usage)
    if step <= 1 and obs.get("initial_logs"):
        initial = obs["initial_logs"][:30]
        lines.append(f"\n=== INITIAL LOGS (first {len(initial)} of {obs.get('log_count')}) ===")
        for lg in initial:
            lines.append(
                f"  [{lg.get('timestamp','')}] {lg.get('host_id','')} | "
                f"{lg.get('event_type','')} | {str(lg.get('process',''))[:50]} | "
                f"cmd={str(lg.get('commandline',''))[:60]} | "
                f"domain={lg.get('target_domain')} | ip={lg.get('target_ip')}"
            )
    # Tool result
    if obs.get("tool_used") and obs.get("tool_result"):
        lines.append(f"\n=== Tool Result: {obs['tool_used']} ===")
        lines.append(json.dumps(obs["tool_result"], indent=2)[:1500])
    if not obs.get("success") and obs.get("error_message"):
        lines.append(f"\n[ERROR] {obs['error_message']}")
    return "\n".join(lines)


async def _llm_call_with_retry(
    oai: AsyncOpenAI,
    model: str,
    messages: list[dict],
    max_retries: int = 4,
) -> str:
    """Call LLM with exponential backoff on rate-limit (429) errors."""
    for attempt in range(max_retries):
        try:
            chat_resp = await oai.chat.completions.create(
                model=model,
                messages=messages,
                temperature=TEMPERATURE,
                max_tokens=MAX_TOKENS,
            )
            return chat_resp.choices[0].message.content or "{}"
        except Exception as exc:
            err = str(exc)
            if "429" in err or "rate_limit" in err.lower() or "rate limit" in err.lower():
                wait = (2 ** attempt) * 10   # 10s, 20s, 40s, 80s
                print(f"    [RATE LIMIT] Waiting {wait}s before retry {attempt+1}/{max_retries}...")
                await asyncio.sleep(wait)
            else:
                raise
    raise RuntimeError(f"LLM call failed after {max_retries} retries (rate limit)")


async def run_episode(
    oai: AsyncOpenAI,
    client: httpx.AsyncClient,
    model: str,
    tier: str,
    verbose: bool,
) -> tuple[float, list[float]]:
    """Run one episode. Returns (grader_score, per_step_rewards)."""

    resp = await client.post(f"/reset?tier_filter={tier}")
    resp.raise_for_status()
    obs = resp.json()

    max_steps = obs.get("max_steps", MAX_STEPS.get(tier, 20))

    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": _obs_to_context(obs, 0, max_steps)},
    ]

    done             = False
    step             = 0
    raw_content      = ""
    step_rewards: list[float] = []
    cumulative_reward = 0.0

    while not done and step < max_steps:
        step += 1

        try:
            raw_content = await _llm_call_with_retry(oai, model, messages)
            cleaned     = _extract_json(raw_content)
            action      = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            if verbose:
                print(f"  [WARN] JSON parse failed: {exc}")
            messages.append({"role": "assistant", "content": raw_content})
            messages.append({"role": "user", "content":
                f"Your output was not valid JSON. Error: {exc}. "
                f"Output ONLY a JSON object like: {{\"command\": \"query_logs\", \"params\": {{\"query\": \"powershell\"}}}}"
            })
            continue
        except Exception as exc:
            if verbose:
                print(f"  [WARN] LLM call failed: {exc}")
            break

        if verbose:
            cmd = action.get("command", "?")
            pms = json.dumps(action.get("params", {}))[:80]
            print(f"  Step {step}: {cmd}({pms})")

        step_resp = await client.post("/step", json=action)
        if step_resp.status_code != 200:
            if verbose:
                print(f"  [ERROR] /step rejected: {step_resp.text[:100]}")
            messages.append({"role": "assistant", "content": raw_content})
            messages.append({"role": "user", "content": f"Action rejected: {step_resp.text[:200]}"})
            continue

        step_data = step_resp.json()
        obs       = step_data.get("observation", {})
        done      = step_data.get("done", False)
        reward    = step_data.get("reward", 0.0)

        step_rewards.append(reward)
        cumulative_reward += reward

        if verbose:
            status = "✅ DONE" if done else "⏳"
            print(f"    → reward={reward:+.4f} | cumul={cumulative_reward:+.4f} | {status}")
            if obs.get("error_message"):
                print(f"    [ENV ERROR] {obs['error_message']}")

        messages.append({"role": "assistant", "content": raw_content})
        messages.append({"role": "user",      "content": _obs_to_context(obs, step, max_steps)})

        if done:
            break

    # Retrieve grader score
    grade_resp = await client.get("/grader")
    if grade_resp.status_code == 200:
        gdata = grade_resp.json()
        score = gdata.get("score", 0.0)
        if verbose:
            print(f"\n  ── Grader Breakdown ──")
            breakdown = gdata.get("breakdown", {})
            for k, v in breakdown.items():
                if k != "final_score":
                    print(f"     {k:<30}: {v:+.4f}")
            print(f"     {'FINAL SCORE':<30}: {score:.4f}")
            deductions = gdata.get("deductions", [])
            if deductions:
                print(f"  ── Deductions ──")
                for d in deductions:
                    print(f"     • {d}")
            print(f"  Expected: verdict={gdata.get('expected_verdict')} | type={gdata.get('expected_attack_type')}")
            print(f"  Got     : verdict={gdata.get('final_verdict')} | type={gdata.get('final_attack_type')}")
        return score, step_rewards
    return 0.0, step_rewards


async def run_baseline_evaluation(
    model: str = "gpt-4o-mini",
    server_url: str = "http://localhost:7860",
    verbose: bool = True,
    episodes_per_tier: int = 1,
) -> dict[str, Any]:
    """
    Run episodes per tier (Easy/Medium/Hard) and return full results.
    Hackathon requirement: complete in < 20 minutes on 2-vCPU / 8 GB.
    """
    api_key  = OPENAI_API_KEY
    base_url = API_BASE_URL

    if not api_key:
        print("[WARN] No API key found. Set OPENAI_API_KEY, HF_TOKEN, or GROQ_API_KEY.")

    kwargs: dict[str, Any] = {"api_key": api_key or "no-key"}
    if base_url:
        kwargs["base_url"] = base_url
    oai = AsyncOpenAI(**kwargs)

    results: dict[str, Any] = {}
    tiers = ["Easy", "Medium", "Hard"]
    t_start = time.time()

    async with httpx.AsyncClient(base_url=server_url, timeout=180.0) as client:
        for tier in tiers:
            if verbose:
                print(f"\n{'='*60}")
                print(f"  TIER: {tier}  |  Model: {model}  |  Episodes: {episodes_per_tier}")
                print(f"{'='*60}")

            tier_scores: list[float] = []
            tier_rewards: list[list[float]] = []

            for ep_idx in range(episodes_per_tier):
                if verbose and episodes_per_tier > 1:
                    print(f"\n  ── Episode {ep_idx+1}/{episodes_per_tier} ──")
                try:
                    score, rewards = await run_episode(oai, client, model, tier, verbose)
                    tier_scores.append(score)
                    tier_rewards.append(rewards)
                    if verbose:
                        print(f"  ⟹ Episode score: {score:.4f}")
                except Exception as exc:
                    if verbose:
                        print(f"  [FATAL] Episode failed: {exc}")
                    tier_scores.append(0.0)

            avg = sum(tier_scores) / len(tier_scores) if tier_scores else 0.0
            results[tier] = {
                "average_score": round(avg, 4),
                "scores":        [round(s, 4) for s in tier_scores],
                "step_rewards":  tier_rewards,
            }
            if verbose:
                print(f"\n  ⟹ {tier} Average: {avg:.4f}")

    elapsed = time.time() - t_start
    results["_meta"] = {
        "model":       model,
        "server_url":  server_url,
        "elapsed_sec": round(elapsed, 1),
        "episodes":    episodes_per_tier,
    }

    return results


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Baseline SOC Log Triage agent — OpenEnv hackathon submission"
    )
    parser.add_argument("--model",      default=os.getenv("MODEL_NAME", "gpt-4o-mini"))
    parser.add_argument("--server-url", default=os.getenv("SOC_SERVER_URL", "http://localhost:7860"))
    parser.add_argument("--episodes",   type=int, default=1, help="Episodes per tier")
    parser.add_argument("--quiet",      action="store_true")
    args = parser.parse_args()

    try:
        results = await run_baseline_evaluation(
            model=args.model,
            server_url=args.server_url,
            verbose=not args.quiet,
            episodes_per_tier=args.episodes,
        )

        meta = results.pop("_meta", {})
        print(f"\n{'='*60}")
        print(f"  BASELINE RESULTS  |  model={meta.get('model')}")
        print(f"  Elapsed: {meta.get('elapsed_sec')}s")
        print(f"{'='*60}")
        for tier in ["Easy", "Medium", "Hard"]:
            if tier in results:
                r = results[tier]
                print(f"  {tier:<8}: {r['average_score']:.4f}  {r['scores']}")
        print(f"{'='*60}")
        print(json.dumps({**results, "_meta": meta}, indent=2))

    except Exception as exc:
        print(f"\n[FATAL] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
