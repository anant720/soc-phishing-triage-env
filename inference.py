"""
inference.py — OpenEnv hackathon submission entry point.

Mandatory per hackathon spec:
  - Uses the OpenAI API client for all LLM calls
  - Reads credentials from environment variables:
      API_BASE_URL  → LLM API endpoint  (default: https://api-inference.huggingface.co/v1)
      MODEL_NAME    → model identifier  (default: Qwen/Qwen2.5-7B-Instruct)
      HF_TOKEN      → Hugging Face API key used as the Bearer token
  - Runs one episode per difficulty tier (Easy, Medium, Hard)
  - Prints a score for each task and a final summary

Usage:
    export API_BASE_URL="https://api-inference.huggingface.co/v1"
    export MODEL_NAME="Qwen/Qwen2.5-7B-Instruct"
    export HF_TOKEN="hf_..."
    python inference.py

    # to run against a local server instead:
    python inference.py --env-url http://localhost:7860

    # to run more episodes per tier:
    python inference.py --episodes 3
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any

import requests
from openai import OpenAI

# ---------------------------------------------------------------------------
# Environment & LLM config — all read from env vars per hackathon spec
# ---------------------------------------------------------------------------

API_BASE_URL = os.environ.get("API_BASE_URL", "https://api-inference.huggingface.co/v1")
MODEL_NAME   = os.environ.get("MODEL_NAME",   "Qwen/Qwen2.5-7B-Instruct")
HF_TOKEN     = os.environ.get("HF_TOKEN",     "")
ENV_URL      = os.environ.get("ENV_URL",      "http://localhost:7860")

MAX_STEPS   = 8     # per-episode step budget (well within 20-min runtime limit)
TEMPERATURE = 0.2   # low temperature → more deterministic, reproducible scores

# ---------------------------------------------------------------------------
# System prompt — tells the LLM exactly how to interact with the environment
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an expert Tier-1 SOC (Security Operations Center) analyst.
Your job is to triage a suspicious email and classify it as one of:
  - "phishing"  : malicious email attempting fraud, credential theft, or malware delivery
  - "benign"    : legitimate email from an authentic sender
  - "escalate"  : ambiguous — needs Tier-2 analyst review

You have these investigation tools available:

1. analyze_headers(email_id)     → checks SPF, DKIM, DMARC and flags header anomalies
2. lookup_threat_intel(domain)   → queries domain reputation: risk score and malware tags
3. sandbox_url(url)              → detonates a URL in sandbox, checks credential harvesting
4. whois_lookup(domain)          → returns domain age and registrar (new domains = red flag)

Rules:
- You MUST call at least one tool before submitting a verdict.
- Think step-by-step. Gather evidence before deciding.
- Respond ONLY with a single valid JSON object — no prose, no markdown fences.

Tool call format:
{"command": "<tool_name>", "params": {<key>: <value>}}

Verdict format:
{"command": "submit_verdict", "params": {"verdict": "<phishing|benign|escalate>"}}"""


# ---------------------------------------------------------------------------
# OpenAI client — pointed at whatever API_BASE_URL is set to
# ---------------------------------------------------------------------------

def make_client() -> OpenAI:
    """
    Builds the OpenAI client. If HF_TOKEN is set we use it as the API key
    so this works against HF's Inference API out of the box. You can also
    point API_BASE_URL at any OpenAI-compatible endpoint (OpenAI, Together,
    Groq, local vLLM, etc.)
    """
    api_key = HF_TOKEN or "no-key-needed"  # some local endpoints don't require a key
    return OpenAI(api_key=api_key, base_url=API_BASE_URL)


# ---------------------------------------------------------------------------
# Environment HTTP helpers
# ---------------------------------------------------------------------------

def env_reset(base_url: str, tier: str) -> dict:
    r = requests.post(f"{base_url}/reset", params={"tier_filter": tier}, timeout=15)
    r.raise_for_status()
    return r.json()


def env_step(base_url: str, action: dict) -> dict:
    r = requests.post(f"{base_url}/step", json=action, timeout=15)
    r.raise_for_status()
    return r.json()


def env_grader(base_url: str) -> dict:
    r = requests.get(f"{base_url}/grader", timeout=10)
    r.raise_for_status()
    return r.json()


def env_health(base_url: str) -> dict:
    r = requests.get(f"{base_url}/health", timeout=10)
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------

def build_user_prompt(step: int, obs: dict, history: list[str]) -> str:
    """
    Converts the current observation into a human-readable prompt for the LLM.
    Includes the full email metadata and a running history of previous steps.
    """
    lines = [
        f"=== EMAIL TRIAGE — Step {step}/{MAX_STEPS} ===",
        f"Email ID    : {obs.get('email_id', 'unknown')}",
        f"Subject     : {obs.get('email_subject', '(no subject)')}",
        f"From        : {obs.get('from_address', '?')}",
        f"Return-Path : {obs.get('return_path', '?')}",
        f"Snippet     : {obs.get('email_snippet', '')[:300]}",
        f"Tier        : {obs.get('difficulty_tier', '?')}",
        f"Tools used  : {obs.get('tools_used', [])}",
        "",
    ]

    if history:
        lines.append("Your action history so far:")
        lines.extend(f"  {h}" for h in history[-4:])  # last 4 steps to stay within context
        lines.append("")

    # give the tool result from the previous step if available
    if obs.get("tool_result"):
        lines.append(f"Last tool result:\n{json.dumps(obs['tool_result'], indent=2)}")
        lines.append("")

    if obs.get("error_message"):
        lines.append(f"⚠ Last action error: {obs['error_message']}")
        lines.append("")

    lines.append("What is your next action? Respond with a single JSON object.")
    return "\n".join(lines)


def parse_action(response_text: str) -> dict | None:
    """
    Pulls the first valid JSON object out of the model's response.
    We're strict here — if the model hallucinates prose we return None
    and the episode will use a fallback.
    """
    text = response_text.strip()

    # strip markdown code fences if present
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1]) if len(lines) > 2 else text

    # find first { ... }
    start = text.find("{")
    end   = text.rfind("}") + 1
    if start == -1 or end == 0:
        return None

    try:
        return json.loads(text[start:end])
    except json.JSONDecodeError:
        return None


# ---------------------------------------------------------------------------
# Single episode runner
# ---------------------------------------------------------------------------

def run_episode(client: OpenAI, base_url: str, tier: str, ep_num: int) -> dict:
    """
    Runs one full episode for the given tier. The LLM decides every action.
    Returns the grader result dict.
    """
    obs     = env_reset(base_url, tier)
    email_id = obs["email_id"]
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    history  = []

    print(f"    ep{ep_num:02d}  id={email_id}  subject={obs.get('email_subject','')[:40]}")

    for step in range(1, MAX_STEPS + 1):
        user_prompt = build_user_prompt(step, obs, history)
        messages.append({"role": "user", "content": user_prompt})

        # call the LLM
        try:
            completion = client.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                temperature=TEMPERATURE,
                max_tokens=256,
                stream=False,
            )
            response_text = completion.choices[0].message.content or ""
        except Exception as exc:
            print(f"         ⚠ LLM call failed ({exc}), using fallback verdict")
            response_text = '{"command":"submit_verdict","params":{"verdict":"escalate"}}'

        messages.append({"role": "assistant", "content": response_text})

        # parse the action
        action = parse_action(response_text)
        if action is None:
            print(f"         ⚠ Unparseable response at step {step}, submitting escalate")
            action = {"command": "submit_verdict", "params": {"verdict": "escalate"}}

        # send action to environment
        try:
            result = env_step(base_url, action)
        except requests.HTTPError as exc:
            if exc.response.status_code == 422:
                # schema violation — tell the model and retry
                obs = {**obs, "error_message": str(exc), "tool_result": None}
                history.append(f"step {step}: schema error — {action.get('command')}")
                messages.append({
                    "role": "user",
                    "content": f"Your last action was rejected (schema error): {exc}\n"
                               "Please fix the format and try again."
                })
                continue
            raise

        reward = result.get("reward", 0.0)
        done   = result.get("done", False)
        obs    = result.get("observation", obs)

        cmd    = action.get("command", "?")
        history.append(f"step {step}: {cmd} → reward {reward:+.2f}")
        print(f"         step {step:02d}  {cmd:<22}  reward={reward:+.3f}  done={done}")

        if done:
            break

    grader = env_grader(base_url)
    score  = grader.get("score", 0.0)
    correct = grader.get("correct", False)
    print(f"         → grader score={score:.4f}  correct={correct}")
    return grader


# ---------------------------------------------------------------------------
# Main loop — runs all three tiers and prints a summary table
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SOC Triage inference script — OpenEnv hackathon entry"
    )
    parser.add_argument("--env-url",  default=ENV_URL,
                        help="SOC Triage environment base URL")
    parser.add_argument("--episodes", type=int, default=1,
                        help="Episodes per tier (default 1 — keep under 20 min)")
    args = parser.parse_args()

    base_url = args.env_url

    # --- sanity checks ---
    if not HF_TOKEN and "huggingface.co" in API_BASE_URL:
        print("⚠  HF_TOKEN is not set. HF Inference API calls will likely fail.")
        print("   Set HF_TOKEN to your Hugging Face token and retry.")

    print(f"\n🌐 Environment : {base_url}")
    print(f"🤖 Model       : {MODEL_NAME}")
    print(f"🔗 LLM API     : {API_BASE_URL}")
    print(f"📊 Episodes    : {args.episodes} per tier\n")

    # health check
    try:
        h = env_health(base_url)
        print(f"✅ Environment health: {h.get('status')}  v{h.get('version')}\n")
    except Exception as exc:
        print(f"❌ Cannot reach environment at {base_url}: {exc}")
        print("   Make sure the server is running before executing inference.py")
        sys.exit(1)

    client = make_client()

    tiers   = ["Easy", "Medium", "Hard"]
    results = {t: [] for t in tiers}

    start_time = time.time()

    for tier in tiers:
        print(f"{'─'*60}")
        print(f"  Tier: {tier}")
        print(f"{'─'*60}")
        for ep in range(1, args.episodes + 1):
            grader = run_episode(client, base_url, tier, ep)
            results[tier].append(grader)

    elapsed = time.time() - start_time

    # --- summary table ---
    print(f"\n{'═'*60}")
    print("  BASELINE RESULTS  —  SOC Phishing Triage Environment")
    print(f"  Model: {MODEL_NAME}")
    print(f"{'═'*60}")
    print(f"  {'Tier':<10}  {'Ep':>3}  {'Score':>7}  {'Correct':>8}  {'Steps':>6}")
    print(f"  {'─'*45}")

    grand_total_score = 0.0
    grand_total_correct = 0
    grand_total_ep = 0

    for tier in tiers:
        tier_scores   = [r.get("score",   0.0)   for r in results[tier]]
        tier_correct  = [r.get("correct", False)  for r in results[tier]]
        tier_steps    = [r.get("step_count", "?") for r in results[tier]]

        for i, (sc, cor, st) in enumerate(zip(tier_scores, tier_correct, tier_steps)):
            print(f"  {tier:<10}  {i+1:>3}  {sc:>7.4f}  {'✓' if cor else '✗':>8}  {str(st):>6}")

        avg_score = sum(tier_scores) / len(tier_scores) if tier_scores else 0.0
        print(f"  {'avg':>10}  {'':>3}  {avg_score:>7.4f}")
        print()

        grand_total_score   += sum(tier_scores)
        grand_total_correct += sum(tier_correct)
        grand_total_ep      += len(tier_scores)

    overall_avg = grand_total_score / grand_total_ep if grand_total_ep else 0.0
    overall_acc = grand_total_correct / grand_total_ep if grand_total_ep else 0.0

    print(f"{'─'*60}")
    print(f"  Overall avg score : {overall_avg:.4f}")
    print(f"  Overall accuracy  : {grand_total_correct}/{grand_total_ep}  ({overall_acc:.1%})")
    print(f"  Total runtime     : {elapsed:.1f}s")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()
