"""
Baseline Agent for the SOC Triage Environment.

Implements a ReAct-style (Reason + Act) agent loop using the OpenAI
Chat Completions API. The agent iteratively invokes SOC tools before
submitting a final triage verdict, adapting to tier difficulties (Easy, Medium, Hard).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
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
# System prompt — instructs the model to behave as a SOC analyst
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an expert Tier-1 SOC (Security Operations Center) analyst.
Your task is to triage a suspicious email and determine whether it is:
  - "phishing"  : A malicious email attempting fraud, credential theft, or malware delivery.
  - "benign"    : A legitimate email from an authentic sender.
  - "escalate"  : An ambiguous email that requires Tier-2 analyst review.

You have access to the following tools to assist your investigation:

1. analyze_headers(email_id)
   → Checks SPF, DKIM, DMARC records and identifies header anomalies.

2. lookup_threat_intel(domain)
   → Queries the threat intelligence database for a domain's reputation score and tags.

3. sandbox_url(url)
   → Detonates a URL in a sandbox and checks for credential harvesting or malware.

4. whois_lookup(domain)
   → Returns WHOIS registration data (registrar, creation date, domain age).

You MUST use at least one tool before submitting your verdict.
Think step-by-step. After gathering enough evidence, submit your final verdict.

Your response MUST always be a single valid JSON object in one of these formats:

To call a tool:
{
  "command": "<tool_name>",
  "params": { ... }
}

To submit a verdict:
{
  "command": "submit_verdict",
  "params": { "verdict": "<phishing|benign|escalate>" }
}

Do NOT include any text outside the JSON object. 
"""

def _obs_to_context(obs: dict[str, Any]) -> str:
    """Serialize an observation into a concise human-readable context string."""
    lines = [
        f"=== Email Under Investigation ===",
        f"ID      : {obs.get('email_id')}",
        f"Subject : {obs.get('email_subject')}",
        f"From    : {obs.get('email_sender')}",
        f"Snippet : {obs.get('email_body_snippet', '')[:300]}",
        f"",
        f"Step {obs.get('step_number')}/{obs.get('max_steps')}",
        f"Tools used so far: {obs.get('tools_used', [])}",
    ]
    if obs.get("tool_used"):
        lines += [
            f"",
            f"--- Last Tool: {obs.get('tool_used')} ---",
            f"{json.dumps(obs.get('tool_result'), indent=2)}",
        ]
    if not obs.get("success") and obs.get("error_message"):
        lines += [
            f"",
            f"--- ERROR from last action ---",
            f"{obs.get('error_message')}",
        ]
    return "\n".join(lines)


async def run_baseline_evaluation(
    model: str = "gpt-4o-mini",
    server_url: str = "http://localhost:8000",
    verbose: bool = True
) -> dict[str, float]:
    """
    Execute the baseline baseline agent on the Easy, Medium, and Hard tasks.
    Returns: {"Easy": 1.0, "Medium": 0.95, "Hard": 0.6}
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY environment variable is not set.")

    oai = AsyncOpenAI(api_key=api_key)
    scores: dict[str, float] = {}

    tiers = ["Easy", "Medium", "Hard"]

    async with httpx.AsyncClient(base_url=server_url, timeout=60.0) as client:
        for tier in tiers:
            if verbose:
                print(f"\n{'='*60}")
                print(f"Starting {tier} Tier Evaluation")
                print(f"{'='*60}")
            
            # Step 1: Reset environment for specific tier
            resp = await client.post(f"/reset?tier_filter={tier}")
            resp.raise_for_status()
            obs = resp.json()

            messages: list[dict[str, str]] = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": _obs_to_context(obs)},
            ]

            done = False
            step_count = 0
            max_steps = obs.get("max_steps", 10)

            while not done and step_count < max_steps:
                step_count += 1
                
                # Step 2: Agent Perception & Action
                try:
                    chat_resp = await oai.chat.completions.create(
                        model=model,
                        messages=messages,
                        temperature=0.2,
                        response_format={"type": "json_object"},
                    )
                    raw_content = chat_resp.choices[0].message.content or "{}"
                    action = json.loads(raw_content)
                except Exception as e:
                    if verbose: print(f"  [WARN] Agent failed to generate valid JSON: {e}")
                    # Push error to context to recover
                    messages.append({"role": "assistant", "content": raw_content})
                    messages.append({"role": "user", "content": f"Output must be valid JSON: {e}"})
                    continue

                if verbose:
                    cmd = action.get("command", "unknown")
                    print(f"  Step {step_count}: Agent commanded '{cmd}'")
                
                # Step 3: Environment Stepping
                step_resp = await client.post("/step", json=action)
                if step_resp.status_code != 200:
                    # e.g. validation error 422
                    error_msg = step_resp.text
                    if verbose: print(f"  [ERROR] /step rejected action: {error_msg}")
                    messages.append({"role": "assistant", "content": raw_content})
                    messages.append({"role": "user", "content": f"Action rejected: {error_msg}"})
                    continue
                
                step_data = step_resp.json()
                obs = step_data.get("observation", {})
                done = step_data.get("done", False)

                # Feed action + environment feedback into memory
                messages.append({"role": "assistant", "content": raw_content})
                # Step 4: Self-Correction Loop via observation error_message
                messages.append({"role": "user", "content": _obs_to_context(obs)})
            
            # Step 5: Score Retrieval
            grader_resp = await client.get("/grader")
            if grader_resp.status_code == 200:
                score = grader_resp.json().get("score", 0.0)
            else:
                if verbose: print(f"  [ERROR] /grader failed: {grader_resp.text}")
                score = 0.0

            scores[tier] = score
            if verbose:
                print(f"  => {tier} Tier Complete | Score: {score}")

    return scores


async def main() -> None:
    parser = argparse.ArgumentParser(description="Baseline ReAct agent evaluation")
    parser.add_argument("--model", default="gpt-4o-mini", help="OpenAI model to use")
    parser.add_argument("--server-url", default=os.getenv("SOC_SERVER_URL", "http://localhost:8000"))
    parser.add_argument("--quiet", action="store_true", help="Suppress output")
    args = parser.parse_args()

    try:
        results = await run_baseline_evaluation(
            model=args.model,
            server_url=args.server_url,
            verbose=not args.quiet
        )
        print(f"\n✅ Final Baseline Scores: {json.dumps(results, indent=2)}")
    except Exception as e:
        print(f"\n[FATAL] Baseline script failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
