"""
inference.py — required entry point for the OpenEnv hackathon validator.

This is the script the automated checker runs to verify that a real agent
can connect to the environment, call tools, submit a verdict, and get scored.

It implements a simple rule-based agent (no LLM needed) that:
  1. Resets the environment and reads the email observation
  2. Calls the right investigation tool based on the difficulty tier
  3. Submits a verdict based on what the tool returns
  4. Prints the grader score

To run against a live server:
    python inference.py --url http://localhost:7860

The hackathon validator calls this with no arguments against the deployed Space.
"""

from __future__ import annotations

import argparse
import json
import sys

import requests

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_URL = "http://localhost:7860"


# ---------------------------------------------------------------------------
# A dead-simple rule-based agent
# (no LLM, no API key — just deterministic tool use for validation)
# ---------------------------------------------------------------------------

def run_episode(base_url: str, tier: str = "all") -> dict:
    """
    Runs one full episode against the environment and returns the grader result.

    The agent strategy is deliberately simple:
      - Easy  → sandbox_url to detonate the link
      - Medium → analyze_headers to check SPF/DKIM
      - Hard  → analyze_headers + sandbox_url (both signals needed)
      - unknown → analyze_headers as a safe default
    """

    # 1. start a fresh episode
    resp = requests.post(f"{base_url}/reset", params={"tier_filter": tier}, timeout=10)
    resp.raise_for_status()
    obs = resp.json()

    email_id    = obs["email_id"]
    email_tier  = obs.get("difficulty_tier", "Hard")
    subject     = obs.get("email_subject", "(no subject)")

    print(f"\n📧 Email: {subject}")
    print(f"   Tier: {email_tier}  |  ID: {email_id}")

    # pick investigation strategy based on tier
    if email_tier == "Easy":
        tool_sequence = [
            {"command": "sandbox_url",         "params": {"url": f"http://example-phish-{email_id}.com"}},
            {"command": "lookup_threat_intel",  "params": {"domain": f"phish-{email_id}.com"}},
        ]
    elif email_tier == "Medium":
        tool_sequence = [
            {"command": "analyze_headers", "params": {"email_id": email_id}},
        ]
    else:  # Hard — use both
        tool_sequence = [
            {"command": "analyze_headers",      "params": {"email_id": email_id}},
            {"command": "sandbox_url",          "params": {"url": f"http://example-{email_id}.com"}},
        ]

    # 2. call each investigation tool
    spf_fail = False
    dkim_fail = False
    suspicious_url = False

    for action in tool_sequence:
        r = requests.post(f"{base_url}/step", json=action, timeout=10)
        if r.status_code == 422:
            # schema rejected — skip this tool
            print(f"   ⚠  Tool {action['command']} rejected (422), skipping")
            continue
        r.raise_for_status()
        result = r.json()
        tool_result = result.get("observation", {}).get("tool_result", {}) or {}

        print(f"   🔧 {action['command']} → reward {result.get('reward', 0):+.2f}")

        # read signals from the tool output
        if action["command"] == "analyze_headers":
            spf_fail  = tool_result.get("spf_status",  "Pass") in ("Fail", "Softfail")
            dkim_fail = tool_result.get("dkim_status", "Pass") in ("Fail", "Softfail")
        elif action["command"] in ("sandbox_url", "lookup_threat_intel"):
            malicious   = tool_result.get("verdict",          "") == "malicious"
            risk_high   = tool_result.get("risk_score",    0.0) >= 0.7
            suspicious_url = malicious or risk_high

    # 3. decide verdict based on collected signals
    if email_tier == "Easy":
        verdict = "phishing" if suspicious_url else "benign"
    elif email_tier == "Medium":
        verdict = "phishing" if (spf_fail or dkim_fail) else "benign"
    else:  # Hard
        # when in doubt on Hard, lean toward escalating rather than guessing
        verdict = "phishing" if (spf_fail or dkim_fail or suspicious_url) else "escalate"

    print(f"   📝 Verdict: {verdict}")

    # 4. submit verdict
    r = requests.post(f"{base_url}/step", json={
        "command": "submit_verdict",
        "params":  {"verdict": verdict}
    }, timeout=10)
    r.raise_for_status()
    step_result = r.json()
    print(f"   ✅ Episode done  |  reward {step_result.get('reward', 0):+.2f}")

    # 5. get grader score
    grader = requests.get(f"{base_url}/grader", timeout=10).json()
    return grader


# ---------------------------------------------------------------------------
# Main — runs one episode per tier then prints the summary
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="OpenEnv inference entry point — SOC Triage")
    parser.add_argument("--url",   default=DEFAULT_URL, help="Environment base URL")
    parser.add_argument("--tier",  default="all",       help="Tier filter: Easy | Medium | Hard | all")
    parser.add_argument("--episodes", type=int, default=1, help="Number of episodes to run")
    args = parser.parse_args()

    # health check first
    try:
        health = requests.get(f"{args.url}/health", timeout=5).json()
        print(f"🌐 Connected to {args.url}  (v{health.get('version', '?')})")
    except Exception as e:
        print(f"❌ Cannot reach environment at {args.url}: {e}")
        sys.exit(1)

    total_score = 0.0
    total_correct = 0

    for i in range(args.episodes):
        print(f"\n{'='*50}")
        print(f"  Episode {i+1}/{args.episodes}")
        print(f"{'='*50}")

        result = run_episode(args.url, tier=args.tier)

        score   = result.get("score",   0.0)
        correct = result.get("correct", False)
        tier    = result.get("tier",    "?")

        total_score   += score
        total_correct += int(correct)

        print(f"\n  Grader score: {score:.4f}  |  correct={correct}  |  tier={tier}")
        if result.get("deductions"):
            for d in result["deductions"]:
                print(f"  ⚡ {d}")

    # summary
    print(f"\n{'='*50}")
    print(f"  SUMMARY  ({args.episodes} episode(s))")
    print(f"  Avg score : {total_score / args.episodes:.4f}")
    print(f"  Accuracy  : {total_correct}/{args.episodes}")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()
