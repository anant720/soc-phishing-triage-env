"""
Gradio Demo UI for the SOC Log Triage Environment.

Shows:
  - Incident alert + initial logs
  - Agent THINKING at each step
  - Tool called + full result
  - Live cumulative RL reward tracker (per-step signal)
  - Final grader score: every component shown with earned/max/status

Runs FastAPI (port 8001, internal) + Gradio (port 7860, external) in one process.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from typing import Generator

import gradio as gr
import httpx

# ---------------------------------------------------------------------------
# Start FastAPI server in a background thread
# ---------------------------------------------------------------------------
_FASTAPI_PORT = 8001
_SERVER_URL   = f"http://localhost:{_FASTAPI_PORT}"


def _find_free_port(start: int = 8001) -> int:
    import socket
    for port in range(start, start + 20):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('', port))
                return port
        except OSError:
            continue
    return start


def _start_fastapi() -> None:
    global _FASTAPI_PORT, _SERVER_URL
    _FASTAPI_PORT = _find_free_port(8001)
    _SERVER_URL   = f"http://localhost:{_FASTAPI_PORT}"
    import uvicorn
    uvicorn.run("server.app:app", host="0.0.0.0",
                port=_FASTAPI_PORT, log_level="error")


threading.Thread(target=_start_fastapi, daemon=True).start()
time.sleep(3)

# ---------------------------------------------------------------------------
# Grader component weights (must match grader.py)
# ---------------------------------------------------------------------------
W_VERDICT          = 0.30
W_TOOLS_MALICIOUS  = 0.25
W_TOOLS_BENIGN     = 0.35
W_ATTACK_TYPE      = 0.20
W_BACKUP_MALICIOUS = 0.15
W_NO_BAD_BACKUP    = 0.25
W_EFFICIENCY       = 0.10
PENALTY_FALSE_BACKUP      = -0.10
PENALTY_BACKUP_WRONG_HOST = -0.08


# ---------------------------------------------------------------------------
# Agent helpers
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are an autonomous Tier-1 SOC analyst investigating a Windows endpoint security incident.

You will receive a bundle of Sysmon logs and must:
1. THINK: write 1-3 sentences of analysis beginning with "THINKING:"
2. ACT: output a single JSON action on its own line beginning with "ACTION:"

Available tools:
  query_logs(query)             - keyword search across all logs
  analyze_process(process_name) - process tree for a named process
  check_ip_reputation(ip)       - threat-intel IP lookup (score 0.0=clean, 1.0=malicious)
  check_file_hash(hash)         - IOC lookup for a file hash
  get_host_summary(host)        - all events/IPs/processes on a host
  trigger_backup(host)          - REQUIRED on compromised hosts before verdict
  submit_verdict(verdict, attack_type, affected_hosts) - end episode

verdict values: malicious | benign | escalate
attack_type (required when malicious): c2_beacon | ransomware | lateral_movement | persistence | data_exfil

ALWAYS follow this format:
THINKING: [your 1-3 sentence analysis]
ACTION: {"command": "tool_name", "params": {"key": "value"}}

STRATEGY:
1. Query logs for suspicious keywords (powershell, EncodedCommand, vssadmin, wmic, curl, rclone)
2. Analyze suspicious processes to see parent/child chain
3. Check IPs/hashes against threat intel
4. trigger_backup on affected host(s) if malicious
5. submit_verdict with correct attack_type and affected_hosts
"""

TOOL_EMOJIS = {
    "query_logs":          "🔍",
    "analyze_process":     "🌲",
    "check_ip_reputation": "🌐",
    "check_file_hash":     "🔑",
    "get_host_summary":    "💻",
    "trigger_backup":      "💾",
    "submit_verdict":      "⚖️",
}


def _extract_thinking_and_action(text: str) -> tuple[str, dict | None]:
    thinking = ""
    action   = None
    tm = re.search(r"THINKING:\s*(.+?)(?=ACTION:|$)", text, re.DOTALL | re.IGNORECASE)
    if tm:
        thinking = tm.group(1).strip()
    am = re.search(r"ACTION:\s*(\{.*\})", text, re.DOTALL | re.IGNORECASE)
    if not am:
        am = re.search(r"(\{[^{}]*\"command\"[^{}]*\})", text, re.DOTALL)
    if am:
        try:
            action = json.loads(am.group(1))
        except json.JSONDecodeError:
            pass
    if not thinking and not am:
        thinking = text.strip()
    return thinking, action


def _format_logs_table(logs: list[dict]) -> str:
    if not logs:
        return "_No logs returned._"
    rows = ["| Time | Host | Event | Process | Domain/IP |",
            "|------|------|-------|---------|-----------|"]
    for lg in logs:
        ts     = str(lg.get("timestamp", ""))[-8:]
        host   = str(lg.get("host_id", ""))[-15:]
        ev     = str(lg.get("event_type", ""))
        proc   = str(lg.get("process", "") or "").split("\\")[-1][:28]
        domain = lg.get("target_domain") or lg.get("target_ip") or "-"
        rows.append(f"| `{ts}` | `{host}` | {ev} | `{proc}` | `{domain}` |")
    return "\n".join(rows)


def _format_tool_result(tool: str, result: dict) -> str:
    if tool == "query_logs":
        matches = result.get("matches", [])
        if not matches:
            return "_No logs matched this query._"
        total = result.get("total_matched", len(matches))
        return f"**Found {total} matching log(s):**\n\n" + _format_logs_table(matches)

    if tool == "analyze_process":
        nodes = result.get("tree", [])
        total = result.get("total_events", 0)
        hosts = result.get("hosts_seen_on", [])
        lines = [f"**{total} events** across: `{'`, `'.join(hosts)}`", ""]
        for n in nodes[:8]:
            cmd  = f" → `{n.get('commandline','')[:60]}`" if n.get("commandline") else ""
            par  = f"  _(parent: {n.get('parent_process','').split(chr(92))[-1]})_" if n.get("parent_process") else ""
            proc = n.get("process", "").split("\\")[-1]
            lines.append(f"- **`{proc}`**{cmd}{par}")
        return "\n".join(lines)

    if tool == "check_ip_reputation":
        score   = result.get("reputation_score", 0)
        cat     = result.get("category", "Unknown")
        country = result.get("country") or ""
        malware = result.get("known_malware") or ""
        bar     = "🟥" * int(score * 10) + "⬜" * (10 - int(score * 10))
        danger  = "🚨 **MALICIOUS**" if score > 0.7 else ("⚠️ Suspicious" if score > 0.3 else "✅ Clean")
        return (f"{danger}\n\n"
                f"Reputation: {bar} **{score:.2f}/1.00**\n\n"
                f"Category: `{cat}` | Country: `{country}` | Malware: `{malware or 'None'}`")

    if tool == "check_file_hash":
        is_mal = result.get("is_malicious", False)
        family = result.get("family") or "Unknown"
        sev    = result.get("severity") or ""
        found  = result.get("found", False)
        if not found:
            return "✅ Hash not found in IOC database — likely clean."
        icon = "🚨" if is_mal else "✅"
        return f"{icon} **{'MALICIOUS' if is_mal else 'Clean'}** | Family: `{family}` | Severity: `{sev}`"

    if tool == "get_host_summary":
        host  = result.get("host", "")
        total = result.get("total_events", 0)
        etypes = result.get("event_types", {})
        procs  = result.get("processes_seen", [])[:6]
        ips    = result.get("ips_contacted", [])
        lines  = [f"**`{host}`** — {total} total events", ""]
        lines.append("Event types: " + ", ".join(f"`{k}:{v}`" for k, v in etypes.items()))
        lines.append("Processes: " + ", ".join(f"`{p.split(chr(92))[-1]}`" for p in procs))
        if ips:
            lines.append("IPs contacted: " + ", ".join(f"`{i}`" for i in ips))
        return "\n".join(lines)

    if tool == "trigger_backup":
        bid = result.get("backup_id", "")[:8]
        return (f"💾 **Backup initiated** for `{result.get('host')}`\n\n"
                f"Backup ID: `{bid}...` | {result.get('message','')}")

    if tool == "submit_verdict":
        return "_Verdict submitted — episode ending…_"

    return f"```json\n{json.dumps(result, indent=2)[:800]}\n```"


def _reward_bar(cumulative: float) -> str:
    """Mini ASCII bar for cumulative reward."""
    capped = max(-1.0, min(1.5, cumulative))
    pct    = (capped + 1.0) / 2.5   # map [-1, 1.5] → [0, 1]
    filled = int(pct * 15)
    bar    = "▓" * filled + "░" * (15 - filled)
    color  = "🟢" if cumulative > 0.5 else ("🟡" if cumulative > 0 else "🔴")
    return f"{color} `[{bar}]` **{cumulative:+.3f}**"


# ---------------------------------------------------------------------------
# Main evaluation generator
# ---------------------------------------------------------------------------

def run_evaluation(
    api_key: str,
    base_url: str,
    model_name: str,
    tier: str,
) -> Generator[str, None, None]:
    from openai import OpenAI

    if not api_key.strip():
        yield "⚠️ **Please enter your API key first.**"
        return

    try:
        r = httpx.get(f"{_SERVER_URL}/health", timeout=5)
        r.raise_for_status()
    except Exception:
        yield "❌ **Environment server not ready. Wait a few seconds.**"
        return

    client = OpenAI(
        api_key=api_key.strip(),
        base_url=base_url.strip() if base_url.strip() else None,
    )

    output    = ""
    messages  = [{"role": "system", "content": SYSTEM_PROMPT}]
    cumul_rew = 0.0

    # ── Reset ──────────────────────────────────────────────────────────────
    try:
        resp = httpx.post(f"{_SERVER_URL}/reset",
                          params={"tier_filter": tier}, timeout=15)
        resp.raise_for_status()
        obs = resp.json()
    except Exception as e:
        yield f"❌ **Failed to start episode:** `{e}`"
        return

    max_steps    = obs.get("max_steps", 20)
    initial_logs = obs.get("initial_logs", [])

    # ── Incident header ────────────────────────────────────────────────────
    output  = f"# 🔐 SOC Incident Triage — **{tier} Tier**\n\n"
    output += "---\n\n"
    output += "## 📋 Incident Details\n\n"
    output += f"**🚨 Alert:** {obs.get('alert_summary')}\n\n"
    output += (f"- **Primary Host:** `{obs.get('primary_host')}`\n"
               f"- **Total Hosts:** {obs.get('host_count')}\n"
               f"- **Total Logs in DB:** {obs.get('log_count')} (agent must search to find them)\n"
               f"- **Max Steps Allowed:** {max_steps}\n\n")

    if initial_logs:
        output += f"### 📄 All {len(initial_logs)} Incident Logs (chronological)\n\n"
        output += _format_logs_table(initial_logs) + "\n\n"

    output += "> ℹ️ **Two separate scores run in parallel:**\n"
    output += "> - **Live RL Reward** (shown each step) = real-time training signal for reinforcement learning\n"
    output += "> - **Grader Score** (shown at end) = final deterministic 0.0–1.0 evaluation\n\n"
    output += "---\n\n## 🤖 Agent Investigation\n\n"
    yield output

    # ── Context for first user message ─────────────────────────────────────
    # UI shows ALL logs, but we cap LLM context to first 30 to stay within
    # rate limits. Agent must use tools (query_logs etc.) to investigate further.
    MAX_CTX_LOGS = 30
    ctx_logs = initial_logs[:MAX_CTX_LOGS]
    ctx  = f"INCIDENT: {obs.get('alert_summary')}\n"
    ctx += f"Host: {obs.get('primary_host')} | Total logs in bundle: {obs.get('log_count')}\n"
    ctx += f"(You can see the first {len(ctx_logs)} logs below. Use query_logs/get_host_summary to investigate the rest.)\n\n"
    ctx += f"First {len(ctx_logs)} logs (chronological):\n"
    for lg in ctx_logs:
        proc = str(lg.get("process") or "").split("\\")[-1][:40]
        ctx += (f"  [{lg.get('timestamp','')}] {lg.get('host_id','')} | "
                f"{lg.get('event_type','')} | {proc} | "
                f"cmd={str(lg.get('commandline') or '')[:50]} | "
                f"domain={lg.get('target_domain')} | ip={lg.get('target_ip')}\n")
    ctx += "\nBegin investigation."
    messages.append({"role": "user", "content": ctx})

    # ── Agent loop ─────────────────────────────────────────────────────────
    done     = False
    step_num = 0

    while not done and step_num < max_steps:
        step_num += 1

        # LLM call — auto-retry on 429 rate limit with exponential backoff
        raw = ""
        call_failed = False
        for attempt in range(4):
            try:
                resp_llm = client.chat.completions.create(
                    model=model_name,
                    messages=messages,
                    temperature=0.1,
                    max_tokens=600,
                )
                raw = resp_llm.choices[0].message.content or ""
                break   # success
            except Exception as e:
                err_str = str(e)
                if "429" in err_str or "rate limit" in err_str.lower() or "rate_limit" in err_str.lower():
                    wait_sec = (2 ** attempt) * 10   # 10s → 20s → 40s → 80s
                    output += (f"\n> ⏳ **Rate limit hit on step {step_num} "
                               f"(attempt {attempt+1}/4) — retrying in {wait_sec}s...**\n\n")
                    yield output
                    time.sleep(wait_sec)
                else:
                    output += f"\n> ⚠️ **LLM error step {step_num}:** `{err_str[:150]}`\n\n"
                    yield output
                    call_failed = True
                    break
        else:
            output += f"\n> ❌ **Rate limit — could not complete step {step_num} after 4 retries. Try a faster model (e.g. `llama-3.1-8b-instant`).**\n\n"
            yield output
            call_failed = True

        if call_failed:
            break

        thinking, action = _extract_thinking_and_action(raw)

        output += f"### Step {step_num} / {max_steps}\n\n"

        if thinking:
            output += f"> 💭 **Agent Thinking:**\n> {thinking}\n\n"

        if action is None:
            output += f"> ⚠️ Could not parse action — retrying.\n\n```\n{raw[:200]}\n```\n\n"
            yield output
            messages.append({"role": "assistant", "content": raw})
            messages.append({"role": "user", "content":
                "Output must follow:\nTHINKING: [analysis]\nACTION: {\"command\":\"...\",\"params\":{...}}"})
            continue

        cmd       = action.get("command", "?")
        params    = action.get("params", {})
        emoji     = TOOL_EMOJIS.get(cmd, "🔧")
        params_str = json.dumps(params)

        output += f"**{emoji} Tool called:** `{cmd}`\n\n"
        output += f"**Parameters:** `{params_str[:100]}`\n\n"
        yield output

        try:
            step_resp = httpx.post(f"{_SERVER_URL}/step", json=action, timeout=20)
            step_data = step_resp.json()
        except Exception as e:
            output += f"> ❌ Env error: `{e}`\n\n"
            yield output
            break

        obs_new = step_data.get("observation", {})
        reward  = step_data.get("reward", 0.0)
        done    = step_data.get("done", False)
        err_msg = obs_new.get("error_message")
        cumul_rew = round(cumul_rew + reward, 4)

        if err_msg:
            output += f"> ❌ **Environment rejected action:** {err_msg}\n\n"
        elif obs_new.get("tool_result"):
            output += f"**📊 Tool Result:**\n\n"
            output += _format_tool_result(cmd, obs_new["tool_result"]) + "\n\n"

        # Live reward tracker
        output += "**📈 Live RL Reward Tracker** _(training signal, not grader score)_\n\n"
        output += f"| This step | Cumulative so far |\n|-----------|-------------------|\n"
        step_sign = "+" if reward >= 0 else ""
        output += f"| `{step_sign}{reward:.4f}` | {_reward_bar(cumul_rew)} |\n\n"
        output += (f"_Step reward breakdown: unique_tool=+0.05 if new, "
                   f"step_penalty=−0.02, verdict_reward on submit_verdict_\n\n")

        if done:
            output += "✅ **Episode complete — fetching grader score...**\n\n"

        output += "---\n\n"
        yield output

        next_ctx  = f"Step {step_num} result for `{cmd}`:\n"
        next_ctx += f"ERROR: {err_msg}\n" if err_msg else ""
        if obs_new.get("tool_result"):
            next_ctx += json.dumps(obs_new["tool_result"])[:800] + "\n"
        next_ctx += (f"\nProgress: step {step_num}/{max_steps} | "
                     f"tools_used: {obs_new.get('tools_used',[])} | "
                     f"backups: {obs_new.get('backup_triggered_hosts',[])} | "
                     f"verdict_submitted: {obs_new.get('verdict_submitted',False)}")
        if not done:
            next_ctx += "\n\nContinue investigation or submit verdict."

        messages.append({"role": "assistant", "content": raw})
        messages.append({"role": "user",      "content": next_ctx})
        obs = obs_new

    # ── Final grader score ─────────────────────────────────────────────────
    output += "---\n\n## 🏆 Final Grader Score\n\n"
    output += "> The grader is a **deterministic end-of-episode evaluator** (0.0–1.0).\n"
    output += "> It does NOT sum per-step rewards. Each component is scored independently.\n\n"

    try:
        grade_resp = httpx.get(f"{_SERVER_URL}/grader", timeout=10)
        gdata = grade_resp.json()
    except Exception as e:
        output += f"❌ Could not get grader score: `{e}`\n"
        yield output
        return

    score     = gdata.get("score", 0.0)
    correct   = gdata.get("correct", False)
    breakdown = gdata.get("breakdown", {})
    deductions = gdata.get("deductions", [])

    # Big score display
    filled = int(score * 20)
    bar    = "█" * filled + "░" * (20 - filled)
    emoji  = "🟢" if score >= 0.8 else ("🟡" if score >= 0.5 else "🔴")
    output += f"### {emoji} `{bar}` &nbsp; **{score:.4f} / 1.0000**\n\n"

    # Get ground truth from grader
    exp_verdict = gdata.get("expected_verdict", "?")
    exp_attack  = gdata.get("expected_attack_type", "?")
    final_verdict = gdata.get("final_verdict", "not submitted")
    final_attack  = gdata.get("final_attack_type", "not provided")
    is_malicious  = (exp_verdict == "malicious")

    # Component-by-component breakdown
    output += "### 📋 Score Component Breakdown\n\n"
    output += "| # | Component | Max Available | Earned / Penalty | Status |\n"
    output += "|---|-----------|:---:|:---:|:---:|\n"

    running = 0.0
    rows = []

    # 1. Verdict (correct or wrong_verdict_penalty)
    v_earned = breakdown.get("verdict", 0.0)
    v_penalty = breakdown.get("wrong_verdict_penalty", 0.0)
    running += v_earned + v_penalty
    v_ok = v_earned >= W_VERDICT - 0.001
    if v_ok:
        rows.append(("1", "⚖️ Correct Verdict",
                     f"`+{W_VERDICT:.2f}`", f"`+{v_earned:.2f}`", "✅"))
    else:
        rows.append(("1", "⚖️ Verdict (WRONG)",
                     f"`+{W_VERDICT:.2f}`", f"`{v_penalty:.2f}` penalty", "❌"))

    # 2. Investigation tools
    t_earned  = breakdown.get("tools", 0.0)
    t_penalty = breakdown.get("no_investigation_penalty", 0.0)
    running  += t_earned + t_penalty
    t_max = W_TOOLS_BENIGN if not is_malicious else W_TOOLS_MALICIOUS
    t_ok  = t_earned >= t_max - 0.001
    rows.append((
        "2", "🔍 Investigation Tools (proportional)",
        f"`+{t_max:.2f}`",
        f"`+{t_earned:.2f}`" if not t_penalty else f"`+{t_earned:.2f}` + `{t_penalty:.2f}` penalty",
        "✅" if t_ok else ("⚠️" if t_earned > 0 else "❌")
    ))
    if t_penalty < 0:
        rows.append(("⚠️", "Penalty: Zero investigation (no tools used)",
                     "—", f"`{t_penalty:.2f}`", "❌"))

    # Rush penalty (if any)
    rush_penalty = breakdown.get("rush_penalty", 0.0)
    running += rush_penalty
    if rush_penalty < 0:
        rows.append(("⚠️", "Penalty: Rush verdict (too fast, too few tools)",
                     "—", f"`{rush_penalty:.2f}`", "❌"))

    # 3. Attack type (malicious only)
    if is_malicious:
        a_earned = breakdown.get("attack_type", 0.0)
        running += a_earned
        a_ok = a_earned >= W_ATTACK_TYPE - 0.001
        rows.append((
            "3", "🎯 Attack Type Classification",
            f"`+{W_ATTACK_TYPE:.2f}`",
            f"`+{a_earned:.2f}`",
            "✅" if a_ok else "❌"
        ))
    else:
        rows.append(("3", "🎯 Attack Type", "`N/A`", "`N/A`", "—"))

    # 4. Backup
    b_earned   = breakdown.get("backup", 0.0)
    false_bk   = breakdown.get("false_backup_penalty", 0.0)
    wrong_host = breakdown.get("backup_wrong_host_penalty", 0.0)
    running   += b_earned + false_bk + wrong_host
    b_max = W_BACKUP_MALICIOUS if is_malicious else W_NO_BAD_BACKUP
    b_ok  = b_earned >= b_max - 0.001
    backup_label = "💾 Backup on Correct Host" if is_malicious else "✅ No False Backup"
    rows.append((
        "4", backup_label,
        f"`+{b_max:.2f}`",
        f"`+{b_earned:.2f}`",
        "✅" if b_ok else "❌"
    ))
    if false_bk < 0:
        rows.append(("⚠️", "Penalty: Backup on benign (false positive)",
                     "—", f"`{false_bk:.2f}`", "❌"))
    if wrong_host < 0:
        rows.append(("⚠️", "Penalty: Backup on wrong host",
                     "—", f"`{wrong_host:.2f}`", "❌"))

    # 5. Efficiency
    e_earned = breakdown.get("efficiency", 0.0)
    running += e_earned
    e_ok = e_earned >= W_EFFICIENCY - 0.001
    rows.append((
        "5", f"⏱️ Step Efficiency ({gdata.get('step_count',0)}/{max_steps} steps)",
        f"`{W_EFFICIENCY:.2f}`",
        f"`{e_earned:.2f}`",
        "✅" if e_ok else ("⚠️" if e_earned > 0 else ("❌" if e_earned < 0 else "〰️"))
    ))

    for row in rows:
        output += f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} |\n"

    output += f"| | **TOTAL** | **`1.00`** | **`{score:.4f}`** | {'✅' if score >= 0.9 else ('🟡' if score >= 0.6 else '🔴')} |\n\n"

    # Score calculation math
    output += "### 🔢 Score Calculation (Pre-Clamp → Final)\n\n"
    raw_score = breakdown.get("raw_score", score)
    output += "```\n"
    output += f"  {'Verdict (correct)' if v_ok else 'Verdict (wrong)':28s}: {v_earned:+.4f}\n"
    if v_penalty < 0:
        output += f"  {'  ↳ Wrong verdict penalty':28s}: {v_penalty:+.4f}\n"
    output += f"  {'Tools (' + str(int(t_earned/t_max*100 if t_max else 0)) + '% coverage)':28s}: {t_earned:+.4f}\n"
    if t_penalty < 0:
        output += f"  {'  ↳ No investigation penalty':28s}: {t_penalty:+.4f}\n"
    if rush_penalty < 0:
        output += f"  {'  ↳ Rush penalty':28s}: {rush_penalty:+.4f}\n"
    if is_malicious:
        output += f"  {'Attack type':28s}: {breakdown.get('attack_type', 0.0):+.4f}\n"
    output += f"  {'Backup':28s}: {b_earned:+.4f}\n"
    if false_bk < 0:
        output += f"  {'  ↳ False backup penalty':28s}: {false_bk:+.4f}\n"
    if wrong_host < 0:
        output += f"  {'  ↳ Wrong host penalty':28s}: {wrong_host:+.4f}\n"
    output += f"  {'Efficiency':28s}: {e_earned:+.4f}\n"
    output += f"  {'─'*35}\n"
    output += f"  {'Raw total (pre-clamp)':28s}:  {raw_score:.4f}\n"
    output += f"  {'Final (clamped 0→1)':28s}:  {score:.4f}\n"
    output += "```\n\n"

    # Ground truth vs agent
    output += "### 🔍 Ground Truth vs Agent\n\n"
    output += "| | Expected | Agent Submitted | Match |\n"
    output += "|--|----------|-----------------|-------|\n"
    output += f"| Verdict | `{exp_verdict}` | `{final_verdict}` | {'✅' if exp_verdict == final_verdict else '❌'} |\n"
    output += f"| Attack Type | `{exp_attack}` | `{final_attack}` | {'✅' if exp_attack == final_attack else ('— ' if exp_verdict == 'benign' else '❌')} |\n\n"

    # What happened per step (tool usage summary)
    tools_used = gdata.get("tools_used", [])
    output += f"**Tools used this episode:** {', '.join(f'`{t}`' for t in tools_used) or '_none_'}\n\n"

    # Deductions explanation
    if deductions:
        output += "### ⚠️ Why Points Were Not Earned\n\n"
        for d in deductions:
            output += f"- {d}\n"
        output += "\n"
    else:
        output += "### ✅ Perfect Investigation!\n\n"
        output += "All 5 components fully earned. Score = 1.0000\n\n"

    # Comparison between RL reward and grader
    output += "---\n\n### ℹ️ RL Reward vs Grader Score Explained\n\n"
    output += ("| | Live RL Reward | Grader Score |\n"
               "|--|---|---|\n"
               "| **Purpose** | Train the agent (RL signal) | Evaluate agent quality |\n"
               "| **When given** | After every single step | Once, at end of episode |\n"
               f"| **This episode** | `{cumul_rew:+.4f}` cumulative | `{score:.4f} / 1.0000` |\n"
               "| **Can exceed 1.0?** | Yes (small per-step bonuses add up) | No — always capped at 1.0 |\n\n")

    yield output


# ---------------------------------------------------------------------------
# Gradio UI
# ---------------------------------------------------------------------------

def build_ui() -> gr.Blocks:
    with gr.Blocks(title="SOC Log Triage — AI Agent Demo") as demo:

        gr.Markdown("""
# 🔐 Autonomous SOC Log Triage — Interactive Agent Demo

> **OpenEnv-compliant** RL environment for cybersecurity triage. The agent investigates
> Windows Sysmon log bundles, reasons about threats, triggers backups, and submits a
> classified verdict — all scored transparently with component-level breakdown.

---
        """)

        with gr.Row():
            # ── Left panel ─────────────────────────────────────────────────
            with gr.Column(scale=1, min_width=310):
                gr.Markdown("### ⚙️ Agent Configuration")

                api_key = gr.Textbox(
                    label="🔑 API Key",
                    placeholder="sk-... (OpenAI) | gsk_... (Groq) | ollama (local)",
                    type="password",
                    info="OpenAI, Groq, Together, Ollama — any OpenAI-compatible endpoint",
                )
                base_url = gr.Textbox(
                    label="🌐 API Base URL",
                    value="",
                    placeholder="Blank = OpenAI. Groq: https://api.groq.com/openai/v1",
                    info="Ollama: http://localhost:11434/v1",
                )
                model_name = gr.Textbox(
                    label="🤖 Model",
                    value="llama-3.1-8b-instant",
                    placeholder="llama-3.1-8b-instant (Groq) / gpt-4o-mini / qwen2.5:7b",
                    info=(
                        "Groq free: llama-3.1-8b-instant (fastest, high limits) "
                        "or llama-3.3-70b-versatile (slower, lower rate limit). "
                        "OpenAI: gpt-4o-mini. Local: qwen2.5:7b"
                    ),
                )
                tier = gr.Radio(
                    choices=["Easy", "Medium", "Hard"],
                    value="Easy",
                    label="🎯 Difficulty Tier",
                    info="Easy: ~50 logs · Medium: ~100 logs · Hard: ~200 logs",
                )
                run_btn = gr.Button("▶  Run Evaluation", variant="primary", size="lg")

                gr.Markdown("""
---
### 📊 Grader Components (v3)

**MALICIOUS episode** — max = 1.00
| Component | Max |
|-----------|-----|
| ⚖️ Correct verdict | `+0.30` |
| 🔍 Investigation tools | `+0.25` (proportional) |
| 🎯 Correct attack type | `+0.20` |
| 💾 Backup on correct host | `+0.15` |
| ⏱️ Step efficiency | `+0.10` |
| **TOTAL** | **1.00** |

**BENIGN episode** — max = 1.00
| Component | Max |
|-----------|-----|
| ⚖️ Correct verdict | `+0.30` |
| 🔍 Investigation tools | `+0.35` (proportional) |
| ✅ Did NOT trigger backup | `+0.25` |
| ⏱️ Step efficiency | `+0.10` |
| **TOTAL** | **1.00** |

**Penalties**
| Penalty | Amount |
|---------|--------|
| ❌ Wrong verdict | `−0.25` |
| 🔍 Zero investigation | `−0.20` |
| 🏃 Rush verdict (fast + no tools) | `−0.10` |
| 💾 Backup on benign | `−0.10` |
| 💾 Backup wrong host | `−0.08` |
| ⏱️ Steps beyond hard limit | `−0.05` |

**Attack types:** `c2_beacon` · `ransomware`
`lateral_movement` · `persistence` · `data_exfil`
                """)

            # ── Right panel ────────────────────────────────────────────────
            with gr.Column(scale=2):
                gr.Markdown("### 🖥️ Live Agent Output")
                output_md = gr.Markdown(
                    value=(
                        "**Configure the agent on the left and click ▶ Run Evaluation.**\n\n"
                        "You will see:\n"
                        "- 📋 Incident details + first logs\n"
                        "- 💭 Agent thinking at each step\n"
                        "- 📊 Tool result for every action\n"
                        "- 📈 Live RL reward after each step\n"
                        "- 🏆 Final grader breakdown (every component)"
                    ),
                    height=950,
                )

        run_btn.click(
            fn=run_evaluation,
            inputs=[api_key, base_url, model_name, tier],
            outputs=output_md,
        )

        gr.Markdown("""
---
<div style='text-align:center;opacity:0.5;font-size:0.8em'>
OpenEnv-compliant · FastAPI + Gradio · 340 incidents · 53,000+ Sysmon logs · 5 attack types
</div>
        """)

    return demo


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    demo = build_ui()
    demo.launch(
        server_name="0.0.0.0",
        server_port=port,
        show_error=True,
        share=False,
        theme=gr.themes.Soft(primary_hue="red", secondary_hue="orange"),
        css="""
            footer { display: none !important; }
            .primary { background: linear-gradient(135deg,#c0392b,#e74c3c) !important; }
        """,
    )
