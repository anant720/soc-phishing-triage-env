"""
Simulated log-analysis tools for the SOC Log Triage Environment.

Each tool queries the triage_scenarios.db (incident_bundles, sysmon_endpoint_logs,
threat_intel_ips, file_hashes tables) and returns a typed result dict.

The `is_malicious` column is NEVER included in any result returned to the agent.
"""
from __future__ import annotations

import json
import random
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any

from models import (
    AnalyzeProcessResult,
    BackupResult,
    FileHashResult,
    HostSummaryResult,
    IPReputationResult,
    LogEntry,
    ProcessTreeNode,
    QueryLogsResult,
)

# Keep is_malicious out of everything the agent sees
_SAFE_LOG_COLUMNS = (
    "id", "host_id", "timestamp", "event_type", "process",
    "commandline", "target_ip", "target_domain", "parent_process", "details"
)
_SAFE_SELECT = ", ".join(_SAFE_LOG_COLUMNS)


def _row_to_log_entry(row: Any) -> LogEntry:
    d = dict(zip(_SAFE_LOG_COLUMNS, row))
    return LogEntry(**d)


def _query_logs(params: dict[str, Any], db_conn: sqlite3.Connection,
                log_ids: list[int]) -> dict[str, Any]:
    """
    Keyword search over the incident's log bundle.
    Searches: process, commandline, target_domain, target_ip, parent_process, details.
    """
    query = str(params.get("query", "")).strip()
    if not query:
        raise ValueError("'query' parameter is required and must be non-empty.")

    t0 = random.randint(5, 80)
    id_placeholders = ",".join("?" * len(log_ids))
    pattern = f"%{query}%"

    sql = f"""
        SELECT {_SAFE_SELECT} FROM sysmon_endpoint_logs
        WHERE id IN ({id_placeholders})
          AND (
            process       LIKE ? COLLATE NOCASE OR
            commandline   LIKE ? COLLATE NOCASE OR
            target_domain LIKE ? COLLATE NOCASE OR
            target_ip     LIKE ? COLLATE NOCASE OR
            parent_process LIKE ? COLLATE NOCASE OR
            details       LIKE ? COLLATE NOCASE
          )
        ORDER BY timestamp
        LIMIT 20
    """
    rows = db_conn.execute(sql, log_ids + [pattern] * 6).fetchall()
    entries = [_row_to_log_entry(r) for r in rows]

    return QueryLogsResult(
        query=query,
        matches=entries,
        total_found=len(entries),
        query_time_ms=t0,
    ).model_dump()


def _analyze_process(params: dict[str, Any], db_conn: sqlite3.Connection,
                     log_ids: list[int]) -> dict[str, Any]:
    """
    Return all log entries where process LIKE %<process_name>% inside this incident,
    plus a simple parent→child tree.
    """
    proc_name = str(params.get("process_name", "")).strip()
    if not proc_name:
        raise ValueError("'process_name' parameter is required.")

    id_placeholders = ",".join("?" * len(log_ids))
    rows = db_conn.execute(
        f"""SELECT {_SAFE_SELECT} FROM sysmon_endpoint_logs
            WHERE id IN ({id_placeholders})
              AND process LIKE ? COLLATE NOCASE
            ORDER BY timestamp""",
        log_ids + [f"%{proc_name}%"],
    ).fetchall()

    entries = [_row_to_log_entry(r) for r in rows]
    hosts = list({e.host_id for e in entries})

    # Build a shallow tree (one level of parent→child)
    tree: list[ProcessTreeNode] = []
    for e in entries:
        node = ProcessTreeNode(
            host_id=e.host_id,
            process=e.process or "",
            commandline=e.commandline,
            parent_process=e.parent_process,
            timestamp=e.timestamp,
        )
        tree.append(node)

    return AnalyzeProcessResult(
        process_name=proc_name,
        hosts_seen_on=hosts,
        tree=tree,
        total_events=len(entries),
    ).model_dump()


def _check_ip_reputation(params: dict[str, Any],
                          db_conn: sqlite3.Connection) -> dict[str, Any]:
    """Look up an IP in the threat_intel_ips table."""
    ip = str(params.get("ip", "")).strip()
    if not ip:
        raise ValueError("'ip' parameter is required.")

    row = db_conn.execute(
        """SELECT ip, reputation_score, category, country, asn, known_malware,
                  first_seen, last_seen
           FROM threat_intel_ips WHERE ip = ?""",
        (ip,),
    ).fetchone()

    if row:
        return IPReputationResult(
            ip=ip, found=True,
            reputation_score=row[1], category=row[2], country=row[3],
            asn=row[4], known_malware=row[5], first_seen=row[6], last_seen=row[7],
        ).model_dump()

    # Not in DB — return clean result
    return IPReputationResult(ip=ip, found=False, reputation_score=0.0,
                               category="Unknown").model_dump()


def _check_file_hash(params: dict[str, Any],
                      db_conn: sqlite3.Connection) -> dict[str, Any]:
    """Look up a file hash in the file_hashes IOC table."""
    file_hash = str(params.get("hash", "")).strip()
    if not file_hash:
        raise ValueError("'hash' parameter is required.")

    row = db_conn.execute(
        "SELECT hash, filename, is_malicious, family, severity FROM file_hashes WHERE hash = ?",
        (file_hash,),
    ).fetchone()

    if row:
        return FileHashResult(
            hash=file_hash, found=True, filename=row[1],
            is_malicious=bool(row[2]), family=row[3], severity=row[4],
        ).model_dump()

    return FileHashResult(hash=file_hash, found=False, is_malicious=False).model_dump()


def _get_host_summary(params: dict[str, Any], db_conn: sqlite3.Connection,
                       log_ids: list[int]) -> dict[str, Any]:
    """Return a summary of all activity on a specific host within this incident."""
    host = str(params.get("host", "")).strip()
    if not host:
        raise ValueError("'host' parameter is required.")

    id_placeholders = ",".join("?" * len(log_ids))
    rows = db_conn.execute(
        f"""SELECT {_SAFE_SELECT} FROM sysmon_endpoint_logs
            WHERE id IN ({id_placeholders}) AND host_id = ?
            ORDER BY timestamp""",
        log_ids + [host],
    ).fetchall()

    if not rows:
        raise ValueError(f"Host '{host}' not found in this incident bundle. "
                         f"Check the host names from the initial_logs.")

    entries = [_row_to_log_entry(r) for r in rows]

    event_types: dict[str, int] = {}
    processes: list[str] = []
    ips: list[str] = []
    domains: list[str] = []
    for e in entries:
        event_types[e.event_type] = event_types.get(e.event_type, 0) + 1
        if e.process and e.process not in processes:
            processes.append(e.process)
        if e.target_ip and e.target_ip not in ips:
            ips.append(e.target_ip)
        if e.target_domain and e.target_domain not in domains:
            domains.append(e.target_domain)

    return HostSummaryResult(
        host=host,
        total_events=len(entries),
        event_types=event_types,
        processes_seen=processes[:20],
        ips_contacted=ips[:10],
        domains_contacted=domains[:10],
        sample_logs=entries[:8],
    ).model_dump()


def _trigger_backup(params: dict[str, Any],
                     db_conn: sqlite3.Connection) -> dict[str, Any]:
    """Simulate triggering an emergency backup on a host."""
    host = str(params.get("host", "")).strip()
    if not host:
        raise ValueError("'host' parameter is required.")

    return BackupResult(
        host=host,
        status="initiated",
        backup_id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        message=f"Emergency snapshot initiated for {host}. ETA: ~3 minutes.",
    ).model_dump()


# ---------------------------------------------------------------------------
# Public dispatch table
# ---------------------------------------------------------------------------

def run_tool(
    tool_name: str,
    params: dict[str, Any],
    db_conn: sqlite3.Connection,
    log_ids: list[int] | None = None,
) -> dict[str, Any]:
    """
    Dispatch a tool call and return a serialisable dict result.

    Raises ValueError on bad params (caught by environment.step() for -0.1 penalty).
    """
    log_ids = log_ids or []

    dispatch = {
        "query_logs":          lambda: _query_logs(params, db_conn, log_ids),
        "analyze_process":     lambda: _analyze_process(params, db_conn, log_ids),
        "check_ip_reputation": lambda: _check_ip_reputation(params, db_conn),
        "check_file_hash":     lambda: _check_file_hash(params, db_conn),
        "get_host_summary":    lambda: _get_host_summary(params, db_conn, log_ids),
        "trigger_backup":      lambda: _trigger_backup(params, db_conn),
    }

    handler = dispatch.get(tool_name)
    if handler is None:
        raise ValueError(f"Unknown tool '{tool_name}'.")
    return handler()
