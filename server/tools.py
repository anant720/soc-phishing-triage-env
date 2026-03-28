"""
Simulated SOC Tool Implementations.

Each tool is a pure function that accepts structured parameters and
returns a Pydantic result model.  Tools read from the static data/
JSON files so there are no live network calls — making the environment
fully reproducible and deterministic (with controlled ±5 % noise).
"""

from __future__ import annotations

import json
import math
import random
from pathlib import Path
from typing import Any

from models import (
    HeaderAnalysisResult,
    SandboxResult,
    ThreatIntelResult,
    WhoisResult,
)

# ---------------------------------------------------------------------------
# Data loading helpers
# ---------------------------------------------------------------------------

# Use absolute data path relative to execution root
_DATA_DIR = Path("data").resolve()


def _load_emails() -> dict[str, Any]:
    path = _DATA_DIR / "phishing_emails.json"
    with path.open() as f:
        emails: list[dict[str, Any]] = json.load(f)
    return {e["id"]: e for e in emails}


def _load_threat_db() -> dict[str, Any]:
    path = _DATA_DIR / "threat_intel_db.json"
    with path.open() as f:
        return json.load(f)


# Lazily loaded singletons
_EMAIL_DB: dict[str, Any] | None = None
_THREAT_DB: dict[str, Any] | None = None


def _emails() -> dict[str, Any]:
    global _EMAIL_DB
    if _EMAIL_DB is None:
        _EMAIL_DB = _load_emails()
    return _EMAIL_DB


def _threat() -> dict[str, Any]:
    global _THREAT_DB
    if _THREAT_DB is None:
        _THREAT_DB = _load_threat_db()
    return _THREAT_DB


# ---------------------------------------------------------------------------
# Noise helper
# ---------------------------------------------------------------------------

def _jitter(value: float, pct: float = 0.05) -> float:
    """Add ±pct relative noise to a float while clamping to [0, 1]."""
    delta = value * pct * random.uniform(-1.0, 1.0)
    return round(min(1.0, max(0.0, value + delta)), 4)


# ===========================================================================
# Tool 1 — Email Header Analyzer
# ===========================================================================

def analyze_headers(
    email_id: str,
    _header_override: dict[str, Any] | None = None,
) -> HeaderAnalysisResult:
    """
    Parse email headers for email_id.

    If *_header_override* is provided (injected by the environment when
    the scenario was loaded from the Phase 2 SQLite DB), it is used
    directly instead of looking up the JSON file.

    Raises
    ------
    ValueError
        If email_id is not found in the static dataset AND no override given.
    """
    if _header_override:
        headers = _header_override
    else:
        db = _emails()
        if email_id not in db:
            raise ValueError(
                f"Unknown email_id: '{email_id}'. "
                f"Valid IDs: {list(db.keys())}"
            )
        headers = db[email_id].get("header_data", {})

    flags: list[str] = list(headers.get("suspicious_flags", []))

    spf   = headers.get("spf_status",        "none")
    dkim  = headers.get("dkim_status",        "none")
    dmarc = headers.get("dmarc_status",       "none")
    reply_mismatch = headers.get("reply_to_mismatch", False)

    if spf.lower()   != "pass": flags.append("SPF_FAIL")
    if dkim.lower()  != "pass": flags.append("DKIM_FAIL")
    if dmarc.lower() != "pass": flags.append("DMARC_FAIL")
    if reply_mismatch:           flags.append("REPLY_TO_MISMATCH")

    return HeaderAnalysisResult(
        spf_status=spf,
        dkim_status=dkim,
        dmarc_status=dmarc,
        reply_to_mismatch=bool(reply_mismatch),
        originating_ip=headers.get("originating_ip", "0.0.0.0"),
        ip_geolocation=headers.get("ip_geolocation", "Unknown"),
        suspicious_flags=list(set(flags)),
    )


# ===========================================================================
# Tool 2 — Threat Intelligence Lookup
# ===========================================================================

def lookup_threat_intel(domain: str) -> ThreatIntelResult:
    """
    Look up a domain (or bare IP) in the simulated threat-intel database.
    Returns a default clean record if the domain is not known.
    """
    db = _threat()
    domains: list[dict[str, Any]] = db.get("domains", [])

    # Exact match first, then substring match
    record = next((d for d in domains if d["domain"] == domain), None)
    if record is None:
        record = next(
            (d for d in domains if domain in d["domain"] or d["domain"] in domain),
            None,
        )

    if record is None:
        # Unknown domain — return a neutral record
        return ThreatIntelResult(
            domain=domain,
            reputation_score=0.05,
            known_malware_families=[],
            first_seen="N/A",
            last_seen="N/A",
            tags=["unknown"],
        )

    return ThreatIntelResult(
        domain=record["domain"],
        reputation_score=_jitter(record.get("reputation_score", 0.1)),
        known_malware_families=record.get("known_malware_families", []),
        first_seen=record.get("first_seen", "N/A"),
        last_seen=record.get("last_seen", "N/A"),
        tags=record.get("tags", []),
    )


# ===========================================================================
# Tool 3 — URL Sandbox
# ===========================================================================

def sandbox_url(url: str) -> SandboxResult:
    """
    Detonate a URL in the simulated sandbox and return behavioral analysis.
    Derives results from the threat-intel database when possible.
    """
    # Strip protocol for domain extraction
    domain = url.split("//")[-1].split("/")[0].split("?")[0]

    db = _threat()
    sandbox_records: list[dict[str, Any]] = db.get("sandbox_results", [])

    record = next(
        (r for r in sandbox_records if domain in r.get("url", "")),
        None,
    )

    if record is None:
        # Also try threat-intel reputation to infer risk
        intel = lookup_threat_intel(domain)
        score = intel.reputation_score
        if score >= 0.8:
            risk = "critical"
        elif score >= 0.6:
            risk = "high"
        elif score >= 0.3:
            risk = "medium"
        else:
            risk = "low"

        return SandboxResult(
            url=url,
            redirects_to=[],
            page_title="",
            credential_harvesting_detected=score >= 0.7,
            malware_download_detected=score >= 0.85,
            risk_level=risk,
        )

    return SandboxResult(
        url=url,
        redirects_to=record.get("redirects_to", []),
        page_title=record.get("page_title", ""),
        credential_harvesting_detected=record.get("credential_harvesting_detected", False),
        malware_download_detected=record.get("malware_download_detected", False),
        risk_level=record.get("risk_level", "low"),
    )


# ===========================================================================
# Tool 4 — WHOIS Lookup
# ===========================================================================

def whois_lookup(domain: str) -> WhoisResult:
    """
    Return simulated WHOIS registration data for a domain.
    """
    db = _threat()
    whois_records: list[dict[str, Any]] = db.get("whois_records", [])

    record = next(
        (r for r in whois_records if r.get("domain", "") == domain),
        None,
    )

    if record is None:
        # Supply a plausible default for unknown domains
        return WhoisResult(
            domain=domain,
            registrar="Unknown Registrar",
            creation_date="2020-01-01",
            expiry_date="2026-01-01",
            registrant_country="Unknown",
            privacy_protected=False,
            age_days=math.floor((2026 - 2020) * 365),
        )

    return WhoisResult(
        domain=record["domain"],
        registrar=record.get("registrar", "Unknown"),
        creation_date=record.get("creation_date", "N/A"),
        expiry_date=record.get("expiry_date", "N/A"),
        registrant_country=record.get("registrant_country", "Unknown"),
        privacy_protected=record.get("privacy_protected", False),
        age_days=record.get("age_days", 0),
    )


# ===========================================================================
# Dispatcher
# ===========================================================================

def run_tool(tool_name: str, parameters: dict[str, Any]) -> dict[str, Any]:
    """
    Dispatch a tool call by name and return the result as a plain dict.

    Parameters
    ----------
    tool_name:
        One of the ToolName enum values (string form).
    parameters:
        Tool-specific keyword arguments.

    Returns
    -------
    dict
        The Pydantic model serialised to a plain dict.
    """
    dispatch = {
        "analyze_headers":     lambda p: analyze_headers(
            p["email_id"],
            _header_override=p.get("_header_override"),
        ),
        "lookup_threat_intel": lambda p: lookup_threat_intel(p["domain"]),
        "sandbox_url":         lambda p: sandbox_url(p["url"]),
        "whois_lookup":        lambda p: whois_lookup(p["domain"]),
    }

    if tool_name not in dispatch:
        raise ValueError(
            f"Unknown tool '{tool_name}'. Valid tools: {list(dispatch.keys())}"
        )

    result = dispatch[tool_name](parameters)
    return result.model_dump()
