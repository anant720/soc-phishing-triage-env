"""
EnvClient wrapper for the SOC Triage Environment.

Provides both async (recommended) and sync interfaces following the
standard OpenEnv EnvClient pattern.

Async usage::

    async with SocTriageEnv(base_url="http://localhost:8000") as env:
        obs  = await env.reset()
        obs  = await env.analyze_headers(obs.email_id)
        obs  = await env.lookup_threat_intel("evil.com")
        obs  = await env.sandbox_url("http://evil.com/login")
        obs  = await env.whois_lookup("evil.com")
        result = await env.submit_verdict(Verdict.PHISHING)

Sync usage::

    with SocTriageEnv(base_url="http://localhost:8000").sync() as env:
        obs = env.reset()
        result = env.submit_verdict(Verdict.BENIGN)
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import Any

import httpx

from models import (
    ToolName,
    TriageAction,
    TriageObservation,
    TriageState,
    Verdict,
)

# ---------------------------------------------------------------------------
# Try to import openenv EnvClient; fall back to a minimal HTTP shim.
# ---------------------------------------------------------------------------
try:
    from openenv.core.env_client import EnvClient  # type: ignore
    _HAS_OPENENV = True
except ImportError:
    _HAS_OPENENV = False

    class EnvClient:  # type: ignore  # pragma: no cover
        """Minimal shim when openenv-core is not installed."""
        def __init__(self, base_url: str, **kwargs: Any) -> None:
            self._base_url = base_url.rstrip("/")
            self._client: httpx.AsyncClient | None = None

        async def __aenter__(self) -> "EnvClient":
            self._client = httpx.AsyncClient(base_url=self._base_url, timeout=30.0)
            return self

        async def __aexit__(self, *_: Any) -> None:
            if self._client:
                await self._client.aclose()

        async def _post(self, path: str, json: dict | None = None) -> dict[str, Any]:
            assert self._client is not None
            resp = await self._client.post(path, json=json or {})
            resp.raise_for_status()
            return resp.json()

        async def _get(self, path: str) -> dict[str, Any]:
            assert self._client is not None
            resp = await self._client.get(path)
            resp.raise_for_status()
            return resp.json()

        def sync(self) -> "_SyncWrapper":
            return _SyncWrapper(self)


# ===========================================================================
# SocTriageEnv — Main Client
# ===========================================================================

class SocTriageEnv(EnvClient):  # type: ignore
    """
    OpenEnv client for the SOC Triage Environment.

    Parameters
    ----------
    base_url:
        URL of the running FastAPI server, e.g. ``"http://localhost:8000"``.
    """

    action_type      = TriageAction
    observation_type = TriageObservation

    def __init__(self, base_url: str = "http://localhost:8000", **kwargs: Any) -> None:
        super().__init__(base_url=base_url, **kwargs)
        self._base_url = base_url.rstrip("/")
        self._http: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "SocTriageEnv":
        self._http = httpx.AsyncClient(base_url=self._base_url, timeout=30.0)
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._http:
            await self._http.aclose()
            self._http = None

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    async def _post_raw(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        assert self._http is not None, "Client not started. Use `async with SocTriageEnv(...) as env:`"
        resp = await self._http.post(path, json=payload)
        resp.raise_for_status()
        return resp.json()

    async def _get_raw(self, path: str) -> dict[str, Any]:
        assert self._http is not None
        resp = await self._http.get(path)
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Core OpenEnv interface
    # ------------------------------------------------------------------

    async def reset(self) -> TriageObservation:
        """Start a new episode and return the initial observation."""
        data = await self._post_raw("/reset", {})
        return TriageObservation.model_validate(data)

    async def step(self, action: TriageAction) -> dict[str, Any]:
        """Execute one action. Returns the raw StepResponse dict."""
        payload = action.model_dump()
        # Convert enums to their string values for JSON serialisation
        payload["tool"] = action.tool.value
        result = await self._post_raw("/step", payload)
        # Parse the nested observation
        if "observation" in result:
            result["observation"] = TriageObservation.model_validate(result["observation"])
        return result

    async def state(self) -> TriageState:
        """Return the current episode state."""
        data = await self._get_raw("/state")
        return TriageState.model_validate(data)

    # ------------------------------------------------------------------
    # Convenience helper methods
    # ------------------------------------------------------------------

    async def analyze_headers(self, email_id: str) -> dict[str, Any]:
        """Invoke the email header analyzer tool."""
        return await self.step(
            TriageAction(tool=ToolName.ANALYZE_HEADERS, parameters={"email_id": email_id})
        )

    async def lookup_threat_intel(self, domain: str) -> dict[str, Any]:
        """Look up a domain in the threat-intelligence database."""
        return await self.step(
            TriageAction(tool=ToolName.LOOKUP_THREAT_INTEL, parameters={"domain": domain})
        )

    async def sandbox_url(self, url: str) -> dict[str, Any]:
        """Detonate a URL in the simulated sandbox."""
        return await self.step(
            TriageAction(tool=ToolName.SANDBOX_URL, parameters={"url": url})
        )

    async def whois_lookup(self, domain: str) -> dict[str, Any]:
        """Query WHOIS registration data for a domain."""
        return await self.step(
            TriageAction(tool=ToolName.WHOIS_LOOKUP, parameters={"domain": domain})
        )

    async def submit_verdict(self, verdict: Verdict | str) -> dict[str, Any]:
        """Submit the final triage verdict and end the episode."""
        v = verdict.value if isinstance(verdict, Verdict) else verdict
        return await self.step(
            TriageAction(tool=ToolName.SUBMIT_VERDICT, parameters={"verdict": v})
        )

    # ------------------------------------------------------------------
    # Sync wrapper
    # ------------------------------------------------------------------

    def sync(self) -> "_SyncWrapper":
        """Return a synchronous wrapper around this async client."""
        return _SyncWrapper(self)


# ===========================================================================
# Sync Wrapper
# ===========================================================================

class _SyncWrapper:
    """
    Synchronous context manager that wraps SocTriageEnv.

    Usage::

        with SocTriageEnv(base_url="...").sync() as env:
            obs = env.reset()
    """

    def __init__(self, client: SocTriageEnv) -> None:
        self._client = client
        self._loop   = asyncio.new_event_loop()

    def __enter__(self) -> "_SyncWrapper":
        self._loop.run_until_complete(self._client.__aenter__())
        return self

    def __exit__(self, *args: Any) -> None:
        self._loop.run_until_complete(self._client.__aexit__(*args))
        self._loop.close()

    def _run(self, coro: Any) -> Any:
        return self._loop.run_until_complete(coro)

    def reset(self) -> TriageObservation:
        return self._run(self._client.reset())

    def step(self, action: TriageAction) -> dict[str, Any]:
        return self._run(self._client.step(action))

    def state(self) -> TriageState:
        return self._run(self._client.state())

    def analyze_headers(self, email_id: str) -> dict[str, Any]:
        return self._run(self._client.analyze_headers(email_id))

    def lookup_threat_intel(self, domain: str) -> dict[str, Any]:
        return self._run(self._client.lookup_threat_intel(domain))

    def sandbox_url(self, url: str) -> dict[str, Any]:
        return self._run(self._client.sandbox_url(url))

    def whois_lookup(self, domain: str) -> dict[str, Any]:
        return self._run(self._client.whois_lookup(domain))

    def submit_verdict(self, verdict: Verdict | str) -> dict[str, Any]:
        return self._run(self._client.submit_verdict(verdict))
