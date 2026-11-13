"""Public demo endpoints. They create synthetic data only and go through the real HTTP API
(in-process), so the demo is subject to exactly the same checks as any other client."""

import time
from collections import deque

import httpx
from fastapi import APIRouter, Request
from pydantic import BaseModel, ConfigDict

from authorityguard.agents.workflow import new_run_id, resume_run, start_run
from authorityguard.deps import SettingsDep
from authorityguard.errors import DomainError

router = APIRouter(prefix="/v1/demo", tags=["demo"])
_recent_runs: deque[float] = deque(maxlen=1000)


class RunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auto_approve: bool = True


class ResumeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approve: bool


def _rate_limit(per_minute: int) -> None:
    now = time.monotonic()
    while _recent_runs and now - _recent_runs[0] > 60:
        _recent_runs.popleft()
    if len(_recent_runs) >= per_minute:
        raise DomainError("rate_limited", "Too many demo runs; try again in a minute.", 429)
    _recent_runs.append(now)


def _client(request: Request, settings, run_id: str) -> httpx.AsyncClient:
    headers = {"X-Trace-Id": run_id}
    if settings.admin_api_key:
        headers["X-API-Key"] = settings.admin_api_key
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=request.app),
        base_url="http://authorityguard.internal",
        headers=headers,
        timeout=30,
    )


@router.post("/run")
async def run_demo(body: RunRequest, request: Request, settings: SettingsDep) -> dict:
    """Run the two-agent attack scenario. With auto_approve=false it pauses for a human."""
    _rate_limit(settings.demo_runs_per_minute)
    run_id = new_run_id()
    async with _client(request, settings, run_id) as client:
        return await start_run(client, run_id, body.auto_approve)


@router.post("/runs/{run_id}/resume")
async def resume_demo(
    run_id: str, body: ResumeRequest, request: Request, settings: SettingsDep
) -> dict:
    """Approve or reject the paused email in a demo run, then finish the run."""
    async with _client(request, settings, run_id) as client:
        result = await resume_run(client, run_id, body.approve)
    if result is None:
        raise DomainError("run_not_waiting", "This demo run is not waiting for approval.", 409)
    return result
