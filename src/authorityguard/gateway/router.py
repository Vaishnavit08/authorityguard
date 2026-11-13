from typing import Annotated, Any

from fastapi import APIRouter, Header
from fastapi.responses import JSONResponse
from sqlmodel import select

from authorityguard.deps import (
    AdminOnly,
    PolicyDep,
    SessionDep,
    SettingsDep,
    SignerDep,
    TraceDep,
)
from authorityguard.errors import not_found
from authorityguard.gateway import service
from authorityguard.gateway.schemas import (
    ApprovalDecisionRequest,
    ApprovalRead,
    AuthorizeRequest,
    DecisionResponse,
    ToolRequest,
)
from authorityguard.gateway.tools import OUTBOX, TOOLS
from authorityguard.storage.models import Approval
from authorityguard.storage.pagination import PageDep

router = APIRouter(prefix="/v1", tags=["gateway"])

AuthHeader = Annotated[str | None, Header(alias="Authorization")]
AgentHeader = Annotated[str | None, Header(alias="X-Agent-Id")]


def _bearer(value: str | None) -> str | None:
    if value and value.lower().startswith("bearer "):
        return value[7:].strip() or None
    return None


@router.get("/tools")
def list_tools() -> list[dict[str, str]]:
    return [
        {"name": t.name, "action": t.action, "description": t.description} for t in TOOLS.values()
    ]


@router.post(
    "/tools/{tool_name}/execute",
    response_model=DecisionResponse,
    responses={202: {"model": DecisionResponse}, 401: {}, 403: {}},
)
def execute_tool(
    tool_name: str,
    body: ToolRequest,
    session: SessionDep,
    signer: SignerDep,
    policy: PolicyDep,
    settings: SettingsDep,
    trace_id: TraceDep,
    authorization: AuthHeader = None,
    x_agent_id: AgentHeader = None,
) -> JSONResponse:
    """Authorize, then (only if allowed) execute a protected tool.

    200 executed · 202 human approval required · 401 bad capability · 403 denied by scope/policy."""
    status, response = service.execute_tool(
        session,
        signer,
        policy,
        settings,
        tool_name=tool_name,
        token=_bearer(authorization),
        agent_id=x_agent_id,
        request=body,
        trace_id=trace_id,
    )
    return JSONResponse(status_code=status, content=response.model_dump(mode="json"))


@router.post("/authorize", response_model=DecisionResponse)
def authorize(
    body: AuthorizeRequest,
    session: SessionDep,
    signer: SignerDep,
    policy: PolicyDep,
    trace_id: TraceDep,
    authorization: AuthHeader = None,
    x_agent_id: AgentHeader = None,
) -> DecisionResponse:
    """Dry run: what would the gateway decide? Nothing executes; the decision is recorded."""
    outcome = service.authorize(
        session, signer, policy, _bearer(authorization), x_agent_id, body.action, body.resource
    )
    row = service.record_decision(
        session,
        trace_id,
        outcome,
        agent_id=x_agent_id,
        action=body.action,
        resource=body.resource,
        policy=policy,
        dry_run=True,
    )
    d = outcome.decision
    return DecisionResponse(
        decision=d.decision,
        reason_code=d.reason_code,
        rule_id=d.rule_id,
        decision_id=row.id,
        trace_id=trace_id,
    )


@router.get("/approvals", response_model=list[ApprovalRead])
def list_approvals(
    session: SessionDep,
    page: PageDep,
    status: str | None = None,
    task_id: str | None = None,
) -> list[Approval]:
    query = select(Approval).order_by(Approval.created_at.desc())  # type: ignore[union-attr]
    if status:
        query = query.where(Approval.status == status)
    if task_id:
        query = query.where(Approval.task_id == task_id)
    return list(session.exec(query.offset(page.offset).limit(page.limit)))


@router.get("/approvals/{approval_id}", response_model=ApprovalRead)
def get_approval(approval_id: str, session: SessionDep) -> Approval:
    approval = session.get(Approval, approval_id)
    if approval is None:
        raise not_found("approval_not_found", "Approval")
    return approval


@router.post(
    "/approvals/{approval_id}/decision", response_model=ApprovalRead, dependencies=AdminOnly
)
def decide_approval(
    approval_id: str, body: ApprovalDecisionRequest, session: SessionDep, trace_id: TraceDep
) -> Approval:
    return service.decide_approval(
        session, approval_id, body.decision == "approve", body.approver, trace_id
    )


@router.get("/outbox")
def outbox() -> list[dict[str, Any]]:
    """Mock emails 'sent' by the email.send tool (metadata only)."""
    return list(OUTBOX)
