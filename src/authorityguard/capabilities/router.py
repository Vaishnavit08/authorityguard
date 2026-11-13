from fastapi import APIRouter
from sqlmodel import select

from authorityguard.audit.service import record_event
from authorityguard.capabilities import service
from authorityguard.capabilities.keys import TokenInvalid
from authorityguard.capabilities.schemas import (
    CapabilityIssue,
    CapabilityIssued,
    CapabilityRead,
    DelegateRequest,
    VerifyRequest,
    VerifyResponse,
)
from authorityguard.deps import AdminOnly, PolicyDep, SessionDep, SettingsDep, SignerDep, TraceDep
from authorityguard.errors import DomainError
from authorityguard.storage.models import Capability
from authorityguard.storage.pagination import PageDep

router = APIRouter(prefix="/v1/capabilities", tags=["capabilities"])


def _issued_event(session, kind: str, trace_id: str, cap: CapabilityIssued, actor: str | None):
    record_event(
        session,
        kind,
        trace_id,
        actor_id=actor,
        subject_id=cap.capability_id,
        task_id=cap.task_id,
        details={
            "subject_agent_id": cap.subject_agent_id,
            "parent_capability_id": cap.parent_capability_id,
            "depth": cap.depth,
            "scopes": [s.model_dump() for s in cap.scopes],
            "expires_at": cap.expires_at.isoformat(),
        },
    )


@router.post("", response_model=CapabilityIssued, status_code=201, dependencies=AdminOnly)
def issue_capability(
    data: CapabilityIssue,
    session: SessionDep,
    signer: SignerDep,
    settings: SettingsDep,
    trace_id: TraceDep,
) -> CapabilityIssued:
    """Issue a root capability for a task's top-level agent. The token is shown only once."""
    cap = service.issue_root_capability(session, signer, settings, data)
    _issued_event(session, "capability.issued", trace_id, cap, actor=None)
    return cap


@router.post("/delegate", response_model=CapabilityIssued, status_code=201)
def delegate_capability(
    data: DelegateRequest,
    session: SessionDep,
    signer: SignerDep,
    settings: SettingsDep,
    policy: PolicyDep,
    trace_id: TraceDep,
) -> CapabilityIssued:
    """An agent delegates a *narrower* capability to its direct child. Authority comes from
    the parent token itself, so no admin key is needed."""
    try:
        cap = service.delegate_capability(session, signer, settings, policy, data)
    except DomainError as exc:
        code = exc.code
        record_event(
            session,
            "capability.delegation_denied",
            trace_id,
            actor_id=data.delegator_agent_id,
            subject_id=data.child_agent_id,
            details={"reason_code": code, "scopes": [s.model_dump() for s in data.scopes]},
        )
        raise
    _issued_event(session, "capability.delegated", trace_id, cap, actor=data.delegator_agent_id)
    return cap


@router.post("/verify", response_model=VerifyResponse)
def verify_capability(
    data: VerifyRequest, session: SessionDep, signer: SignerDep
) -> VerifyResponse:
    """Introspect a token. Always 200: `valid` says whether it may be used right now."""
    try:
        cap, _claims = service.verify_capability(session, signer, data.token, data.agent_id)
    except TokenInvalid as exc:
        return VerifyResponse(valid=False, reason_code=exc.code)
    return VerifyResponse(valid=True, capability=CapabilityRead.model_validate(cap))


@router.get("", response_model=list[CapabilityRead])
def list_capabilities(
    session: SessionDep, page: PageDep, task_id: str | None = None
) -> list[Capability]:
    query = select(Capability).order_by(Capability.issued_at, Capability.id)
    if task_id:
        query = query.where(Capability.task_id == task_id)
    return list(session.exec(query.offset(page.offset).limit(page.limit)))


@router.get("/{capability_id}", response_model=CapabilityRead)
def get_capability(capability_id: str, session: SessionDep) -> Capability:
    return service.get_capability(session, capability_id)


@router.post("/{capability_id}/revoke", response_model=CapabilityRead, dependencies=AdminOnly)
def revoke_capability(capability_id: str, session: SessionDep, trace_id: TraceDep) -> Capability:
    cap = service.revoke_capability(session, capability_id)
    record_event(session, "capability.revoked", trace_id, subject_id=cap.id, task_id=cap.task_id)
    return cap
