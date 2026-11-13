from typing import Annotated

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from authorityguard.capabilities import service
from authorityguard.capabilities.keys import Signer, TokenInvalid, get_signer
from authorityguard.capabilities.schemas import (
    CapabilityIssue,
    CapabilityIssued,
    CapabilityRead,
    VerifyRequest,
    VerifyResponse,
)
from authorityguard.config import Settings, get_settings
from authorityguard.storage.db import get_session
from authorityguard.storage.models import Capability
from authorityguard.storage.pagination import PageDep

router = APIRouter(prefix="/v1/capabilities", tags=["capabilities"])
SessionDep = Annotated[Session, Depends(get_session)]
SignerDep = Annotated[Signer, Depends(get_signer)]
SettingsDep = Annotated[Settings, Depends(get_settings)]


@router.post("", response_model=CapabilityIssued, status_code=201)
def issue_capability(
    data: CapabilityIssue, session: SessionDep, signer: SignerDep, settings: SettingsDep
) -> CapabilityIssued:
    """Issue a root capability for a task's top-level agent. The token is shown only once."""
    return service.issue_root_capability(session, signer, settings, data)


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


@router.post("/{capability_id}/revoke", response_model=CapabilityRead)
def revoke_capability(capability_id: str, session: SessionDep) -> Capability:
    return service.revoke_capability(session, capability_id)
