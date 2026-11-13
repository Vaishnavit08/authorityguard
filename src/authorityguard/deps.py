"""FastAPI dependencies shared by every router."""

import hmac
import re
import uuid
from typing import Annotated

from fastapi import Depends, Header, Request
from sqlmodel import Session

from authorityguard.capabilities.keys import Signer, get_signer
from authorityguard.config import Settings, get_settings
from authorityguard.errors import DomainError
from authorityguard.policy.engine import Policy, get_policy
from authorityguard.storage.db import get_session

SessionDep = Annotated[Session, Depends(get_session)]
SignerDep = Annotated[Signer, Depends(get_signer)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
PolicyDep = Annotated[Policy, Depends(get_policy)]

_TRACE_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")


def new_trace_id() -> str:
    return uuid.uuid4().hex


def trace_id_for(request: Request) -> str:
    """Use the caller's X-Trace-Id if well-formed, so one demo run shares one trace."""
    supplied = request.headers.get("x-trace-id", "")
    return supplied if _TRACE_ID.match(supplied) else new_trace_id()


def _trace(request: Request) -> str:
    return request.state.trace_id


TraceDep = Annotated[str, Depends(_trace)]


def require_admin(
    settings: SettingsDep,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> None:
    """Protect management endpoints when AG_ADMIN_API_KEY is configured."""
    expected = settings.admin_api_key
    if not expected:
        return
    if not x_api_key or not hmac.compare_digest(x_api_key.encode(), expected.encode()):
        raise DomainError("admin_key_required", "A valid X-API-Key header is required.", 401)


AdminOnly = [Depends(require_admin)]
