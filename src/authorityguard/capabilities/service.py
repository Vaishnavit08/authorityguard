"""Issue, verify and revoke capability tokens.

Verification is layered. A token is accepted only if *all* of these hold:
  1. signature, algorithm, issuer, audience, expiry and not-before are valid (keys.Signer)
  2. the capability is known to us, matches the stored hash and is not revoked
  3. its task is still active
  4. the subject agent, every ancestor and their owner are still active
  5. if the caller says which agent it is, that agent is the token's subject
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlmodel import Session

from authorityguard.capabilities.keys import Signer, TokenInvalid, token_hash
from authorityguard.capabilities.schemas import CapabilityIssue, CapabilityIssued, Scope
from authorityguard.config import Settings
from authorityguard.errors import DomainError, not_found
from authorityguard.identity.service import chain_problem
from authorityguard.storage.models import Capability, Task, TaskStatus


def _dedupe(scopes: list[Scope]) -> list[Scope]:
    return list(dict.fromkeys(scopes))


def issue_root_capability(
    session: Session,
    signer: Signer,
    settings: Settings,
    data: CapabilityIssue,
    now: datetime | None = None,
) -> CapabilityIssued:
    task = session.get(Task, data.task_id)
    if task is None:
        raise not_found("task_not_found", "Task")
    if task.status != TaskStatus.active:
        raise DomainError("task_inactive", "Capabilities can only be issued for active tasks.", 409)
    if problem := chain_problem(session, task.root_agent_id):
        raise DomainError(problem, "The task's root agent may not receive capabilities.", 409)

    ttl = data.ttl_seconds or settings.capability_default_ttl_seconds
    if ttl > settings.capability_max_ttl_seconds:
        raise DomainError(
            "ttl_too_long",
            f"ttl_seconds may not exceed {settings.capability_max_ttl_seconds}.",
            422,
        )

    issued_at = (now or datetime.now(UTC)).replace(microsecond=0)
    expires_at = issued_at + timedelta(seconds=ttl)
    scopes = _dedupe(data.scopes)
    jti = str(uuid.uuid4())

    claims: dict[str, Any] = {
        "iss": signer.issuer,
        "aud": signer.audience,
        "sub": task.root_agent_id,
        "jti": jti,
        "iat": int(issued_at.timestamp()),
        "nbf": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        "task_id": task.id,
        "principal_id": task.principal_user_id,
        "scopes": [s.model_dump() for s in scopes],
        "depth": 0,
        "parent_jti": None,
    }
    token = signer.sign(claims)

    session.add(
        Capability(
            id=jti,
            task_id=task.id,
            subject_agent_id=task.root_agent_id,
            issuer=signer.issuer,
            audience=signer.audience,
            scopes=claims["scopes"],
            token_hash=token_hash(token),
            issued_at=issued_at,
            expires_at=expires_at,
        )
    )
    session.commit()

    return CapabilityIssued(
        capability_id=jti,
        token=token,
        task_id=task.id,
        subject_agent_id=task.root_agent_id,
        scopes=scopes,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def verify_capability(
    session: Session,
    signer: Signer,
    token: str,
    presenter_agent_id: str | None = None,
) -> tuple[Capability, dict[str, Any]]:
    """Return (capability, claims) or raise TokenInvalid with a stable reason code."""
    claims = signer.verify(token)

    cap = session.get(Capability, claims["jti"])
    if cap is None:
        raise TokenInvalid("unknown_capability")
    if cap.token_hash != token_hash(token):
        raise TokenInvalid("token_mismatch")
    if cap.revoked_at is not None:
        raise TokenInvalid("capability_revoked")
    if claims["sub"] != cap.subject_agent_id or claims.get("task_id") != cap.task_id:
        raise TokenInvalid("claims_mismatch")

    task = session.get(Task, cap.task_id)
    if task is None or task.status != TaskStatus.active:
        raise TokenInvalid("task_inactive")
    if problem := chain_problem(session, cap.subject_agent_id):
        raise TokenInvalid(problem)

    if presenter_agent_id is not None and presenter_agent_id != cap.subject_agent_id:
        raise TokenInvalid("subject_mismatch")

    return cap, claims


def get_capability(session: Session, capability_id: str) -> Capability:
    cap = session.get(Capability, capability_id)
    if cap is None:
        raise not_found("capability_not_found", "Capability")
    return cap


def revoke_capability(session: Session, capability_id: str) -> Capability:
    cap = get_capability(session, capability_id)
    if cap.revoked_at is not None:
        raise DomainError("already_revoked", "Capability is already revoked.", 409)
    cap.revoked_at = datetime.now(UTC)
    session.add(cap)
    session.commit()
    session.refresh(cap)
    return cap
