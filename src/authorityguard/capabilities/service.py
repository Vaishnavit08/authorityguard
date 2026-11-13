"""Issue, delegate, verify and revoke capability tokens.

Verification is layered. A token is accepted only if *all* of these hold:
  1. signature, algorithm, issuer, audience, expiry and not-before are valid (keys.Signer)
  2. the capability is known to us, matches the stored hash and is not revoked
  3. no ancestor capability in its delegation chain is revoked
  4. its task is still active
  5. the subject agent, every ancestor agent and their owner are still active
  6. if the caller says which agent it is, that agent is the token's subject
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlmodel import Session

from authorityguard.capabilities.keys import Signer, TokenInvalid, token_hash
from authorityguard.capabilities.schemas import (
    CapabilityIssue,
    CapabilityIssued,
    DelegateRequest,
    Scope,
)
from authorityguard.config import Settings
from authorityguard.errors import DomainError, not_found
from authorityguard.identity.service import chain_problem
from authorityguard.policy.engine import Policy, scope_within
from authorityguard.storage.models import Agent, Capability, Task, TaskStatus


def _dedupe(scopes: list[Scope]) -> list[Scope]:
    return list(dict.fromkeys(scopes))


def _now(now: datetime | None) -> datetime:
    return (now or datetime.now(UTC)).replace(microsecond=0)


def _check_ttl(settings: Settings, ttl: int) -> None:
    if ttl > settings.capability_max_ttl_seconds:
        raise DomainError(
            "ttl_too_long",
            f"ttl_seconds may not exceed {settings.capability_max_ttl_seconds}.",
            422,
        )


def _mint(
    session: Session,
    signer: Signer,
    *,
    task: Task,
    subject_agent_id: str,
    scopes: list[Scope],
    issued_at: datetime,
    expires_at: datetime,
    depth: int,
    parent_id: str | None,
) -> CapabilityIssued:
    jti = str(uuid.uuid4())
    claims: dict[str, Any] = {
        "iss": signer.issuer,
        "aud": signer.audience,
        "sub": subject_agent_id,
        "jti": jti,
        "iat": int(issued_at.timestamp()),
        "nbf": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        "task_id": task.id,
        "principal_id": task.principal_user_id,
        "scopes": [s.model_dump() for s in scopes],
        "depth": depth,
        "parent_jti": parent_id,
    }
    token = signer.sign(claims)
    session.add(
        Capability(
            id=jti,
            task_id=task.id,
            subject_agent_id=subject_agent_id,
            parent_capability_id=parent_id,
            depth=depth,
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
        subject_agent_id=subject_agent_id,
        parent_capability_id=parent_id,
        depth=depth,
        scopes=scopes,
        issued_at=issued_at,
        expires_at=expires_at,
    )


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
    _check_ttl(settings, ttl)
    issued_at = _now(now)
    return _mint(
        session,
        signer,
        task=task,
        subject_agent_id=task.root_agent_id,
        scopes=_dedupe(data.scopes),
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=ttl),
        depth=0,
        parent_id=None,
    )


def delegate_capability(
    session: Session,
    signer: Signer,
    settings: Settings,
    policy: Policy,
    data: DelegateRequest,
    now: datetime | None = None,
) -> CapabilityIssued:
    """Attenuation: the child capability can only ever be *narrower* than its parent."""
    try:
        parent, parent_claims = verify_capability(
            session, signer, data.parent_token, presenter_agent_id=data.delegator_agent_id
        )
    except TokenInvalid as exc:
        raise DomainError(exc.code, "Parent capability is not valid.", 401) from exc

    child = session.get(Agent, data.child_agent_id)
    if child is None:
        raise not_found("agent_not_found", "Child agent")
    # Authority flows only down the registered agent tree, one level at a time.
    if child.parent_agent_id != parent.subject_agent_id:
        raise DomainError(
            "not_a_child_agent", "Capabilities can only be delegated to a direct child agent.", 409
        )
    if problem := chain_problem(session, child.id):
        raise DomainError(problem, "Child agent may not receive capabilities.", 409)

    depth = parent.depth + 1
    if depth > policy.max_delegation_depth:
        raise DomainError(
            "delegation_too_deep",
            f"Delegation depth may not exceed {policy.max_delegation_depth}.",
            403,
        )

    scopes = _dedupe(data.scopes)
    for scope in scopes:
        if not any(scope_within(scope.model_dump(), p) for p in parent.scopes):
            raise DomainError(
                "scope_escalation",
                f"Scope {scope.action} on {scope.resource} is not covered by the parent.",
                403,
            )

    issued_at = _now(now)
    parent_expiry = datetime.fromtimestamp(parent_claims["exp"], UTC)
    if data.ttl_seconds is not None:
        _check_ttl(settings, data.ttl_seconds)
        expires_at = issued_at + timedelta(seconds=data.ttl_seconds)
        if expires_at > parent_expiry:
            raise DomainError(
                "ttl_exceeds_parent", "A child capability may not outlive its parent.", 403
            )
    else:
        default = issued_at + timedelta(seconds=settings.capability_default_ttl_seconds)
        expires_at = min(default, parent_expiry)

    task = session.get(Task, parent.task_id)
    assert task is not None  # verify_capability already checked the task
    return _mint(
        session,
        signer,
        task=task,
        subject_agent_id=child.id,
        scopes=scopes,
        issued_at=issued_at,
        expires_at=expires_at,
        depth=depth,
        parent_id=parent.id,
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

    # Revoking a parent capability disables every capability delegated from it.
    ancestor_id = cap.parent_capability_id
    while ancestor_id is not None:
        ancestor = session.get(Capability, ancestor_id)
        if ancestor is None or ancestor.revoked_at is not None:
            raise TokenInvalid("parent_capability_revoked")
        ancestor_id = ancestor.parent_capability_id

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
