"""Read-only views: audit trail, decisions, delegation graph and dashboard stats."""

from typing import Any

from fastapi import APIRouter
from sqlalchemy import func
from sqlmodel import select

from authorityguard.capabilities.schemas import CapabilityRead
from authorityguard.deps import SessionDep
from authorityguard.errors import not_found
from authorityguard.gateway.schemas import ApprovalRead
from authorityguard.identity.schemas import AgentRead, UserRead
from authorityguard.identity.service import get_agent
from authorityguard.storage.models import (
    Agent,
    Approval,
    AuditEvent,
    AuthorizationDecision,
    Capability,
    Task,
    User,
)
from authorityguard.storage.pagination import PageDep
from authorityguard.tasks.schemas import TaskRead

router = APIRouter(prefix="/v1", tags=["audit"])


def _dump(rows: list[Any]) -> list[dict[str, Any]]:
    return [r.model_dump(mode="json") for r in rows]


@router.get("/audit/events")
def list_events(
    session: SessionDep,
    page: PageDep,
    trace_id: str | None = None,
    task_id: str | None = None,
    event_type: str | None = None,
) -> list[dict[str, Any]]:
    query = select(AuditEvent).order_by(AuditEvent.created_at.desc(), AuditEvent.id)  # type: ignore[union-attr]
    if trace_id:
        query = query.where(AuditEvent.trace_id == trace_id)
    if task_id:
        query = query.where(AuditEvent.task_id == task_id)
    if event_type:
        query = query.where(AuditEvent.event_type == event_type)
    return _dump(list(session.exec(query.offset(page.offset).limit(page.limit))))


@router.get("/decisions")
def list_decisions(
    session: SessionDep,
    page: PageDep,
    trace_id: str | None = None,
    task_id: str | None = None,
    decision: str | None = None,
) -> list[dict[str, Any]]:
    query = select(AuthorizationDecision).order_by(
        AuthorizationDecision.created_at.desc(),  # type: ignore[union-attr]
        AuthorizationDecision.id,
    )
    if trace_id:
        query = query.where(AuthorizationDecision.trace_id == trace_id)
    if task_id:
        query = query.where(AuthorizationDecision.task_id == task_id)
    if decision:
        query = query.where(AuthorizationDecision.decision == decision)
    return _dump(list(session.exec(query.offset(page.offset).limit(page.limit))))


@router.get("/tasks/{task_id}/graph")
def task_graph(task_id: str, session: SessionDep) -> dict[str, Any]:
    """Everything needed to answer 'who authorized this action?' for one task."""
    task = session.get(Task, task_id)
    if task is None:
        raise not_found("task_not_found", "Task")
    caps = list(
        session.exec(
            select(Capability).where(Capability.task_id == task_id).order_by(Capability.issued_at)
        )
    )
    agent_ids = {task.root_agent_id} | {c.subject_agent_id for c in caps}
    agents = [a for a in (session.get(Agent, i) for i in agent_ids) if a is not None]
    decisions = session.exec(
        select(AuthorizationDecision)
        .where(AuthorizationDecision.task_id == task_id)
        .order_by(AuthorizationDecision.created_at)
        .limit(500)
    )
    approvals = session.exec(select(Approval).where(Approval.task_id == task_id))
    principal = session.get(User, task.principal_user_id)
    return {
        "task": TaskRead.model_validate(task).model_dump(mode="json"),
        "principal": UserRead.model_validate(principal).model_dump(mode="json")
        if principal
        else None,
        "agents": [AgentRead.model_validate(a).model_dump(mode="json") for a in agents],
        "capabilities": [CapabilityRead.model_validate(c).model_dump(mode="json") for c in caps],
        "decisions": _dump(list(decisions)),
        "approvals": [ApprovalRead.model_validate(a).model_dump(mode="json") for a in approvals],
    }


@router.get("/agents/{agent_id}/delegation-graph")
def delegation_graph(agent_id: str, session: SessionDep) -> dict[str, Any]:
    """Ancestors (up to the human owner) and all descendants of one agent."""
    agent = get_agent(session, agent_id)
    ancestors: list[Agent] = []
    current = agent
    while current.parent_agent_id and len(ancestors) < 16:
        parent = session.get(Agent, current.parent_agent_id)
        if parent is None:
            break
        ancestors.append(parent)
        current = parent

    def subtree(node: Agent, depth: int = 0) -> dict[str, Any]:
        children = (
            list(session.exec(select(Agent).where(Agent.parent_agent_id == node.id)))
            if depth < 16
            else []
        )
        return {
            "agent": AgentRead.model_validate(node).model_dump(mode="json"),
            "children": [subtree(c, depth + 1) for c in children],
        }

    owner = session.get(User, agent.owner_user_id)
    return {
        "owner": UserRead.model_validate(owner).model_dump(mode="json") if owner else None,
        "ancestors": [AgentRead.model_validate(a).model_dump(mode="json") for a in ancestors],
        "tree": subtree(agent),
    }


@router.get("/stats")
def stats(session: SessionDep) -> dict[str, Any]:
    def count(model: Any, *where: Any) -> int:
        q = select(func.count()).select_from(model)
        for w in where:
            q = q.where(w)
        return session.exec(q).one()

    real = AuthorizationDecision.dry_run.is_(False)  # type: ignore[attr-defined]
    return {
        "users": count(User),
        "agents": count(Agent),
        "tasks": count(Task),
        "capabilities": count(Capability),
        "decisions": count(AuthorizationDecision, real),
        "allowed": count(AuthorizationDecision, real, AuthorizationDecision.decision == "allow"),
        "denied": count(AuthorizationDecision, real, AuthorizationDecision.decision == "deny"),
        "approvals_pending": count(Approval, Approval.status == "pending"),
        "audit_events": count(AuditEvent),
    }
