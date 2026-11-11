"""Task rules. A task records which human is the source of authority and which agent
receives it first; every later delegation must trace back to this pair."""

from datetime import UTC, datetime

from sqlmodel import Session

from authorityguard.errors import DomainError, not_found
from authorityguard.storage.models import Agent, IdentityStatus, Task, TaskStatus, User
from authorityguard.tasks.schemas import TaskCreate

# completed and cancelled are terminal: a closed task can never be reopened.
_TASK_TRANSITIONS: dict[TaskStatus, set[TaskStatus]] = {
    TaskStatus.active: {TaskStatus.completed, TaskStatus.cancelled},
    TaskStatus.completed: set(),
    TaskStatus.cancelled: set(),
}


def create_task(session: Session, data: TaskCreate) -> Task:
    principal = session.get(User, data.principal_user_id)
    if principal is None:
        raise not_found("principal_not_found", "Principal user")
    if principal.status != IdentityStatus.active:
        raise DomainError("principal_inactive", "Principal user is not active.", 409)

    agent = session.get(Agent, data.root_agent_id)
    if agent is None:
        raise not_found("agent_not_found", "Root agent")
    if agent.status != IdentityStatus.active:
        raise DomainError("agent_inactive", "Root agent is not active.", 409)
    # Authority flows only from a human to *their own* agent.
    if agent.owner_user_id != principal.id:
        raise DomainError(
            "agent_not_owned_by_principal", "Root agent is not owned by the principal.", 403
        )
    # Tasks start at the top of a chain; sub-agents get authority only by delegation.
    if agent.parent_agent_id is not None:
        raise DomainError(
            "root_agent_not_top_level", "Root agent must not have a parent agent.", 409
        )

    task = Task(
        principal_user_id=principal.id,
        root_agent_id=agent.id,
        purpose=data.purpose,
    )
    session.add(task)
    session.commit()
    session.refresh(task)
    return task


def get_task(session: Session, task_id: str) -> Task:
    task = session.get(Task, task_id)
    if task is None:
        raise not_found("task_not_found", "Task")
    return task


def set_task_status(session: Session, task_id: str, status: TaskStatus) -> Task:
    task = get_task(session, task_id)
    if status not in _TASK_TRANSITIONS[TaskStatus(task.status)]:
        raise DomainError(
            "invalid_transition", f"Cannot change task from {task.status} to {status}.", 409
        )
    task.status = status
    task.closed_at = datetime.now(UTC)
    session.add(task)
    session.commit()
    session.refresh(task)
    return task
