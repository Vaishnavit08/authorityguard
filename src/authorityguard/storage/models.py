"""Database tables. Weeks 0–1 cover identities and tasks; capabilities, policies,
decisions, approvals and audit events are added in later milestones.

Status columns are stored as plain strings (not native DB enums) so new states can be
added later without a PostgreSQL enum-type migration. Allowed values live in code."""

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import JSON, DateTime, String
from sqlmodel import Field, SQLModel


def _new_id() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(UTC)


class IdentityStatus(StrEnum):
    active = "active"
    suspended = "suspended"
    revoked = "revoked"


class TaskStatus(StrEnum):
    active = "active"
    completed = "completed"
    cancelled = "cancelled"


class User(SQLModel, table=True):
    __tablename__ = "users"

    id: str = Field(default_factory=_new_id, primary_key=True)
    demo_name: str = Field(index=True, unique=True, max_length=100)
    status: IdentityStatus = Field(default=IdentityStatus.active, sa_type=String(20))
    created_at: datetime = Field(default_factory=_now, sa_type=DateTime(timezone=True))


class Agent(SQLModel, table=True):
    __tablename__ = "agents"

    id: str = Field(default_factory=_new_id, primary_key=True)
    owner_user_id: str = Field(foreign_key="users.id", index=True)
    parent_agent_id: str | None = Field(default=None, foreign_key="agents.id", index=True)
    name: str = Field(max_length=100)
    status: IdentityStatus = Field(default=IdentityStatus.active, sa_type=String(20))
    created_at: datetime = Field(default_factory=_now, sa_type=DateTime(timezone=True))


class Task(SQLModel, table=True):
    __tablename__ = "tasks"

    id: str = Field(default_factory=_new_id, primary_key=True)
    principal_user_id: str = Field(foreign_key="users.id", index=True)
    root_agent_id: str = Field(foreign_key="agents.id", index=True)
    purpose: str = Field(max_length=500)
    status: TaskStatus = Field(default=TaskStatus.active, sa_type=String(20), index=True)
    created_at: datetime = Field(default_factory=_now, sa_type=DateTime(timezone=True))
    closed_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))


class Capability(SQLModel, table=True):
    """Metadata for every issued capability token. The token itself is never stored,
    only its SHA-256 hash, so a database leak does not hand out usable tokens."""

    __tablename__ = "capabilities"

    id: str = Field(primary_key=True)  # the token's jti
    task_id: str = Field(foreign_key="tasks.id", index=True)
    subject_agent_id: str = Field(foreign_key="agents.id", index=True)
    parent_capability_id: str | None = Field(
        default=None, foreign_key="capabilities.id", index=True
    )
    depth: int = 0  # 0 = issued to the root agent; +1 per delegation (Week 3)
    issuer: str = Field(max_length=100)
    audience: str = Field(max_length=100)
    scopes: list[dict] = Field(sa_type=JSON)
    token_hash: str = Field(max_length=64, unique=True)
    issued_at: datetime = Field(sa_type=DateTime(timezone=True))
    expires_at: datetime = Field(sa_type=DateTime(timezone=True))
    revoked_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))


class ApprovalStatus(StrEnum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    used = "used"  # approved and consumed by exactly one execution


class Approval(SQLModel, table=True):
    """A human sign-off bound to one exact action (threat T7) that can be used once (T6)."""

    __tablename__ = "approvals"

    id: str = Field(default_factory=_new_id, primary_key=True)
    trace_id: str = Field(max_length=64, index=True)
    task_id: str = Field(foreign_key="tasks.id", index=True)
    agent_id: str = Field(foreign_key="agents.id")
    capability_id: str = Field(foreign_key="capabilities.id")
    action: str = Field(max_length=100)
    resource: str = Field(max_length=300)
    # SHA-256 over capability, agent, action, resource and parameters.
    action_hash: str = Field(max_length=64)
    # Human-readable summary for the approver; never full document contents.
    summary: dict = Field(default_factory=dict, sa_type=JSON)
    status: ApprovalStatus = Field(default=ApprovalStatus.pending, sa_type=String(20), index=True)
    created_at: datetime = Field(default_factory=_now, sa_type=DateTime(timezone=True))
    expires_at: datetime = Field(sa_type=DateTime(timezone=True))
    decided_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
    decided_by: str | None = Field(default=None, max_length=100)
    used_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))


class AuthorizationDecision(SQLModel, table=True):
    __tablename__ = "authorization_decisions"

    id: str = Field(default_factory=_new_id, primary_key=True)
    trace_id: str = Field(max_length=64, index=True)
    task_id: str | None = Field(default=None, index=True)
    agent_id: str | None = Field(default=None, max_length=64, index=True)
    capability_id: str | None = Field(default=None, max_length=64)
    action: str = Field(max_length=100)
    resource: str = Field(max_length=300)
    decision: str = Field(max_length=20)
    reason_code: str = Field(max_length=60)
    rule_id: str | None = Field(default=None, max_length=100)
    policy_version: str = Field(max_length=50)
    dry_run: bool = False
    latency_ms: float = 0.0
    created_at: datetime = Field(default_factory=_now, sa_type=DateTime(timezone=True))


class AuditEvent(SQLModel, table=True):
    """Append-only log. `details` is redacted before it is stored (threat T11)."""

    __tablename__ = "audit_events"

    id: str = Field(default_factory=_new_id, primary_key=True)
    trace_id: str = Field(max_length=64, index=True)
    event_type: str = Field(max_length=60, index=True)
    actor_id: str | None = Field(default=None, max_length=64)
    subject_id: str | None = Field(default=None, max_length=64)
    task_id: str | None = Field(default=None, max_length=64, index=True)
    details: dict = Field(default_factory=dict, sa_type=JSON)
    created_at: datetime = Field(default_factory=_now, sa_type=DateTime(timezone=True))
