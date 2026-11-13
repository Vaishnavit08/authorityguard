from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

# e.g. "file.read", "doc.summarize", "email.send"
ACTION_PATTERN = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$"
# Either "*" or a literal with an optional single trailing "*" (prefix match), no whitespace.
RESOURCE_PATTERN = r"^(\*|[^\s*]+\*?)$"


class Scope(BaseModel):
    """One permission: may perform `action` on `resource`.
    `requires_approval` is recorded now and enforced by the gateway from Week 4."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    action: str = Field(pattern=ACTION_PATTERN, max_length=100)
    resource: str = Field(pattern=RESOURCE_PATTERN, max_length=300)
    requires_approval: bool = False


Scopes = Annotated[list[Scope], Field(min_length=1, max_length=50)]


class CapabilityIssue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str
    scopes: Scopes
    ttl_seconds: int | None = Field(default=None, ge=1)


class CapabilityIssued(BaseModel):
    """Returned once, at issue time. This is the only time the raw token is ever shown."""

    capability_id: str
    token: str
    token_type: str = "Bearer"  # noqa: S105  (a token *type*, not a secret)
    task_id: str
    subject_agent_id: str
    parent_capability_id: str | None = None
    depth: int = 0
    scopes: list[Scope]
    issued_at: datetime
    expires_at: datetime


class DelegateRequest(BaseModel):
    """An agent hands part of its authority to one of its direct child agents."""

    model_config = ConfigDict(extra="forbid")

    parent_token: str = Field(max_length=8192)
    delegator_agent_id: str  # must be the parent token's subject
    child_agent_id: str
    scopes: Scopes
    ttl_seconds: int | None = Field(default=None, ge=1)


class CapabilityRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    task_id: str
    subject_agent_id: str
    parent_capability_id: str | None
    depth: int
    scopes: list[Scope]
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None


class VerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(max_length=8192)
    # The agent presenting the token. If given, it must be the token's subject (threat T2).
    agent_id: str | None = None


class VerifyResponse(BaseModel):
    valid: bool
    reason_code: str | None = None
    capability: CapabilityRead | None = None
