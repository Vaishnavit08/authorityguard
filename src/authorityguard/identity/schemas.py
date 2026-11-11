from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from authorityguard.storage.models import IdentityStatus

# Demo names only: synthetic identities, never real emails or employee IDs.
NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,99}$"


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    demo_name: str = Field(pattern=NAME_PATTERN)


class UserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    demo_name: str
    status: IdentityStatus
    created_at: datetime


class AgentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    owner_user_id: str
    name: str = Field(pattern=NAME_PATTERN)
    parent_agent_id: str | None = None


class IdentityStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: IdentityStatus


class AgentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    owner_user_id: str
    parent_agent_id: str | None
    name: str
    status: IdentityStatus
    created_at: datetime
