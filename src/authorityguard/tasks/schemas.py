from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

from authorityguard.storage.models import TaskStatus

Purpose = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=500)]


class TaskCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_user_id: str
    root_agent_id: str
    purpose: Purpose


class TaskStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: TaskStatus


class TaskRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    principal_user_id: str
    root_agent_id: str
    purpose: str
    status: TaskStatus
    created_at: datetime
    closed_at: datetime | None
