import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_PARAMS_CHARS = 25_000


class ToolRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    resource: str = Field(min_length=1, max_length=300)
    params: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = None

    @field_validator("params")
    @classmethod
    def _limit_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        if len(json.dumps(v, default=str)) > MAX_PARAMS_CHARS:
            raise ValueError(f"params may not exceed {MAX_PARAMS_CHARS} characters")
        return v


class AuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str = Field(min_length=1, max_length=100)
    resource: str = Field(min_length=1, max_length=300)


class DecisionResponse(BaseModel):
    decision: Literal["allow", "deny", "approval_required"]
    reason_code: str
    rule_id: str | None = None
    approval_id: str | None = None
    decision_id: str | None = None
    trace_id: str
    result: dict[str, Any] | None = None


class ApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "reject"]
    approver: str = Field(default="demo-approver", pattern=r"^[A-Za-z0-9 _.-]{1,100}$")


class ApprovalRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    trace_id: str
    task_id: str
    agent_id: str
    capability_id: str
    action: str
    resource: str
    summary: dict[str, Any]
    status: str
    created_at: datetime
    expires_at: datetime
    decided_at: datetime | None
    decided_by: str | None
    used_at: datetime | None
