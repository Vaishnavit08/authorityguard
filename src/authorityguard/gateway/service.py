"""Execution gateway: no protected tool runs without a recorded policy decision.

agent ──Bearer capability + X-Agent-Id──▶ gateway
    1. verify capability (signature, expiry, revocation, live state, presenter)
    2. policy engine: allow / deny / approval_required
    3. approval_required → create an approval bound to the exact action, return 202
       retry with approval_id → approval must be approved, unexpired, unused, same hash
    4. record decision + audit event, then (and only then) run the tool
"""

import hashlib
import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import update
from sqlmodel import Session

from authorityguard.audit.service import record_event
from authorityguard.capabilities.keys import Signer, TokenInvalid
from authorityguard.capabilities.service import verify_capability
from authorityguard.config import Settings
from authorityguard.errors import DomainError, not_found
from authorityguard.gateway.schemas import DecisionResponse, ToolRequest
from authorityguard.gateway.tools import TOOLS, ToolError
from authorityguard.policy.engine import Decision, Policy, evaluate
from authorityguard.storage.models import (
    Approval,
    ApprovalStatus,
    AuthorizationDecision,
    Capability,
)


@dataclass
class Outcome:
    decision: Decision
    capability: Capability | None
    latency_ms: float


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def action_hash(
    capability_id: str, agent_id: str, action: str, resource: str, params: dict[str, Any]
) -> str:
    canonical = json.dumps(
        {
            "capability_id": capability_id,
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "params": params,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def authorize(
    session: Session,
    signer: Signer,
    policy: Policy,
    token: str | None,
    agent_id: str | None,
    action: str,
    resource: str,
) -> Outcome:
    start = time.perf_counter()

    def done(decision: Decision, cap: Capability | None = None) -> Outcome:
        return Outcome(decision, cap, (time.perf_counter() - start) * 1000)

    if not token:
        return done(Decision("deny", "capability_required"))
    if not agent_id:
        return done(Decision("deny", "agent_id_required"))
    try:
        cap, _claims = verify_capability(session, signer, token, presenter_agent_id=agent_id)
    except TokenInvalid as exc:
        return done(Decision("deny", exc.code))
    return done(evaluate(policy, cap.scopes, action, resource), cap)


def record_decision(
    session: Session,
    trace_id: str,
    outcome: Outcome,
    *,
    agent_id: str | None,
    action: str,
    resource: str,
    policy: Policy,
    dry_run: bool,
    decision: Decision | None = None,
) -> AuthorizationDecision:
    d = decision or outcome.decision
    cap = outcome.capability
    row = AuthorizationDecision(
        trace_id=trace_id,
        task_id=cap.task_id if cap else None,
        agent_id=(agent_id or "")[:64] or None,
        capability_id=cap.id if cap else None,
        action=action,
        resource=resource,
        decision=d.decision,
        reason_code=d.reason_code,
        rule_id=d.rule_id,
        policy_version=policy.version,
        dry_run=dry_run,
        latency_ms=round(outcome.latency_ms, 3),
    )
    session.add(row)
    session.commit()
    return row


def _consume_approval(session: Session, approval_id: str, expected_hash: str) -> Decision:
    approval = session.get(Approval, approval_id)
    if approval is None:
        return Decision("deny", "approval_not_found")
    # Bound to the exact capability, agent, action, resource and parameters (threat T7).
    if approval.action_hash != expected_hash:
        return Decision("deny", "approval_mismatch")
    status = ApprovalStatus(approval.status)
    if status == ApprovalStatus.pending:
        return Decision("approval_required", "approval_pending")
    if status == ApprovalStatus.rejected:
        return Decision("deny", "approval_rejected")
    if status == ApprovalStatus.used:
        return Decision("deny", "approval_already_used")
    if _aware(approval.expires_at) < datetime.now(UTC):
        return Decision("deny", "approval_expired")

    # Single use (threat T6): only one request can flip approved -> used.
    result = session.exec(
        update(Approval)
        .where(Approval.id == approval_id, Approval.status == ApprovalStatus.approved)
        .values(status=ApprovalStatus.used, used_at=datetime.now(UTC))
    )
    session.commit()
    if result.rowcount != 1:
        return Decision("deny", "approval_already_used")
    return Decision("allow", "approved")


def execute_tool(
    session: Session,
    signer: Signer,
    policy: Policy,
    settings: Settings,
    *,
    tool_name: str,
    token: str | None,
    agent_id: str | None,
    request: ToolRequest,
    trace_id: str,
) -> tuple[int, DecisionResponse]:
    tool = TOOLS.get(tool_name)
    if tool is None:
        raise not_found("unknown_tool", "Tool")

    outcome = authorize(session, signer, policy, token, agent_id, tool.action, request.resource)
    decision = outcome.decision
    cap = outcome.capability
    common = {"agent_id": agent_id, "action": tool.action, "resource": request.resource}

    if decision.decision == "approval_required" and cap is not None:
        assert agent_id is not None
        digest = action_hash(cap.id, agent_id, tool.action, request.resource, request.params)
        if request.approval_id is None:
            approval = Approval(
                trace_id=trace_id,
                task_id=cap.task_id,
                agent_id=agent_id,
                capability_id=cap.id,
                action=tool.action,
                resource=request.resource,
                action_hash=digest,
                summary=tool.approval_summary(request.resource, request.params),
                expires_at=datetime.now(UTC) + timedelta(seconds=settings.approval_ttl_seconds),
            )
            session.add(approval)
            session.commit()
            row = record_decision(
                session, trace_id, outcome, policy=policy, dry_run=False, **common
            )
            record_event(
                session,
                "approval.requested",
                trace_id,
                actor_id=agent_id,
                subject_id=approval.id,
                task_id=cap.task_id,
                details={**common, "reason_code": decision.reason_code, **approval.summary},
            )
            return 202, DecisionResponse(
                decision="approval_required",
                reason_code=decision.reason_code,
                rule_id=decision.rule_id,
                approval_id=approval.id,
                decision_id=row.id,
                trace_id=trace_id,
            )
        decision = _consume_approval(session, request.approval_id, digest)

    row = record_decision(
        session, trace_id, outcome, policy=policy, dry_run=False, decision=decision, **common
    )
    if decision.decision != "allow":
        record_event(
            session,
            "tool.blocked",
            trace_id,
            actor_id=agent_id,
            task_id=cap.task_id if cap else None,
            details={**common, "decision": decision.decision, "reason_code": decision.reason_code},
        )
        status = 202 if decision.decision == "approval_required" else (401 if cap is None else 403)
        return status, DecisionResponse(
            decision=decision.decision,
            reason_code=decision.reason_code,
            rule_id=decision.rule_id,
            approval_id=request.approval_id,
            decision_id=row.id,
            trace_id=trace_id,
        )

    assert cap is not None
    try:
        result = tool.run(request.resource, request.params)
    except ToolError as exc:
        record_event(
            session,
            "tool.failed",
            trace_id,
            actor_id=agent_id,
            task_id=cap.task_id,
            details={**common, "error": exc.code},
        )
        raise DomainError(exc.code, exc.message, exc.status_code) from exc

    record_event(
        session,
        "tool.executed",
        trace_id,
        actor_id=agent_id,
        task_id=cap.task_id,
        details={
            **common,
            "reason_code": decision.reason_code,
            **tool.audit_details(request.resource, request.params, result),
        },
    )
    return 200, DecisionResponse(
        decision="allow",
        reason_code=decision.reason_code,
        rule_id=decision.rule_id,
        approval_id=request.approval_id,
        decision_id=row.id,
        trace_id=trace_id,
        result=result,
    )


def decide_approval(
    session: Session, approval_id: str, approve: bool, approver: str, trace_id: str
) -> Approval:
    approval = session.get(Approval, approval_id)
    if approval is None:
        raise not_found("approval_not_found", "Approval")
    if approval.status != ApprovalStatus.pending:
        raise DomainError("approval_not_pending", "Only pending approvals can be decided.", 409)
    if _aware(approval.expires_at) < datetime.now(UTC):
        raise DomainError("approval_expired", "This approval request has expired.", 409)
    approval.status = ApprovalStatus.approved if approve else ApprovalStatus.rejected
    approval.decided_at = datetime.now(UTC)
    approval.decided_by = approver
    session.add(approval)
    session.commit()
    session.refresh(approval)
    record_event(
        session,
        "approval.approved" if approve else "approval.rejected",
        trace_id,
        actor_id=approver,
        subject_id=approval.id,
        task_id=approval.task_id,
        details={"action": approval.action, "resource": approval.resource},
    )
    return approval
