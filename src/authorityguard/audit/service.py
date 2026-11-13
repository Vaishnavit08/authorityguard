"""Audit log. Events are append-only and redacted before they are stored."""

from typing import Any

from sqlmodel import Session

from authorityguard.storage.models import AuditEvent

# Keys whose values must never reach the log (tokens, secrets, document contents).
SENSITIVE_KEYS = {
    "token",
    "parent_token",
    "authorization",
    "api_key",
    "password",
    "secret",
    "content",
    "body",
    "text",
    "summary_text",
    "body_preview",  # shown to the approver in the approval record, never logged
}
MAX_STRING = 200


def redact(value: Any, _depth: int = 0) -> Any:
    if _depth > 5:
        return "[truncated]"
    if isinstance(value, dict):
        return {
            k: ("[redacted]" if k.lower() in SENSITIVE_KEYS else redact(v, _depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v, _depth + 1) for v in value[:50]]
    if isinstance(value, str) and len(value) > MAX_STRING:
        return value[:MAX_STRING] + "…"
    return value


def record_event(
    session: Session,
    event_type: str,
    trace_id: str,
    *,
    actor_id: str | None = None,
    subject_id: str | None = None,
    task_id: str | None = None,
    details: dict[str, Any] | None = None,
    commit: bool = True,
) -> AuditEvent:
    event = AuditEvent(
        trace_id=trace_id,
        event_type=event_type,
        actor_id=actor_id,
        subject_id=subject_id,
        task_id=task_id,
        details=redact(details or {}),
    )
    session.add(event)
    if commit:
        session.commit()
    return event
