"""Policy decision point.

`evaluate()` is a pure function: the same scopes, policy and request always give the same
decision. It never calls an LLM and never trusts what an agent claims about itself.

Order of checks (first failure wins):
  1. resource is in canonical form          -> deny  resource_not_canonical
  2. some scope grants this action          -> deny  scope_not_granted
  3. some granting scope covers the resource -> deny  resource_out_of_scope
  4. no policy `deny` rule matches          -> deny  <rule reason_code>
  5. approval needed (scope or policy rule) -> approval_required
  6. otherwise                              -> allow
"""

import json
import posixpath
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from authorityguard.config import get_settings

DecisionKind = Literal["allow", "deny", "approval_required"]


@dataclass(frozen=True)
class Decision:
    decision: DecisionKind
    reason_code: str
    rule_id: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    effect: Literal["deny", "require_approval"]
    action: str  # exact action or "*"
    resource: str  # same pattern language as scopes
    reason_code: str


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    description: str = ""
    max_delegation_depth: int = Field(default=2, ge=0, le=10)
    rules: list[PolicyRule] = []


# --- pattern language ------------------------------------------------------------
# "*" = anything; "prefix*" = starts with prefix; anything else = exact match.


def resource_covers(pattern: str, resource: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return resource.startswith(pattern[:-1])
    return resource == pattern


def pattern_within(child: str, parent: str) -> bool:
    """True if every resource matched by `child` is also matched by `parent`."""
    if parent == "*":
        return True
    if child == "*":
        return False
    if parent.endswith("*"):
        return child.rstrip("*").startswith(parent[:-1])
    return child == parent  # exact parent only covers the identical exact child


def scope_within(child: dict[str, Any], parent: dict[str, Any]) -> bool:
    """A delegated scope must be the same action, a narrower resource, and must not
    drop a parent's approval requirement."""
    if child["action"] != parent["action"]:
        return False
    if not pattern_within(child["resource"], parent["resource"]):
        return False
    return not (parent.get("requires_approval") and not child.get("requires_approval"))


def is_canonical(resource: str) -> bool:
    """Reject path tricks that could slip past prefix matching, e.g.
    '/demo/projects/../hr/salaries.txt' or '/demo/projects/%2e%2e/x'."""
    if any(ch in resource for ch in ("\\", "%", "\x00")) or resource != resource.strip():
        return False
    if resource.startswith("/"):
        return posixpath.normpath(resource) == resource and "//" not in resource
    return True


def _rule_matches(rule: PolicyRule, action: str, resource: str) -> bool:
    return (rule.action in ("*", action)) and resource_covers(rule.resource, resource)


def evaluate(policy: Policy, scopes: list[dict[str, Any]], action: str, resource: str) -> Decision:
    if not is_canonical(resource):
        return Decision("deny", "resource_not_canonical")

    granting = [s for s in scopes if s["action"] == action]
    if not granting:
        return Decision("deny", "scope_not_granted")

    covering = [s for s in granting if resource_covers(s["resource"], resource)]
    if not covering:
        return Decision("deny", "resource_out_of_scope")

    for rule in policy.rules:
        if rule.effect == "deny" and _rule_matches(rule, action, resource):
            return Decision("deny", rule.reason_code, rule.id)

    # If every scope that covers the request demands approval, approval is needed.
    if all(s.get("requires_approval") for s in covering):
        return Decision("approval_required", "scope_requires_approval")

    for rule in policy.rules:
        if rule.effect == "require_approval" and _rule_matches(rule, action, resource):
            return Decision("approval_required", rule.reason_code, rule.id)

    return Decision("allow", "allowed")


def load_policy(path: str | Path) -> Policy:
    return Policy.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))


@lru_cache
def get_policy() -> Policy:
    return load_policy(get_settings().policy_path)
