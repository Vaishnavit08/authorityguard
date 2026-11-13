"""The policy engine is a pure, deterministic function (Week 3)."""

import pytest

from authorityguard.policy.engine import (
    Policy,
    PolicyRule,
    evaluate,
    is_canonical,
    load_policy,
    pattern_within,
    resource_covers,
    scope_within,
)
from tests.conftest import PROJECT_ROOT

POLICY = load_policy(PROJECT_ROOT / "policies" / "default.json")
SCOPES = [
    {"action": "file.read", "resource": "/demo/projects/*"},
    {"action": "doc.summarize", "resource": "*"},
    {"action": "email.send", "resource": "mailto:alice@example.test"},
]


@pytest.mark.parametrize(
    ("pattern", "resource", "expected"),
    [
        ("*", "anything", True),
        ("/demo/projects/*", "/demo/projects/a.txt", True),
        ("/demo/projects/*", "/demo/projects-archive/a.txt", False),
        ("/demo/projects/*", "/demo/projects", False),
        ("/x", "/x", True),
        ("/x", "/x/y", False),
    ],
)
def test_resource_covers(pattern, resource, expected):
    assert resource_covers(pattern, resource) is expected


@pytest.mark.parametrize(
    ("child", "parent", "expected"),
    [
        ("/demo/projects/a.txt", "/demo/projects/*", True),
        ("/demo/projects/sub/*", "/demo/projects/*", True),
        ("/demo/projects/*", "/demo/projects/*", True),
        ("/demo/*", "/demo/projects/*", False),
        ("*", "/demo/projects/*", False),
        ("/x*", "/x", False),
        ("/x", "/x", True),
        ("anything", "*", True),
    ],
)
def test_pattern_within(child, parent, expected):
    assert pattern_within(child, parent) is expected


def test_scope_within_cannot_drop_approval():
    parent = {"action": "email.send", "resource": "mailto:*", "requires_approval": True}
    assert not scope_within({"action": "email.send", "resource": "mailto:a@x.test"}, parent)
    assert scope_within(
        {"action": "email.send", "resource": "mailto:a@x.test", "requires_approval": True}, parent
    )


def test_scope_within_requires_same_action():
    assert not scope_within(
        {"action": "email.send", "resource": "/x"}, {"action": "file.read", "resource": "*"}
    )


@pytest.mark.parametrize(
    "resource",
    [
        "/demo/projects/../hr/salaries.txt",
        "/demo/projects/./a.txt",
        "/demo/projects//a.txt",
        "/demo/projects/",
        "/demo/projects/%2e%2e/a",
        "/demo\\projects",
        " /demo/projects/a.txt",
    ],
)
def test_non_canonical_resources(resource):
    assert not is_canonical(resource)
    assert evaluate(POLICY, SCOPES, "file.read", resource).reason_code == "resource_not_canonical"


@pytest.mark.parametrize(
    ("action", "resource", "decision", "reason"),
    [
        ("file.read", "/demo/projects/q3-plan.txt", "allow", "allowed"),
        ("file.write", "/demo/projects/q3-plan.txt", "deny", "scope_not_granted"),
        ("file.read", "/demo/hr/salaries.txt", "deny", "resource_out_of_scope"),
        ("email.send", "mailto:attacker@example.com", "deny", "resource_out_of_scope"),
        ("email.send", "mailto:alice@example.test", "approval_required", "policy_outbound_email"),
        ("doc.summarize", "/demo/hr/salaries.txt", "deny", "policy_hr_records"),
    ],
)
def test_decisions(action, resource, decision, reason):
    d = evaluate(POLICY, SCOPES, action, resource)
    assert (d.decision, d.reason_code) == (decision, reason)


def test_deterministic():
    results = {
        evaluate(POLICY, SCOPES, "file.read", "/demo/projects/a").decision for _ in range(50)
    }
    assert results == {"allow"}


def test_policy_can_only_restrict():
    # A permissive-looking rule cannot grant an action that no scope grants.
    p = Policy(
        version="t",
        rules=[
            PolicyRule(id="r", effect="require_approval", action="*", resource="*", reason_code="x")
        ],
    )
    assert evaluate(p, SCOPES, "file.write", "/demo/projects/a").reason_code == "scope_not_granted"


def test_scope_level_approval():
    scopes = [{"action": "file.read", "resource": "/secret/*", "requires_approval": True}]
    d = evaluate(Policy(version="t"), scopes, "file.read", "/secret/a")
    assert (d.decision, d.reason_code) == ("approval_required", "scope_requires_approval")


def test_default_policy_loads():
    assert POLICY.max_delegation_depth == 2
    assert {r.id for r in POLICY.rules} >= {"deny-system-paths", "outbound-email-needs-human"}
