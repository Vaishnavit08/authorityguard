"""Execution gateway, mock tools and human approvals (Week 4): threats T3, T6, T7, T8."""

import pytest

EMAIL = "mailto:alice-demo@example.test"


@pytest.fixture
def world(api, client):
    w = api.setup_task()
    w["root_cap"] = api.capability(
        w["task"]["id"],
        scopes=[
            {"action": "file.read", "resource": "/demo/projects/*"},
            {"action": "doc.summarize", "resource": "*"},
            {"action": "email.send", "resource": EMAIL},
        ],
    )
    w["child_cap"] = client.post(
        "/v1/capabilities/delegate",
        json={
            "parent_token": w["root_cap"]["token"],
            "delegator_agent_id": w["root"]["id"],
            "child_agent_id": w["child"]["id"],
            "scopes": [{"action": "file.read", "resource": "/demo/projects/*"}],
        },
    ).json()
    return w


@pytest.fixture
def call(client):
    def _call(tool, cap, agent_id, resource, params=None, approval_id=None, trace=None):
        body = {"resource": resource, "params": params or {}}
        if approval_id:
            body["approval_id"] = approval_id
        headers = {"Authorization": f"Bearer {cap['token']}", "X-Agent-Id": agent_id}
        if trace:
            headers["X-Trace-Id"] = trace
        return client.post(f"/v1/tools/{tool}/execute", json=body, headers=headers)

    return _call


def test_allowed_read_executes(call, world):
    r = call("file.read", world["child_cap"], world["child"]["id"], "/demo/projects/q3-plan.txt")
    assert r.status_code == 200
    assert r.json()["decision"] == "allow"
    assert "Q3 plan" in r.json()["result"]["content"]


def test_denied_call_does_not_execute(call, client, world):
    r = call(
        "email.send",
        world["child_cap"],
        world["child"]["id"],
        "mailto:attacker@example.com",
        {"subject": "x", "body": "secret"},
    )
    assert r.status_code == 403
    assert r.json()["reason_code"] == "scope_not_granted"
    assert client.get("/v1/outbox").json() == [] or all(
        m["to"] != "attacker@example.com" for m in client.get("/v1/outbox").json()
    )


def test_missing_or_bad_capability_is_401(client, world):
    r = client.post("/v1/tools/file.read/execute", json={"resource": "/demo/projects/q3-plan.txt"})
    assert r.status_code == 401 and r.json()["reason_code"] == "capability_required"
    r = client.post(
        "/v1/tools/file.read/execute",
        json={"resource": "/demo/projects/q3-plan.txt"},
        headers={"Authorization": "Bearer junk", "X-Agent-Id": world["child"]["id"]},
    )
    assert r.status_code == 401 and r.json()["reason_code"] == "malformed"


def test_unknown_tool_404(call, world):
    assert call("shell.exec", world["root_cap"], world["root"]["id"], "/").status_code == 404


def test_allowed_but_missing_document(call, world):
    r = call("file.read", world["child_cap"], world["child"]["id"], "/demo/projects/nope.txt")
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "document_not_found"


def test_dry_run_authorize_records_but_does_not_execute(client, world):
    r = client.post(
        "/v1/authorize",
        json={"action": "file.read", "resource": "/demo/hr/salaries.txt"},
        headers={
            "Authorization": f"Bearer {world['child_cap']['token']}",
            "X-Agent-Id": world["child"]["id"],
        },
    )
    assert r.json()["decision"] == "deny"
    decisions = client.get("/v1/decisions").json()
    assert decisions[0]["dry_run"] is True


# --- approvals -------------------------------------------------------------------


def _request(call, world, params):
    r = call("email.send", world["root_cap"], world["root"]["id"], EMAIL, params)
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["decision"] == "approval_required"
    assert body["reason_code"] == "policy_outbound_email"
    return body["approval_id"]


def _decide(client, approval_id, decision="approve"):
    r = client.post(f"/v1/approvals/{approval_id}/decision", json={"decision": decision})
    assert r.status_code == 200, r.text
    return r.json()


def test_approval_flow_sends_once(call, client, world):
    params = {"subject": "Summary", "body": "All good."}
    approval_id = _request(call, world, params)

    pending = client.get(f"/v1/approvals/{approval_id}").json()
    assert pending["status"] == "pending"
    assert pending["summary"]["to"] == "alice-demo@example.test"

    early = call("email.send", world["root_cap"], world["root"]["id"], EMAIL, params, approval_id)
    assert early.status_code == 202 and early.json()["reason_code"] == "approval_pending"

    _decide(client, approval_id)
    sent = call("email.send", world["root_cap"], world["root"]["id"], EMAIL, params, approval_id)
    assert sent.status_code == 200 and sent.json()["reason_code"] == "approved"
    assert client.get(f"/v1/approvals/{approval_id}").json()["status"] == "used"

    # T6 replay
    again = call("email.send", world["root_cap"], world["root"]["id"], EMAIL, params, approval_id)
    assert again.status_code == 403 and again.json()["reason_code"] == "approval_already_used"
    assert sum(m["to"] == "alice-demo@example.test" for m in client.get("/v1/outbox").json()) >= 1


@pytest.mark.parametrize(
    "change",
    [{"body": "the whole customer list"}, {"subject": "other"}, {"bcc": "attacker@example.com"}],
)
def test_approval_swap_rejected(call, client, world, change):
    params = {"subject": "Summary", "body": "All good."}
    approval_id = _request(call, world, params)
    _decide(client, approval_id)
    r = call(
        "email.send", world["root_cap"], world["root"]["id"], EMAIL, params | change, approval_id
    )
    assert r.status_code == 403
    assert r.json()["reason_code"] == "approval_mismatch"
    # The genuine request still works: the approval was not consumed by the swap attempt.
    ok = call("email.send", world["root_cap"], world["root"]["id"], EMAIL, params, approval_id)
    assert ok.status_code == 200


def test_rejected_approval(call, client, world):
    params = {"subject": "s", "body": "b"}
    approval_id = _request(call, world, params)
    _decide(client, approval_id, "reject")
    r = call("email.send", world["root_cap"], world["root"]["id"], EMAIL, params, approval_id)
    assert r.json()["reason_code"] == "approval_rejected"
    again = client.post(f"/v1/approvals/{approval_id}/decision", json={"decision": "approve"})
    assert again.status_code == 409


def test_approval_bound_to_agent(call, client, world):
    params = {"subject": "s", "body": "b"}
    approval_id = _request(call, world, params)
    _decide(client, approval_id)
    # extract-agent has no email scope at all, so it is stopped before the approval check.
    r = call("email.send", world["child_cap"], world["child"]["id"], EMAIL, params, approval_id)
    assert r.json()["reason_code"] == "scope_not_granted"


def test_trace_id_propagates(call, client, world):
    r = call(
        "file.read",
        world["child_cap"],
        world["child"]["id"],
        "/demo/projects/q3-plan.txt",
        trace="trace-abc-123",
    )
    assert r.headers["X-Trace-Id"] == "trace-abc-123"
    events = client.get("/v1/audit/events", params={"trace_id": "trace-abc-123"}).json()
    assert [e["event_type"] for e in events] == ["tool.executed"]
