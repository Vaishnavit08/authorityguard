"""T1 — delegation can only ever narrow authority (Week 3)."""

import pytest

FILE_READ = [{"action": "file.read", "resource": "/demo/projects/*"}]


@pytest.fixture
def world(api):
    w = api.setup_task()
    w["root_cap"] = api.capability(
        w["task"]["id"],
        scopes=[
            {"action": "file.read", "resource": "/demo/projects/*"},
            {"action": "doc.summarize", "resource": "*"},
            {
                "action": "email.send",
                "resource": "mailto:alice@example.test",
                "requires_approval": True,
            },
        ],
        ttl_seconds=600,
    )
    return w


def _delegate(client, w, scopes, ttl=None, child=None, token=None, delegator=None):
    body = {
        "parent_token": token or w["root_cap"]["token"],
        "delegator_agent_id": delegator or w["root"]["id"],
        "child_agent_id": child or w["child"]["id"],
        "scopes": scopes,
    }
    if ttl is not None:
        body["ttl_seconds"] = ttl
    return client.post("/v1/capabilities/delegate", json=body)


def test_narrower_delegation_allowed(client, world):
    r = _delegate(client, world, FILE_READ)
    assert r.status_code == 201
    cap = r.json()
    assert cap["depth"] == 1
    assert cap["parent_capability_id"] == world["root_cap"]["capability_id"]
    assert cap["subject_agent_id"] == world["child"]["id"]
    # Defaults to the default TTL but never beyond the parent's expiry.
    assert cap["expires_at"] <= world["root_cap"]["expires_at"]


@pytest.mark.parametrize(
    "scopes",
    [
        [{"action": "file.write", "resource": "/demo/projects/*"}],  # new action
        [{"action": "file.read", "resource": "/demo/*"}],  # broader resource
        [{"action": "file.read", "resource": "*"}],
        [{"action": "email.send", "resource": "mailto:*", "requires_approval": True}],
        # same email scope but silently dropping the approval requirement
        [{"action": "email.send", "resource": "mailto:alice@example.test"}],
    ],
)
def test_escalating_delegation_rejected(client, world, scopes):
    r = _delegate(client, world, scopes)
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "scope_escalation"


def test_child_cannot_outlive_parent(client, world):
    r = _delegate(client, world, FILE_READ, ttl=601)
    assert r.json()["detail"]["code"] == "ttl_exceeds_parent"


def test_only_direct_children(client, api, world):
    mallory = api.user("mallory-demo")
    other = api.agent(mallory["id"], "mallory-agent")
    for target in (other["id"], world["root"]["id"]):
        r = _delegate(client, world, FILE_READ, child=target)
        assert r.json()["detail"]["code"] == "not_a_child_agent"


def test_delegator_must_be_token_subject(client, world):
    r = _delegate(client, world, FILE_READ, delegator=world["child"]["id"])
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "subject_mismatch"


def test_depth_limit(client, api, world):
    sub1 = api.agent(world["user"]["id"], "sub-1", world["child"]["id"])
    sub2 = api.agent(world["user"]["id"], "sub-2", sub1["id"])
    c1 = _delegate(client, world, FILE_READ).json()
    c2 = _delegate(
        client,
        world,
        FILE_READ,
        child=sub1["id"],
        token=c1["token"],
        delegator=world["child"]["id"],
    )
    assert c2.status_code == 201 and c2.json()["depth"] == 2
    c3 = _delegate(
        client, world, FILE_READ, child=sub2["id"], token=c2.json()["token"], delegator=sub1["id"]
    )
    assert c3.status_code == 403
    assert c3.json()["detail"]["code"] == "delegation_too_deep"


def test_revoking_parent_disables_children(client, api, world):
    child_cap = _delegate(client, world, FILE_READ).json()
    assert api.verify(child_cap["token"])["valid"] is True
    client.post(f"/v1/capabilities/{world['root_cap']['capability_id']}/revoke")
    assert api.verify(child_cap["token"])["reason_code"] == "parent_capability_revoked"


def test_denied_delegation_is_audited(client, world):
    _delegate(client, world, [{"action": "file.read", "resource": "*"}])
    events = client.get("/v1/audit/events", params={"event_type": "capability.delegation_denied"})
    assert events.json()[0]["details"]["reason_code"] == "scope_escalation"
