"""Identity lifecycle: suspend / reactivate / revoke, with revoked as terminal (threat T10)."""

import pytest


def test_suspend_and_reactivate_agent(api):
    user = api.user()
    agent = api.agent(user["id"])
    assert api.status("agents", agent["id"], "suspended")["status"] == "suspended"
    assert api.status("agents", agent["id"], "active")["status"] == "active"


@pytest.mark.parametrize("kind", ["users", "agents"])
def test_revoked_is_terminal(api, kind):
    user = api.user()
    obj = user if kind == "users" else api.agent(user["id"])
    api.status(kind, obj["id"], "revoked")
    for status in ["active", "suspended", "revoked"]:
        r = api.status(kind, obj["id"], status, expect=409)
        assert r["detail"]["code"] == "invalid_transition"


def test_same_status_is_rejected(api):
    user = api.user()
    r = api.status("users", user["id"], "active", expect=409)
    assert r["detail"]["code"] == "invalid_transition"


def test_unknown_status_value_rejected(client, api):
    user = api.user()
    r = client.post(f"/v1/users/{user['id']}/status", json={"status": "admin"})
    assert r.status_code == 422


def test_status_of_missing_identity_404(api):
    assert api.status("agents", "nope", "suspended", expect=404)["detail"]["code"] == (
        "agent_not_found"
    )
    assert api.status("users", "nope", "suspended", expect=404)["detail"]["code"] == (
        "user_not_found"
    )


def test_suspended_owner_cannot_register_agents(api):
    user = api.user()
    api.status("users", user["id"], "suspended")
    r = api.agent(user["id"], expect=409)
    assert r["detail"]["code"] == "owner_inactive"


def test_suspended_parent_cannot_get_children(api):
    user = api.user()
    root = api.agent(user["id"])
    api.status("agents", root["id"], "suspended")
    r = api.agent(user["id"], "extract-agent", root["id"], expect=409)
    assert r["detail"]["code"] == "parent_inactive"


def test_list_pagination_limits(client, api):
    for i in range(3):
        api.user(f"user-{i}")
    page = client.get("/v1/users", params={"limit": 2, "offset": 1}).json()
    assert [u["demo_name"] for u in page] == ["user-1", "user-2"]
    assert client.get("/v1/users", params={"limit": 501}).status_code == 422
    assert client.get("/v1/users", params={"offset": -1}).status_code == 422
