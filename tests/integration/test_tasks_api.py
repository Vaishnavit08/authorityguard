"""Tasks bind a human principal to one of *their own* top-level agents."""

import pytest


@pytest.fixture
def alice(api):
    user = api.user("alice-demo")
    root = api.agent(user["id"], "research-agent")
    child = api.agent(user["id"], "extract-agent", root["id"])
    return {"user": user, "root": root, "child": child}


def test_create_get_and_list_task(client, api, alice):
    task = api.task(alice["user"]["id"], alice["root"]["id"], "  Summarize project docs  ")
    assert task["status"] == "active"
    assert task["purpose"] == "Summarize project docs"  # whitespace stripped
    assert task["closed_at"] is None
    assert client.get(f"/v1/tasks/{task['id']}").json()["id"] == task["id"]

    listed = client.get("/v1/tasks", params={"principal_user_id": alice["user"]["id"]}).json()
    assert [t["id"] for t in listed] == [task["id"]]


def test_task_for_unknown_principal_rejected(api, alice):
    r = api.task("nobody", alice["root"]["id"], expect=404)
    assert r["detail"]["code"] == "principal_not_found"


def test_task_for_unknown_agent_rejected(api, alice):
    r = api.task(alice["user"]["id"], "nobody", expect=404)
    assert r["detail"]["code"] == "agent_not_found"


def test_task_with_another_users_agent_rejected(api, alice):
    # Confused-deputy setup: mallory tries to start a task on alice's agent.
    mallory = api.user("mallory-demo")
    r = api.task(mallory["id"], alice["root"]["id"], expect=403)
    assert r["detail"]["code"] == "agent_not_owned_by_principal"


def test_task_cannot_start_at_a_sub_agent(api, alice):
    # Sub-agents may only receive authority through delegation, never directly.
    r = api.task(alice["user"]["id"], alice["child"]["id"], expect=409)
    assert r["detail"]["code"] == "root_agent_not_top_level"


def test_task_for_suspended_principal_rejected(api, alice):
    api.status("users", alice["user"]["id"], "suspended")
    r = api.task(alice["user"]["id"], alice["root"]["id"], expect=409)
    assert r["detail"]["code"] == "principal_inactive"


def test_task_for_suspended_agent_rejected(api, alice):
    api.status("agents", alice["root"]["id"], "suspended")
    r = api.task(alice["user"]["id"], alice["root"]["id"], expect=409)
    assert r["detail"]["code"] == "agent_inactive"


@pytest.mark.parametrize("purpose", ["", "   ", "x" * 501])
def test_invalid_purpose_rejected(client, alice, purpose):
    r = client.post(
        "/v1/tasks",
        json={
            "principal_user_id": alice["user"]["id"],
            "root_agent_id": alice["root"]["id"],
            "purpose": purpose,
        },
    )
    assert r.status_code == 422


def test_client_cannot_set_task_status_on_create(client, alice):
    r = client.post(
        "/v1/tasks",
        json={
            "principal_user_id": alice["user"]["id"],
            "root_agent_id": alice["root"]["id"],
            "purpose": "x",
            "status": "completed",
        },
    )
    assert r.status_code == 422


@pytest.mark.parametrize("final", ["completed", "cancelled"])
def test_task_close_is_terminal(api, alice, final):
    task = api.task(alice["user"]["id"], alice["root"]["id"])
    closed = api.status("tasks", task["id"], final)
    assert closed["status"] == final
    assert closed["closed_at"] is not None

    for status in ["active", "completed", "cancelled"]:
        r = api.status("tasks", task["id"], status, expect=409)
        assert r["detail"]["code"] == "invalid_transition"


def test_list_tasks_filtered_by_status(client, api, alice):
    t1 = api.task(alice["user"]["id"], alice["root"]["id"], "one")
    api.task(alice["user"]["id"], alice["root"]["id"], "two")
    api.status("tasks", t1["id"], "completed")
    active = client.get("/v1/tasks", params={"status": "active"}).json()
    assert [t["purpose"] for t in active] == ["two"]
    assert client.get("/v1/tasks", params={"status": "bogus"}).status_code == 422


def test_get_missing_task_404(client):
    r = client.get("/v1/tasks/nope")
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "task_not_found"
