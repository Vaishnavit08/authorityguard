"""Admin key protection for management endpoints, dashboard and meta endpoints."""

import pytest

from authorityguard.config import Settings, get_settings


@pytest.fixture
def locked(client):
    client.app.dependency_overrides[get_settings] = lambda: Settings(admin_api_key="s3cret-demo")
    yield client
    client.app.dependency_overrides.pop(get_settings)


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/v1/users", {"demo_name": "eve"}),
        ("/v1/agents", {"owner_user_id": "x", "name": "a"}),
        ("/v1/tasks", {"principal_user_id": "x", "root_agent_id": "y", "purpose": "p"}),
        (
            "/v1/capabilities",
            {"task_id": "x", "scopes": [{"action": "file.read", "resource": "*"}]},
        ),
        ("/v1/approvals/x/decision", {"decision": "approve"}),
        ("/v1/users/x/status", {"status": "suspended"}),
    ],
)
def test_management_requires_key_when_configured(locked, path, body):
    r = locked.post(path, json=body)
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "admin_key_required"
    wrong = locked.post(path, json=body, headers={"X-API-Key": "nope"})
    assert wrong.status_code == 401


def test_correct_key_works(locked):
    r = locked.post("/v1/users", json={"demo_name": "eve"}, headers={"X-API-Key": "s3cret-demo"})
    assert r.status_code == 201


def test_public_demo_works_with_key_configured(locked):
    # The demo uses the key internally; visitors never see it.
    r = locked.post("/v1/demo/run", json={"auto_approve": True})
    assert r.status_code == 200 and r.json()["status"] == "completed"


def test_reads_stay_public(locked):
    for path in ("/v1/stats", "/v1/decisions", "/v1/audit/events", "/v1/outbox", "/health"):
        assert locked.get(path).status_code == 200


def test_dashboard_and_root(client):
    r = client.get("/dashboard")
    assert r.status_code == 200 and "AuthorityGuard" in r.text
    assert client.get("/", follow_redirects=False).headers["location"] == "/dashboard"


def test_health_and_policy(client):
    h = client.get("/health").json()
    assert h["status"] == "ok" and h["policy_version"]
    assert client.get("/policy").json()["max_delegation_depth"] == 2


def test_security_headers(client):
    r = client.get("/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Trace-Id"]
