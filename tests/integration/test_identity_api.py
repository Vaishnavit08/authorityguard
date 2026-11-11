"""Identity registry: every agent has a unique ID and a known, active owner / parent (threat T9)."""


def _user(client, name="alice-demo"):
    r = client.post("/v1/users", json={"demo_name": name})
    assert r.status_code == 201, r.text
    return r.json()


def _agent(client, owner_id, name="research-agent", parent_id=None):
    return client.post(
        "/v1/agents",
        json={"owner_user_id": owner_id, "name": name, "parent_agent_id": parent_id},
    )


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_create_and_list_users(client):
    alice = _user(client)
    assert alice["status"] == "active"
    assert client.get(f"/v1/users/{alice['id']}").json()["demo_name"] == "alice-demo"
    assert [u["id"] for u in client.get("/v1/users").json()] == [alice["id"]]


def test_duplicate_user_rejected(client):
    _user(client)
    r = client.post("/v1/users", json={"demo_name": "alice-demo"})
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "user_exists"


def test_unknown_fields_rejected(client):
    # Callers must not be able to set server-controlled fields such as status.
    r = client.post("/v1/users", json={"demo_name": "eve-demo", "status": "active", "id": "x"})
    assert r.status_code == 422


def test_invalid_name_rejected(client):
    assert client.post("/v1/users", json={"demo_name": "<script>"}).status_code == 422


def test_create_root_and_child_agent(client):
    alice = _user(client)
    root = _agent(client, alice["id"]).json()
    child = _agent(client, alice["id"], "extract-agent", root["id"])
    assert child.status_code == 201
    assert child.json()["parent_agent_id"] == root["id"]
    assert root["id"] != child.json()["id"]

    listed = client.get("/v1/agents", params={"owner_user_id": alice["id"]}).json()
    assert {a["name"] for a in listed} == {"research-agent", "extract-agent"}


def test_agent_with_unknown_owner_rejected(client):
    r = _agent(client, "does-not-exist")
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "owner_not_found"


def test_agent_with_unknown_parent_rejected(client):
    alice = _user(client)
    r = _agent(client, alice["id"], parent_id="does-not-exist")
    assert r.status_code == 404
    assert r.json()["detail"]["code"] == "parent_not_found"


def test_child_cannot_attach_to_another_users_agent(client):
    alice = _user(client, "alice-demo")
    mallory = _user(client, "mallory-demo")
    alice_root = _agent(client, alice["id"]).json()

    r = _agent(client, mallory["id"], "sneaky-agent", alice_root["id"])
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "owner_mismatch"


def test_get_missing_agent_404(client):
    assert client.get("/v1/agents/nope").status_code == 404


def test_seed_scenario_identities(client, scenario):
    user = _user(client, scenario["user"]["demo_name"])
    ids = {}
    for a in scenario["agents"]:
        r = _agent(client, user["id"], a["name"], ids.get(a["parent"]))
        assert r.status_code == 201
        ids[a["key"]] = r.json()["id"]
    assert client.get(f"/v1/agents/{ids['extract']}").json()["parent_agent_id"] == ids["research"]
