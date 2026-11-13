"""Audit trail, redaction and the delegation graph (Week 5): threats T11, T12."""

from authorityguard.audit.service import redact


def test_redact_removes_secrets_and_contents():
    out = redact(
        {
            "token": "eyJ...",
            "nested": {"body": "secret text", "to": "a@x.test"},
            "list": [{"content": "doc"}],
            "long": "x" * 500,
        }
    )
    assert out["token"] == "[redacted]"
    assert out["nested"] == {"body": "[redacted]", "to": "a@x.test"}
    assert out["list"] == [{"content": "[redacted]"}]
    assert len(out["long"]) <= 201


def test_events_never_contain_tokens_or_document_text(client):
    r = client.post("/v1/demo/run", json={"auto_approve": True})
    assert r.status_code == 200
    run = r.json()
    events = client.get("/v1/audit/events", params={"trace_id": run["trace_id"], "limit": 500})
    dump = events.text
    assert "eyJ" not in dump  # no JWTs
    assert "IGNORE PREVIOUS INSTRUCTIONS" not in dump  # no document contents
    assert "Key accounts" not in dump


def test_every_gateway_call_has_a_decision(client):
    run = client.post("/v1/demo/run", json={"auto_approve": True}).json()
    gateway_steps = [s for s in run["steps"] if s.get("action")]
    decisions = client.get("/v1/decisions", params={"trace_id": run["trace_id"], "limit": 500})
    assert len(decisions.json()) == len(gateway_steps)


def test_task_graph_reconstructs_chain(client):
    run = client.post("/v1/demo/run", json={"auto_approve": True}).json()
    g = client.get(f"/v1/tasks/{run['task_id']}/graph").json()
    assert g["principal"]["demo_name"].startswith("alice-demo")
    caps = {c["depth"]: c for c in g["capabilities"]}
    assert caps[1]["parent_capability_id"] == caps[0]["id"]
    names = {a["id"]: a["name"] for a in g["agents"]}
    assert names[caps[0]["subject_agent_id"]] == "research-agent"
    assert names[caps[1]["subject_agent_id"]] == "extract-agent"
    assert any(d["reason_code"] == "scope_not_granted" for d in g["decisions"])


def test_agent_delegation_graph(api, client):
    w = api.setup_task()
    g = client.get(f"/v1/agents/{w['child']['id']}/delegation-graph").json()
    assert [a["name"] for a in g["ancestors"]] == ["research-agent"]
    assert g["owner"]["demo_name"] == "alice-demo"
    root = client.get(f"/v1/agents/{w['root']['id']}/delegation-graph").json()
    assert root["tree"]["children"][0]["agent"]["name"] == "extract-agent"


def test_stats(client):
    client.post("/v1/demo/run", json={"auto_approve": True})
    s = client.get("/v1/stats").json()
    assert s["denied"] >= 5 and s["allowed"] >= 5 and s["audit_events"] > 10
