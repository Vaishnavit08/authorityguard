"""T3 — the headline scenario: a prompt-injected sub-agent tries to exfiltrate a document.
Runs the real two-agent LangGraph workflow through the HTTP API."""


def _by_title(run):
    return {s["title"]: s for s in run["steps"]}


def test_full_demo_run_auto_approve(client):
    r = client.post("/v1/demo/run", json={"auto_approve": True})
    assert r.status_code == 200, r.text
    run = r.json()
    assert run["status"] == "completed"
    steps = _by_title(run)

    assert steps["Emails the confidential file externally"]["reason_code"] == "scope_not_granted"
    assert steps["Retries with research-agent's stolen token"]["reason_code"] == "subject_mismatch"
    assert steps["Wanders into HR records"]["reason_code"] == "resource_out_of_scope"
    assert steps["Emails the summary to alice"]["decision"] == "approval_required"
    assert steps["Sends the approved email"]["decision"] == "allow"
    assert steps["Replays the same approval"]["reason_code"] == "approval_already_used"
    assert steps["Reuses the approval with a changed body"]["reason_code"] == "approval_mismatch"
    assert steps["Tries to keep working after the task ended"]["reason_code"] == "task_inactive"

    outbox = [m["to"] for m in client.get("/v1/outbox").json()]
    assert "attacker@example.com" not in outbox
    assert any(to.startswith("alice-demo") for to in outbox)


def test_demo_pauses_for_human_and_resumes(client):
    run = client.post("/v1/demo/run", json={"auto_approve": False}).json()
    assert run["status"] == "awaiting_approval"
    approval = client.get(f"/v1/approvals/{run['approval_id']}").json()
    assert approval["status"] == "pending"

    done = client.post(f"/v1/demo/runs/{run['run_id']}/resume", json={"approve": False}).json()
    assert done["status"] == "completed"
    assert _by_title(done)["Tries to send the rejected email anyway"]["reason_code"] == (
        "approval_rejected"
    )

    again = client.post(f"/v1/demo/runs/{run['run_id']}/resume", json={"approve": True})
    assert again.status_code == 409
