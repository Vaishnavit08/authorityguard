"""T2 — confused deputy: a sub-agent (or any other agent) presents the root agent's token."""


def test_sub_agent_cannot_use_root_agents_token(api):
    world = api.setup_task()
    root_cap = api.capability(world["task"]["id"])

    # The extract-agent got hold of the research-agent's broader token (e.g. via shared memory).
    stolen = api.verify(root_cap["token"], agent_id=world["child"]["id"])
    assert stolen == {"valid": False, "reason_code": "subject_mismatch", "capability": None}

    # The rightful holder can still use it.
    assert api.verify(root_cap["token"], agent_id=world["root"]["id"])["valid"] is True


def test_other_users_agent_cannot_use_token(api):
    world = api.setup_task()
    root_cap = api.capability(world["task"]["id"])
    mallory = api.user("mallory-demo")
    mallory_agent = api.agent(mallory["id"], "mallory-agent")

    result = api.verify(root_cap["token"], agent_id=mallory_agent["id"])
    assert result["reason_code"] == "subject_mismatch"
