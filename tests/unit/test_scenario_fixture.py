"""The seeded scenario must stay internally consistent as later milestones build on it."""


def test_delegated_scopes_are_subset_of_root(scenario):
    root = {(s["action"], s["resource"]) for s in scenario["task"]["root_scopes"]}
    for d in scenario["task"]["delegations"]:
        assert {(s["action"], s["resource"]) for s in d["scopes"]} <= root


def test_scenario_contains_attack_and_benign_cases(scenario):
    decisions = {e["decision"] for e in scenario["expected_decisions"]}
    assert {"allow", "deny", "approval_required"} <= decisions


def test_scenario_uses_only_synthetic_domains(scenario):
    for e in scenario["expected_decisions"]:
        if e["resource"].startswith("mailto:"):
            assert e["resource"].endswith(("@example.com", "@example.test"))
