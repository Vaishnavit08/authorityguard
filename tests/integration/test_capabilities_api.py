"""Issuing, verifying and revoking capabilities through the API."""

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from sqlmodel import Session, select

from authorityguard.capabilities.keys import token_hash
from authorityguard.capabilities.schemas import CapabilityIssue
from authorityguard.capabilities.service import issue_root_capability
from authorityguard.config import Settings
from authorityguard.storage.models import Capability


@pytest.fixture
def world(api):
    return api.setup_task()


def test_issue_and_verify(api, world, signer):
    cap = api.capability(world["task"]["id"])
    assert cap["subject_agent_id"] == world["root"]["id"]
    assert cap["token_type"] == "Bearer"

    claims = jwt.decode(cap["token"], options={"verify_signature": False})
    assert claims["sub"] == world["root"]["id"]
    assert claims["task_id"] == world["task"]["id"]
    assert claims["principal_id"] == world["user"]["id"]
    assert claims["exp"] - claims["iat"] == 900  # default 15 minutes
    assert claims["depth"] == 0

    result = api.verify(cap["token"], world["root"]["id"])
    assert result["valid"] is True
    assert result["capability"]["id"] == cap["capability_id"]


def test_duplicate_scopes_collapsed(api, world):
    scope = {"action": "file.read", "resource": "/demo/projects/*"}
    cap = api.capability(world["task"]["id"], scopes=[scope, scope])
    assert len(cap["scopes"]) == 1


def test_database_stores_hash_not_token(api, world, engine):
    cap = api.capability(world["task"]["id"])
    with Session(engine) as s:
        row = s.exec(select(Capability)).one()
    assert row.token_hash == token_hash(cap["token"])
    assert cap["token"] not in str(row.model_dump())


def test_listing_never_returns_tokens(client, api, world):
    api.capability(world["task"]["id"])
    listed = client.get("/v1/capabilities", params={"task_id": world["task"]["id"]}).json()
    assert len(listed) == 1
    assert "token" not in listed[0]


def test_issue_for_unknown_task_404(api):
    assert api.capability("nope", expect=404)["detail"]["code"] == "task_not_found"


@pytest.mark.parametrize("final", ["completed", "cancelled"])
def test_issue_for_closed_task_rejected(api, world, final):
    api.status("tasks", world["task"]["id"], final)
    r = api.capability(world["task"]["id"], expect=409)
    assert r["detail"]["code"] == "task_inactive"


def test_issue_when_root_agent_suspended_rejected(api, world):
    api.status("agents", world["root"]["id"], "suspended")
    r = api.capability(world["task"]["id"], expect=409)
    assert r["detail"]["code"] == "agent_inactive"


def test_ttl_above_max_rejected(api, world):
    r = api.capability(world["task"]["id"], ttl_seconds=3601, expect=422)
    assert r["detail"]["code"] == "ttl_too_long"


@pytest.mark.parametrize(
    "scope",
    [
        {"action": "FILE.READ", "resource": "/x"},  # uppercase
        {"action": "read", "resource": "/x"},  # no namespace
        {"action": "file.read", "resource": "/a*/b"},  # wildcard in the middle
        {"action": "file.read", "resource": "/a b"},  # whitespace
        {"action": "file.read", "resource": "/x", "admin": True},  # unknown field
    ],
)
def test_invalid_scopes_rejected(api, world, scope):
    api.capability(world["task"]["id"], scopes=[scope], expect=422)


def test_empty_scopes_rejected(api, world):
    api.capability(world["task"]["id"], scopes=[], expect=422)


# --- use-time checks: a once-valid token stops working when the world changes ----


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (("tasks", "task", "completed"), "task_inactive"),
        (("agents", "root", "suspended"), "agent_inactive"),
        (("agents", "root", "revoked"), "agent_inactive"),
        (("users", "user", "suspended"), "principal_inactive"),
    ],
)
def test_token_stops_working_after_state_change(api, world, change, reason):
    cap = api.capability(world["task"]["id"])
    kind, key, status = change
    api.status(kind, world[key]["id"], status)
    assert api.verify(cap["token"]) == {"valid": False, "reason_code": reason, "capability": None}


def test_revoked_capability_rejected(client, api, world):
    cap = api.capability(world["task"]["id"])
    r = client.post(f"/v1/capabilities/{cap['capability_id']}/revoke")
    assert r.status_code == 200 and r.json()["revoked_at"] is not None
    assert api.verify(cap["token"])["reason_code"] == "capability_revoked"
    again = client.post(f"/v1/capabilities/{cap['capability_id']}/revoke")
    assert again.status_code == 409


def test_expired_capability_rejected(api, world, engine, signer):
    with Session(engine) as s:
        issued = issue_root_capability(
            s,
            signer,
            Settings(),
            CapabilityIssue(
                task_id=world["task"]["id"],
                scopes=[{"action": "file.read", "resource": "*"}],
            ),
            now=datetime.now(UTC) - timedelta(hours=2),
        )
    assert api.verify(issued.token)["reason_code"] == "expired"


def test_validly_signed_but_unknown_capability_rejected(api, world, signer):
    # Even a correctly signed token is refused if we never recorded issuing it.
    cap = api.capability(world["task"]["id"])
    claims = jwt.decode(cap["token"], options={"verify_signature": False})
    ghost = signer.sign(claims | {"jti": "never-issued"})
    assert api.verify(ghost)["reason_code"] == "unknown_capability"


def test_reissued_token_with_same_jti_rejected(api, world, signer):
    # Same jti, different content (e.g. scopes widened with a leaked key): hash check fails.
    cap = api.capability(world["task"]["id"])
    claims = jwt.decode(cap["token"], options={"verify_signature": False})
    widened = signer.sign(claims | {"scopes": [{"action": "email.send", "resource": "*"}]})
    assert api.verify(widened)["reason_code"] == "token_mismatch"


def test_tampered_token_via_api(api, world):
    cap = api.capability(world["task"]["id"])
    tampered = cap["token"][:-4] + ("AAAA" if not cap["token"].endswith("AAAA") else "BBBB")
    assert api.verify(tampered)["reason_code"] in {"invalid_signature", "malformed"}
