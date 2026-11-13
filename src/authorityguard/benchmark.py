"""Reproducible security benchmark.

Runs benign, boundary and adversarial scenarios through the real HTTP API (in-process, fresh
SQLite database, fresh signing key) and compares the result with an *unprotected baseline*:
an agent that calls tools directly, where every requested action is performed.

    python -m authorityguard.benchmark                 # print summary
    python -m authorityguard.benchmark --report docs/benchmark-report.md --json benchmark-results.json
    python -m authorityguard.benchmark --check         # exit 1 if any attack succeeds / benign blocked

A scenario "is performed" if the tool ran (HTTP 200), a dry-run said allow, or a delegation
was issued (HTTP 201). Attacks must not be performed; benign actions must be.
"""

import argparse
import base64
import itertools
import json
import platform
import statistics
import sys
import time
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session

from authorityguard import __version__
from authorityguard.capabilities.keys import Signer, get_signer
from authorityguard.capabilities.schemas import CapabilityIssue
from authorityguard.capabilities.service import issue_root_capability
from authorityguard.config import Settings
from authorityguard.gateway.tools import DEMO_DOCUMENTS
from authorityguard.policy.engine import get_policy
from authorityguard.storage.db import get_session, init_db, make_engine
from authorityguard.storage.models import Approval

PROJECT_DOCS = [p for p in DEMO_DOCUMENTS if p.startswith("/demo/projects/")]


# --- harness ----------------------------------------------------------------------


@dataclass
class Scenario:
    id: str
    category: str
    kind: str  # benign | boundary | attack
    expected: str  # allow | block
    description: str
    run: Callable[["Ctx"], tuple[bool, str]]


@dataclass
class Result:
    scenario: Scenario
    performed: bool
    reason: str
    correct: bool
    ms: float


@dataclass
class Ctx:
    client: TestClient
    engine: Any
    signer: Signer
    latencies: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    _n: itertools.count = field(default_factory=itertools.count)

    # -- raw calls --
    def _post(self, kind: str, path: str, body: dict, headers: dict | None = None):
        t = time.perf_counter()
        r = self.client.post(path, json=body, headers=headers or {})
        self.latencies[kind].append((time.perf_counter() - t) * 1000)
        return r

    def exec(self, tool, token, agent, resource, params=None, approval_id=None):
        body = {"resource": resource, "params": params or {}}
        if approval_id:
            body["approval_id"] = approval_id
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        if agent:
            headers["X-Agent-Id"] = agent
        r = self._post("execute", f"/v1/tools/{tool}/execute", body, headers)
        data = r.json()
        reason = data.get("reason_code") or (data.get("detail") or {}).get("code", "")
        return r.status_code, data, reason

    def authz(self, token, agent, action, resource):
        headers = {"Authorization": f"Bearer {token}", "X-Agent-Id": agent}
        r = self._post(
            "authorize", "/v1/authorize", {"action": action, "resource": resource}, headers
        )
        return r.json()

    def delegate(self, parent_token, delegator, child, scopes, ttl=None):
        body = {
            "parent_token": parent_token,
            "delegator_agent_id": delegator,
            "child_agent_id": child,
            "scopes": scopes,
        }
        if ttl is not None:
            body["ttl_seconds"] = ttl
        r = self._post("delegate", "/v1/capabilities/delegate", body)
        data = r.json()
        return r.status_code, (data.get("detail") or {}).get("code", "delegated")

    def mgmt(self, path, body):
        r = self.client.post(path, json=body)
        assert r.status_code < 300, f"{path}: {r.status_code} {r.text}"
        return r.json()

    # -- fixtures --
    def world(self, extra_agents: int = 0) -> dict[str, Any]:
        n = next(self._n)
        name = f"bench-user-{n}"
        user = self.mgmt("/v1/users", {"demo_name": name})
        root = self.mgmt("/v1/agents", {"owner_user_id": user["id"], "name": "research-agent"})
        child = self.mgmt(
            "/v1/agents",
            {"owner_user_id": user["id"], "name": "extract-agent", "parent_agent_id": root["id"]},
        )
        chain = [root, child]
        for i in range(extra_agents):
            chain.append(
                self.mgmt(
                    "/v1/agents",
                    {
                        "owner_user_id": user["id"],
                        "name": f"sub-{i}",
                        "parent_agent_id": chain[-1]["id"],
                    },
                )
            )
        task = self.mgmt(
            "/v1/tasks",
            {"principal_user_id": user["id"], "root_agent_id": root["id"], "purpose": "benchmark"},
        )
        email = f"mailto:{name}@example.test"
        cap = self.mgmt(
            "/v1/capabilities",
            {
                "task_id": task["id"],
                "scopes": [
                    {"action": "file.read", "resource": "/demo/projects/*"},
                    {"action": "doc.summarize", "resource": "*"},
                    {"action": "email.send", "resource": email},
                ],
            },
        )
        child_cap = self.mgmt(
            "/v1/capabilities/delegate",
            {
                "parent_token": cap["token"],
                "delegator_agent_id": root["id"],
                "child_agent_id": child["id"],
                "scopes": [{"action": "file.read", "resource": "/demo/projects/*"}],
            },
        )
        return {
            "name": name,
            "email": email,
            "user": user,
            "root": root["id"],
            "child": child["id"],
            "chain": [a["id"] for a in chain],
            "task": task["id"],
            "root_token": cap["token"],
            "child_token": child_cap["token"],
            "child_cap_id": child_cap["capability_id"],
            "root_cap_id": cap["capability_id"],
        }

    def outsider(self) -> dict[str, Any]:
        n = next(self._n)
        user = self.mgmt("/v1/users", {"demo_name": f"mallory-{n}"})
        agent = self.mgmt("/v1/agents", {"owner_user_id": user["id"], "name": "mallory-agent"})
        return {"user": user["id"], "agent": agent["id"]}

    def request_email_approval(self, w, body="summary"):
        params = {"subject": "Summary", "body": body}
        status, data, _ = self.exec("email.send", w["root_token"], w["root"], w["email"], params)
        assert status == 202, data
        return data["approval_id"], params

    def decide(self, approval_id, approve=True):
        self.mgmt(
            f"/v1/approvals/{approval_id}/decision",
            {"decision": "approve" if approve else "reject"},
        )


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def _tamper(token: str, **changes: Any) -> str:
    header, payload, sig = token.split(".")
    claims = jwt.decode(token, options={"verify_signature": False}) | changes
    return f"{header}.{_b64(claims)}.{sig}"


# --- scenarios --------------------------------------------------------------------


def build_scenarios(ctx: Ctx) -> list[Scenario]:
    w = ctx.world()  # shared, non-destructive world
    mallory = ctx.outsider()
    out: list[Scenario] = []

    def add(category, kind, expected, description, fn):
        out.append(
            Scenario(f"{category}-{len(out) + 1:03d}", category, kind, expected, description, fn)
        )

    def tool(t, token_key, agent_key, resource, params=None):
        def run(c: Ctx):
            token = w[token_key] if token_key in w else token_key
            agent = w[agent_key] if agent_key in w else agent_key
            status, _, reason = c.exec(t, token, agent, resource, params)
            return status == 200, reason

        return run

    def dry(token_key, agent_key, action, resource):
        def run(c: Ctx):
            d = c.authz(w[token_key], w.get(agent_key, agent_key), action, resource)
            return d["decision"] == "allow", d["reason_code"]

        return run

    # ---- benign ----
    for doc in PROJECT_DOCS:
        add(
            "benign_read",
            "benign",
            "allow",
            f"extract-agent reads {doc}",
            tool("file.read", "child_token", "child", doc),
        )
        add(
            "benign_read",
            "benign",
            "allow",
            f"research-agent reads {doc}",
            tool("file.read", "root_token", "root", doc),
        )
        for agent, token in (("child", "child_token"), ("root", "root_token")):
            add(
                "benign_dry_run",
                "benign",
                "allow",
                f"dry-run file.read {doc} as {agent}",
                dry(token, agent, "file.read", doc),
            )
    for i in range(24):
        text = ("Quarterly status update. " * (1 + i % 6)) + f"Item {i}."
        add(
            "benign_summarize",
            "benign",
            "allow",
            f"research-agent summarizes text #{i}",
            tool(
                "doc.summarize",
                "root_token",
                "root",
                f"/demo/projects/note-{i}.txt",
                {"text": text},
            ),
        )
    for i in range(6):

        def approved_email(c: Ctx, i=i):
            approval_id, params = c.request_email_approval(w, body=f"Summary #{i}")
            c.decide(approval_id)
            status, _, reason = c.exec(
                "email.send", w["root_token"], w["root"], w["email"], params, approval_id
            )
            return status == 200, reason

        add(
            "benign_approved_email",
            "benign",
            "allow",
            f"research-agent emails the principal after human approval #{i}",
            approved_email,
        )
    for scopes in (
        [{"action": "file.read", "resource": "/demo/projects/*"}],
        [{"action": "file.read", "resource": "/demo/projects/q3-plan.txt"}],
        [{"action": "file.read", "resource": "/demo/projects/roadmap*"}],
        [{"action": "doc.summarize", "resource": "*"}],
        [{"action": "doc.summarize", "resource": "/demo/projects/*"}],
        [{"action": "email.send", "resource": w["email"]}],
    ):
        add(
            "benign_delegation",
            "benign",
            "allow",
            f"narrower delegation {scopes[0]}",
            lambda c, s=scopes: (lambda st: (st[0] == 201, st[1]))(
                c.delegate(w["root_token"], w["root"], w["child"], s)
            ),
        )

    # ---- boundary ----
    def exact_child(c: Ctx, target: str, granted: str):
        r = c.client.post(
            "/v1/capabilities/delegate",
            json={
                "parent_token": w["root_token"],
                "delegator_agent_id": w["root"],
                "child_agent_id": w["child"],
                "scopes": [{"action": "file.read", "resource": granted}],
            },
        )
        token = r.json()["token"]
        status, _, reason = c.exec("file.read", token, w["child"], target)
        return status == 200, reason

    for doc in PROJECT_DOCS:
        add(
            "boundary_exact_scope",
            "boundary",
            "allow",
            f"exact-file capability reads {doc}",
            lambda c, d=doc: exact_child(c, d, d),
        )
    other = PROJECT_DOCS[1]
    for doc in [d for d in PROJECT_DOCS if d != other]:
        add(
            "boundary_exact_scope_deny",
            "boundary",
            "block",
            f"exact-file capability for {other} reads {doc}",
            lambda c, d=doc: exact_child(c, d, other),
        )
    for res, why in [
        ("/demo/projects-archive/old-plan.txt", "sibling folder sharing the prefix"),
        ("/demo/projectsX/q3-plan.txt", "prefix without separator"),
        ("/demo/project/q3-plan.txt", "similar folder name"),
        ("/DEMO/projects/q3-plan.txt", "case variation"),
        ("/demo/projects/", "folder itself, trailing slash"),
        ("/demo", "parent folder"),
    ]:
        add(
            "boundary_resource",
            "boundary",
            "block",
            f"extract-agent reads {res} ({why})",
            tool("file.read", "child_token", "child", res),
        )
    for res in [
        w["email"] + ".evil.example.com",
        w["email"].upper(),
        "mailto:" + w["name"] + "@example.com",
    ]:
        add(
            "boundary_resource",
            "boundary",
            "block",
            f"research-agent emails look-alike {res}",
            tool("email.send", "root_token", "root", res, {"subject": "s", "body": "b"}),
        )

    # ---- attacks: scope escalation ----
    for target in ["mailto:attacker@example.com", "mailto:exfil@example.net", w["email"]]:
        add(
            "scope_escalation",
            "attack",
            "block",
            f"extract-agent (file.read only) emails {target}",
            tool("email.send", "child_token", "child", target, {"subject": "data", "body": "x"}),
        )
    for doc in PROJECT_DOCS[:3]:
        add(
            "scope_escalation",
            "attack",
            "block",
            f"extract-agent summarizes {doc} (not granted)",
            tool("doc.summarize", "child_token", "child", doc, {"text": "x"}),
        )
    for action in ["file.write", "file.delete", "admin.grant_role"]:
        add(
            "scope_escalation",
            "attack",
            "block",
            f"research-agent attempts {action}",
            dry("root_token", "root", action, "/demo/projects/q3-plan.txt"),
        )

    # ---- attacks: resource escape ----
    escapes = [
        "/demo/hr/salaries.txt",
        "/etc/passwd",
        "/demo/projects/../hr/salaries.txt",
        "/demo/projects/./../../etc/passwd",
        "/demo/projects//../hr/salaries.txt",
        "/demo/projects/%2e%2e/hr/salaries.txt",
        "/demo/projects\\..\\hr\\salaries.txt",
        " /demo/projects/q3-plan.txt",
    ]
    for res in escapes:
        for agent, token in (("child", "child_token"), ("root", "root_token")):
            add(
                "resource_escape",
                "attack",
                "block",
                f"{agent} reads {res!r}",
                tool("file.read", token, agent, res),
            )

    # ---- attacks: token theft / confused deputy ----
    add(
        "token_theft",
        "attack",
        "block",
        "extract-agent uses research-agent's token to email out",
        tool(
            "email.send",
            "root_token",
            "child",
            "mailto:attacker@example.com",
            {"subject": "x", "body": "y"},
        ),
    )
    add(
        "token_theft",
        "attack",
        "block",
        "extract-agent uses research-agent's token to summarize",
        tool("doc.summarize", "root_token", "child", "/demo/projects/q3-plan.txt", {"text": "x"}),
    )
    add(
        "token_theft",
        "attack",
        "block",
        "extract-agent uses research-agent's token to email the principal",
        tool("email.send", "root_token", "child", w["email"], {"subject": "x", "body": "y"}),
    )
    add(
        "token_theft",
        "attack",
        "block",
        "another user's agent uses research-agent's token",
        tool("file.read", "root_token", mallory["agent"], PROJECT_DOCS[0]),
    )
    add(
        "token_theft",
        "attack",
        "block",
        "another user's agent uses extract-agent's token",
        tool("file.read", "child_token", mallory["agent"], PROJECT_DOCS[0]),
    )
    add(
        "token_theft",
        "attack",
        "block",
        "token presented without X-Agent-Id",
        tool("file.read", "child_token", "", PROJECT_DOCS[0]),
    )
    add(
        "token_theft",
        "attack",
        "block",
        "extract-agent claims to be research-agent (spoofed id)",
        tool("doc.summarize", "child_token", "root", "/demo/projects/q3-plan.txt", {"text": "x"}),
    )
    add(
        "token_theft",
        "attack",
        "block",
        "no capability at all",
        tool("file.read", "", "child", PROJECT_DOCS[0]),
    )

    # ---- attacks: token tampering / forgery ----
    add(
        "token_tampering",
        "attack",
        "block",
        "extract-agent edits its token to add email.send",
        lambda c: (lambda s: (s[0] == 200, s[2]))(
            c.exec(
                "email.send",
                _tamper(w["child_token"], scopes=[{"action": "email.send", "resource": "*"}]),
                w["child"],
                "mailto:attacker@example.com",
                {"subject": "x", "body": "y"},
            )
        ),
    )
    add(
        "token_tampering",
        "attack",
        "block",
        "token edited to extend expiry by a year",
        lambda c: (lambda s: (s[0] == 200, s[2]))(
            c.exec(
                "file.read",
                _tamper(w["child_token"], exp=int(time.time()) + 31_536_000),
                w["child"],
                PROJECT_DOCS[0],
            )
        ),
    )
    attacker = Signer(Ed25519PrivateKey.generate(), "authorityguard", "authorityguard-gateway")
    forged_claims = jwt.decode(w["child_token"], options={"verify_signature": False})
    add(
        "token_tampering",
        "attack",
        "block",
        "token forged with an attacker's key",
        lambda c: (lambda s: (s[0] == 200, s[2]))(
            c.exec("file.read", attacker.sign(forged_claims), w["child"], PROJECT_DOCS[0])
        ),
    )
    add(
        "token_tampering",
        "attack",
        "block",
        "unsigned token (alg: none)",
        lambda c: (lambda s: (s[0] == 200, s[2]))(
            c.exec(
                "file.read",
                jwt.encode(forged_claims, None, algorithm="none"),
                w["child"],
                PROJECT_DOCS[0],
            )
        ),
    )
    add(
        "token_tampering",
        "attack",
        "block",
        "signature truncated",
        lambda c: (lambda s: (s[0] == 200, s[2]))(
            c.exec("file.read", w["child_token"][:-6], w["child"], PROJECT_DOCS[0])
        ),
    )
    add(
        "token_tampering",
        "attack",
        "block",
        "garbage token",
        tool("file.read", "not-a-token", "child", PROJECT_DOCS[0]),
    )
    add(
        "token_tampering",
        "attack",
        "block",
        "validly signed token that was never issued",
        lambda c: (lambda s: (s[0] == 200, s[2]))(
            c.exec(
                "file.read",
                c.signer.sign(forged_claims | {"jti": "never-issued"}),
                w["child"],
                PROJECT_DOCS[0],
            )
        ),
    )
    add(
        "token_tampering",
        "attack",
        "block",
        "token for a different audience",
        lambda c: (lambda s: (s[0] == 200, s[2]))(
            c.exec(
                "file.read",
                c.signer.sign(forged_claims | {"aud": "billing-service"}),
                w["child"],
                PROJECT_DOCS[0],
            )
        ),
    )

    def expired(c: Ctx):
        with Session(c.engine) as s:
            issued = issue_root_capability(
                s,
                c.signer,
                Settings(),
                CapabilityIssue(
                    task_id=w["task"],
                    scopes=[{"action": "file.read", "resource": "/demo/projects/*"}],
                ),
                now=datetime.now(UTC) - timedelta(hours=2),
            )
        status, _, reason = c.exec("file.read", issued.token, w["root"], PROJECT_DOCS[0])
        return status == 200, reason

    add("token_tampering", "attack", "block", "expired capability", expired)

    # ---- attacks: revocation / lifecycle (each on its own world) ----
    def after(change: Callable[[Ctx, dict], None], use_child: bool = True):
        def run(c: Ctx):
            wx = c.world()
            change(c, wx)
            agent, token = (
                (wx["child"], wx["child_token"]) if use_child else (wx["root"], wx["root_token"])
            )
            status, _, reason = c.exec("file.read", token, agent, PROJECT_DOCS[0])
            return status == 200, reason

        return run

    add(
        "revocation",
        "attack",
        "block",
        "child capability revoked, then used",
        after(lambda c, wx: c.mgmt(f"/v1/capabilities/{wx['child_cap_id']}/revoke", {})),
    )
    add(
        "revocation",
        "attack",
        "block",
        "parent capability revoked; child keeps using its own",
        after(lambda c, wx: c.mgmt(f"/v1/capabilities/{wx['root_cap_id']}/revoke", {})),
    )
    add(
        "revocation",
        "attack",
        "block",
        "extract-agent suspended, then acts",
        after(lambda c, wx: c.mgmt(f"/v1/agents/{wx['child']}/status", {"status": "suspended"})),
    )
    add(
        "revocation",
        "attack",
        "block",
        "parent agent revoked; child acts",
        after(lambda c, wx: c.mgmt(f"/v1/agents/{wx['root']}/status", {"status": "revoked"})),
    )
    add(
        "revocation",
        "attack",
        "block",
        "human principal suspended; agent acts",
        after(
            lambda c, wx: c.mgmt(f"/v1/users/{wx['user']['id']}/status", {"status": "suspended"}),
            False,
        ),
    )
    add(
        "revocation",
        "attack",
        "block",
        "task completed; agent keeps working",
        after(lambda c, wx: c.mgmt(f"/v1/tasks/{wx['task']}/status", {"status": "completed"})),
    )
    add(
        "revocation",
        "attack",
        "block",
        "task cancelled; agent keeps working",
        after(
            lambda c, wx: c.mgmt(f"/v1/tasks/{wx['task']}/status", {"status": "cancelled"}), False
        ),
    )

    # ---- attacks: delegation escalation ----
    def deleg(scopes, ttl=None, child_key="child", token_key="root_token", delegator_key="root"):
        def run(c: Ctx):
            child = w[child_key] if child_key in w else child_key
            st, reason = c.delegate(w[token_key], w[delegator_key], child, scopes, ttl)
            return st == 201, reason

        return run

    add(
        "delegation_escalation",
        "attack",
        "block",
        "delegate email.send to a broader recipient",
        deleg([{"action": "email.send", "resource": "mailto:*"}]),
    )
    add(
        "delegation_escalation",
        "attack",
        "block",
        "delegate file.read on /demo/*",
        deleg([{"action": "file.read", "resource": "/demo/*"}]),
    )
    add(
        "delegation_escalation",
        "attack",
        "block",
        "delegate file.read on *",
        deleg([{"action": "file.read", "resource": "*"}]),
    )
    add(
        "delegation_escalation",
        "attack",
        "block",
        "delegate an action the parent never had",
        deleg([{"action": "file.write", "resource": "/demo/projects/*"}]),
    )
    add(
        "delegation_escalation",
        "attack",
        "block",
        "child capability that outlives its parent",
        deleg([{"action": "file.read", "resource": "/demo/projects/*"}], ttl=3600),
    )
    add(
        "delegation_escalation",
        "attack",
        "block",
        "delegate to another user's agent",
        deleg(
            [{"action": "file.read", "resource": "/demo/projects/*"}], child_key=mallory["agent"]
        ),
    )
    add(
        "delegation_escalation",
        "attack",
        "block",
        "delegate to itself",
        deleg([{"action": "file.read", "resource": "/demo/projects/*"}], child_key="root"),
    )
    add(
        "delegation_escalation",
        "attack",
        "block",
        "extract-agent re-delegates using a spoofed delegator",
        deleg(
            [{"action": "file.read", "resource": "/demo/projects/*"}],
            token_key="child_token",
            delegator_key="root",
        ),
    )

    def too_deep(c: Ctx):
        wx = c.world(extra_agents=2)  # root -> child -> sub-0 -> sub-1
        scopes = [{"action": "file.read", "resource": "/demo/projects/*"}]
        token, parent = wx["child_token"], wx["child"]
        for agent in wx["chain"][2:]:
            r = c.client.post(
                "/v1/capabilities/delegate",
                json={
                    "parent_token": token,
                    "delegator_agent_id": parent,
                    "child_agent_id": agent,
                    "scopes": scopes,
                },
            )
            if r.status_code != 201:
                return False, r.json()["detail"]["code"]
            token, parent = r.json()["token"], agent
        return True, "delegated"

    add(
        "delegation_escalation",
        "attack",
        "block",
        "delegation chain deeper than policy allows",
        too_deep,
    )

    # ---- attacks: approval bypass / swap / replay ----
    def no_approval(c: Ctx):
        status, _, reason = c.exec(
            "email.send",
            w["root_token"],
            w["root"],
            w["email"],
            {"subject": "s", "body": "unapproved"},
        )
        return status == 200, reason

    add("approval_bypass", "attack", "block", "email without asking a human", no_approval)

    def fake_approval(c: Ctx):
        status, _, reason = c.exec(
            "email.send",
            w["root_token"],
            w["root"],
            w["email"],
            {"subject": "s", "body": "b"},
            approval_id="00000000-fake",
        )
        return status == 200, reason

    add("approval_bypass", "attack", "block", "email with a made-up approval id", fake_approval)

    def pending(c: Ctx):
        approval_id, params = c.request_email_approval(w, "pending")
        status, _, reason = c.exec(
            "email.send", w["root_token"], w["root"], w["email"], params, approval_id
        )
        return status == 200, reason

    add("approval_bypass", "attack", "block", "email using an approval nobody decided yet", pending)

    def rejected(c: Ctx):
        approval_id, params = c.request_email_approval(w, "rejected")
        c.decide(approval_id, approve=False)
        status, _, reason = c.exec(
            "email.send", w["root_token"], w["root"], w["email"], params, approval_id
        )
        return status == 200, reason

    add("approval_bypass", "attack", "block", "email after the human rejected it", rejected)

    def expired_approval(c: Ctx):
        approval_id, params = c.request_email_approval(w, "expiring")
        c.decide(approval_id)
        with Session(c.engine) as s:
            a = s.get(Approval, approval_id)
            a.expires_at = datetime.now(UTC) - timedelta(minutes=1)
            s.add(a)
            s.commit()
        status, _, reason = c.exec(
            "email.send", w["root_token"], w["root"], w["email"], params, approval_id
        )
        return status == 200, reason

    add("approval_bypass", "attack", "block", "email with an expired approval", expired_approval)

    def swap(change: Callable[[dict], tuple[str, dict]]):
        def run(c: Ctx):
            approval_id, params = c.request_email_approval(w, "approved body")
            c.decide(approval_id)
            resource, new_params = change(params)
            status, _, reason = c.exec(
                "email.send", w["root_token"], w["root"], resource, new_params, approval_id
            )
            return status == 200, reason

        return run

    add(
        "approval_swap",
        "attack",
        "block",
        "approved email, body swapped before sending",
        swap(lambda p: (w["email"], p | {"body": "the full customer list"})),
    )
    add(
        "approval_swap",
        "attack",
        "block",
        "approved email, subject swapped",
        swap(lambda p: (w["email"], p | {"subject": "Re: confidential"})),
    )
    add(
        "approval_swap",
        "attack",
        "block",
        "approved email, extra parameter smuggled in",
        swap(lambda p: (w["email"], p | {"bcc": "attacker@example.com"})),
    )
    add(
        "approval_swap",
        "attack",
        "block",
        "approved email, recipient swapped to attacker",
        swap(lambda p: ("mailto:attacker@example.com", p)),
    )

    def replay(times: int):
        def run(c: Ctx):
            approval_id, params = c.request_email_approval(w, f"replay x{times}")
            c.decide(approval_id)
            c.exec("email.send", w["root_token"], w["root"], w["email"], params, approval_id)
            performed, reason = False, ""
            for _ in range(times):
                status, _, reason = c.exec(
                    "email.send", w["root_token"], w["root"], w["email"], params, approval_id
                )
                performed = performed or status == 200
            return performed, reason

        return run

    for times in (1, 2, 5):
        add("replay", "attack", "block", f"approved email replayed {times}x", replay(times))

    def cross_agent_approval(c: Ctx):
        approval_id, params = c.request_email_approval(w, "for root only")
        c.decide(approval_id)
        status, _, reason = c.exec(
            "email.send", w["child_token"], w["child"], w["email"], params, approval_id
        )
        return status == 200, reason

    add(
        "approval_swap",
        "attack",
        "block",
        "extract-agent uses research-agent's approval",
        cross_agent_approval,
    )

    return out


# --- runner -----------------------------------------------------------------------


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def _make_ctx() -> Ctx:
    from apps.api.main import create_app

    engine = make_engine("sqlite://", poolclass=StaticPool)
    init_db(engine)
    signer = Signer(Ed25519PrivateKey.generate(), "authorityguard", "authorityguard-gateway")
    app = create_app()

    def _session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _session
    app.dependency_overrides[get_signer] = lambda: signer
    return Ctx(client=TestClient(app), engine=engine, signer=signer)


def run_benchmark(load_requests: int = 500) -> dict[str, Any]:
    ctx = _make_ctx()
    scenarios = build_scenarios(ctx)
    results: list[Result] = []
    for sc in scenarios:
        t = time.perf_counter()
        performed, reason = sc.run(ctx)
        ms = (time.perf_counter() - t) * 1000
        results.append(Result(sc, performed, reason, performed == (sc.expected == "allow"), ms))

    # Load: repeated authorization decisions on one capability.
    w = ctx.world()
    load: list[float] = []
    for i in range(load_requests):
        t = time.perf_counter()
        ctx.authz(w["child_token"], w["child"], "file.read", PROJECT_DOCS[i % len(PROJECT_DOCS)])
        load.append((time.perf_counter() - t) * 1000)

    from sqlmodel import select

    from authorityguard.storage.models import AuthorizationDecision

    with Session(ctx.engine) as s:
        server_ms = [d.latency_ms for d in s.exec(select(AuthorizationDecision))]

    return summarize(results, load, server_ms)


def summarize(results: list[Result], load: list[float], server_ms: list[float]) -> dict[str, Any]:
    should_block = [r for r in results if r.scenario.expected == "block"]
    should_allow = [r for r in results if r.scenario.expected == "allow"]
    by_cat: dict[str, dict[str, Any]] = {}
    for r in results:
        c = by_cat.setdefault(
            r.scenario.category,
            {
                "kind": r.scenario.kind,
                "expected": r.scenario.expected,
                "count": 0,
                "protected_correct": 0,
                "baseline_correct": 0,
                "reasons": defaultdict(int),
            },
        )
        c["count"] += 1
        c["protected_correct"] += r.correct
        # Baseline performs every requested action.
        c["baseline_correct"] += r.scenario.expected == "allow"
        c["reasons"][r.reason or "-"] += 1

    def rate(n: int, d: int) -> float:
        return round(100 * n / d, 2) if d else 0.0

    return {
        "meta": {
            "version": __version__,
            "policy_version": get_policy().version,
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "python": platform.python_version(),
            "platform": platform.platform(),
        },
        "totals": {
            "scenarios": len(results),
            "should_block": len(should_block),
            "should_allow": len(should_allow),
        },
        "protected": {
            "attack_success_rate": rate(sum(r.performed for r in should_block), len(should_block)),
            "false_block_rate": rate(sum(not r.performed for r in should_allow), len(should_allow)),
            "task_completion_rate": rate(sum(r.performed for r in should_allow), len(should_allow)),
            "accuracy": rate(sum(r.correct for r in results), len(results)),
        },
        "baseline": {
            "attack_success_rate": 100.0 if should_block else 0.0,
            "false_block_rate": 0.0,
            "task_completion_rate": 100.0,
            "accuracy": rate(len(should_allow), len(results)),
        },
        "latency_ms": {
            "server_authorization_p50": round(_percentile(server_ms, 0.5), 3),
            "server_authorization_p95": round(_percentile(server_ms, 0.95), 3),
            "load_requests": len(load),
            "end_to_end_authorize_p50": round(_percentile(load, 0.5), 2),
            "end_to_end_authorize_p95": round(_percentile(load, 0.95), 2),
            "end_to_end_authorize_p99": round(_percentile(load, 0.99), 2),
            "mean_scenario_ms": round(statistics.mean(r.ms for r in results), 2) if results else 0,
        },
        "categories": {k: {**v, "reasons": dict(v["reasons"])} for k, v in sorted(by_cat.items())},
        "failures": [
            {
                "id": r.scenario.id,
                "description": r.scenario.description,
                "expected": r.scenario.expected,
                "performed": r.performed,
                "reason": r.reason,
            }
            for r in results
            if not r.correct
        ],
        "scenarios": [
            {
                "id": r.scenario.id,
                "category": r.scenario.category,
                "kind": r.scenario.kind,
                "expected": r.scenario.expected,
                "performed": r.performed,
                "reason": r.reason,
                "correct": r.correct,
                "description": r.scenario.description,
            }
            for r in results
        ],
    }


def render_markdown(s: dict[str, Any]) -> str:
    p, b, lat, t = s["protected"], s["baseline"], s["latency_ms"], s["totals"]
    lines = [
        "# AuthorityGuard — Benchmark Report",
        "",
        f"Generated {s['meta']['generated_at']} · AuthorityGuard v{s['meta']['version']} · "
        f"policy `{s['meta']['policy_version']}` · Python {s['meta']['python']}",
        "",
        "Reproduce: `python -m authorityguard.benchmark --report docs/benchmark-report.md`",
        "",
        "## Method",
        "",
        "Every scenario goes through the real HTTP API in-process, against a fresh SQLite database",
        "and a fresh Ed25519 key. **Baseline** = the same agents calling tools directly with no",
        "authorization layer, so every requested action is performed. A scenario is *performed* if",
        "the tool ran (HTTP 200), a dry-run returned `allow`, or a delegation was issued (HTTP 201).",
        "",
        f"* **{t['scenarios']} scenarios**: {t['should_allow']} should succeed (benign + boundary-allow), "
        f"{t['should_block']} should be blocked (attacks + boundary-deny).",
        "* Agents are deterministic (no LLM), so results are exactly reproducible.",
        "",
        "## Results",
        "",
        "| Metric | Unprotected baseline | AuthorityGuard |",
        "|--------|---------------------:|---------------:|",
        f"| Attack success rate (lower is better) | {b['attack_success_rate']}% | **{p['attack_success_rate']}%** |",
        f"| False-block rate on legitimate actions | {b['false_block_rate']}% | **{p['false_block_rate']}%** |",
        f"| Legitimate task completion | {b['task_completion_rate']}% | **{p['task_completion_rate']}%** |",
        f"| Overall decision accuracy | {b['accuracy']}% | **{p['accuracy']}%** |",
        "",
        "## Latency",
        "",
        "| Measure | p50 | p95 | p99 |",
        "|---------|----:|----:|----:|",
        f"| Server-side authorization decision (ms) | {lat['server_authorization_p50']} | {lat['server_authorization_p95']} | – |",
        f"| End-to-end `/v1/authorize`, {lat['load_requests']} sequential requests (ms) | "
        f"{lat['end_to_end_authorize_p50']} | {lat['end_to_end_authorize_p95']} | {lat['end_to_end_authorize_p99']} |",
        "",
        "Measured in-process on a single core with SQLite; numbers are indicative, not a production SLO.",
        "",
        "## By category",
        "",
        "| Category | Kind | Expected | Scenarios | Baseline correct | AuthorityGuard correct | Reason codes |",
        "|----------|------|----------|----------:|-----------------:|-----------------------:|--------------|",
    ]
    for name, c in s["categories"].items():
        reasons = ", ".join(f"`{k}`×{v}" for k, v in sorted(c["reasons"].items()))
        lines.append(
            f"| {name} | {c['kind']} | {c['expected']} | {c['count']} | "
            f"{c['baseline_correct']}/{c['count']} | {c['protected_correct']}/{c['count']} | {reasons} |"
        )
    lines += ["", "## Failures", ""]
    if s["failures"]:
        lines += [
            f"* `{f['id']}` {f['description']}: expected {f['expected']}, "
            f"performed={f['performed']} ({f['reason']})"
            for f in s["failures"]
        ]
    else:
        lines.append("None. Every scenario produced the expected outcome.")
    lines += [
        "",
        "## Limitations",
        "",
        "* Scenarios are hand-designed from the threat model; they show the controls work for these",
        "  attack classes, not that every possible attack is prevented.",
        "* A permitted action can still be misused *within* its scope (e.g. summarizing the wrong",
        "  allowed document). Scopes cannot capture full natural-language intent.",
        "* Only tools routed through the gateway are protected.",
        "* Agents are deterministic stand-ins; a real LLM changes *which* calls are attempted, not",
        "  how each call is decided.",
        "",
        "## All scenarios",
        "",
        "| ID | Expected | Performed | Reason | Description |",
        "|----|----------|-----------|--------|-------------|",
    ]
    lines += [
        f"| {r['id']} | {r['expected']} | {'yes' if r['performed'] else 'no'} | `{r['reason']}` | "
        f"{r['description'].replace('|', '/')} |"
        for r in s["scenarios"]
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--report", help="write a Markdown report to this path")
    ap.add_argument("--json", help="write raw results as JSON to this path")
    ap.add_argument("--load", type=int, default=500, help="number of load-test requests")
    ap.add_argument("--check", action="store_true", help="exit 1 unless every scenario is correct")
    args = ap.parse_args(argv)

    s = run_benchmark(load_requests=args.load)
    p, lat = s["protected"], s["latency_ms"]
    print(
        f"scenarios={s['totals']['scenarios']}  attack_success={p['attack_success_rate']}%  "
        f"false_block={p['false_block_rate']}%  accuracy={p['accuracy']}%  "
        f"authorize p50={lat['end_to_end_authorize_p50']}ms p95={lat['end_to_end_authorize_p95']}ms"
    )
    for f in s["failures"]:
        print(f"  FAIL {f['id']}: {f['description']} (performed={f['performed']}, {f['reason']})")
    if args.report:
        Path(args.report).write_text(render_markdown(s), encoding="utf-8")
        print(f"report -> {args.report}")
    if args.json:
        Path(args.json).write_text(json.dumps(s, indent=2), encoding="utf-8")
        print(f"json -> {args.json}")
    return 1 if (args.check and s["failures"]) else 0


if __name__ == "__main__":
    sys.exit(main())
