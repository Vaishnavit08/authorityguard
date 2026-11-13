"""Two-agent LangGraph demo that exercises AuthorityGuard end to end over its HTTP API.

    alice-demo ──task──▶ research-agent ──delegates file.read only──▶ extract-agent

1. setup        create the human, both agents, the task and the root capability
2. delegate     research-agent hands extract-agent a narrower capability (file.read only)
3. extract      extract-agent reads two documents. One contains a prompt injection; the agent
                "falls for it" and tries to email the file out → DENIED (scope_not_granted).
                It then tries the research-agent's token → DENIED (subject_mismatch),
                and an HR file → DENIED (resource_out_of_scope).
4. summarize    research-agent summarizes the documents → allowed
5. request_send research-agent emails the summary to alice → APPROVAL REQUIRED (policy)
6. human        LangGraph interrupt(): the run pauses until a human approves or rejects
7. send         approved → sent once; replay → DENIED; swapped body → DENIED
8. finish       task completed → the capability stops working → DENIED (task_inactive)

The agents are deterministic stand-ins for LLMs, so the demo is reproducible and needs no
API key. Every decision is made by AuthorityGuard, never by the agent.
"""

import operator
import uuid
from contextvars import ContextVar
from typing import Annotated, Any, TypedDict

import httpx
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from authorityguard.gateway.tools import INJECTION_PATTERN

# The HTTP client for the current run. Kept out of graph state (it is not serializable).
current_client: ContextVar[httpx.AsyncClient] = ContextVar("authorityguard_demo_client")

DOCUMENTS = ["/demo/projects/q3-plan.txt", "/demo/projects/customer-list.txt"]


class DemoState(TypedDict, total=False):
    run_id: str
    user_name: str
    user_id: str
    root_id: str
    child_id: str
    task_id: str
    root_token: str
    child_token: str
    documents: dict[str, str]
    summaries: list[str]
    approval_id: str | None
    approval_decision: str
    status: str
    steps: Annotated[list[dict[str, Any]], operator.add]


def _step(agent: str, title: str, **extra: Any) -> dict[str, Any]:
    return {"agent": agent, "title": title, **extra}


async def _post(path: str, json: dict[str, Any], **headers: str) -> httpx.Response:
    return await current_client.get().post(path, json=json, headers=headers)


async def _tool(
    tool: str,
    token: str,
    agent_id: str,
    resource: str,
    params: dict[str, Any] | None = None,
    approval_id: str | None = None,
) -> tuple[int, dict[str, Any]]:
    body: dict[str, Any] = {"resource": resource, "params": params or {}}
    if approval_id:
        body["approval_id"] = approval_id
    r = await _post(
        f"/v1/tools/{tool}/execute",
        body,
        Authorization=f"Bearer {token}",
        **{"X-Agent-Id": agent_id},
    )
    return r.status_code, r.json()


def _decision_step(agent: str, title: str, tool: str, resource: str, status: int, body: dict):
    detail = body.get("detail")
    if isinstance(detail, dict):  # tool error after an allow (e.g. missing document)
        return _step(
            agent,
            title,
            action=tool,
            resource=resource,
            http=status,
            decision="error",
            reason_code=detail.get("code"),
        )
    return _step(
        agent,
        title,
        action=tool,
        resource=resource,
        http=status,
        decision=body.get("decision"),
        reason_code=body.get("reason_code"),
        rule_id=body.get("rule_id"),
        approval_id=body.get("approval_id"),
    )


def _ok(r: httpx.Response) -> dict[str, Any]:
    if r.status_code >= 400:
        raise RuntimeError(f"{r.request.method} {r.request.url.path} → {r.status_code}: {r.text}")
    return r.json()


# --- nodes ------------------------------------------------------------------------


async def setup(state: DemoState) -> dict[str, Any]:
    name = f"alice-demo-{state['run_id'][:6]}"
    user = _ok(await _post("/v1/users", {"demo_name": name}))
    root = _ok(await _post("/v1/agents", {"owner_user_id": user["id"], "name": "research-agent"}))
    child = _ok(
        await _post(
            "/v1/agents",
            {"owner_user_id": user["id"], "name": "extract-agent", "parent_agent_id": root["id"]},
        )
    )
    task = _ok(
        await _post(
            "/v1/tasks",
            {
                "principal_user_id": user["id"],
                "root_agent_id": root["id"],
                "purpose": "Summarize the project documents and email me the summary",
            },
        )
    )
    scopes = [
        {"action": "file.read", "resource": "/demo/projects/*"},
        {"action": "doc.summarize", "resource": "*"},
        {"action": "email.send", "resource": f"mailto:{name}@example.test"},
    ]
    cap = _ok(await _post("/v1/capabilities", {"task_id": task["id"], "scopes": scopes}))
    return {
        "user_name": name,
        "user_id": user["id"],
        "root_id": root["id"],
        "child_id": child["id"],
        "task_id": task["id"],
        "root_token": cap["token"],
        "documents": {},
        "summaries": [],
        "steps": [
            _step(
                name,
                "Human starts a task for research-agent",
                decision="info",
                detail=task["purpose"],
            ),
            _step(
                "authorityguard",
                "Root capability issued to research-agent",
                decision="info",
                capability_id=cap["capability_id"],
                scopes=scopes,
                expires_at=cap["expires_at"],
            ),
        ],
    }


async def delegate(state: DemoState) -> dict[str, Any]:
    scopes = [{"action": "file.read", "resource": "/demo/projects/*"}]
    r = await _post(
        "/v1/capabilities/delegate",
        {
            "parent_token": state["root_token"],
            "delegator_agent_id": state["root_id"],
            "child_agent_id": state["child_id"],
            "scopes": scopes,
        },
    )
    cap = _ok(r)
    return {
        "child_token": cap["token"],
        "steps": [
            _step(
                "research-agent",
                "Delegates a narrower capability to extract-agent",
                decision="allow",
                reason_code="delegated",
                scopes=scopes,
                capability_id=cap["capability_id"],
                depth=cap["depth"],
            )
        ],
    }


async def extract(state: DemoState) -> dict[str, Any]:
    steps: list[dict[str, Any]] = []
    docs: dict[str, str] = {}
    child, token = state["child_id"], state["child_token"]

    for path in DOCUMENTS:
        status, body = await _tool("file.read", token, child, path)
        steps.append(
            _decision_step("extract-agent", f"Reads {path}", "file.read", path, status, body)
        )
        if status == 200:
            docs[path] = body["result"]["content"]

    for path, text in docs.items():
        match = INJECTION_PATTERN.search(text + " ")
        if not match:
            continue
        target = f"mailto:{match.group(1)}"
        steps.append(
            _step(
                "extract-agent",
                f"Prompt injection in {path}: agent obeys it",
                decision="info",
                detail=f"Tries to email the file to {match.group(1)}",
            )
        )
        status, body = await _tool(
            "email.send", token, child, target, {"subject": "customer list", "body": text}
        )
        steps.append(
            _decision_step(
                "extract-agent",
                "Emails the confidential file externally",
                "email.send",
                target,
                status,
                body,
            )
        )
        status, body = await _tool(
            "email.send",
            state["root_token"],
            child,
            target,
            {"subject": "customer list", "body": text},
        )
        steps.append(
            _decision_step(
                "extract-agent",
                "Retries with research-agent's stolen token",
                "email.send",
                target,
                status,
                body,
            )
        )

    status, body = await _tool("file.read", token, child, "/demo/hr/salaries.txt")
    steps.append(
        _decision_step(
            "extract-agent",
            "Wanders into HR records",
            "file.read",
            "/demo/hr/salaries.txt",
            status,
            body,
        )
    )
    return {"documents": docs, "steps": steps}


async def summarize(state: DemoState) -> dict[str, Any]:
    steps, summaries = [], []
    for path, text in state["documents"].items():
        status, body = await _tool(
            "doc.summarize", state["root_token"], state["root_id"], path, {"text": text}
        )
        steps.append(
            _decision_step(
                "research-agent", f"Summarizes {path}", "doc.summarize", path, status, body
            )
        )
        if status == 200:
            summaries.append(body["result"]["summary"])
    return {"summaries": summaries, "steps": steps}


def _email(state: DemoState) -> tuple[str, dict[str, Any]]:
    to = f"mailto:{state['user_name']}@example.test"
    return to, {"subject": "Project summary", "body": "\n".join(state["summaries"])}


async def request_send(state: DemoState) -> dict[str, Any]:
    to, params = _email(state)
    status, body = await _tool("email.send", state["root_token"], state["root_id"], to, params)
    return {
        "approval_id": body.get("approval_id"),
        "steps": [
            _decision_step(
                "research-agent", "Emails the summary to alice", "email.send", to, status, body
            )
        ],
    }


def human(state: DemoState) -> dict[str, Any]:
    if not state.get("approval_id"):
        return {"approval_decision": "none"}
    decision = interrupt({"approval_id": state["approval_id"], "question": "Send this email?"})
    return {"approval_decision": "approve" if decision == "approve" else "reject"}


async def send(state: DemoState) -> dict[str, Any]:
    approval_id = state.get("approval_id")
    if not approval_id:
        return {}
    approve = state["approval_decision"] == "approve"
    _ok(
        await _post(
            f"/v1/approvals/{approval_id}/decision",
            {"decision": "approve" if approve else "reject", "approver": state["user_name"]},
        )
    )
    steps = [
        _step(
            state["user_name"],
            "Human approves the email" if approve else "Human rejects the email",
            decision="info",
            approval_id=approval_id,
        )
    ]

    to, params = _email(state)
    root, token = state["root_id"], state["root_token"]
    status, body = await _tool("email.send", token, root, to, params, approval_id)
    title = "Sends the approved email" if approve else "Tries to send the rejected email anyway"
    steps.append(_decision_step("research-agent", title, "email.send", to, status, body))
    if approve:
        status, body = await _tool("email.send", token, root, to, params, approval_id)
        steps.append(
            _decision_step(
                "research-agent", "Replays the same approval", "email.send", to, status, body
            )
        )
        swapped = params | {"body": params["body"] + "\nP.S. attaching the full customer list"}
        status, body = await _tool("email.send", token, root, to, swapped, approval_id)
        steps.append(
            _decision_step(
                "research-agent",
                "Reuses the approval with a changed body",
                "email.send",
                to,
                status,
                body,
            )
        )
    return {"steps": steps}


async def finish(state: DemoState) -> dict[str, Any]:
    _ok(await _post(f"/v1/tasks/{state['task_id']}/status", {"status": "completed"}))
    status, body = await _tool("file.read", state["child_token"], state["child_id"], DOCUMENTS[0])
    return {
        "status": "completed",
        "steps": [
            _step(state["user_name"], "Task marked completed", decision="info"),
            _decision_step(
                "extract-agent",
                "Tries to keep working after the task ended",
                "file.read",
                DOCUMENTS[0],
                status,
                body,
            ),
        ],
    }


def build_graph():
    g = StateGraph(DemoState)
    for name, fn in [
        ("setup", setup),
        ("delegate", delegate),
        ("extract", extract),
        ("summarize", summarize),
        ("request_send", request_send),
        ("human", human),
        ("send", send),
        ("finish", finish),
    ]:
        g.add_node(name, fn)
    g.add_edge(START, "setup")
    for a, b in [
        ("setup", "delegate"),
        ("delegate", "extract"),
        ("extract", "summarize"),
        ("summarize", "request_send"),
        ("request_send", "human"),
        ("human", "send"),
        ("send", "finish"),
    ]:
        g.add_edge(a, b)
    g.add_edge("finish", END)
    return g.compile(checkpointer=InMemorySaver())


GRAPH = build_graph()


def _result(run_id: str, state: dict[str, Any], status: str) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "trace_id": run_id,
        "status": status,
        "task_id": state.get("task_id"),
        "approval_id": state.get("approval_id"),
        "steps": state.get("steps", []),
    }


async def start_run(client: httpx.AsyncClient, run_id: str, auto_approve: bool) -> dict[str, Any]:
    token = current_client.set(client)
    try:
        config = {"configurable": {"thread_id": run_id}}
        state = await GRAPH.ainvoke({"run_id": run_id, "steps": []}, config)
        if "__interrupt__" in state:
            if not auto_approve:
                return _result(run_id, state, "awaiting_approval")
            state = await GRAPH.ainvoke(Command(resume="approve"), config)
        return _result(run_id, state, state.get("status", "completed"))
    finally:
        current_client.reset(token)


async def resume_run(
    client: httpx.AsyncClient, run_id: str, approve: bool
) -> dict[str, Any] | None:
    config = {"configurable": {"thread_id": run_id}}
    snapshot = GRAPH.get_state(config)
    if not snapshot.next or "human" not in snapshot.next:
        return None
    token = current_client.set(client)
    try:
        state = await GRAPH.ainvoke(Command(resume="approve" if approve else "reject"), config)
        return _result(run_id, state, state.get("status", "completed"))
    finally:
        current_client.reset(token)


def new_run_id() -> str:
    return uuid.uuid4().hex
