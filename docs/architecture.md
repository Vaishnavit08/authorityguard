# AuthorityGuard — One-page Design (v0.1)

## Problem

In multi-agent workflows, a human authorizes one agent for a narrow task. That agent delegates to
sub-agents that call tools. If the human's authority is not carried, and narrowed, through every hop, a
sub-agent can act beyond what the human intended. This is the confused-deputy problem / excessive agency.

## Research question

Can delegated agent permissions be **constrained to the original human's authority** at runtime, with
low false-block rate and low latency overhead, compared with an unprotected baseline?

## Core flow

1. Human authenticates → `POST /v1/tasks` creates a task and a **signed, short-lived capability**
   (issuer, subject agent, audience, task, scopes, expiry, unique ID).
2. The root agent delegates → `POST /v1/capabilities/delegate` issues a **child capability that can only be narrower**.
3. Every tool call → `POST /v1/tools/{tool}/execute` → gateway verifies the capability → policy engine decides.
4. Decision: **allow** (execute), **deny** (reason code), or **approval required** (pause; human approves the exact parameters).
5. Every decision and delegation hop is written to the audit log → dashboard reconstructs the chain.

## Components and modules

| Module | Package | Milestone |
|--------|---------|-----------|
| Identity registry + lifecycle | `src/authorityguard/identity` | Weeks 0–1 ✅ |
| Tasks | `src/authorityguard/tasks` | Week 1 ✅ |
| Capability issuer + verification | `src/authorityguard/capabilities` | Week 2 ✅ |
| Delegation (attenuation) | `src/authorityguard/capabilities` | Week 3 ✅ |
| Policy decision point | `src/authorityguard/policy` + `policies/default.json` | Week 3 ✅ |
| Execution gateway + approvals | `src/authorityguard/gateway` | Week 4 ✅ |
| LangGraph demo agents | `src/authorityguard/agents` | Week 4 ✅ |
| Audit + delegation graph | `src/authorityguard/audit` | Week 5 ✅ |
| Storage | `src/authorityguard/storage` | ongoing |
| API app | `apps/api` | ongoing |
| Dashboard (single page served by the API) | `apps/api/static` | Week 5 ✅ |
| Benchmark | `src/authorityguard/benchmark.py` | Week 6 ✅ |

## Key design decisions

| Decision | Choice | Reason |
|----------|--------|--------|
| Who decides authorization | Backend code + policy engine only | LLM output is untrusted (threat model T3) |
| Token format | JWT signed with Ed25519 (`EdDSA`) via PyJWT | Standard claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `jti`); no custom crypto |
| Token storage | Only a SHA-256 hash is stored; raw token shown once | A DB leak doesn't hand out usable tokens |
| Verification | Signature **and** DB record **and** live state (task, agent chain) | A valid signature alone is never enough |
| Policy engine | Pure Python evaluator + JSON policy document (OPA/Rego is a drop-in future option) | Deterministic, unit-testable, no extra service to deploy |
| DB | SQLite for local dev, PostgreSQL in Docker / CI | Works without Docker on day 1; SQLModel abstracts both |
| Schema changes | Alembic migrations; a test fails on model/migration drift | Reproducible upgrades; the app never runs `create_all` |
| Status columns | Strings validated in code, not native DB enums | Add states without a PostgreSQL enum migration |
| Lifecycle | `revoked` and closed tasks are terminal | A revoked identity or closed task can never be reused |
| Default decision | **Deny** | Fail closed |
| Agent framework | LangGraph with `interrupt()` + `InMemorySaver` | The run genuinely pauses for a human and resumes |
| Dashboard | Static HTML/JS served by FastAPI (not Streamlit) | One container to deploy; no extra process |
| Demo agents | Deterministic stand-ins for LLMs | Reproducible benchmark, no API key; decisions are independent of the model |
| Deployment | Docker image on Render free tier via `render.yaml` | Free public link; same image smoke-tested in CI |

## Demo scenario (seed: `tests/fixtures/scenario_research_summary.json`)

The user "alice-demo" asks `research-agent` to summarize two documents from `/demo/projects`.
`research-agent` delegates extraction to `extract-agent` with `file.read` only.
A prompt-injected document makes `extract-agent` call `email.send_external` → **denied**.
`research-agent` asks to email the summary to the user's own demo inbox → **approval required** → approved → executed.

## Success metrics (Week 6 benchmark)

Attack success rate (protected vs baseline), false-block rate, task completion rate, p50/p95
authorization latency, failures broken down by attack category, over 100–200 scenarios.
