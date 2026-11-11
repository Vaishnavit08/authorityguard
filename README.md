# AuthorityGuard

**Delegated authorization and runtime policy enforcement for multi-agent AI systems.**

When a human asks an agent to do a narrow task and that agent delegates to sub-agents, AuthorityGuard
makes sure no agent in the chain can act beyond the human's original authority. Every sensitive tool
call is checked by deterministic backend code before it runs. The LLM never makes the authorization decision.

> Status: **Week 1 complete.** Identity registry (users, agents, parent/child, lifecycle) and tasks are
> implemented, migrated with Alembic and tested on SQLite and PostgreSQL (CI). Capabilities, delegation,
> policy, gateway and dashboard follow the roadmap below.

## Demo scenario

`alice-demo` asks `research-agent` to summarize project documents. It delegates file reading to
`extract-agent`. A prompt-injected document tells `extract-agent` to email a confidential file to an
attacker. AuthorityGuard **denies** it, because the delegated capability only allows `file.read`.
See [`tests/fixtures/scenario_research_summary.json`](tests/fixtures/scenario_research_summary.json).

## Quick start (no Docker needed)

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows  (macOS/Linux: source .venv/bin/activate)
pip install -e ".[dev]"
pytest
alembic upgrade head            # create / update the local SQLite schema
uvicorn apps.api.main:app --reload
```

Open http://127.0.0.1:8000/docs for the interactive API.

### With Docker Compose (PostgreSQL)

```bash
docker compose up --build       # the API container runs `alembic upgrade head` on start
```

### Changing the schema

Edit `src/authorityguard/storage/models.py`, then generate and review a migration:

```bash
alembic revision --autogenerate -m "describe the change"
```

`tests/integration/test_migrations.py` fails if models and migrations drift apart.

## API (current)

| Method | Route | Purpose |
|--------|-------|---------|
| GET | `/health` | Liveness |
| POST | `/v1/users` | Create a demo user |
| GET | `/v1/users`, `/v1/users/{id}` | List / get users |
| POST | `/v1/users/{id}/status` | `active` ⇄ `suspended`, or `revoked` (terminal) |
| POST | `/v1/agents` | Register an agent (optional parent; must share the parent's owner) |
| GET | `/v1/agents`, `/v1/agents/{id}` | List (filter by `owner_user_id`) / get agents |
| POST | `/v1/agents/{id}/status` | Same lifecycle as users |
| POST | `/v1/tasks` | Start a task: principal + *their own top-level* agent + purpose |
| GET | `/v1/tasks`, `/v1/tasks/{id}` | List (filter by `principal_user_id`, `status`) / get tasks |
| POST | `/v1/tasks/{id}/status` | `completed` or `cancelled` (both terminal) |

All lists accept `limit` (1–500, default 100) and `offset`. Errors return
`{"detail": {"code": "...", "message": "..."}}` with a stable machine-readable `code`.

> ⚠️ There is no caller authentication yet: any client can call any endpoint. Human authentication and
> signed capabilities arrive in Week 2. Run locally only.

## Roadmap

| Week | Milestone | Status |
|------|-----------|--------|
| 0 | Threat model, design, skeleton, seeded scenario | ✅ |
| 1 | Users / agents / tasks API, lifecycle, Alembic migrations, PostgreSQL CI | ✅ |
| 2 | Signed short-lived capability tokens (iss/aud/exp/jti checks) | ⬜ |
| 3 | Delegation attenuation + policy engine | ⬜ |
| 4 | LangGraph agents, mock tools, execution gateway, human approval | ⬜ |
| 5 | Audit log, delegation graph, Streamlit dashboard | ⬜ |
| 6 | Adversarial benchmark (100–200 scenarios), CI, demo video | ⬜ |

## Documentation

* [Threat model](docs/threat-model.md): assets, trust boundaries, 13 threats mapped to controls and tests
* [Architecture](docs/architecture.md): one-page design, decisions, success metrics

## Project layout

```
apps/api/            FastAPI app
apps/dashboard/      Streamlit dashboard (Week 5)
src/authorityguard/  identity, policy, gateway, agents, audit, storage
tests/               unit, integration, adversarial, fixtures
policies/            versioned policy documents
docs/                threat model, architecture, benchmark report
```

## Non-goals and limitations

Synthetic data and mock tools only. No real Microsoft 365 / Google Workspace integration, enterprise SSO,
multi-tenancy or custom cryptography. This is a research prototype, **not** a production security product,
and it does not claim to prevent all prompt injection.
