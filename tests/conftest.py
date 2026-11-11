import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel

from apps.api.main import create_app
from authorityguard.storage.db import get_session, init_db, make_engine

FIXTURES = Path(__file__).parent / "fixtures"
PROJECT_ROOT = Path(__file__).parent.parent

# Default: fast in-memory SQLite. CI also runs the suite against PostgreSQL by setting this.
TEST_DATABASE_URL = os.environ.get("AG_TEST_DATABASE_URL", "sqlite://")


@pytest.fixture
def engine():
    if TEST_DATABASE_URL == "sqlite://":
        # StaticPool keeps one shared connection so the in-memory DB survives across sessions.
        eng = make_engine(TEST_DATABASE_URL, poolclass=StaticPool)
    else:
        eng = make_engine(TEST_DATABASE_URL)
        SQLModel.metadata.drop_all(eng)
    init_db(eng)
    yield eng
    SQLModel.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture
def client(engine):
    app = create_app()

    def _session():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_session] = _session
    return TestClient(app)


@pytest.fixture
def scenario():
    return json.loads((FIXTURES / "scenario_research_summary.json").read_text())


# --- small API helpers shared by integration tests -------------------------------


@pytest.fixture
def api(client):
    class Api:
        def user(self, name="alice-demo"):
            r = client.post("/v1/users", json={"demo_name": name})
            assert r.status_code == 201, r.text
            return r.json()

        def agent(self, owner_id, name="research-agent", parent_id=None, expect=201):
            r = client.post(
                "/v1/agents",
                json={"owner_user_id": owner_id, "name": name, "parent_agent_id": parent_id},
            )
            assert r.status_code == expect, r.text
            return r.json()

        def task(self, principal_id, agent_id, purpose="Summarize demo docs", expect=201):
            r = client.post(
                "/v1/tasks",
                json={
                    "principal_user_id": principal_id,
                    "root_agent_id": agent_id,
                    "purpose": purpose,
                },
            )
            assert r.status_code == expect, r.text
            return r.json()

        def status(self, kind, obj_id, status, expect=200):
            r = client.post(f"/v1/{kind}/{obj_id}/status", json={"status": status})
            assert r.status_code == expect, r.text
            return r.json()

    return Api()
