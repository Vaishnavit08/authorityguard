from fastapi import APIRouter
from sqlmodel import select

from authorityguard.audit.service import record_event
from authorityguard.deps import AdminOnly, SessionDep, TraceDep
from authorityguard.identity import service
from authorityguard.identity.schemas import (
    AgentCreate,
    AgentRead,
    IdentityStatusUpdate,
    UserCreate,
    UserRead,
)
from authorityguard.storage.models import Agent, User
from authorityguard.storage.pagination import PageDep

router = APIRouter(prefix="/v1", tags=["identity"])


@router.post("/users", response_model=UserRead, status_code=201, dependencies=AdminOnly)
def create_user(data: UserCreate, session: SessionDep, trace_id: TraceDep) -> User:
    user = service.create_user(session, data)
    record_event(session, "user.created", trace_id, subject_id=user.id)
    return user


@router.get("/users", response_model=list[UserRead])
def list_users(session: SessionDep, page: PageDep) -> list[User]:
    query = select(User).order_by(User.created_at, User.id).offset(page.offset).limit(page.limit)
    return list(session.exec(query))


@router.get("/users/{user_id}", response_model=UserRead)
def get_user(user_id: str, session: SessionDep) -> User:
    return service.get_user(session, user_id)


@router.post("/users/{user_id}/status", response_model=UserRead, dependencies=AdminOnly)
def set_user_status(
    user_id: str, data: IdentityStatusUpdate, session: SessionDep, trace_id: TraceDep
) -> User:
    user = service.set_user_status(session, user_id, data.status)
    record_event(
        session,
        "user.status_changed",
        trace_id,
        subject_id=user.id,
        details={"status": user.status},
    )
    return user


@router.post("/agents", response_model=AgentRead, status_code=201, dependencies=AdminOnly)
def create_agent(data: AgentCreate, session: SessionDep, trace_id: TraceDep) -> Agent:
    agent = service.create_agent(session, data)
    record_event(
        session,
        "agent.registered",
        trace_id,
        actor_id=agent.owner_user_id,
        subject_id=agent.id,
        details={"name": agent.name, "parent_agent_id": agent.parent_agent_id},
    )
    return agent


@router.get("/agents", response_model=list[AgentRead])
def list_agents(
    session: SessionDep, page: PageDep, owner_user_id: str | None = None
) -> list[Agent]:
    query = select(Agent).order_by(Agent.created_at, Agent.id)
    if owner_user_id:
        query = query.where(Agent.owner_user_id == owner_user_id)
    return list(session.exec(query.offset(page.offset).limit(page.limit)))


@router.get("/agents/{agent_id}", response_model=AgentRead)
def get_agent(agent_id: str, session: SessionDep) -> Agent:
    return service.get_agent(session, agent_id)


@router.post("/agents/{agent_id}/status", response_model=AgentRead, dependencies=AdminOnly)
def set_agent_status(
    agent_id: str, data: IdentityStatusUpdate, session: SessionDep, trace_id: TraceDep
) -> Agent:
    agent = service.set_agent_status(session, agent_id, data.status)
    record_event(
        session,
        "agent.status_changed",
        trace_id,
        subject_id=agent.id,
        details={"status": agent.status},
    )
    return agent
