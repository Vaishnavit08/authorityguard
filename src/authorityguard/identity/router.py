from typing import Annotated

from fastapi import APIRouter, Depends
from sqlmodel import Session, select

from authorityguard.identity import service
from authorityguard.identity.schemas import (
    AgentCreate,
    AgentRead,
    IdentityStatusUpdate,
    UserCreate,
    UserRead,
)
from authorityguard.storage.db import get_session
from authorityguard.storage.models import Agent, User
from authorityguard.storage.pagination import PageDep

router = APIRouter(prefix="/v1", tags=["identity"])
SessionDep = Annotated[Session, Depends(get_session)]


@router.post("/users", response_model=UserRead, status_code=201)
def create_user(data: UserCreate, session: SessionDep) -> User:
    return service.create_user(session, data)


@router.get("/users", response_model=list[UserRead])
def list_users(session: SessionDep, page: PageDep) -> list[User]:
    query = select(User).order_by(User.created_at, User.id).offset(page.offset).limit(page.limit)
    return list(session.exec(query))


@router.get("/users/{user_id}", response_model=UserRead)
def get_user(user_id: str, session: SessionDep) -> User:
    return service.get_user(session, user_id)


@router.post("/users/{user_id}/status", response_model=UserRead)
def set_user_status(user_id: str, data: IdentityStatusUpdate, session: SessionDep) -> User:
    return service.set_user_status(session, user_id, data.status)


@router.post("/agents", response_model=AgentRead, status_code=201)
def create_agent(data: AgentCreate, session: SessionDep) -> Agent:
    return service.create_agent(session, data)


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


@router.post("/agents/{agent_id}/status", response_model=AgentRead)
def set_agent_status(agent_id: str, data: IdentityStatusUpdate, session: SessionDep) -> Agent:
    return service.set_agent_status(session, agent_id, data.status)
