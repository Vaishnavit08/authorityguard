"""Identity registry rules. These are enforced here in backend code, not by any agent."""

from sqlmodel import Session, select

from authorityguard.errors import DomainError, not_found
from authorityguard.identity.schemas import AgentCreate, UserCreate
from authorityguard.storage.models import Agent, IdentityStatus, User

# revoked is terminal: a revoked identity can never act again (threat T10).
_IDENTITY_TRANSITIONS: dict[IdentityStatus, set[IdentityStatus]] = {
    IdentityStatus.active: {IdentityStatus.suspended, IdentityStatus.revoked},
    IdentityStatus.suspended: {IdentityStatus.active, IdentityStatus.revoked},
    IdentityStatus.revoked: set(),
}


def check_transition(current: IdentityStatus, new: IdentityStatus) -> None:
    if new not in _IDENTITY_TRANSITIONS[IdentityStatus(current)]:
        raise DomainError(
            "invalid_transition", f"Cannot change status from {current} to {new}.", 409
        )


def create_user(session: Session, data: UserCreate) -> User:
    if session.exec(select(User).where(User.demo_name == data.demo_name)).first():
        raise DomainError("user_exists", "A user with this demo_name already exists.", 409)
    user = User(demo_name=data.demo_name)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def get_user(session: Session, user_id: str) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise not_found("user_not_found", "User")
    return user


def get_agent(session: Session, agent_id: str) -> Agent:
    agent = session.get(Agent, agent_id)
    if agent is None:
        raise not_found("agent_not_found", "Agent")
    return agent


def create_agent(session: Session, data: AgentCreate) -> Agent:
    owner = session.get(User, data.owner_user_id)
    if owner is None:
        raise not_found("owner_not_found", "Owner user")
    if owner.status != IdentityStatus.active:
        raise DomainError("owner_inactive", "Owner user is not active.", 409)

    if data.parent_agent_id is not None:
        parent = session.get(Agent, data.parent_agent_id)
        if parent is None:
            raise not_found("parent_not_found", "Parent agent")
        if parent.status != IdentityStatus.active:
            raise DomainError("parent_inactive", "Parent agent is not active.", 409)
        # A child agent acts for the same human as its parent; cross-owner chains
        # would let one user's agent borrow another user's authority.
        if parent.owner_user_id != data.owner_user_id:
            raise DomainError(
                "owner_mismatch", "Child agent must have the same owner as its parent.", 409
            )

    agent = Agent(
        owner_user_id=data.owner_user_id,
        parent_agent_id=data.parent_agent_id,
        name=data.name,
    )
    session.add(agent)
    session.commit()
    session.refresh(agent)
    return agent


def set_user_status(session: Session, user_id: str, status: IdentityStatus) -> User:
    user = get_user(session, user_id)
    check_transition(user.status, status)
    user.status = status
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def set_agent_status(session: Session, agent_id: str, status: IdentityStatus) -> Agent:
    # Only this agent's row changes. Descendants are not rewritten; from Week 2 every
    # protected action checks the whole chain (owner + all ancestors) at use time.
    agent = get_agent(session, agent_id)
    check_transition(agent.status, status)
    agent.status = status
    session.add(agent)
    session.commit()
    session.refresh(agent)
    return agent
