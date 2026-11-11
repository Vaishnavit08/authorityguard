from collections.abc import Iterator

from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, create_engine

from authorityguard.config import get_settings


def make_engine(url: str, **kwargs) -> Engine:
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_engine(url, connect_args=connect_args, **kwargs)
    if url.startswith("sqlite"):
        # SQLite ignores foreign keys unless asked; PostgreSQL always enforces them.
        @event.listens_for(engine, "connect")
        def _enable_fk(dbapi_conn, _record):
            dbapi_conn.execute("PRAGMA foreign_keys=ON")

    return engine


engine = make_engine(get_settings().database_url)


def init_db(target: Engine | None = None) -> None:
    from authorityguard.storage import models  # noqa: F401  (registers tables)

    SQLModel.metadata.create_all(target or engine)


def get_session() -> Iterator[Session]:
    with Session(engine) as session:
        yield session
