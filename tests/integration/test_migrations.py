"""Alembic migrations must build exactly the schema the models describe, and be reversible."""

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import inspect
from sqlmodel import SQLModel

from authorityguard.storage.db import make_engine
from tests.conftest import PROJECT_ROOT, TEST_DATABASE_URL


@pytest.fixture
def db_url(tmp_path):
    if TEST_DATABASE_URL == "sqlite://":
        return f"sqlite:///{(tmp_path / 'migrations.db').as_posix()}"
    return TEST_DATABASE_URL


def _config(url: str) -> Config:
    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    cfg.attributes["configure_logger"] = False
    return cfg


def test_upgrade_matches_models_and_downgrade_is_clean(db_url):
    cfg = _config(db_url)
    engine = make_engine(db_url)
    SQLModel.metadata.drop_all(engine)  # start clean when sharing a CI database
    try:
        command.upgrade(cfg, "head")
        with engine.connect() as conn:
            diff = compare_metadata(MigrationContext.configure(conn), SQLModel.metadata)
        assert diff == [], f"Models changed without a migration: {diff}"

        command.downgrade(cfg, "base")
        assert set(inspect(engine).get_table_names()) <= {"alembic_version"}
    finally:
        command.downgrade(cfg, "base")
        engine.dispose()
