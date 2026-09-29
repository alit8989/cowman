"""Pytest configuration and reusable fixtures."""

import os
from pathlib import Path
import tempfile
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cowman.core.config import CowmanConfig
import cowman.core.config as config_module
import cowman.storage.database as db_module
from cowman.storage.models import Base


@pytest.fixture(autouse=True)
def test_db(monkeypatch, tmp_path):
    """Provide an isolated, temporary SQLite database for every test."""
    db_file = tmp_path / "test_cowman.db"
    engine = create_engine(
        f"sqlite:///{db_file}",
        connect_args={"check_same_thread": False},
        echo=False,
    )
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    Base.metadata.create_all(bind=engine)

    # Patch global engine and session factory
    monkeypatch.setattr(db_module, "_ENGINE", engine)
    monkeypatch.setattr(db_module, "_SESSION_FACTORY", factory)
    monkeypatch.setattr(db_module, "get_engine", lambda db_path=None: engine)
    monkeypatch.setattr(db_module, "get_session_factory", lambda: factory)

    yield engine

    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture(autouse=True)
def reset_config(monkeypatch):
    """Ensure every test runs with an isolated, clean default configuration."""
    cfg = CowmanConfig()
    monkeypatch.setattr(config_module, "_GLOBAL_CONFIG", cfg)
    return cfg
