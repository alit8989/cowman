"""Database initialization and session management using SQLAlchemy and SQLite."""

from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from cowman.core.config import get_config
from cowman.storage.models import Base

_ENGINE = None
_SESSION_FACTORY = None


def get_engine(db_path: Optional[Path] = None):
    global _ENGINE, _SESSION_FACTORY
    if _ENGINE is None or db_path is not None:
        target_path = db_path or get_config().resolved_database_path()
        target_path.parent.mkdir(parents=True, exist_ok=True)
        db_url = f"sqlite:///{target_path}"
        engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False},
            echo=False,
        )
        if db_path is None:
            _ENGINE = engine
            _SESSION_FACTORY = sessionmaker(bind=engine, autoflush=False, autocommit=False)
        return engine
    return _ENGINE


def get_session_factory():
    global _SESSION_FACTORY
    if _SESSION_FACTORY is None:
        get_engine()
    return _SESSION_FACTORY


def init_db(db_path: Optional[Path] = None) -> None:
    """Initialize SQLite database tables."""
    engine = get_engine(db_path)
    Base.metadata.create_all(bind=engine)


@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """Provide a transactional database session."""
    factory = get_session_factory()
    session: Session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
