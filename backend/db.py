"""Database engine and session management (SQLAlchemy 2.0)."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


_engine: Engine | None = None
_session_factory: sessionmaker[Session] | None = None


def _ensure_sqlite_directory(url: str) -> None:
    parsed = make_url(url)
    if parsed.get_backend_name() != "sqlite":
        return
    database = parsed.database
    if not database or database == ":memory:":
        return
    Path(database).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def configure_database(url: str | None = None, *, echo: bool | None = None) -> Engine:
    """Create (or replace) the global engine/session factory."""
    global _engine, _session_factory

    settings = get_settings()
    target_url = url or settings.database_url
    _ensure_sqlite_directory(target_url)

    engine_kwargs: dict = {
        "pool_pre_ping": True,
        "echo": settings.database_echo if echo is None else echo,
    }
    if make_url(target_url).get_backend_name() == "sqlite":
        engine_kwargs["connect_args"] = {"check_same_thread": False}

    if _engine is not None:
        _engine.dispose()

    _engine = create_engine(target_url, **engine_kwargs)
    _session_factory = sessionmaker(
        bind=_engine,
        autoflush=False,
        expire_on_commit=False,
    )
    return _engine


def get_engine() -> Engine:
    if _engine is None:
        configure_database()
    assert _engine is not None
    return _engine


def get_session_factory() -> sessionmaker[Session]:
    if _session_factory is None:
        configure_database()
    assert _session_factory is not None
    return _session_factory


def get_db() -> Iterator[Session]:
    """FastAPI dependency that yields a scoped session."""
    db = get_session_factory()()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Session context manager for workers and startup tasks."""
    db = get_session_factory()()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def create_all() -> None:
    from . import models  # noqa: F401  (register metadata)

    Base.metadata.create_all(get_engine())


def drop_all() -> None:
    from . import models  # noqa: F401

    Base.metadata.drop_all(get_engine())


def reset_database(url: str | None = None) -> Engine:
    """Testing helper: dispose the current engine and reconfigure."""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None
    return configure_database(url)


def database_is_ready() -> bool:
    try:
        with get_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        return False
    else:
        return True
