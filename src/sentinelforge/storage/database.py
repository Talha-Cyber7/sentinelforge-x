"""Database engine and session configuration."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_DATABASE_PATH = PROJECT_ROOT / "data" / "local" / "sentinelforge.db"


class Base(DeclarativeBase):
    """Base class for all SentinelForge X database models."""


def create_database_engine(
    database_url: str | None = None,
) -> Engine:
    """Create a SQLAlchemy engine.

    If no URL is provided, use a local SQLite database inside the ignored
    data/local directory.
    """

    if database_url is None:
        DEFAULT_DATABASE_PATH.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        database_url = f"sqlite:///{DEFAULT_DATABASE_PATH.as_posix()}"

    connect_args: dict[str, object] = {}

    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    return create_engine(
        database_url,
        connect_args=connect_args,
    )


def create_session_factory(
    engine: Engine,
) -> sessionmaker[Session]:
    """Create sessions bound to a database engine."""

    return sessionmaker(
        bind=engine,
        class_=Session,
        expire_on_commit=False,
    )


def initialise_database(engine: Engine) -> None:
    """Create all registered tables."""

    Base.metadata.create_all(engine)
