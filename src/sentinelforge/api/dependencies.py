"""FastAPI dependencies for database access."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy.orm import Session

from sentinelforge.storage.database import (
    create_database_engine,
    create_session_factory,
    initialise_database,
)

engine = create_database_engine()
initialise_database(engine)
SessionLocal = create_session_factory(engine)


def get_db() -> Generator[Session, None, None]:
    """Provide one database session per API request."""

    session = SessionLocal()

    try:
        yield session
    finally:
        session.close()
