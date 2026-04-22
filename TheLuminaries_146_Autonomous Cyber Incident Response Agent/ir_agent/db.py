from __future__ import annotations

import os
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from ir_agent.models import Base


def _database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    # Fallback for local dev (non-docker)
    return "postgresql+psycopg://ir:ir@localhost:5432/ir"


ENGINE = create_engine(_database_url(), pool_pre_ping=True)
SessionLocal = sessionmaker(bind=ENGINE, autoflush=False, autocommit=False, expire_on_commit=False)


def init_db() -> None:
    # Ensure pgvector exists before creating tables with vector columns.
    # In non-pgvector Postgres, this will fail; in that case, models fall back to float[].
    try:
        with ENGINE.connect() as conn:
            conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector;"))
            conn.commit()
    except Exception:
        pass

    Base.metadata.create_all(bind=ENGINE)


@contextmanager
def session_scope() -> Session:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
