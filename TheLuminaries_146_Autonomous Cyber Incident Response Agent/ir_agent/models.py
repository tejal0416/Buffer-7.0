from __future__ import annotations

from sqlalchemy import ARRAY, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

try:
    from pgvector.sqlalchemy import Vector  # type: ignore

    _VECTOR_AVAILABLE = True
except Exception:  # pragma: no cover
    Vector = None  # type: ignore[assignment]
    _VECTOR_AVAILABLE = False


class Base(DeclarativeBase):
    pass


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    ingested_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    source: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)

    host: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    process: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Optional embedding for semantic retrieval. With pgvector available, this becomes a native
    # `vector(256)` column. Otherwise we store a float[] (still local, but similarity is done in Python).
    embedding: Mapped[list[float] | None] = mapped_column(
        Vector(256) if _VECTOR_AVAILABLE else ARRAY(Float), nullable=True
    )


class EventEntity(Base):
    __tablename__ = "event_entities"

    event_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("events.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    entity_type: Mapped[str] = mapped_column(String(32), primary_key=True)
    entity_value: Mapped[str] = mapped_column(String(256), primary_key=True)

    __table_args__ = (Index("idx_event_entities_lookup", "entity_type", "entity_value"),)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # uuid4 string
    created_at: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[object] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    start_ts: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    end_ts: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    title: Mapped[str] = mapped_column(String(256), nullable=False)
    incident_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open", index=True)

    fidelity_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, index=True)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, index=True)
    coverage_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0, index=True)

    entities: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    sources: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    playbook: Mapped[dict | None] = mapped_column(JSONB, nullable=True)


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    event_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("events.id", ondelete="CASCADE"), primary_key=True, index=True
    )


class TelemetryStatus(Base):
    __tablename__ = "telemetry_status"

    source: Mapped[str] = mapped_column(String(32), primary_key=True)
    host: Mapped[str] = mapped_column(String(128), primary_key=True, default="")
    last_seen_ts: Mapped[object] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    updated_at: Mapped[object] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[object] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
