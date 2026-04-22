from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class IngestEvent(BaseModel):
    timestamp: datetime = Field(..., description="Event timestamp (ISO8601).")
    source: str = Field(..., description="Log source, e.g., siem|edr|iam|net")
    event_type: str = Field(..., description="Normalized event type, e.g., auth_failed|process_start")

    severity: int = Field(0, description="0-100 integer severity (optional).")

    host: str | None = None
    user: str | None = None
    ip: str | None = None
    process: str | None = None

    message: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict, description="Original payload (kept for audit).")


class IngestRaw(BaseModel):
    timestamp: datetime = Field(..., description="Log timestamp (ISO8601).")
    source: str = Field(..., description="Log source name.")
    message: str = Field(..., description="Raw log line / message.")
    severity: int = Field(0, description="0-100 integer severity (optional).")
    meta: dict[str, Any] = Field(default_factory=dict, description="Optional extra fields.")


class IngestResponse(BaseModel):
    event_id: int


class IngestBatchResponse(BaseModel):
    inserted: int
    event_ids: list[int]


class CorrelateRequest(BaseModel):
    lookback_minutes: int | None = Field(None, description="Override configured lookback window.")
    rebuild_all: bool = Field(True, description="If true, delete and rebuild incidents from scratch.")


class CorrelateResponse(BaseModel):
    incidents_created: int
    incidents_total: int


class EventOut(BaseModel):
    id: int
    timestamp: datetime
    source: str
    event_type: str
    severity: int
    host: str | None
    user: str | None
    ip: str | None
    process: str | None
    message: str | None
    raw: dict[str, Any]


class IncidentSummary(BaseModel):
    id: str
    title: str
    incident_type: str
    status: str

    start_ts: datetime
    end_ts: datetime

    fidelity_score: float
    confidence_score: float
    coverage_score: float

    event_count: int
    sources: list[str]
    entities: dict[str, list[str]]


class IncidentDetail(IncidentSummary):
    evidence: dict[str, Any]
    events: list[EventOut]


class PlaybookStep(BaseModel):
    step: int
    id: str | None = None
    title: str
    description: str
    objective: str | None = None
    procedure: str | None = None
    validation: str | None = None
    rollback: str | None = None
    evidence_event_ids: list[int] = Field(default_factory=list)


class PlaybookResponse(BaseModel):
    incident_id: str
    incident_type: str
    generated_by: str
    missing_sources: list[str]
    steps: list[PlaybookStep]
    runbook: dict[str, Any] | None = None
