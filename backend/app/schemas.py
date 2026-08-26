"""Public API schemas."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ScanProfile(StrEnum):
    QUICK = "quick"
    BALANCED = "balanced"
    DEEP = "deep"


class JobStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    CANCELLING = "cancelling"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def terminal(self) -> bool:
        return self in {self.COMPLETED, self.FAILED, self.CANCELLED}


class ArtifactResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    job_id: str
    name: str
    kind: str = "artifact"
    media_type: str = "application/octet-stream"
    size_bytes: int = Field(ge=0)
    sha256: str
    parent_id: str | None = None
    created_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    artifact_url: str
    download_url: str
    preview_url: str | None = None


class JobResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str
    status: JobStatus
    profile: ScanProfile
    original_filename: str
    content_type: str
    size_bytes: int = Field(ge=0)
    sha256: str
    flag_prefix: str | None = None
    progress: float = Field(ge=0, le=1)
    current_stage: str | None = None
    cancel_requested: bool = False
    created_at: str
    updated_at: str
    started_at: str | None = None
    completed_at: str | None = None
    error: dict[str, str] | None = None
    result: dict[str, Any] | None = None
    artifacts: list[ArtifactResponse] = Field(default_factory=list)
    events_url: str
    report_urls: dict[str, str]


class JobListResponse(BaseModel):
    items: list[JobResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1)
    offset: int = Field(ge=0)


class HealthResponse(BaseModel):
    status: str
    version: str
    database: str
    uptime_seconds: float = Field(ge=0)
    jobs: dict[str, int]


class CapabilitiesResponse(BaseModel):
    name: str
    version: str
    max_upload_bytes: int
    profiles: list[str]
    formats: list[str]
    analysis_categories: list[str]
    exports: list[str]
    tools: list[dict[str, Any]]
    limits: dict[str, int | float]


class MessageResponse(BaseModel):
    message: str


TERMINAL_STATUSES = {
    JobStatus.COMPLETED.value,
    JobStatus.FAILED.value,
    JobStatus.CANCELLED.value,
}
