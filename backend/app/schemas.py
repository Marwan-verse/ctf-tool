"""Public API schemas."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


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


class AnalysisOptions(BaseModel):
    """User-configurable analysis controls with hard safety bounds."""

    model_config = ConfigDict(extra="forbid", strict=True)

    structure_analysis: bool = True
    visual_analysis: bool = True
    lsb_analysis: bool = True
    ocr: bool = True
    barcodes: bool = True
    recursive_extraction: bool = True
    decoders: bool = True
    crypto_analysis: bool = True
    repairs: bool = True
    external_tools: bool = True
    external_extraction: bool = True
    evidence_type: Literal["auto", "image", "audio"] = "auto"
    audio_spectrogram: bool = True
    audio_signal_decoders: bool = True
    audio_sstv: bool = True
    audio_channel_exports: bool = True
    audio_audacity_bundle: bool = True
    audio_analysis_seconds: int = Field(default=180, ge=15, le=300)
    audio_spectrogram_fft: Literal[256, 512, 1024, 2048, 4096] = 2048
    audio_channel_mode: Literal["mix", "left", "right", "difference"] = "mix"
    audio_lsb_bits: int = Field(default=2, ge=1, le=4)
    max_recursion_depth: int = Field(default=3, ge=1, le=4)
    max_artifacts: int = Field(default=100, ge=25, le=500)
    tool_timeout_seconds: int = Field(default=60, ge=5, le=180)
    external_output_kib: int = Field(default=1024, ge=64, le=2048)
    max_external_files: int = Field(default=32, ge=1, le=64)
    foremost_depth: int = Field(default=2, ge=1, le=4)
    color_remap_variants: int = Field(default=8, ge=0, le=8)
    zsteg_mode: Literal["all", "lsb"] = "all"
    ocr_language: str = Field(default="eng", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_+\-]+$")
    selected_external_tools: list[str] | None = Field(default=None, max_length=64)

    @classmethod
    def for_profile(cls, profile: ScanProfile | str) -> "AnalysisOptions":
        profile_name = str(profile)
        budgets = {
            "quick": (2, 45, 20, 512, 16, 4),
            "balanced": (3, 100, 60, 1024, 32, 8),
            "deep": (4, 220, 180, 2048, 64, 8),
        }
        recursion, artifacts, timeout, output_kib, external_files, remaps = budgets.get(profile_name, budgets["balanced"])
        foremost_depth = {"quick": 1, "balanced": 2, "deep": 4}.get(profile_name, 2)
        return cls(
            max_recursion_depth=recursion,
            max_artifacts=artifacts,
            tool_timeout_seconds=timeout,
            external_output_kib=output_kib,
            max_external_files=external_files,
            foremost_depth=foremost_depth,
            color_remap_variants=remaps,
            audio_analysis_seconds={"quick": 60, "balanced": 180, "deep": 300}.get(profile_name, 180),
            audio_spectrogram_fft={"quick": 1024, "balanced": 2048, "deep": 4096}.get(profile_name, 2048),
            audio_lsb_bits={"quick": 1, "balanced": 2, "deep": 4}.get(profile_name, 2),
        )

    @field_validator("selected_external_tools")
    @classmethod
    def unique_tool_ids(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        normalized: list[str] = []
        seen: set[str] = set()
        for item in value:
            tool_id = item.strip().lower()
            if not tool_id or len(tool_id) > 64:
                raise ValueError("External tool identifiers must contain 1 to 64 characters.")
            if tool_id not in seen:
                seen.add(tool_id)
                normalized.append(tool_id)
        return normalized


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
    options: AnalysisOptions = Field(default_factory=AnalysisOptions)
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
    builtin_tools: list[dict[str, Any]]
    option_defaults: dict[str, dict[str, Any]]
    limits: dict[str, int | float]


class ToolInstallRequest(BaseModel):
    """Explicit request to install a fixed allowlist of forensic tools."""

    model_config = ConfigDict(extra="forbid", strict=True)

    tool_ids: list[str] = Field(min_length=1, max_length=64)
    confirmed: bool

    @field_validator("tool_ids")
    @classmethod
    def normalize_tool_ids(cls, value: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for item in value:
            tool_id = item.strip().lower()
            if not tool_id or len(tool_id) > 64:
                raise ValueError("Tool identifiers must contain 1 to 64 characters.")
            if tool_id not in seen:
                seen.add(tool_id)
                normalized.append(tool_id)
        if not normalized:
            raise ValueError("At least one tool identifier is required.")
        return normalized


class MessageResponse(BaseModel):
    message: str


TERMINAL_STATUSES = {
    JobStatus.COMPLETED.value,
    JobStatus.FAILED.value,
    JobStatus.CANCELLED.value,
}
