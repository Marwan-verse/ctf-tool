"""FastAPI control plane for the local Forenscope GUI."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
import threading
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path
from typing import Any, Literal
from uuid import UUID, uuid4

import anyio
from fastapi import FastAPI, File, Form, HTTPException, Query, Request, Response, UploadFile, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from pydantic import ValidationError
from starlette.background import BackgroundTask
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .analyzers.external import TOOL_SPECS, discover_wsl_tools, resolve_tool
from .config import MEBIBYTE, Settings, settings as default_settings
from .hexedit import (
    HexEditError,
    LiveEditTooLargeError,
    PreviewUnavailableError,
    analyze_edited_file,
    normalize_edits,
    patch_digest,
    read_repair_candidate,
    render_edited_preview,
    write_edited_copy,
    write_repair_copy,
)
from .hexview import inspect_file
from .jobs import JobManager
from .reporting import (
    artifact_download_details,
    artifact_public_record,
    build_export_payload,
    input_artifact_record,
    job_public_record,
    report_csp,
    report_json_bytes,
    render_html_report,
    sniff_media_type,
    write_report_zip,
)
from .schemas import (
    AnalysisOptions,
    CapabilitiesResponse,
    HealthResponse,
    HexEditRequest,
    HexRepairRequest,
    HexSaveRequest,
    JobListResponse,
    JobResponse,
    JobStatus,
    ScanProfile,
    TERMINAL_STATUSES,
    ToolInstallRequest,
)
from .security import (
    OriginValidationMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    UnsafePathError,
    normalize_display_filename,
    require_regular_file,
    resolve_under,
    safe_content_disposition,
    validate_short_text,
)
from .storage import Storage
from .tool_installation import INSTALLABLE_TOOL_IDS, install_strategy, install_tools


logger = logging.getLogger(__name__)
_SSE_EVENT_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,47}$")
_TOOL_CAPABILITY_CACHE_SECONDS = 300.0
_tool_capability_cache_lock = threading.Lock()
_tool_capability_cache: tuple[float, list[dict[str, Any]]] | None = None


def _detail(code: str, message: str) -> dict[str, dict[str, str]]:
    return {"detail": {"code": code, "message": message}}


def _not_found(kind: str = "Job") -> HTTPException:
    return HTTPException(status_code=404, detail={"code": "not_found", "message": f"{kind} was not found."})


def _storage(request: Request) -> Storage:
    return request.app.state.storage


def _jobs(request: Request) -> JobManager:
    return request.app.state.jobs


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def _present_job(storage: Storage, job: dict[str, Any]) -> dict[str, Any]:
    return job_public_record(job, storage.list_artifacts(str(job["id"])))


def _get_job_or_404(storage: Storage, job_id: str) -> dict[str, Any]:
    job = storage.get_job(job_id)
    if job is None:
        raise _not_found()
    return job


def _get_artifact_or_404(storage: Storage, job_id: str, artifact_id: str) -> dict[str, Any]:
    artifact = storage.get_artifact(job_id, artifact_id)
    if artifact is None:
        raise _not_found("Artifact")
    return artifact


def _artifact_path(settings: Settings, job_id: str, artifact: dict[str, Any]) -> Path:
    try:
        job_dir = resolve_under(settings.jobs_dir, job_id, must_exist=True)
        return require_regular_file(job_dir, str(artifact["relative_path"]))
    except (OSError, UnsafePathError, ValueError) as exc:
        raise HTTPException(
            status_code=410,
            detail={"code": "artifact_unavailable", "message": "This artifact is no longer available on disk."},
        ) from exc


def _tool_capability(spec: Any, wsl_tools: dict[str, str]) -> dict[str, Any]:
    resolved = resolve_tool(spec.executable, wsl_tools=wsl_tools)
    return {
        "id": spec.tool_id,
        "name": spec.name,
        "executable": spec.executable,
        "category": spec.category,
        "available": resolved is not None,
        "resolved": resolved.display if resolved else None,
        "source": resolved.source if resolved else None,
        "profiles": sorted(spec.profiles),
        "formats": sorted(spec.kinds) if spec.kinds is not None else ["all"],
        "installable": spec.tool_id in INSTALLABLE_TOOL_IDS,
        "install_strategy": install_strategy(spec.tool_id),
        "install_hint": (
            f"Detected through {resolved.source}: {resolved.display}."
            if resolved
            else "Install automatically from Scan settings, then refresh availability."
        ),
        "source_url": spec.source_url,
    }


def _tool_capabilities() -> list[dict[str, Any]]:
    global _tool_capability_cache
    now = time.monotonic()
    with _tool_capability_cache_lock:
        if _tool_capability_cache and now - _tool_capability_cache[0] < _TOOL_CAPABILITY_CACHE_SECONDS:
            return [dict(item) for item in _tool_capability_cache[1]]
    wsl_tools = discover_wsl_tools(tuple(spec.executable for spec in TOOL_SPECS))
    capabilities = [_tool_capability(spec, wsl_tools) for spec in TOOL_SPECS]
    with _tool_capability_cache_lock:
        _tool_capability_cache = (time.monotonic(), capabilities)
    return [dict(item) for item in capabilities]


def _invalidate_tool_capabilities() -> None:
    global _tool_capability_cache
    with _tool_capability_cache_lock:
        _tool_capability_cache = None


def _parse_analysis_options(raw: str | None, profile: ScanProfile, *, max_artifacts: int) -> AnalysisOptions:
    defaults = AnalysisOptions.for_profile(profile)
    if raw is None or not raw.strip():
        parsed = defaults
    else:
        if len(raw.encode("utf-8")) > 16 * 1024:
            raise HTTPException(
                status_code=422,
                detail={"code": "options_too_large", "message": "Analysis settings are limited to 16 KiB."},
            )
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=422,
                detail={"code": "invalid_options", "message": "Analysis settings must be a valid JSON object."},
            ) from exc
        if not isinstance(payload, dict):
            raise HTTPException(
                status_code=422,
                detail={"code": "invalid_options", "message": "Analysis settings must be a JSON object."},
            )
        try:
            parsed = AnalysisOptions.model_validate(defaults.model_dump() | payload)
        except ValidationError as exc:
            first = exc.errors()[0] if exc.errors() else {}
            message = str(first.get("msg") or "Analysis settings are invalid.")
            raise HTTPException(
                status_code=422,
                detail={"code": "invalid_options", "message": message},
            ) from exc

    declared_tools = {spec.tool_id for spec in TOOL_SPECS}
    unknown = sorted(set(parsed.selected_external_tools or ()) - declared_tools)
    if unknown:
        raise HTTPException(
            status_code=422,
            detail={"code": "unknown_tool", "message": f"Unknown external tool setting: {unknown[0]}"},
        )
    if parsed.max_artifacts > max_artifacts:
        raise HTTPException(
            status_code=422,
            detail={"code": "artifact_limit", "message": f"This installation allows at most {max_artifacts} artifacts per job."},
        )
    return parsed


def create_app(settings: Settings | None = None) -> FastAPI:
    configured = settings or default_settings

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        configured.ensure_directories()
        storage = Storage(configured.database_path)
        storage.initialize()
        manager = JobManager(storage=storage, settings=configured)
        recovered = manager.start()
        if recovered:
            logger.warning("Marked %d interrupted analysis job(s) as failed", len(recovered))
        application.state.settings = configured
        application.state.storage = storage
        application.state.jobs = manager
        application.state.started_at = time.monotonic()
        application.state.tool_install_lock = asyncio.Lock()
        application.state.hex_edit_locks = {}
        try:
            yield
        finally:
            manager.shutdown()

    application = FastAPI(
        title="Forenscope API",
        summary="Local-first image, audio, and corrupted-file forensics control plane",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=list(configured.allowed_origins),
        allow_origin_regex=r"^https?://(?:localhost|127\.0\.0\.1|\[::1\])(?::\d{1,5})?$",
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Accept", "Content-Type", "Last-Event-ID"],
        expose_headers=["Content-Disposition", "X-Artifact-SHA256"],
        max_age=600,
    )
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=list(configured.allowed_hosts))
    application.add_middleware(OriginValidationMiddleware, allowed_origins=configured.allowed_origins)
    application.add_middleware(
        RateLimitMiddleware,
        default_limit=configured.rate_limit_per_minute,
        upload_limit=configured.upload_limit_per_minute,
    )
    application.add_middleware(SecurityHeadersMiddleware)

    @application.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        errors = [
            {
                "field": ".".join(str(part) for part in error.get("loc", ())[1:]),
                "message": str(error.get("msg", "Invalid value")),
                "type": str(error.get("type", "validation_error")),
            }
            for error in exc.errors()
        ]
        return JSONResponse(
            _detail("validation_error", "One or more request fields are invalid.") | {"errors": errors},
            status_code=422,
        )

    @application.exception_handler(Exception)
    async def unhandled_error_handler(_request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled API error", exc_info=exc)
        return JSONResponse(
            _detail("internal_error", "The local API encountered an unexpected error."),
            status_code=500,
        )

    @application.get("/", include_in_schema=False)
    async def root() -> dict[str, str]:
        return {"name": "Forenscope API", "version": __version__, "health": "/api/health"}

    @application.get("/api/health", response_model=HealthResponse)
    async def health(request: Request) -> dict[str, Any]:
        storage = _storage(request)
        database_ok = await anyio.to_thread.run_sync(storage.ping)
        counts = await anyio.to_thread.run_sync(storage.job_counts)
        counts["active_workers"] = _jobs(request).active_count()
        return {
            "status": "ok" if database_ok else "degraded",
            "version": __version__,
            "database": "ok" if database_ok else "unavailable",
            "uptime_seconds": max(0.0, time.monotonic() - float(request.app.state.started_at)),
            "jobs": counts,
        }

    @application.get("/api/capabilities", response_model=CapabilitiesResponse)
    async def capabilities(request: Request, refresh: bool = Query(default=False)) -> dict[str, Any]:
        configured_settings = _settings(request)
        if refresh:
            _invalidate_tool_capabilities()
        tools = await anyio.to_thread.run_sync(_tool_capabilities)
        return {
            "name": "Forenscope Forensics Analyzer",
            "version": __version__,
            "max_upload_bytes": configured_settings.max_upload_bytes,
            "profiles": [profile.value for profile in ScanProfile],
            "formats": [
                "PNG", "APNG", "JPEG", "MPO", "BMP", "GIF", "WebP", "SVG", "TIFF", "BigTIFF", "ICO", "CUR",
                "WAV", "AIFF", "FLAC", "Ogg", "Opus", "MP3", "AAC", "M4A", "AU", "WMA", "AMR", "CAF", "MIDI",
                "PDF", "ZIP", "Gzip", "Bzip2", "XZ", "Text", "Unknown binary",
            ],
            "analysis_categories": [
                "identity",
                "metadata",
                "structure",
                "strings",
                "embedded-files",
                "visual-lab",
                "steganography",
                "ocr",
                "barcodes",
                "decoding",
                "crypto",
                "repair",
                "audio-waveform",
                "audio-spectrum",
                "audio-signal",
                "audio-decoding",
                "audio-sstv",
                "file-recovery",
            ],
            "exports": ["json", "html", "zip"],
            "tools": tools,
            "builtin_tools": [
                {"id": "decomposer", "name": "Bit-layer decomposer", "category": "visual", "available": True, "formats": ["all images"]},
                {"id": "color_remapping", "name": "Color remapping", "category": "visual", "available": True, "formats": ["all images"]},
                {"id": "pcrt", "name": "PCRT-compatible PNG repair", "category": "repair", "available": True, "formats": ["png"]},
                {"id": "header-recovery", "name": "Signature, header, and PNG boundary recovery", "category": "repair", "available": True, "formats": ["png", "jpeg", "unknown binary"]},
                {"id": "bmp-word-lanes", "name": "BMP bitfield word-lane payload recovery", "category": "steganography", "available": True, "formats": ["bmp"]},
                {"id": "svg-text", "name": "Static SVG text and tspan recovery", "category": "steganography", "available": True, "formats": ["svg"]},
                {"id": "crypto-analysis", "name": "Encrypted payload detection and recovery", "category": "crypto", "available": True, "formats": ["extracted payloads"]},
                {"id": "audio-waveform", "name": "PCM waveform and statistics", "category": "audio", "available": True, "formats": ["wav"]},
                {"id": "audio-spectrogram", "name": "Built-in STFT spectrogram", "category": "audio-spectrum", "available": True, "formats": ["wav"]},
                {"id": "audio-pcm-lsb", "name": "PCM byte/channel bit-plane extraction", "category": "steganography", "available": True, "formats": ["wav"]},
                {"id": "audio-signal-decoders", "name": "DTMF and Morse decoders", "category": "audio-decoding", "available": True, "formats": ["wav"]},
                {"id": "audio-sstv", "name": "RX-SSTV-compatible VIS image decoder", "category": "audio-sstv", "available": True, "formats": ["wav"]},
                {"id": "audio-audacity", "name": "Audacity review bundle", "category": "audio", "available": True, "formats": ["wav"]},
            ],
            "option_defaults": {
                profile.value: AnalysisOptions.for_profile(profile).model_dump()
                for profile in ScanProfile
            },
            "limits": {
                "max_upload_bytes": configured_settings.max_upload_bytes,
                "max_artifacts": configured_settings.max_artifacts,
                "max_report_bytes": configured_settings.max_report_bytes,
                "max_workers": configured_settings.max_workers,
            },
        }

    @application.post("/api/tools/install")
    async def install_missing_tools(request: Request, payload: ToolInstallRequest) -> dict[str, Any]:
        if not payload.confirmed:
            raise HTTPException(
                status_code=400,
                detail={"code": "confirmation_required", "message": "Confirm the automatic installation request before continuing."},
            )
        declared_tools = {spec.tool_id for spec in TOOL_SPECS}
        unknown = sorted(set(payload.tool_ids) - declared_tools)
        if unknown:
            raise HTTPException(
                status_code=422,
                detail={"code": "unknown_tool", "message": f"Unknown tool installation request: {unknown[0]}"},
            )
        lock: asyncio.Lock = request.app.state.tool_install_lock
        if lock.locked():
            raise HTTPException(
                status_code=409,
                detail={"code": "installation_in_progress", "message": "Another tool installation is already running."},
            )
        async with lock:
            report = await anyio.to_thread.run_sync(partial(install_tools, payload.tool_ids))
            _invalidate_tool_capabilities()
            return report

    @application.post("/api/jobs", response_model=JobResponse, status_code=status.HTTP_202_ACCEPTED)
    async def create_job(
        request: Request,
        file: UploadFile = File(..., description="Image, audio, or corrupted media evidence"),
        profile: ScanProfile = Form(ScanProfile.BALANCED),
        flag_prefix: str | None = Form(None, max_length=160),
        password: str | None = Form(None, max_length=4096),
        options: str | None = Form(None, max_length=16 * 1024),
    ) -> dict[str, Any]:
        configured_settings = _settings(request)
        parsed_options = _parse_analysis_options(
            options,
            profile,
            max_artifacts=configured_settings.max_artifacts,
        )
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                announced_size = int(content_length)
            except ValueError as exc:
                raise HTTPException(
                    status_code=400,
                    detail={"code": "invalid_content_length", "message": "Content-Length must be a valid integer."},
                ) from exc
            if announced_size < 0 or announced_size > configured_settings.max_upload_bytes + 2 * MEBIBYTE:
                raise HTTPException(
                    status_code=413,
                    detail={
                        "code": "upload_too_large",
                        "message": f"Uploads are limited to {configured_settings.max_upload_bytes} bytes.",
                    },
                )

        try:
            normalized_prefix = validate_short_text(flag_prefix, field="flag_prefix", maximum=160)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail={"code": "invalid_flag_prefix", "message": str(exc)}) from exc
        if password is not None and len(password.encode("utf-8")) > 16 * 1024:
            raise HTTPException(
                status_code=422,
                detail={"code": "password_too_long", "message": "The password is too long."},
            )

        job_id = str(uuid4())
        display_filename = normalize_display_filename(file.filename, fallback="upload.bin")
        content_type = (file.content_type or "application/octet-stream")[:127]
        if any(ord(character) < 32 or ord(character) == 127 for character in content_type):
            content_type = "application/octet-stream"
        job_dir = resolve_under(configured_settings.jobs_dir, job_id, must_exist=False)
        input_dir = resolve_under(job_dir, "input", must_exist=False)
        output_dir = resolve_under(job_dir, "output", must_exist=False)
        input_dir.mkdir(parents=True, exist_ok=False)
        output_dir.mkdir(parents=True, exist_ok=False)
        input_path = resolve_under(input_dir, "source.upload", must_exist=False)
        digest = hashlib.sha256()
        size_bytes = 0
        persisted = False
        try:
            async with await anyio.open_file(input_path, "xb") as destination:
                while chunk := await file.read(MEBIBYTE):
                    size_bytes += len(chunk)
                    if size_bytes > configured_settings.max_upload_bytes:
                        raise HTTPException(
                            status_code=413,
                            detail={
                                "code": "upload_too_large",
                                "message": f"Uploads are limited to {configured_settings.max_upload_bytes} bytes.",
                            },
                        )
                    digest.update(chunk)
                    await destination.write(chunk)
            if size_bytes == 0:
                raise HTTPException(
                    status_code=400,
                    detail={"code": "empty_upload", "message": "The uploaded file is empty."},
                )

            verified_media_type, verified_previewable = await anyio.to_thread.run_sync(sniff_media_type, input_path)
            storage = _storage(request)
            job = await anyio.to_thread.run_sync(
                partial(
                    storage.create_job,
                    {
                        "id": job_id,
                        "profile": profile.value,
                        "original_filename": display_filename,
                        "content_type": content_type,
                        "size_bytes": size_bytes,
                        "sha256": digest.hexdigest(),
                        "flag_prefix": normalized_prefix,
                        "options": parsed_options.model_dump(),
                        "input_relative_path": "input/source.upload",
                        "output_relative_path": "output",
                    },
                )
            )
            persisted = True
            await anyio.to_thread.run_sync(
                partial(
                    storage.upsert_artifact,
                    input_artifact_record(
                        job_id=job_id,
                        original_filename=display_filename,
                        relative_path="input/source.upload",
                        content_type=verified_media_type if verified_previewable else content_type,
                        size_bytes=size_bytes,
                        sha256=digest.hexdigest(),
                        previewable=verified_previewable,
                    ),
                )
            )
            initial_response = _present_job(storage, job)
            try:
                _jobs(request).submit(job_id, password=password)
            except Exception:
                logger.exception("Unable to schedule job %s", job_id)
                failure = {
                    "partial": True,
                    "summary": "The analysis could not be scheduled.",
                    "errors": [{"code": "scheduler_unavailable", "message": "The analysis could not be scheduled."}],
                }
                storage.finish_job(
                    job_id,
                    status="failed",
                    result=failure,
                    error_code="scheduler_unavailable",
                    error_message="The analysis could not be scheduled.",
                )
                return _present_job(storage, _get_job_or_404(storage, job_id))
            return initial_response
        finally:
            await file.close()
            password = None
            if not persisted and job_dir.exists():
                try:
                    await anyio.to_thread.run_sync(shutil.rmtree, job_dir)
                except OSError:
                    logger.warning("Unable to remove rejected upload directory %s", job_id)

    @application.get("/api/jobs", response_model=JobListResponse)
    async def list_jobs(
        request: Request,
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        status_filter: JobStatus | None = Query(None, alias="status"),
    ) -> dict[str, Any]:
        storage = _storage(request)
        items, total = await anyio.to_thread.run_sync(
            partial(
                storage.list_jobs,
                limit=limit,
                offset=offset,
                status=status_filter.value if status_filter else None,
            )
        )
        return {
            "items": [_present_job(storage, item) for item in items],
            "total": total,
            "limit": limit,
            "offset": offset,
        }

    @application.get("/api/jobs/{job_id}", response_model=JobResponse)
    async def get_job(request: Request, job_id: UUID) -> dict[str, Any]:
        storage = _storage(request)
        job = await anyio.to_thread.run_sync(storage.get_job, str(job_id))
        if job is None:
            raise _not_found()
        return _present_job(storage, job)

    @application.post("/api/jobs/{job_id}/cancel", response_model=JobResponse, status_code=202)
    async def cancel_job(request: Request, job_id: UUID) -> dict[str, Any]:
        storage = _storage(request)
        job = await anyio.to_thread.run_sync(_jobs(request).request_cancel, str(job_id))
        if job is None:
            raise _not_found()
        return _present_job(storage, job)

    @application.delete("/api/jobs/{job_id}", status_code=204)
    async def delete_job(request: Request, job_id: UUID) -> Response:
        identifier = str(job_id)
        storage = _storage(request)
        if await anyio.to_thread.run_sync(storage.get_job, identifier) is None:
            raise _not_found()
        try:
            deleted = await anyio.to_thread.run_sync(_jobs(request).delete_job, identifier)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "job_active",
                    "message": "Cancel this job and wait for it to finish before deleting it.",
                },
            ) from exc
        if not deleted:
            raise _not_found()
        return Response(status_code=204)

    @application.get("/api/jobs/{job_id}/events")
    async def job_events(
        request: Request,
        job_id: UUID,
        after: int = Query(0, ge=0),
    ) -> StreamingResponse:
        identifier = str(job_id)
        storage = _storage(request)
        if await anyio.to_thread.run_sync(storage.get_job, identifier) is None:
            raise _not_found()
        header_cursor = request.headers.get("last-event-id")
        if header_cursor:
            try:
                after = max(after, int(header_cursor))
            except ValueError as exc:
                raise HTTPException(
                    status_code=400,
                    detail={"code": "invalid_event_cursor", "message": "Last-Event-ID must be an integer."},
                ) from exc

        async def stream() -> AsyncIterator[str]:
            cursor = after
            last_heartbeat = time.monotonic()
            while True:
                if await request.is_disconnected():
                    return
                events = await anyio.to_thread.run_sync(
                    partial(storage.list_events, identifier, after_id=cursor, limit=250)
                )
                if events:
                    for event in events:
                        cursor = int(event["id"])
                        event_name = str(event["type"])
                        if not _SSE_EVENT_NAME.fullmatch(event_name):
                            event_name = "message"
                        data = json.dumps(event, ensure_ascii=False, separators=(",", ":"), default=str)
                        yield f"id: {cursor}\nevent: {event_name}\ndata: {data}\n\n"
                        if event["type"] == "terminal":
                            return
                    continue

                job = await anyio.to_thread.run_sync(storage.get_job, identifier)
                if job is None:
                    return
                if str(job["status"]) in TERMINAL_STATUSES:
                    synthetic = {
                        "job_id": identifier,
                        "type": "terminal",
                        "created_at": job.get("completed_at") or job.get("updated_at"),
                        "data": {
                            "status": job["status"],
                            "progress": job["progress"],
                            "partial": bool(job.get("result") and job["result"].get("partial")),
                        },
                    }
                    yield "event: terminal\ndata: " + json.dumps(synthetic, separators=(",", ":")) + "\n\n"
                    return
                if time.monotonic() - last_heartbeat >= 15:
                    yield ": keep-alive\n\n"
                    last_heartbeat = time.monotonic()
                await asyncio.sleep(configured.event_poll_seconds)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-store",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @application.get("/api/jobs/{job_id}/artifacts")
    async def list_artifacts(request: Request, job_id: UUID) -> dict[str, Any]:
        identifier = str(job_id)
        storage = _storage(request)
        _get_job_or_404(storage, identifier)
        artifacts = await anyio.to_thread.run_sync(storage.list_artifacts, identifier)
        return {"items": [artifact_public_record(item) for item in artifacts], "total": len(artifacts)}

    async def artifact_file_response(
        request: Request,
        job_id: UUID,
        artifact_id: UUID,
        *,
        inline: bool,
    ) -> FileResponse:
        identifier = str(job_id)
        storage = _storage(request)
        _get_job_or_404(storage, identifier)
        artifact = _get_artifact_or_404(storage, identifier, str(artifact_id))
        path = _artifact_path(_settings(request), identifier, artifact)
        download_name, detected_media_type = await anyio.to_thread.run_sync(
            artifact_download_details, path, str(artifact.get("name") or path.name)
        )
        media_type = detected_media_type
        if inline:
            sniffed_type, previewable = await anyio.to_thread.run_sync(sniff_media_type, path)
            if not artifact.get("previewable") or not previewable:
                raise HTTPException(
                    status_code=415,
                    detail={"code": "preview_unavailable", "message": "Only verified raster-image and browser-safe audio artifacts can be previewed."},
                )
            media_type = sniffed_type
        return FileResponse(
            path,
            media_type=media_type,
            filename=None,
            headers={
                "Content-Disposition": safe_content_disposition(download_name, inline=inline),
                "X-Artifact-SHA256": str(artifact["sha256"]),
                "Content-Security-Policy": "default-src 'none'; sandbox; frame-ancestors 'none'",
            },
        )

    @application.get("/api/jobs/{job_id}/artifacts/{artifact_id}")
    async def get_artifact_file(
        request: Request,
        job_id: UUID,
        artifact_id: UUID,
        download: bool = Query(True),
    ) -> FileResponse:
        return await artifact_file_response(request, job_id, artifact_id, inline=not download)

    @application.get("/api/jobs/{job_id}/artifacts/{artifact_id}/download")
    async def download_artifact(request: Request, job_id: UUID, artifact_id: UUID) -> FileResponse:
        return await artifact_file_response(request, job_id, artifact_id, inline=False)

    @application.get("/api/jobs/{job_id}/artifacts/{artifact_id}/preview")
    async def preview_artifact(request: Request, job_id: UUID, artifact_id: UUID) -> FileResponse:
        return await artifact_file_response(request, job_id, artifact_id, inline=True)

    @application.get("/api/jobs/{job_id}/hex")
    async def hex_view(
        request: Request,
        job_id: UUID,
        artifact_id: UUID | None = Query(None),
        offset: int = Query(0, ge=0, le=1_000_000_000_000),
        length: int = Query(8192, ge=16, le=64 * 1024),
        search: str | None = Query(None, max_length=256),
        search_mode: Literal["text", "hex"] = Query("text"),
        include_anomalies: bool = Query(True),
    ) -> dict[str, Any]:
        """Return a bounded read-only byte window and anomaly hints."""

        identifier = str(job_id)
        storage = _storage(request)
        _get_job_or_404(storage, identifier)
        if artifact_id is None:
            artifacts = await anyio.to_thread.run_sync(storage.list_artifacts, identifier)
            artifact = next((item for item in artifacts if item.get("kind") == "original"), None)
            if artifact is None:
                raise _not_found("Source artifact")
        else:
            artifact = await anyio.to_thread.run_sync(storage.get_artifact, identifier, str(artifact_id))
            if artifact is None:
                raise _not_found("Artifact")
        path = _artifact_path(_settings(request), identifier, artifact)
        try:
            payload = await anyio.to_thread.run_sync(
                partial(
                    inspect_file,
                    path,
                    offset=offset,
                    length=length,
                    search=search,
                    search_mode=search_mode,
                    include_anomalies=include_anomalies,
                    filename=str(artifact.get("name") or ""),
                    declared_media_type=str(artifact.get("media_type") or ""),
                )
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail={"code": "invalid_hex_search", "message": str(exc)},
            ) from exc
        except OSError as exc:
            raise HTTPException(
                status_code=410,
                detail={"code": "artifact_unavailable", "message": "This artifact is no longer available on disk."},
            ) from exc
        payload["artifact"] = artifact_public_record(artifact)
        return payload

    def resolve_hex_artifact(identifier: str, artifact_id: str | None, storage: Storage) -> dict[str, Any]:
        """Resolve a requested artifact while keeping path selection server-side."""

        if artifact_id is None:
            artifacts = storage.list_artifacts(identifier)
            artifact = next((item for item in artifacts if item.get("kind") == "original"), None)
            if artifact is None:
                raise _not_found("Source artifact")
            return artifact
        artifact = storage.get_artifact(identifier, str(artifact_id))
        if artifact is None:
            raise _not_found("Artifact")
        return artifact

    def validate_hex_request(
        request_model: HexEditRequest,
        *,
        request: Request,
        identifier: str,
        storage: Storage,
    ) -> tuple[dict[str, Any], Path, list[dict[str, int]]]:
        artifact = resolve_hex_artifact(identifier, request_model.artifact_id, storage)
        source_sha = str(artifact.get("sha256") or "").lower()
        if request_model.base_sha256 != source_sha:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "stale_artifact",
                    "message": "This artifact changed since the editor loaded it. Refresh the artifact before applying edits.",
                },
            )
        path = _artifact_path(_settings(request), identifier, artifact)
        try:
            normalized = normalize_edits(
                [item.model_dump() for item in request_model.edits],
                path.stat().st_size,
            )
        except (HexEditError, OSError) as exc:
            if isinstance(exc, OSError):
                raise HTTPException(
                    status_code=410,
                    detail={"code": "artifact_unavailable", "message": "This artifact is no longer available on disk."},
                ) from exc
            raise HTTPException(status_code=422, detail={"code": "invalid_hex_edits", "message": str(exc)}) from exc
        return artifact, path, normalized

    def validate_hex_repair_request(
        request_model: HexRepairRequest,
        *,
        request: Request,
        identifier: str,
        storage: Storage,
    ) -> tuple[dict[str, Any], Path]:
        artifact = resolve_hex_artifact(identifier, request_model.artifact_id, storage)
        source_sha = str(artifact.get("sha256") or "").lower()
        if request_model.base_sha256 != source_sha:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "stale_artifact",
                    "message": "This artifact changed since the editor loaded it. Refresh the artifact before creating a repair.",
                },
            )
        path = _artifact_path(_settings(request), identifier, artifact)
        return artifact, path

    @application.post("/api/jobs/{job_id}/hex/analyze")
    async def analyze_hex_edits(request: Request, job_id: UUID, payload: HexEditRequest) -> dict[str, Any]:
        """Analyze a sparse edited copy in memory; no temporary artifact is persisted."""

        identifier = str(job_id)
        storage = _storage(request)
        _get_job_or_404(storage, identifier)
        artifact, path, normalized = validate_hex_request(payload, request=request, identifier=identifier, storage=storage)
        try:
            result = await anyio.to_thread.run_sync(
                partial(
                    analyze_edited_file,
                    path,
                    normalized,
                    filename=str(artifact.get("name") or ""),
                    declared_media_type=str(artifact.get("media_type") or ""),
                    revision=payload.revision,
                )
            )
        except LiveEditTooLargeError as exc:
            raise HTTPException(status_code=413, detail={"code": "live_edit_limit", "message": str(exc)}) from exc
        except (HexEditError, OSError) as exc:
            raise HTTPException(status_code=422, detail={"code": "invalid_hex_edits", "message": str(exc)}) from exc
        result["artifact"] = artifact_public_record(artifact)
        result["original_sha256"] = str(artifact.get("sha256") or "")
        return result

    @application.post("/api/jobs/{job_id}/hex/preview")
    async def preview_hex_edits(request: Request, job_id: UUID, payload: HexEditRequest) -> Response:
        """Render edited bytes directly to a browser-safe response without saving them."""

        identifier = str(job_id)
        storage = _storage(request)
        _get_job_or_404(storage, identifier)
        artifact, path, normalized = validate_hex_request(payload, request=request, identifier=identifier, storage=storage)
        try:
            rendered, media_type, _kind = await anyio.to_thread.run_sync(partial(render_edited_preview, path, normalized))
        except LiveEditTooLargeError as exc:
            raise HTTPException(status_code=413, detail={"code": "live_edit_limit", "message": str(exc)}) from exc
        except PreviewUnavailableError as exc:
            raise HTTPException(status_code=415, detail={"code": "preview_unavailable", "message": str(exc)}) from exc
        except (HexEditError, OSError) as exc:
            raise HTTPException(status_code=422, detail={"code": "invalid_hex_edits", "message": str(exc)}) from exc
        return Response(
            rendered,
            media_type=media_type,
            headers={
                "Cache-Control": "no-store, max-age=0",
                "X-Hex-Revision": str(payload.revision),
                "X-Hex-Source-SHA256": str(artifact.get("sha256") or ""),
                "Content-Security-Policy": "default-src 'none'; sandbox; frame-ancestors 'none'",
            },
        )

    @application.post("/api/jobs/{job_id}/hex/save")
    async def save_hex_edits(request: Request, job_id: UUID, payload: HexSaveRequest) -> dict[str, Any]:
        """Persist a sparse edit as a new child artifact using an atomic write."""

        identifier = str(job_id)
        storage = _storage(request)
        job = _get_job_or_404(storage, identifier)
        if str(job.get("status")) not in TERMINAL_STATUSES:
            raise HTTPException(
                status_code=409,
                detail={"code": "job_active", "message": "Wait for the analysis to finish before saving a derived hex artifact."},
            )
        lock_map: dict[str, asyncio.Lock] = getattr(request.app.state, "hex_edit_locks", {})
        lock = lock_map.setdefault(identifier, asyncio.Lock())
        async with lock:
            artifact, source_path, normalized = validate_hex_request(payload, request=request, identifier=identifier, storage=storage)
            artifacts = await anyio.to_thread.run_sync(storage.list_artifacts, identifier)
            if len(artifacts) >= _settings(request).max_artifacts:
                raise HTTPException(
                    status_code=409,
                    detail={"code": "artifact_limit", "message": "This job has reached its derived-artifact limit."},
                )
            configured_settings = _settings(request)
            job_dir = resolve_under(configured_settings.jobs_dir, identifier, must_exist=True)
            edit_dir = resolve_under(job_dir, "output", "hex-edits", must_exist=False)
            edit_dir.mkdir(parents=True, exist_ok=True)
            source_name = normalize_display_filename(str(artifact.get("name") or "source.bin"), fallback="source.bin")
            requested_name = normalize_display_filename(payload.name, fallback="") if payload.name else ""
            if not requested_name:
                stem = Path(source_name).stem or "source"
                suffix = Path(source_name).suffix or ".bin"
                requested_name = f"{stem}-edited{suffix}"
            # The random server prefix prevents path collisions while the
            # display name remains useful in the artifact list.
            destination_name = f"{uuid4().hex}-{requested_name}"
            destination = resolve_under(job_dir, "output", "hex-edits", destination_name, must_exist=False)
            temporary = resolve_under(job_dir, "output", "hex-edits", f".{uuid4().hex}.tmp", must_exist=False)
            try:
                written = await anyio.to_thread.run_sync(partial(write_edited_copy, source_path, temporary, normalized))
                if not written["changed_count"]:
                    temporary.unlink(missing_ok=True)
                    raise HTTPException(status_code=422, detail={"code": "no_effective_edits", "message": "Every submitted byte already had that value."})
                await anyio.to_thread.run_sync(partial(os.replace, temporary, destination))
                media_type, sniff_previewable = await anyio.to_thread.run_sync(sniff_media_type, destination)
                relative_path = destination.relative_to(job_dir).as_posix()
                record = {
                    "id": str(uuid4()),
                    "job_id": identifier,
                    "parent_id": str(artifact["id"]),
                    "name": requested_name,
                    "kind": "hex-edit",
                    "relative_path": relative_path,
                    "media_type": media_type,
                    "size_bytes": int(written["size_bytes"]),
                    "sha256": written["sha256"],
                    "previewable": bool(sniff_previewable),
                    "metadata": {
                        "immutable_derived": True,
                        "producer": "hex-editor",
                        "transformation": "sparse byte overwrite",
                        "source_artifact_id": str(artifact["id"]),
                        "source_sha256": str(artifact.get("sha256") or ""),
                        "edit_count": len(normalized),
                        "changed_count": int(written["changed_count"]),
                        "patch_sha256": patch_digest(normalized),
                        "edited_offsets": [item["offset"] for item in normalized[:512]],
                    },
                }
                stored = await anyio.to_thread.run_sync(storage.upsert_artifact, record)
                try:
                    await anyio.to_thread.run_sync(
                        storage.append_event,
                        identifier,
                        "artifact",
                        {"artifact_id": stored["id"], "name": stored["name"], "message": "Saved a new derived artifact from Hex editor edits."},
                    )
                except Exception:
                    # The artifact and its bytes are already a consistent
                    # pair; an event-log failure must not delete the indexed
                    # file and leave a dangling database row.
                    logger.warning("Unable to append hex artifact event for job %s", identifier, exc_info=True)
            except HTTPException:
                temporary.unlink(missing_ok=True)
                destination.unlink(missing_ok=True)
                raise
            except (HexEditError, OSError, ValueError) as exc:
                temporary.unlink(missing_ok=True)
                destination.unlink(missing_ok=True)
                raise HTTPException(status_code=422, detail={"code": "hex_save_failed", "message": str(exc)}) from exc
            except Exception as exc:
                # If indexing fails after the atomic move, remove the derived
                # bytes as well so the filesystem and SQLite cannot diverge.
                temporary.unlink(missing_ok=True)
                destination.unlink(missing_ok=True)
                logger.exception("Unable to persist hex-derived artifact for job %s", identifier)
                raise HTTPException(status_code=500, detail={"code": "hex_save_failed", "message": "The derived artifact could not be indexed."}) from exc
            return {"artifact": artifact_public_record(stored), "source_sha256": str(artifact.get("sha256") or "")}

    @application.post("/api/jobs/{job_id}/hex/repair")
    async def create_hex_repair(request: Request, job_id: UUID, payload: HexRepairRequest) -> dict[str, Any]:
        """Create a deterministic format repair as a new immutable artifact."""

        identifier = str(job_id)
        storage = _storage(request)
        job = _get_job_or_404(storage, identifier)
        if str(job.get("status")) not in TERMINAL_STATUSES:
            raise HTTPException(
                status_code=409,
                detail={"code": "job_active", "message": "Wait for the analysis to finish before creating a repair artifact."},
            )
        lock_map: dict[str, asyncio.Lock] = getattr(request.app.state, "hex_edit_locks", {})
        lock = lock_map.setdefault(identifier, asyncio.Lock())
        async with lock:
            artifact, source_path = validate_hex_repair_request(payload, request=request, identifier=identifier, storage=storage)
            artifacts = await anyio.to_thread.run_sync(storage.list_artifacts, identifier)
            if len(artifacts) >= _settings(request).max_artifacts:
                raise HTTPException(
                    status_code=409,
                    detail={"code": "artifact_limit", "message": "This job has reached its derived-artifact limit."},
                )
            source_name = normalize_display_filename(str(artifact.get("name") or "source.bin"), fallback="source.bin")
            try:
                repaired_data, candidate = await anyio.to_thread.run_sync(
                    partial(
                        read_repair_candidate,
                        source_path,
                        payload.candidate_id,
                        filename=source_name,
                        declared_media_type=str(artifact.get("media_type") or ""),
                    )
                )
            except LiveEditTooLargeError as exc:
                raise HTTPException(status_code=413, detail={"code": "repair_limit", "message": str(exc)}) from exc
            except (HexEditError, OSError) as exc:
                raise HTTPException(status_code=422, detail={"code": "repair_unavailable", "message": str(exc)}) from exc
            configured_settings = _settings(request)
            job_dir = resolve_under(configured_settings.jobs_dir, identifier, must_exist=True)
            edit_dir = resolve_under(job_dir, "output", "hex-edits", must_exist=False)
            edit_dir.mkdir(parents=True, exist_ok=True)
            requested_name = normalize_display_filename(payload.name, fallback="") if payload.name else ""
            if not requested_name:
                label = normalize_display_filename(str(candidate.get("label") or "repair"), fallback="repair")
                stem = Path(source_name).stem or "source"
                suffix = Path(source_name).suffix or ".bin"
                requested_name = normalize_display_filename(f"{stem}-{label}{suffix}", fallback=f"source-repair{suffix}")
            destination_name = f"{uuid4().hex}-{requested_name}"
            destination = resolve_under(job_dir, "output", "hex-edits", destination_name, must_exist=False)
            temporary = resolve_under(job_dir, "output", "hex-edits", f".{uuid4().hex}.tmp", must_exist=False)
            try:
                written = await anyio.to_thread.run_sync(partial(write_repair_copy, temporary, repaired_data))
                await anyio.to_thread.run_sync(partial(os.replace, temporary, destination))
                media_type, sniff_previewable = await anyio.to_thread.run_sync(sniff_media_type, destination)
                relative_path = destination.relative_to(job_dir).as_posix()
                record = {
                    "id": str(uuid4()),
                    "job_id": identifier,
                    "parent_id": str(artifact["id"]),
                    "name": requested_name,
                    "kind": "repair",
                    "relative_path": relative_path,
                    "media_type": media_type,
                    "size_bytes": int(written["size_bytes"]),
                    "sha256": written["sha256"],
                    "previewable": bool(sniff_previewable),
                    "metadata": {
                        "immutable_derived": True,
                        "repair_candidate": True,
                        "producer": candidate.get("producer") or "format-parser",
                        "transformation": candidate.get("transformation") or "deterministic format repair",
                        "reason": candidate.get("reason") or "The format parser found a structural repair.",
                        "repair_candidate_id": candidate.get("id"),
                        "format": candidate.get("format"),
                        "source_artifact_id": str(artifact["id"]),
                        "source_sha256": str(artifact.get("sha256") or ""),
                        "source_size": candidate.get("source_size"),
                        "repaired_size": candidate.get("repaired_size"),
                        "changed_bytes": candidate.get("changed_bytes"),
                        "changed_offsets": candidate.get("changed_offsets", [])[:64],
                        "after_integrity": candidate.get("after_integrity"),
                    },
                }
                stored = await anyio.to_thread.run_sync(storage.upsert_artifact, record)
                try:
                    await anyio.to_thread.run_sync(
                        storage.append_event,
                        identifier,
                        "artifact",
                        {"artifact_id": stored["id"], "name": stored["name"], "message": "Saved a deterministic format repair candidate."},
                    )
                except Exception:
                    logger.warning("Unable to append hex repair event for job %s", identifier, exc_info=True)
            except (HexEditError, OSError, ValueError) as exc:
                temporary.unlink(missing_ok=True)
                destination.unlink(missing_ok=True)
                raise HTTPException(status_code=422, detail={"code": "repair_save_failed", "message": str(exc)}) from exc
            except Exception as exc:
                temporary.unlink(missing_ok=True)
                destination.unlink(missing_ok=True)
                logger.exception("Unable to persist hex repair for job %s", identifier)
                raise HTTPException(status_code=500, detail={"code": "repair_save_failed", "message": "The repair artifact could not be indexed."}) from exc
            return {
                "artifact": artifact_public_record(stored),
                "candidate": candidate,
                "source_sha256": str(artifact.get("sha256") or ""),
            }

    async def export_context(request: Request, job_id: UUID) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
        identifier = str(job_id)
        storage = _storage(request)
        job = await anyio.to_thread.run_sync(storage.get_job, identifier)
        if job is None:
            raise _not_found()
        artifacts = await anyio.to_thread.run_sync(storage.list_artifacts, identifier)
        return job, artifacts, build_export_payload(job, artifacts)

    @application.get("/api/jobs/{job_id}/report.json")
    async def export_json(request: Request, job_id: UUID) -> Response:
        _job, _artifacts, payload = await export_context(request, job_id)
        identifier = str(job_id)
        return Response(
            report_json_bytes(payload),
            media_type="application/json",
            headers={"Content-Disposition": safe_content_disposition(f"forenscope-{identifier}.json")},
        )

    @application.get("/api/jobs/{job_id}/report.html")
    async def export_html(
        request: Request,
        job_id: UUID,
        download: bool = Query(False),
    ) -> HTMLResponse:
        _job, _artifacts, payload = await export_context(request, job_id)
        identifier = str(job_id)
        return HTMLResponse(
            render_html_report(payload),
            headers={
                "Content-Disposition": safe_content_disposition(f"forenscope-{identifier}.html", inline=not download),
                "Content-Security-Policy": report_csp(),
            },
        )

    @application.get("/api/jobs/{job_id}/report.zip")
    async def export_zip(request: Request, job_id: UUID) -> FileResponse:
        _job, artifacts, payload = await export_context(request, job_id)
        configured_settings = _settings(request)
        temp_handle = tempfile.NamedTemporaryFile(
            prefix="forenscope-report-",
            suffix=".zip",
            dir=configured_settings.temp_dir,
            delete=False,
        )
        temp_path = Path(temp_handle.name)
        temp_handle.close()
        identifier = str(job_id)
        job_dir = resolve_under(configured_settings.jobs_dir, identifier, must_exist=True)
        try:
            await anyio.to_thread.run_sync(
                partial(write_report_zip, temp_path, payload=payload, artifacts=artifacts, job_dir=job_dir)
            )
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise
        return FileResponse(
            temp_path,
            media_type="application/zip",
            headers={"Content-Disposition": safe_content_disposition(f"forenscope-{identifier}.zip")},
            background=BackgroundTask(temp_path.unlink, missing_ok=True),
        )

    return application


app = create_app()


def run() -> None:
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8787, reload=False)
