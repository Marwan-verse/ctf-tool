"""FastAPI control plane for the local Forenscope GUI."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
import zipfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path
from typing import Any
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
from .analyzers.external import TOOL_SPECS
from .config import MEBIBYTE, Settings, settings as default_settings
from .jobs import JobManager
from .reporting import (
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
    JobListResponse,
    JobResponse,
    JobStatus,
    ScanProfile,
    TERMINAL_STATUSES,
    ToolDownloadRequest,
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


# Static, HTTPS-only project pages used by the GUI's missing-tool install links.
# The server never downloads or executes these binaries automatically.
TOOL_DOWNLOAD_URLS: dict[str, str] = {
    "file": "https://darwinsys.com/file/",
    "exiftool": "https://exiftool.org/",
    "exiv2": "https://exiv2.org/download.html",
    "strings": "https://sourceware.org/binutils/",
    "identify": "https://imagemagick.org/script/download.php",
    "pngcheck": "https://libpng.org/pub/png/apps/pngcheck.html",
    "pngcrush": "https://pmt.sourceforge.net/pngcrush/",
    "jpeginfo": "https://github.com/tjko/jpeginfo",
    "jpegtran": "https://libjpeg-turbo.org/Downloads",
    "djpeg": "https://libjpeg-turbo.org/Downloads",
    "zsteg": "https://github.com/zed-0xff/zsteg",
    "stegseek": "https://github.com/RickdeJager/stegseek",
    "steghide": "https://steghide.sourceforge.net/download.php",
    "outguess": "https://github.com/resurrecting-open-source-projects/outguess",
    "jpseek": "https://github.com/search?q=jpseek&type=repositories",
    "jsteg": "https://github.com/lukechampine/jsteg",
    "openstego": "https://www.openstego.com/download.html",
    "binwalk": "https://github.com/ReFirmLabs/binwalk",
    "foremost": "https://github.com/korczis/foremost",
    "7z": "https://www.7-zip.org/download.html",
    "tiffinfo": "https://libtiff.gitlab.io/libtiff/",
    "tiffdump": "https://libtiff.gitlab.io/libtiff/",
    "webpinfo": "https://developers.google.com/speed/webp/download",
    "webpmux": "https://developers.google.com/speed/webp/download",
    "gifsicle": "https://www.lcdf.org/gifsicle/",
    "tesseract": "https://github.com/tesseract-ocr/tesseract",
    "zbarimg": "https://github.com/mchehab/zbar",
}

# Winget package IDs are deliberately fixed. The download endpoint never
# accepts package names or URLs from the browser and never runs the installers.
WINGET_PACKAGE_IDS: dict[str, str] = {
    "exiftool": "OliverBetz.ExifTool",
    "exiv2": "Exiv2.Exiv2",
    "identify": "ImageMagick.ImageMagick",
    "openstego": "syvaidya.openstego",
    "7z": "7zip.7zip",
    "tesseract": "tesseract-ocr.tesseract",
}
MAX_TOOL_DOWNLOAD_BYTES = 512 * MEBIBYTE
MAX_TOOL_DOWNLOAD_FILE_BYTES = 256 * MEBIBYTE


logger = logging.getLogger(__name__)
_SSE_EVENT_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,47}$")


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


def _tool_capabilities() -> list[dict[str, Any]]:
    return [
        {
            "id": spec.tool_id,
            "name": spec.name,
            "executable": spec.executable,
            "category": spec.category,
            "available": shutil.which(spec.executable) is not None,
            "profiles": sorted(spec.profiles),
            "formats": sorted(spec.kinds) if spec.kinds is not None else ["all"],
            "download_url": TOOL_DOWNLOAD_URLS.get(spec.tool_id),
            "install_hint": "Open the project page for install instructions; Forenscope will detect it after restart.",
        }
        for spec in TOOL_SPECS
    ]


def _tool_download_root(settings: Settings) -> Path:
    root = (settings.data_dir / "tool-downloads").resolve()
    data_root = settings.data_dir.resolve()
    if data_root not in root.parents:
        raise RuntimeError("Tool download directory escaped the configured data directory")
    root.mkdir(parents=True, exist_ok=True)
    return root


def _run_winget_download(executable: str, package_id: str, target: Path) -> dict[str, Any]:
    """Download one allowlisted package with a bounded, non-interactive process."""

    command = [
        executable,
        "download",
        "--id",
        package_id,
        "--exact",
        "--source",
        "winget",
        "--download-directory",
        str(target),
        "--accept-source-agreements",
        "--accept-package-agreements",
        "--disable-interactivity",
    ]
    output_limit = 64 * 1024
    started = time.monotonic()
    with tempfile.TemporaryFile(mode="w+b") as output_file:
        kwargs: dict[str, Any] = {
            "args": command,
            "cwd": str(target),
            "stdin": subprocess.DEVNULL,
            "stdout": output_file,
            "stderr": subprocess.STDOUT,
            "shell": False,
            "close_fds": True,
        }
        if os.name == "nt":
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            process = subprocess.Popen(**kwargs)
        except OSError as exc:
            return {"status": "failed", "return_code": None, "output": f"{type(exc).__name__}: {str(exc)[:400]}"}
        status = "completed"
        try:
            process.wait(timeout=120)
        except subprocess.TimeoutExpired:
            status = "timed_out"
            try:
                process.terminate()
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
                process.wait(timeout=2)
        output_file.seek(0)
        output = output_file.read(output_limit + 1).decode("utf-8", "replace")
        if len(output) > output_limit:
            output = output[:output_limit] + "\n… output truncated"
        return {
            "status": status if status != "completed" or process.returncode == 0 else "failed",
            "return_code": process.returncode,
            "output": output.strip(),
            "duration_ms": int((time.monotonic() - started) * 1000),
        }


def _download_tool_installers(settings: Settings, tool_ids: list[str]) -> dict[str, Any]:
    root = _tool_download_root(settings)
    bundle_id = f"bundle-{uuid4().hex}"
    batch_dir = (root / f"batch-{uuid4().hex}").resolve()
    if root not in batch_dir.parents:
        raise RuntimeError("Tool download batch escaped its root")
    batch_dir.mkdir(parents=True, exist_ok=False)
    manager = shutil.which("winget")
    items: list[dict[str, Any]] = []
    downloaded_files: list[Path] = []
    total_bytes = 0
    try:
        for tool_id in tool_ids:
            package_id = WINGET_PACKAGE_IDS.get(tool_id)
            base_item = {
                "id": tool_id,
                "download_url": TOOL_DOWNLOAD_URLS.get(tool_id),
            }
            spec = next((candidate for candidate in TOOL_SPECS if candidate.tool_id == tool_id), None)
            if spec is not None and shutil.which(spec.executable) is not None:
                items.append({**base_item, "status": "already_available", "message": "Tool is already available on PATH."})
                continue
            if package_id is None:
                items.append({
                    **base_item,
                    "status": "manual",
                    "message": "No safe package-manager mapping is available; use the project download page.",
                })
                continue
            if manager is None:
                items.append({
                    **base_item,
                    "status": "manager_unavailable",
                    "message": "The supported package manager (winget) is not installed on this host.",
                })
                continue
            result = _run_winget_download(manager, package_id, batch_dir)
            new_files: list[Path] = []
            for candidate in sorted(batch_dir.rglob("*")):
                if candidate.is_symlink() or not candidate.is_file() or candidate in downloaded_files:
                    continue
                try:
                    size = candidate.stat().st_size
                except OSError:
                    continue
                if size <= 0 or size > MAX_TOOL_DOWNLOAD_FILE_BYTES or total_bytes + size > MAX_TOOL_DOWNLOAD_BYTES:
                    continue
                new_files.append(candidate)
                downloaded_files.append(candidate)
                total_bytes += size
            item_status = "downloaded" if result["status"] == "completed" and new_files else result["status"]
            items.append({
                **base_item,
                "status": item_status,
                "message": "Installer downloaded." if item_status == "downloaded" else (result.get("output") or "Package download did not produce an installer."),
                "package_id": package_id,
                "files": [file.name for file in new_files],
                "duration_ms": result.get("duration_ms", 0),
            })

        bundle_path = (root / f"{bundle_id}.zip").resolve()
        if root not in bundle_path.parents:
            raise RuntimeError("Tool bundle escaped its root")
        if downloaded_files:
            with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                for file in downloaded_files:
                    archive.write(file, arcname=file.name)
        else:
            bundle_id = ""
        downloaded_count = sum(item.get("status") == "downloaded" for item in items)
        if downloaded_count and downloaded_count == len(items):
            status = "completed"
        elif downloaded_count:
            status = "partial"
        else:
            status = "unavailable"
        return {
            "status": status,
            "manager": "winget" if manager else None,
            "bundle_url": f"/api/tools/download-bundles/{bundle_id}" if bundle_id else None,
            "downloaded_count": downloaded_count,
            "total_bytes": total_bytes,
            "items": items,
            "message": "Downloaded installers are packaged in one bundle. Install them, then restart the local API." if downloaded_count else "No installers were downloaded; use the per-tool project links.",
        }
    finally:
        try:
            shutil.rmtree(batch_dir)
        except OSError:
            logger.warning("Could not remove temporary tool download directory %s", batch_dir)


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
        try:
            yield
        finally:
            manager.shutdown()

    application = FastAPI(
        title="Forenscope API",
        summary="Local-first image forensics control plane",
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
    async def capabilities(request: Request) -> dict[str, Any]:
        configured_settings = _settings(request)
        tools = await anyio.to_thread.run_sync(_tool_capabilities)
        return {
            "name": "Forenscope Image Analyzer",
            "version": __version__,
            "max_upload_bytes": configured_settings.max_upload_bytes,
            "profiles": [profile.value for profile in ScanProfile],
            "formats": ["PNG", "APNG", "JPEG", "MPO", "BMP", "GIF", "WebP", "TIFF", "BigTIFF", "ICO", "CUR"],
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
            ],
            "exports": ["json", "html", "zip"],
            "tools": tools,
            "builtin_tools": [
                {"id": "decomposer", "name": "Bit-layer decomposer", "category": "visual", "available": True, "formats": ["all images"]},
                {"id": "color_remapping", "name": "Color remapping", "category": "visual", "available": True, "formats": ["all images"]},
                {"id": "pcrt", "name": "PCRT-compatible PNG repair", "category": "repair", "available": True, "formats": ["png"]},
                {"id": "crypto-analysis", "name": "Encrypted payload detection and recovery", "category": "crypto", "available": True, "formats": ["extracted payloads"]},
                {"id": "spectrogram", "name": "Spectrogram", "category": "audio", "available": False, "formats": ["audio section"]},
                {"id": "pdfinfo", "name": "pdfinfo", "category": "document", "available": False, "formats": ["document section"]},
                {"id": "pdfid", "name": "PDFiD", "category": "document", "available": False, "formats": ["document section"]},
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

    @application.post("/api/tools/download")
    async def download_tools(request: Request, payload: ToolDownloadRequest) -> dict[str, Any]:
        if not payload.confirmed:
            raise HTTPException(
                status_code=400,
                detail={"code": "confirmation_required", "message": "Confirm the explicit tool download request before continuing."},
            )
        declared_tools = {spec.tool_id for spec in TOOL_SPECS}
        unknown = sorted(set(payload.tool_ids) - declared_tools)
        if unknown:
            raise HTTPException(
                status_code=422,
                detail={"code": "unknown_tool", "message": f"Unknown tool download request: {unknown[0]}"},
            )
        return await anyio.to_thread.run_sync(
            partial(_download_tool_installers, _settings(request), payload.tool_ids)
        )

    @application.get("/api/tools/download-bundles/{bundle_id}")
    async def download_tool_bundle(request: Request, bundle_id: str) -> FileResponse:
        if not re.fullmatch(r"bundle-[0-9a-f]{32}", bundle_id):
            raise _not_found("Tool bundle")
        try:
            root = _tool_download_root(_settings(request))
            bundle = require_regular_file(root, f"{bundle_id}.zip")
        except (OSError, UnsafePathError, ValueError) as exc:
            raise _not_found("Tool bundle") from exc
        return FileResponse(bundle, media_type="application/zip", filename="forenscope-tool-installers.zip")

    @application.post("/api/jobs", response_model=JobResponse, status_code=status.HTTP_202_ACCEPTED)
    async def create_job(
        request: Request,
        file: UploadFile = File(..., description="Image or corrupted image evidence"),
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
                        content_type=content_type,
                        size_bytes=size_bytes,
                        sha256=digest.hexdigest(),
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
        media_type = str(artifact.get("media_type") or "application/octet-stream")
        if inline:
            sniffed_type, previewable = await anyio.to_thread.run_sync(sniff_media_type, path)
            if not artifact.get("previewable") or not previewable:
                raise HTTPException(
                    status_code=415,
                    detail={"code": "preview_unavailable", "message": "Only verified raster image artifacts can be previewed."},
                )
            media_type = sniffed_type
        return FileResponse(
            path,
            media_type=media_type,
            filename=None,
            headers={
                "Content-Disposition": safe_content_disposition(str(artifact["name"]), inline=inline),
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
