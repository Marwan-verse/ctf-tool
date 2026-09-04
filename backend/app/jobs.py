"""In-process analysis scheduling and resilient job state transitions."""

from __future__ import annotations

import logging
import re
import shutil
import threading
from collections.abc import Callable, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any, Protocol

from .config import Settings
from .reporting import discover_artifacts, json_safe, normalize_report
from .schemas import TERMINAL_STATUSES
from .security import require_regular_file, resolve_under
from .storage import Storage


logger = logging.getLogger(__name__)
_EVENT_TYPE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{0,47}$")


class EngineProtocol(Protocol):
    def run(
        self,
        input_path: Path,
        output_dir: Path,
        profile: str,
        flag_prefix: str | None,
        password: str | None,
        progress_callback: Callable[..., None],
        is_cancelled: Callable[[], bool],
        options: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]: ...


EngineFactory = Callable[[], EngineProtocol]


def _default_engine_factory() -> EngineProtocol:
    # Kept lazy so health checks and report browsing still work if an optional
    # analyzer dependency is unavailable.
    from .engine import AnalysisEngine

    return AnalysisEngine()


def _redact_event_values(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): ("<redacted>" if "password" in str(key).lower() else _redact_event_values(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_event_values(item) for item in value]
    return value


class JobManager:
    def __init__(
        self,
        *,
        storage: Storage,
        settings: Settings,
        engine_factory: EngineFactory | None = None,
    ) -> None:
        self.storage = storage
        self.settings = settings
        self.engine_factory = engine_factory or _default_engine_factory
        self._executor = ThreadPoolExecutor(
            max_workers=settings.max_workers,
            thread_name_prefix="remanence-analysis",
        )
        self._lock = threading.RLock()
        self._futures: dict[str, Future[None]] = {}
        self._cancel_events: dict[str, threading.Event] = {}
        self._closed = False

    def start(self) -> list[str]:
        """Mark work abandoned by a previous process as a visible failure."""

        return self.storage.recover_interrupted_jobs()

    def submit(self, job_id: str, *, password: str | None) -> None:
        with self._lock:
            if self._closed:
                raise RuntimeError("Job manager is shutting down")
            if job_id in self._futures:
                raise RuntimeError("Job is already scheduled")
            cancellation = threading.Event()
            self._cancel_events[job_id] = cancellation
            try:
                future = self._executor.submit(self._run_job, job_id, password, cancellation)
            except Exception:
                self._cancel_events.pop(job_id, None)
                raise
            self._futures[job_id] = future
            future.add_done_callback(lambda completed, identifier=job_id: self._forget(identifier, completed))

    def _forget(self, job_id: str, future: Future[None]) -> None:
        with self._lock:
            if self._futures.get(job_id) is future:
                self._futures.pop(job_id, None)
                self._cancel_events.pop(job_id, None)

    def request_cancel(self, job_id: str) -> dict[str, Any] | None:
        job = self.storage.request_cancel(job_id)
        if job is None or str(job["status"]) in TERMINAL_STATUSES:
            return job
        with self._lock:
            cancellation = self._cancel_events.get(job_id)
            future = self._futures.get(job_id)
            if cancellation is not None:
                cancellation.set()
            cancelled_before_start = bool(future and future.cancel())
        if cancelled_before_start:
            result = normalize_report(
                {
                    "partial": True,
                    "cancelled": True,
                    "summary": "Analysis was cancelled before it started.",
                    "errors": [],
                },
                job_dir=self.settings.jobs_dir / job_id,
                max_bytes=self.settings.max_report_bytes,
            )
            return self.storage.finish_job(job_id, status="cancelled", result=result)
        return self.storage.get_job(job_id)

    def is_active(self, job_id: str) -> bool:
        with self._lock:
            future = self._futures.get(job_id)
            return bool(future and not future.done())

    def active_count(self) -> int:
        with self._lock:
            return sum(1 for future in self._futures.values() if not future.done())

    def delete_job(self, job_id: str) -> bool:
        job = self.storage.get_job(job_id)
        if job is None:
            return False
        if str(job["status"]) not in TERMINAL_STATUSES or self.is_active(job_id):
            raise RuntimeError("Active jobs must be cancelled and reach a terminal state before deletion")
        job_dir = resolve_under(self.settings.jobs_dir, job_id, must_exist=False)
        if job_dir.exists():
            if job_dir.is_symlink():
                raise RuntimeError("Refusing to delete a symbolic-link job directory")
            shutil.rmtree(job_dir)
        return self.storage.delete_job(job_id)

    def shutdown(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for cancellation in self._cancel_events.values():
                cancellation.set()
            for future in self._futures.values():
                future.cancel()
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _run_job(self, job_id: str, password: str | None, cancellation: threading.Event) -> None:
        job = self.storage.begin_job(job_id)
        if job is None:
            return
        if str(job["status"]) != "running":
            if bool(job.get("cancel_requested")) or str(job["status"]) == "cancelling":
                result = normalize_report(
                    {"partial": True, "cancelled": True, "summary": "Analysis was cancelled."},
                    job_dir=self.settings.jobs_dir / job_id,
                    max_bytes=self.settings.max_report_bytes,
                )
                self.storage.finish_job(job_id, status="cancelled", result=result)
            return

        job_dir = resolve_under(self.settings.jobs_dir, job_id, must_exist=True)
        output_dir = resolve_under(job_dir, str(job["output_relative_path"]), must_exist=False)
        output_dir.mkdir(parents=True, exist_ok=True)
        input_path = require_regular_file(job_dir, str(job["input_relative_path"]))

        def is_cancelled() -> bool:
            return cancellation.is_set()

        def progress_callback(*args: Any, **kwargs: Any) -> None:
            try:
                payload = self._progress_payload(args, kwargs)
                payload = _redact_event_values(json_safe(payload, base_dir=job_dir))
                if not isinstance(payload, dict):
                    payload = {"message": str(payload)}
                raw_event_type = str(payload.pop("type", payload.pop("event_type", "progress")))
                event_type = raw_event_type if _EVENT_TYPE.fullmatch(raw_event_type) else "progress"
                if event_type in {"terminal", "status", "cancel_requested"}:
                    event_type = "progress"
                progress = self._coerce_progress(payload.get("progress"))
                stage_value = payload.get("stage") or payload.get("tool") or payload.get("method")
                stage = str(stage_value)[:160] if stage_value is not None else None
                if progress is not None:
                    payload["progress"] = progress
                if stage is not None:
                    payload["stage"] = stage
                self.storage.update_progress_and_append_event(
                    job_id,
                    progress=progress,
                    stage=stage,
                    event_type=event_type,
                    payload=payload,
                )
            except Exception:
                # Progress telemetry must never abort the forensic analysis.
                logger.debug("Unable to persist progress for job %s", job_id, exc_info=True)

        report: dict[str, Any]
        final_status = "completed"
        error_code: str | None = None
        error_message: str | None = None
        try:
            engine = self.engine_factory()
            raw_report = engine.run(
                input_path=input_path,
                output_dir=output_dir,
                profile=str(job["profile"]),
                flag_prefix=job.get("flag_prefix"),
                password=password,
                options=job.get("options") or {},
                progress_callback=progress_callback,
                is_cancelled=is_cancelled,
            )
            report = normalize_report(
                raw_report,
                job_dir=job_dir,
                max_bytes=self.settings.max_report_bytes,
            )
            if is_cancelled():
                final_status = "cancelled"
                report["partial"] = True
                report["cancelled"] = True
                report.setdefault("summary", "Analysis was cancelled; partial results are available.")
        except Exception as exc:
            logger.exception("Analysis job %s failed", job_id)
            if is_cancelled():
                final_status = "cancelled"
                error_code = None
                error_message = None
                report = normalize_report(
                    {
                        "partial": True,
                        "cancelled": True,
                        "summary": "Analysis was cancelled; partial artifacts may still be available.",
                    },
                    job_dir=job_dir,
                    max_bytes=self.settings.max_report_bytes,
                )
            else:
                final_status = "failed"
                error_code = "engine_unavailable" if isinstance(exc, (ImportError, ModuleNotFoundError)) else "analysis_failed"
                error_message = (
                    "The analysis engine is unavailable. Check the local installation."
                    if error_code == "engine_unavailable"
                    else "The analysis engine stopped unexpectedly. Partial artifacts may still be available."
                )
                report = normalize_report(
                    {
                        "partial": True,
                        "summary": error_message,
                        "errors": [{"code": error_code, "message": error_message, "exception_type": type(exc).__name__}],
                    },
                    job_dir=job_dir,
                    max_bytes=self.settings.max_report_bytes,
                )
        finally:
            # Drop the last in-memory reference to user-supplied password data as
            # soon as the engine call has returned.
            password = None

        indexed = self._index_artifacts(
            job_id=job_id,
            job_dir=job_dir,
            output_dir=output_dir,
            report=report,
            is_cancelled=is_cancelled if final_status != "cancelled" else None,
        )
        report["artifact_count"] = indexed
        self.storage.finish_job(
            job_id,
            status=final_status,
            result=report,
            error_code=error_code,
            error_message=error_message,
            return_job=False,
        )

    def _index_artifacts(
        self,
        *,
        job_id: str,
        job_dir: Path,
        output_dir: Path,
        report: Mapping[str, Any],
        is_cancelled: Callable[[], bool] | None,
    ) -> int:
        try:
            artifacts = discover_artifacts(
                job_id=job_id,
                job_dir=job_dir,
                output_dir=output_dir,
                report=report,
                maximum=self.settings.max_artifacts,
                is_cancelled=is_cancelled,
            )
            return self.storage.upsert_artifacts(artifacts)
        except Exception:
            logger.exception("Unable to index all artifacts for job %s", job_id)
            try:
                self.storage.append_event(
                    job_id,
                    "warning",
                    {"code": "artifact_index_failed", "message": "Some derived files could not be indexed."},
                )
            except Exception:
                logger.debug("Unable to persist artifact warning for %s", job_id, exc_info=True)
            return 0

    @staticmethod
    def _progress_payload(args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> dict[str, Any]:
        payload: dict[str, Any] = {}
        if args:
            first = args[0]
            if isinstance(first, Mapping):
                payload.update(first)
            elif isinstance(first, str):
                payload["stage"] = first
            elif isinstance(first, (int, float)):
                payload["progress"] = first
            else:
                payload["message"] = str(first)
        if len(args) >= 2:
            second = args[1]
            if isinstance(second, (int, float)):
                payload["progress"] = second
            elif "message" not in payload:
                payload["message"] = str(second)
        if len(args) >= 3 and "message" not in payload:
            payload["message"] = str(args[2])
        payload.update(dict(kwargs))
        return payload

    @staticmethod
    def _coerce_progress(value: Any) -> float | None:
        if value is None:
            return None
        try:
            progress = float(value)
        except (TypeError, ValueError):
            return None
        if 1 < progress <= 100:
            progress /= 100
        return max(0.0, min(1.0, progress))
