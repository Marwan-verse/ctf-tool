"""SQLite persistence for jobs, events, and extracted artifacts."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .schemas import TERMINAL_STATUSES


ACTIVE_STATUSES = {"queued", "running", "cancelling"}


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _json_load(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return fallback


class Storage:
    """Short-lived SQLite connections with transactional state transitions."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path.resolve()
        self._schema_lock = threading.Lock()
        self._initialized = False

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self.database_path,
            timeout=10.0,
            isolation_level="DEFERRED",
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        try:
            yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._schema_lock:
            if self._initialized:
                return
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
            with self._connect() as connection:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("PRAGMA synchronous = NORMAL")
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS jobs (
                        id TEXT PRIMARY KEY,
                        status TEXT NOT NULL CHECK(status IN ('queued','running','cancelling','completed','failed','cancelled')),
                        profile TEXT NOT NULL CHECK(profile IN ('quick','balanced','deep')),
                        original_filename TEXT NOT NULL,
                        content_type TEXT NOT NULL,
                        size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
                        sha256 TEXT NOT NULL,
                        flag_prefix TEXT,
                        options_json TEXT NOT NULL DEFAULT '{}',
                        input_relative_path TEXT NOT NULL,
                        output_relative_path TEXT NOT NULL,
                        progress REAL NOT NULL DEFAULT 0 CHECK(progress >= 0 AND progress <= 1),
                        current_stage TEXT,
                        cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN (0,1)),
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        started_at TEXT,
                        completed_at TEXT,
                        error_code TEXT,
                        error_message TEXT,
                        report_json TEXT
                    );

                    CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                        event_type TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS artifacts (
                        id TEXT PRIMARY KEY,
                        job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                        parent_id TEXT,
                        name TEXT NOT NULL,
                        kind TEXT NOT NULL,
                        relative_path TEXT NOT NULL,
                        media_type TEXT NOT NULL,
                        size_bytes INTEGER NOT NULL CHECK(size_bytes >= 0),
                        sha256 TEXT NOT NULL,
                        previewable INTEGER NOT NULL DEFAULT 0 CHECK(previewable IN (0,1)),
                        metadata_json TEXT NOT NULL DEFAULT '{}',
                        created_at TEXT NOT NULL,
                        UNIQUE(job_id, relative_path)
                    );

                    CREATE INDEX IF NOT EXISTS idx_jobs_status_created
                        ON jobs(status, created_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_jobs_created
                        ON jobs(created_at DESC);
                    CREATE INDEX IF NOT EXISTS idx_events_job_id_id
                        ON events(job_id, id);
                    CREATE INDEX IF NOT EXISTS idx_artifacts_job_created
                        ON artifacts(job_id, created_at, id);
                    """
                )
                columns = {
                    str(row["name"])
                    for row in connection.execute("PRAGMA table_info(jobs)").fetchall()
                }
                if "options_json" not in columns:
                    connection.execute("ALTER TABLE jobs ADD COLUMN options_json TEXT NOT NULL DEFAULT '{}'")
                connection.commit()
            self._initialized = True

    def ping(self) -> bool:
        try:
            with self._connect() as connection:
                return connection.execute("SELECT 1").fetchone()[0] == 1
        except sqlite3.Error:
            return False

    @staticmethod
    def _insert_event(
        connection: sqlite3.Connection,
        job_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        *,
        created_at: str | None = None,
    ) -> int:
        timestamp = created_at or utc_now()
        cursor = connection.execute(
            "INSERT INTO events(job_id, event_type, payload_json, created_at) VALUES (?, ?, ?, ?)",
            (job_id, event_type, _json_dump(dict(payload)), timestamp),
        )
        return int(cursor.lastrowid)

    @staticmethod
    def _job_from_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        item = dict(row)
        report_json = item.pop("report_json", None)
        item["options"] = _json_load(item.pop("options_json", None), {})
        item["result"] = _json_load(report_json, None)
        item["cancel_requested"] = bool(item.get("cancel_requested"))
        return item

    @staticmethod
    def _artifact_from_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        item = dict(row)
        item["previewable"] = bool(item.get("previewable"))
        item["metadata"] = _json_load(item.pop("metadata_json", None), {})
        return item

    @staticmethod
    def _event_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "job_id": row["job_id"],
            "type": row["event_type"],
            "created_at": row["created_at"],
            "data": _json_load(row["payload_json"], {}),
        }

    def create_job(self, values: Mapping[str, Any]) -> dict[str, Any]:
        timestamp = utc_now()
        with self._connect() as connection, connection:
            connection.execute(
                """
                INSERT INTO jobs(
                    id, status, profile, original_filename, content_type,
                    size_bytes, sha256, flag_prefix, options_json, input_relative_path,
                    output_relative_path, progress, current_stage,
                    cancel_requested, created_at, updated_at
                ) VALUES (?, 'queued', ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'Queued', 0, ?, ?)
                """,
                (
                    values["id"],
                    values["profile"],
                    values["original_filename"],
                    values["content_type"],
                    int(values["size_bytes"]),
                    values["sha256"],
                    values.get("flag_prefix"),
                    _json_dump(values.get("options") or {}),
                    values["input_relative_path"],
                    values["output_relative_path"],
                    timestamp,
                    timestamp,
                ),
            )
            self._insert_event(
                connection,
                str(values["id"]),
                "status",
                {"status": "queued", "progress": 0.0, "stage": "Queued"},
                created_at=timestamp,
            )
            row = connection.execute("SELECT * FROM jobs WHERE id = ?", (values["id"],)).fetchone()
        result = self._job_from_row(row)
        assert result is not None
        return result

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return self._job_from_row(row)

    def list_jobs(
        self,
        *,
        limit: int,
        offset: int,
        status: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        with self._connect() as connection:
            if status is None:
                rows = connection.execute(
                    "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
                total = int(connection.execute("SELECT COUNT(*) FROM jobs").fetchone()[0])
            else:
                rows = connection.execute(
                    "SELECT * FROM jobs WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                    (status, limit, offset),
                ).fetchall()
                total = int(
                    connection.execute("SELECT COUNT(*) FROM jobs WHERE status = ?", (status,)).fetchone()[0]
                )
        return [item for row in rows if (item := self._job_from_row(row)) is not None], total

    def job_counts(self) -> dict[str, int]:
        counts = {
            "queued": 0,
            "running": 0,
            "cancelling": 0,
            "completed": 0,
            "failed": 0,
            "cancelled": 0,
        }
        with self._connect() as connection:
            rows = connection.execute("SELECT status, COUNT(*) AS count FROM jobs GROUP BY status").fetchall()
        for row in rows:
            counts[str(row["status"])] = int(row["count"])
        return counts

    def append_event(self, job_id: str, event_type: str, payload: Mapping[str, Any]) -> int:
        with self._connect() as connection, connection:
            return self._insert_event(connection, job_id, event_type, payload)

    def list_events(self, job_id: str, *, after_id: int = 0, limit: int = 250) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, job_id, event_type, payload_json, created_at
                FROM events WHERE job_id = ? AND id > ? ORDER BY id ASC LIMIT ?
                """,
                (job_id, after_id, limit),
            ).fetchall()
        return [self._event_from_row(row) for row in rows]

    def begin_job(self, job_id: str) -> dict[str, Any] | None:
        timestamp = utc_now()
        with self._connect() as connection, connection:
            cursor = connection.execute(
                """
                UPDATE jobs
                SET status = 'running', started_at = COALESCE(started_at, ?),
                    updated_at = ?, current_stage = 'Starting analysis'
                WHERE id = ? AND status = 'queued' AND cancel_requested = 0
                """,
                (timestamp, timestamp, job_id),
            )
            if cursor.rowcount:
                self._insert_event(
                    connection,
                    job_id,
                    "status",
                    {"status": "running", "progress": 0.0, "stage": "Starting analysis"},
                    created_at=timestamp,
                )
            row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return self._job_from_row(row)

    def update_progress(self, job_id: str, *, progress: float | None, stage: str | None) -> None:
        timestamp = utc_now()
        with self._connect() as connection, connection:
            if progress is None:
                connection.execute(
                    """
                    UPDATE jobs SET current_stage = COALESCE(?, current_stage), updated_at = ?
                    WHERE id = ? AND status IN ('running','cancelling')
                    """,
                    (stage, timestamp, job_id),
                )
            else:
                normalized = max(0.0, min(1.0, float(progress)))
                connection.execute(
                    """
                    UPDATE jobs
                    SET progress = MAX(progress, ?), current_stage = COALESCE(?, current_stage), updated_at = ?
                    WHERE id = ? AND status IN ('running','cancelling')
                    """,
                    (normalized, stage, timestamp, job_id),
                )

    def request_cancel(self, job_id: str) -> dict[str, Any] | None:
        timestamp = utc_now()
        with self._connect() as connection, connection:
            current = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if current is None:
                return None
            if str(current["status"]) in TERMINAL_STATUSES:
                return self._job_from_row(current)
            was_requested = bool(current["cancel_requested"])
            connection.execute(
                """
                UPDATE jobs
                SET cancel_requested = 1, status = 'cancelling',
                    current_stage = 'Cancellation requested', updated_at = ?
                WHERE id = ? AND status IN ('queued','running','cancelling')
                """,
                (timestamp, job_id),
            )
            if not was_requested:
                self._insert_event(
                    connection,
                    job_id,
                    "cancel_requested",
                    {"status": "cancelling", "message": "Cancellation requested"},
                    created_at=timestamp,
                )
            row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return self._job_from_row(row)

    def finish_job(
        self,
        job_id: str,
        *,
        status: str,
        result: Mapping[str, Any] | None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> dict[str, Any] | None:
        if status not in TERMINAL_STATUSES:
            raise ValueError("finish_job requires a terminal status")
        timestamp = utc_now()
        serialized_result = _json_dump(dict(result)) if result is not None else None
        with self._connect() as connection, connection:
            current = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
            if current is None:
                return None
            if str(current["status"]) in TERMINAL_STATUSES:
                return self._job_from_row(current)
            progress = 1.0 if status == "completed" else float(current["progress"])
            stage = {
                "completed": "Analysis complete",
                "failed": "Analysis failed",
                "cancelled": "Analysis cancelled",
            }[status]
            connection.execute(
                """
                UPDATE jobs
                SET status = ?, progress = ?, current_stage = ?, completed_at = ?,
                    updated_at = ?, error_code = ?, error_message = ?, report_json = ?
                WHERE id = ? AND status IN ('queued','running','cancelling')
                """,
                (
                    status,
                    progress,
                    stage,
                    timestamp,
                    timestamp,
                    error_code,
                    error_message,
                    serialized_result,
                    job_id,
                ),
            )
            terminal_payload: dict[str, Any] = {
                "status": status,
                "progress": progress,
                "stage": stage,
                "partial": bool(result and result.get("partial")),
            }
            if error_code:
                terminal_payload["error"] = {"code": error_code, "message": error_message or "Analysis failed"}
            self._insert_event(connection, job_id, "terminal", terminal_payload, created_at=timestamp)
            row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return self._job_from_row(row)

    def recover_interrupted_jobs(self) -> list[str]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT id FROM jobs WHERE status IN ('queued','running','cancelling') ORDER BY created_at"
            ).fetchall()
        recovered: list[str] = []
        for row in rows:
            job_id = str(row["id"])
            result = {
                "partial": True,
                "errors": [
                    {
                        "code": "server_restarted",
                        "message": "The local API stopped before this analysis finished.",
                    }
                ],
            }
            self.finish_job(
                job_id,
                status="failed",
                result=result,
                error_code="server_restarted",
                error_message="The local API stopped before this analysis finished.",
            )
            recovered.append(job_id)
        return recovered

    def upsert_artifact(self, values: Mapping[str, Any]) -> dict[str, Any]:
        created_at = str(values.get("created_at") or utc_now())
        with self._connect() as connection, connection:
            connection.execute(
                """
                INSERT INTO artifacts(
                    id, job_id, parent_id, name, kind, relative_path, media_type,
                    size_bytes, sha256, previewable, metadata_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id, relative_path) DO UPDATE SET
                    parent_id = excluded.parent_id,
                    name = excluded.name,
                    kind = excluded.kind,
                    media_type = excluded.media_type,
                    size_bytes = excluded.size_bytes,
                    sha256 = excluded.sha256,
                    previewable = excluded.previewable,
                    metadata_json = excluded.metadata_json
                """,
                (
                    values["id"],
                    values["job_id"],
                    values.get("parent_id"),
                    values["name"],
                    values.get("kind", "artifact"),
                    values["relative_path"],
                    values.get("media_type", "application/octet-stream"),
                    int(values["size_bytes"]),
                    values["sha256"],
                    int(bool(values.get("previewable"))),
                    _json_dump(dict(values.get("metadata") or {})),
                    created_at,
                ),
            )
            row = connection.execute(
                "SELECT * FROM artifacts WHERE job_id = ? AND relative_path = ?",
                (values["job_id"], values["relative_path"]),
            ).fetchone()
        result = self._artifact_from_row(row)
        assert result is not None
        return result

    def list_artifacts(self, job_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM artifacts WHERE job_id = ? ORDER BY created_at, id",
                (job_id,),
            ).fetchall()
        return [item for row in rows if (item := self._artifact_from_row(row)) is not None]

    def get_artifact(self, job_id: str, artifact_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM artifacts WHERE job_id = ? AND id = ?",
                (job_id, artifact_id),
            ).fetchone()
        return self._artifact_from_row(row)

    def delete_job(self, job_id: str) -> bool:
        with self._connect() as connection, connection:
            cursor = connection.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
        return bool(cursor.rowcount)
