"""Runtime configuration for the local Remanence control plane."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


MEBIBYTE = 1024 * 1024
DEFAULT_ALLOWED_ORIGINS = (
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
)
DEFAULT_ALLOWED_HOSTS = ("localhost", "127.0.0.1", "[::1]", "testserver")


def _environment(name: str) -> str | None:
    """Read a Remanence setting while accepting the former prefix for upgrades."""

    value = os.getenv(name)
    if value is not None:
        return value
    if name.startswith("REMANENCE_"):
        return os.getenv(f"FORENSCOPE_{name.removeprefix('REMANENCE_')}")
    return None


def _positive_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = _environment(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def _positive_float(name: str, default: float, *, minimum: float = 0.01) -> float:
    raw = _environment(name)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number") from exc
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def _is_loopback_origin(origin: str) -> bool:
    parsed = urlsplit(origin)
    if parsed.scheme not in {"http", "https"}:
        return False
    return parsed.hostname in {"localhost", "127.0.0.1", "::1"}


@dataclass(frozen=True, slots=True)
class Settings:
    """Validated application settings.

    The service is deliberately local-only. Environment configuration can add
    local ports, but cannot silently widen browser access to a remote origin.
    """

    data_dir: Path
    database_path: Path
    jobs_dir: Path
    temp_dir: Path
    max_upload_bytes: int = 100 * MEBIBYTE
    max_workers: int = 2
    max_artifacts: int = 500
    max_report_bytes: int = 25 * MEBIBYTE
    event_poll_seconds: float = 0.35
    rate_limit_per_minute: int = 300
    upload_limit_per_minute: int = 12
    allowed_origins: tuple[str, ...] = DEFAULT_ALLOWED_ORIGINS
    allowed_hosts: tuple[str, ...] = DEFAULT_ALLOWED_HOSTS

    @classmethod
    def from_env(cls) -> "Settings":
        backend_dir = Path(__file__).resolve().parents[1]
        data_dir = Path(_environment("REMANENCE_DATA_DIR") or str(backend_dir / "data")).expanduser().resolve()
        database_raw = _environment("REMANENCE_DB_PATH")
        default_database = data_dir / "remanence.sqlite3"
        legacy_database = data_dir / "forenscope.sqlite3"
        if not default_database.exists() and legacy_database.exists():
            default_database = legacy_database
        database_path = (
            Path(database_raw).expanduser().resolve()
            if database_raw
            else default_database.resolve()
        )

        origins_raw = _environment("REMANENCE_ALLOWED_ORIGINS")
        origins = (
            tuple(item.strip().rstrip("/") for item in origins_raw.split(",") if item.strip())
            if origins_raw
            else DEFAULT_ALLOWED_ORIGINS
        )
        if not origins or any(not _is_loopback_origin(origin) for origin in origins):
            raise ValueError("REMANENCE_ALLOWED_ORIGINS may contain only loopback HTTP(S) origins")

        hosts_raw = _environment("REMANENCE_ALLOWED_HOSTS")
        hosts = (
            tuple(item.strip() for item in hosts_raw.split(",") if item.strip())
            if hosts_raw
            else DEFAULT_ALLOWED_HOSTS
        )
        if not hosts:
            raise ValueError("REMANENCE_ALLOWED_HOSTS cannot be empty")

        return cls(
            data_dir=data_dir,
            database_path=database_path,
            jobs_dir=(data_dir / "jobs").resolve(),
            temp_dir=(data_dir / "tmp").resolve(),
            max_upload_bytes=_positive_int("REMANENCE_MAX_UPLOAD_BYTES", 100 * MEBIBYTE),
            max_workers=_positive_int("REMANENCE_MAX_WORKERS", 2),
            max_artifacts=_positive_int("REMANENCE_MAX_ARTIFACTS", 500),
            max_report_bytes=_positive_int("REMANENCE_MAX_REPORT_BYTES", 25 * MEBIBYTE),
            event_poll_seconds=_positive_float("REMANENCE_EVENT_POLL_SECONDS", 0.35),
            rate_limit_per_minute=_positive_int("REMANENCE_RATE_LIMIT", 300),
            upload_limit_per_minute=_positive_int("REMANENCE_UPLOAD_RATE_LIMIT", 12),
            allowed_origins=origins,
            allowed_hosts=hosts,
        )

    def ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)


settings = Settings.from_env()
