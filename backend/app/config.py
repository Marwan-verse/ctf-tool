"""Runtime configuration for the local Forenscope control plane."""

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


def _positive_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.getenv(name)
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
    raw = os.getenv(name)
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
        data_dir = Path(os.getenv("FORENSCOPE_DATA_DIR", str(backend_dir / "data"))).expanduser().resolve()
        database_raw = os.getenv("FORENSCOPE_DB_PATH")
        database_path = (
            Path(database_raw).expanduser().resolve()
            if database_raw
            else (data_dir / "forenscope.sqlite3").resolve()
        )

        origins_raw = os.getenv("FORENSCOPE_ALLOWED_ORIGINS")
        origins = (
            tuple(item.strip().rstrip("/") for item in origins_raw.split(",") if item.strip())
            if origins_raw
            else DEFAULT_ALLOWED_ORIGINS
        )
        if not origins or any(not _is_loopback_origin(origin) for origin in origins):
            raise ValueError("FORENSCOPE_ALLOWED_ORIGINS may contain only loopback HTTP(S) origins")

        hosts_raw = os.getenv("FORENSCOPE_ALLOWED_HOSTS")
        hosts = (
            tuple(item.strip() for item in hosts_raw.split(",") if item.strip())
            if hosts_raw
            else DEFAULT_ALLOWED_HOSTS
        )
        if not hosts:
            raise ValueError("FORENSCOPE_ALLOWED_HOSTS cannot be empty")

        return cls(
            data_dir=data_dir,
            database_path=database_path,
            jobs_dir=(data_dir / "jobs").resolve(),
            temp_dir=(data_dir / "tmp").resolve(),
            max_upload_bytes=_positive_int("FORENSCOPE_MAX_UPLOAD_BYTES", 100 * MEBIBYTE),
            max_workers=_positive_int("FORENSCOPE_MAX_WORKERS", 2),
            max_artifacts=_positive_int("FORENSCOPE_MAX_ARTIFACTS", 500),
            max_report_bytes=_positive_int("FORENSCOPE_MAX_REPORT_BYTES", 25 * MEBIBYTE),
            event_poll_seconds=_positive_float("FORENSCOPE_EVENT_POLL_SECONDS", 0.35),
            rate_limit_per_minute=_positive_int("FORENSCOPE_RATE_LIMIT", 300),
            upload_limit_per_minute=_positive_int("FORENSCOPE_UPLOAD_RATE_LIMIT", 12),
            allowed_origins=origins,
            allowed_hosts=hosts,
        )

    def ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)


settings = Settings.from_env()
