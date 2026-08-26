"""Small, dependency-light security primitives for the local API."""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]+")
_SAFE_FILENAME_CHARACTERS = re.compile(r"[^A-Za-z0-9._ -]+")


class UnsafePathError(ValueError):
    """Raised when a path would escape its configured evidence directory."""


def resolve_under(root: Path, *parts: str | Path, must_exist: bool = False) -> Path:
    """Resolve *parts* below *root*, rejecting traversal and symlink escapes."""

    resolved_root = root.resolve(strict=True) if root.exists() else root.resolve(strict=False)
    candidate = resolved_root.joinpath(*parts).resolve(strict=must_exist)
    if candidate == resolved_root or resolved_root not in candidate.parents:
        raise UnsafePathError("Path is outside the configured evidence directory")
    return candidate


def require_regular_file(root: Path, relative_path: str) -> Path:
    """Return a contained, existing, non-symlink regular file."""

    raw = root.joinpath(relative_path)
    if raw.is_symlink():
        raise UnsafePathError("Symbolic-link artifacts are not served")
    candidate = resolve_under(root, relative_path, must_exist=True)
    if not candidate.is_file():
        raise UnsafePathError("Artifact is not a regular file")
    return candidate


def normalize_display_filename(filename: str | None, *, fallback: str = "upload.bin") -> str:
    """Make an untrusted upload name safe for display and response headers.

    The returned name is never used as a storage path.
    """

    if not filename:
        return fallback
    leaf = filename.replace("\\", "/").rsplit("/", 1)[-1]
    leaf = _CONTROL_CHARACTERS.sub("", leaf).strip(" .")
    leaf = _SAFE_FILENAME_CHARACTERS.sub("_", leaf)
    return (leaf[:180] or fallback).strip(" .") or fallback


def safe_content_disposition(filename: str, *, inline: bool = False) -> str:
    cleaned = normalize_display_filename(filename, fallback="artifact.bin")
    ascii_name = cleaned.encode("ascii", "ignore").decode("ascii") or "artifact.bin"
    ascii_name = ascii_name.replace('"', "_").replace("\\", "_")
    disposition = "inline" if inline else "attachment"
    return f"{disposition}; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(cleaned)}"


def validate_short_text(value: str | None, *, field: str, maximum: int) -> str | None:
    if value is None:
        return None
    if len(value) > maximum:
        raise ValueError(f"{field} is too long (maximum {maximum} characters)")
    if _CONTROL_CHARACTERS.search(value):
        raise ValueError(f"{field} contains control characters")
    stripped = value.strip()
    return stripped or None


def is_allowed_origin(origin: str, allowed_origins: Sequence[str]) -> bool:
    normalized = origin.rstrip("/")
    if normalized in allowed_origins:
        return True
    parsed = urlsplit(normalized)
    return parsed.scheme in {"http", "https"} and parsed.hostname in {
        "localhost",
        "127.0.0.1",
        "::1",
    }


class SlidingWindowLimiter:
    """Thread-safe in-memory limiter suitable for a single local process."""

    def __init__(self, window_seconds: float = 60.0) -> None:
        self.window_seconds = window_seconds
        self._entries: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._checks = 0

    def check(self, key: tuple[str, str], limit: int) -> tuple[bool, int]:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            entries = self._entries[key]
            while entries and entries[0] <= cutoff:
                entries.popleft()
            if len(entries) >= limit:
                retry_after = max(1, int(self.window_seconds - (now - entries[0])) + 1)
                return False, retry_after
            entries.append(now)
            self._checks += 1
            if self._checks % 500 == 0:
                stale = [entry_key for entry_key, values in self._entries.items() if not values or values[-1] <= cutoff]
                for entry_key in stale:
                    self._entries.pop(entry_key, None)
            return True, 0


class RateLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        default_limit: int,
        upload_limit: int,
        window_seconds: float = 60.0,
    ) -> None:
        self.app = app
        self.default_limit = default_limit
        self.upload_limit = upload_limit
        self.limiter = SlidingWindowLimiter(window_seconds)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = str(scope.get("path", ""))
        method = str(scope.get("method", "GET")).upper()
        bucket = "upload" if method == "POST" and path.rstrip("/") == "/api/jobs" else "api"
        limit = self.upload_limit if bucket == "upload" else self.default_limit
        client = scope.get("client")
        client_ip = str(client[0]) if client else "local"
        allowed, retry_after = self.limiter.check((client_ip, bucket), limit)
        if not allowed:
            response = JSONResponse(
                {"detail": {"code": "rate_limited", "message": "Too many requests; try again shortly."}},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


class OriginValidationMiddleware:
    """Reject browser requests from non-loopback origins, including simple ones."""

    def __init__(self, app: ASGIApp, *, allowed_origins: Sequence[str]) -> None:
        self.app = app
        self.allowed_origins = tuple(origin.rstrip("/") for origin in allowed_origins)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            headers = Headers(scope=scope)
            origin = headers.get("origin")
            if origin and not is_allowed_origin(origin, self.allowed_origins):
                response = JSONResponse(
                    {"detail": {"code": "origin_denied", "message": "This API accepts only local UI origins."}},
                    status_code=403,
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


class SecurityHeadersMiddleware:
    """Attach conservative headers to API, downloads, and streamed responses."""

    _HEADERS = {
        "Content-Security-Policy": "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'",
        "Cross-Origin-Resource-Policy": "same-site",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Cache-Control": "no-store",
    }

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in self._HEADERS.items():
                    if name.lower() not in headers:
                        headers[name] = value
            await send(message)

        await self.app(scope, receive, send_with_headers)


ASGIHandler = Callable[[Scope, Receive, Send], Awaitable[Any]]
