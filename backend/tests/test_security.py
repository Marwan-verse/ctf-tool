from __future__ import annotations

from pathlib import Path

import pytest

from app.config import Settings
from app.security import (
    SlidingWindowLimiter,
    UnsafePathError,
    is_allowed_origin,
    normalize_display_filename,
    require_regular_file,
    resolve_under,
    safe_content_disposition,
    validate_short_text,
)


@pytest.mark.parametrize("relative", ("../escape", "nested/../../escape", "/absolute/path"))
def test_resolve_under_rejects_path_escape(tmp_path: Path, relative: str) -> None:
    root = tmp_path / "root"
    root.mkdir()

    with pytest.raises(UnsafePathError):
        resolve_under(root, relative)


def test_require_regular_file_rejects_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    link = root / "link.txt"
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    with pytest.raises(UnsafePathError):
        require_regular_file(root, "link.txt")


def test_upload_filename_is_display_only_and_header_safe() -> None:
    hostile = "../../bad\r\nX-Evil: yes/\u202eflag.png"

    normalized = normalize_display_filename(hostile)
    disposition = safe_content_disposition(hostile)

    assert normalized == "_flag.png"
    assert "\r" not in disposition and "\n" not in disposition
    assert "X-Evil" not in normalized
    assert "../" not in disposition and "..\\" not in disposition


def test_short_text_rejects_controls_and_oversize_values() -> None:
    with pytest.raises(ValueError, match="control"):
        validate_short_text("flag\nvalue", field="flag_prefix", maximum=64)
    with pytest.raises(ValueError, match="too long"):
        validate_short_text("x" * 65, field="flag_prefix", maximum=64)


def test_only_loopback_origins_are_accepted(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert is_allowed_origin("http://localhost:3000", ("http://localhost:3000",))
    assert is_allowed_origin("http://127.0.0.1:9999", ())
    assert not is_allowed_origin("https://attacker.example", ("http://localhost:3000",))

    monkeypatch.setenv("FORENSCOPE_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("FORENSCOPE_ALLOWED_ORIGINS", "https://attacker.example")
    with pytest.raises(ValueError, match="loopback"):
        Settings.from_env()


def test_sliding_window_limiter_enforces_bucket_limit() -> None:
    limiter = SlidingWindowLimiter(window_seconds=60)

    assert limiter.check(("local", "upload"), 2) == (True, 0)
    assert limiter.check(("local", "upload"), 2) == (True, 0)
    allowed, retry_after = limiter.check(("local", "upload"), 2)
    assert allowed is False
    assert retry_after >= 1
