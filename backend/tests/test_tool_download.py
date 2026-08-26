from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from app import main
from app.config import Settings
from app.schemas import ToolDownloadRequest


def make_settings(root: Path) -> Settings:
    data_dir = root / "data"
    return Settings(
        data_dir=data_dir,
        database_path=data_dir / "forenscope.sqlite3",
        jobs_dir=data_dir / "jobs",
        temp_dir=data_dir / "tmp",
    )


def test_tool_download_request_is_strict_and_deduplicated() -> None:
    request = ToolDownloadRequest.model_validate({"tool_ids": [" ZSTEG ", "zsteg"], "confirmed": True})
    assert request.tool_ids == ["zsteg"]

    with pytest.raises(ValidationError):
        ToolDownloadRequest.model_validate({"tool_ids": ["zsteg"], "confirmed": "yes"})


def test_tool_download_bundles_allowlisted_installer(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    settings = make_settings(tmp_path)

    def fake_which(executable: str) -> str | None:
        return "C:\\Windows\\System32\\winget.exe" if executable == "winget" else None

    def fake_download(_executable: str, _package_id: str, target: Path) -> dict[str, object]:
        (target / "ExifTool-installer.msixbundle").write_bytes(b"installer")
        return {"status": "completed", "return_code": 0, "output": "ok", "duration_ms": 1}

    monkeypatch.setattr(main.shutil, "which", fake_which)
    monkeypatch.setattr(main, "_run_winget_download", fake_download)

    report = main._download_tool_installers(settings, ["exiftool", "zsteg"])

    assert report["status"] == "partial"
    assert report["downloaded_count"] == 1
    assert report["items"][0]["status"] == "downloaded"
    assert report["items"][1]["status"] == "manual"
    bundle_url = report["bundle_url"]
    assert isinstance(bundle_url, str)
    bundle_name = bundle_url.rsplit("/", 1)[-1] + ".zip"
    bundle_path = settings.data_dir / "tool-downloads" / bundle_name
    assert bundle_path.is_file()
    assert not list((settings.data_dir / "tool-downloads").glob("batch-*"))
