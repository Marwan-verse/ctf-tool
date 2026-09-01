from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


def test_summary_job_listing_omits_heavy_report_and_artifacts(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path / "data",
        database_path=tmp_path / "data" / "forenscope.sqlite3",
        jobs_dir=tmp_path / "data" / "jobs",
        temp_dir=tmp_path / "data" / "tmp",
    )
    application = create_app(settings)
    with TestClient(application) as client:
        storage = application.state.storage
        storage.create_job(
            {
                "id": "job-summary",
                "profile": "quick",
                "original_filename": "evidence.bin",
                "content_type": "application/octet-stream",
                "size_bytes": 4,
                "sha256": "a" * 64,
                "options": {"external_tools": False},
                "input_relative_path": "input/source.bin",
                "output_relative_path": "output",
            }
        )
        storage.upsert_artifact(
            {
                "id": "artifact-summary",
                "job_id": "job-summary",
                "name": "source.bin",
                "kind": "original",
                "relative_path": "input/source.bin",
                "size_bytes": 4,
                "sha256": "a" * 64,
            }
        )
        storage.finish_job("job-summary", status="completed", result={"large": ["value"] * 100})

        full = client.get("/api/jobs", params={"limit": 5, "detail": "full"})
        summary = client.get("/api/jobs", params={"limit": 5, "detail": "summary"})

    assert full.status_code == 200
    assert full.json()["items"][0]["result"]["large"]
    assert len(full.json()["items"][0]["artifacts"]) == 1
    assert summary.status_code == 200
    assert summary.json()["items"][0]["result"] is None
    assert summary.json()["items"][0]["artifacts"] == []

