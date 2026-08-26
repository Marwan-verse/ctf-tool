from __future__ import annotations

from pathlib import Path

from app.storage import Storage


def new_job(job_id: str = "job-1") -> dict[str, object]:
    return {
        "id": job_id,
        "profile": "quick",
        "original_filename": "evidence.png",
        "content_type": "image/png",
        "size_bytes": 123,
        "sha256": "a" * 64,
        "flag_prefix": None,
        "options": {"ocr": False, "max_artifacts": 45},
        "input_relative_path": f"jobs/{job_id}/input/source.png",
        "output_relative_path": f"jobs/{job_id}/output",
    }


def test_job_state_progress_and_cancellation_are_persistent(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "forenscope.sqlite3")
    storage.initialize()
    storage.create_job(new_job())

    assert storage.get_job("job-1")["options"] == {"ocr": False, "max_artifacts": 45}

    assert storage.begin_job("job-1")["status"] == "running"
    storage.update_progress("job-1", progress=0.6, stage="Parsing")
    storage.update_progress("job-1", progress=0.2, stage="Older callback")
    assert storage.get_job("job-1")["progress"] == 0.6

    first = storage.request_cancel("job-1")
    second = storage.request_cancel("job-1")
    assert first["status"] == second["status"] == "cancelling"
    assert first["cancel_requested"] is True
    assert len([event for event in storage.list_events("job-1") if event["type"] == "cancel_requested"]) == 1

    terminal = storage.finish_job("job-1", status="cancelled", result={"partial": True})
    assert terminal["status"] == "cancelled"
    assert storage.finish_job("job-1", status="completed", result={})["status"] == "cancelled"


def test_interrupted_jobs_are_recovered_as_failed(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "forenscope.sqlite3")
    storage.initialize()
    storage.create_job(new_job("queued"))
    storage.create_job(new_job("running"))
    storage.begin_job("running")

    assert set(storage.recover_interrupted_jobs()) == {"queued", "running"}
    for job_id in ("queued", "running"):
        job = storage.get_job(job_id)
        assert job["status"] == "failed"
        assert job["error_code"] == "server_restarted"
        assert job["result"]["partial"] is True
