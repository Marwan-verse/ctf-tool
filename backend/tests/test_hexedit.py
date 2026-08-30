from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.hexedit import apply_edits, diagnose_bytes, normalize_edits, read_repair_candidate, write_edited_copy
from app.main import create_app
from app.reporting import input_artifact_record
from app.config import Settings
from app.storage import Storage

from conftest import patterned_pixels, rgb_png


def tiny_png() -> bytes:
    return rgb_png(4, 4, patterned_pixels(4, 4))


def test_sparse_edit_stream_is_exact_and_does_not_touch_source(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    destination = tmp_path / "edited.bin"
    original = bytes(range(256)) * 2
    source.write_bytes(original)
    result = write_edited_copy(source, destination, [{"offset": 0, "value": 0xFF}, {"offset": 255, "value": 0xEE}, {"offset": 256, "value": 0xDD}])
    expected = bytearray(original)
    expected[0] = 0xFF
    expected[255] = 0xEE
    expected[256] = 0xDD
    assert destination.read_bytes() == bytes(expected)
    assert source.read_bytes() == original
    assert result["sha256"] == hashlib.sha256(bytes(expected)).hexdigest()
    assert result["changed_count"] == 3


def test_edit_validation_rejects_duplicates_and_out_of_range(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        normalize_edits([{"offset": 1, "value": 2}, {"offset": 1, "value": 3}], 8)
    with pytest.raises(ValueError):
        normalize_edits([{"offset": 8, "value": 2}], 8)
    assert apply_edits(b"abc", [{"offset": 1, "value": ord("Z")}]) == b"aZc"


def test_integrity_separates_png_crc_errors_from_heuristic_bytes() -> None:
    clean = tiny_png()
    assert diagnose_bytes(clean, filename="evidence.png")["verdict"] == "valid"
    broken = bytearray(clean)
    ihdr_crc_last_byte = 8 + 4 + 4 + 13 + 3
    broken[ihdr_crc_last_byte] ^= 0x01
    verdict = diagnose_bytes(bytes(broken), filename="evidence.png")
    assert verdict["verdict"] == "corrupt"
    assert any(item["kind"] == "png-crc" for item in verdict["issues"])
    noisy = clean + (b"\x00" * 140)
    assert diagnose_bytes(noisy, filename="evidence.png")["verdict"] in {"valid", "warning"}


def test_integrity_detects_tiff_and_ico_structure() -> None:
    # Minimal, bounded directory headers are enough to exercise format
    # detection and the parser-backed Hex integrity contract.
    tiff = b"II*\x00\x08\x00\x00\x00\x00\x00\x00\x00"
    ico = b"\x00\x00\x01\x00\x00\x00"
    tiff_result = diagnose_bytes(tiff, filename="evidence.tiff")
    ico_result = diagnose_bytes(ico, filename="evidence.ico")
    assert tiff_result["detected_format"] == "tiff"
    assert tiff_result["validation_format"] == "tiff"
    assert tiff_result["verdict"] == "valid"
    assert ico_result["detected_format"] == "ico"
    assert ico_result["validation_format"] == "ico"
    assert ico_result["verdict"] == "valid"


def _make_api_fixture(tmp_path: Path, source_bytes: bytes | None = None) -> tuple[TestClient, str, str, Path, bytes]:
    settings = Settings(
        data_dir=tmp_path / "data",
        database_path=tmp_path / "data" / "forenscope.sqlite3",
        jobs_dir=tmp_path / "data" / "jobs",
        temp_dir=tmp_path / "data" / "tmp",
        max_artifacts=20,
    )
    application = create_app(settings)
    client = TestClient(application)
    client.__enter__()
    storage = Storage(settings.database_path)
    storage.initialize()
    job_id = str(uuid4())
    job_dir = settings.jobs_dir / job_id
    source_path = job_dir / "input" / "source.upload"
    (job_dir / "output").mkdir(parents=True, exist_ok=True)
    source_path.parent.mkdir(parents=True, exist_ok=True)
    # The default fixture keeps a harmless trailing payload so a byte edit can
    # be rendered by Pillow while the integrity panel reports a review warning.
    original = source_bytes if source_bytes is not None else tiny_png() + b"CTF"
    source_path.write_bytes(original)
    source_sha = hashlib.sha256(original).hexdigest()
    storage.create_job(
        {
            "id": job_id,
            "profile": "quick",
            "original_filename": "evidence.png",
            "content_type": "image/png",
            "size_bytes": len(original),
            "sha256": source_sha,
            "input_relative_path": f"input/source.upload",
            "output_relative_path": "output",
        }
    )
    artifact = input_artifact_record(
        job_id=job_id,
        original_filename="evidence.png",
        relative_path="input/source.upload",
        content_type="image/png",
        size_bytes=len(original),
        sha256=source_sha,
        previewable=True,
    )
    storage.upsert_artifact(artifact)
    storage.finish_job(job_id, status="completed", result={"section": "image"})
    return client, job_id, artifact["id"], source_path, original


def test_hex_api_live_preview_and_save_preserve_original(tmp_path: Path) -> None:
    client, job_id, artifact_id, source_path, original = _make_api_fixture(tmp_path)
    try:
        body = {"artifact_id": artifact_id, "base_sha256": hashlib.sha256(original).hexdigest(), "revision": 4, "edits": [{"offset": len(original) - 1, "value": ord("!")}]}
        analysis = client.post(f"/api/jobs/{job_id}/hex/analyze", json=body)
        assert analysis.status_code == 200, analysis.text
        assert analysis.json()["revision"] == 4
        assert analysis.json()["integrity"]["verdict"] in {"valid", "warning", "corrupt"}
        preview = client.post(f"/api/jobs/{job_id}/hex/preview", json=body)
        assert preview.status_code == 200, preview.text
        assert preview.headers["content-type"].startswith("image/png")
        saved = client.post(f"/api/jobs/{job_id}/hex/save", json={**body, "name": "..\\edited.png"})
        assert saved.status_code == 200, saved.text
        derived = saved.json()["artifact"]
        assert derived["kind"] == "hex-edit"
        assert derived["parent_id"] == artifact_id
        assert derived["name"] == "edited.png"
        assert source_path.read_bytes() == original
        assert derived["sha256"] != hashlib.sha256(original).hexdigest()
    finally:
        client.__exit__(None, None, None)


def test_artifact_download_uses_recovered_content_extension(tmp_path: Path) -> None:
    client, job_id, _source_id, source_path, _original = _make_api_fixture(tmp_path)
    try:
        output = source_path.parents[1] / "output"
        recovered = output / "recovered-internal.bin"
        payload = tiny_png()
        recovered.write_bytes(payload)
        artifact_id = str(uuid4())
        client.app.state.storage.upsert_artifact({
            "id": artifact_id,
            "job_id": job_id,
            "parent_id": None,
            "name": "decoded-payload.txt",
            "kind": "derived",
            "relative_path": "output/recovered-internal.bin",
            "media_type": "application/octet-stream",
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "previewable": False,
            "metadata": {},
        })

        response = client.get(f"/api/jobs/{job_id}/artifacts/{artifact_id}/download")

        assert response.status_code == 200
        assert 'filename="decoded-payload.png"' in response.headers["content-disposition"]
        assert response.headers["content-type"].startswith("image/png")
        assert response.content == payload
    finally:
        client.__exit__(None, None, None)


def test_hex_api_rejects_stale_hash_and_duplicate_offsets(tmp_path: Path) -> None:
    client, job_id, artifact_id, _source_path, original = _make_api_fixture(tmp_path)
    try:
        stale = {"artifact_id": artifact_id, "base_sha256": "0" * 64, "edits": [{"offset": 1, "value": 2}]}
        assert client.post(f"/api/jobs/{job_id}/hex/analyze", json=stale).status_code == 409
        duplicate = {"artifact_id": artifact_id, "base_sha256": hashlib.sha256(original).hexdigest(), "edits": [{"offset": 1, "value": 2}, {"offset": 1, "value": 3}]}
        response = client.post(f"/api/jobs/{job_id}/hex/analyze", json=duplicate)
        assert response.status_code == 422
    finally:
        client.__exit__(None, None, None)


def test_missing_png_end_chunk_exposes_and_saves_copy_only_repair(tmp_path: Path) -> None:
    damaged = tiny_png()[:-12]
    client, job_id, artifact_id, source_path, original = _make_api_fixture(tmp_path, damaged)
    try:
        view = client.get(f"/api/jobs/{job_id}/hex", params={"artifact_id": artifact_id})
        assert view.status_code == 200, view.text
        candidates = view.json()["integrity"]["repair_candidates"]
        assert candidates
        candidate = next(item for item in candidates if item["format"] == "png")
        repaired_data, _ = read_repair_candidate(source_path, candidate["id"], filename="evidence.png", declared_media_type="image/png")
        assert diagnose_bytes(repaired_data, filename="evidence.png", include_repairs=False)["verdict"] == "valid"
        saved = client.post(
            f"/api/jobs/{job_id}/hex/repair",
            json={"artifact_id": artifact_id, "base_sha256": hashlib.sha256(original).hexdigest(), "candidate_id": candidate["id"]},
        )
        assert saved.status_code == 200, saved.text
        derived = saved.json()["artifact"]
        assert derived["kind"] == "repair"
        assert derived["parent_id"] == artifact_id
        assert source_path.read_bytes() == damaged
    finally:
        client.__exit__(None, None, None)


def test_corrupted_png_header_exposes_recovery_candidate_in_hex_lab(tmp_path: Path) -> None:
    damaged = bytearray(tiny_png())
    damaged[:8] = b"\x89PB\x11\r\n\x1a\n"
    damaged[8:12] = b"\x00\x12\x13\x14"
    client, job_id, artifact_id, source_path, original = _make_api_fixture(tmp_path, bytes(damaged))
    try:
        view = client.get(f"/api/jobs/{job_id}/hex", params={"artifact_id": artifact_id})
        assert view.status_code == 200, view.text
        candidates = view.json()["integrity"]["repair_candidates"]
        candidate = next(item for item in candidates if item["label"] == "png_header_recovered")
        repaired, details = read_repair_candidate(source_path, candidate["id"], filename="evidence.png", declared_media_type="image/png")
        assert repaired.startswith(b"\x89PNG\r\n\x1a\n")
        assert details["format"] == "png"
        assert source_path.read_bytes() == original
    finally:
        client.__exit__(None, None, None)
