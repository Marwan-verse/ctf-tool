from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.reporting import input_artifact_record
from app.storage import Storage


def _capture_api(tmp_path: Path, *, name: str = "evidence.pcap", payload: bytes | None = None) -> tuple[TestClient, str, str, Settings, Storage]:
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
    source = payload if payload is not None else b"\xd4\xc3\xb2\xa1" + b"\0" * 20
    source_path = settings.jobs_dir / job_id / "input" / "source.upload"
    source_path.parent.mkdir(parents=True, exist_ok=True)
    (settings.jobs_dir / job_id / "output").mkdir(parents=True, exist_ok=True)
    source_path.write_bytes(source)
    digest = hashlib.sha256(source).hexdigest()
    storage.create_job({
        "id": job_id,
        "profile": "quick",
        "original_filename": name,
        "content_type": "application/vnd.tcpdump.pcap",
        "size_bytes": len(source),
        "sha256": digest,
        "input_relative_path": "input/source.upload",
        "output_relative_path": "output",
    })
    artifact = input_artifact_record(
        job_id=job_id,
        original_filename=name,
        relative_path="input/source.upload",
        content_type="application/vnd.tcpdump.pcap",
        size_bytes=len(source),
        sha256=digest,
        previewable=False,
    )
    storage.upsert_artifact(artifact)
    storage.finish_job(job_id, status="completed", result={"section": "network"})
    return client, job_id, artifact["id"], settings, storage


def test_traffic_query_resolves_capture_server_side(monkeypatch, tmp_path: Path) -> None:
    client, job_id, artifact_id, _settings, _storage = _capture_api(tmp_path)
    called: dict[str, object] = {}

    def fake_workbench(path: Path, **kwargs):
        called.update({"path": path, **kwargs})
        return {"action": "packets", "packet_rows": [{"number": "1", "protocol": "TCP"}], "packet_count": 1}

    monkeypatch.setattr("app.main.run_tshark_workbench", fake_workbench)
    try:
        response = client.post(
            f"/api/jobs/{job_id}/traffic/query",
            json={"action": "packets", "artifact_id": artifact_id, "display_filter": 'tcp.port == 443 && http.host contains "ctf"', "packet_limit": 50},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["read_only"] is True
        assert body["artifact"]["id"] == artifact_id
        assert body["packet_rows"][0]["protocol"] == "TCP"
        assert Path(str(called["path"])).name == "source.upload"
        assert called["display_filter"] == 'tcp.port == 443 && http.host contains "ctf"'
    finally:
        client.__exit__(None, None, None)


def test_traffic_query_rejects_non_capture_and_control_characters(tmp_path: Path) -> None:
    client, job_id, artifact_id, _settings, _storage = _capture_api(tmp_path, name="notes.txt", payload=b"not a capture")
    try:
        non_capture = client.post(f"/api/jobs/{job_id}/traffic/query", json={"artifact_id": artifact_id})
        assert non_capture.status_code == 415
        invalid_filter = client.post(
            f"/api/jobs/{job_id}/traffic/query",
            json={"artifact_id": artifact_id, "display_filter": "tcp\n-z credentials"},
        )
        assert invalid_filter.status_code == 422
    finally:
        client.__exit__(None, None, None)


def test_traffic_query_accepts_only_server_resolved_tls_keylog(monkeypatch, tmp_path: Path) -> None:
    client, job_id, artifact_id, settings, storage = _capture_api(tmp_path)
    keylog = b"CLIENT_RANDOM " + b"a" * 64 + b" " + b"b" * 96 + b"\n"
    keylog_path = settings.jobs_dir / job_id / "output" / "tls.keys"
    keylog_path.write_bytes(keylog)
    keylog_id = str(uuid4())
    storage.upsert_artifact({
        "id": keylog_id,
        "job_id": job_id,
        "parent_id": artifact_id,
        "name": "tls.keys",
        "kind": "text",
        "relative_path": "output/tls.keys",
        "media_type": "text/plain",
        "size_bytes": len(keylog),
        "sha256": hashlib.sha256(keylog).hexdigest(),
        "previewable": False,
        "metadata": {"producer": "test"},
    })
    called: dict[str, object] = {}

    def fake_workbench(path: Path, **kwargs):
        called.update({"path": path, **kwargs})
        return {"action": "statistics", "statistic": "protocol_hierarchy", "output": "ok"}

    monkeypatch.setattr("app.main.run_tshark_workbench", fake_workbench)
    try:
        response = client.post(
            f"/api/jobs/{job_id}/traffic/query",
            json={"artifact_id": artifact_id, "keylog_artifact_id": keylog_id, "action": "statistics"},
        )
        assert response.status_code == 200, response.text
        assert called["keylog_path"] == keylog_path

        keylog_path.write_bytes(b"not a key log\n")
        rejected = client.post(
            f"/api/jobs/{job_id}/traffic/query",
            json={"artifact_id": artifact_id, "keylog_artifact_id": keylog_id, "action": "statistics"},
        )
        assert rejected.status_code == 415
    finally:
        client.__exit__(None, None, None)
