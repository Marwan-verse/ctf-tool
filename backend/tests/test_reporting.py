from __future__ import annotations

import json
import zipfile
from pathlib import Path

from app.reporting import artifact_download_details, artifact_download_filename, normalize_report, render_html_report, report_csp, sniff_media_type, write_report_zip


def test_normalized_report_redacts_passwords_and_private_paths(tmp_path: Path) -> None:
    job_dir = tmp_path / "private-job"
    output = job_dir / "output"
    output.mkdir(parents=True)
    raw = {
        "provided_password": "do-not-export",
        "nested": {"input_password": "also-secret", "path": output / "artifact.bin"},
    }

    report = normalize_report(raw, job_dir=job_dir, max_bytes=64 * 1024)
    rendered = json.dumps(report)

    assert "do-not-export" not in rendered
    assert "also-secret" not in rendered
    assert str(tmp_path) not in rendered
    assert report["provided_password"] == "<redacted>"
    assert report["nested"]["path"] == "output/artifact.bin"


def test_report_size_limit_produces_valid_bounded_json(tmp_path: Path) -> None:
    report = normalize_report(
        {"logs": ["X" * 50_000 for _ in range(100)]},
        job_dir=tmp_path,
        max_bytes=2_048,
    )
    encoded = json.dumps(report, separators=(",", ":")).encode()

    assert len(encoded) <= 2_048
    assert report["partial"] is True
    assert report["report_truncated"] is True


def test_html_report_escapes_untrusted_values_and_has_hash_only_style_csp() -> None:
    payload = {
        "exported_at": "2026-08-25T12:00:00Z",
        "job": {
            "id": "job-1",
            "status": "completed",
            "profile": "quick",
            "original_filename": "</title><script>alert(1)</script>.png",
            "sha256": "a" * 64,
        },
        "result": {"candidates": [{"value": "flag{<img src=x onerror=alert(1)>}", "confidence": "high"}]},
        "artifacts": [],
    }

    document = render_html_report(payload)
    csp = report_csp()

    assert "<script>alert(1)</script>" not in document
    assert "<img src=x" not in document
    assert "&lt;script&gt;" in document
    assert "style-src 'sha256-" in csp
    assert "'unsafe-inline'" not in csp


def test_bmp_artifacts_are_safe_inline_previews(tmp_path: Path) -> None:
    carved = tmp_path / "carved.bmp"
    carved.write_bytes(b"BM" + b"\0" * 14)

    assert sniff_media_type(carved) == ("image/bmp", True)


def test_wav_artifacts_are_verified_safe_inline_audio(tmp_path: Path) -> None:
    recovered = tmp_path / "recovered.wav"
    recovered.write_bytes(b"RIFF" + (4).to_bytes(4, "little") + b"WAVE")

    assert sniff_media_type(recovered) == ("audio/wav", True)


def test_recovered_download_names_follow_content_signatures(tmp_path: Path) -> None:
    png = tmp_path / "internal-artifact.bin"
    png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    pcap = tmp_path / "internal-capture.bin"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    wav = tmp_path / "internal-audio.bin"
    wav.write_bytes(b"RIFF\x04\x00\x00\x00WAVE")

    assert artifact_download_filename(png, "corrupted-photo.dat") == "corrupted-photo.png"
    assert artifact_download_filename(pcap, "packet-recovery.txt") == "packet-recovery.pcap"
    assert artifact_download_filename(wav, "channel-export.raw") == "channel-export.wav"
    assert artifact_download_details(png, "corrupted-photo.dat") == ("corrupted-photo.png", "image/png")
    assert artifact_download_details(pcap, "packet-recovery.txt") == ("packet-recovery.pcap", "application/vnd.tcpdump.pcap")
    assert artifact_download_details(wav, "channel-export.raw") == ("channel-export.wav", "audio/wav")


def test_zip_export_uses_generated_paths_and_skips_escape(tmp_path: Path) -> None:
    job_dir = tmp_path / "job"
    output = job_dir / "output"
    output.mkdir(parents=True)
    source = output / "payload.bin"
    source.write_bytes(b"flag{zip_manifest}")
    outside = tmp_path / "outside.txt"
    outside.write_text("must not be exported", encoding="utf-8")
    artifacts = [
        {
            "id": "safe-id",
            "job_id": "job-1",
            "relative_path": "output/payload.bin",
            "name": "../../hostile.bin",
            "kind": "extracted",
            "size_bytes": source.stat().st_size,
            "sha256": "b" * 64,
        },
        {
            "id": "escape-id",
            "job_id": "job-1",
            "relative_path": "../outside.txt",
            "name": "outside.txt",
        },
    ]
    payload = {"job": {"id": "job-1", "sha256": "a" * 64}, "result": {}, "artifacts": []}
    target = tmp_path / "case.zip"

    write_report_zip(target, payload=payload, artifacts=artifacts, job_dir=job_dir)

    with zipfile.ZipFile(target) as archive:
        names = archive.namelist()
        manifest = json.loads(archive.read("manifest.json"))
    assert names[:2] == ["report.json", "report.html"]
    assert "artifacts/safe-id/hostile.txt" in names
    assert all(".." not in name and not name.startswith("/") for name in names)
    assert [item["id"] for item in manifest["artifacts"]] == ["safe-id"]
