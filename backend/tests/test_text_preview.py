from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from app.analyzers.formats import analyze_format
from app.config import Settings
from app.main import create_app
from app.reporting import input_artifact_record
from app.storage import Storage
from app.text_preview import TextPreviewUnavailableError, build_text_preview


def _docx_with_text(text: str) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types />")
        archive.writestr(
            "word/document.xml",
            f"<w:document xmlns:w='urn:test'><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>",
        )
    return buffer.getvalue()


def _docx_with_hidden_ctf_text() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types />")
        archive.writestr(
            "word/document.xml",
            "<w:document xmlns:w='urn:test'><w:body><w:p>"
            "<w:r><w:t>fl</w:t></w:r><w:r><w:t>ag{docx_split}</w:t></w:r>"
            "<w:del><w:r><w:delText>flag{docx_deleted}</w:delText></w:r></w:del>"
            "</w:p></w:body></w:document>",
        )
        archive.writestr("customXml/item1.xml", "<clue>flag{docx_custom_xml}</clue>")
    return buffer.getvalue()


def _text_preview_api_fixture(tmp_path: Path, source_bytes: bytes, name: str) -> tuple[TestClient, str, str]:
    settings = Settings(
        data_dir=tmp_path / "data",
        database_path=tmp_path / "data" / "forenscope.sqlite3",
        jobs_dir=tmp_path / "data" / "jobs",
        temp_dir=tmp_path / "data" / "tmp",
        max_artifacts=20,
    )
    client = TestClient(create_app(settings))
    client.__enter__()
    storage = Storage(settings.database_path)
    storage.initialize()
    job_id = str(uuid4())
    job_dir = settings.jobs_dir / job_id
    source_path = job_dir / "input" / "source.upload"
    source_path.parent.mkdir(parents=True, exist_ok=True)
    (job_dir / "output").mkdir(parents=True, exist_ok=True)
    source_path.write_bytes(source_bytes)
    digest = hashlib.sha256(source_bytes).hexdigest()
    storage.create_job({
        "id": job_id,
        "profile": "quick",
        "original_filename": name,
        "content_type": "text/plain",
        "size_bytes": len(source_bytes),
        "sha256": digest,
        "input_relative_path": "input/source.upload",
        "output_relative_path": "output",
    })
    artifact = input_artifact_record(
        job_id=job_id,
        original_filename=name,
        relative_path="input/source.upload",
        content_type="text/plain",
        size_bytes=len(source_bytes),
        sha256=digest,
        previewable=False,
    )
    storage.upsert_artifact(artifact)
    storage.finish_job(job_id, status="completed", result={"section": "image"})
    return client, job_id, str(artifact["id"])


def test_plain_text_parser_preserves_document_for_ctf_scanning() -> None:
    report = analyze_format("text", b"title: a challenge\nencoded: flag{plain_text_document}\n")

    assert report["properties"]["encoding"] == "utf-8"
    assert report["properties"]["line_count"] == 3
    assert report["text_records"][0]["text"] == "title: a challenge\nencoded: flag{plain_text_document}\n"


def test_document_preview_extracts_ooxml_text_without_rendering(tmp_path: Path) -> None:
    path = tmp_path / "source.upload"
    path.write_bytes(_docx_with_text("picoCTF{docx_preview_fixture}"))

    preview = build_text_preview(path, filename="challenge.docx")

    assert preview["kind"] == "docx"
    assert preview["encoding"] == "extracted document package text"
    assert "picoCTF{docx_preview_fixture}" in preview["text"]
    assert preview["sources"] == ["word/document.xml"]


def test_macro_ooxml_and_xps_packages_get_plain_text_previews(tmp_path: Path) -> None:
    macro_path = tmp_path / "challenge.docm"
    macro_path.write_bytes(_docx_with_text("flag{macro_document_preview}"))
    macro_preview = build_text_preview(macro_path, filename=macro_path.name)
    assert macro_preview["kind"] == "docx"
    assert "flag{macro_document_preview}" in macro_preview["text"]

    xps_path = tmp_path / "challenge.xps"
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "Documents/1/Pages/1.fpage",
            '<FixedPage xmlns="http://schemas.microsoft.com/xps/2005/06"><Glyphs UnicodeString="flag{xps_preview}" /></FixedPage>',
        )
    xps_path.write_bytes(payload.getvalue())
    xps_preview = build_text_preview(xps_path, filename=xps_path.name)
    assert xps_preview["kind"] == "xps"
    assert "flag{xps_preview}" in xps_preview["text"]


def test_document_solver_recovers_split_deleted_and_custom_ooxml_text() -> None:
    report = analyze_format("docx", _docx_with_hidden_ctf_text())
    recovered = "\n".join(str(record["text"]) for record in report["text_records"])

    assert "flag{docx_split}" in recovered
    assert "flag{docx_deleted}" in recovered
    assert "flag{docx_custom_xml}" in recovered
    assert any(finding["title"] == "Tracked-deletion text recovered" for finding in report["findings"])


def test_document_solver_decodes_text_json_rtf_and_pdf_hiding_patterns() -> None:
    text_report = analyze_format("text", b'{"clue":"\\\\u0066lag{json_escape}"}')
    rtf_report = analyze_format("rtf", br"{\rtf1 ordinary {\v flag\{rtf_hidden\}}}")
    pdf_report = analyze_format("pdf", b"%PDF-1.4\nBT\n(fl) Tj\n(ag{pdf_split}) Tj\nET\n%%EOF\n")

    assert any("flag{json_escape}" in str(record["text"]) for record in text_report["text_records"])
    assert any(record["source"] == "rtf-hidden-text" and "flag{rtf_hidden}" in str(record["text"]) for record in rtf_report["text_records"])
    assert any(record["source"] == "PDF page text sequence" and "flag{pdf_split}" in str(record["text"]) for record in pdf_report["text_records"])


def test_document_preview_reads_package_text_beyond_source_preview_cap(tmp_path: Path) -> None:
    path = tmp_path / "source.upload"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types />")
        archive.writestr(
            "word/document.xml",
            "<w:document xmlns:w='urn:test'><w:body><w:p><w:r><w:t>flag{large_preview}</w:t></w:r></w:p></w:body></w:document>",
        )
        archive.writestr("word/media/filler.bin", b"x" * (2 * 1024 * 1024 + 64))

    preview = build_text_preview(path, filename="challenge.docx")

    assert "flag{large_preview}" in preview["text"]
    assert not preview["truncated"]


def test_document_preview_rejects_binary_data_even_with_a_text_extension(tmp_path: Path) -> None:
    path = tmp_path / "source.upload"
    path.write_bytes(b"\x00\xff\x01\x02" * 64)

    try:
        build_text_preview(path, filename="misleading.txt")
    except TextPreviewUnavailableError as exc:
        assert "safely readable text" in str(exc)
    else:
        raise AssertionError("binary data should not be decoded as a text preview")


def test_text_preview_endpoint_returns_plain_text_json(tmp_path: Path) -> None:
    client, job_id, artifact_id = _text_preview_api_fixture(
        tmp_path,
        b"line one\nflag{endpoint_text_preview}\n",
        "challenge.txt",
    )
    try:
        response = client.get(f"/api/jobs/{job_id}/artifacts/{artifact_id}/text-preview")

        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["artifact_id"] == artifact_id
        assert payload["kind"] == "text"
        assert payload["text"] == "line one\nflag{endpoint_text_preview}\n"
        assert response.headers["content-type"].startswith("application/json")
    finally:
        client.__exit__(None, None, None)
