from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path

from app.analyzers.archive import carve_zip_local_header_extras, trim_zip_archive
from app.engine import AnalysisEngine


def _zip_bytes(name: str, payload: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(name, payload)
    return buffer.getvalue()


def _outer_with_local_extra(embedded: bytes) -> bytes:
    """Build a valid ZIP with an opaque embedded ZIP in local extra bytes.

    ``zipfile`` normally mirrors ``ZipInfo.extra`` into both local and central
    headers.  This fixture deliberately patches only the local header and then
    adjusts the EOCD central-directory offset, matching the CTF construction.
    """

    base = bytearray(_zip_bytes("carrier.txt", b"carrier bytes"))
    assert base[:4] == b"PK\x03\x04"
    name_length = struct.unpack_from("<H", base, 26)[0]
    assert struct.unpack_from("<H", base, 28)[0] == 0
    data_start = 30 + name_length
    extra = b"\x20\xa2\x04\x00" + embedded + b"\x00\x00"
    struct.pack_into("<H", base, 28, len(extra))
    patched = base[:data_start] + extra + base[data_start:]
    eocd = patched.rfind(b"PK\x05\x06")
    assert eocd >= 0
    central_offset = struct.unpack_from("<L", patched, eocd + 16)[0]
    struct.pack_into("<L", patched, eocd + 16, central_offset + len(extra))
    candidate = bytes(patched)
    with zipfile.ZipFile(io.BytesIO(candidate)) as archive:
        assert archive.namelist() == ["carrier.txt"]
        assert archive.read("carrier.txt") == b"carrier bytes"
        assert archive.infolist()[0].extra == b""
    return candidate


def test_trim_zip_archive_stops_at_embedded_eocd() -> None:
    embedded = _zip_bytes("flag.txt", b"flag{trimmed_zip}")
    trimmed = trim_zip_archive(embedded + b"outer trailing bytes", max_size=1024 * 1024)
    assert trimmed is not None
    payload, details = trimmed
    assert payload == embedded
    assert details["entry_count"] == 1


def test_carve_local_header_extra_when_central_extra_is_empty() -> None:
    embedded = _zip_bytes("flag.txt", b"ICC{local_extra_fixture}")
    outer = _outer_with_local_extra(embedded)
    recovered = carve_zip_local_header_extras(outer, max_archive_size=1024 * 1024)
    assert len(recovered) == 1
    assert recovered[0]["data"] == embedded
    assert recovered[0]["offset"] == 30 + len("carrier.txt") + 4
    assert recovered[0]["outer_member"] == "carrier.txt"


def test_engine_extracts_local_extra_zip_and_flag(tmp_path: Path) -> None:
    embedded = _zip_bytes("[Content_Types].xml", b"<flag>ICC{engine_local_extra}</flag>")
    source = tmp_path / "challenge.docx"
    outer = _outer_with_local_extra(embedded)
    source.write_bytes(outer)
    report = AnalysisEngine().run(
        input_path=source,
        output_dir=tmp_path / "output",
        profile="quick",
        flag_prefix=None,
        password=None,
        progress_callback=None,
        is_cancelled=lambda: False,
        options={
            "external_tools": False,
            "visual_analysis": False,
            "lsb_analysis": False,
            "ocr": False,
            "barcodes": False,
            "decoders": False,
            "crypto_analysis": False,
            "repairs": False,
        },
    )
    assert report["status"] == "completed"
    assert any(candidate["value"] == "ICC{engine_local_extra}" for candidate in report["candidates"])
    method = next(item for item in report["methods"] if item["id"] == "zip-local-extra-carver")
    assert method["details"]["recovered_archives"] == 1
    assert any(artifact["name"] == "embedded_zip_local_extra_at_2d" for artifact in report["artifacts"])
    assert source.read_bytes() == outer
