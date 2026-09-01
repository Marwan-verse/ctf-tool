from __future__ import annotations

import io
import struct
import zipfile

import pytest

from app.analyzers.common import extension_for, mime_for, sniff_kind
from app.analyzers.extended import zip_directory_is_bounded
from app.analyzers.formats import analyze_format


@pytest.mark.parametrize(
    ("payload", "filename", "expected"),
    [
        (b"8BPS\x00\x01" + b"\0" * 24, "image.bin", "psd"),
        (b"gimp xcf file\0" + b"\0" * 20, "image.bin", "xcf"),
        (b"P6\n2 1\n255\n\xff\0\0\0\xff\0", "image.bin", "netpbm"),
        (b"MSCF" + b"\0" * 40, "archive.bin", "cab"),
        (b"070701" + b"0" * 104, "archive.bin", "cpio"),
        (b"\xed\xab\xee\xdb" + b"\0" * 100, "package.bin", "rpm"),
        (b"xar!" + b"\0" * 40, "archive.bin", "xar"),
        (b"\xac\xed\x00\x05\x74\x00\x04flag", "object.bin", "java_serialized"),
        (b"PACK\x00\x00\x00\x02\x00\x00\x00\x01", "object.bin", "git_pack"),
        (b"DIRC\x00\x00\x00\x02\x00\x00\x00\x01", "index.bin", "git_index"),
        (b"\x89HDF\r\n\x1a\n" + b"\0" * 32, "data.bin", "hdf5"),
        (bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3") + b"\0" * 32, "notes.bin", "onenote"),
    ],
)
def test_extended_magic_detection(payload: bytes, filename: str, expected: str) -> None:
    assert sniff_kind(payload, filename) == expected


def test_psd_and_netpbm_headers_are_parsed_without_decoding_pixels() -> None:
    psd = b"8BPS" + struct.pack(">H6sHIIHH", 1, b"\0" * 6, 3, 2, 4, 8, 3) + struct.pack(">III", 0, 0, 0)
    psd_report = analyze_format("psd", psd)
    assert psd_report["properties"]["width"] == 4
    assert psd_report["properties"]["height"] == 2
    assert psd_report["properties"]["color_mode"] == "RGB"

    pnm = b"P6\n# ctf metadata\n2 1\n255\n\xff\0\0\0\xff\0TRAILER"
    pnm_report = analyze_format("netpbm", pnm)
    assert pnm_report["properties"]["expected_raster_bytes"] == 6
    assert pnm_report["properties"]["trailing_bytes"] == len(b"TRAILER")
    assert "ctf metadata" in pnm_report["text_records"][0]["text"]


def _zip_package(name: str, payload: bytes) -> bytes:
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, payload)
    return target.getvalue()


def test_zip_directory_is_gated_before_materializing_entries() -> None:
    payload = _zip_package("manifest.xml", b"flag{bounded_zip}")
    assert zip_directory_is_bounded(payload, max_entries=100, max_directory_bytes=1024 * 1024)
    hostile = bytearray(payload)
    eocd = hostile.rfind(b"PK\x05\x06")
    hostile[eocd + 8:eocd + 12] = b"\xff\xff\xff\xff"
    assert not zip_directory_is_bounded(bytes(hostile), max_entries=100, max_directory_bytes=1024 * 1024)


@pytest.mark.parametrize(
    ("filename", "kind", "member"),
    [
        ("challenge.apk", "apk", "AndroidManifest.xml"),
        ("challenge.aab", "aab", "base/manifest/AndroidManifest.xml"),
        ("challenge.jar", "jar", "META-INF/MANIFEST.MF"),
        ("challenge.xps", "xps", "Documents/1/Pages/1.fpage"),
        ("challenge.msix", "msix", "AppxManifest.xml"),
    ],
)
def test_zip_application_packages_are_typed_and_scanned(filename: str, kind: str, member: str) -> None:
    payload = _zip_package(member, b"<root>flag{package_text}</root>")
    assert sniff_kind(payload, filename) == kind
    report = analyze_format(kind, payload)
    assert report["properties"]["entries"] == 1
    assert any("flag{package_text}" in item["text"] for item in report["text_records"])


def test_bson_keys_strings_and_binary_values_are_recovered() -> None:
    text = b"flag{bson}"
    body = b"\x02message\0" + struct.pack("<i", len(text) + 1) + text + b"\0"
    body += b"\x05blob\0" + struct.pack("<i", 4) + b"\0PK\x03\x04"
    document = struct.pack("<i", 4 + len(body) + 1) + body + b"\0"

    assert sniff_kind(document, "challenge.bson") == "bson"
    report = analyze_format("bson", document)
    assert report["properties"]["documents_parsed"] == 1
    assert "flag{bson}" in report["text_records"][0]["text"]
    assert report["extracted"][0]["kind"] == "zip"


def test_serialized_data_is_inspected_without_instantiation() -> None:
    java = b"\xac\xed\x00\x05\x74\x00\x11flag{java_stream}"
    java_report = analyze_format("java_serialized", java)
    assert "flag{java_stream}" in java_report["text_records"][0]["text"]

    pickle = b"\x80\x04\x95\x14\x00\x00\x00\x00\x00\x00\x00\x8c\x11flag{pickle_data}\x94."
    pickle_report = analyze_format("python_pickle", pickle)
    assert "flag{pickle_data}" in pickle_report["text_records"][0]["text"]
    assert any("not" in item["description"].lower() for item in pickle_report["findings"])


def test_intel_hex_is_checksum_validated_and_reconstructed() -> None:
    # 04 0000 00 504b0304 checksum=5a
    source = b":04000000504B03045A\n:00000001FF\n"
    assert sniff_kind(source, "firmware.hex") == "intel_hex"
    report = analyze_format("intel_hex", source)
    assert report["properties"]["records_decoded"] == 1
    assert report["extracted"][0]["data"] == b"PK\x03\x04"
    assert report["extracted"][0]["kind"] == "zip"


def test_new_types_have_stable_mime_and_download_extensions() -> None:
    assert extension_for("psd") == ".psd"
    assert mime_for("avif") == "image/avif"
    assert extension_for("java_serialized") == ".ser"
    assert mime_for("hdf5") == "application/x-hdf5"
