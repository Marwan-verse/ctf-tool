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


@pytest.mark.parametrize(
    ("payload", "filename", "expected"),
    [
        (b"qoif" + struct.pack(">IIBB", 1, 1, 4, 0) + b"\0" * 8, "image.bin", "qoi"),
        (b"DDS " + struct.pack("<I", 124) + b"\0" * 120, "texture.bin", "dds"),
        (b"\xabKTX 20\xbb\r\n\x1a\n" + b"\0" * 68, "texture.bin", "ktx"),
        (b"v/1\x01\x02\0\0\0\0", "image.bin", "openexr"),
        (b"\0" * 128 + b"DICM" + b"\0" * 8, "medical.bin", "dicom"),
        (b"SIMPLE  =                    T".ljust(80, b" "), "science.bin", "fits"),
        (struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, 4096, 1, 0, 0), "system.bin", "android_sparse"),
        (b"\xd0\x0d\xfe\xed" + b"\0" * 36, "tree.bin", "dtb"),
        (b"x\x9f>\x22\x01\0", "winmail.dat", "tnef"),
    ],
)
def test_second_tier_magic_detection(payload: bytes, filename: str, expected: str) -> None:
    assert sniff_kind(payload, filename) == expected


def test_qoi_structure_finds_exact_trailing_payload() -> None:
    marker = b"\0\0\0\0\0\0\0\x01"
    source = b"qoif" + struct.pack(">IIBB", 1, 1, 4, 0) + b"\xfe\xff\x00\x00" + marker + b"PK\x03\x04"
    report = analyze_format("qoi", source)
    assert report["properties"]["decoded_pixels"] == 1
    assert report["properties"]["end_marker_valid"] is True
    assert report["properties"]["trailing_bytes"] == 4
    assert report["extracted"][0]["kind"] == "zip"


def test_dds_ktx_and_openexr_headers_are_bounded() -> None:
    dds = bytearray(128)
    dds[:4] = b"DDS "
    struct.pack_into("<I", dds, 4, 124)
    struct.pack_into("<II", dds, 12, 32, 64)
    struct.pack_into("<I", dds, 76, 32)
    dds[84:88] = b"DXT1"
    dds_report = analyze_format("dds", bytes(dds))
    assert dds_report["properties"]["width"] == 64
    assert dds_report["properties"]["height"] == 32
    assert dds_report["properties"]["fourcc"] == "DXT1"

    kv_payload = b"KTXwriter\0flag{ktx_metadata}"
    kv_record = struct.pack("<I", len(kv_payload)) + kv_payload
    kv_record += b"\0" * ((-len(kv_record)) % 4)
    ktx_header = b"\xabKTX 20\xbb\r\n\x1a\n" + struct.pack(
        "<9I4I2Q", 37, 1, 8, 4, 0, 0, 1, 1, 0, 0, 0, 80, len(kv_record), 0, 0,
    )
    ktx_report = analyze_format("ktx", ktx_header + kv_record)
    assert ktx_report["properties"]["width"] == 8
    assert "flag{ktx_metadata}" in ktx_report["text_records"][0]["text"]

    value = b"flag{openexr_attribute}"
    exr = b"v/1\x01" + struct.pack("<I", 2) + b"comments\0string\0" + struct.pack("<I", len(value)) + value + b"\0"
    exr_report = analyze_format("openexr", exr)
    assert exr_report["properties"]["version"] == 2
    assert "flag{openexr_attribute}" in exr_report["text_records"][0]["text"]


def _dicom_explicit(tag: tuple[int, int], vr: bytes, payload: bytes) -> bytes:
    if len(payload) % 2:
        payload += b"\0" if vr == b"UI" else b" "
    if vr.decode("ascii") in {"OB", "OD", "OF", "OL", "OV", "OW", "SQ", "SV", "UC", "UR", "UT", "UN", "UV"}:
        return struct.pack("<HH", *tag) + vr + b"\0\0" + struct.pack("<I", len(payload)) + payload
    return struct.pack("<HH", *tag) + vr + struct.pack("<H", len(payload)) + payload


def test_dicom_and_fits_text_and_residue_are_recovered() -> None:
    dicom = b"\0" * 128 + b"DICM"
    dicom += _dicom_explicit((0x0002, 0x0010), b"UI", b"1.2.840.10008.1.2.1")
    dicom += _dicom_explicit((0x0010, 0x0010), b"PN", b"flag{dicom_patient}")
    dicom += _dicom_explicit((0x0028, 0x0010), b"US", struct.pack("<H", 32))
    dicom += _dicom_explicit((0x7FE0, 0x0010), b"OB", b"")
    dicom_report = analyze_format("dicom", dicom)
    assert dicom_report["properties"]["rows"] == 32
    assert "flag{dicom_patient}" in dicom_report["text_records"][0]["text"]

    def card(value: str) -> bytes:
        return value.encode("ascii").ljust(80, b" ")

    fits = card("SIMPLE  =                    T") + card("BITPIX  =                    8") + card("NAXIS   =                    0")
    fits += card("COMMENT flag{fits_card}") + card("END")
    fits = fits.ljust(2880, b" ") + b"PK\x03\x04"
    fits_report = analyze_format("fits", fits)
    assert fits_report["properties"]["trailing_bytes"] == 4
    assert "flag{fits_card}" in fits_report["text_records"][0]["text"]
    assert fits_report["extracted"][0]["kind"] == "zip"

    extension_hdu = card("XTENSION= 'IMAGE   '") + card("BITPIX  =                    8") + card("NAXIS   =                    0") + card("PCOUNT  =                    0") + card("GCOUNT  =                    1") + card("END")
    multi_hdu = fits[:2880] + extension_hdu.ljust(2880, b" ") + b"PK\x03\x04"
    multi_report = analyze_format("fits", multi_hdu)
    assert multi_report["properties"]["hdu_count"] == 2
    assert multi_report["properties"]["logical_file_end"] == 5760
    assert multi_report["properties"]["trailing_bytes"] == 4


def test_android_sparse_and_dtb_emit_validated_child_artifacts() -> None:
    raw = b"PK\x03\x04" + b"\0" * 508
    sparse = struct.pack("<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, 512, 1, 1, 0)
    sparse += struct.pack("<HHII", 0xCAC1, 0, 1, 12 + len(raw)) + raw
    sparse_report = analyze_format("android_sparse", sparse)
    assert sparse_report["properties"]["valid_chunk_table"] is True
    assert sparse_report["extracted"][0]["kind"] == "zip"

    strings = b"compatible\0payload\0"
    structure = struct.pack(">I", 1) + b"\0\0\0\0"
    compatible = b"ctf,board\0"
    structure += struct.pack(">III", 3, len(compatible), 0) + compatible + b"\0" * ((-len(compatible)) % 4)
    embedded = b"\x89PNG\r\n\x1a\n"
    structure += struct.pack(">III", 3, len(embedded), len(b"compatible\0")) + embedded
    structure += struct.pack(">III", 2, 9, 0)
    struct_offset = 40
    strings_offset = struct_offset + len(structure)
    total_size = strings_offset + len(strings)
    header = struct.pack(">10I", 0xD00DFEED, total_size, struct_offset, strings_offset, 40, 17, 16, 0, len(strings), len(structure))
    dtb_report = analyze_format("dtb", header + structure + strings)
    assert dtb_report["properties"]["nodes"] == 1
    assert "ctf,board" in dtb_report["text_records"][0]["text"]
    assert dtb_report["extracted"][0]["kind"] == "png"


def test_tnef_attributes_and_attachment_checksums_are_validated() -> None:
    def attribute(attribute_id: int, payload: bytes, level: int = 2, attribute_type: int = 6) -> bytes:
        return bytes([level]) + struct.pack("<HHI", attribute_id, attribute_type, len(payload)) + payload + struct.pack("<H", sum(payload) & 0xFFFF)

    source = b"x\x9f>\x22\x01\0"
    source += attribute(0x8010, b"flag.txt\0")
    source += attribute(0x800F, b"flag{tnef_attachment}")
    report = analyze_format("tnef", source)
    assert report["properties"]["invalid_attribute_checksums"] == 0
    assert report["properties"]["attachments_extracted"] == 1
    assert report["extracted"][0]["label"] == "flag.txt"
    assert report["extracted"][0]["data"] == b"flag{tnef_attachment}"


def test_second_tier_types_have_stable_mime_and_extensions() -> None:
    assert mime_for("dicom") == "application/dicom"
    assert extension_for("fits") == ".fits"
    assert mime_for("tnef") == "application/vnd.ms-tnef"
    assert extension_for("android_sparse") == ".simg"
    assert extension_for("dtb") == ".dtb"
