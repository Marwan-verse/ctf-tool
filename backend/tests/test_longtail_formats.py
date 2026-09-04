from __future__ import annotations

import struct
import zlib

import pytest

from app.analyzers.common import extension_for, mime_for, sniff_kind
from app.analyzers.formats import analyze_format


def _avro_long(value: int) -> bytes:
    unsigned = (value << 1) ^ (value >> 63)
    result = bytearray()
    while unsigned & ~0x7F:
        result.append((unsigned & 0x7F) | 0x80)
        unsigned >>= 7
    result.append(unsigned)
    return bytes(result)


def _protobuf_varint(value: int) -> bytes:
    result = bytearray()
    while value & ~0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _protobuf_uint(field: int, value: int) -> bytes:
    return _protobuf_varint(field << 3) + _protobuf_varint(value)


def _protobuf_bytes(field: int, value: bytes) -> bytes:
    return _protobuf_varint((field << 3) | 2) + _protobuf_varint(len(value)) + value


@pytest.mark.parametrize(
    ("payload", "filename", "kind"),
    [
        (b"PAR1data\0\0\0\0PAR1", "x.bin", "parquet"),
        (b"Obj\x01" + b"\0" * 20, "x.bin", "avro"),
        (b"ARROW1\0\0\0\0\0\0ARROW1", "x.bin", "arrow_ipc"),
        (b"ORC\0", "x.bin", "orc"),
        (b"'\x05\x19V" + b"\0" * 60, "x.bin", "uimage"),
        (b"ANDROID!" + b"\0" * 40, "x.bin", "android_boot"),
        (b"VNDRBOOT" + b"\0" * 40, "x.bin", "android_vendor_boot"),
        (b"WARC/1.1\r\nContent-Length: 0\r\n\r\n", "x.bin", "warc"),
        (b"ITSF" + b"\0" * 60, "x.bin", "chm"),
        (b"AT&TFORM" + b"\0\0\0\x04DJVU", "x.bin", "djvu"),
        (b"hsqs" + b"\0" * 92, "x.bin", "squashfs"),
    ],
)
def test_longtail_magic_detection(payload: bytes, filename: str, kind: str) -> None:
    assert sniff_kind(payload, filename) == kind


def test_columnar_dataset_footers_and_avro_blocks_are_bounded() -> None:
    parquet_footer = b"schema flag{parquet_footer}"
    parquet = b"PAR1column-data" + parquet_footer + struct.pack("<I", len(parquet_footer)) + b"PAR1" + b"PK\x03\x04"
    parquet_report = analyze_format("parquet", parquet)
    assert parquet_report["properties"]["footer_bytes"] == len(parquet_footer)
    assert parquet_report["properties"]["trailing_bytes"] == 4
    assert parquet_report["extracted"][0]["kind"] == "zip"

    arrow_footer = b"field flag{arrow_footer}"
    arrow = b"ARROW1\0\0stream" + arrow_footer + struct.pack("<I", len(arrow_footer)) + b"ARROW1"
    arrow_report = analyze_format("arrow_ipc", arrow)
    assert arrow_report["properties"]["footer_bytes"] == len(arrow_footer)
    assert "flag{arrow_footer}" in arrow_report["text_records"][0]["text"]

    schema = b'{"type":"record","name":"Flag","fields":[]}'
    metadata = bytearray(_avro_long(2))
    for key, value in ((b"avro.schema", schema), (b"avro.codec", b"null")):
        metadata += _avro_long(len(key)) + key + _avro_long(len(value)) + value
    metadata += _avro_long(0)
    sync = bytes(range(16))
    block = b"flag{avro_record_bytes}"
    avro = b"Obj\x01" + bytes(metadata) + sync + _avro_long(1) + _avro_long(len(block)) + block + sync
    avro_report = analyze_format("avro", avro)
    assert avro_report["properties"]["blocks"] == 1
    assert avro_report["properties"]["declared_records"] == 1
    assert "Flag" in avro_report["text_records"][0]["text"]


def test_orc_postscript_is_decoded_without_decompressing_stripes() -> None:
    metadata = b"metadata flag{orc_footer}"
    footer = b"footer"
    postscript = b"".join((
        _protobuf_uint(1, len(footer)),
        _protobuf_uint(2, 0),
        _protobuf_uint(3, 262_144),
        _protobuf_uint(5, len(metadata)),
        _protobuf_bytes(8000, b"ORC"),
    ))
    source = b"ORC" + metadata + footer + postscript + bytes([len(postscript)])
    report = analyze_format("orc", source)
    assert report["properties"]["valid_tail_geometry"] is True
    assert report["properties"]["postscript_magic"] == "ORC"
    assert report["properties"]["compression"] == "none"


def test_uimage_crcs_and_android_boot_segments_are_recovered() -> None:
    payload = b"PK\x03\x04flag{uimage_payload}"
    data_crc = zlib.crc32(payload) & 0xFFFFFFFF
    fields = (0x27051956, 0, 1_700_000_000, len(payload), 0x8000, 0x8000, data_crc, 5, 2, 5, 0, b"CTF firmware")
    header = bytearray(struct.pack(">7I4B32s", *fields))
    header_crc = zlib.crc32(header) & 0xFFFFFFFF
    struct.pack_into(">I", header, 4, header_crc)
    report = analyze_format("uimage", bytes(header) + payload + b"TAIL")
    assert report["properties"]["header_crc_valid"] is True
    assert report["properties"]["data_crc_valid"] is True
    assert report["extracted"][0]["kind"] == "zip"
    assert report["properties"]["trailing_bytes"] == 4

    kernel = b"\x1f\x8b\x08kernel"
    ramdisk = b"070701ramdisk"
    boot_header = bytearray(1580)
    boot_header[:8] = b"ANDROID!"
    struct.pack_into("<IIII", boot_header, 8, len(kernel), len(ramdisk), 0, 1580)
    struct.pack_into("<I", boot_header, 40, 3)
    boot_header[44:44 + len(b"console=ttyS0 flag{boot_cmdline}")] = b"console=ttyS0 flag{boot_cmdline}"
    boot = bytes(boot_header).ljust(4096, b"\0") + kernel
    boot = boot.ljust(8192, b"\0") + ramdisk
    boot_report = analyze_format("android_boot", boot)
    assert boot_report["properties"]["header_version"] == 3
    assert boot_report["properties"]["parser_stop"] is None
    assert "flag{boot_cmdline}" in boot_report["text_records"][0]["text"]
    assert [item["kind"] for item in boot_report["extracted"][:2]] == ["gzip", "cpio"]


def test_uefi_squashfs_warc_chm_and_djvu_boundaries() -> None:
    fv = bytearray(64)
    fv[16:32] = bytes(range(16))
    struct.pack_into("<Q4sIHHHBB", fv, 32, 64, b"_FVH", 0, 64, 0, 0, 0, 2)
    checksum = (-sum(int.from_bytes(fv[index:index + 2], "little") for index in range(0, 64, 2))) & 0xFFFF
    struct.pack_into("<H", fv, 50, checksum)
    fv_report = analyze_format("uefi_fv", bytes(fv) + b"PK\x03\x04")
    assert fv_report["properties"]["header_checksum_valid"] is True
    assert fv_report["extracted"][0]["kind"] == "zip"

    squash_header = struct.pack(
        "<5I6H8Q", 0x73717368, 3, 1_700_000_000, 131_072, 0,
        4, 17, 0, 1, 4, 0, 1, 96, 80, 0xFFFFFFFFFFFFFFFF, 96, 96, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
    )
    squash_report = analyze_format("squashfs", squash_header + b"TAIL")
    assert squash_report["properties"]["valid_superblock_geometry"] is True
    assert squash_report["properties"]["trailing_bytes"] == 4

    http = b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\n"
    warc_header = (
        b"WARC/1.1\r\nWARC-Type: response\r\nWARC-Target-URI: https://example.test/flag.png\r\n"
        b"Content-Type: application/http; msgtype=response\r\nContent-Length: " + str(len(http)).encode() + b"\r\n\r\n"
    )
    warc_report = analyze_format("warc", warc_header + http + b"\r\n\r\n")
    assert warc_report["properties"]["records"] == 1
    assert warc_report["extracted"][0]["kind"] == "png"

    chm = bytearray(96)
    chm[:4] = b"ITSF"
    struct.pack_into("<II", chm, 4, 3, 96)
    chm += b"flag{chm_directory_string}\0"
    chm_report = analyze_format("chm", bytes(chm))
    assert "flag{chm_directory_string}" in chm_report["text_records"][0]["text"]

    text = b"flag{djvu_text_layer}"
    chunk = b"TXTa" + struct.pack(">I", len(text)) + text + (b"\0" if len(text) & 1 else b"")
    form = b"DJVU" + chunk
    djvu = b"AT&TFORM" + struct.pack(">I", len(form)) + form
    djvu_report = analyze_format("djvu", djvu)
    assert djvu_report["properties"]["chunks"] == 1
    assert "flag{djvu_text_layer}" in djvu_report["text_records"][0]["text"]


def test_longtail_mime_and_extensions_are_stable() -> None:
    assert mime_for("parquet") == "application/vnd.apache.parquet"
    assert extension_for("arrow_ipc") == ".arrow"
    assert mime_for("warc") == "application/warc"
    assert extension_for("squashfs") == ".squashfs"
