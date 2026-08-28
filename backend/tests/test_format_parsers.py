from __future__ import annotations

import binascii
import io
import struct
import zipfile
from pathlib import Path

from app.analyzers.formats import analyze_format, parse_bmp, parse_png, propose_header_repairs


def test_png_text_metadata_is_extracted_with_provenance(metadata_png: Path) -> None:
    result = parse_png(metadata_png.read_bytes(), profile="quick")

    assert result["properties"]["width"] == 8
    assert result["properties"]["height"] == 8
    assert result["properties"]["bad_crc_count"] == 0
    assert result["metadata"]["png:Comment"] == "flag{metadata_text_chunk}"
    assert any(record["source"] == "tEXt" and record["offset"] >= 8 for record in result["text_records"])


def test_png_trailer_is_bounded_and_extracted(trailing_png: Path) -> None:
    result = parse_png(trailing_png.read_bytes(), profile="balanced")

    [trailer] = [item for item in result["extracted"] if item["label"] == "png_trailer"]
    assert trailer["data"].startswith(b"PK\x03\x04")
    assert b"flag{png_trailing_data}" in trailer["data"]
    assert trailer["offset"] > 8
    assert any(finding["title"] == "Data follows PNG IEND" for finding in result["findings"])


def test_bad_png_crc_is_reported_and_deep_mode_proposes_copy_only_repair(malformed_png: Path) -> None:
    source = malformed_png.read_bytes()
    result = parse_png(source, profile="deep")

    assert result["properties"]["bad_crc_count"] == 1
    assert any(finding["title"] == "PNG CRC mismatch" for finding in result["findings"])
    [repair] = [item for item in result["repairs"] if item["label"] == "png_crc_repaired"]
    assert repair["data"] != source
    assert parse_png(repair["data"], profile="quick")["properties"]["bad_crc_count"] == 0
    # The derived repair must not mutate the evidence file.
    assert malformed_png.read_bytes() == source


def test_malformed_input_returns_a_report_instead_of_raising() -> None:
    result = analyze_format("png", b"\x89PNG\r\n\x1a\n\x7f" * 20, profile="quick")

    assert result["kind"] == "png"
    assert isinstance(result["findings"], list)
    assert isinstance(result["properties"], dict)


def test_corrupted_png_signature_and_ihdr_length_get_a_provenance_candidate(metadata_png: Path) -> None:
    source = bytearray(metadata_png.read_bytes())
    source[:8] = b"\x89PB\x11\r\n\x1a\n"
    source[8:12] = b"\x00\x12\x13\x14"

    [candidate] = propose_header_repairs(bytes(source), profile="deep")

    assert candidate["kind"] == "png"
    assert candidate["data"][:8] == b"\x89PNG\r\n\x1a\n"
    assert candidate["data"][8:12] == b"\x00\x00\x00\r"
    assert parse_png(candidate["data"], profile="quick")["properties"]["width"] == 8
    assert candidate["details"] == {"signature_repaired": True, "ihdr_length_repaired": True}


def test_multi_stage_corrupted_png_is_recovered_from_crc_and_boundaries(clean_png: Path) -> None:
    original = clean_png.read_bytes()
    phys_payload = b"\x00\x00\x0b\x13\x00\x00\x0b\x13\x01"
    phys = struct.pack(">I", len(phys_payload)) + b"pHYs" + phys_payload
    phys += struct.pack(">I", binascii.crc32(b"pHYs" + phys_payload) & 0xFFFFFFFF)
    clean = original[:33] + phys + original[33:]
    first_idat = 33 + len(phys)
    corrupted = bytearray(clean)
    corrupted[:8] = b"\x89eN4\r\n\xb0\xaa"
    corrupted[12:16] = b'C"DR'
    corrupted[41] = 0xAA  # pHYs byte; its original CRC remains as evidence.
    corrupted[first_idat:first_idat + 4] = b"\xAA\xAA\xFF\xA5"
    corrupted[first_idat + 4:first_idat + 8] = b"\xABDET"

    [candidate] = propose_header_repairs(bytes(corrupted), profile="deep")

    assert candidate["label"] == "png_structure_recovered"
    assert candidate["data"] == clean
    details = candidate["details"]
    assert details["signature_repaired"] is True
    assert details["ihdr_type_repaired"] is True
    assert details["ancillary_byte_repairs"] == [{"chunk": "pHYs", "offset": 41, "from": "aa", "to": "00"}]
    assert details["inferred_chunks"][0]["type"] == "IDAT"
    repaired = parse_png(candidate["data"], profile="quick")
    assert repaired["properties"]["bad_crc_count"] == 0
    assert repaired["properties"]["iend_present"] is True


def test_corrupted_jpeg_soi_with_jfif_evidence_gets_a_candidate() -> None:
    # Two literal prefix bytes stand in for a damaged FF D8 SOI.  The valid
    # APP0 length/JFIF marker and following JPEG marker make the repair safe.
    source = b"\\x\xff\xe0\x00\x10JFIF\x00" + (b"\x00" * 9) + b"\xff\xdb" + (b"\x00" * 20)

    [candidate] = propose_header_repairs(source, profile="deep")

    assert candidate["kind"] == "jpeg"
    assert candidate["data"][:3] == b"\xff\xd8\xff"
    assert "start-of-image" in candidate["transformation"]


def test_bmp_interleaved_word_lane_recovers_and_trims_zip() -> None:
    archive_buffer = io.BytesIO()
    with zipfile.ZipFile(archive_buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("clue.txt", "picoCTF{synthetic_bmp_word_lane}")
    archive_data = archive_buffer.getvalue()

    # Keep enough carrier data after EOCD to exceed zipfile's normal backward
    # search window. This is the layout used by picoCTF's Invisible WORDs.
    width, height = 400, 200
    pixel_count = width * height
    hidden_lane = archive_data.ljust(pixel_count * 2, b"\xa5")
    pixels = bytearray(pixel_count * 4)
    pixels[0::4] = b"\x00" * pixel_count
    pixels[1::4] = b"\x00" * pixel_count
    pixels[2::4] = hidden_lane[0::2]
    pixels[3::4] = hidden_lane[1::2]

    pixel_offset = 14 + 124
    bmp = bytearray(pixel_offset + len(pixels))
    bmp[:2] = b"BM"
    struct.pack_into("<I", bmp, 2, len(bmp))
    struct.pack_into("<I", bmp, 10, pixel_offset)
    struct.pack_into("<IiiHHII", bmp, 14, 124, width, height, 1, 32, 3, len(pixels))
    struct.pack_into("<IIII", bmp, 54, 0x00007C00, 0x000003E0, 0x0000001F, 0)
    bmp[pixel_offset:] = pixels

    result = parse_bmp(bytes(bmp), profile="quick")

    assert result["properties"]["bitfield_masks"] == [
        "0x00007c00", "0x000003e0", "0x0000001f", "0x00000000",
    ]
    [recovered] = [item for item in result["extracted"] if item["label"] == "bmp_word_lane_1_zip"]
    assert recovered["data"] == archive_data
    assert len(hidden_lane) - len(recovered["data"]) > 65_557
    with zipfile.ZipFile(io.BytesIO(recovered["data"])) as archive:
        assert archive.read("clue.txt") == b"picoCTF{synthetic_bmp_word_lane}"
    assert any(finding["title"] == "File hidden in a BMP word lane" for finding in result["findings"])
