from __future__ import annotations

from pathlib import Path

from app.analyzers.formats import analyze_format, parse_png


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
