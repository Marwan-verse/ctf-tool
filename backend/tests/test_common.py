from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from app.analyzers.common import (
    AnalyzerCancelled,
    bounded_read,
    check_cancelled,
    find_magic_offsets,
    iter_ascii_strings,
    iter_utf16_strings,
    safe_label,
    sniff_kind,
)

from conftest import lsb_pixels, patterned_pixels, rgb_png


def test_deterministic_png_builder() -> None:
    first = rgb_png(8, 8, patterned_pixels(8, 8))
    second = rgb_png(8, 8, patterned_pixels(8, 8))

    assert first == second
    assert sniff_kind(first, "misleading.txt") == "png"
    assert hashlib.sha256(first).hexdigest() == hashlib.sha256(second).hexdigest()


def test_lsb_fixture_changes_only_low_bits() -> None:
    baseline = patterned_pixels(24, 24)
    embedded = lsb_pixels(24, 24, b"flag{rgb_lsb_fixture}")

    assert len(baseline) == len(embedded)
    assert all((before ^ after) in (0, 1) for before, after in zip(baseline, embedded, strict=True))


def test_bounded_read_reports_truncation(tmp_path: Path) -> None:
    source = tmp_path / "bounded.bin"
    source.write_bytes(b"0123456789")

    assert bounded_read(source, 4) == (b"0123", True)
    assert bounded_read(source, 10) == (b"0123456789", False)


def test_string_scanners_preserve_offsets() -> None:
    ascii_hits = list(iter_ascii_strings(b"\0\0flag{ascii}\0"))
    utf16_hits = list(iter_utf16_strings(b"XX" + "flag{utf16}".encode("utf-16-le") + b"\0\0"))

    assert ascii_hits == [{"encoding": "ascii", "offset": 2, "text": "flag{ascii}"}]
    assert any(hit["text"] == "flag{utf16}" for hit in utf16_hits)


def test_magic_scan_finds_embedded_archive_offset() -> None:
    data = b"prefix" + b"PK\x03\x04" + b"payload"

    assert {hit["kind"]: hit["offset"] for hit in find_magic_offsets(data)}["zip"] == 6


@pytest.mark.parametrize(
    ("hostile", "expected"),
    [
        ("../../etc/passwd", "etc_passwd"),
        ("--output=$(touch owned)", "--output_touch_owned"),
        ("\u202eflag.png", "flag.png"),
        ("...", "artifact"),
    ],
)
def test_safe_label_never_returns_a_path(hostile: str, expected: str) -> None:
    value = safe_label(hostile)

    assert value == expected
    assert "/" not in value
    assert "\\" not in value
    assert ".." not in value


def test_cancellation_is_cooperative_and_callback_errors_do_not_cancel() -> None:
    with pytest.raises(AnalyzerCancelled):
        check_cancelled(lambda: True)

    def broken_callback() -> bool:
        raise RuntimeError("UI callback failed")

    check_cancelled(broken_callback)
