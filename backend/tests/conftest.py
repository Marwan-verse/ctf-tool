from __future__ import annotations

import binascii
import struct
import zlib
from collections.abc import Iterator
from pathlib import Path

import pytest


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    """Build a PNG chunk without relying on an image library."""

    checksum = binascii.crc32(kind)
    checksum = binascii.crc32(payload, checksum) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", checksum)


def rgb_png(
    width: int,
    height: int,
    pixels: bytes,
    *,
    text_chunks: tuple[tuple[str, str], ...] = (),
    trailer: bytes = b"",
) -> bytes:
    """Return a deterministic, non-interlaced, 8-bit RGB PNG."""

    expected = width * height * 3
    if len(pixels) != expected:
        raise ValueError(f"expected {expected} pixel bytes, got {len(pixels)}")

    scanlines = bytearray()
    row_size = width * 3
    for row in range(height):
        scanlines.append(0)  # PNG filter type: None
        start = row * row_size
        scanlines.extend(pixels[start : start + row_size])

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    chunks = [png_chunk(b"IHDR", ihdr)]
    for keyword, value in text_chunks:
        chunks.append(png_chunk(b"tEXt", keyword.encode("latin-1") + b"\0" + value.encode("latin-1")))
    chunks.extend((png_chunk(b"IDAT", zlib.compress(bytes(scanlines), level=9)), png_chunk(b"IEND", b"")))
    return PNG_SIGNATURE + b"".join(chunks) + trailer


def patterned_pixels(width: int, height: int) -> bytes:
    """Generate stable, varied RGB bytes that do not contain flag-like text."""

    values = bytearray()
    for y in range(height):
        for x in range(width):
            values.extend(
                (
                    (x * 17 + y * 3 + 24) % 256,
                    (x * 5 + y * 29 + 80) % 256,
                    (x * 11 + y * 7 + 144) % 256,
                )
            )
    return bytes(values)


def lsb_pixels(width: int, height: int, message: bytes) -> bytes:
    """Embed a NUL-terminated message in sequential RGB least-significant bits."""

    source = bytearray(patterned_pixels(width, height))
    encoded = message + b"\0"
    bits = [(byte >> shift) & 1 for byte in encoded for shift in range(7, -1, -1)]
    if len(bits) > len(source):
        raise ValueError("message does not fit in PNG fixture")
    for index, bit in enumerate(bits):
        source[index] = (source[index] & 0xFE) | bit
    return bytes(source)


@pytest.fixture
def fixture_dir(tmp_path: Path) -> Path:
    return tmp_path / "image-fixtures"


@pytest.fixture
def clean_png(fixture_dir: Path) -> Path:
    fixture_dir.mkdir(parents=True, exist_ok=True)
    path = fixture_dir / "clean-negative.png"
    path.write_bytes(rgb_png(16, 16, patterned_pixels(16, 16)))
    return path


@pytest.fixture
def metadata_png(fixture_dir: Path) -> Path:
    fixture_dir.mkdir(parents=True, exist_ok=True)
    path = fixture_dir / "metadata.png"
    path.write_bytes(
        rgb_png(
            8,
            8,
            patterned_pixels(8, 8),
            text_chunks=(("Comment", "flag{metadata_text_chunk}"), ("Author", "ForenScope QA")),
        )
    )
    return path


@pytest.fixture
def trailing_png(fixture_dir: Path) -> Path:
    fixture_dir.mkdir(parents=True, exist_ok=True)
    path = fixture_dir / "trailing-data.png"
    path.write_bytes(
        rgb_png(
            8,
            8,
            patterned_pixels(8, 8),
            trailer=b"PK\x03\x04flag{png_trailing_data}\n",
        )
    )
    return path


@pytest.fixture
def lsb_png(fixture_dir: Path) -> Path:
    fixture_dir.mkdir(parents=True, exist_ok=True)
    path = fixture_dir / "lsb.png"
    path.write_bytes(rgb_png(24, 24, lsb_pixels(24, 24, b"flag{rgb_lsb_fixture}")))
    return path


@pytest.fixture
def malformed_png(fixture_dir: Path) -> Path:
    fixture_dir.mkdir(parents=True, exist_ok=True)
    path = fixture_dir / "malformed-crc.png"
    data = bytearray(rgb_png(8, 8, patterned_pixels(8, 8)))
    # Flip the final byte of the IHDR CRC. The image remains parseable by many
    # decoders but is structurally invalid, which is ideal for validator tests.
    ihdr_crc_last_byte = len(PNG_SIGNATURE) + 4 + 4 + 13 + 3
    data[ihdr_crc_last_byte] ^= 0xFF
    path.write_bytes(data)
    return path


@pytest.fixture
def malicious_named_png(fixture_dir: Path) -> Path:
    fixture_dir.mkdir(parents=True, exist_ok=True)
    path = fixture_dir / "--$(touch-owned);..%2f..%2fflag.png"
    path.write_bytes(rgb_png(4, 4, patterned_pixels(4, 4)))
    return path


@pytest.fixture(autouse=True)
def deterministic_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Keep locale/time-sensitive report fields stable where supported."""

    monkeypatch.setenv("TZ", "UTC")
    monkeypatch.setenv("LC_ALL", "C.UTF-8")
    yield
