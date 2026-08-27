"""Safe sparse-byte editing, live previews, and format-aware integrity checks."""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import struct
import zlib
import zipfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from PIL import Image, UnidentifiedImageError


MAX_EDIT_COUNT = 4096
MAX_LIVE_EDIT_BYTES = 32 * 1024 * 1024
MAX_PREVIEW_PIXELS = 40_000_000
MAX_PREVIEW_EDGE = 2400
MAX_STRUCTURE_ITEMS = 100_000

_IMAGE_KINDS = {"png", "jpeg", "gif", "bmp", "webp"}
_AUDIO_MIME = {
    "wav": "audio/wav",
    "flac": "audio/flac",
    "ogg": "audio/ogg",
    "mp3": "audio/mpeg",
    "m4a": "audio/mp4",
}
_EXTENSION_KIND = {
    ".png": "png",
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".jpe": "jpeg",
    ".gif": "gif",
    ".bmp": "bmp",
    ".webp": "webp",
    ".wav": "wav",
    ".wave": "wav",
    ".zip": "zip",
}
_MEDIA_KIND = {
    "image/png": "png",
    "image/jpeg": "jpeg",
    "image/gif": "gif",
    "image/bmp": "bmp",
    "image/webp": "webp",
    "audio/wav": "wav",
    "audio/x-wav": "wav",
    "application/zip": "zip",
    "application/x-zip-compressed": "zip",
}
_SIGNATURES = {
    "png": "89 50 4e 47 0d 0a 1a 0a",
    "jpeg": "ff d8 ff",
    "gif": "47 49 46 38 37/39 61",
    "bmp": "42 4d",
    "webp": "52 49 46 46 … 57 45 42 50",
    "wav": "52 49 46 46 … 57 41 56 45",
    "zip": "50 4b 03 04",
}


class HexEditError(ValueError):
    """Raised when a sparse edit request is invalid."""


class LiveEditTooLargeError(HexEditError):
    """Raised when live validation would exceed its in-memory safety budget."""


class PreviewUnavailableError(HexEditError):
    """Raised when edited bytes cannot be rendered safely in a browser."""


def _issue(
    kind: str,
    title: str,
    description: str,
    severity: str,
    *,
    offset: int | None = None,
    length: int | None = None,
    expected: str | None = None,
    actual: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "kind": kind,
        "title": title,
        "description": description,
        "severity": severity,
    }
    if offset is not None:
        item["offset"] = max(0, int(offset))
    if length is not None:
        item["length"] = max(0, int(length))
    if expected is not None:
        item["expected"] = expected
    if actual is not None:
        item["actual"] = actual
    if details:
        item["details"] = dict(details)
    return item


def _check(identifier: str, status: str, summary: str) -> dict[str, str]:
    return {"id": identifier, "status": status, "summary": summary}


def detect_magic_kind(data: bytes) -> str | None:
    """Identify formats only from bytes, never from an extension fallback."""

    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if data.startswith(b"BM"):
        return "bmp"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return "wav"
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if data.startswith(b"fLaC"):
        return "flac"
    if data.startswith(b"OggS"):
        return "ogg"
    if data.startswith(b"ID3") or (len(data) >= 2 and data[0] == 0xFF and data[1] & 0xE6 == 0xE2):
        return "mp3"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return "m4a"
    return None


def expected_kind(filename: str = "", declared_media_type: str = "") -> str | None:
    media = declared_media_type.split(";", 1)[0].strip().lower()
    return _MEDIA_KIND.get(media) or _EXTENSION_KIND.get(Path(filename).suffix.lower())


def normalize_edits(edits: Iterable[Mapping[str, Any]], total_size: int) -> list[dict[str, int]]:
    """Validate sparse replacement edits and reject ambiguous duplicates."""

    normalized: list[dict[str, int]] = []
    offsets: set[int] = set()
    for raw in edits:
        if len(normalized) >= MAX_EDIT_COUNT:
            raise HexEditError(f"A live edit is limited to {MAX_EDIT_COUNT:,} changed bytes.")
        try:
            offset = int(raw["offset"])
            value = int(raw["value"])
        except (KeyError, TypeError, ValueError) as exc:
            raise HexEditError("Each edit must contain an integer offset and byte value.") from exc
        if offset < 0 or offset >= total_size:
            raise HexEditError(f"Byte offset {offset} is outside this {total_size:,}-byte artifact.")
        if value < 0 or value > 255:
            raise HexEditError("Edited byte values must be between 0 and 255.")
        if offset in offsets:
            raise HexEditError(f"Byte offset {offset} appears more than once in this edit request.")
        offsets.add(offset)
        normalized.append({"offset": offset, "value": value})
    if not normalized:
        raise HexEditError("Change at least one byte before previewing or saving.")
    normalized.sort(key=lambda item: item["offset"])
    return normalized


def apply_edits(data: bytes, edits: Iterable[Mapping[str, Any]]) -> bytes:
    normalized = normalize_edits(edits, len(data))
    patched = bytearray(data)
    for edit in normalized:
        patched[edit["offset"]] = edit["value"]
    return bytes(patched)


def read_edited_bytes(path: Path, edits: Iterable[Mapping[str, Any]]) -> tuple[bytes, list[dict[str, int]]]:
    total_size = path.stat().st_size
    if total_size > MAX_LIVE_EDIT_BYTES:
        raise LiveEditTooLargeError(
            f"Live preview and integrity checks are limited to {MAX_LIVE_EDIT_BYTES // (1024 * 1024)} MiB; "
            "the edits can still be saved as a derived artifact."
        )
    normalized = normalize_edits(edits, total_size)
    data = path.read_bytes()
    patched = bytearray(data)
    for edit in normalized:
        patched[edit["offset"]] = edit["value"]
    return bytes(patched), normalized


def write_edited_copy(
    source: Path,
    destination: Path,
    edits: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Stream an edited copy to a new path without ever modifying ``source``."""

    total_size = source.stat().st_size
    normalized = normalize_edits(edits, total_size)
    edit_map = {item["offset"]: item["value"] for item in normalized}
    ordered_offsets = [item["offset"] for item in normalized]
    edit_index = 0
    digest = hashlib.sha256()
    written = 0
    changed = 0
    with source.open("rb") as reader, destination.open("xb") as writer:
        while block := reader.read(1024 * 1024):
            mutable = bytearray(block)
            block_start = written
            block_end = block_start + len(mutable)
            while edit_index < len(ordered_offsets) and ordered_offsets[edit_index] < block_end:
                absolute = ordered_offsets[edit_index]
                local = absolute - block_start
                replacement = edit_map[absolute]
                if mutable[local] != replacement:
                    mutable[local] = replacement
                    changed += 1
                edit_index += 1
            payload = bytes(mutable)
            writer.write(payload)
            digest.update(payload)
            written += len(payload)
        writer.flush()
        os.fsync(writer.fileno())
    return {
        "sha256": digest.hexdigest(),
        "size_bytes": written,
        "edit_count": len(normalized),
        "changed_count": changed,
        "edits": normalized,
    }


def patch_digest(edits: Iterable[Mapping[str, Any]]) -> str:
    encoded = json.dumps(list(edits), sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _validate_png(data: bytes) -> tuple[list[dict[str, Any]], list[dict[str, str]], bool]:
    issues: list[dict[str, Any]] = []
    checks: list[dict[str, str]] = []
    signature = b"\x89PNG\r\n\x1a\n"
    if not data.startswith(signature):
        issues.append(_issue("png-signature", "PNG signature is missing", "The first eight bytes do not match the PNG signature.", "error", offset=0, length=min(8, len(data)), expected=_SIGNATURES["png"], actual=data[:8].hex(" ")))
        checks.append(_check("signature", "failed", "PNG signature mismatch."))
        return issues, checks, True
    checks.append(_check("signature", "passed", "PNG signature is present."))
    cursor = 8
    chunk_count = 0
    saw_ihdr = False
    saw_idat = False
    saw_iend = False
    complete = True
    while cursor < len(data) and chunk_count < MAX_STRUCTURE_ITEMS:
        if len(data) - cursor < 12:
            issues.append(_issue("png-truncated-chunk", "PNG chunk is truncated", "Not enough bytes remain for a PNG chunk header, data, and CRC.", "error", offset=cursor, length=len(data) - cursor))
            complete = True
            break
        length = int.from_bytes(data[cursor:cursor + 4], "big")
        chunk_type = data[cursor + 4:cursor + 8]
        chunk_end = cursor + 12 + length
        chunk_name = chunk_type.decode("ascii", "replace")
        if not re.fullmatch(rb"[A-Za-z]{4}", chunk_type):
            issues.append(_issue("png-invalid-chunk-type", "PNG chunk type is invalid", "Chunk type bytes must be four ASCII letters.", "error", offset=cursor + 4, length=4, actual=chunk_type.hex(" ")))
        if chunk_end > len(data):
            issues.append(_issue("png-truncated-chunk", f"{chunk_name} chunk exceeds the file", "The declared chunk length runs past the end of the artifact.", "error", offset=cursor, length=len(data) - cursor, expected=f"{length} data bytes plus CRC", actual=f"{max(0, len(data) - cursor - 12)} data bytes available"))
            break
        payload = data[cursor + 8:cursor + 8 + length]
        expected_crc = int.from_bytes(data[cursor + 8 + length:chunk_end], "big")
        actual_crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            issues.append(_issue("png-crc", f"{chunk_name} CRC does not match", "The stored PNG chunk checksum does not match its type and data bytes.", "error", offset=cursor + 8 + length, length=4, expected=f"{actual_crc:08x}", actual=f"{expected_crc:08x}"))
        if chunk_count == 0 and chunk_type != b"IHDR":
            issues.append(_issue("png-ihdr-order", "IHDR is not the first chunk", "PNG requires IHDR immediately after the signature.", "error", offset=cursor + 4, length=4, expected="IHDR", actual=chunk_name))
        if chunk_type == b"IHDR":
            if saw_ihdr:
                issues.append(_issue("png-duplicate-ihdr", "PNG contains multiple IHDR chunks", "A PNG datastream must contain exactly one IHDR chunk.", "error", offset=cursor + 4, length=4))
            saw_ihdr = True
            if length != 13:
                issues.append(_issue("png-ihdr-length", "IHDR has the wrong length", "IHDR must contain exactly 13 data bytes.", "error", offset=cursor, length=4, expected="13", actual=str(length)))
            elif len(payload) >= 8:
                width = int.from_bytes(payload[:4], "big")
                height = int.from_bytes(payload[4:8], "big")
                if width == 0 or height == 0:
                    issues.append(_issue("png-dimensions", "PNG dimensions are invalid", "PNG width and height must both be greater than zero.", "error", offset=cursor + 8, length=8, actual=f"{width} × {height}"))
        elif chunk_type == b"IDAT":
            if not saw_ihdr:
                issues.append(_issue("png-idat-order", "IDAT appears before IHDR", "Image data cannot precede the PNG header.", "error", offset=cursor + 4, length=4))
            saw_idat = True
        elif chunk_type == b"IEND":
            if length != 0:
                issues.append(_issue("png-iend-length", "IEND contains unexpected data", "PNG IEND must have a zero data length.", "error", offset=cursor, length=4, expected="0", actual=str(length)))
            saw_iend = True
            if chunk_end < len(data):
                issues.append(_issue("png-trailing-data", "Bytes follow the PNG end marker", "Trailing data may be intentional CTF content, concatenated data, or accidental corruption.", "warning", offset=chunk_end, length=len(data) - chunk_end))
            cursor = chunk_end
            break
        cursor = chunk_end
        chunk_count += 1
    if chunk_count >= MAX_STRUCTURE_ITEMS:
        complete = False
        issues.append(_issue("png-check-limit", "PNG chunk check reached its safety limit", "The remaining chunk structure was not validated.", "warning", offset=cursor))
    if not saw_ihdr:
        issues.append(_issue("png-missing-ihdr", "PNG header chunk is missing", "No IHDR chunk was found.", "error", offset=8))
    if not saw_idat:
        issues.append(_issue("png-missing-idat", "PNG image data is missing", "No IDAT chunk was found.", "error", offset=8))
    if not saw_iend:
        issues.append(_issue("png-missing-iend", "PNG end marker is missing", "The PNG datastream does not contain an IEND chunk.", "error", offset=max(0, len(data) - 1)))
    crc_errors = sum(1 for item in issues if item["kind"] == "png-crc")
    checks.append(_check("chunks", "failed" if any(item["severity"] == "error" for item in issues) else "passed", f"Inspected {chunk_count + int(saw_iend):,} PNG chunk(s)."))
    checks.append(_check("crc", "failed" if crc_errors else "passed", f"Found {crc_errors} invalid PNG chunk checksum(s)." if crc_errors else "All inspected PNG chunk checksums match."))
    return issues, checks, complete


def _validate_jpeg(data: bytes) -> tuple[list[dict[str, Any]], list[dict[str, str]], bool]:
    issues: list[dict[str, Any]] = []
    checks: list[dict[str, str]] = []
    if not data.startswith(b"\xff\xd8"):
        issues.append(_issue("jpeg-soi", "JPEG start marker is missing", "A JPEG must begin with FF D8.", "error", offset=0, length=min(2, len(data)), expected="ff d8", actual=data[:2].hex(" ")))
        checks.append(_check("markers", "failed", "JPEG start marker mismatch."))
        return issues, checks, True
    cursor = 2
    marker_count = 1
    saw_frame = False
    saw_scan = False
    saw_eoi = False
    complete = True
    standalone = {0x01, *range(0xD0, 0xD9)}
    frame_markers = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
    while cursor < len(data) and marker_count < MAX_STRUCTURE_ITEMS:
        if data[cursor] != 0xFF:
            issues.append(_issue("jpeg-unexpected-byte", "Unexpected byte between JPEG segments", "JPEG segment headers must begin with FF outside entropy-coded scan data.", "error", offset=cursor, length=1, expected="ff", actual=f"{data[cursor]:02x}"))
            next_marker = data.find(b"\xff", cursor + 1)
            if next_marker < 0:
                break
            cursor = next_marker
        while cursor < len(data) and data[cursor] == 0xFF:
            cursor += 1
        if cursor >= len(data):
            issues.append(_issue("jpeg-truncated-marker", "JPEG ends inside a marker", "The final FF marker byte has no marker code.", "error", offset=len(data) - 1, length=1))
            break
        marker = data[cursor]
        marker_offset = cursor - 1
        cursor += 1
        marker_count += 1
        if marker == 0xD9:
            saw_eoi = True
            if cursor < len(data):
                issues.append(_issue("jpeg-trailing-data", "Bytes follow the JPEG end marker", "Trailing data may be intentional embedded CTF content or an accidental append.", "warning", offset=cursor, length=len(data) - cursor))
            break
        if marker in standalone:
            continue
        if cursor + 2 > len(data):
            issues.append(_issue("jpeg-truncated-length", "JPEG segment length is truncated", "A two-byte segment length is not fully present.", "error", offset=cursor, length=len(data) - cursor))
            break
        segment_length = int.from_bytes(data[cursor:cursor + 2], "big")
        if segment_length < 2:
            issues.append(_issue("jpeg-segment-length", "JPEG segment length is invalid", "Segment lengths include their two length bytes and cannot be below two.", "error", offset=cursor, length=2, expected=">= 2", actual=str(segment_length)))
            break
        segment_end = cursor + segment_length
        if segment_end > len(data):
            issues.append(_issue("jpeg-truncated-segment", "JPEG segment exceeds the file", "The declared segment length runs past the end of the artifact.", "error", offset=marker_offset, length=len(data) - marker_offset, expected=f"{segment_length} bytes", actual=f"{len(data) - cursor} available"))
            break
        if marker in frame_markers:
            saw_frame = True
            if segment_length >= 8:
                height = int.from_bytes(data[cursor + 3:cursor + 5], "big")
                width = int.from_bytes(data[cursor + 5:cursor + 7], "big")
                if width == 0 or height == 0:
                    issues.append(_issue("jpeg-dimensions", "JPEG frame dimensions are invalid", "JPEG width and height must both be greater than zero.", "error", offset=cursor + 3, length=4, actual=f"{width} × {height}"))
        cursor = segment_end
        if marker != 0xDA:
            continue
        saw_scan = True
        while cursor < len(data):
            found = data.find(b"\xff", cursor)
            if found < 0:
                cursor = len(data)
                break
            if found + 1 >= len(data):
                cursor = len(data)
                break
            code = data[found + 1]
            if code == 0x00 or 0xD0 <= code <= 0xD7:
                cursor = found + 2
                continue
            if code == 0xFF:
                cursor = found + 1
                continue
            cursor = found
            break
    if marker_count >= MAX_STRUCTURE_ITEMS:
        complete = False
        issues.append(_issue("jpeg-check-limit", "JPEG marker check reached its safety limit", "The remaining marker structure was not validated.", "warning", offset=cursor))
    if not saw_frame:
        issues.append(_issue("jpeg-missing-frame", "JPEG frame header is missing", "No supported start-of-frame segment was found.", "error", offset=2))
    if not saw_scan:
        issues.append(_issue("jpeg-missing-scan", "JPEG scan data is missing", "No start-of-scan segment was found.", "error", offset=2))
    if not saw_eoi:
        issues.append(_issue("jpeg-missing-eoi", "JPEG end marker is missing", "The JPEG does not end with a parsed FF D9 marker.", "error", offset=max(0, len(data) - 2), length=min(2, len(data))))
    checks.append(_check("markers", "failed" if any(item["severity"] == "error" for item in issues) else "passed", f"Inspected {marker_count:,} JPEG marker(s)."))
    return issues, checks, complete


def _consume_gif_subblocks(data: bytes, cursor: int) -> tuple[int, bool]:
    count = 0
    while cursor < len(data) and count < MAX_STRUCTURE_ITEMS:
        size = data[cursor]
        cursor += 1
        if size == 0:
            return cursor, True
        if cursor + size > len(data):
            return len(data), False
        cursor += size
        count += 1
    return cursor, False


def _validate_gif(data: bytes) -> tuple[list[dict[str, Any]], list[dict[str, str]], bool]:
    issues: list[dict[str, Any]] = []
    checks: list[dict[str, str]] = []
    if not data.startswith((b"GIF87a", b"GIF89a")):
        issues.append(_issue("gif-signature", "GIF signature is missing", "A GIF must begin with GIF87a or GIF89a.", "error", offset=0, length=min(6, len(data)), expected="GIF87a or GIF89a", actual=data[:6].decode("ascii", "replace")))
        return issues, [_check("blocks", "failed", "GIF signature mismatch.")], True
    if len(data) < 13:
        issues.append(_issue("gif-truncated-header", "GIF logical screen descriptor is truncated", "At least 13 bytes are required for the GIF header and screen descriptor.", "error", offset=6, length=max(0, len(data) - 6)))
        return issues, [_check("blocks", "failed", "GIF header is truncated.")], True
    width = int.from_bytes(data[6:8], "little")
    height = int.from_bytes(data[8:10], "little")
    if width == 0 or height == 0:
        issues.append(_issue("gif-dimensions", "GIF dimensions are invalid", "Logical width and height must both be greater than zero.", "error", offset=6, length=4, actual=f"{width} × {height}"))
    packed = data[10]
    cursor = 13
    if packed & 0x80:
        cursor += 3 * (2 ** ((packed & 0x07) + 1))
    if cursor > len(data):
        issues.append(_issue("gif-color-table", "GIF global color table is truncated", "The declared global color table runs past the file.", "error", offset=13, length=max(0, len(data) - 13)))
        return issues, [_check("blocks", "failed", "GIF global color table is incomplete.")], True
    saw_image = False
    saw_trailer = False
    block_count = 0
    complete = True
    while cursor < len(data) and block_count < MAX_STRUCTURE_ITEMS:
        introducer = data[cursor]
        block_offset = cursor
        cursor += 1
        block_count += 1
        if introducer == 0x3B:
            saw_trailer = True
            if cursor < len(data):
                issues.append(_issue("gif-trailing-data", "Bytes follow the GIF trailer", "Trailing data may be intentional CTF content or an accidental append.", "warning", offset=cursor, length=len(data) - cursor))
            break
        if introducer == 0x21:
            if cursor >= len(data):
                issues.append(_issue("gif-truncated-extension", "GIF extension is truncated", "The extension label byte is missing.", "error", offset=block_offset, length=1))
                break
            cursor += 1
            cursor, ok = _consume_gif_subblocks(data, cursor)
            if not ok:
                issues.append(_issue("gif-truncated-extension", "GIF extension data is truncated", "An extension data sub-block runs past the file or lacks a terminator.", "error", offset=block_offset, length=len(data) - block_offset))
                break
            continue
        if introducer == 0x2C:
            saw_image = True
            if cursor + 9 > len(data):
                issues.append(_issue("gif-truncated-image", "GIF image descriptor is truncated", "The image descriptor requires nine bytes after its separator.", "error", offset=block_offset, length=len(data) - block_offset))
                break
            local_packed = data[cursor + 8]
            cursor += 9
            if local_packed & 0x80:
                cursor += 3 * (2 ** ((local_packed & 0x07) + 1))
            if cursor >= len(data):
                issues.append(_issue("gif-truncated-image", "GIF image data is truncated", "The color table or LZW minimum code-size byte is missing.", "error", offset=block_offset, length=len(data) - block_offset))
                break
            cursor += 1
            cursor, ok = _consume_gif_subblocks(data, cursor)
            if not ok:
                issues.append(_issue("gif-truncated-image", "GIF image sub-block is truncated", "Image data runs past the file or lacks a zero terminator.", "error", offset=block_offset, length=len(data) - block_offset))
                break
            continue
        issues.append(_issue("gif-invalid-block", "GIF contains an unknown block introducer", "Expected an image, extension, or trailer block.", "error", offset=block_offset, length=1, expected="2c, 21, or 3b", actual=f"{introducer:02x}"))
        break
    if block_count >= MAX_STRUCTURE_ITEMS:
        complete = False
        issues.append(_issue("gif-check-limit", "GIF block check reached its safety limit", "The remaining block structure was not validated.", "warning", offset=cursor))
    if not saw_image:
        issues.append(_issue("gif-no-image", "GIF contains no image frame", "No image descriptor was found in the datastream.", "warning", offset=13))
    if not saw_trailer:
        issues.append(_issue("gif-missing-trailer", "GIF trailer is missing", "The GIF datastream does not contain its 3B terminator.", "error", offset=max(0, len(data) - 1)))
    checks.append(_check("blocks", "failed" if any(item["severity"] == "error" for item in issues) else "passed", f"Inspected {block_count:,} GIF block(s)."))
    return issues, checks, complete


def _validate_bmp(data: bytes) -> tuple[list[dict[str, Any]], list[dict[str, str]], bool]:
    issues: list[dict[str, Any]] = []
    if not data.startswith(b"BM"):
        issues.append(_issue("bmp-signature", "BMP signature is missing", "A bitmap file must begin with BM.", "error", offset=0, length=min(2, len(data)), expected="42 4d", actual=data[:2].hex(" ")))
        return issues, [_check("headers", "failed", "BMP signature mismatch.")], True
    if len(data) < 18:
        issues.append(_issue("bmp-truncated-header", "BMP header is truncated", "The file is too short to contain its file and DIB header sizes.", "error", offset=0, length=len(data)))
        return issues, [_check("headers", "failed", "BMP header is truncated.")], True
    declared_size = int.from_bytes(data[2:6], "little")
    pixel_offset = int.from_bytes(data[10:14], "little")
    dib_size = int.from_bytes(data[14:18], "little")
    if declared_size > len(data):
        issues.append(_issue("bmp-declared-size", "BMP is shorter than its declared size", "The file header claims more bytes than are present.", "error", offset=2, length=4, expected=str(declared_size), actual=str(len(data))))
    elif declared_size and declared_size < len(data):
        issues.append(_issue("bmp-trailing-data", "Bytes follow the declared BMP data", "The extra bytes may be embedded CTF data or an accidental append.", "warning", offset=declared_size, length=len(data) - declared_size))
    if dib_size < 12:
        issues.append(_issue("bmp-dib-size", "BMP DIB header size is invalid", "Known BMP DIB headers are at least 12 bytes.", "error", offset=14, length=4, expected=">= 12", actual=str(dib_size)))
    elif 14 + dib_size > len(data):
        issues.append(_issue("bmp-truncated-dib", "BMP DIB header is truncated", "The declared DIB header runs past the artifact.", "error", offset=14, length=len(data) - 14, expected=str(dib_size), actual=str(max(0, len(data) - 14))))
    if pixel_offset < 14 + min(dib_size, len(data)) or pixel_offset > len(data):
        issues.append(_issue("bmp-pixel-offset", "BMP pixel offset is invalid", "The pixel array offset points inside the headers or beyond the artifact.", "error", offset=10, length=4, expected=f"between {14 + dib_size} and {len(data)}", actual=str(pixel_offset)))
    if dib_size >= 12 and len(data) >= 14 + min(dib_size, 16):
        if dib_size == 12 and len(data) >= 22:
            width = int.from_bytes(data[18:20], "little")
            height = int.from_bytes(data[20:22], "little")
        elif len(data) >= 26:
            width = int.from_bytes(data[18:22], "little", signed=True)
            height = int.from_bytes(data[22:26], "little", signed=True)
        else:
            width = height = 0
        if width == 0 or height == 0:
            issues.append(_issue("bmp-dimensions", "BMP dimensions are invalid", "Bitmap width and height cannot be zero.", "error", offset=18, length=8 if dib_size != 12 else 4, actual=f"{width} × {height}"))
    checks = [_check("headers", "failed" if any(item["severity"] == "error" for item in issues) else "passed", "Checked BMP file, DIB, size, and pixel-offset fields.")]
    return issues, checks, True


def _validate_riff(data: bytes, form: bytes, label: str) -> tuple[list[dict[str, Any]], list[dict[str, str]], bool, list[tuple[bytes, int, int]]]:
    issues: list[dict[str, Any]] = []
    chunks: list[tuple[bytes, int, int]] = []
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != form:
        expected = f"RIFF … {form.decode('ascii', 'replace')}"
        issues.append(_issue(f"{label}-signature", f"{label.upper()} RIFF signature is missing", f"The file does not begin with {expected}.", "error", offset=0, length=min(12, len(data)), expected=expected, actual=data[:12].hex(" ")))
        return issues, [_check("riff", "failed", f"{label.upper()} RIFF signature mismatch.")], True, chunks
    declared_end = int.from_bytes(data[4:8], "little") + 8
    if declared_end > len(data):
        issues.append(_issue(f"{label}-riff-size", f"{label.upper()} RIFF container is truncated", "The RIFF size field extends past the artifact.", "error", offset=4, length=4, expected=str(declared_end), actual=str(len(data))))
    elif declared_end < len(data):
        issues.append(_issue(f"{label}-trailing-data", f"Bytes follow the {label.upper()} RIFF container", "Trailing bytes may be intentional embedded data or an accidental append.", "warning", offset=declared_end, length=len(data) - declared_end))
    boundary = min(len(data), declared_end)
    cursor = 12
    complete = True
    while cursor < boundary and len(chunks) < MAX_STRUCTURE_ITEMS:
        if cursor + 8 > boundary:
            issues.append(_issue(f"{label}-truncated-chunk-header", f"{label.upper()} chunk header is truncated", "Fewer than eight bytes remain for a RIFF chunk header.", "error", offset=cursor, length=boundary - cursor))
            break
        chunk_id = data[cursor:cursor + 4]
        size = int.from_bytes(data[cursor + 4:cursor + 8], "little")
        payload_offset = cursor + 8
        payload_end = payload_offset + size
        padded_end = payload_end + (size & 1)
        chunks.append((chunk_id, payload_offset, size))
        if payload_end > boundary:
            issues.append(_issue(f"{label}-truncated-chunk", f"{chunk_id.decode('ascii', 'replace')} chunk exceeds the RIFF container", "The chunk length runs past the declared RIFF boundary.", "error", offset=cursor, length=boundary - cursor, expected=str(size), actual=str(max(0, boundary - payload_offset))))
            break
        if padded_end > boundary:
            issues.append(_issue(f"{label}-missing-padding", f"{chunk_id.decode('ascii', 'replace')} chunk padding is missing", "Odd-length RIFF chunks require one padding byte.", "error", offset=payload_end, length=0))
            break
        cursor = padded_end
    if len(chunks) >= MAX_STRUCTURE_ITEMS:
        complete = False
        issues.append(_issue(f"{label}-check-limit", f"{label.upper()} chunk check reached its safety limit", "The remaining chunk structure was not validated.", "warning", offset=cursor))
    checks = [_check("riff", "failed" if any(item["severity"] == "error" for item in issues) else "passed", f"Inspected {len(chunks):,} RIFF chunk(s).")]
    return issues, checks, complete, chunks


def _validate_wav(data: bytes) -> tuple[list[dict[str, Any]], list[dict[str, str]], bool]:
    issues, checks, complete, chunks = _validate_riff(data, b"WAVE", "wav")
    fmt_chunks = [item for item in chunks if item[0] == b"fmt "]
    data_chunks = [item for item in chunks if item[0] == b"data"]
    block_align = 0
    if not fmt_chunks:
        issues.append(_issue("wav-missing-fmt", "WAV format chunk is missing", "A WAVE file requires a fmt chunk.", "error", offset=12))
    else:
        _, offset, size = fmt_chunks[0]
        if size < 16 or offset + 16 > len(data):
            issues.append(_issue("wav-fmt-size", "WAV format chunk is too short", "The common WAVE format fields require at least 16 bytes.", "error", offset=offset - 8, length=min(size + 8, max(0, len(data) - offset + 8)), expected=">= 16", actual=str(size)))
        else:
            audio_format, channels, sample_rate, byte_rate, block_align, bits = struct.unpack_from("<HHIIHH", data, offset)
            if audio_format == 0:
                issues.append(_issue("wav-audio-format", "WAV audio format code is invalid", "Format code zero is not defined for WAVE sample data.", "error", offset=offset, length=2, actual="0"))
            if channels == 0:
                issues.append(_issue("wav-channels", "WAV channel count is zero", "At least one audio channel is required.", "error", offset=offset + 2, length=2))
            if sample_rate == 0:
                issues.append(_issue("wav-sample-rate", "WAV sample rate is zero", "A playable WAVE stream requires a non-zero sample rate.", "error", offset=offset + 4, length=4))
            if block_align == 0:
                issues.append(_issue("wav-block-align", "WAV block alignment is zero", "Sample frames cannot have zero-byte alignment.", "error", offset=offset + 12, length=2))
            if byte_rate == 0 or (sample_rate and block_align and byte_rate != sample_rate * block_align):
                issues.append(_issue("wav-byte-rate", "WAV byte rate is inconsistent", "The byte-rate field should equal sample rate multiplied by block alignment.", "warning", offset=offset + 8, length=4, expected=str(sample_rate * block_align), actual=str(byte_rate)))
            if bits == 0:
                issues.append(_issue("wav-bit-depth", "WAV bit depth is zero", "Bits per sample must be non-zero for standard PCM-like data.", "warning", offset=offset + 14, length=2))
    if not data_chunks:
        issues.append(_issue("wav-missing-data", "WAV audio data chunk is missing", "No data chunk was found in the WAVE container.", "error", offset=12))
    elif block_align:
        _, offset, size = data_chunks[0]
        if size % block_align:
            issues.append(_issue("wav-partial-frame", "WAV data ends on a partial sample frame", "The data chunk length is not divisible by block alignment.", "warning", offset=offset + size - (size % block_align), length=size % block_align, expected=f"multiple of {block_align}", actual=str(size)))
    checks.append(_check("wave-fields", "failed" if any(item["severity"] == "error" for item in issues) else "passed", "Checked required WAVE chunks and core sample fields."))
    return issues, checks, complete


def _validate_webp(data: bytes) -> tuple[list[dict[str, Any]], list[dict[str, str]], bool]:
    issues, checks, complete, chunks = _validate_riff(data, b"WEBP", "webp")
    if not any(chunk_id in {b"VP8 ", b"VP8L", b"VP8X"} for chunk_id, _, _ in chunks):
        issues.append(_issue("webp-missing-image", "WebP image chunk is missing", "No VP8, VP8L, or VP8X image header chunk was found.", "error", offset=12))
    checks.append(_check("webp-image", "failed" if any(item["severity"] == "error" for item in issues) else "passed", "Checked the WebP RIFF image chunk."))
    return issues, checks, complete


def _validate_zip(data: bytes) -> tuple[list[dict[str, Any]], list[dict[str, str]], bool]:
    issues: list[dict[str, Any]] = []
    checks: list[dict[str, str]] = []
    search_start = max(0, len(data) - 65_557)
    eocd = data.rfind(b"PK\x05\x06", search_start)
    if eocd < 0:
        issues.append(_issue("zip-missing-eocd", "ZIP central-directory end record is missing", "No EOCD signature was found within the final 65,557 bytes.", "error", offset=max(0, len(data) - 22), length=min(22, len(data))))
        return issues, [_check("central-directory", "failed", "ZIP EOCD record was not found.")], True
    if eocd + 22 > len(data):
        issues.append(_issue("zip-truncated-eocd", "ZIP EOCD record is truncated", "The end record does not contain all fixed fields.", "error", offset=eocd, length=len(data) - eocd))
        return issues, [_check("central-directory", "failed", "ZIP EOCD record is incomplete.")], True
    disk_number, central_disk, disk_entries, total_entries, central_size, central_offset, comment_length = struct.unpack_from("<HHHHIIH", data, eocd + 4)
    if eocd + 22 + comment_length != len(data):
        if eocd + 22 + comment_length > len(data):
            issues.append(_issue("zip-comment-length", "ZIP comment is truncated", "The EOCD comment length extends past the artifact.", "error", offset=eocd + 20, length=2, expected=str(comment_length), actual=str(max(0, len(data) - eocd - 22))))
        else:
            issues.append(_issue("zip-trailing-data", "Bytes follow the ZIP end record", "Trailing data may be intentional challenge content or an accidental append.", "warning", offset=eocd + 22 + comment_length, length=len(data) - (eocd + 22 + comment_length)))
    if disk_number or central_disk or disk_entries != total_entries:
        issues.append(_issue("zip-multidisk", "ZIP uses multi-disk fields", "Multi-disk archives cannot be fully validated by this local check.", "warning", offset=eocd + 4, length=8, details={"disk": disk_number, "central_disk": central_disk, "entries_on_disk": disk_entries, "total_entries": total_entries}))
    if central_offset + central_size > eocd:
        issues.append(_issue("zip-central-bounds", "ZIP central directory has invalid bounds", "The declared central directory overlaps or extends beyond its end record.", "error", offset=eocd + 12, length=8, expected=f"end <= {eocd}", actual=str(central_offset + central_size)))
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) != total_entries and not (disk_number or central_disk):
                issues.append(_issue("zip-entry-count", "ZIP entry count does not match", "The parsed central-directory entry count differs from EOCD.", "error", offset=eocd + 10, length=2, expected=str(total_entries), actual=str(len(entries))))
            if len(entries) > MAX_STRUCTURE_ITEMS:
                issues.append(_issue("zip-check-limit", "ZIP entry check reached its safety limit", "Only the bounded central-directory structure was reviewed.", "warning", offset=central_offset))
    except (OSError, ValueError, zipfile.BadZipFile, NotImplementedError) as exc:
        issues.append(_issue("zip-parser", "ZIP central directory cannot be parsed", "Python's bounded ZIP metadata parser rejected the archive structure.", "error", offset=central_offset, length=min(central_size, max(0, len(data) - central_offset)), actual=type(exc).__name__))
    checks.append(_check("central-directory", "failed" if any(item["severity"] == "error" for item in issues) else "passed", f"Checked the ZIP EOCD and {total_entries:,} declared central-directory entry/entries."))
    return issues, checks, True


_VALIDATORS = {
    "png": _validate_png,
    "jpeg": _validate_jpeg,
    "gif": _validate_gif,
    "bmp": _validate_bmp,
    "webp": _validate_webp,
    "wav": _validate_wav,
    "zip": _validate_zip,
}


def diagnose_bytes(data: bytes, *, filename: str = "", declared_media_type: str = "") -> dict[str, Any]:
    """Return a conservative structural verdict independent of heuristic anomalies."""

    detected = detect_magic_kind(data)
    expected = expected_kind(filename, declared_media_type)
    issues: list[dict[str, Any]] = []
    checks: list[dict[str, str]] = []
    validation_kind = detected if detected in _VALIDATORS else expected if expected in _VALIDATORS else None
    if expected and detected and expected != detected:
        issues.append(_issue("format-mismatch", "Content does not match the expected format", "The detected byte signature differs from the artifact name or declared media type.", "warning", offset=0, length=min(12, len(data)), expected=expected, actual=detected))
    elif expected and detected is None:
        issues.append(_issue("missing-signature", f"Expected {expected.upper()} signature is missing", "The artifact name or media type identifies a known format, but its signature is absent.", "error", offset=0, length=min(12, len(data)), expected=_SIGNATURES.get(expected, expected), actual=data[:12].hex(" ")))
    if validation_kind:
        format_issues, format_checks, complete = _VALIDATORS[validation_kind](data)
        issues.extend(format_issues)
        checks.extend(format_checks)
        supported = True
    else:
        complete = False
        supported = False
        checks.append(_check("format-parser", "skipped", "No strict structural parser is available for these bytes."))
    errors = sum(1 for item in issues if item.get("severity") == "error")
    warnings = sum(1 for item in issues if item.get("severity") == "warning")
    if errors:
        verdict = "corrupt"
        summary = f"Found {errors} confirmed structural error{'s' if errors != 1 else ''}"
        if warnings:
            summary += f" and {warnings} warning{'s' if warnings != 1 else ''}"
        summary += "."
    elif warnings:
        verdict = "warning"
        summary = f"No confirmed structural break was found, but {warnings} warning{'s require' if warnings != 1 else ' requires'} review."
    elif supported and complete:
        verdict = "valid"
        summary = "No structural violation was found by the available format checks."
    else:
        verdict = "unknown"
        summary = "This format is not fully supported by the structural validator; no corruption verdict is claimed."
    return {
        "verdict": verdict,
        "expected_format": expected,
        "detected_format": detected,
        "validation_format": validation_kind,
        "validation_complete": bool(complete),
        "summary": summary,
        "issues": issues[:200],
        "checks": checks[:100],
    }


def diagnose_file(path: Path, *, filename: str = "", declared_media_type: str = "") -> dict[str, Any]:
    total_size = path.stat().st_size
    if total_size > MAX_LIVE_EDIT_BYTES:
        with path.open("rb") as handle:
            head = handle.read(64)
        detected = detect_magic_kind(head)
        return {
            "verdict": "unknown",
            "expected_format": expected_kind(filename or path.name, declared_media_type),
            "detected_format": detected,
            "validation_format": None,
            "validation_complete": False,
            "summary": f"Full structural validation is limited to {MAX_LIVE_EDIT_BYTES // (1024 * 1024)} MiB for responsive live editing.",
            "issues": [_issue("validation-size-limit", "Full integrity check was bounded", "The artifact exceeds the live editor's in-memory validation budget.", "info", offset=0, length=total_size)],
            "checks": [_check("format-parser", "skipped", "Artifact exceeds the live structural-validation budget.")],
        }
    return diagnose_bytes(path.read_bytes(), filename=filename or path.name, declared_media_type=declared_media_type)


def analyze_edited_file(
    path: Path,
    edits: Iterable[Mapping[str, Any]],
    *,
    filename: str = "",
    declared_media_type: str = "",
    revision: int = 0,
) -> dict[str, Any]:
    data, normalized = read_edited_bytes(path, edits)
    detected = detect_magic_kind(data)
    preview_kind = "image" if detected in _IMAGE_KINDS else "audio" if detected in _AUDIO_MIME else "none"
    return {
        "revision": max(0, int(revision)),
        "edited_size": len(data),
        "edit_count": len(normalized),
        "sha256": hashlib.sha256(data).hexdigest(),
        "integrity": diagnose_bytes(data, filename=filename or path.name, declared_media_type=declared_media_type),
        "preview": {
            "kind": preview_kind,
            "available": preview_kind != "none",
            "media_type": "image/png" if preview_kind == "image" else _AUDIO_MIME.get(detected or ""),
            "message": "The edited bytes can be rendered live." if preview_kind != "none" else "No safe browser preview is available for this byte signature.",
        },
    }


def render_edited_preview(
    path: Path,
    edits: Iterable[Mapping[str, Any]],
) -> tuple[bytes, str, str]:
    """Return a safe preview payload, re-encoding images as PNG."""

    data, _normalized = read_edited_bytes(path, edits)
    kind = detect_magic_kind(data)
    if kind in _IMAGE_KINDS:
        try:
            with Image.open(io.BytesIO(data)) as probe:
                width, height = probe.size
                if width <= 0 or height <= 0 or width * height > MAX_PREVIEW_PIXELS:
                    raise PreviewUnavailableError("Edited image dimensions exceed the safe preview budget.")
                probe.verify()
            with Image.open(io.BytesIO(data)) as image:
                image.seek(0)
                image.load()
                image.thumbnail((MAX_PREVIEW_EDGE, MAX_PREVIEW_EDGE), Image.Resampling.LANCZOS)
                rendered = image.convert("RGBA" if "A" in image.getbands() else "RGB")
                output = io.BytesIO()
                rendered.save(output, format="PNG", optimize=False)
                return output.getvalue(), "image/png", "image"
        except PreviewUnavailableError:
            raise
        except (OSError, ValueError, SyntaxError, UnidentifiedImageError, Image.DecompressionBombError) as exc:
            raise PreviewUnavailableError("The edited image cannot be decoded into a safe live preview yet.") from exc
    if kind in _AUDIO_MIME:
        return data, _AUDIO_MIME[kind], "audio"
    raise PreviewUnavailableError("These edited bytes do not have a supported image or audio signature.")
