from __future__ import annotations

import hashlib
import math
import mimetypes
import os
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator


PROFILE_LIMITS: dict[str, dict[str, int]] = {
    "quick": {
        "read_bytes": 32 * 1024 * 1024,
        "max_strings": 5_000,
        "max_artifacts": 45,
        "max_artifact_bytes": 192 * 1024 * 1024,
        "max_single_artifact": 48 * 1024 * 1024,
        "decode_depth": 2,
        "decode_nodes": 30,
        "recursion_depth": 2,
        "tool_timeout": 20,
        "visual_megapixels": 24,
    },
    "balanced": {
        "read_bytes": 96 * 1024 * 1024,
        "max_strings": 15_000,
        "max_artifacts": 100,
        "max_artifact_bytes": 500 * 1024 * 1024,
        "max_single_artifact": 96 * 1024 * 1024,
        "decode_depth": 3,
        "decode_nodes": 100,
        "recursion_depth": 3,
        "tool_timeout": 60,
        "visual_megapixels": 40,
    },
    "deep": {
        "read_bytes": 192 * 1024 * 1024,
        "max_strings": 40_000,
        "max_artifacts": 220,
        "max_artifact_bytes": 1024 * 1024 * 1024,
        "max_single_artifact": 192 * 1024 * 1024,
        "decode_depth": 4,
        "decode_nodes": 300,
        "recursion_depth": 4,
        "tool_timeout": 180,
        "visual_megapixels": 64,
    },
}


MIME_BY_KIND = {
    "png": "image/png",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "bmp": "image/bmp",
    "webp": "image/webp",
    "tiff": "image/tiff",
    "ico": "image/x-icon",
    "wav": "audio/wav",
    "aiff": "audio/aiff",
    "flac": "audio/flac",
    "ogg": "audio/ogg",
    "mp3": "audio/mpeg",
    "aac": "audio/aac",
    "m4a": "audio/mp4",
    "au": "audio/basic",
    "asf": "audio/x-ms-wma",
    "amr": "audio/amr",
    "caf": "audio/x-caf",
    "midi": "audio/midi",
    "zip": "application/zip",
    "gzip": "application/gzip",
    "zlib": "application/zlib",
    "bzip2": "application/x-bzip2",
    "xz": "application/x-xz",
    "zstd": "application/zstd",
    "pdf": "application/pdf",
    "text": "text/plain",
    "binary": "application/octet-stream",
}


class AnalyzerCancelled(RuntimeError):
    """Raised at a cooperative cancellation boundary."""


def cancel_requested(check: Any) -> bool:
    if check is None:
        return False
    try:
        if callable(check):
            return bool(check())
        if hasattr(check, "is_set"):
            return bool(check.is_set())
        return bool(check)
    except Exception:
        # A broken UI callback must not silently cancel a forensic job.
        return False


def check_cancelled(check: Any) -> None:
    if cancel_requested(check):
        raise AnalyzerCancelled("analysis cancelled")


def utc_now() -> str:
    # Millisecond precision is enough for an audit report and is stable JSON.
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int(time.time_ns() / 1_000_000) % 1000:03d}Z"


def sha256_file(path: os.PathLike[str] | str, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bounded_read(path: os.PathLike[str] | str, maximum: int) -> tuple[bytes, bool]:
    with open(path, "rb") as handle:
        data = handle.read(maximum + 1)
    return data[:maximum], len(data) > maximum


def sniff_kind(data: bytes, filename: str = "") -> str:
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
    if len(data) >= 12 and data[:4] == b"FORM" and data[8:12] in {b"AIFF", b"AIFC"}:
        return "aiff"
    if data.startswith(b"fLaC"):
        return "flac"
    if data.startswith(b"OggS"):
        return "ogg"
    if data.startswith(b"ID3") or (len(data) >= 2 and data[0] == 0xFF and data[1] & 0xE6 == 0xE2):
        return "mp3"
    if len(data) >= 2 and data[0] == 0xFF and data[1] & 0xF6 == 0xF0:
        return "aac"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return "m4a"
    if data.startswith(b".snd"):
        return "au"
    if data.startswith(b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c"):
        return "asf"
    if data.startswith(b"#!AMR\n"):
        return "amr"
    if data.startswith(b"caff"):
        return "caf"
    if data.startswith(b"MThd"):
        return "midi"
    if data.startswith((b"II*\x00", b"MM\x00*", b"II+\x00", b"MM\x00+")):
        return "tiff"
    if data.startswith(b"\x00\x00\x01\x00") or data.startswith(b"\x00\x00\x02\x00"):
        return "ico"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        return "zip"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if len(data) >= 2 and data[0] == 0x78 and ((data[0] << 8) + data[1]) % 31 == 0:
        return "zlib"
    if data.startswith(b"BZh"):
        return "bzip2"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if data.startswith(b"(\xb5/\xfd"):
        return "zstd"
    if data.startswith(b"%PDF-"):
        return "pdf"
    markup_head = data[:8192].lstrip(b"\xef\xbb\xbf\x00\t\r\n ").lower()
    if b"<svg" in markup_head and (markup_head.startswith((b"<svg", b"<?xml", b"<!--"))):
        return "svg"
    if data and _looks_textual(data[:8192]):
        return "text"
    extension = Path(filename).suffix.lower()
    return {
        ".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".jpe": "jpeg",
        ".gif": "gif", ".bmp": "bmp", ".webp": "webp", ".svg": "svg",
        ".tif": "tiff", ".tiff": "tiff", ".ico": "ico", ".cur": "ico",
        ".wav": "wav", ".wave": "wav", ".aif": "aiff", ".aiff": "aiff", ".aifc": "aiff",
        ".flac": "flac", ".ogg": "ogg", ".oga": "ogg", ".opus": "ogg",
        ".mp3": "mp3", ".aac": "aac", ".m4a": "m4a", ".mp4": "m4a",
        ".au": "au", ".snd": "au", ".wma": "asf", ".amr": "amr", ".caf": "caf",
        ".mid": "midi", ".midi": "midi",
    }.get(extension, "binary")


def mime_for(kind: str, filename: str = "") -> str:
    return MIME_BY_KIND.get(kind) or mimetypes.guess_type(filename)[0] or "application/octet-stream"


def extension_for(kind: str) -> str:
    return {
        "png": ".png", "jpeg": ".jpg", "gif": ".gif", "bmp": ".bmp",
        "webp": ".webp", "svg": ".svg", "tiff": ".tiff", "ico": ".ico", "zip": ".zip",
        "wav": ".wav", "aiff": ".aiff", "flac": ".flac", "ogg": ".ogg",
        "mp3": ".mp3", "aac": ".aac", "m4a": ".m4a", "au": ".au",
        "asf": ".wma", "amr": ".amr", "caf": ".caf", "midi": ".mid",
        "gzip": ".gz", "zlib": ".zlib", "bzip2": ".bz2", "xz": ".xz", "zstd": ".zst",
        "pdf": ".pdf", "text": ".txt",
    }.get(kind, ".bin")


def safe_label(value: str, maximum: int = 80) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip()).strip("._")
    return (value or "artifact")[:maximum]


def display_text(value: Any, maximum: int = 4096) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    value = str(value).replace("\x00", "\\0")
    # Keep tabs/newlines; remove terminal control sequences and bidi controls.
    value = "".join(ch for ch in value if ch in "\n\r\t" or (ord(ch) >= 32 and ch not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"))
    return value[:maximum]


def byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_textual(data: bytes) -> bool:
    if not data:
        return False
    acceptable = sum(1 for byte in data if byte in (9, 10, 13) or 32 <= byte <= 126)
    return acceptable / len(data) >= 0.88


def iter_ascii_strings(data: bytes, minimum: int = 4, limit: int = 10_000) -> Iterator[dict[str, Any]]:
    emitted = 0
    start: int | None = None
    for index, byte in enumerate(data + b"\x00"):
        if 32 <= byte <= 126 or byte == 9:
            if start is None:
                start = index
        elif start is not None:
            if index - start >= minimum:
                yield {"encoding": "ascii", "offset": start, "text": data[start:index].decode("ascii", "replace")}
                emitted += 1
                if emitted >= limit:
                    return
            start = None


def iter_utf16_strings(data: bytes, minimum: int = 4, limit: int = 5_000) -> Iterator[dict[str, Any]]:
    emitted = 0
    for endian in ("little", "big"):
        for parity in (0, 1):
            index = parity
            start: int | None = None
            chars: list[str] = []
            while index + 1 < len(data):
                code = int.from_bytes(data[index:index + 2], endian)
                if 32 <= code <= 126 or code == 9:
                    if start is None:
                        start = index
                    chars.append(chr(code))
                else:
                    if start is not None and len(chars) >= minimum:
                        yield {
                            "encoding": "utf-16-le" if endian == "little" else "utf-16-be",
                            "offset": start,
                            "text": "".join(chars),
                        }
                        emitted += 1
                        if emitted >= limit:
                            return
                    start = None
                    chars = []
                index += 2
            if start is not None and len(chars) >= minimum:
                yield {
                    "encoding": "utf-16-le" if endian == "little" else "utf-16-be",
                    "offset": start,
                    "text": "".join(chars),
                }
                emitted += 1
                if emitted >= limit:
                    return


def find_magic_offsets(data: bytes, maximum_per_kind: int = 20) -> list[dict[str, Any]]:
    signatures = {
        "png": b"\x89PNG\r\n\x1a\n", "jpeg": b"\xff\xd8\xff", "gif87a": b"GIF87a",
        "gif89a": b"GIF89a", "zip": b"PK\x03\x04", "pdf": b"%PDF-",
        "gzip": b"\x1f\x8b\x08", "bzip2": b"BZh", "xz": b"\xfd7zXZ\x00",
        "7zip": b"7z\xbc\xaf'\x1c", "rar": b"Rar!\x1a\x07", "sqlite": b"SQLite format 3\x00",
    }
    hits: list[dict[str, Any]] = []
    for name, signature in signatures.items():
        start = 0
        for _ in range(maximum_per_kind):
            offset = data.find(signature, start)
            if offset < 0:
                break
            hits.append({"kind": name, "offset": offset, "signature_hex": signature.hex()})
            start = offset + 1
    return sorted(hits, key=lambda item: (item["offset"], item["kind"]))


def normalize_json(value: Any, depth: int = 0) -> Any:
    """Convert third-party metadata values into deterministic JSON primitives."""
    if depth > 8:
        return display_text(value, 256)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {"encoding": "hex", "value": value[:256].hex(), "truncated": len(value) > 256}
    if isinstance(value, dict):
        return {display_text(key, 128): normalize_json(val, depth + 1) for key, val in list(value.items())[:500]}
    if isinstance(value, (list, tuple, set)):
        return [normalize_json(item, depth + 1) for item in list(value)[:500]]
    return display_text(value)


def iter_chunks(iterable: Iterable[Any], size: int) -> Iterator[list[Any]]:
    bucket: list[Any] = []
    for item in iterable:
        bucket.append(item)
        if len(bucket) == size:
            yield bucket
            bucket = []
    if bucket:
        yield bucket
