"""Bounded byte inspection for the Hex results view."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any, Iterator

from .analyzers.common import find_magic_offsets


MAX_WINDOW_BYTES = 64 * 1024
MAX_SEARCH_BYTES = 256
MAX_SEARCH_MATCHES = 100
MAX_ANOMALIES = 80
CHUNK_BYTES = 64 * 1024
ENTROPY_BLOCK_BYTES = 4096
ZERO_RUN_THRESHOLD = 96
REPEATED_RUN_THRESHOLD = 128
_HEX_SEARCH_RE = re.compile(r"^[0-9a-fA-F]+$")


def parse_search(value: str | None, mode: str) -> bytes:
    """Parse a bounded text or hexadecimal search needle."""

    if value is None or not value.strip():
        return b""
    if mode not in {"text", "hex"}:
        raise ValueError("Search mode must be text or hex.")
    if mode == "text":
        encoded = value.encode("utf-8")
        if len(encoded) > MAX_SEARCH_BYTES:
            raise ValueError(f"Text searches are limited to {MAX_SEARCH_BYTES} bytes.")
        return encoded
    compact = re.sub(r"[\s:_-]", "", value)
    if not compact or len(compact) % 2 or len(compact) > MAX_SEARCH_BYTES * 2 or not _HEX_SEARCH_RE.fullmatch(compact):
        raise ValueError("Hex searches must contain an even number of hexadecimal digits.")
    return bytes.fromhex(compact)


def _iter_chunks(path: Path, chunk_size: int = CHUNK_BYTES) -> Iterator[tuple[int, bytes]]:
    with path.open("rb") as handle:
        offset = 0
        while chunk := handle.read(chunk_size):
            yield offset, chunk
            offset += len(chunk)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def scan_anomalies(path: Path, *, maximum: int = MAX_ANOMALIES) -> list[dict[str, Any]]:
    """Find bounded byte-pattern anomalies without materializing the file."""

    anomalies: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    carry = b""
    run_value: int | None = None
    run_start = 0
    run_length = 0

    def add(item: dict[str, Any]) -> bool:
        key = (str(item["kind"]), int(item["offset"]))
        if key in seen:
            return False
        seen.add(key)
        anomalies.append(item)
        return len(anomalies) >= max(1, min(MAX_ANOMALIES, maximum))

    for chunk_offset, chunk in _iter_chunks(path):
        block = carry + chunk
        block_offset = chunk_offset - len(carry)
        for index, value in enumerate(chunk):
            if value == run_value:
                run_length += 1
                continue
            if run_value is not None and run_length >= (ZERO_RUN_THRESHOLD if run_value == 0 else REPEATED_RUN_THRESHOLD):
                if run_value == 0:
                    item = {
                        "kind": "long-zero-run",
                        "title": "Long zero run",
                        "description": f"{run_length:,} consecutive 0x00 bytes may indicate padding, a cleared region, or an empty channel.",
                        "offset": run_start,
                        "length": run_length,
                        "severity": "warning",
                        "details": {"byte": "00", "run_length": run_length},
                    }
                else:
                    item = {
                        "kind": "repeated-byte-run",
                        "title": "Repeated-byte run",
                        "description": f"{run_length:,} consecutive 0x{run_value:02x} bytes may indicate padding or an unusual encoded region.",
                        "offset": run_start,
                        "length": run_length,
                        "severity": "info",
                        "details": {"byte": f"{run_value:02x}", "run_length": run_length},
                    }
                if add(item):
                    return sorted(anomalies, key=lambda value: (int(value["offset"]), str(value["kind"])))[:maximum]
            run_value = value
            run_start = chunk_offset + index
            run_length = 1
        for hit in find_magic_offsets(block, maximum_per_kind=4):
            local_offset = int(hit["offset"])
            absolute_offset = block_offset + local_offset
            if absolute_offset <= 0:
                continue
            item = {
                "kind": "embedded-signature",
                "title": f"Embedded {hit['kind']} signature",
                "description": f"A {hit['kind']} file signature appears at byte offset 0x{absolute_offset:x} inside this artifact.",
                "offset": absolute_offset,
                "length": len(bytes.fromhex(str(hit["signature_hex"]))),
                "severity": "warning",
                "details": {"signature": hit["signature_hex"], "format": hit["kind"]},
            }
            if add(item):
                return sorted(anomalies, key=lambda value: (int(value["offset"]), str(value["kind"])))[:maximum]
        for local_offset in range(0, len(chunk), ENTROPY_BLOCK_BYTES):
            entropy_block = chunk[local_offset:local_offset + ENTROPY_BLOCK_BYTES]
            if len(entropy_block) < ENTROPY_BLOCK_BYTES:
                continue
            score = _entropy(entropy_block)
            if score < 7.65:
                continue
            item = {
                "kind": "high-entropy-region",
                "title": "High-entropy region",
                "description": f"A 4 KiB block has {score:.2f} bits/byte of entropy; encrypted or compressed data may be present.",
                "offset": chunk_offset + local_offset,
                "length": len(entropy_block),
                "severity": "info",
                "details": {"entropy_bits_per_byte": round(score, 3), "window_bytes": len(entropy_block)},
            }
            if add(item):
                return sorted(anomalies, key=lambda value: (int(value["offset"]), str(value["kind"])))[:maximum]
        carry = block[-255:]
    if run_value is not None and run_length >= (ZERO_RUN_THRESHOLD if run_value == 0 else REPEATED_RUN_THRESHOLD):
        item = {
            "kind": "long-zero-run" if run_value == 0 else "repeated-byte-run",
            "title": "Long zero run" if run_value == 0 else "Repeated-byte run",
            "description": (
                f"{run_length:,} consecutive 0x00 bytes may indicate padding, a cleared region, or an empty channel."
                if run_value == 0
                else f"{run_length:,} consecutive 0x{run_value:02x} bytes may indicate padding or an unusual encoded region."
            ),
            "offset": run_start,
            "length": run_length,
            "severity": "warning" if run_value == 0 else "info",
            "details": {"byte": f"{run_value:02x}", "run_length": run_length},
        }
        add(item)
    return sorted(anomalies, key=lambda value: (int(value["offset"]), str(value["kind"])))[:max(1, min(MAX_ANOMALIES, maximum))]


def find_matches(path: Path, needle: bytes, *, maximum: int = MAX_SEARCH_MATCHES) -> list[dict[str, int]]:
    """Search the complete artifact with a small overlap between chunks."""

    if not needle:
        return []
    matches: list[dict[str, int]] = []
    seen_offsets: set[int] = set()
    carry = b""
    overlap = max(0, len(needle) - 1)
    for chunk_offset, chunk in _iter_chunks(path, chunk_size=1024 * 1024):
        block = carry + chunk
        block_offset = chunk_offset - len(carry)
        start = 0
        while len(matches) < maximum:
            found = block.find(needle, start)
            if found < 0:
                break
            absolute_offset = block_offset + found
            if absolute_offset not in seen_offsets:
                matches.append({"offset": absolute_offset, "length": len(needle)})
                seen_offsets.add(absolute_offset)
            start = found + 1
        if len(matches) >= maximum:
            break
        carry = block[-overlap:] if overlap else b""
    return matches


def _rows(data: bytes, base_offset: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for local_offset in range(0, len(data), 16):
        chunk = data[local_offset:local_offset + 16]
        rows.append(
            {
                "offset": base_offset + local_offset,
                "hex": " ".join(f"{byte:02x}" for byte in chunk),
                "bytes": list(chunk),
                "ascii": "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk),
                "length": len(chunk),
            }
        )
    return rows


def inspect_file(
    path: Path,
    *,
    offset: int = 0,
    length: int = 8192,
    search: str | None = None,
    search_mode: str = "text",
    include_anomalies: bool = True,
    filename: str = "",
    declared_media_type: str = "",
) -> dict[str, Any]:
    """Return a bounded hex window, whole-file matches, anomaly hints, and integrity."""

    total_size = path.stat().st_size
    bounded_offset = max(0, min(int(offset), total_size))
    bounded_length = max(16, min(MAX_WINDOW_BYTES, int(length)))
    with path.open("rb") as handle:
        handle.seek(bounded_offset)
        data = handle.read(min(bounded_length, max(0, total_size - bounded_offset)))
    needle = parse_search(search, search_mode)
    matches = find_matches(path, needle) if needle else []
    anomalies = scan_anomalies(path) if include_anomalies else []
    # Integrity is intentionally independent from heuristic anomaly signals:
    # zero runs, entropy changes, and embedded signatures are useful leads but
    # are not evidence that a file is structurally corrupt.
    from .hexedit import diagnose_file

    integrity = diagnose_file(path, filename=filename or path.name, declared_media_type=declared_media_type)
    return {
        "offset": bounded_offset,
        "length": len(data),
        "total_size": total_size,
        "rows": _rows(data, bounded_offset),
        "matches": matches,
        "anomalies": anomalies,
        "search": {"query": search or "", "mode": search_mode, "byte_length": len(needle), "match_count": len(matches)},
        "anomaly_scan": {"enabled": bool(include_anomalies), "count": len(anomalies), "bounded": True},
        "integrity": integrity,
    }
