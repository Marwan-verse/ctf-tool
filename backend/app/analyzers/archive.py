"""Bounded helpers for recovering embedded ZIP archives.

ZIP-family containers (including OOXML/DOCX) can carry bytes in a local file
header's extra field that are not represented in the central-directory extra
field.  The stdlib ``zipfile`` API intentionally exposes the latter, so this
module performs a small, read-only local-header pass before normal archive
traversal.

All functions in this module validate candidate ZIP structure and enforce
member/size/ratio limits before returning bytes.  They never extract files or
interpret archive member names as paths.
"""

from __future__ import annotations

import io
import struct
import zipfile
from typing import Any


_ZIP_LOCAL_SIGNATURE = b"PK\x03\x04"
_ZIP_CENTRAL_SIGNATURE = b"PK\x01\x02"
_ZIP_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP_LOCAL_HEADER_SIZE = 30
_ZIP_EOCD_SIZE = 22
_MAX_LOCAL_EXTRA = 65_535


def trim_zip_archive(
    data: bytes,
    *,
    max_size: int,
    max_entries: int = 1_000,
    max_member_size: int = 192 * 1024 * 1024,
    max_total_size: int = 512 * 1024 * 1024,
    max_ratio: int = 2_000,
) -> tuple[bytes, dict[str, int]] | None:
    """Return a validated ZIP prefix, trimming unrelated trailing bytes.

    The first valid EOCD is selected.  Each EOCD-looking byte sequence is
    checked against central-directory bounds and then opened with the stdlib
    metadata parser.  No member data is decompressed here; the same bounded
    checks are repeated by the engine before a member is read.
    """

    if not isinstance(data, bytes) or not data or max_size <= 0:
        return None
    bounded = data[: min(len(data), max_size)]
    if len(bounded) < _ZIP_LOCAL_HEADER_SIZE or bounded[:4] != _ZIP_LOCAL_SIGNATURE:
        return None

    cursor = 0
    while True:
        eocd = bounded.find(_ZIP_EOCD_SIGNATURE, cursor)
        if eocd < 0:
            return None
        cursor = eocd + 1
        if eocd + _ZIP_EOCD_SIZE > len(bounded):
            continue
        try:
            (
                signature,
                disk_number,
                central_disk,
                entries_on_disk,
                total_entries,
                central_size,
                central_offset,
                comment_length,
            ) = struct.unpack_from("<4s4H2LH", bounded, eocd)
        except struct.error:
            continue
        if signature != _ZIP_EOCD_SIGNATURE:
            continue
        if disk_number != 0 or central_disk != 0 or entries_on_disk != total_entries:
            continue
        end = eocd + _ZIP_EOCD_SIZE + comment_length
        if end > len(bounded):
            continue
        if central_offset < 0 or central_size < 0 or central_offset + central_size > eocd:
            continue
        if total_entries and (central_offset + 4 > len(bounded) or bounded[central_offset:central_offset + 4] != _ZIP_CENTRAL_SIGNATURE):
            continue

        candidate = bounded[:end]
        try:
            with zipfile.ZipFile(io.BytesIO(candidate)) as archive:
                infos = archive.infolist()
        except (OSError, ValueError, zipfile.BadZipFile):
            continue
        if len(infos) != total_entries or len(infos) > max_entries:
            continue
        expanded_total = 0
        safe = True
        for info in infos:
            if info.file_size < 0 or info.compress_size < 0:
                safe = False
                break
            if info.file_size > max_member_size:
                safe = False
                break
            if info.compress_size and info.file_size / max(1, info.compress_size) > max_ratio:
                safe = False
                break
            expanded_total += info.file_size
            if expanded_total > max_total_size:
                safe = False
                break
        if not safe:
            continue
        return candidate, {
            "archive_size": len(candidate),
            "eocd_offset": eocd,
            "comment_length": comment_length,
            "entry_count": total_entries,
            "expanded_bytes": expanded_total,
        }


def carve_zip_local_header_extras(
    data: bytes,
    *,
    max_candidates: int = 16,
    max_extra_bytes: int = _MAX_LOCAL_EXTRA,
    max_archive_size: int = 192 * 1024 * 1024,
    max_entries: int = 1_000,
    max_member_size: int = 192 * 1024 * 1024,
    max_total_size: int = 512 * 1024 * 1024,
    max_ratio: int = 2_000,
) -> list[dict[str, Any]]:
    """Find validated ZIPs stored inside local-file-header extra fields.

    The outer archive's central directory is used only to locate legitimate
    local headers.  The local extra bytes are treated as opaque data and are
    scanned for ZIP local-header signatures; this also handles malformed or
    non-TLV padding before the embedded archive, as used by several CTFs.
    """

    if not isinstance(data, bytes) or len(data) < _ZIP_LOCAL_HEADER_SIZE or max_candidates <= 0:
        return []
    max_extra_bytes = max(0, min(int(max_extra_bytes), _MAX_LOCAL_EXTRA))
    if max_extra_bytes == 0:
        return []

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as outer:
            infos = outer.infolist()
    except (OSError, ValueError, zipfile.BadZipFile):
        return []

    recovered: list[dict[str, Any]] = []
    seen: set[bytes] = set()
    for info in infos[:max_entries]:
        if len(recovered) >= max_candidates:
            break
        header_offset = int(getattr(info, "header_offset", -1))
        if header_offset < 0 or header_offset + _ZIP_LOCAL_HEADER_SIZE > len(data):
            continue
        try:
            (
                signature,
                _version,
                _flags,
                _method,
                _modified_time,
                _modified_date,
                _crc,
                _compressed_size,
                _uncompressed_size,
                name_length,
                extra_length,
            ) = struct.unpack_from("<4s5H3L2H", data, header_offset)
        except struct.error:
            continue
        if signature != _ZIP_LOCAL_SIGNATURE:
            continue
        if extra_length <= 0 or extra_length > max_extra_bytes:
            continue
        extra_start = header_offset + _ZIP_LOCAL_HEADER_SIZE + name_length
        extra_end = extra_start + extra_length
        if extra_start < 0 or extra_end > len(data):
            continue

        extra = data[extra_start:extra_end]
        cursor = 0
        while len(recovered) < max_candidates:
            relative = extra.find(_ZIP_LOCAL_SIGNATURE, cursor)
            if relative < 0:
                break
            cursor = relative + 1
            embedded_offset = extra_start + relative
            trimmed = trim_zip_archive(
                data[embedded_offset:],
                max_size=max_archive_size,
                max_entries=max_entries,
                max_member_size=max_member_size,
                max_total_size=max_total_size,
                max_ratio=max_ratio,
            )
            if trimmed is None:
                continue
            candidate, details = trimmed
            if candidate in seen:
                continue
            seen.add(candidate)
            recovered.append({
                "data": candidate,
                "offset": embedded_offset,
                "extra_offset": extra_start,
                "extra_length": extra_length,
                "header_offset": header_offset,
                "outer_member": str(getattr(info, "filename", "")),
                **details,
            })
    return recovered

