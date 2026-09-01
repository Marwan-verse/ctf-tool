"""Bounded parsers for common endpoint and mobile CTF forensic artifacts."""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import lzma
import math
import plistlib
import re
import struct
import time
import zlib
from typing import Any

from .common import display_text, iter_ascii_strings, iter_utf16_strings, sniff_kind
from .compression import CompressionError, decompress_mozlz4


def _result(kind: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "properties": {},
        "metadata": {},
        "findings": [],
        "text_records": [],
        "extracted": [],
        "repairs": [],
    }


def _finding(severity: str, category: str, title: str, description: str, **details: Any) -> dict[str, Any]:
    return {
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "details": details,
    }


def _filetime(value: int) -> str | None:
    if value <= 0:
        return None
    try:
        moment = dt.datetime(1601, 1, 1, tzinfo=dt.UTC) + dt.timedelta(microseconds=value / 10)
    except (OverflowError, ValueError):
        return None
    return moment.isoformat().replace("+00:00", "Z")


def _unix_time(value: int) -> str | None:
    if value <= 0:
        return None
    try:
        moment = dt.datetime.fromtimestamp(value, tz=dt.UTC)
    except (OSError, OverflowError, ValueError):
        return None
    return moment.isoformat().replace("+00:00", "Z")


def _apple_time(value: float) -> str | None:
    if not math.isfinite(value):
        return None
    try:
        moment = dt.datetime(2001, 1, 1, tzinfo=dt.UTC) + dt.timedelta(seconds=value)
    except (OverflowError, ValueError):
        return None
    return moment.isoformat().replace("+00:00", "Z")


def _bounded_zlib(payload: bytes, maximum: int) -> bytes | None:
    try:
        decoder = zlib.decompressobj()
        output = decoder.decompress(payload, maximum + 1)
        if len(output) > maximum or decoder.unconsumed_tail:
            return None
        output += decoder.flush(maximum + 1 - len(output))
        return output if len(output) <= maximum else None
    except (ValueError, zlib.error):
        return None


def parse_android_backup(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Decode an unencrypted Android ADB backup into a bounded TAR artifact."""

    result = _result("android_backup")
    if not data.startswith(b"ANDROID BACKUP\n"):
        result["findings"].append(_finding(
            "error", "structure", "Invalid Android backup header",
            "The expected ANDROID BACKUP header is missing.",
        ))
        return result
    cursor = len(b"ANDROID BACKUP\n")
    lines: list[str] = []
    for _ in range(3):
        end = data.find(b"\n", cursor, cursor + 256)
        if end < 0:
            result["findings"].append(_finding(
                "error", "structure", "Truncated Android backup header",
                "The backup version, compression, or encryption line is incomplete.",
            ))
            return result
        lines.append(data[cursor:end].decode("ascii", "replace").strip())
        cursor = end + 1
    version, compressed_text, encryption = lines
    compressed = compressed_text == "1"
    result["properties"].update({
        "backup_version": version,
        "compressed": compressed,
        "encryption": encryption,
        "payload_offset": cursor,
    })
    if encryption.casefold() != "none":
        result["findings"].append(_finding(
            "warning", "encryption", "Encrypted Android backup",
            "The backup payload was not decrypted. A supplied password and Android Backup Extractor are required.",
            encryption=encryption,
        ))
        return result
    payload = data[cursor:]
    maximum = 192 * 1024 * 1024 if profile == "deep" else 96 * 1024 * 1024
    if compressed:
        payload = _bounded_zlib(payload, maximum) or b""
        transformation = "bounded zlib decompression of unencrypted Android backup payload"
    else:
        transformation = "remove Android backup header from unencrypted TAR payload"
        if len(payload) > maximum:
            payload = b""
    if not payload:
        result["findings"].append(_finding(
            "warning", "resource-limit", "Android backup payload not expanded",
            "The payload was malformed or exceeded the bounded expansion limit.",
            maximum_bytes=maximum,
        ))
        return result
    detected = sniff_kind(payload, "android-backup.tar")
    result["properties"]["decoded_size"] = len(payload)
    result["properties"]["decoded_kind"] = detected
    if detected != "tar":
        result["findings"].append(_finding(
            "warning", "structure", "Android backup payload is not a recognized TAR",
            "The decoded bytes were retained for recursive inspection, but the TAR signature was not confirmed.",
            detected_kind=detected,
        ))
    result["extracted"].append({
        "label": "android_backup.tar",
        "data": payload,
        "producer": "android-backup-parser",
        "transformation": transformation,
        "offset": cursor,
        "kind": detected,
    })
    result["findings"].append(_finding(
        "info", "mobile", "Android backup payload recovered",
        "The unencrypted ADB backup was decoded as inert bytes for normal bounded archive and SQLite analysis.",
        decoded_size=len(payload),
    ))
    return result


def _plist_value_text(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, dt.datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        if len(value) <= 256 * 1024:
            try:
                decoded = value.decode("utf-8")
            except UnicodeDecodeError:
                return value[:256].hex()
            return decoded
    return None


def parse_plist(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Read XML/binary Apple property lists with Python's non-executing parser."""

    result = _result("plist")
    maximum = 64 * 1024 * 1024 if profile == "deep" else 32 * 1024 * 1024
    if len(data) > maximum:
        result["findings"].append(_finding(
            "warning", "resource-limit", "Property list parsing bounded",
            "The property list exceeds the safe in-memory parser limit.",
            size=len(data), maximum_bytes=maximum,
        ))
        return result
    try:
        root = plistlib.loads(data)
    except (InvalidFileException, ValueError, TypeError, OverflowError) as exc:
        result["findings"].append(_finding(
            "warning", "structure", "Property list parser stopped safely",
            "The plist is malformed or uses an unsupported encoding.",
            error=f"{type(exc).__name__}: {display_text(exc, 300)}",
        ))
        return result
    pending: list[tuple[str, Any]] = [("$", root)]
    lines: list[str] = []
    nodes = 0
    truncated = False
    while pending and nodes < 20_000:
        path, value = pending.pop()
        nodes += 1
        if isinstance(value, dict):
            for key, child in reversed(list(value.items())[:5_000]):
                pending.append((f"{path}.{display_text(key, 160)}", child))
            continue
        if isinstance(value, (list, tuple)):
            for index, child in reversed(list(enumerate(value[:5_000]))):
                pending.append((f"{path}[{index}]", child))
            continue
        rendered = _plist_value_text(value)
        if rendered:
            lines.append(f"{path} = {display_text(rendered, 256_000)}")
        if len(lines) >= 10_000:
            truncated = bool(pending)
            break
    truncated = truncated or bool(pending)
    result["properties"].update({
        "encoding": "binary" if data.startswith(b"bplist00") else "xml",
        "root_type": type(root).__name__,
        "nodes_scanned": nodes,
        "truncated": truncated,
    })
    if lines:
        result["text_records"].append({
            "encoding": "plist-values",
            "offset": None,
            "text": display_text("\n".join(lines), 2_000_000),
            "source": "Apple property-list keys and values",
            "confidence_hint": 9,
            "transform_chain": ["parse property list without object hooks", "flatten bounded keys and values"],
        })
    return result


# plistlib exposes this exception from its private parser path in some Python
# versions, while other versions surface ValueError.  Keep a stable alias.
InvalidFileException = getattr(plistlib, "InvalidFileException", ValueError)


_LNK_FLAG_NAMES = {
    0: "HasLinkTargetIDList",
    1: "HasLinkInfo",
    2: "HasName",
    3: "HasRelativePath",
    4: "HasWorkingDir",
    5: "HasArguments",
    6: "HasIconLocation",
    7: "IsUnicode",
    8: "ForceNoLinkInfo",
    13: "RunAsUser",
    17: "RunWithShimLayer",
}


def _read_c_string(data: bytes, offset: int, *, unicode: bool = False, maximum: int = 32_768) -> str:
    if offset <= 0 or offset >= len(data):
        return ""
    end_limit = min(len(data), offset + maximum)
    if unicode:
        end = offset
        while end + 1 < end_limit and data[end:end + 2] != b"\0\0":
            end += 2
        return display_text(data[offset:end].decode("utf-16-le", "replace"), maximum // 2)
    end = data.find(b"\0", offset, end_limit)
    if end < 0:
        end = end_limit
    return display_text(data[offset:end].decode("cp1252", "replace"), maximum)


def parse_lnk(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Parse Windows Shell Link headers and user-controlled StringData."""

    result = _result("lnk")
    expected_clsid = bytes.fromhex("0114020000000000c000000000000046")
    if len(data) < 76 or data[:4] != b"L\0\0\0" or data[4:20] != expected_clsid:
        result["findings"].append(_finding(
            "error", "structure", "Invalid Windows shortcut",
            "The Shell Link header size or CLSID is missing.",
        ))
        return result
    link_flags = int.from_bytes(data[20:24], "little")
    enabled_flags = [name for bit, name in _LNK_FLAG_NAMES.items() if link_flags & (1 << bit)]
    result["properties"].update({
        "link_flags": f"0x{link_flags:08x}",
        "enabled_flags": enabled_flags,
        "file_attributes": f"0x{int.from_bytes(data[24:28], 'little'):08x}",
        "creation_time": _filetime(int.from_bytes(data[28:36], "little")),
        "access_time": _filetime(int.from_bytes(data[36:44], "little")),
        "write_time": _filetime(int.from_bytes(data[44:52], "little")),
        "target_file_size": int.from_bytes(data[52:56], "little"),
        "icon_index": int.from_bytes(data[56:60], "little", signed=True),
        "show_command": int.from_bytes(data[60:64], "little"),
        "hotkey": int.from_bytes(data[64:66], "little"),
    })
    offset = 76
    if link_flags & 0x1 and offset + 2 <= len(data):
        id_list_size = int.from_bytes(data[offset:offset + 2], "little")
        result["properties"]["target_id_list_size"] = id_list_size
        offset = min(len(data), offset + 2 + id_list_size)
    if link_flags & 0x2 and offset + 4 <= len(data):
        link_info_start = offset
        link_info_size = int.from_bytes(data[offset:offset + 4], "little")
        if 0x1C <= link_info_size <= len(data) - offset:
            header_size = int.from_bytes(data[offset + 4:offset + 8], "little")
            local_offset = int.from_bytes(data[offset + 16:offset + 20], "little")
            suffix_offset = int.from_bytes(data[offset + 24:offset + 28], "little")
            local_unicode = int.from_bytes(data[offset + 28:offset + 32], "little") if header_size >= 0x24 else 0
            suffix_unicode = int.from_bytes(data[offset + 32:offset + 36], "little") if header_size >= 0x24 else 0
            local_path = _read_c_string(data, link_info_start + (local_unicode or local_offset), unicode=bool(local_unicode))
            suffix = _read_c_string(data, link_info_start + (suffix_unicode or suffix_offset), unicode=bool(suffix_unicode))
            if local_path:
                result["metadata"]["local_base_path"] = local_path
            if suffix:
                result["metadata"]["common_path_suffix"] = suffix
            offset += link_info_size
        else:
            result["findings"].append(_finding(
                "warning", "structure", "Malformed Shell LinkInfo block",
                "The declared LinkInfo size extends outside the shortcut.",
                offset=offset, declared_size=link_info_size,
            ))
    is_unicode = bool(link_flags & (1 << 7))
    string_fields = (
        (2, "description"),
        (3, "relative_path"),
        (4, "working_directory"),
        (5, "command_line_arguments"),
        (6, "icon_location"),
    )
    recovered: list[str] = []
    for bit, label in string_fields:
        if not link_flags & (1 << bit) or offset + 2 > len(data):
            continue
        character_count = int.from_bytes(data[offset:offset + 2], "little")
        offset += 2
        byte_count = character_count * (2 if is_unicode else 1)
        if byte_count < 0 or byte_count > 2 * 1024 * 1024 or offset + byte_count > len(data):
            result["findings"].append(_finding(
                "warning", "structure", "Malformed Shell Link string",
                "A StringData field extends outside the shortcut.",
                field=label, declared_characters=character_count,
            ))
            break
        raw = data[offset:offset + byte_count]
        offset += byte_count
        value = display_text(raw.decode("utf-16-le" if is_unicode else "cp1252", "replace"), 256_000)
        if value:
            result["metadata"][label] = value
            recovered.append(f"{label}: {value}")
    if recovered:
        result["text_records"].append({
            "encoding": "shell-link-string-data",
            "offset": None,
            "text": "\n".join(recovered),
            "source": "Windows Shell Link fields",
            "confidence_hint": 10,
        })
    if link_flags & (1 << 5):
        result["findings"].append(_finding(
            "info", "endpoint-artifact", "Shortcut command-line arguments recovered",
            "The argument string was reported as evidence only and was never executed.",
        ))
    return result


def parse_jumplist(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Recover bounded path evidence and embedded Shell Links from a Jump List."""

    result = _result("jumplist")
    ole_container = data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
    scan_limit = min(len(data), 64 * 1024 * 1024 if profile == "deep" else 16 * 1024 * 1024)
    source = data[:scan_limit]
    shell_link_signature = b"L\0\0\0" + bytes.fromhex("0114020000000000c000000000000046")
    offsets: list[int] = []
    cursor = 0
    while len(offsets) < 2_000:
        offset = source.find(shell_link_signature, cursor)
        if offset < 0:
            break
        offsets.append(offset)
        cursor = offset + len(shell_link_signature)
    link_summaries: list[str] = []
    for index, offset in enumerate(offsets):
        parsed = parse_lnk(source[offset:min(len(source), offset + 2 * 1024 * 1024)], profile)
        metadata = parsed.get("metadata") if isinstance(parsed.get("metadata"), dict) else {}
        fields = [
            f"{key}={display_text(value, 4096)}"
            for key, value in metadata.items()
            if value not in {None, ""}
        ]
        link_summaries.append(f"embedded_lnk={index + 1} offset={offset}" + (" " + " ".join(fields) if fields else ""))
    strings = [
        f"utf16@{record['offset']}: {display_text(record['text'], 16_384)}"
        for record in iter_utf16_strings(source, minimum=4, limit=10_000)
        if str(record.get("text") or "").strip()
    ]
    result["properties"].update({
        "container": "automatic-destinations OLE" if ole_container else "custom-destinations/unknown",
        "embedded_shell_links": len(offsets),
        "bytes_scanned": scan_limit,
        "truncated": len(data) > scan_limit or len(offsets) >= 2_000,
    })
    rendered = link_summaries + strings
    if rendered:
        result["text_records"].append({
            "encoding": "jumplist-paths-and-shell-links",
            "offset": None,
            "text": display_text("\n".join(rendered), 2_000_000),
            "source": "Windows Jump List paths and embedded Shell Link fields",
            "confidence_hint": 8,
        })
    result["findings"].append(_finding(
        "info", "endpoint-artifact", "Windows Jump List inspected",
        "Path strings and embedded LNK fields were recovered as evidence without following or executing any target.",
        embedded_shell_links=len(offsets),
    ))
    return result


def parse_prefetch(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Triage uncompressed Windows Prefetch headers and path strings."""

    result = _result("prefetch")
    if data.startswith(b"MAM\x04"):
        result["properties"]["compressed"] = True
        result["findings"].append(_finding(
            "info", "endpoint-artifact", "Compressed Windows Prefetch detected",
            "The built-in pass does not expand XPRESS-Huffman data; the optional sccainfo adapter can parse supported variants.",
        ))
        return result
    if len(data) < 84 or data[4:8] != b"SCCA":
        result["findings"].append(_finding(
            "error", "structure", "Invalid Windows Prefetch header",
            "The SCCA signature is missing or truncated.",
        ))
        return result
    version = int.from_bytes(data[:4], "little")
    executable = display_text(data[16:76].decode("utf-16-le", "replace").rstrip("\0"), 260)
    last_run_offsets = {17: 120, 23: 128, 26: 128, 30: 128, 31: 128}
    run_count_offsets = {17: 144, 23: 152, 26: 208, 30: 208, 31: 208}
    timestamps: list[str] = []
    timestamp_offset = last_run_offsets.get(version)
    timestamp_slots = 8 if version >= 26 else 1
    if timestamp_offset is not None:
        for index in range(timestamp_slots):
            start = timestamp_offset + index * 8
            if start + 8 > len(data):
                break
            rendered = _filetime(int.from_bytes(data[start:start + 8], "little"))
            if rendered:
                timestamps.append(rendered)
    run_count_offset = run_count_offsets.get(version)
    run_count = int.from_bytes(data[run_count_offset:run_count_offset + 4], "little") if run_count_offset is not None and run_count_offset + 4 <= len(data) else None
    result["properties"].update({
        "compressed": False,
        "version": version,
        "executable_name": executable,
        "prefetch_hash": f"{int.from_bytes(data[76:80], 'little'):08X}",
        "declared_file_size": int.from_bytes(data[12:16], "little"),
        "run_count": run_count,
        "last_run_times": timestamps,
    })
    scan_limit = min(len(data), 32 * 1024 * 1024 if profile == "deep" else 8 * 1024 * 1024)
    strings = [
        display_text(record["text"], 16_384)
        for record in iter_utf16_strings(data[:scan_limit], minimum=4, limit=10_000)
        if record["text"].strip()
    ]
    if strings:
        result["text_records"].append({
            "encoding": "prefetch-utf16-paths",
            "offset": None,
            "text": display_text("\n".join(strings), 2_000_000),
            "source": "Windows Prefetch executable and path strings",
            "confidence_hint": 8,
        })
    return result


def parse_mft(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Recover resident FILE_NAME attributes from an extracted NTFS $MFT."""

    result = _result("mft")
    record_size = 1024
    maximum_records = 100_000 if profile == "deep" else 25_000
    names: list[str] = []
    parsed_records = 0
    allocated_records = 0
    for offset in range(0, min(len(data), maximum_records * record_size), record_size):
        record = data[offset:offset + record_size]
        if len(record) < 64 or record[:4] not in {b"FILE", b"BAAD"}:
            continue
        parsed_records += 1
        flags = int.from_bytes(record[22:24], "little")
        allocated_records += int(bool(flags & 0x1))
        attribute_offset = int.from_bytes(record[20:22], "little")
        attribute_count = 0
        while attribute_offset + 16 <= len(record) and attribute_count < 128:
            attribute_type = int.from_bytes(record[attribute_offset:attribute_offset + 4], "little")
            if attribute_type == 0xFFFFFFFF:
                break
            attribute_length = int.from_bytes(record[attribute_offset + 4:attribute_offset + 8], "little")
            if attribute_length < 24 or attribute_offset + attribute_length > len(record):
                break
            nonresident = record[attribute_offset + 8] != 0
            if attribute_type == 0x30 and not nonresident:
                content_length = int.from_bytes(record[attribute_offset + 16:attribute_offset + 20], "little")
                content_offset = int.from_bytes(record[attribute_offset + 20:attribute_offset + 22], "little")
                content = record[attribute_offset + content_offset:attribute_offset + content_offset + content_length]
                if len(content) >= 66:
                    name_length = content[64]
                    name_end = 66 + name_length * 2
                    if name_length and name_end <= len(content):
                        filename = display_text(content[66:name_end].decode("utf-16-le", "replace"), 1024)
                        if filename:
                            parent = int.from_bytes(content[:6], "little")
                            names.append(f"record={offset // record_size} parent={parent} allocated={bool(flags & 0x1)} name={filename}")
            attribute_offset += attribute_length
            attribute_count += 1
        if len(names) >= 50_000:
            break
    result["properties"].update({
        "record_size_assumption": record_size,
        "records_parsed": parsed_records,
        "allocated_records": allocated_records,
        "filenames_recovered": len(names),
        "truncated": len(data) > maximum_records * record_size or len(names) >= 50_000,
    })
    if names:
        result["text_records"].append({
            "encoding": "ntfs-file-name-attributes",
            "offset": None,
            "text": display_text("\n".join(names), 2_000_000),
            "source": "NTFS MFT resident FILE_NAME attributes",
            "confidence_hint": 9,
        })
    return result


def parse_usn(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Parse bounded USN_RECORD_V2/V3 filenames from an extracted $J stream."""

    result = _result("usn")
    offset = 0
    records = 0
    lines: list[str] = []
    maximum = 250_000 if profile == "deep" else 50_000
    scan_attempts = 0
    maximum_attempts = 2_000_000 if profile == "deep" else 500_000
    while offset + 60 <= len(data) and records < maximum and scan_attempts < maximum_attempts:
        scan_attempts += 1
        record_length = int.from_bytes(data[offset:offset + 4], "little")
        major = int.from_bytes(data[offset + 4:offset + 6], "little")
        if major == 2:
            minimum, name_length_offset, name_offset_offset = 60, 56, 58
            timestamp_offset, reason_offset = 32, 40
        elif major in {3, 4}:
            minimum, name_length_offset, name_offset_offset = 76, 72, 74
            timestamp_offset, reason_offset = 48, 56
        else:
            # Extracted $J streams are commonly sparse. Skip a bounded run of
            # aligned zero cells without spending one parser turn per 8 bytes.
            if data[offset:offset + 8] == b"\0" * 8:
                zero_end = min(len(data), offset + 64 * 1024)
                candidate = offset + 8
                while candidate + 8 <= zero_end and data[candidate:candidate + 8] == b"\0" * 8:
                    candidate += 8
                offset = candidate
            else:
                offset += 8
            continue
        if record_length < minimum or offset + record_length > len(data):
            offset += 8
            continue
        name_length = int.from_bytes(data[offset + name_length_offset:offset + name_length_offset + 2], "little")
        name_offset = int.from_bytes(data[offset + name_offset_offset:offset + name_offset_offset + 2], "little")
        if name_length and name_offset >= minimum and name_offset + name_length <= record_length:
            raw_name = data[offset + name_offset:offset + name_offset + name_length]
            filename = display_text(raw_name.decode("utf-16-le", "replace"), 2048)
            reason = int.from_bytes(data[offset + reason_offset:offset + reason_offset + 4], "little")
            timestamp = _filetime(int.from_bytes(data[offset + timestamp_offset:offset + timestamp_offset + 8], "little"))
            lines.append(f"offset={offset} version={major} time={timestamp or ''} reason=0x{reason:08x} name={filename}")
        records += 1
        offset += (record_length + 7) & ~7
    result["properties"].update({
        "records_parsed": records,
        "filenames_recovered": len(lines),
        "bytes_scanned": offset,
        "scan_attempts": scan_attempts,
        "truncated": records >= maximum or scan_attempts >= maximum_attempts,
    })
    if lines:
        result["text_records"].append({
            "encoding": "usn-record-filenames",
            "offset": None,
            "text": display_text("\n".join(lines), 2_000_000),
            "source": "NTFS USN change-journal records",
            "confidence_hint": 9,
        })
    return result


def parse_recycle_bin_i(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Parse the Windows Vista+ $Recycle.Bin $I metadata companion file."""

    result = _result("recycle_bin_i")
    if len(data) < 24:
        result["findings"].append(_finding(
            "error", "structure", "Truncated Recycle Bin metadata",
            "A Windows $I record requires at least its 24-byte fixed header.",
        ))
        return result
    version = int.from_bytes(data[:8], "little")
    if version not in {1, 2}:
        result["findings"].append(_finding(
            "error", "structure", "Unsupported Recycle Bin metadata version",
            "The $I record does not use the documented version 1 or 2 layout.",
            version=version,
        ))
        return result
    original_size = int.from_bytes(data[8:16], "little")
    deleted_at = _filetime(int.from_bytes(data[16:24], "little"))
    declared_characters: int | None = None
    path_offset = 24
    if version == 2:
        if len(data) < 28:
            result["findings"].append(_finding(
                "error", "structure", "Truncated version 2 Recycle Bin metadata",
                "The original-path character count is incomplete.",
            ))
            return result
        declared_characters = int.from_bytes(data[24:28], "little")
        path_offset = 28
        if declared_characters > 32_768:
            result["findings"].append(_finding(
                "warning", "resource-limit", "Recycle Bin path length bounded",
                "The declared original path is implausibly large and was not decoded.",
                declared_characters=declared_characters,
            ))
            return result
        path_end = min(len(data), path_offset + declared_characters * 2)
        raw_path = data[path_offset:path_end]
        original_path = display_text(raw_path.decode("utf-16-le", "replace").rstrip("\0"), 32_768)
    else:
        original_path = _read_c_string(data, path_offset, unicode=True, maximum=65_536)
    result["properties"].update({
        "format_version": version,
        "original_file_size": original_size,
        "deletion_time": deleted_at,
        "declared_path_characters": declared_characters,
    })
    if original_path:
        result["metadata"]["original_path"] = original_path
        result["text_records"].append({
            "encoding": "recycle-bin-utf16-path",
            "offset": path_offset,
            "text": original_path,
            "source": "Windows $Recycle.Bin $I original path",
            "confidence_hint": 10,
        })
    result["findings"].append(_finding(
        "info", "endpoint-artifact", "Recycle Bin deletion metadata recovered",
        "The original path, file size, and UTC deletion time were read as evidence; the paired $R content was not opened or executed.",
        original_path=original_path,
        deletion_time=deleted_at,
    ))
    return result


def _sqlite_sidecar_strings(data: bytes, *, profile: str) -> list[dict[str, Any]]:
    scan_limit = min(len(data), 32 * 1024 * 1024 if profile == "deep" else 8 * 1024 * 1024)
    records = list(iter_ascii_strings(data[:scan_limit], minimum=5, limit=5_000))
    records.extend(iter_utf16_strings(data[:scan_limit], minimum=5, limit=5_000))
    return records


def parse_sqlite_wal(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Inspect SQLite write-ahead-log headers, frames, and bounded page strings."""

    result = _result("sqlite_wal")
    if len(data) < 32 or data[:4] not in {b"7\x7f\x06\x82", b"7\x7f\x06\x83"}:
        result["findings"].append(_finding(
            "error", "structure", "Invalid SQLite WAL header",
            "The documented SQLite write-ahead-log magic or 32-byte header is missing.",
        ))
        return result
    page_size = int.from_bytes(data[8:12], "big")
    if page_size == 1:
        page_size = 65_536
    valid_page_size = 512 <= page_size <= 65_536 and page_size & (page_size - 1) == 0
    frame_size = 24 + page_size if valid_page_size else 0
    available_frames = (len(data) - 32) // frame_size if frame_size else 0
    maximum_frames = 100_000 if profile == "deep" else 25_000
    frames: list[str] = []
    committed_frames = 0
    for index in range(min(available_frames, maximum_frames)):
        offset = 32 + index * frame_size
        page_number = int.from_bytes(data[offset:offset + 4], "big")
        database_pages = int.from_bytes(data[offset + 4:offset + 8], "big")
        committed_frames += int(database_pages != 0)
        if len(frames) < 10_000:
            frames.append(f"frame={index + 1} page={page_number} commit_database_pages={database_pages}")
    result["properties"].update({
        "magic": data[:4].hex(),
        "format_version": int.from_bytes(data[4:8], "big"),
        "page_size": page_size,
        "page_size_valid": valid_page_size,
        "checkpoint_sequence": int.from_bytes(data[12:16], "big"),
        "salt_1": int.from_bytes(data[16:20], "big"),
        "salt_2": int.from_bytes(data[20:24], "big"),
        "frames_available": available_frames,
        "frames_scanned": min(available_frames, maximum_frames),
        "commit_markers": committed_frames,
        "truncated": available_frames > maximum_frames,
    })
    records = _sqlite_sidecar_strings(data, profile=profile)
    rendered = frames + [f"string@{record['offset']}: {record['text']}" for record in records]
    if rendered:
        result["text_records"].append({
            "encoding": "sqlite-wal-frames-and-strings",
            "offset": None,
            "text": display_text("\n".join(rendered), 2_000_000),
            "source": "SQLite WAL frame metadata and bounded page strings",
            "confidence_hint": 8,
        })
    result["findings"].append(_finding(
        "info", "database", "SQLite write-ahead log inspected",
        "WAL frames can retain newer or deleted application/browser records. This pass is read-only and does not replay the WAL into a database.",
    ))
    return result


def parse_sqlite_journal(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Inspect SQLite rollback-journal headers, page records, and strings."""

    result = _result("sqlite_journal")
    magic = b"\xd9\xd5\x05\xf9 \xa1c\xd7"
    if len(data) < 28 or data[:8] != magic:
        result["findings"].append(_finding(
            "error", "structure", "Invalid SQLite rollback-journal header",
            "The documented eight-byte rollback-journal magic or fixed header is missing.",
        ))
        return result
    page_count = int.from_bytes(data[8:12], "big")
    sector_size = int.from_bytes(data[20:24], "big")
    page_size = int.from_bytes(data[24:28], "big")
    valid_sector = 28 <= sector_size <= 1024 * 1024 and sector_size & (sector_size - 1) == 0
    valid_page = 512 <= page_size <= 65_536 and page_size & (page_size - 1) == 0
    record_size = page_size + 8 if valid_page else 0
    available_records = max(0, (len(data) - sector_size) // record_size) if valid_sector and record_size else 0
    maximum_records = 100_000 if profile == "deep" else 25_000
    pages: list[str] = []
    for index in range(min(available_records, maximum_records, 10_000)):
        offset = sector_size + index * record_size
        pages.append(f"record={index + 1} original_page={int.from_bytes(data[offset:offset + 4], 'big')}")
    result["properties"].update({
        "declared_page_count": "all remaining" if page_count == 0xFFFFFFFF else page_count,
        "checksum_nonce": int.from_bytes(data[12:16], "big"),
        "initial_database_pages": int.from_bytes(data[16:20], "big"),
        "sector_size": sector_size,
        "sector_size_valid": valid_sector,
        "page_size": page_size,
        "page_size_valid": valid_page,
        "records_available": available_records,
        "records_scanned": min(available_records, maximum_records),
        "truncated": available_records > maximum_records,
    })
    records = _sqlite_sidecar_strings(data, profile=profile)
    rendered = pages + [f"string@{record['offset']}: {record['text']}" for record in records]
    if rendered:
        result["text_records"].append({
            "encoding": "sqlite-journal-pages-and-strings",
            "offset": None,
            "text": display_text("\n".join(rendered), 2_000_000),
            "source": "SQLite rollback-journal page metadata and bounded strings",
            "confidence_hint": 8,
        })
    result["findings"].append(_finding(
        "info", "database", "SQLite rollback journal inspected",
        "Rollback pages can retain pre-transaction records. This pass is read-only and never writes page data back into a database.",
    ))
    return result


def _thumbnail_payload_extent(data: bytes, offset: int, kind: str) -> int | None:
    """Return the end of one bounded embedded image, without decoding pixels."""

    maximum_end = min(len(data), offset + 32 * 1024 * 1024)
    if kind == "png":
        cursor = offset + 8
        for _ in range(10_000):
            if cursor + 12 > maximum_end:
                return None
            length = int.from_bytes(data[cursor:cursor + 4], "big")
            if length > 16 * 1024 * 1024 or cursor + 12 + length > maximum_end:
                return None
            chunk_type = data[cursor + 4:cursor + 8]
            cursor += 12 + length
            if chunk_type == b"IEND":
                return cursor
        return None
    if kind == "jpeg":
        end = data.find(b"\xff\xd9", offset + 3, maximum_end)
        return end + 2 if end >= 0 else None
    if kind == "bmp" and offset + 6 <= maximum_end:
        size = int.from_bytes(data[offset + 2:offset + 6], "little")
        return offset + size if 26 <= size <= 32 * 1024 * 1024 and offset + size <= maximum_end else None
    if kind == "webp" and offset + 12 <= maximum_end and data[offset + 8:offset + 12] == b"WEBP":
        size = int.from_bytes(data[offset + 4:offset + 8], "little") + 8
        return offset + size if 12 <= size <= 32 * 1024 * 1024 and offset + size <= maximum_end else None
    return None


def parse_thumbcache(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Carve bounded images from a Windows Explorer thumbnail-cache database."""

    result = _result("thumbcache")
    is_cache = data.startswith(b"CMMM")
    is_index = data.startswith(b"IMMM") or (len(data) >= 8 and data[4:8] == b"IMMM")
    if not (is_cache or is_index):
        result["findings"].append(_finding(
            "error", "structure", "Invalid Windows thumbnail cache",
            "The documented CMMM cache or IMMM index signature is missing.",
        ))
        return result
    version_offset = 4 if data.startswith((b"CMMM", b"IMMM")) else 8
    version = int.from_bytes(data[version_offset:version_offset + 4], "little") if len(data) >= version_offset + 4 else None
    scan_limit = min(len(data), 128 * 1024 * 1024 if profile == "deep" else 48 * 1024 * 1024)
    source = data[:scan_limit]
    signatures = (
        (b"\x89PNG\r\n\x1a\n", "png", ".png"),
        (b"\xff\xd8\xff", "jpeg", ".jpg"),
        (b"BM", "bmp", ".bmp"),
        (b"RIFF", "webp", ".webp"),
    )
    candidates: list[tuple[int, str, str]] = []
    for signature, kind, extension in signatures:
        cursor = 0
        while len(candidates) < 4_000:
            offset = source.find(signature, cursor)
            if offset < 0:
                break
            candidates.append((offset, kind, extension))
            cursor = offset + len(signature)
    candidates.sort(key=lambda item: item[0])
    seen: set[str] = set()
    recovered_bytes = 0
    maximum_images = 1_000 if profile == "deep" else 300
    maximum_recovered = 512 * 1024 * 1024 if profile == "deep" else 128 * 1024 * 1024
    for offset, kind, extension in candidates:
        if len(result["extracted"]) >= maximum_images or recovered_bytes >= maximum_recovered:
            break
        end = _thumbnail_payload_extent(source, offset, kind)
        if end is None:
            continue
        payload = source[offset:end]
        digest = hashlib.sha256(payload).hexdigest()
        if digest in seen or recovered_bytes + len(payload) > maximum_recovered:
            continue
        seen.add(digest)
        recovered_bytes += len(payload)
        result["extracted"].append({
            "label": f"thumbnail_{len(result['extracted']) + 1:04d}_{digest[:12]}{extension}",
            "data": payload,
            "producer": "windows-thumbcache-parser",
            "transformation": "carve complete embedded thumbnail using bounded image structure",
            "offset": offset,
            "kind": kind,
        })
    result["properties"].update({
        "database_role": "index" if is_index else "thumbnail cache",
        "format_version": version,
        "cache_entry_signatures": source.count(b"CMMM"),
        "images_recovered": len(result["extracted"]),
        "recovered_bytes": recovered_bytes,
        "bytes_scanned": scan_limit,
        "truncated": len(data) > scan_limit or len(result["extracted"]) >= maximum_images or recovered_bytes >= maximum_recovered,
    })
    identifiers = list(iter_ascii_strings(source, minimum=8, limit=5_000))
    if identifiers:
        result["text_records"].append({
            "encoding": "thumbcache-identifiers",
            "offset": None,
            "text": display_text("\n".join(f"{record['offset']}: {record['text']}" for record in identifiers), 1_000_000),
            "source": "Windows thumbnail-cache identifiers and strings",
            "confidence_hint": 6,
        })
    result["findings"].append(_finding(
        "info", "endpoint-artifact", "Windows thumbnail cache inspected",
        "Complete cached PNG, JPEG, BMP, and WebP previews were copied into isolated child artifacts; the database was never modified.",
        images_recovered=len(result["extracted"]),
    ))
    return result


_UTMP_TYPE_NAMES = {
    0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME",
    5: "INIT_PROCESS", 6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS", 9: "ACCOUNTING",
}


def _utmp_text(raw: bytes) -> str:
    return display_text(raw.split(b"\0", 1)[0].decode("utf-8", "replace"), 4_096)


def parse_utmp(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Parse the common 384-byte Linux glibc utmp/wtmp/btmp record layout."""

    result = _result("utmp")
    record_size = 384
    maximum_records = 500_000 if profile == "deep" else 100_000
    lines: list[str] = []
    invalid_types = 0
    invalid_timestamps = 0
    records_seen = min(len(data) // record_size, maximum_records)
    for index in range(records_seen):
        record = data[index * record_size:(index + 1) * record_size]
        if not any(record):
            continue
        record_type = int.from_bytes(record[0:2], "little", signed=True)
        pid = int.from_bytes(record[4:8], "little", signed=True)
        line = _utmp_text(record[8:40])
        terminal_id = _utmp_text(record[40:44])
        user = _utmp_text(record[44:76])
        host = _utmp_text(record[76:332])
        timestamp_value = int.from_bytes(record[340:344], "little", signed=True)
        timestamp = _unix_time(timestamp_value)
        invalid_types += int(record_type not in _UTMP_TYPE_NAMES)
        invalid_timestamps += int(timestamp_value != 0 and timestamp is None)
        address = ""
        raw_address = record[348:364]
        try:
            if any(raw_address[4:]):
                address = str(ipaddress.ip_address(raw_address))
            elif any(raw_address[:4]):
                address = str(ipaddress.ip_address(raw_address[:4]))
        except ValueError:
            address = ""
        lines.append(
            f"record={index} type={_UTMP_TYPE_NAMES.get(record_type, f'UNKNOWN({record_type})')} "
            f"pid={pid} time={timestamp or ''} user={user} line={line} id={terminal_id} host={host} address={address}"
        )
    result["properties"].update({
        "record_layout": "Linux glibc 384-byte utmp",
        "records_available": len(data) // record_size,
        "records_scanned": records_seen,
        "records_rendered": len(lines),
        "trailing_bytes": len(data) % record_size,
        "invalid_record_types": invalid_types,
        "invalid_timestamps": invalid_timestamps,
        "truncated": len(data) // record_size > maximum_records,
    })
    if lines:
        result["text_records"].append({
            "encoding": "linux-utmp-records",
            "offset": None,
            "text": display_text("\n".join(lines), 2_000_000),
            "source": "Linux utmp/wtmp/btmp login records",
            "confidence_hint": 9,
        })
    if len(data) % record_size:
        result["findings"].append(_finding(
            "warning", "structure", "UTMP layout mismatch or trailing data",
            "The file is not an exact sequence of the common 384-byte Linux glibc records; another platform layout may be in use.",
            trailing_bytes=len(data) % record_size,
        ))
    if invalid_types or invalid_timestamps:
        result["findings"].append(_finding(
            "warning", "anti-forensics", "Unusual Linux login records",
            "Invalid type codes or timestamps can indicate corruption, a different architecture, or edited accounting records.",
            invalid_record_types=invalid_types,
            invalid_timestamps=invalid_timestamps,
        ))
    return result


def _mbdb_string(data: bytes, offset: int) -> tuple[bytes, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated MBDB string length")
    length = int.from_bytes(data[offset:offset + 2], "big")
    offset += 2
    if length == 0xFFFF:
        return b"", offset
    if length > 4 * 1024 * 1024 or offset + length > len(data):
        raise ValueError("MBDB string extends outside bounded input")
    return data[offset:offset + length], offset + length


def parse_ios_mbdb(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Parse legacy iTunes/Finder Manifest.mbdb file-path records."""

    result = _result("ios_mbdb")
    if not data.startswith(b"mbdb\x05\x00"):
        result["findings"].append(_finding(
            "error", "structure", "Invalid iOS backup manifest",
            "The legacy Manifest.mbdb magic and version bytes are missing.",
        ))
        return result
    offset = 6
    maximum_records = 250_000 if profile == "deep" else 75_000
    lines: list[str] = []
    rendered_characters = 0
    maximum_rendered_characters = 4_000_000
    encrypted_records = 0
    malformed = False
    records = 0
    while offset < len(data) and records < maximum_records:
        record_offset = offset
        try:
            fields: list[bytes] = []
            for _ in range(5):
                value, offset = _mbdb_string(data, offset)
                fields.append(value)
            if offset + 40 > len(data):
                raise ValueError("truncated MBDB fixed record")
            mode = int.from_bytes(data[offset:offset + 2], "big")
            inode = int.from_bytes(data[offset + 2:offset + 10], "big")
            uid = int.from_bytes(data[offset + 10:offset + 14], "big")
            gid = int.from_bytes(data[offset + 14:offset + 18], "big")
            mtime = int.from_bytes(data[offset + 18:offset + 22], "big")
            atime = int.from_bytes(data[offset + 22:offset + 26], "big")
            ctime = int.from_bytes(data[offset + 26:offset + 30], "big")
            file_size = int.from_bytes(data[offset + 30:offset + 38], "big")
            flag = data[offset + 38]
            property_count = data[offset + 39]
            offset += 40
            properties: list[str] = []
            property_characters = 0
            for _ in range(property_count):
                key_raw, offset = _mbdb_string(data, offset)
                value_raw, offset = _mbdb_string(data, offset)
                key = display_text(key_raw.decode("utf-8", "replace"), 512)
                if key.casefold() in {"encryptionkey", "password", "secret"}:
                    rendered_property = f"{key}=<binary value omitted>"
                else:
                    rendered_property = f"{key}={display_text(value_raw.decode('utf-8', 'replace'), 4_096)}"
                if property_characters + len(rendered_property) <= 65_536:
                    properties.append(rendered_property)
                    property_characters += len(rendered_property)
        except ValueError:
            malformed = True
            break
        domain = display_text(fields[0].decode("utf-8", "replace"), 4_096)
        path = display_text(fields[1].decode("utf-8", "replace"), 32_768)
        link_target = display_text(fields[2].decode("utf-8", "replace"), 32_768)
        data_hash = fields[3].hex()
        encryption_key_length = len(fields[4])
        encrypted_records += int(encryption_key_length > 0)
        file_id = hashlib.sha1(f"{domain}-{path}".encode("utf-8", "replace")).hexdigest()
        file_type = {0x8000: "file", 0x4000: "directory", 0xA000: "symlink"}.get(mode & 0xF000, "other")
        suffix = f" properties={'; '.join(properties)}" if properties else ""
        rendered_line = (
            f"record={records} offset={record_offset} type={file_type} mode=0{mode:o} uid={uid} gid={gid} "
            f"inode={inode} size={file_size} mtime={_unix_time(mtime) or ''} atime={_unix_time(atime) or ''} "
            f"ctime={_unix_time(ctime) or ''} flag={flag} file_id={file_id} domain={domain} path={path} "
            f"link_target={link_target} data_hash={data_hash} encryption_key_bytes={encryption_key_length}{suffix}"
        )
        if rendered_characters + len(rendered_line) <= maximum_rendered_characters:
            lines.append(rendered_line)
            rendered_characters += len(rendered_line)
        records += 1
    result["properties"].update({
        "manifest_version": "5.0",
        "records_parsed": records,
        "records_rendered": len(lines),
        "encrypted_file_records": encrypted_records,
        "bytes_scanned": offset,
        "malformed": malformed,
        "truncated": records >= maximum_records and offset < len(data),
    })
    if lines:
        result["text_records"].append({
            "encoding": "ios-backup-manifest-records",
            "offset": None,
            "text": display_text("\n".join(lines), 2_000_000),
            "source": "legacy iOS Manifest.mbdb file mappings",
            "confidence_hint": 10,
        })
    if malformed:
        result["findings"].append(_finding(
            "warning", "structure", "iOS backup manifest stopped at malformed record",
            "The parser retained all complete preceding records and stopped before reading outside the supplied bytes.",
            offset=offset,
        ))
    result["findings"].append(_finding(
        "info", "mobile", "Legacy iOS backup manifest inspected",
        "Domain/path mappings and SHA-1 backup filenames were recovered. Encryption-key blobs were never rendered or used for decryption.",
        records=records,
    ))
    return result


def parse_mozlz4(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Recover Firefox session/search JSON from its custom raw-LZ4 wrapper."""

    result = _result("mozlz4")
    maximum = 128 * 1024 * 1024 if profile == "deep" else 64 * 1024 * 1024
    try:
        decoded = decompress_mozlz4(data, maximum)
    except CompressionError as exc:
        result["findings"].append(_finding(
            "warning", "structure", "Mozilla JSONLZ4 decompression stopped safely",
            "The custom header, raw LZ4 block, or declared output size is invalid.",
            error=display_text(exc, 300),
        ))
        return result
    result["properties"].update({
        "declared_uncompressed_size": int.from_bytes(data[8:12], "little"),
        "uncompressed_size": len(decoded),
        "json_like": decoded.lstrip().startswith((b"{", b"[")),
    })
    decoded_text = display_text(decoded.decode("utf-8", "replace"), 2_000_000)
    if decoded_text:
        result["text_records"].append({
            "encoding": "utf-8-jsonlz4",
            "offset": 12,
            "text": decoded_text,
            "source": "Firefox MOZLZ4 decompressed JSON",
            "confidence_hint": 10,
            "transform_chain": ["validate mozLz40 header", "bounded raw LZ4 decompression", "UTF-8 decode"],
        })
    result["extracted"].append({
        "label": "firefox_session.json" if result["properties"]["json_like"] else "firefox_mozlz4_payload.bin",
        "data": decoded,
        "producer": "mozilla-jsonlz4-parser",
        "transformation": "bounded raw LZ4 decompression using declared output size",
        "offset": 12,
        "kind": sniff_kind(decoded, "firefox_session.json"),
    })
    return result


def parse_leveldb(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Inspect a LevelDB table or log file and surface bounded logical records."""

    result = _result("leveldb")
    table_magic = b"\x57\xfb\x80\x8b\x24\x75\x47\xdb"
    is_table = len(data) >= 48 and data.endswith(table_magic)
    scan_limit = min(len(data), 96 * 1024 * 1024 if profile == "deep" else 32 * 1024 * 1024)
    source = data[:scan_limit]
    logical_records: list[tuple[int, bytes]] = []
    malformed_records = 0
    if not is_table:
        cursor = 0
        fragments = bytearray()
        fragment_offset = 0
        while cursor + 7 <= len(source) and len(logical_records) < 100_000:
            block_remaining = 32_768 - (cursor % 32_768)
            if block_remaining < 7:
                cursor += block_remaining
                continue
            header = source[cursor:cursor + 7]
            if header == b"\0" * 7:
                cursor += block_remaining
                continue
            length = int.from_bytes(header[4:6], "little")
            record_type = header[6]
            if record_type not in {1, 2, 3, 4} or length > block_remaining - 7 or cursor + 7 + length > len(source):
                malformed_records += 1
                cursor += block_remaining
                continue
            payload = source[cursor + 7:cursor + 7 + length]
            if record_type == 1:
                logical_records.append((cursor, payload))
                fragments.clear()
            elif record_type == 2:
                fragments = bytearray(payload)
                fragment_offset = cursor
            elif record_type == 3 and fragments:
                if len(fragments) + len(payload) <= 16 * 1024 * 1024:
                    fragments.extend(payload)
                else:
                    fragments.clear()
                    malformed_records += 1
            elif record_type == 4 and fragments:
                if len(fragments) + len(payload) <= 16 * 1024 * 1024:
                    fragments.extend(payload)
                    logical_records.append((fragment_offset, bytes(fragments)))
                else:
                    malformed_records += 1
                fragments.clear()
            cursor += 7 + length
    result["properties"].update({
        "file_role": "sorted table" if is_table else "log or manifest",
        "table_magic_valid": is_table,
        "logical_records": len(logical_records),
        "malformed_physical_records": malformed_records,
        "bytes_scanned": scan_limit,
        "truncated": len(data) > scan_limit or len(logical_records) >= 100_000,
    })
    records: list[str] = []
    for offset, payload in logical_records[:20_000]:
        for item in iter_ascii_strings(payload, minimum=4, limit=100):
            records.append(f"record@{offset}+{item['offset']}: {display_text(item['text'], 16_384)}")
        for item in iter_utf16_strings(payload, minimum=4, limit=100):
            records.append(f"record@{offset}+{item['offset']} utf16: {display_text(item['text'], 16_384)}")
        if len(records) >= 20_000:
            break
    # SSTable data blocks may be uncompressed and remain useful even without
    # reconstructing the entire surrounding database directory.
    raw_strings = list(iter_ascii_strings(source, minimum=5, limit=10_000))
    records.extend(f"raw@{item['offset']}: {display_text(item['text'], 16_384)}" for item in raw_strings)
    if records:
        result["text_records"].append({
            "encoding": "leveldb-record-strings",
            "offset": None,
            "text": display_text("\n".join(records), 2_000_000),
            "source": "LevelDB logical records and bounded table strings",
            "confidence_hint": 8,
        })
    result["findings"].append(_finding(
        "info", "database", "LevelDB browser/application artifact inspected",
        "Recoverable WAL/MANIFEST fragments and table strings were scanned without opening sibling files or modifying the database.",
        logical_records=len(logical_records),
    ))
    return result


_DS_STORE_TYPES = {b"bool", b"shor", b"long", b"comp", b"dutc", b"type", b"blob", b"ustr"}


def parse_ds_store(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Recover live and stale Finder record names from a .DS_Store B-tree."""

    result = _result("ds_store")
    magic_offset = 4 if data.startswith(b"\0\0\0\x01Bud1") else 0
    if data[magic_offset:magic_offset + 4] != b"Bud1":
        result["findings"].append(_finding(
            "error", "structure", "Invalid .DS_Store header",
            "The Finder buddy-allocator signature is missing.",
        ))
        return result
    scan_limit = min(len(data), 64 * 1024 * 1024 if profile == "deep" else 16 * 1024 * 1024)
    source = data[:scan_limit]
    maximum_records = 50_000 if profile == "deep" else 15_000
    maximum_text = 4_000_000
    cursor = magic_offset + 4
    deadline = time.monotonic() + (10.0 if profile == "deep" else 3.0)
    iterations = 0
    timed_out = False
    records = 0
    malformed_candidates = 0
    rendered_characters = 0
    lines: list[str] = []
    names: set[str] = set()
    seen: set[tuple[str, str, str]] = set()
    while cursor + 16 <= len(source) and records < maximum_records:
        iterations += 1
        if iterations % 4_096 == 0 and time.monotonic() > deadline:
            timed_out = True
            break
        record_offset = cursor
        name_length = int.from_bytes(source[cursor:cursor + 4], "big")
        if not 1 <= name_length <= 2_048:
            cursor += 1
            continue
        name_end = cursor + 4 + name_length * 2
        if name_end + 8 > len(source):
            cursor += 1
            continue
        record_type = source[name_end + 4:name_end + 8]
        if record_type not in _DS_STORE_TYPES:
            cursor += 1
            continue
        try:
            name = source[cursor + 4:name_end].decode("utf-16-be", "strict")
        except UnicodeDecodeError:
            cursor += 1
            continue
        if not name or any(ord(character) < 0x20 and character not in "\t" for character in name):
            cursor += 1
            continue
        field = source[name_end:name_end + 4].decode("ascii", "replace")
        value_offset = name_end + 8
        value_end = value_offset
        summary = ""
        try:
            if record_type == b"bool":
                if value_offset + 1 > len(source):
                    raise ValueError
                value_end = value_offset + 1
                summary = str(bool(source[value_offset]))
            elif record_type in {b"shor", b"long"}:
                if value_offset + 4 > len(source):
                    raise ValueError
                value_end = value_offset + 4
                summary = str(int.from_bytes(source[value_offset:value_end], "big"))
            elif record_type in {b"comp", b"dutc"}:
                if value_offset + 8 > len(source):
                    raise ValueError
                value_end = value_offset + 8
                summary = str(int.from_bytes(source[value_offset:value_end], "big"))
            elif record_type == b"type":
                if value_offset + 4 > len(source):
                    raise ValueError
                value_end = value_offset + 4
                summary = display_text(source[value_offset:value_end].decode("ascii", "replace"), 64)
            elif record_type in {b"blob", b"ustr"}:
                if value_offset + 4 > len(source):
                    raise ValueError
                value_length = int.from_bytes(source[value_offset:value_offset + 4], "big")
                byte_length = value_length * 2 if record_type == b"ustr" else value_length
                if byte_length > 4 * 1024 * 1024 or value_offset + 4 + byte_length > len(source):
                    raise ValueError
                value_start = value_offset + 4
                value_end = value_start + byte_length
                payload = source[value_start:value_end]
                if record_type == b"ustr":
                    summary = display_text(payload.decode("utf-16-be", "replace"), 16_384)
                else:
                    strings = list(iter_ascii_strings(payload, minimum=4, limit=20))
                    strings.extend(iter_utf16_strings(payload, minimum=4, limit=20))
                    summary = display_text(" | ".join(str(item["text"]) for item in strings), 16_384)
                    if not summary:
                        summary = f"<blob {byte_length} bytes>"
            else:
                raise ValueError
        except ValueError:
            malformed_candidates += 1
            cursor += 1
            continue
        key = (name, field, summary)
        if key not in seen:
            seen.add(key)
            names.add(name)
            rendered = (
                f"offset={record_offset} name={display_text(name, 8_192)} "
                f"field={field} type={record_type.decode('ascii')} value={summary}"
            )
            if rendered_characters + len(rendered) <= maximum_text:
                lines.append(rendered)
                rendered_characters += len(rendered)
            records += 1
        cursor = max(value_end, cursor + 1)
    result["properties"].update({
        "format": "Finder buddy-allocator B-tree",
        "records_recovered": records,
        "records_rendered": len(lines),
        "unique_names": len(names),
        "malformed_candidates": malformed_candidates,
        "bytes_scanned": scan_limit,
        "timed_out": timed_out,
        "truncated": len(data) > scan_limit or records >= maximum_records or timed_out,
    })
    if lines:
        result["text_records"].append({
            "encoding": "ds-store-records",
            "offset": None,
            "text": display_text("\n".join(lines), 2_000_000),
            "source": "macOS Finder .DS_Store live and stale records",
            "confidence_hint": 9,
        })
    result["findings"].append(_finding(
        "info", "endpoint-artifact", "macOS Finder metadata inspected",
        "Record-aware scanning recovered Finder filenames and metadata, including structurally intact stale records, without rewriting the B-tree.",
        unique_names=len(names), records=records,
    ))
    return result


def _binary_cookie_string(record: bytes, offset: int) -> str | None:
    if offset < 56 or offset >= len(record):
        return None
    end = record.find(b"\0", offset, min(len(record), offset + 65_536))
    if end < 0:
        return None
    return display_text(record[offset:end].decode("utf-8", "replace"), 65_536)


def parse_binarycookies(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Parse Safari/macOS NSHTTPCookieStorage binary cookie pages."""

    result = _result("binarycookies")
    if len(data) < 8 or not data.startswith(b"cook"):
        result["findings"].append(_finding(
            "error", "structure", "Invalid Safari binary-cookie file",
            "The four-byte cook signature or page-count field is missing.",
        ))
        return result
    page_count = int.from_bytes(data[4:8], "big")
    maximum_pages = 20_000 if profile == "deep" else 5_000
    maximum_cookies = 250_000 if profile == "deep" else 75_000
    if page_count > maximum_pages or 8 + page_count * 4 > len(data):
        result["findings"].append(_finding(
            "warning", "structure", "Unreasonable Safari cookie page table",
            "The declared page count exceeds the bounded parser limit or the file length.",
            declared_pages=page_count,
        ))
        return result
    page_sizes = [int.from_bytes(data[8 + index * 4:12 + index * 4], "big") for index in range(page_count)]
    cursor = 8 + page_count * 4
    pages_end = cursor + sum(page_sizes)
    if any(size < 12 or size > 64 * 1024 * 1024 for size in page_sizes) or sum(page_sizes) > len(data) - cursor:
        result["findings"].append(_finding(
            "warning", "structure", "Invalid Safari cookie page sizes",
            "At least one page is too small, too large, or extends beyond the supplied file.",
        ))
        return result
    lines: list[str] = []
    rendered_characters = 0
    maximum_text = 4_000_000
    cookies = 0
    malformed = 0
    scan_steps = 0
    maximum_scan_steps = 4_000_000 if profile == "deep" else 1_000_000
    deadline = time.monotonic() + (12.0 if profile == "deep" else 4.0)
    timed_out = False
    calculated_checksum = 0
    pages_scanned = 0
    pages_consumed = 0
    for page_index, page_size in enumerate(page_sizes):
        if cookies >= maximum_cookies:
            break
        page = data[cursor:cursor + page_size]
        cursor += page_size
        pages_consumed += 1
        calculated_checksum = (calculated_checksum + sum(memoryview(page)[::4])) & 0xFFFFFFFF
        if len(page) < 12 or page[:4] != b"\0\0\x01\0":
            malformed += 1
            continue
        cookie_count = int.from_bytes(page[4:8], "little")
        if cookie_count > maximum_cookies or 8 + cookie_count * 4 + 4 > len(page):
            malformed += 1
            continue
        offsets = [int.from_bytes(page[8 + index * 4:12 + index * 4], "little") for index in range(cookie_count)]
        pages_scanned += 1
        for cookie_index, record_offset in enumerate(offsets):
            if cookies >= maximum_cookies:
                break
            if record_offset + 56 > len(page):
                malformed += 1
                continue
            record_size = int.from_bytes(page[record_offset:record_offset + 4], "little")
            if record_size < 56 or record_size > 16 * 1024 * 1024 or record_offset + record_size > len(page):
                malformed += 1
                continue
            record = page[record_offset:record_offset + record_size]
            flags = int.from_bytes(record[8:12], "little")
            field_offsets = [int.from_bytes(record[position:position + 4], "little") for position in (16, 20, 24, 28)]
            domain, name, path, value = (_binary_cookie_string(record, field_offset) for field_offset in field_offsets)
            if None in {domain, name, path, value}:
                malformed += 1
                continue
            try:
                expires_value = struct.unpack_from("<d", record, 40)[0]
                created_value = struct.unpack_from("<d", record, 48)[0]
            except struct.error:
                malformed += 1
                continue
            rendered = (
                f"page={page_index} cookie={cookie_index} domain={domain} name={name} path={path} value={value} "
                f"secure={bool(flags & 0x01)} http_only={bool(flags & 0x04)} flags=0x{flags:08x} "
                f"created={_apple_time(created_value) or ''} expires={_apple_time(expires_value) or ''}"
            )
            if rendered_characters + len(rendered) <= maximum_text:
                lines.append(rendered)
                rendered_characters += len(rendered)
            cookies += 1
    stored_checksum = int.from_bytes(data[pages_end:pages_end + 4], "big") if pages_end + 4 <= len(data) else None
    all_pages_consumed = pages_consumed == page_count
    result["properties"].update({
        "declared_pages": page_count,
        "pages_scanned": pages_scanned,
        "cookies_parsed": cookies,
        "cookies_rendered": len(lines),
        "malformed_records_or_pages": malformed,
        "stored_checksum": stored_checksum,
        "calculated_checksum": calculated_checksum,
        "checksum_valid": stored_checksum == calculated_checksum if stored_checksum is not None and all_pages_consumed else None,
        "truncated": cookies >= maximum_cookies or not all_pages_consumed,
    })
    if lines:
        result["text_records"].append({
            "encoding": "safari-binary-cookie-records",
            "offset": None,
            "text": display_text("\n".join(lines), 2_000_000),
            "source": "Safari/macOS Cookies.binarycookies records",
            "confidence_hint": 10,
        })
    result["findings"].append(_finding(
        "info", "browser", "Safari binary cookies inspected",
        "Cookie pages were parsed in memory without loading Safari or writing session data back to disk. Cookie values may contain sensitive session evidence.",
        cookies=cookies,
    ))
    return result


def _journal_payload(payload: bytes, flags: int, maximum: int) -> bytes | None:
    """Decode one bounded journal DATA payload when its codec is available."""

    if flags == 0:
        return payload if len(payload) <= maximum else None
    if flags == 0x01:
        try:
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
            output = decoder.decompress(payload, max_length=maximum + 1)
            return output if len(output) <= maximum and decoder.eof else None
        except lzma.LZMAError:
            return None
    if flags == 0x04:
        try:
            import zstandard  # type: ignore

            return zstandard.ZstdDecompressor().decompress(payload, max_output_size=maximum)
        except Exception:
            return None
    # systemd's legacy DATA-object LZ4 representation is not an LZ4 frame.
    # journalctl remains the authoritative optional cross-check for this codec.
    return None


def parse_systemd_journal(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Inspect bounded systemd journal objects without altering the journal."""

    result = _result("systemd_journal")
    if len(data) < 104 or not data.startswith(b"LPKSHHRH"):
        result["findings"].append(_finding(
            "error", "structure", "Invalid systemd journal",
            "The LPKSHHRH signature or minimum journal header is missing.",
        ))
        return result
    compatible_flags = int.from_bytes(data[8:12], "little")
    incompatible_flags = int.from_bytes(data[12:16], "little")
    header_size = int.from_bytes(data[88:96], "little")
    arena_size = int.from_bytes(data[96:104], "little")
    scan_limit = min(len(data), 256 * 1024 * 1024 if profile == "deep" else 64 * 1024 * 1024)
    if header_size < 104 or header_size > scan_limit:
        result["findings"].append(_finding(
            "warning", "structure", "Invalid systemd journal header size",
            "Object parsing stopped because the declared header does not fit inside the bounded input.",
            header_size=header_size,
        ))
        return result
    declared_end = header_size + arena_size
    object_end = min(scan_limit, declared_end if arena_size else scan_limit)
    compact = bool(incompatible_flags & 0x10)
    maximum_objects = 500_000 if profile == "deep" else 125_000
    maximum_fields = 100_000 if profile == "deep" else 25_000
    maximum_decompressed = 4 * 1024 * 1024 if profile == "deep" else 1 * 1024 * 1024
    cursor = header_size
    objects = 0
    data_objects = 0
    entry_objects = 0
    compressed_objects = 0
    skipped_compressed = 0
    malformed = 0
    scan_steps = 0
    maximum_scan_steps = 2_000_000 if profile == "deep" else 500_000
    deadline = time.monotonic() + (12.0 if profile == "deep" else 4.0)
    timed_out = False
    rendered_characters = 0
    lines: list[str] = []
    while cursor + 16 <= object_end and objects < maximum_objects and scan_steps < maximum_scan_steps:
        scan_steps += 1
        if scan_steps % 4_096 == 0 and time.monotonic() > deadline:
            timed_out = True
            break
        object_type = data[cursor]
        flags = data[cursor + 1]
        object_size = int.from_bytes(data[cursor + 8:cursor + 16], "little")
        if object_type not in range(1, 8) or object_size < 16 or object_size > 64 * 1024 * 1024 or cursor + object_size > object_end:
            malformed += 1
            cursor += 8
            continue
        objects += 1
        if object_type == 1:
            data_objects += 1
            payload_offset = 72 if compact else 64
            if object_size < payload_offset:
                malformed += 1
            else:
                compressed_objects += int(flags != 0)
                payload = _journal_payload(data[cursor + payload_offset:cursor + object_size], flags, maximum_decompressed)
                if payload is None:
                    skipped_compressed += int(flags != 0)
                elif len(lines) < maximum_fields:
                    separator = payload.find(b"=")
                    field = payload[:separator] if separator > 0 else b""
                    if re.fullmatch(br"[A-Z_][A-Z0-9_]{0,63}", field):
                        value = payload[separator + 1:]
                        if value and sum(byte in b"\t\r\n" or 32 <= byte < 127 for byte in value[:65_536]) >= max(1, len(value[:65_536]) * 3 // 4):
                            rendered_value = display_text(value.decode("utf-8", "replace"), 65_536)
                        else:
                            strings = list(iter_ascii_strings(value[:1_000_000], minimum=4, limit=100))
                            strings.extend(iter_utf16_strings(value[:1_000_000], minimum=4, limit=100))
                            rendered_value = display_text(" | ".join(str(item["text"]) for item in strings), 65_536)
                        rendered = f"offset={cursor} {field.decode('ascii')}={rendered_value}"
                        if rendered_characters + len(rendered) <= 4_000_000:
                            lines.append(rendered)
                            rendered_characters += len(rendered)
        elif object_type == 3 and object_size >= 64:
            entry_objects += 1
            if len(lines) < maximum_fields:
                sequence = int.from_bytes(data[cursor + 16:cursor + 24], "little")
                realtime = int.from_bytes(data[cursor + 24:cursor + 32], "little")
                timestamp = _unix_time(realtime // 1_000_000)
                rendered = f"entry sequence={sequence} realtime_utc={timestamp or ''} realtime_microseconds={realtime}"
                if rendered_characters + len(rendered) <= 4_000_000:
                    lines.append(rendered)
                    rendered_characters += len(rendered)
        cursor = (cursor + object_size + 7) & ~7
    state_names = {0: "offline", 1: "online", 2: "archived"}
    result["properties"].update({
        "state": state_names.get(data[16], f"unknown-{data[16]}"),
        "compatible_flags": f"0x{compatible_flags:08x}",
        "incompatible_flags": f"0x{incompatible_flags:08x}",
        "compact_format": compact,
        "header_size": header_size,
        "arena_size": arena_size,
        "declared_objects": int.from_bytes(data[144:152], "little") if len(data) >= 152 else None,
        "declared_entries": int.from_bytes(data[152:160], "little") if len(data) >= 160 else None,
        "objects_scanned": objects,
        "data_objects": data_objects,
        "entry_objects": entry_objects,
        "compressed_data_objects": compressed_objects,
        "compressed_objects_not_decoded": skipped_compressed,
        "malformed_objects": malformed,
        "scan_steps": scan_steps,
        "timed_out": timed_out,
        "bytes_scanned": object_end,
        "truncated": len(data) > scan_limit or declared_end > scan_limit or objects >= maximum_objects or scan_steps >= maximum_scan_steps or timed_out,
    })
    if lines:
        result["text_records"].append({
            "encoding": "systemd-journal-fields",
            "offset": None,
            "text": display_text("\n".join(lines), 2_000_000),
            "source": "systemd journal DATA and ENTRY objects",
            "confidence_hint": 9,
        })
    if skipped_compressed:
        result["findings"].append(_finding(
            "info", "compression", "Some compressed journal fields need journalctl",
            "The native pass retained supported XZ/ZSTD fields; legacy journal LZ4 fields are left to the optional authoritative journalctl adapter.",
            skipped=skipped_compressed,
        ))
    result["findings"].append(_finding(
        "info", "event-log", "systemd journal inspected",
        "Journal objects and bounded field values were read without opening the file for writing or changing its online/offline state.",
        objects=objects,
    ))
    return result


def parse_ese(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Triage an Extensible Storage Engine database without opening tables."""

    result = _result("ese")
    if len(data) < 64 or data[4:8] != b"\xef\xcd\xab\x89":
        result["findings"].append(_finding(
            "error", "structure", "Invalid ESE database header",
            "The expected ESE database magic is missing.",
        ))
        return result
    result["properties"].update({
        "header_checksum": f"{int.from_bytes(data[:4], 'little'):08x}",
        "format_version": int.from_bytes(data[8:12], "little"),
        "file_type": int.from_bytes(data[12:16], "little"),
    })
    scan_limit = min(len(data), 32 * 1024 * 1024 if profile == "deep" else 8 * 1024 * 1024)
    records = list(iter_ascii_strings(data[:scan_limit], minimum=5, limit=5_000))
    records.extend(iter_utf16_strings(data[:scan_limit], minimum=5, limit=5_000))
    if records:
        result["text_records"].append({
            "encoding": "ese-raw-strings",
            "offset": None,
            "text": display_text("\n".join(str(record["text"]) for record in records), 2_000_000),
            "source": "ESE database bounded strings",
            "confidence_hint": 6,
        })
    result["findings"].append(_finding(
        "info", "database", "ESE database detected",
        "Use the optional esedbinfo adapter for catalog and table metadata; no database was modified.",
    ))
    return result


def parse_virtual_disk(data: bytes, profile: str = "balanced", *, disk_kind: str) -> dict[str, Any]:
    """Expose safe header metadata for common VM/disk-image containers."""

    result = _result(disk_kind)
    properties: dict[str, Any] = {"container": disk_kind, "file_size": len(data)}
    if disk_kind == "qcow" and len(data) >= 72 and data.startswith(b"QFI\xfb"):
        properties.update({
            "version": int.from_bytes(data[4:8], "big"),
            "backing_file_offset": int.from_bytes(data[8:16], "big"),
            "backing_file_size": int.from_bytes(data[16:20], "big"),
            "cluster_bits": int.from_bytes(data[20:24], "big"),
            "virtual_size": int.from_bytes(data[24:32], "big"),
            "encryption_method": int.from_bytes(data[32:36], "big"),
        })
    elif disk_kind == "vmdk" and len(data) >= 64 and data.startswith(b"KDMV"):
        properties.update({
            "version": int.from_bytes(data[4:8], "little"),
            "flags": f"0x{int.from_bytes(data[8:12], 'little'):08x}",
            "capacity_sectors": int.from_bytes(data[12:20], "little"),
            "grain_size_sectors": int.from_bytes(data[20:28], "little"),
        })
    elif disk_kind == "vhdx":
        properties["signature_valid"] = data.startswith(b"vhdxfile")
    elif disk_kind == "vdi":
        properties["signature_valid"] = data.startswith(b"<<< Oracle VM VirtualBox Disk Image >>>")
    elif disk_kind == "dmg":
        trailer = data[-512:] if len(data) >= 512 else b""
        properties["koly_trailer_present"] = trailer.startswith(b"koly")
        if trailer.startswith(b"koly") and len(trailer) >= 40:
            properties["version"] = int.from_bytes(trailer[4:8], "big")
            properties["data_fork_offset"] = int.from_bytes(trailer[24:32], "big")
            properties["data_fork_length"] = int.from_bytes(trailer[32:40], "big")
    elif disk_kind == "aff":
        properties["signature_valid"] = data.startswith(b"AFF10")
    result["properties"].update(properties)
    strings = list(iter_ascii_strings(data[: min(len(data), 2 * 1024 * 1024)], minimum=6, limit=1_000))
    if strings:
        result["text_records"].append({
            "encoding": "container-header-strings",
            "offset": None,
            "text": display_text("\n".join(str(record["text"]) for record in strings), 500_000),
            "source": f"{disk_kind.upper()} container strings",
            "confidence_hint": 5,
        })
    result["findings"].append(_finding(
        "info", "disk", f"{disk_kind.upper()} virtual disk container detected",
        "Header metadata was inspected read-only. The optional qemu-img adapter can report container and backing-chain metadata without conversion.",
    ))
    return result
