from __future__ import annotations

import io
import pickletools
import re
import struct
import time
import zipfile
from typing import Any, Iterable

from .common import display_text, iter_ascii_strings, iter_utf16_strings, safe_label, sniff_kind


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


def zip_directory_is_bounded(data: bytes, *, max_entries: int, max_directory_bytes: int) -> bool:
    """Validate a single-disk, non-Zip64 central directory before ZipFile.

    Python's ``ZipFile`` materializes the complete directory during opening,
    so checking ``infolist`` afterwards is too late for an entry-count bomb.
    """

    if len(data) < 22:
        return False
    tail_start = max(0, len(data) - (65_535 + 22))
    tail = data[tail_start:]
    eocd = tail.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(tail):
        return False
    disk, central_disk, disk_entries, entries, central_size, central_offset, comment_size = struct.unpack_from("<HHHHIIH", tail, eocd + 4)
    return bool(
        disk == 0
        and central_disk == 0
        and disk_entries == entries
        and entries < 0xFFFF
        and central_size < 0xFFFFFFFF
        and central_offset < 0xFFFFFFFF
        and entries <= max_entries
        and central_size <= max_directory_bytes
        and eocd + 22 + comment_size <= len(tail)
        and central_offset + central_size <= len(data)
    )


def _append_bounded_strings(
    result: dict[str, Any],
    data: bytes,
    *,
    source: str,
    profile: str,
    confidence: int = 5,
) -> None:
    scan_limit = min(len(data), 16 * 1024 * 1024 if profile == "deep" else 4 * 1024 * 1024)
    records = list(iter_ascii_strings(data[:scan_limit], minimum=5, limit=2_500))
    records.extend(iter_utf16_strings(data[:scan_limit], minimum=5, limit=2_500))
    if not records:
        return
    result["text_records"].append({
        "encoding": "bounded-container-strings",
        "offset": None,
        "text": display_text("\n".join(str(record["text"]) for record in records), 2_000_000),
        "source": source,
        "confidence_hint": confidence,
    })


def parse_psd(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Inspect the fixed PSD/PSB header and bounded resource sections."""

    result = _result("psd")
    if len(data) < 26 or data[:4] != b"8BPS":
        result["findings"].append(_finding("error", "structure", "Invalid PSD/PSB header", "The 8BPS header is missing or truncated."))
        return result
    version = int.from_bytes(data[4:6], "big")
    channels = int.from_bytes(data[12:14], "big")
    height = int.from_bytes(data[14:18], "big")
    width = int.from_bytes(data[18:22], "big")
    depth = int.from_bytes(data[22:24], "big")
    color_mode = int.from_bytes(data[24:26], "big")
    color_names = {
        0: "bitmap", 1: "grayscale", 2: "indexed", 3: "RGB", 4: "CMYK",
        7: "multichannel", 8: "duotone", 9: "Lab",
    }
    result["properties"].update({
        "container": "PSB" if version == 2 else "PSD" if version == 1 else "unknown",
        "version": version,
        "channels": channels,
        "width": width,
        "height": height,
        "bits_per_channel": depth,
        "color_mode": color_names.get(color_mode, f"unknown-{color_mode}"),
        "reserved_bytes_zero": data[6:12] == b"\0" * 6,
    })
    cursor = 26
    section_names = ("color_mode_data", "image_resources", "layer_and_mask")
    for section in section_names:
        length_bytes = 8 if section == "layer_and_mask" and version == 2 else 4
        if cursor + length_bytes > len(data):
            result["findings"].append(_finding("warning", "structure", "PSD section table is truncated", "A declared section length could not be read.", section=section))
            break
        length = int.from_bytes(data[cursor:cursor + length_bytes], "big")
        cursor += length_bytes
        result["properties"][f"{section}_bytes"] = length
        if length > len(data) - cursor:
            result["findings"].append(_finding(
                "warning", "structure", "PSD section exceeds available bytes",
                "The section was not trusted because its declared length leaves the file.",
                section=section, declared=length, available=len(data) - cursor,
            ))
            break
        cursor += length
    if version not in {1, 2} or not 1 <= channels <= 56 or width < 1 or height < 1:
        result["findings"].append(_finding("warning", "structure", "Unusual PSD geometry", "One or more fixed header fields are outside common PSD/PSB limits."))
    _append_bounded_strings(result, data, source="PSD/PSB resources and layer strings", profile=profile, confidence=6)
    return result


def _pnm_tokens(data: bytes, limit: int = 16) -> tuple[list[bytes], int]:
    tokens: list[bytes] = []
    cursor = 0
    while cursor < len(data) and len(tokens) < limit:
        while cursor < len(data) and data[cursor] in b" \t\r\n":
            cursor += 1
        if cursor < len(data) and data[cursor] == 0x23:
            line_end = data.find(b"\n", cursor)
            cursor = len(data) if line_end < 0 else line_end + 1
            continue
        start = cursor
        while cursor < len(data) and data[cursor] not in b" \t\r\n#":
            cursor += 1
        if cursor > start:
            tokens.append(data[start:cursor])
        elif cursor < len(data):
            cursor += 1
    while cursor < len(data) and data[cursor] in b" \t\r\n":
        cursor += 1
    return tokens, cursor


def parse_netpbm(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Parse PBM/PGM/PPM/PAM headers without allocating the declared raster."""

    result = _result("netpbm")
    if len(data) < 3 or data[:2] not in {b"P1", b"P2", b"P3", b"P4", b"P5", b"P6", b"P7"}:
        result["findings"].append(_finding("error", "structure", "Invalid Netpbm header", "No supported P1-P7 magic number was found."))
        return result
    magic = data[:2].decode("ascii")
    comments = [display_text(match.group(1).decode("utf-8", "replace"), 4_096) for match in re.finditer(br"(?m)^#[ \t]?(.*)$", data[:256 * 1024])][:100]
    if magic == "P7":
        header_end = data.find(b"ENDHDR")
        if header_end < 0 or header_end > 256 * 1024:
            result["findings"].append(_finding("warning", "structure", "PAM header is incomplete", "ENDHDR was not found inside the bounded header."))
            return result
        fields = {}
        for line in data[2:header_end].splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) == 2 and parts[0].isalpha():
                fields[parts[0].decode("ascii", "replace").casefold()] = display_text(parts[1], 256)
        width = int(fields.get("width", "0")) if str(fields.get("width", "0")).isdigit() else 0
        height = int(fields.get("height", "0")) if str(fields.get("height", "0")).isdigit() else 0
        depth = int(fields.get("depth", "0")) if str(fields.get("depth", "0")).isdigit() else 0
        maxval = int(fields.get("maxval", "0")) if str(fields.get("maxval", "0")).isdigit() else 0
        raster_offset = header_end + len(b"ENDHDR")
        while raster_offset < len(data) and data[raster_offset] in b"\r\n":
            raster_offset += 1
        result["properties"].update({"magic": magic, "width": width, "height": height, "channels": depth, "max_value": maxval, "tuple_type": fields.get("tupltype"), "raster_offset": raster_offset})
    else:
        required = 3 if magic in {"P1", "P4"} else 4
        tokens, raster_offset = _pnm_tokens(data[:256 * 1024], limit=required)
        if len(tokens) < required:
            result["findings"].append(_finding("warning", "structure", "Netpbm header is incomplete", "The bounded header does not contain width, height, and required sample metadata."))
            return result
        try:
            width, height = int(tokens[1]), int(tokens[2])
            maxval = 1 if magic in {"P1", "P4"} else int(tokens[3])
        except ValueError:
            result["findings"].append(_finding("warning", "structure", "Netpbm dimensions are invalid", "A numeric header token could not be parsed."))
            return result
        result["properties"].update({"magic": magic, "width": width, "height": height, "max_value": maxval, "raster_offset": raster_offset})
        if magic in {"P4", "P5", "P6"} and 0 < width <= 1_000_000 and 0 < height <= 1_000_000 and 0 < maxval <= 65_535:
            channels = 3 if magic == "P6" else 1
            row_bytes = (width + 7) // 8 if magic == "P4" else width * channels * (2 if maxval > 255 else 1)
            expected = row_bytes * height
            result["properties"].update({"channels": channels, "expected_raster_bytes": expected, "available_raster_bytes": max(0, len(data) - raster_offset), "trailing_bytes": max(0, len(data) - raster_offset - expected)})
    result["metadata"]["comments"] = comments
    if comments:
        result["text_records"].append({"encoding": "netpbm-comments", "offset": None, "text": "\n".join(comments), "source": "Netpbm comment records", "confidence_hint": 9})
    return result


def parse_xcf(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("xcf")
    if len(data) < 26 or not data.startswith(b"gimp xcf "):
        result["findings"].append(_finding("error", "structure", "Invalid XCF header", "The GIMP XCF signature is missing or truncated."))
        return result
    version_field = data[9:14].rstrip(b"\0").decode("ascii", "replace")
    width = int.from_bytes(data[14:18], "big")
    height = int.from_bytes(data[18:22], "big")
    base_type = int.from_bytes(data[22:26], "big")
    result["properties"].update({"version": version_field or "file", "width": width, "height": height, "base_type": {0: "RGB", 1: "grayscale", 2: "indexed"}.get(base_type, f"unknown-{base_type}")})
    _append_bounded_strings(result, data, source="XCF layer, channel, path, and parasite strings", profile=profile, confidence=7)
    return result


def parse_hdf5(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("hdf5")
    signature = b"\x89HDF\r\n\x1a\n"
    valid_offsets = (0, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
    offset = next((candidate for candidate in valid_offsets if data[candidate:candidate + 8] == signature), -1)
    if offset < 0:
        result["findings"].append(_finding("error", "structure", "Invalid HDF5 superblock", "The HDF5 signature was not found at an allowed user-block boundary."))
        return result
    result["properties"].update({"superblock_offset": offset, "superblock_version": data[offset + 8] if len(data) > offset + 8 else None, "file_size": len(data)})
    _append_bounded_strings(result, data, source="HDF5 object names, attributes, and string datasets", profile=profile, confidence=7)
    result["findings"].append(_finding("info", "database", "HDF5 container inspected", "Object and attribute strings were scanned without importing model code or executing stored metadata."))
    return result


def parse_access_db(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("access_db")
    signature = data[4:32].split(b"\0", 1)[0].decode("ascii", "replace") if len(data) >= 32 else ""
    if not signature.startswith(("Standard Jet DB", "Standard ACE DB")):
        result["findings"].append(_finding("error", "structure", "Invalid Access database header", "A Jet or ACE database signature was not found."))
        return result
    result["properties"].update({"engine_signature": signature, "page_size_hint": int.from_bytes(data[20:22], "little") if len(data) >= 22 else None, "file_size": len(data)})
    _append_bounded_strings(result, data, source="Access Jet/ACE table, column, and value strings", profile=profile, confidence=6)
    result["findings"].append(_finding("info", "database", "Access database detected", "The native pass is read-only triage; authoritative table recovery can be performed with mdbtools or a forensic database suite."))
    return result


class _BsonLimit(Exception):
    pass


def _bson_cstring(data: bytes, cursor: int, end: int) -> tuple[str, int]:
    terminator = data.find(b"\0", cursor, min(end, cursor + 65_536))
    if terminator < 0:
        raise ValueError("unterminated BSON cstring")
    return data[cursor:terminator].decode("utf-8", "replace"), terminator + 1


def _walk_bson_document(data: bytes, start: int, end: int, depth: int, state: dict[str, Any]) -> int:
    if depth > 6 or state["nodes"] >= state["node_limit"] or time.monotonic() > state["deadline"]:
        raise _BsonLimit
    if start + 5 > end:
        raise ValueError("truncated BSON document")
    length = int.from_bytes(data[start:start + 4], "little", signed=True)
    document_end = start + length
    if length < 5 or document_end > end or data[document_end - 1] != 0:
        raise ValueError("invalid BSON document length")
    cursor = start + 4
    while cursor < document_end - 1:
        element_type = data[cursor]
        cursor += 1
        key, cursor = _bson_cstring(data, cursor, document_end)
        state["nodes"] += 1
        if len(state["keys"]) < 50_000 and state["text_chars"] < state["text_limit"]:
            bounded_key = display_text(key, min(4_096, state["text_limit"] - state["text_chars"]))
            state["keys"].append(bounded_key)
            state["text_chars"] += len(bounded_key)
        if element_type in {0x02, 0x0D, 0x0E}:
            if cursor + 4 > document_end:
                raise ValueError("truncated BSON string")
            size = int.from_bytes(data[cursor:cursor + 4], "little", signed=True)
            cursor += 4
            if size < 1 or cursor + size > document_end or data[cursor + size - 1] != 0:
                raise ValueError("invalid BSON string length")
            if len(state["strings"]) < 50_000 and state["text_chars"] < state["text_limit"]:
                retain = min(size - 1, 256_000, state["text_limit"] - state["text_chars"])
                value = data[cursor:cursor + retain].decode("utf-8", "replace")
                state["strings"].append(value)
                state["text_chars"] += len(value)
            cursor += size
        elif element_type in {0x03, 0x04}:
            cursor = _walk_bson_document(data, cursor, document_end, depth + 1, state)
        elif element_type == 0x05:
            if cursor + 5 > document_end:
                raise ValueError("truncated BSON binary")
            size = int.from_bytes(data[cursor:cursor + 4], "little", signed=True)
            cursor += 5
            if size < 0 or cursor + size > document_end:
                raise ValueError("invalid BSON binary length")
            payload = data[cursor:cursor + min(size, state["binary_limit"])]
            if payload and len(state["binaries"]) < 32 and state["binary_total"] + len(payload) <= state["binary_total_limit"]:
                state["binaries"].append((key, payload, size))
                state["binary_total"] += len(payload)
            cursor += size
        elif element_type in {0x01, 0x09, 0x11, 0x12}:
            cursor += 8
        elif element_type in {0x10}:
            cursor += 4
        elif element_type in {0x13}:
            cursor += 16
        elif element_type in {0x07}:
            cursor += 12
        elif element_type in {0x08}:
            cursor += 1
        elif element_type in {0x0A, 0x7F, 0xFF}:
            pass
        elif element_type == 0x0B:
            _, cursor = _bson_cstring(data, cursor, document_end)
            _, cursor = _bson_cstring(data, cursor, document_end)
        elif element_type == 0x0F:
            if cursor + 4 > document_end:
                raise ValueError("truncated BSON code-with-scope")
            total = int.from_bytes(data[cursor:cursor + 4], "little", signed=True)
            if total < 14 or cursor + total > document_end:
                raise ValueError("invalid BSON code-with-scope length")
            cursor += total
        else:
            raise ValueError(f"unsupported BSON element type 0x{element_type:02x}")
        if cursor > document_end:
            raise ValueError("BSON element exceeds its document")
        if state["nodes"] >= state["node_limit"] or time.monotonic() > state["deadline"]:
            raise _BsonLimit
    return document_end


def parse_bson(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("bson")
    state: dict[str, Any] = {
        "nodes": 0,
        "node_limit": 200_000 if profile == "deep" else 50_000,
        "binary_limit": 16 * 1024 * 1024 if profile == "deep" else 4 * 1024 * 1024,
        "binary_total": 0,
        "binary_total_limit": 32 * 1024 * 1024 if profile == "deep" else 8 * 1024 * 1024,
        "text_chars": 0,
        "text_limit": 4_000_000 if profile == "deep" else 2_000_000,
        "keys": [], "strings": [], "binaries": [],
        "deadline": time.monotonic() + (8.0 if profile == "deep" else 3.0),
    }
    cursor = 0
    documents = 0
    malformed = None
    limited = False
    maximum_documents = 100_000 if profile == "deep" else 20_000
    while cursor < len(data) and documents < maximum_documents:
        try:
            cursor = _walk_bson_document(data, cursor, len(data), 0, state)
        except _BsonLimit:
            limited = True
            break
        except ValueError as exc:
            malformed = display_text(exc, 300)
            break
        documents += 1
    result["properties"].update({"documents_parsed": documents, "elements_parsed": state["nodes"], "bytes_consumed": cursor, "trailing_bytes": len(data) - cursor, "bounded": limited or documents >= maximum_documents, "parser_error": malformed})
    rendered = [f"key={key}" for key in state["keys"][:50_000]] + [f"string={value}" for value in state["strings"][:50_000]]
    if rendered:
        result["text_records"].append({"encoding": "bson-keys-and-strings", "offset": None, "text": display_text("\n".join(rendered), 2_000_000), "source": "BSON elements", "confidence_hint": 9})
    for key, payload, declared in state["binaries"]:
        result["extracted"].append({"label": f"bson_binary_{display_text(key, 80)}", "data": payload, "kind": sniff_kind(payload), "offset": None, "transformation": f"extract bounded BSON binary field {display_text(key, 80)}", "parameters": {"declared_bytes": declared, "retained_bytes": len(payload)}})
    if malformed and documents == 0:
        result["findings"].append(_finding("warning", "structure", "BSON validation stopped", "No complete top-level BSON document could be validated.", error=malformed))
    return result


def parse_java_serialized(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("java_serialized")
    if not data.startswith(b"\xac\xed\x00\x05"):
        result["findings"].append(_finding("error", "structure", "Invalid Java serialization header", "STREAM_MAGIC or STREAM_VERSION is missing."))
        return result
    scan_limit = min(len(data), 32 * 1024 * 1024 if profile == "deep" else 8 * 1024 * 1024)
    strings: list[str] = []
    cursor = 4
    while cursor < scan_limit and len(strings) < 20_000:
        token = data[cursor]
        if token == 0x74 and cursor + 3 <= scan_limit:
            size = int.from_bytes(data[cursor + 1:cursor + 3], "big")
            if cursor + 3 + size <= scan_limit:
                strings.append(data[cursor + 3:cursor + 3 + size].decode("utf-8", "replace"))
                cursor += 3 + size
                continue
        if token == 0x7C and cursor + 9 <= scan_limit:
            size = int.from_bytes(data[cursor + 1:cursor + 9], "big")
            if size <= 4 * 1024 * 1024 and cursor + 9 + size <= scan_limit:
                strings.append(data[cursor + 9:cursor + 9 + size].decode("utf-8", "replace"))
                cursor += 9 + size
                continue
        cursor += 1
    result["properties"].update({"stream_version": 5, "strings_recovered": len(strings), "bytes_scanned": scan_limit, "truncated": len(data) > scan_limit})
    if strings:
        result["text_records"].append({"encoding": "java-serialization-strings", "offset": None, "text": display_text("\n".join(strings), 2_000_000), "source": "Java TC_STRING/TC_LONGSTRING records", "confidence_hint": 9})
    result["findings"].append(_finding("warning", "serialization", "Java serialized object was not instantiated", "Only bounded stream tokens were inspected; no ObjectInputStream deserialization occurred."))
    return result


def parse_python_pickle(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("python_pickle")
    limit = min(len(data), 32 * 1024 * 1024 if profile == "deep" else 8 * 1024 * 1024)
    opcodes = 0
    globals_found: list[str] = []
    strings: list[str] = []
    stopped = None
    deadline = time.monotonic() + (5.0 if profile == "deep" else 2.0)
    try:
        for opcode, argument, position in pickletools.genops(data[:limit]):
            opcodes += 1
            if opcode.name in {"GLOBAL", "STACK_GLOBAL", "REDUCE", "BUILD", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "EXT1", "EXT2", "EXT4"}:
                globals_found.append(f"offset={position} opcode={opcode.name} argument={display_text(argument, 500)}")
            if isinstance(argument, str) and len(strings) < 50_000:
                strings.append(argument)
            elif isinstance(argument, bytes) and len(argument) <= 1_000_000 and len(strings) < 50_000:
                strings.append(argument.decode("utf-8", "replace"))
            if opcodes >= 200_000 or time.monotonic() > deadline:
                stopped = "resource limit"
                break
    except (ValueError, EOFError, struct.error) as exc:
        stopped = f"{type(exc).__name__}: {display_text(exc, 300)}"
    result["properties"].update({"opcodes_scanned": opcodes, "dangerous_or_constructing_opcodes": len(globals_found), "bytes_available": len(data), "bytes_retained": limit, "stopped": stopped})
    if strings:
        result["text_records"].append({"encoding": "pickle-string-operands", "offset": None, "text": display_text("\n".join(strings), 2_000_000), "source": "pickle opcode arguments", "confidence_hint": 8})
    if globals_found:
        result["text_records"].append({"encoding": "pickle-construction-opcodes", "offset": None, "text": display_text("\n".join(globals_found), 500_000), "source": "pickle executable/construction opcode inventory", "confidence_hint": 9})
    result["findings"].append(_finding("warning", "serialization", "Pickle was disassembled without loading it", "pickle.loads was deliberately not used because a supplied pickle can execute arbitrary code.", construction_opcodes=len(globals_found)))
    return result


def parse_pyc(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("pyc")
    if len(data) < 16 or data[2:4] != b"\r\n":
        result["findings"].append(_finding("warning", "structure", "Unrecognized Python bytecode header", "The file extension indicates PYC, but its implementation-specific magic is incomplete."))
        return result
    flags = int.from_bytes(data[4:8], "little")
    hash_based = bool(flags & 1)
    result["properties"].update({"magic_hex": data[:4].hex(), "flags": f"0x{flags:08x}", "hash_based": hash_based, "checked_hash": bool(flags & 2) if hash_based else None, "source_hash": data[8:16].hex() if hash_based else None, "source_timestamp": int.from_bytes(data[8:12], "little") if not hash_based else None, "source_size": int.from_bytes(data[12:16], "little") if not hash_based else None})
    _append_bounded_strings(result, data[16:], source="PYC code object names and constants (raw, no marshal loading)", profile=profile, confidence=7)
    result["findings"].append(_finding("info", "program", "Python bytecode inspected without unmarshalling", "Only the fixed header and bounded raw strings were read; implementation-specific marshal objects were not instantiated."))
    return result


def parse_git_object(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    kind = "git_pack" if data.startswith(b"PACK") else "git_index"
    result = _result(kind)
    if kind == "git_pack" and len(data) >= 12:
        result["properties"].update({"version": int.from_bytes(data[4:8], "big"), "declared_objects": int.from_bytes(data[8:12], "big"), "has_trailing_sha1": len(data) >= 32})
    elif kind == "git_index" and len(data) >= 12:
        result["properties"].update({"version": int.from_bytes(data[4:8], "big"), "declared_entries": int.from_bytes(data[8:12], "big")})
    else:
        result["findings"].append(_finding("error", "structure", "Truncated Git object container", "The fixed pack/index header is incomplete."))
        return result
    _append_bounded_strings(result, data, source=f"{kind.replace('_', ' ')} names and paths", profile=profile, confidence=7)
    return result


def _intel_hex_checksum(record: bytes) -> bool:
    return bool(record) and sum(record) & 0xFF == 0


def parse_firmware_text(data: bytes, profile: str = "balanced", *, kind: str) -> dict[str, Any]:
    result = _result(kind)
    lines = data[: min(len(data), 64 * 1024 * 1024 if profile == "deep" else 16 * 1024 * 1024)].splitlines()
    decoded: list[tuple[int, bytes]] = []
    invalid = 0
    address_base = 0
    for line_number, raw_line in enumerate(lines[:1_000_000], 1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            if kind == "intel_hex":
                if not line.startswith(b":") or len(line) < 11:
                    raise ValueError
                record = bytes.fromhex(line[1:].decode("ascii"))
                count = record[0]
                if len(record) != count + 5 or not _intel_hex_checksum(record):
                    raise ValueError
                address = int.from_bytes(record[1:3], "big")
                record_type = record[3]
                payload = record[4:4 + count]
                if record_type == 0:
                    decoded.append((address_base + address, payload))
                elif record_type == 2 and len(payload) == 2:
                    address_base = int.from_bytes(payload, "big") << 4
                elif record_type == 4 and len(payload) == 2:
                    address_base = int.from_bytes(payload, "big") << 16
            else:
                if len(line) < 10 or line[:1] != b"S" or line[1:2] not in b"123":
                    continue
                record_type = int(line[1:2])
                record = bytes.fromhex(line[2:].decode("ascii"))
                if not record or record[0] != len(record) - 1 or sum(record) & 0xFF != 0xFF:
                    raise ValueError
                address_size = {1: 2, 2: 3, 3: 4}[record_type]
                address = int.from_bytes(record[1:1 + address_size], "big")
                decoded.append((address, record[1 + address_size:-1]))
        except (ValueError, UnicodeDecodeError):
            invalid += 1
            if invalid > 1_000:
                break
    decoded.sort(key=lambda item: item[0])
    output = bytearray()
    base = decoded[0][0] if decoded else 0
    for address, payload in decoded:
        relative = address - base
        if relative < 0 or relative > 64 * 1024 * 1024:
            continue
        if relative > len(output):
            output.extend(b"\xff" * min(relative - len(output), 8 * 1024 * 1024))
        if relative > len(output):
            continue
        required = relative + len(payload)
        if required > 64 * 1024 * 1024:
            continue
        if required > len(output):
            output.extend(b"\xff" * (required - len(output)))
        output[relative:required] = payload
    result["properties"].update({"records_decoded": len(decoded), "invalid_records": invalid, "lowest_address": base if decoded else None, "highest_address": max((address + len(payload) for address, payload in decoded), default=None), "reconstructed_bytes": len(output), "input_truncated": len(lines) > 1_000_000})
    if output:
        payload = bytes(output)
        result["extracted"].append({"label": f"{kind}_reconstructed_firmware", "data": payload, "kind": sniff_kind(payload), "offset": None, "transformation": f"validate checksums and reconstruct {kind} data records", "parameters": {"base_address": base, "records": len(decoded)}})
    return result


def parse_zip_application(data: bytes, profile: str = "balanced", *, package_kind: str) -> dict[str, Any]:
    """Inspect executable/document ZIP packages without following paths or running code."""

    result = _result(package_kind)
    entry_limit = 2_000 if profile == "deep" else 750
    member_limit = 4 * 1024 * 1024 if profile == "deep" else 1 * 1024 * 1024
    total_limit = 32 * 1024 * 1024 if profile == "deep" else 8 * 1024 * 1024
    if not zip_directory_is_bounded(data, max_entries=10_000, max_directory_bytes=32 * 1024 * 1024):
        result["findings"].append(_finding(
            "warning", "resource-limit", "ZIP application directory rejected",
            "The central directory is missing, multi-disk/Zip64, or exceeds the safe entry/byte limits.",
        ))
        return result
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (OSError, ValueError, zipfile.BadZipFile):
        result["findings"].append(_finding("error", "structure", "Invalid ZIP application package", "The package directory could not be read."))
        return result
    with archive:
        infos = archive.infolist()
        names = [info.filename.replace("\\", "/") for info in infos if not info.is_dir()]
        lowered = [name.casefold() for name in names]
        result["properties"].update({
            "entries": len(infos),
            "encrypted_entries": sum(bool(info.flag_bits & 1) for info in infos),
            "total_declared_uncompressed_bytes": sum(max(0, info.file_size) for info in infos),
            "dex_files": sum(name.endswith(".dex") for name in lowered),
            "native_libraries": sum(name.endswith((".so", ".dll", ".dylib")) for name in lowered),
            "signature_files": sum(name.startswith("meta-inf/") and name.endswith((".rsa", ".dsa", ".ec", ".sf")) for name in lowered),
            "package_names_sample": names[:200],
        })
        text_names = ("manifest", "content_types", "appxmanifest", "androidmanifest", "package", "container", "fixedpage", "documentstructure")
        total_read = 0
        scanned = 0
        for info in infos[:entry_limit]:
            if info.is_dir() or info.flag_bits & 1 or info.file_size <= 0 or info.file_size > member_limit:
                continue
            name = info.filename.replace("\\", "/")
            lowered_name = name.casefold()
            eligible = lowered_name.endswith((".xml", ".rels", ".json", ".txt", ".properties", ".mf", ".html", ".xhtml", ".xaml", ".fpage", ".fdoc", ".fdseq")) or any(marker in lowered_name for marker in text_names)
            if not eligible or total_read >= total_limit or info.compress_size and info.file_size / max(1, info.compress_size) > 200:
                continue
            try:
                with archive.open(info, "r") as member:
                    payload = member.read(min(member_limit, total_limit - total_read) + 1)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                continue
            if len(payload) > min(member_limit, total_limit - total_read):
                continue
            total_read += len(payload)
            scanned += 1
            strings = list(iter_ascii_strings(payload, minimum=4, limit=2_000))
            strings.extend(iter_utf16_strings(payload, minimum=4, limit=2_000))
            if strings:
                result["text_records"].append({"encoding": "zip-package-member-strings", "offset": None, "text": display_text("\n".join(str(item["text"]) for item in strings), 500_000), "source": f"{package_kind.upper()} member:{display_text(name, 240)}", "confidence_hint": 8})
        result["properties"].update({"text_members_scanned": scanned, "text_member_bytes_read": total_read, "entry_listing_truncated": len(infos) > entry_limit})
    result["findings"].append(_finding("info", "package", f"{package_kind.upper()} package inspected", "Package entries were read in memory with per-member, total-size, entry-count, and compression-ratio limits."))
    return result


_DICOM_LONG_VR = {"OB", "OD", "OF", "OL", "OV", "OW", "SQ", "SV", "UC", "UR", "UT", "UN", "UV"}
_DICOM_TEXT_VR = {"AE", "AS", "CS", "DA", "DS", "DT", "IS", "LO", "LT", "PN", "SH", "ST", "TM", "UC", "UI", "UR", "UT"}
_DICOM_TAGS: dict[tuple[int, int], tuple[str, str]] = {
    (0x0002, 0x0002): ("media_storage_sop_class_uid", "UI"),
    (0x0002, 0x0003): ("media_storage_sop_instance_uid", "UI"),
    (0x0002, 0x0010): ("transfer_syntax_uid", "UI"),
    (0x0002, 0x0012): ("implementation_class_uid", "UI"),
    (0x0008, 0x0008): ("image_type", "CS"),
    (0x0008, 0x0020): ("study_date", "DA"),
    (0x0008, 0x0030): ("study_time", "TM"),
    (0x0008, 0x0060): ("modality", "CS"),
    (0x0008, 0x1030): ("study_description", "LO"),
    (0x0008, 0x103E): ("series_description", "LO"),
    (0x0010, 0x0010): ("patient_name", "PN"),
    (0x0010, 0x0020): ("patient_id", "LO"),
    (0x0018, 0x1030): ("protocol_name", "LO"),
    (0x0020, 0x0011): ("series_number", "IS"),
    (0x0020, 0x0013): ("instance_number", "IS"),
    (0x0028, 0x0008): ("number_of_frames", "IS"),
    (0x0028, 0x0010): ("rows", "US"),
    (0x0028, 0x0011): ("columns", "US"),
    (0x0028, 0x0100): ("bits_allocated", "US"),
    (0x7FE0, 0x0010): ("pixel_data", "OB"),
}


def _dicom_element(
    data: bytes,
    cursor: int,
    end: int,
    *,
    endian: str,
    explicit_vr: bool,
) -> tuple[tuple[int, int], str, int | None, int, int]:
    if cursor + 8 > end:
        raise ValueError("truncated DICOM element header")
    group, element = struct.unpack_from(f"{endian}HH", data, cursor)
    if explicit_vr:
        raw_vr = data[cursor + 4:cursor + 6]
        if len(raw_vr) != 2 or not raw_vr.isalpha() or not raw_vr.isupper():
            raise ValueError("invalid explicit DICOM value representation")
        vr = raw_vr.decode("ascii")
        if vr in _DICOM_LONG_VR:
            if cursor + 12 > end:
                raise ValueError("truncated long DICOM element header")
            length = struct.unpack_from(f"{endian}I", data, cursor + 8)[0]
            value_offset = cursor + 12
        else:
            length = struct.unpack_from(f"{endian}H", data, cursor + 6)[0]
            value_offset = cursor + 8
    else:
        vr = _DICOM_TAGS.get((group, element), ("", "UN"))[1]
        length = struct.unpack_from(f"{endian}I", data, cursor + 4)[0]
        value_offset = cursor + 8
    if length == 0xFFFFFFFF:
        return (group, element), vr, None, value_offset, value_offset
    if length > end - value_offset:
        raise ValueError("DICOM element exceeds retained bytes")
    return (group, element), vr, length, value_offset, value_offset + length


def parse_dicom(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Inspect a Part 10 DICOM stream without decoding pixel data."""

    result = _result("dicom")
    if len(data) < 132 or data[128:132] != b"DICM":
        result["findings"].append(_finding("error", "structure", "Invalid DICOM Part 10 header", "The 128-byte preamble and DICM prefix are missing or truncated."))
        return result
    preamble = data[:128]
    result["properties"].update({"file_size": len(data), "preamble_nonzero_bytes": sum(value != 0 for value in preamble)})
    preamble_kind = sniff_kind(preamble)
    if any(preamble) and preamble_kind not in {"binary", "text"}:
        result["extracted"].append({
            "label": "dicom_preamble_payload",
            "data": preamble,
            "kind": preamble_kind,
            "offset": 0,
            "transformation": "extract non-zero DICOM preamble",
            "parameters": {"bytes": 128},
        })

    scan_end = min(len(data), 64 * 1024 * 1024 if profile == "deep" else 16 * 1024 * 1024)
    cursor = 132
    transfer_syntax = "1.2.840.10008.1.2.1"
    values: list[str] = []
    elements = 0
    malformed: str | None = None
    deadline = time.monotonic() + (8.0 if profile == "deep" else 3.0)

    while cursor + 8 <= scan_end and elements < 20_000:
        group = int.from_bytes(data[cursor:cursor + 2], "little")
        if group != 0x0002:
            break
        try:
            tag, vr, length, value_offset, next_cursor = _dicom_element(data, cursor, scan_end, endian="<", explicit_vr=True)
        except ValueError as exc:
            malformed = display_text(exc, 300)
            break
        if length is None:
            malformed = "undefined-length file meta element"
            break
        payload = data[value_offset:next_cursor]
        name = _DICOM_TAGS.get(tag, (f"tag_{tag[0]:04x}_{tag[1]:04x}", vr))[0]
        if vr in _DICOM_TEXT_VR and length <= 1_000_000:
            value = payload.rstrip(b"\0 ").decode("utf-8", "replace")
            if value:
                values.append(f"({tag[0]:04X},{tag[1]:04X}) {name} [{vr}] = {value}")
                if name == "transfer_syntax_uid":
                    transfer_syntax = value
                result["metadata"][name] = display_text(value, 16_384)
        cursor = next_cursor
        elements += 1

    endian = ">" if transfer_syntax == "1.2.840.10008.1.2.2" else "<"
    explicit_vr = transfer_syntax != "1.2.840.10008.1.2"
    pixel_offset: int | None = None
    pixel_length: int | None = None
    while cursor + 8 <= scan_end and elements < (100_000 if profile == "deep" else 40_000) and time.monotonic() <= deadline:
        try:
            tag, vr, length, value_offset, next_cursor = _dicom_element(data, cursor, scan_end, endian=endian, explicit_vr=explicit_vr)
        except ValueError as exc:
            malformed = display_text(exc, 300)
            break
        name, expected_vr = _DICOM_TAGS.get(tag, (f"tag_{tag[0]:04x}_{tag[1]:04x}", vr))
        if tag == (0x7FE0, 0x0010):
            pixel_offset, pixel_length = value_offset, length
            if length is None:
                malformed = "encapsulated undefined-length pixel data was not traversed"
            break
        if length is None:
            malformed = f"undefined-length {name}; nested sequences were not traversed"
            break
        payload = data[value_offset:next_cursor]
        effective_vr = vr if explicit_vr else expected_vr
        if effective_vr in _DICOM_TEXT_VR and length <= 1_000_000:
            value = payload.rstrip(b"\0 ").decode("utf-8", "replace")
            if value:
                values.append(f"({tag[0]:04X},{tag[1]:04X}) {name} [{effective_vr}] = {value}")
                if tag in _DICOM_TAGS:
                    result["metadata"][name] = display_text(value, 16_384)
        elif effective_vr in {"US", "SS"} and length in {2, 4, 6, 8} and tag in _DICOM_TAGS:
            signed = effective_vr == "SS"
            width = 2
            numbers = [int.from_bytes(payload[index:index + width], "little" if endian == "<" else "big", signed=signed) for index in range(0, length, width)]
            result["properties"][name] = numbers[0] if len(numbers) == 1 else numbers
        cursor = next_cursor
        elements += 1

    result["properties"].update({
        "transfer_syntax_uid": transfer_syntax,
        "explicit_vr": explicit_vr,
        "byte_order": "big-endian" if endian == ">" else "little-endian",
        "elements_scanned": elements,
        "bytes_scanned": min(cursor, scan_end),
        "pixel_data_offset": pixel_offset,
        "pixel_data_length": pixel_length,
        "parser_stop": malformed,
        "input_truncated": len(data) > scan_end,
    })
    if values:
        result["text_records"].append({"encoding": "dicom-text-vr", "offset": 132, "text": display_text("\n".join(values), 2_000_000), "source": "DICOM text-valued data elements", "confidence_hint": 10})
    if malformed:
        result["findings"].append(_finding("info", "structure", "DICOM traversal stopped conservatively", "The parser retained completed elements and stopped before an unsupported or incomplete structure.", reason=malformed))
    return result


def parse_fits(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Parse bounded FITS HDUs and carve only bytes after their padded end."""

    result = _result("fits")
    if len(data) < 80 or not data[:30].startswith(b"SIMPLE  ="):
        result["findings"].append(_finding("error", "structure", "Invalid FITS primary header", "The first 80-byte card does not begin with the required SIMPLE keyword."))
        return result
    card_limit = 100_000 if profile == "deep" else 25_000
    hdu_limit = 1_024 if profile == "deep" else 256
    all_cards: list[str] = []
    summaries: list[dict[str, Any]] = []
    primary_values: dict[str, str] = {}
    cursor = 0
    cards_scanned = 0
    incomplete: str | None = None

    for hdu_index in range(hdu_limit):
        if cursor + 80 > len(data):
            break
        prefix = data[cursor:cursor + 8]
        if hdu_index == 0 and prefix != b"SIMPLE  ":
            incomplete = "primary HDU does not start with SIMPLE"
            break
        if hdu_index > 0 and prefix not in {b"XTENSION", b"SIMPLE  "}:
            break
        header_start = cursor
        values: dict[str, str] = {}
        cards: list[str] = []
        end_offset: int | None = None
        while cursor + 80 <= len(data) and cards_scanned < card_limit:
            raw = data[cursor:cursor + 80]
            card = raw.decode("ascii", "replace")
            keyword = card[:8].strip()
            if keyword:
                cards.append(card.rstrip())
            if card[8:10] == "= ":
                values[keyword] = card[10:].split("/", 1)[0].strip()
            cursor += 80
            cards_scanned += 1
            if keyword == "END":
                end_offset = cursor
                break
        if end_offset is None:
            incomplete = f"HDU {hdu_index} has no END card within the bounded scan"
            break
        header_bytes = ((end_offset - header_start + 2879) // 2880) * 2880
        data_start = header_start + header_bytes
        if data_start > len(data):
            incomplete = f"HDU {hdu_index} header padding exceeds retained bytes"
            break

        def integer(keyword: str, default: int = 0) -> int:
            try:
                return int(values.get(keyword, str(default)).strip().strip("'"))
            except ValueError:
                return default

        bitpix = integer("BITPIX")
        naxis = max(0, min(999, integer("NAXIS")))
        if naxis > 16:
            incomplete = f"HDU {hdu_index} declares more than 16 dimensions"
            break
        axes = [max(0, integer(f"NAXIS{axis}")) for axis in range(1, naxis + 1)]
        elements = 1
        for axis in axes:
            elements *= axis
            if elements > 1 << 60:
                incomplete = f"HDU {hdu_index} dimensions exceed the safe arithmetic limit"
                break
        if incomplete:
            break
        bytes_per_value = abs(bitpix) // 8 if bitpix and abs(bitpix) % 8 == 0 else 0
        pcount = max(0, integer("PCOUNT"))
        gcount = max(1, integer("GCOUNT", 1))
        expected_data = bytes_per_value * gcount * (elements + pcount) if naxis > 0 and bytes_per_value else 0
        padded_data_bytes = ((expected_data + 2879) // 2880) * 2880
        logical_end = data_start + padded_data_bytes
        if logical_end > len(data):
            incomplete = f"HDU {hdu_index} data exceeds retained bytes"
            break
        hdu_type = "PRIMARY" if hdu_index == 0 else values.get("XTENSION", "EXTENSION").strip().strip("'")
        summaries.append({"index": hdu_index, "type": hdu_type, "header_offset": header_start, "header_bytes": header_bytes, "data_offset": data_start, "data_bytes": expected_data, "padded_end": logical_end, "bitpix": bitpix, "axes": axes})
        all_cards.extend([f"[HDU {hdu_index} {hdu_type}]", *cards])
        if hdu_index == 0:
            primary_values = values
        cursor = logical_end

    if len(summaries) >= hdu_limit and data[cursor:cursor + 8] in {b"XTENSION", b"SIMPLE  "}:
        incomplete = "FITS HDU traversal reached the profile HDU limit"
    trailer_bytes = max(0, len(data) - cursor)
    primary = summaries[0] if summaries else {}
    result["properties"].update({
        "hdu_count": len(summaries), "cards": cards_scanned, "hdus": summaries[:256],
        "header_bytes": primary.get("header_bytes"), "bitpix": primary.get("bitpix"), "naxis": len(primary.get("axes", [])),
        "axes": primary.get("axes", []), "expected_primary_data_bytes": primary.get("data_bytes"),
        "expected_primary_hdu_end": primary.get("padded_end"), "logical_file_end": cursor,
        "trailing_bytes": trailer_bytes, "header_scan_bounded": cards_scanned >= card_limit,
        "parser_stop": incomplete,
    })
    for key in ("OBJECT", "TELESCOP", "INSTRUME", "OBSERVER", "DATE", "DATE-OBS", "ORIGIN", "EXTEND"):
        if key in primary_values:
            result["metadata"][key.casefold().replace("-", "_")] = display_text(primary_values[key].strip().strip("'"), 16_384)
    if all_cards:
        result["text_records"].append({"encoding": "fits-80-byte-cards", "offset": 0, "text": display_text("\n".join(all_cards), 2_000_000), "source": "FITS HDU header cards", "confidence_hint": 10})
    if incomplete:
        result["findings"].append(_finding("warning", "structure", "FITS traversal stopped", "Completed HDUs were retained before an incomplete or unsafe header/data declaration.", reason=incomplete))
    trailer_limit = 64 * 1024 * 1024 if profile == "deep" else 16 * 1024 * 1024
    if summaries and not incomplete and 0 < trailer_bytes <= trailer_limit:
        trailer = data[cursor:]
        if any(trailer):
            result["extracted"].append({"label": "fits_trailing_payload", "data": trailer, "kind": sniff_kind(trailer), "offset": cursor, "transformation": "extract bytes after the final padded FITS HDU", "parameters": {"bytes": len(trailer), "hdus": len(summaries)}})
    return result


def parse_qoi(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("qoi")
    if len(data) < 22 or not data.startswith(b"qoif"):
        result["findings"].append(_finding("error", "structure", "Invalid QOI header", "The qoif header or minimum end marker is missing."))
        return result
    width = int.from_bytes(data[4:8], "big")
    height = int.from_bytes(data[8:12], "big")
    channels, colorspace = data[12], data[13]
    target_pixels = width * height
    cursor = 14
    decoded_pixels = 0
    chunks = 0
    limit = min(len(data), 192 * 1024 * 1024 if profile == "deep" else 96 * 1024 * 1024)
    chunk_limit = {"quick": 500_000, "balanced": 2_000_000, "deep": 5_000_000}.get(profile, 2_000_000)
    deadline = time.monotonic() + (5.0 if profile == "deep" else 2.0)
    while cursor < limit and decoded_pixels < target_pixels and chunks < chunk_limit and time.monotonic() <= deadline:
        opcode = data[cursor]
        cursor += 1
        if opcode == 0xFE:
            cursor += 3
            decoded_pixels += 1
        elif opcode == 0xFF:
            cursor += 4
            decoded_pixels += 1
        elif opcode & 0xC0 == 0x80:
            cursor += 1
            decoded_pixels += 1
        elif opcode & 0xC0 == 0xC0:
            decoded_pixels += (opcode & 0x3F) + 1
        else:
            decoded_pixels += 1
        chunks += 1
        if cursor > limit:
            break
    marker_valid = decoded_pixels == target_pixels and data[cursor:cursor + 8] == b"\0\0\0\0\0\0\0\x01"
    logical_end = cursor + 8 if marker_valid else cursor
    trailer_bytes = max(0, len(data) - logical_end) if marker_valid else 0
    scan_bounded = not marker_valid and (chunks >= chunk_limit or time.monotonic() > deadline)
    result["properties"].update({
        "width": width, "height": height, "channels": channels, "colorspace": colorspace,
        "target_pixels": target_pixels, "decoded_pixels": decoded_pixels, "chunks_scanned": chunks,
        "end_marker_valid": marker_valid, "logical_end": logical_end if marker_valid else None,
        "trailing_bytes": trailer_bytes, "geometry_valid": width > 0 and height > 0 and channels in {3, 4} and colorspace in {0, 1},
        "scan_bounded": scan_bounded,
    })
    if scan_bounded:
        result["findings"].append(_finding("info", "resource-limit", "QOI chunk traversal reached its profile limit", "No logical trailer was emitted because the canonical end marker was not reached within the chunk/time budget.", chunks=chunks, chunk_limit=chunk_limit))
    elif not marker_valid:
        result["findings"].append(_finding("warning", "structure", "QOI stream did not reach its canonical end marker", "Chunk lengths or the declared pixel count do not match the available bytes."))
    trailer_limit = 64 * 1024 * 1024 if profile == "deep" else 16 * 1024 * 1024
    if 0 < trailer_bytes <= trailer_limit:
        trailer = data[logical_end:]
        result["extracted"].append({"label": "qoi_trailing_payload", "data": trailer, "kind": sniff_kind(trailer), "offset": logical_end, "transformation": "extract bytes after canonical QOI end marker", "parameters": {"bytes": len(trailer)}})
    return result


def parse_dds(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("dds")
    if len(data) < 128 or data[:4] != b"DDS " or int.from_bytes(data[4:8], "little") != 124:
        result["findings"].append(_finding("error", "structure", "Invalid DDS header", "DDS magic and the 124-byte base header are required."))
        return result
    pixel_format_size = int.from_bytes(data[76:80], "little")
    fourcc = data[84:88].rstrip(b"\0").decode("ascii", "replace")
    has_dx10 = fourcc == "DX10" and len(data) >= 148
    result["properties"].update({
        "flags": f"0x{int.from_bytes(data[8:12], 'little'):08x}",
        "height": int.from_bytes(data[12:16], "little"), "width": int.from_bytes(data[16:20], "little"),
        "pitch_or_linear_size": int.from_bytes(data[20:24], "little"), "depth": int.from_bytes(data[24:28], "little"),
        "mipmap_count": int.from_bytes(data[28:32], "little"), "pixel_format_size": pixel_format_size,
        "pixel_format_flags": f"0x{int.from_bytes(data[80:84], 'little'):08x}", "fourcc": fourcc or None,
        "rgb_bit_count": int.from_bytes(data[88:92], "little"), "caps": f"0x{int.from_bytes(data[108:112], 'little'):08x}",
        "has_dx10_header": has_dx10, "pixel_data_offset": 148 if has_dx10 else 128,
    })
    if has_dx10:
        result["properties"].update({"dxgi_format": int.from_bytes(data[128:132], "little"), "resource_dimension": int.from_bytes(data[132:136], "little"), "array_size": int.from_bytes(data[140:144], "little")})
    if pixel_format_size != 32:
        result["findings"].append(_finding("warning", "structure", "Unexpected DDS pixel-format size", "The DDS_PIXELFORMAT structure should be 32 bytes.", declared=pixel_format_size))
    _append_bounded_strings(result, data[: min(len(data), 4 * 1024 * 1024)], source="DDS header and texture strings", profile=profile, confidence=6)
    return result


_KTX1_IDENTIFIER = b"\xabKTX 11\xbb\r\n\x1a\n"
_KTX2_IDENTIFIER = b"\xabKTX 20\xbb\r\n\x1a\n"


def _ktx_key_values(data: bytes, offset: int, length: int, *, endian: str) -> list[str]:
    if offset < 0 or length < 0 or offset + length > len(data) or length > 32 * 1024 * 1024:
        return []
    cursor, end = offset, offset + length
    records: list[str] = []
    while cursor + 4 <= end and len(records) < 10_000:
        size = int.from_bytes(data[cursor:cursor + 4], "little" if endian == "<" else "big")
        cursor += 4
        if size <= 0 or size > end - cursor:
            break
        payload = data[cursor:cursor + size]
        key, separator, value = payload.partition(b"\0")
        rendered_key = key.decode("utf-8", "replace")
        if separator:
            rendered_value = value.rstrip(b"\0").decode("utf-8", "replace")
            records.append(f"{rendered_key}={display_text(rendered_value, 16_384)}")
        else:
            records.append(display_text(rendered_key, 16_384))
        cursor += size
        cursor = (cursor + 3) & ~3
    return records


def parse_ktx(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("ktx")
    if data.startswith(_KTX1_IDENTIFIER) and len(data) >= 64:
        endian_marker = data[12:16]
        endian = "<" if endian_marker == b"\x01\x02\x03\x04" else ">" if endian_marker == b"\x04\x03\x02\x01" else ""
        if not endian:
            result["findings"].append(_finding("error", "structure", "Invalid KTX1 endianness marker", "The KTX1 byte-order marker is not recognized."))
            return result
        fields = struct.unpack_from(f"{endian}12I", data, 16)
        gl_type, type_size, gl_format, internal_format, base_format, width, height, depth, arrays, faces, levels, kv_bytes = fields
        kv_offset = 64
        records = _ktx_key_values(data, kv_offset, kv_bytes, endian=endian)
        result["properties"].update({"version": 1, "byte_order": "little-endian" if endian == "<" else "big-endian", "gl_type": gl_type, "type_size": type_size, "gl_format": gl_format, "gl_internal_format": internal_format, "gl_base_internal_format": base_format, "width": width, "height": height, "depth": depth, "array_elements": arrays, "faces": faces, "mipmap_levels": levels, "key_value_bytes": kv_bytes, "image_data_offset": kv_offset + kv_bytes})
    elif data.startswith(_KTX2_IDENTIFIER) and len(data) >= 80:
        fields = struct.unpack_from("<9I4I2Q", data, 12)
        vk_format, type_size, width, height, depth, layers, faces, levels, supercompression, dfd_offset, dfd_length, kv_offset, kv_length, sgd_offset, sgd_length = fields
        records = _ktx_key_values(data, kv_offset, kv_length, endian="<")
        result["properties"].update({"version": 2, "vk_format": vk_format, "type_size": type_size, "width": width, "height": height, "depth": depth, "layers": layers, "faces": faces, "levels": levels, "supercompression_scheme": supercompression, "dfd_offset": dfd_offset, "dfd_bytes": dfd_length, "key_value_offset": kv_offset, "key_value_bytes": kv_length, "supercompression_global_offset": sgd_offset, "supercompression_global_bytes": sgd_length})
    else:
        result["findings"].append(_finding("error", "structure", "Invalid KTX header", "Neither the KTX1 nor KTX2 identifier and minimum header were found."))
        return result
    if records:
        result["text_records"].append({"encoding": "ktx-key-value-data", "offset": None, "text": display_text("\n".join(records), 1_000_000), "source": "KTX metadata", "confidence_hint": 10})
    return result


def _bounded_cstring(data: bytes, cursor: int, end: int, maximum: int = 65_536) -> tuple[str, int]:
    terminator = data.find(b"\0", cursor, min(end, cursor + maximum))
    if terminator < 0:
        raise ValueError("unterminated bounded string")
    return data[cursor:terminator].decode("utf-8", "replace"), terminator + 1


def parse_openexr(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("openexr")
    if len(data) < 9 or data[:4] != b"v/1\x01":
        result["findings"].append(_finding("error", "structure", "Invalid OpenEXR header", "The OpenEXR magic number and version field are missing."))
        return result
    version_field = int.from_bytes(data[4:8], "little")
    cursor = 8
    scan_end = min(len(data), 32 * 1024 * 1024 if profile == "deep" else 8 * 1024 * 1024)
    attributes: list[str] = []
    attribute_count = 0
    malformed: str | None = None
    while cursor < scan_end and attribute_count < 20_000:
        if data[cursor] == 0:
            cursor += 1
            break
        try:
            name, cursor = _bounded_cstring(data, cursor, scan_end, 4_096)
            attr_type, cursor = _bounded_cstring(data, cursor, scan_end, 4_096)
        except ValueError as exc:
            malformed = display_text(exc, 300)
            break
        if cursor + 4 > scan_end:
            malformed = "truncated OpenEXR attribute size"
            break
        size = int.from_bytes(data[cursor:cursor + 4], "little")
        cursor += 4
        if size > scan_end - cursor:
            malformed = f"attribute {name} exceeds retained header bytes"
            break
        payload = data[cursor:cursor + size]
        cursor += size
        rendered = f"{name} [{attr_type}] ({size} bytes)"
        if attr_type in {"string", "stringvector"} and size <= 1_000_000:
            value = payload.rstrip(b"\0").decode("utf-8", "replace")
            rendered += f" = {display_text(value, 16_384)}"
            result["metadata"][safe_label(name, 80)] = display_text(value, 16_384)
        elif attr_type == "box2i" and size == 16:
            x_min, y_min, x_max, y_max = struct.unpack("<iiii", payload)
            result["properties"][safe_label(name, 80)] = {"x_min": x_min, "y_min": y_min, "x_max": x_max, "y_max": y_max, "width": x_max - x_min + 1, "height": y_max - y_min + 1}
        elif attr_type == "compression" and size == 1:
            result["properties"]["compression_code"] = payload[0]
        elif attr_type == "chlist":
            channel_cursor = 0
            channels: list[str] = []
            while channel_cursor < len(payload) and len(channels) < 256 and payload[channel_cursor] != 0:
                try:
                    channel, next_cursor = _bounded_cstring(payload, channel_cursor, len(payload), 4_096)
                except ValueError:
                    break
                if next_cursor + 16 > len(payload):
                    break
                channels.append(channel)
                channel_cursor = next_cursor + 16
            result["properties"]["channels"] = channels
            rendered += f" = {', '.join(channels)}"
        attributes.append(rendered)
        attribute_count += 1
    result["properties"].update({"version": version_field & 0xFF, "version_flags": f"0x{version_field & 0xFFFFFF00:08x}", "tiled": bool(version_field & 0x200), "long_names": bool(version_field & 0x400), "deep_data": bool(version_field & 0x800), "multi_part": bool(version_field & 0x1000), "attributes": attribute_count, "header_end": cursor, "parser_stop": malformed})
    if attributes:
        result["text_records"].append({"encoding": "openexr-attributes", "offset": 8, "text": display_text("\n".join(attributes), 1_000_000), "source": "OpenEXR header attributes", "confidence_hint": 10})
    if malformed:
        result["findings"].append(_finding("warning", "structure", "OpenEXR header traversal stopped", "Completed attributes were retained before an invalid or incomplete attribute.", reason=malformed))
    return result


def parse_android_sparse(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("android_sparse")
    if len(data) < 28 or data[:4] != b"\x3a\xff\x26\xed":
        result["findings"].append(_finding("error", "structure", "Invalid Android sparse-image header", "The sparse magic or 28-byte header is missing."))
        return result
    magic, major, minor, file_header_size, chunk_header_size, block_size, total_blocks, total_chunks, checksum = struct.unpack_from("<IHHHHIIII", data, 0)
    output_size = block_size * total_blocks
    result["properties"].update({"major_version": major, "minor_version": minor, "file_header_size": file_header_size, "chunk_header_size": chunk_header_size, "block_size": block_size, "total_blocks": total_blocks, "total_chunks": total_chunks, "expanded_bytes": output_size, "image_checksum": f"0x{checksum:08x}"})
    if magic != 0xED26FF3A or not 28 <= file_header_size <= 4096 or not 12 <= chunk_header_size <= 4096 or block_size < 512 or block_size > 16 * 1024 * 1024 or block_size % 4:
        result["findings"].append(_finding("error", "structure", "Unsafe Android sparse-image geometry", "One or more fixed header sizes are outside conservative bounds."))
        return result
    reconstruct_limit = {"quick": 16, "balanced": 64, "deep": 192}.get(profile, 64) * 1024 * 1024
    reconstruct = output_size <= reconstruct_limit
    expanded = bytearray() if reconstruct else None
    cursor = file_header_size
    blocks_seen = 0
    parsed = 0
    counts: dict[str, int] = {"raw": 0, "fill": 0, "skip": 0, "crc32": 0}
    malformed: str | None = None
    deadline = time.monotonic() + (8.0 if profile == "deep" else 3.0)
    for _ in range(min(total_chunks, 1_000_000)):
        if time.monotonic() > deadline:
            malformed = "sparse chunk traversal reached the profile time limit"
            break
        if cursor + chunk_header_size > len(data):
            malformed = "truncated sparse chunk header"
            break
        chunk_type, _reserved, chunk_blocks, total_size = struct.unpack_from("<HHII", data, cursor)
        if total_size < chunk_header_size or total_size > len(data) - cursor:
            malformed = "sparse chunk leaves the retained file"
            break
        payload_offset = cursor + chunk_header_size
        payload_size = total_size - chunk_header_size
        expanded_chunk = chunk_blocks * block_size
        if chunk_type != 0xCAC4 and (chunk_blocks > total_blocks - blocks_seen or expanded_chunk > output_size):
            malformed = "sparse chunks exceed the declared expanded block count"
            break
        if chunk_type == 0xCAC1:
            if payload_size != expanded_chunk:
                malformed = "raw sparse chunk size mismatch"
                break
            counts["raw"] += 1
            if expanded is not None:
                expanded.extend(data[payload_offset:payload_offset + payload_size])
        elif chunk_type == 0xCAC2:
            if payload_size != 4:
                malformed = "fill sparse chunk is not four bytes"
                break
            counts["fill"] += 1
            if expanded is not None:
                expanded.extend(data[payload_offset:payload_offset + 4] * (expanded_chunk // 4))
        elif chunk_type == 0xCAC3:
            if payload_size != 0:
                malformed = "don't-care sparse chunk unexpectedly has data"
                break
            counts["skip"] += 1
            if expanded is not None:
                expanded.extend(b"\0" * expanded_chunk)
        elif chunk_type == 0xCAC4:
            if payload_size != 4 or chunk_blocks != 0:
                malformed = "CRC32 sparse chunk has invalid geometry"
                break
            counts["crc32"] += 1
        else:
            malformed = f"unknown sparse chunk type 0x{chunk_type:04x}"
            break
        blocks_seen += chunk_blocks
        parsed += 1
        cursor += total_size
    valid = malformed is None and parsed == total_chunks and blocks_seen == total_blocks
    result["properties"].update({"chunks_parsed": parsed, "blocks_reconstructed": blocks_seen, "chunk_counts": counts, "valid_chunk_table": valid, "parser_stop": malformed, "reconstruction_limited": not reconstruct})
    if valid and expanded is not None and len(expanded) == output_size:
        payload = bytes(expanded)
        result["extracted"].append({"label": "android_sparse_expanded_image", "data": payload, "kind": sniff_kind(payload, "expanded.img"), "offset": None, "transformation": "expand validated Android sparse chunks", "parameters": {"bytes": len(payload), "chunks": parsed}})
    elif not reconstruct:
        result["findings"].append(_finding("info", "resource-limit", "Android sparse expansion was not materialized", "The declared expanded image exceeds the profile's in-memory child-artifact limit.", declared_bytes=output_size, limit_bytes=reconstruct_limit))
    if malformed:
        result["findings"].append(_finding("warning", "structure", "Android sparse chunk traversal stopped", "No partial expanded image was emitted.", reason=malformed))
    return result


def parse_dtb(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("dtb")
    if len(data) < 40 or data[:4] != b"\xd0\x0d\xfe\xed":
        result["findings"].append(_finding("error", "structure", "Invalid flattened device tree header", "The FDT magic or 40-byte header is missing."))
        return result
    fields = struct.unpack_from(">10I", data, 0)
    _magic, total_size, struct_offset, strings_offset, reserve_offset, version, last_compatible, boot_cpu, strings_size, struct_size = fields
    result["properties"].update({"declared_total_bytes": total_size, "structure_offset": struct_offset, "structure_bytes": struct_size, "strings_offset": strings_offset, "strings_bytes": strings_size, "reserve_map_offset": reserve_offset, "version": version, "last_compatible_version": last_compatible, "boot_cpu_id": boot_cpu})
    boundary = min(total_size, len(data))
    if total_size < 40 or struct_offset + struct_size > boundary or strings_offset + strings_size > boundary:
        result["findings"].append(_finding("error", "structure", "Device-tree blocks exceed the file", "The structure or strings block is outside the declared and retained bounds."))
        return result
    strings = data[strings_offset:strings_offset + strings_size]
    cursor, struct_end = struct_offset, struct_offset + struct_size
    stack: list[str] = []
    records: list[str] = []
    nodes = properties = 0
    extracted_total = 0
    malformed: str | None = None
    deadline = time.monotonic() + (8.0 if profile == "deep" else 3.0)
    while cursor + 4 <= struct_end and nodes < 100_000 and properties < 200_000 and time.monotonic() <= deadline:
        token = int.from_bytes(data[cursor:cursor + 4], "big")
        cursor += 4
        if token == 1:
            try:
                name, cursor = _bounded_cstring(data, cursor, struct_end, 65_536)
            except ValueError as exc:
                malformed = display_text(exc, 300)
                break
            cursor = (cursor + 3) & ~3
            if len(stack) >= 128:
                malformed = "device-tree nesting limit reached"
                break
            stack.append(name)
            nodes += 1
        elif token == 2:
            if not stack:
                malformed = "unbalanced FDT_END_NODE token"
                break
            stack.pop()
        elif token == 3:
            if cursor + 8 > struct_end:
                malformed = "truncated FDT_PROP token"
                break
            length, name_offset = struct.unpack_from(">II", data, cursor)
            cursor += 8
            if length > struct_end - cursor or name_offset >= len(strings):
                malformed = "device-tree property leaves its blocks"
                break
            try:
                name, _ = _bounded_cstring(strings, name_offset, len(strings), 65_536)
            except ValueError as exc:
                malformed = display_text(exc, 300)
                break
            payload = data[cursor:cursor + length]
            path = "/" + "/".join(part for part in stack if part)
            rendered = ""
            parts = payload.rstrip(b"\0").split(b"\0") if payload else []
            if parts and all(part and sum(32 <= byte < 127 or byte in {9, 10, 13} for byte in part) / len(part) >= 0.85 for part in parts):
                rendered = " | ".join(part.decode("utf-8", "replace") for part in parts)
            elif length in {4, 8, 12, 16}:
                rendered = " ".join(f"0x{int.from_bytes(payload[index:index + 4], 'big'):08x}" for index in range(0, length, 4))
            if rendered:
                records.append(f"{path or '/'}: {name} = {display_text(rendered, 32_768)}")
            child_kind = sniff_kind(payload, name)
            if 8 <= length <= 4 * 1024 * 1024 and child_kind not in {"binary", "text", "dtb"} and len(result["extracted"]) < 32 and extracted_total + length <= 16 * 1024 * 1024:
                result["extracted"].append({"label": f"dtb_{safe_label(name, 80)}", "data": payload, "kind": child_kind, "offset": cursor, "transformation": f"extract bounded device-tree property {safe_label(name, 80)}", "parameters": {"node": display_text(path or "/", 240), "bytes": length}})
                extracted_total += length
            cursor += length
            cursor = (cursor + 3) & ~3
            properties += 1
        elif token == 4:
            continue
        elif token == 9:
            break
        else:
            malformed = f"unknown device-tree token 0x{token:08x}"
            break
    result["properties"].update({"nodes": nodes, "properties": properties, "bytes_consumed": cursor - struct_offset, "parser_stop": malformed, "trailing_bytes": max(0, len(data) - total_size)})
    if records:
        result["text_records"].append({"encoding": "flattened-device-tree-properties", "offset": struct_offset, "text": display_text("\n".join(records), 2_000_000), "source": "flattened device-tree nodes and properties", "confidence_hint": 10})
    if malformed:
        result["findings"].append(_finding("warning", "structure", "Device-tree traversal stopped", "Completed nodes and properties were retained before an invalid token or resource limit.", reason=malformed))
    return result


def parse_tnef(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("tnef")
    if len(data) < 6 or data[:4] != b"x\x9f>\x22":
        result["findings"].append(_finding("error", "structure", "Invalid TNEF header", "The Microsoft TNEF signature and legacy key are missing."))
        return result
    attribute_names = {
        0x8004: "subject", 0x8008: "message_class", 0x800C: "body", 0x800F: "attachment_data",
        0x8010: "attachment_title", 0x8011: "attachment_metafile", 0x9001: "attachment_transport_filename",
        0x9002: "attachment_render_data", 0x9003: "mapi_properties", 0x9005: "attachment_properties",
        0x9006: "tnef_version", 0x9007: "oem_codepage",
    }
    cursor = 6
    attributes = invalid_checksums = 0
    current_name = "attachment.bin"
    text: list[str] = []
    extracted_total = 0
    scan_end = min(len(data), 128 * 1024 * 1024 if profile == "deep" else 32 * 1024 * 1024)
    malformed: str | None = None
    while cursor + 11 <= scan_end and attributes < 100_000:
        level = data[cursor]
        attribute_id = int.from_bytes(data[cursor + 1:cursor + 3], "little")
        attribute_type = int.from_bytes(data[cursor + 3:cursor + 5], "little")
        length = int.from_bytes(data[cursor + 5:cursor + 9], "little")
        value_offset = cursor + 9
        checksum_offset = value_offset + length
        if length > scan_end - value_offset or checksum_offset + 2 > scan_end:
            malformed = "TNEF attribute exceeds retained bytes"
            break
        payload = data[value_offset:checksum_offset]
        checksum = int.from_bytes(data[checksum_offset:checksum_offset + 2], "little")
        if sum(payload) & 0xFFFF != checksum:
            invalid_checksums += 1
        name = attribute_names.get(attribute_id, f"attribute_0x{attribute_id:04x}")
        if attribute_id in {0x8004, 0x8008, 0x800C, 0x8010, 0x9001}:
            value = payload.rstrip(b"\0").decode("cp1252", "replace")
            text.append(f"{name} = {display_text(value, 100_000)}")
            if attribute_id in {0x8010, 0x9001} and value.strip():
                current_name = safe_label(value, 120)
        if attribute_id == 0x800F and payload and len(result["extracted"]) < 64 and extracted_total + len(payload) <= 64 * 1024 * 1024:
            result["extracted"].append({"label": current_name, "data": payload, "kind": sniff_kind(payload, current_name), "offset": value_offset, "transformation": "extract bounded TNEF attachment data", "parameters": {"level": level, "attribute_type": attribute_type, "checksum_valid": sum(payload) & 0xFFFF == checksum}})
            extracted_total += len(payload)
            current_name = "attachment.bin"
        cursor = checksum_offset + 2
        attributes += 1
    result["properties"].update({"legacy_key": int.from_bytes(data[4:6], "little"), "attributes": attributes, "invalid_attribute_checksums": invalid_checksums, "attachments_extracted": len(result["extracted"]), "bytes_scanned": cursor, "parser_stop": malformed, "input_truncated": len(data) > scan_end})
    if text:
        result["text_records"].append({"encoding": "tnef-message-attributes", "offset": 6, "text": display_text("\n".join(text), 2_000_000), "source": "TNEF message and attachment attributes", "confidence_hint": 9})
    if malformed:
        result["findings"].append(_finding("warning", "structure", "TNEF traversal stopped", "Completed attributes and attachments were retained before an invalid or incomplete attribute.", reason=malformed))
    return result


def parse_opaque_container(data: bytes, profile: str = "balanced", *, kind: str) -> dict[str, Any]:
    """Read fixed headers for less common containers and retain bounded strings."""

    result = _result(kind)
    props: dict[str, Any] = {"file_size": len(data)}
    if kind == "cab" and len(data) >= 36 and data.startswith(b"MSCF"):
        props.update({"declared_file_size": int.from_bytes(data[8:12], "little"), "files_offset": int.from_bytes(data[16:20], "little"), "version": f"{data[25]}.{data[24]}", "folders": int.from_bytes(data[26:28], "little"), "files": int.from_bytes(data[28:30], "little"), "flags": f"0x{int.from_bytes(data[30:32], 'little'):04x}"})
    elif kind == "xar" and len(data) >= 28 and data.startswith(b"xar!"):
        props.update({"header_size": int.from_bytes(data[4:6], "big"), "version": int.from_bytes(data[6:8], "big"), "compressed_toc_bytes": int.from_bytes(data[8:16], "big"), "uncompressed_toc_bytes": int.from_bytes(data[16:24], "big"), "checksum_algorithm": int.from_bytes(data[24:28], "big")})
    elif kind == "rpm" and len(data) >= 96 and data.startswith(b"\xed\xab\xee\xdb"):
        props.update({"major_version": data[4], "minor_version": data[5], "package_type": int.from_bytes(data[6:8], "big"), "architecture": int.from_bytes(data[8:10], "big"), "package_name": display_text(data[10:76].split(b"\0", 1)[0], 80), "os": int.from_bytes(data[76:78], "big"), "signature_type": int.from_bytes(data[78:80], "big")})
    elif kind == "cpio":
        props["variant"] = data[:6].decode("ascii", "replace") if data[:6] in {b"070701", b"070702", b"070707"} else "binary"
    elif kind == "onenote":
        props["header_guid"] = data[:16].hex()
    elif kind == "vhd":
        footer = data[-512:] if len(data) >= 512 and data[-512:-504] == b"conectix" else data[:512]
        if len(footer) >= 512 and footer[:8] == b"conectix":
            props.update({"features": f"0x{int.from_bytes(footer[8:12], 'big'):08x}", "format_version": f"0x{int.from_bytes(footer[12:16], 'big'):08x}", "data_offset": int.from_bytes(footer[16:24], "big"), "creator_application": display_text(footer[28:32], 8), "creator_version": f"0x{int.from_bytes(footer[32:36], 'big'):08x}", "original_size": int.from_bytes(footer[40:48], "big"), "current_size": int.from_bytes(footer[48:56], "big"), "disk_type": int.from_bytes(footer[60:64], "big"), "unique_id": footer[68:84].hex()})
    result["properties"].update(props)
    _append_bounded_strings(result, data, source=f"{kind.upper()} header and member strings", profile=profile, confidence=6)
    result["findings"].append(_finding("info", "container", f"{kind.upper()} container inspected", "Only fixed metadata and bounded strings were read; embedded code was not executed."))
    return result
