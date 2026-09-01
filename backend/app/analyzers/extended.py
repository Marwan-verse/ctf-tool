from __future__ import annotations

import io
import pickletools
import re
import struct
import time
import zipfile
from typing import Any, Iterable

from .common import display_text, iter_ascii_strings, iter_utf16_strings, sniff_kind


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
            eligible = lowered_name.endswith((".xml", ".rels", ".json", ".txt", ".properties", ".mf", ".html", ".xhtml")) or any(marker in lowered_name for marker in text_names)
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
