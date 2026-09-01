from __future__ import annotations

import struct
from typing import Any

from .common import display_text


def _result(kind: str) -> dict[str, Any]:
    return {"kind": kind, "properties": {}, "metadata": {}, "findings": [], "text_records": [], "extracted": [], "repairs": []}


def _finding(severity: str, title: str, description: str, **details: Any) -> dict[str, Any]:
    return {"severity": severity, "category": "video-structure", "title": title, "description": description, "details": details}


_BMFF_CONTAINERS = {
    b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"dinf", b"mvex", b"moof", b"traf",
    b"mfra", b"udta", b"ilst", b"meta", b"ipro", b"sinf", b"schi", b"tref", b"iprp", b"ipco",
}
_BMFF_TEXT = {b"\xa9nam", b"\xa9ART", b"\xa9alb", b"\xa9cmt", b"\xa9day", b"\xa9too", b"name", b"titl", b"auth", b"desc"}


def parse_iso_bmff(data: bytes, profile: str = "balanced", *, kind: str = "mp4") -> dict[str, Any]:
    result = _result(kind)
    if len(data) < 12 or data[4:8] != b"ftyp":
        raise ValueError("ISO BMFF ftyp box is missing")
    box_limit = {"quick": 1_000, "balanced": 4_000, "deep": 12_000}.get(profile, 4_000)
    boxes: list[dict[str, Any]] = []
    top_end = 0
    truncated = False

    def walk(start: int, end: int, depth: int) -> None:
        nonlocal truncated
        cursor = start
        while cursor + 8 <= end and len(boxes) < box_limit:
            size32 = struct.unpack_from(">I", data, cursor)[0]
            box_type = data[cursor + 4:cursor + 8]
            header_size = 8
            if size32 == 1:
                if cursor + 16 > end:
                    truncated = True
                    break
                size = struct.unpack_from(">Q", data, cursor + 8)[0]
                header_size = 16
            elif size32 == 0:
                size = end - cursor
            else:
                size = size32
            if size < header_size or size > end - cursor:
                truncated = True
                boxes.append({"index": len(boxes), "type": box_type.decode("latin-1", "replace"), "offset": cursor, "size": size, "depth": depth, "truncated": True})
                break
            box_end = cursor + size
            record: dict[str, Any] = {"index": len(boxes), "type": box_type.decode("latin-1", "replace"), "offset": cursor, "size": size, "header_size": header_size, "depth": depth}
            boxes.append(record)
            payload_start = cursor + header_size
            if box_type == b"ftyp" and size >= header_size + 8:
                result["properties"]["major_brand"] = data[payload_start:payload_start + 4].decode("latin-1", "replace")
                result["properties"]["minor_version"] = struct.unpack_from(">I", data, payload_start + 4)[0]
                result["properties"]["compatible_brands"] = [data[index:index + 4].decode("latin-1", "replace") for index in range(payload_start + 8, box_end - 3, 4)][:64]
            if box_type in _BMFF_TEXT:
                payload = data[payload_start:box_end]
                text = "".join(chr(byte) if byte in {9, 10, 13} or 32 <= byte < 127 else " " for byte in payload)
                text = " ".join(text.split())
                if len(text) >= 3:
                    result["text_records"].append({"text": display_text(text, 4096), "offset": payload_start, "source": f"bmff:{record['type']}", "encoding": "printable-bytes"})
            child_start = payload_start + (4 if box_type == b"meta" and size >= header_size + 4 else 0)
            if box_type in _BMFF_CONTAINERS and depth < 8 and child_start + 8 <= box_end:
                walk(child_start, box_end, depth + 1)
            cursor = box_end

    walk(0, len(data), 0)
    for box in boxes:
        if box["depth"] == 0 and not box.get("truncated"):
            top_end = max(top_end, int(box["offset"]) + int(box["size"]))
    result["properties"].update({"boxes": boxes, "box_count": len(boxes), "box_limit_reached": len(boxes) >= box_limit})
    if truncated:
        result["findings"].append(_finding("warning", "ISO BMFF box table is inconsistent", "At least one declared box extends beyond its parent or the inspected input."))
    if top_end and len(data) - top_end >= 16:
        trailer = data[top_end:]
        result["properties"].update({"trailer_offset": top_end, "trailer_size": len(trailer)})
        result["findings"].append(_finding("warning", "Data follows the ISO BMFF container", f"{len(trailer)} byte(s) follow the last complete top-level box.", offset=top_end))
        result["extracted"].append({"label": f"{kind}_trailer", "data": trailer, "offset": top_end, "producer": "built-in-iso-bmff", "transformation": "extract bytes after final complete top-level box"})
    return result


def _read_ebml_vint(data: bytes, offset: int, *, keep_marker: bool = False) -> tuple[int, int, bool]:
    if offset >= len(data) or data[offset] == 0:
        raise ValueError("invalid EBML variable integer")
    first = data[offset]
    width = 1
    marker = 0x80
    while width <= 8 and not first & marker:
        marker >>= 1
        width += 1
    if width > 8 or offset + width > len(data):
        raise ValueError("truncated EBML variable integer")
    value = first if keep_marker else first & (marker - 1)
    for index in range(1, width):
        value = (value << 8) | data[offset + index]
    unknown = not keep_marker and value == (1 << (7 * width)) - 1
    return value, width, unknown


def parse_ebml_video(data: bytes, profile: str = "balanced", *, kind: str = "matroska") -> dict[str, Any]:
    result = _result(kind)
    if len(data) < 8 or not data.startswith(b"\x1aE\xdf\xa3"):
        raise ValueError("EBML header is missing")
    elements: list[dict[str, Any]] = []
    cursor = 0
    limit = {"quick": 1_000, "balanced": 4_000, "deep": 10_000}.get(profile, 4_000)
    identifiers = {0x1A45DFA3: "EBML", 0x18538067: "Segment", 0x1549A966: "Info", 0x1654AE6B: "Tracks", 0x1F43B675: "Cluster", 0x4282: "DocType", 0x7BA9: "Title", 0x4D80: "MuxingApp", 0x5741: "WritingApp"}
    text_ids = {0x4282, 0x7BA9, 0x4D80, 0x5741}
    while cursor < len(data) and len(elements) < limit:
        element_offset = cursor
        try:
            element_id, id_width, _ = _read_ebml_vint(data, cursor, keep_marker=True)
            cursor += id_width
            size, size_width, unknown = _read_ebml_vint(data, cursor)
            cursor += size_width
        except ValueError:
            break
        if unknown:
            elements.append({"index": len(elements), "id": f"0x{element_id:x}", "name": identifiers.get(element_id), "offset": element_offset, "size": None, "unknown_size": True})
            break
        if size > len(data) - cursor:
            result["findings"].append(_finding("warning", "EBML element is truncated", "An element declares more bytes than remain.", offset=element_offset, element_id=f"0x{element_id:x}", declared_size=size))
            break
        record = {"index": len(elements), "id": f"0x{element_id:x}", "name": identifiers.get(element_id), "offset": element_offset, "payload_offset": cursor, "size": size}
        elements.append(record)
        if element_id in text_ids and size <= 64 * 1024:
            text = data[cursor:cursor + size].decode("utf-8", "replace")
            record["text"] = display_text(text, 1000)
            result["text_records"].append({"text": display_text(text, 4096), "offset": cursor, "source": f"ebml:{identifiers.get(element_id, element_id)}", "encoding": "utf-8"})
            if element_id == 0x4282:
                result["properties"]["document_type"] = display_text(text, 80)
        cursor += size
        # The first top-level Segment normally contains nested EBML elements;
        # stop the flat walk instead of misinterpreting its media payload.
        if element_id == 0x18538067:
            break
    result["properties"].update({"elements": elements, "element_count": len(elements), "element_limit_reached": len(elements) >= limit})
    # Metadata strings are safe to locate directly even when Segment has an
    # unknown length; the core string scanner still handles all other content.
    header = data[: min(len(data), 1024 * 1024)]
    if "document_type" not in result["properties"]:
        if b"webm" in header.lower():
            result["properties"]["document_type"] = "webm"
        elif b"matroska" in header.lower():
            result["properties"]["document_type"] = "matroska"
    return result


def parse_avi(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("avi")
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"AVI ":
        raise ValueError("AVI RIFF header is missing")
    declared_payload = struct.unpack_from("<I", data, 4)[0]
    declared_end = 8 + declared_payload
    chunks: list[dict[str, Any]] = []
    limit = {"quick": 1_000, "balanced": 4_000, "deep": 12_000}.get(profile, 4_000)
    info_tags = {b"INAM": "name", b"IART": "artist", b"ICMT": "comment", b"ICRD": "date", b"ISFT": "software", b"ICOP": "copyright"}

    def walk(start: int, end: int, depth: int) -> None:
        cursor = start
        while cursor + 8 <= end and len(chunks) < limit:
            chunk_id = data[cursor:cursor + 4]
            size = struct.unpack_from("<I", data, cursor + 4)[0]
            payload_start = cursor + 8
            payload_end = payload_start + size
            if payload_end > end:
                result["findings"].append(_finding("warning", "AVI chunk is truncated", "A RIFF chunk extends beyond its parent.", offset=cursor, chunk_id=chunk_id.decode("latin-1", "replace"), declared_size=size))
                break
            record: dict[str, Any] = {"index": len(chunks), "id": chunk_id.decode("latin-1", "replace"), "offset": cursor, "size": size, "depth": depth}
            chunks.append(record)
            if chunk_id in {b"RIFF", b"LIST"} and size >= 4 and depth < 8:
                record["list_type"] = data[payload_start:payload_start + 4].decode("latin-1", "replace")
                walk(payload_start + 4, payload_end, depth + 1)
            elif chunk_id in info_tags and size <= 64 * 1024:
                text = data[payload_start:payload_end].rstrip(b"\x00").decode("utf-8", "replace")
                result["metadata"][f"avi:{info_tags[chunk_id]}"] = display_text(text, 4096)
                result["text_records"].append({"text": display_text(text, 4096), "offset": payload_start, "source": f"avi:{info_tags[chunk_id]}", "encoding": "utf-8"})
            cursor = payload_end + (size & 1)

    parse_end = min(len(data), declared_end)
    walk(12, parse_end, 0)
    result["properties"].update({"declared_size": declared_end, "chunks": chunks, "chunk_count": len(chunks), "chunk_limit_reached": len(chunks) >= limit})
    if declared_end > len(data):
        result["findings"].append(_finding("warning", "AVI is truncated", "The RIFF size exceeds the inspected input.", declared_size=declared_end, available_size=len(data)))
    elif len(data) - declared_end >= 16:
        trailer = data[declared_end:]
        result["findings"].append(_finding("warning", "Data follows AVI RIFF", f"{len(trailer)} byte(s) follow the declared RIFF container.", offset=declared_end))
        result["extracted"].append({"label": "avi_trailer", "data": trailer, "offset": declared_end, "producer": "built-in-avi", "transformation": "extract bytes after declared RIFF container"})
    return result
