from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from .common import display_text, sniff_kind


def _result(kind: str) -> dict[str, Any]:
    return {"kind": kind, "properties": {}, "metadata": {}, "findings": [], "text_records": [], "extracted": [], "repairs": []}


def _finding(title: str, description: str, **details: Any) -> dict[str, Any]:
    return {"severity": "warning", "category": "structured-data", "title": title, "description": description, "details": details}


@dataclass
class _Budget:
    limit: int
    nodes: int = 0

    def take(self) -> None:
        self.nodes += 1
        if self.nodes > self.limit:
            raise ValueError("structured node limit exceeded")


def _bytes_value(payload: bytes, offset: int, source: str, result: dict[str, Any]) -> Any:
    if not payload:
        return ""
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    printable = text and sum(character.isprintable() or character in "\r\n\t" for character in text) / len(text) >= 0.85
    if printable:
        rendered = display_text(text, 4096)
        result["text_records"].append({"text": rendered, "offset": offset, "source": source, "encoding": "utf-8"})
        return rendered
    detected = sniff_kind(payload)
    if detected != "binary" and len(payload) >= 16:
        result["extracted"].append({"label": f"{source.replace(':', '_')}_{offset}", "data": payload, "offset": offset, "producer": f"built-in-{source.split(':', 1)[0]}", "transformation": "extract structured byte string", "kind": detected})
    return {"bytes": len(payload), "hex_preview": payload[:128].hex(), "detected_type": detected}


def parse_bencode(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("bencode")
    budget = _Budget({"quick": 2_000, "balanced": 8_000, "deep": 20_000}.get(profile, 8_000))

    def parse(offset: int, depth: int) -> tuple[Any, int]:
        budget.take()
        if depth > 32 or offset >= len(data):
            raise ValueError("bencode nesting or input boundary exceeded")
        marker = data[offset]
        if marker == ord("i"):
            end = data.find(b"e", offset + 1, min(len(data), offset + 128))
            if end < 0:
                raise ValueError("unterminated bencode integer")
            raw = data[offset + 1:end]
            if (
                not raw
                or raw == b"-0"
                or (raw.startswith(b"0") and len(raw) > 1)
                or (raw.startswith(b"-0") and len(raw) > 2)
            ):
                raise ValueError("invalid bencode integer")
            return int(raw), end + 1
        if marker in {ord("l"), ord("d")}:
            cursor = offset + 1
            items: list[Any] = []
            while cursor < len(data) and data[cursor] != ord("e"):
                if marker == ord("d"):
                    key, cursor = parse(cursor, depth + 1)
                    value, cursor = parse(cursor, depth + 1)
                    items.append({"key": key, "value": value})
                else:
                    value, cursor = parse(cursor, depth + 1)
                    items.append(value)
            if cursor >= len(data):
                raise ValueError("unterminated bencode container")
            return ({"dictionary": items} if marker == ord("d") else items), cursor + 1
        if ord("0") <= marker <= ord("9"):
            colon = data.find(b":", offset, min(len(data), offset + 32))
            if colon < 0:
                raise ValueError("invalid bencode byte-string length")
            raw_length = data[offset:colon]
            if len(raw_length) > 1 and raw_length.startswith(b"0"):
                raise ValueError("non-canonical bencode byte-string length")
            length = int(raw_length)
            payload_offset = colon + 1
            if length > 64 * 1024 * 1024 or length > len(data) - payload_offset:
                raise ValueError("bencode byte string exceeds input or safety limit")
            payload = data[payload_offset:payload_offset + length]
            return _bytes_value(payload, payload_offset, "bencode:string", result), payload_offset + length
        raise ValueError(f"unknown bencode marker 0x{marker:02x}")

    try:
        value, end = parse(0, 0)
        result["properties"].update({"value": value, "node_count": budget.nodes, "consumed_bytes": end})
        if len(data) - end >= 16:
            trailer = data[end:]
            result["findings"].append(_finding("Data follows bencode value", f"{len(trailer)} byte(s) follow the complete root value.", offset=end))
            result["extracted"].append({"label": "bencode_trailer", "data": trailer, "offset": end, "producer": "built-in-bencode", "transformation": "extract bytes after root bencode value"})
    except (ValueError, OverflowError) as exc:
        result["findings"].append(_finding("Bencode structure is malformed", display_text(exc, 300)))
        result["properties"]["parser_error"] = display_text(exc, 300)
    return result


def _cbor_uint(data: bytes, offset: int, additional: int) -> tuple[int | None, int, bool]:
    if additional < 24:
        return additional, offset, False
    sizes = {24: 1, 25: 2, 26: 4, 27: 8}
    if additional == 31:
        return None, offset, True
    size = sizes.get(additional)
    if not size or offset + size > len(data):
        raise ValueError("invalid or truncated CBOR length")
    return int.from_bytes(data[offset:offset + size], "big"), offset + size, False


def parse_cbor(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("cbor")
    budget = _Budget({"quick": 2_000, "balanced": 8_000, "deep": 20_000}.get(profile, 8_000))

    def parse(offset: int, depth: int, allow_break: bool = False) -> tuple[Any, int]:
        budget.take()
        if depth > 32 or offset >= len(data):
            raise ValueError("CBOR nesting or input boundary exceeded")
        initial = data[offset]
        offset += 1
        major, additional = initial >> 5, initial & 0x1F
        if major == 7 and additional == 31:
            if allow_break:
                return {"break": True}, offset
            raise ValueError("unexpected CBOR break marker")
        value, offset, indefinite = _cbor_uint(data, offset, additional)
        if major == 0:
            return value, offset
        if major == 1:
            return -1 - int(value or 0), offset
        if major in {2, 3}:
            if indefinite:
                parts: list[Any] = []
                while True:
                    child, offset = parse(offset, depth + 1, allow_break=True)
                    if child == {"break": True}:
                        break
                    parts.append(child)
                return parts, offset
            length = int(value or 0)
            if length > 64 * 1024 * 1024 or length > len(data) - offset:
                raise ValueError("CBOR string exceeds input or safety limit")
            payload_offset = offset
            payload = data[offset:offset + length]
            if major == 3:
                text = payload.decode("utf-8", "replace")
                rendered = display_text(text, 4096)
                result["text_records"].append({"text": rendered, "offset": payload_offset, "source": "cbor:text", "encoding": "utf-8"})
                return rendered, offset + length
            return _bytes_value(payload, payload_offset, "cbor:bytes", result), offset + length
        if major in {4, 5}:
            items: list[Any] = []
            remaining = None if indefinite else int(value or 0)
            if remaining is not None and remaining > budget.limit:
                raise ValueError("CBOR container count exceeds node limit")
            count = 0
            while remaining is None or count < remaining:
                if indefinite and offset < len(data) and data[offset] == 0xFF:
                    offset += 1
                    break
                if major == 5:
                    key, offset = parse(offset, depth + 1)
                    item, offset = parse(offset, depth + 1)
                    items.append({"key": key, "value": item})
                else:
                    item, offset = parse(offset, depth + 1)
                    items.append(item)
                count += 1
            return ({"map": items} if major == 5 else items), offset
        if major == 6:
            tagged, offset = parse(offset, depth + 1)
            return {"tag": value, "value": tagged}, offset
        if major == 7:
            if additional in {20, 21}:
                return additional == 21, offset
            if additional in {22, 23}:
                return None if additional == 22 else {"undefined": True}, offset
            if additional == 25:
                return struct.unpack(">e", int(value or 0).to_bytes(2, "big"))[0], offset
            if additional == 26:
                return struct.unpack(">f", int(value or 0).to_bytes(4, "big"))[0], offset
            if additional == 27:
                return struct.unpack(">d", int(value or 0).to_bytes(8, "big"))[0], offset
            return {"simple": value}, offset
        raise ValueError("unsupported CBOR major type")

    try:
        value, end = parse(0, 0)
        result["properties"].update({"value": value, "node_count": budget.nodes, "consumed_bytes": end, "self_described": data.startswith(b"\xd9\xd9\xf7")})
        if len(data) - end >= 16:
            result["extracted"].append({"label": "cbor_trailer", "data": data[end:], "offset": end, "producer": "built-in-cbor", "transformation": "extract bytes after root CBOR item"})
    except (ValueError, OverflowError, struct.error) as exc:
        result["findings"].append(_finding("CBOR structure is malformed", display_text(exc, 300)))
        result["properties"]["parser_error"] = display_text(exc, 300)
    return result


def parse_msgpack(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("msgpack")
    budget = _Budget({"quick": 2_000, "balanced": 8_000, "deep": 20_000}.get(profile, 8_000))

    def take(offset: int, size: int) -> tuple[bytes, int]:
        if size > 64 * 1024 * 1024 or offset + size > len(data):
            raise ValueError("MessagePack value exceeds input or safety limit")
        return data[offset:offset + size], offset + size

    def parse(offset: int, depth: int) -> tuple[Any, int]:
        budget.take()
        if depth > 32 or offset >= len(data):
            raise ValueError("MessagePack nesting or input boundary exceeded")
        marker = data[offset]
        offset += 1
        if marker <= 0x7F:
            return marker, offset
        if marker >= 0xE0:
            return marker - 256, offset
        if 0xA0 <= marker <= 0xBF:
            length = marker & 0x1F
            payload, offset = take(offset, length)
            text = payload.decode("utf-8", "replace")
            result["text_records"].append({"text": display_text(text, 4096), "offset": offset - length, "source": "msgpack:string", "encoding": "utf-8"})
            return display_text(text, 4096), offset
        if 0x90 <= marker <= 0x9F:
            count = marker & 0x0F
            items = []
            for _ in range(count):
                value, offset = parse(offset, depth + 1)
                items.append(value)
            return items, offset
        if 0x80 <= marker <= 0x8F:
            count = marker & 0x0F
            items = []
            for _ in range(count):
                key, offset = parse(offset, depth + 1)
                value, offset = parse(offset, depth + 1)
                items.append({"key": key, "value": value})
            return {"map": items}, offset
        if marker in {0xC0, 0xC2, 0xC3}:
            return {0xC0: None, 0xC2: False, 0xC3: True}[marker], offset
        if marker in {0xCA, 0xCB}:
            size, code = (4, ">f") if marker == 0xCA else (8, ">d")
            payload, offset = take(offset, size)
            return struct.unpack(code, payload)[0], offset
        integer_sizes = {0xCC: (1, False), 0xCD: (2, False), 0xCE: (4, False), 0xCF: (8, False), 0xD0: (1, True), 0xD1: (2, True), 0xD2: (4, True), 0xD3: (8, True)}
        if marker in integer_sizes:
            size, signed = integer_sizes[marker]
            payload, offset = take(offset, size)
            return int.from_bytes(payload, "big", signed=signed), offset
        length_sizes = {0xC4: (1, "bin"), 0xC5: (2, "bin"), 0xC6: (4, "bin"), 0xD9: (1, "str"), 0xDA: (2, "str"), 0xDB: (4, "str"), 0xDC: (2, "array"), 0xDD: (4, "array"), 0xDE: (2, "map"), 0xDF: (4, "map")}
        if marker in length_sizes:
            size_width, kind = length_sizes[marker]
            raw, offset = take(offset, size_width)
            count = int.from_bytes(raw, "big")
            if count > budget.limit and kind in {"array", "map"}:
                raise ValueError("MessagePack container count exceeds node limit")
            if kind in {"bin", "str"}:
                payload_offset = offset
                payload, offset = take(offset, count)
                if kind == "bin":
                    return _bytes_value(payload, payload_offset, "msgpack:bytes", result), offset
                text = payload.decode("utf-8", "replace")
                result["text_records"].append({"text": display_text(text, 4096), "offset": payload_offset, "source": "msgpack:string", "encoding": "utf-8"})
                return display_text(text, 4096), offset
            items = []
            for _ in range(count):
                if kind == "map":
                    key, offset = parse(offset, depth + 1)
                    value, offset = parse(offset, depth + 1)
                    items.append({"key": key, "value": value})
                else:
                    value, offset = parse(offset, depth + 1)
                    items.append(value)
            return ({"map": items} if kind == "map" else items), offset
        if marker in {0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xC7, 0xC8, 0xC9}:
            fixed = {0xD4: 1, 0xD5: 2, 0xD6: 4, 0xD7: 8, 0xD8: 16}
            if marker in fixed:
                length = fixed[marker]
            else:
                width = {0xC7: 1, 0xC8: 2, 0xC9: 4}[marker]
                raw, offset = take(offset, width)
                length = int.from_bytes(raw, "big")
            type_raw, offset = take(offset, 1)
            payload, offset = take(offset, length)
            return {"extension_type": int.from_bytes(type_raw, "big", signed=True), "bytes": len(payload), "hex_preview": payload[:128].hex()}, offset
        raise ValueError(f"unsupported MessagePack marker 0x{marker:02x}")

    try:
        value, end = parse(0, 0)
        result["properties"].update({"value": value, "node_count": budget.nodes, "consumed_bytes": end})
        if len(data) - end >= 16:
            result["extracted"].append({"label": "msgpack_trailer", "data": data[end:], "offset": end, "producer": "built-in-msgpack", "transformation": "extract bytes after root MessagePack value"})
    except (ValueError, OverflowError, struct.error) as exc:
        result["findings"].append(_finding("MessagePack structure is malformed", display_text(exc, 300)))
        result["properties"]["parser_error"] = display_text(exc, 300)
    return result


def _protobuf_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for index in range(10):
        if offset + index >= len(data):
            raise ValueError("truncated Protocol Buffers varint")
        byte = data[offset + index]
        value |= (byte & 0x7F) << (index * 7)
        if not byte & 0x80:
            return value, offset + index + 1
    raise ValueError("Protocol Buffers varint exceeds 10 bytes")


def parse_protobuf(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("protobuf")
    field_limit = {"quick": 2_000, "balanced": 8_000, "deep": 20_000}.get(profile, 8_000)
    fields: list[dict[str, Any]] = []
    cursor = 0
    try:
        while cursor < len(data) and len(fields) < field_limit:
            field_offset = cursor
            key, cursor = _protobuf_varint(data, cursor)
            number, wire = key >> 3, key & 7
            if number <= 0 or wire not in {0, 1, 2, 5}:
                raise ValueError("invalid Protocol Buffers field key")
            record: dict[str, Any] = {"index": len(fields), "field_number": number, "wire_type": wire, "offset": field_offset}
            if wire == 0:
                record["value"], cursor = _protobuf_varint(data, cursor)
            elif wire in {1, 5}:
                size = 8 if wire == 1 else 4
                if cursor + size > len(data):
                    raise ValueError("truncated fixed-width Protocol Buffers field")
                record["value_hex"] = data[cursor:cursor + size].hex()
                record["value_unsigned"] = int.from_bytes(data[cursor:cursor + size], "little")
                cursor += size
            else:
                size, cursor = _protobuf_varint(data, cursor)
                if size > 64 * 1024 * 1024 or size > len(data) - cursor:
                    raise ValueError("length-delimited Protocol Buffers field exceeds input or safety limit")
                payload_offset = cursor
                payload = data[cursor:cursor + size]
                cursor += size
                record["length"] = size
                record["value"] = _bytes_value(payload, payload_offset, f"protobuf:field-{number}", result)
            fields.append(record)
        result["properties"].update({"fields": fields, "field_count": len(fields), "consumed_bytes": cursor, "schema_available": False})
        if cursor < len(data):
            result["findings"].append(_finding("Protocol Buffers field limit reached", "Only the bounded prefix of fields was decoded.", decoded_fields=len(fields), remaining_bytes=len(data) - cursor))
    except (ValueError, OverflowError) as exc:
        result["findings"].append(_finding("Protocol Buffers wire structure is malformed", display_text(exc, 300), offset=cursor))
        result["properties"].update({"fields": fields, "field_count": len(fields), "consumed_bytes": cursor, "schema_available": False, "parser_error": display_text(exc, 300)})
    return result
