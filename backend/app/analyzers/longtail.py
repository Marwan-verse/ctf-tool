"""Bounded structural parsers for dataset, firmware, and legacy document formats.

These parsers intentionally stop at container boundaries.  They do not invoke
schema/object loaders, mount filesystems, render active document content, or
execute anything found in challenge-controlled bytes.
"""

from __future__ import annotations

import struct
import time
import uuid
import zlib
from typing import Any

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


def _append_strings(
    result: dict[str, Any], data: bytes, *, source: str, offset: int = 0, confidence: int = 6
) -> None:
    records = list(iter_ascii_strings(data[: 4 * 1024 * 1024], minimum=5, limit=2_000))
    records.extend(iter_utf16_strings(data[: 4 * 1024 * 1024], minimum=5, limit=1_000))
    values = [display_text(record.get("text"), 32_768) for record in records]
    values = [value for value in values if value]
    if values:
        result["text_records"].append({
            "encoding": "bounded-container-strings",
            "offset": offset,
            "text": display_text("\n".join(values), 2_000_000),
            "source": source,
            "confidence_hint": confidence,
        })


def _append_trailer(
    result: dict[str, Any], data: bytes, logical_end: int, *, label: str, maximum: int = 64 * 1024 * 1024
) -> None:
    if not 0 <= logical_end < len(data):
        return
    trailer = data[logical_end:]
    result["properties"]["trailing_bytes"] = len(trailer)
    if len(trailer) > maximum:
        result["findings"].append(_finding(
            "info", "resource-limit", "Trailing payload exceeds the extraction limit",
            "The exact boundary was retained, but the residue was not copied into memory.",
            bytes=len(trailer), limit_bytes=maximum,
        ))
        return
    result["extracted"].append({
        "label": label,
        "data": trailer,
        "kind": sniff_kind(trailer, label),
        "offset": logical_end,
        "transformation": "copy bytes after the validated logical container end",
        "parameters": {"bytes": len(trailer)},
    })
    result["findings"].append(_finding(
        "high", "trailing-data", "Data follows the declared container end",
        "The trailing bytes were copied exactly for recursive analysis.",
        offset=logical_end, bytes=len(trailer),
    ))


def _footer_container(
    data: bytes, *, kind: str, magic: bytes, footer_name: str, allow_encrypted_magic: bytes | None = None
) -> dict[str, Any]:
    result = _result(kind)
    start_magic = data[: len(magic)]
    allowed = {magic} | ({allow_encrypted_magic} if allow_encrypted_magic else set())
    if len(data) < len(magic) * 2 + 4 or start_magic not in allowed:
        result["findings"].append(_finding("error", "structure", f"Invalid {footer_name} header", "The required leading magic is missing or truncated."))
        return result

    candidates: list[tuple[int, int, bytes]] = []
    scan_start = max(len(magic), len(data) - 16 * 1024 * 1024)
    for trailer_magic in allowed:
        position = data.rfind(trailer_magic, scan_start)
        while position >= len(magic) + 4:
            footer_length = int.from_bytes(data[position - 4:position], "little")
            footer_start = position - 4 - footer_length
            if len(magic) <= footer_start <= position - 4:
                candidates.append((position, footer_length, trailer_magic))
                break
            position = data.rfind(trailer_magic, scan_start, position)
    if not candidates:
        result["findings"].append(_finding("warning", "structure", f"{footer_name} footer was not found", "No structurally plausible trailing magic and footer length were found in the bounded tail."))
        result["properties"].update({"leading_magic": start_magic.decode("ascii", "replace"), "file_size": len(data)})
        return result

    magic_offset, footer_length, trailer_magic = max(candidates, key=lambda item: item[0])
    footer_start = magic_offset - 4 - footer_length
    logical_end = magic_offset + len(trailer_magic)
    footer = data[footer_start:magic_offset - 4]
    result["properties"].update({
        "leading_magic": start_magic.decode("ascii", "replace"),
        "trailing_magic": trailer_magic.decode("ascii", "replace"),
        "footer_offset": footer_start,
        "footer_bytes": footer_length,
        "logical_file_end": logical_end,
        "encrypted_footer": bool(allow_encrypted_magic and trailer_magic == allow_encrypted_magic),
    })
    _append_strings(result, footer, source=f"{footer_name} footer strings", offset=footer_start, confidence=7)
    _append_trailer(result, data, logical_end, label=f"{kind}_trailing_payload")
    return result


def parse_parquet(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Locate a Parquet footer without instantiating its Thrift schema."""

    result = _footer_container(
        data, kind="parquet", magic=b"PAR1", footer_name="Parquet", allow_encrypted_magic=b"PARE"
    )
    if result["properties"]:
        result["findings"].append(_finding(
            "info", "dataset", "Parquet footer located safely",
            "Footer bytes and bounded strings were inspected without loading Thrift metadata or column data.",
        ))
    return result


def parse_arrow_ipc(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Locate an Arrow IPC/Feather V2 footer without loading FlatBuffers."""

    result = _footer_container(data, kind="arrow_ipc", magic=b"ARROW1", footer_name="Arrow IPC")
    if result["properties"]:
        result["properties"]["format_alias"] = "Feather V2 / Arrow IPC file"
        result["findings"].append(_finding(
            "info", "dataset", "Arrow IPC footer located safely",
            "The FlatBuffer footer was treated as inert bytes; field extensions and record batches were not instantiated.",
        ))
    return result


def _read_avro_long(data: bytes, cursor: int, end: int) -> tuple[int, int]:
    value = 0
    shift = 0
    for _ in range(10):
        if cursor >= end:
            raise ValueError("truncated Avro variable-length integer")
        byte = data[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return (value >> 1) ^ -(value & 1), cursor
        shift += 7
    raise ValueError("Avro integer exceeds 64-bit encoding")


def parse_avro(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("avro")
    if len(data) < 20 or data[:4] != b"Obj\x01":
        result["findings"].append(_finding("error", "structure", "Invalid Avro object-container header", "The Obj\\x01 magic or sync marker is missing."))
        return result
    cursor = 4
    metadata: dict[str, bytes] = {}
    malformed: str | None = None
    try:
        total_metadata = 0
        while len(metadata) < 256:
            count, cursor = _read_avro_long(data, cursor, len(data))
            if count == 0:
                break
            if count < 0:
                count = -count
                block_size, cursor = _read_avro_long(data, cursor, len(data))
                if block_size < 0 or block_size > 8 * 1024 * 1024:
                    raise ValueError("Avro metadata block exceeds the safety limit")
            if count > 256 - len(metadata):
                raise ValueError("Avro metadata entry limit reached")
            for _ in range(count):
                key_length, cursor = _read_avro_long(data, cursor, len(data))
                if not 0 <= key_length <= 4096 or cursor + key_length > len(data):
                    raise ValueError("invalid Avro metadata key length")
                key = data[cursor:cursor + key_length].decode("utf-8", "replace")
                cursor += key_length
                value_length, cursor = _read_avro_long(data, cursor, len(data))
                if not 0 <= value_length <= 8 * 1024 * 1024 or cursor + value_length > len(data):
                    raise ValueError("invalid Avro metadata value length")
                total_metadata += value_length
                if total_metadata > 8 * 1024 * 1024:
                    raise ValueError("Avro metadata total exceeds the safety limit")
                metadata[display_text(key, 4096)] = data[cursor:cursor + value_length]
                cursor += value_length
        else:
            raise ValueError("Avro metadata entry limit reached")
        if cursor + 16 > len(data):
            raise ValueError("truncated Avro sync marker")
        sync = data[cursor:cursor + 16]
        cursor += 16
    except ValueError as exc:
        malformed = display_text(exc, 300)
        sync = b""

    codec = metadata.get("avro.codec", b"null").decode("utf-8", "replace")
    schema = metadata.get("avro.schema", b"").decode("utf-8", "replace")
    result["properties"].update({
        "metadata_entries": len(metadata), "codec": display_text(codec, 160),
        "header_bytes": cursor, "sync_marker": sync.hex(), "schema_present": bool(schema),
    })
    for key, value in metadata.items():
        if key == "avro.schema":
            result["metadata"]["schema"] = display_text(schema, 1_000_000)
        elif len(value) <= 65_536:
            result["metadata"][safe_label(key, 100)] = display_text(value.decode("utf-8", "replace"), 65_536)
    if schema:
        result["text_records"].append({
            "encoding": "json-schema", "offset": 4,
            "text": display_text(schema, 1_000_000), "source": "Avro embedded schema",
            "confidence_hint": 10,
        })

    blocks = records = payload_bytes = 0
    block_rows: list[str] = []
    deadline = time.monotonic() + (8.0 if profile == "deep" else 3.0)
    if not malformed:
        try:
            while cursor < len(data) and blocks < 100_000 and time.monotonic() <= deadline:
                count, cursor = _read_avro_long(data, cursor, len(data))
                size, cursor = _read_avro_long(data, cursor, len(data))
                if count < 0 or size < 0 or size > len(data) - cursor - 16:
                    raise ValueError("invalid Avro data-block geometry")
                payload_offset = cursor
                cursor += size
                if data[cursor:cursor + 16] != sync:
                    raise ValueError("Avro data block has a mismatched sync marker")
                cursor += 16
                records += count
                payload_bytes += size
                if len(block_rows) < 2_000:
                    block_rows.append(f"block {blocks}: records={count}, stored_bytes={size}, offset={payload_offset}")
                blocks += 1
        except ValueError as exc:
            malformed = display_text(exc, 300)
    result["properties"].update({
        "blocks": blocks, "declared_records": records, "stored_block_bytes": payload_bytes,
        "bytes_consumed": cursor, "parser_stop": malformed,
    })
    if block_rows:
        result["text_records"].append({
            "encoding": "avro-block-index", "offset": result["properties"]["header_bytes"],
            "text": "\n".join(block_rows), "source": "Avro validated block inventory", "confidence_hint": 9,
        })
    if malformed:
        result["findings"].append(_finding("warning", "structure", "Avro traversal stopped safely", "Completed metadata and blocks were retained before an invalid boundary.", reason=malformed))
    else:
        result["findings"].append(_finding("info", "dataset", "Avro container indexed safely", "The schema and block boundaries were read without constructing schema-defined objects or decompressing records."))
    return result


def _read_uvarint(data: bytes, cursor: int, end: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if cursor >= end:
            raise ValueError("truncated protobuf variable-length integer")
        byte = data[cursor]
        cursor += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, cursor
    raise ValueError("protobuf integer exceeds 64 bits")


def _protobuf_fields(data: bytes, *, maximum: int = 128) -> dict[int, list[int | bytes]]:
    cursor = 0
    fields: dict[int, list[int | bytes]] = {}
    count = 0
    while cursor < len(data) and count < maximum:
        key, cursor = _read_uvarint(data, cursor, len(data))
        field, wire = key >> 3, key & 7
        if field <= 0:
            raise ValueError("invalid protobuf field number")
        if wire == 0:
            value, cursor = _read_uvarint(data, cursor, len(data))
        elif wire == 1:
            if cursor + 8 > len(data):
                raise ValueError("truncated fixed64 field")
            value = int.from_bytes(data[cursor:cursor + 8], "little")
            cursor += 8
        elif wire == 2:
            length, cursor = _read_uvarint(data, cursor, len(data))
            if length > len(data) - cursor:
                raise ValueError("length-delimited field leaves the postscript")
            value = data[cursor:cursor + length]
            cursor += length
        elif wire == 5:
            if cursor + 4 > len(data):
                raise ValueError("truncated fixed32 field")
            value = int.from_bytes(data[cursor:cursor + 4], "little")
            cursor += 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
        fields.setdefault(field, []).append(value)
        count += 1
    return fields


def parse_orc(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("orc")
    if len(data) < 4 or data[:3] != b"ORC":
        result["findings"].append(_finding("error", "structure", "Invalid ORC header", "The leading ORC magic is missing."))
        return result
    postscript_length = data[-1]
    postscript_offset = len(data) - 1 - postscript_length
    if postscript_length == 0 or postscript_offset < 3:
        result["findings"].append(_finding("error", "structure", "Invalid ORC postscript length", "The final byte does not locate a bounded postscript."))
        return result
    postscript = data[postscript_offset:-1]
    malformed: str | None = None
    try:
        fields = _protobuf_fields(postscript)
    except ValueError as exc:
        fields = {}
        malformed = display_text(exc, 300)
    integer = lambda field, default=0: int(fields.get(field, [default])[0]) if fields.get(field) and isinstance(fields[field][0], int) else default
    footer_length = integer(1)
    compression = integer(2)
    metadata_length = integer(5)
    stripe_statistics_length = integer(7)
    magic_values = [value for value in fields.get(8000, []) if isinstance(value, bytes)]
    magic = magic_values[0].decode("ascii", "replace") if magic_values else ""
    footer_offset = postscript_offset - footer_length
    metadata_offset = footer_offset - metadata_length
    geometry_valid = footer_length >= 0 and metadata_length >= 0 and metadata_offset >= 3
    compression_names = {0: "none", 1: "zlib", 2: "snappy", 3: "lzo", 4: "lz4", 5: "zstd"}
    versions: list[int] = []
    for value in fields.get(4, []):
        if isinstance(value, int):
            versions.append(value)
        elif isinstance(value, bytes):
            cursor = 0
            try:
                while cursor < len(value) and len(versions) < 16:
                    number, cursor = _read_uvarint(value, cursor, len(value))
                    versions.append(number)
            except ValueError:
                malformed = malformed or "malformed packed ORC version field"
    result["properties"].update({
        "postscript_offset": postscript_offset, "postscript_bytes": postscript_length,
        "footer_offset": footer_offset, "footer_bytes": footer_length,
        "metadata_offset": metadata_offset, "metadata_bytes": metadata_length,
        "stripe_statistics_bytes": stripe_statistics_length,
        "compression": compression_names.get(compression, f"unknown-{compression}"),
        "compression_block_bytes": integer(3), "version": versions,
        "writer_version": integer(6), "postscript_magic": magic,
        "valid_tail_geometry": geometry_valid, "parser_stop": malformed,
    })
    if geometry_valid:
        _append_strings(result, data[metadata_offset:postscript_offset], source="ORC metadata/footer strings", offset=metadata_offset, confidence=6)
    if malformed or not geometry_valid or (magic and magic != "ORC"):
        result["findings"].append(_finding("warning", "structure", "ORC tail is malformed or inconsistent", "The postscript was not used beyond its validated boundaries.", reason=malformed, magic=magic))
    else:
        result["findings"].append(_finding("info", "dataset", "ORC tail indexed safely", "The protobuf postscript and exact footer boundaries were inspected without decompressing stripes."))
    return result


def parse_uimage(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("uimage")
    if len(data) < 64 or data[:4] != b"'\x05\x19V":
        result["findings"].append(_finding("error", "structure", "Invalid U-Boot legacy image header", "The 64-byte uImage header or magic is missing."))
        return result
    magic, header_crc, timestamp, size, load, entry, data_crc, os_code, arch, image_type, compression, raw_name = struct.unpack(">7I4B32s", data[:64])
    header_copy = bytearray(data[:64])
    header_copy[4:8] = b"\0" * 4
    payload_end = 64 + size
    payload_complete = payload_end <= len(data)
    payload = data[64:payload_end] if payload_complete else data[64:]
    compression_names = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo", 5: "lz4", 6: "zstd"}
    type_names = {1: "standalone", 2: "kernel", 3: "ramdisk", 4: "multi-file", 5: "firmware", 6: "script", 7: "filesystem", 8: "flat-device-tree"}
    result["properties"].update({
        "magic": f"0x{magic:08x}", "name": display_text(raw_name.split(b"\0", 1)[0], 80),
        "timestamp": timestamp, "declared_payload_bytes": size,
        "load_address": f"0x{load:08x}", "entry_address": f"0x{entry:08x}",
        "os_code": os_code, "architecture_code": arch,
        "image_type": type_names.get(image_type, f"unknown-{image_type}"),
        "compression": compression_names.get(compression, f"unknown-{compression}"),
        "header_crc32": f"0x{header_crc:08x}", "header_crc_valid": zlib.crc32(header_copy) & 0xFFFFFFFF == header_crc,
        "data_crc32": f"0x{data_crc:08x}", "data_crc_valid": (zlib.crc32(payload) & 0xFFFFFFFF == data_crc) if payload_complete else None,
        "payload_complete": payload_complete, "logical_file_end": payload_end,
    })
    result["text_records"].append({
        "encoding": "u-boot-header", "offset": 0,
        "text": f"name={result['properties']['name']}\nimage_type={result['properties']['image_type']}\ncompression={result['properties']['compression']}\nload_address={result['properties']['load_address']}\nentry_address={result['properties']['entry_address']}",
        "source": "U-Boot legacy image header", "confidence_hint": 10,
    })
    if payload_complete and size and size <= 64 * 1024 * 1024:
        result["extracted"].append({
            "label": "uimage_payload", "data": payload, "kind": sniff_kind(payload, "uimage_payload.bin"),
            "offset": 64, "transformation": "copy CRC-addressed U-Boot image payload",
            "parameters": {"bytes": size, "data_crc_valid": result["properties"]["data_crc_valid"]},
        })
    if payload_complete:
        _append_trailer(result, data, payload_end, label="uimage_trailing_payload")
    else:
        result["findings"].append(_finding("warning", "structure", "U-Boot payload is truncated", "The declared payload extends beyond retained bytes; no partial child was emitted."))
    return result


def _align(value: int, alignment: int) -> int:
    if alignment <= 0:
        raise ValueError("alignment must be positive")
    return (value + alignment - 1) // alignment * alignment


def _append_segment(
    result: dict[str, Any], data: bytes, *, name: str, offset: int, size: int, budget: list[int]
) -> bool:
    if size == 0:
        return True
    if size < 0 or offset < 0 or size > len(data) - offset:
        return False
    if size > budget[0]:
        result["findings"].append(_finding("info", "resource-limit", f"{name} was not materialized", "The exact segment boundary is valid, but it exceeds the remaining child-artifact budget.", bytes=size, limit_bytes=budget[0]))
        return True
    payload = data[offset:offset + size]
    label = f"android_boot_{safe_label(name, 80)}"
    result["extracted"].append({
        "label": label, "data": payload, "kind": sniff_kind(payload, f"{name}.bin"), "offset": offset,
        "transformation": f"copy declared Android boot {safe_label(name, 80)} segment",
        "parameters": {"bytes": size},
    })
    budget[0] -= size
    return True


def parse_android_boot(data: bytes, profile: str = "balanced", *, vendor: bool = False) -> dict[str, Any]:
    kind = "android_vendor_boot" if vendor else "android_boot"
    result = _result(kind)
    expected = b"VNDRBOOT" if vendor else b"ANDROID!"
    if len(data) < 44 or data[:8] != expected:
        result["findings"].append(_finding("error", "structure", "Invalid Android boot-image header", "The expected eight-byte boot magic is missing or truncated."))
        return result
    budget = [16 * 1024 * 1024 if profile == "quick" else 64 * 1024 * 1024]
    segments: list[tuple[str, int, int]] = []
    malformed: str | None = None
    if vendor:
        if len(data) < 2112:
            malformed = "truncated vendor_boot v3 header"
            version = int.from_bytes(data[8:12], "little")
            page_size = int.from_bytes(data[12:16], "little")
            header_size = 0
        else:
            version = int.from_bytes(data[8:12], "little")
            page_size = int.from_bytes(data[12:16], "little")
            ramdisk_size = int.from_bytes(data[24:28], "little")
            cmdline = data[28:2076].split(b"\0", 1)[0].decode("utf-8", "replace")
            name = data[2080:2096].split(b"\0", 1)[0].decode("utf-8", "replace")
            header_size = int.from_bytes(data[2096:2100], "little")
            dtb_size = int.from_bytes(data[2100:2104], "little")
            cursor = _align(header_size, page_size) if page_size else 0
            segments.append(("vendor_ramdisk", cursor, ramdisk_size))
            cursor = _align(cursor + ramdisk_size, page_size) if page_size else 0
            segments.append(("dtb", cursor, dtb_size))
            cursor = _align(cursor + dtb_size, page_size) if page_size else 0
            table_size = bootconfig_size = 0
            if version >= 4 and len(data) >= 2128:
                table_size = int.from_bytes(data[2112:2116], "little")
                table_entries = int.from_bytes(data[2116:2120], "little")
                table_entry_size = int.from_bytes(data[2120:2124], "little")
                bootconfig_size = int.from_bytes(data[2124:2128], "little")
                segments.append(("vendor_ramdisk_table", cursor, table_size))
                cursor = _align(cursor + table_size, page_size)
                segments.append(("bootconfig", cursor, bootconfig_size))
                result["properties"].update({"ramdisk_table_entries": table_entries, "ramdisk_table_entry_bytes": table_entry_size})
            result["properties"].update({"product_name": display_text(name, 160), "command_line": display_text(cmdline, 4096), "vendor_ramdisk_bytes": ramdisk_size, "dtb_bytes": dtb_size, "ramdisk_table_bytes": table_size, "bootconfig_bytes": bootconfig_size})
    else:
        version = int.from_bytes(data[40:44], "little")
        if version <= 2:
            page_size = int.from_bytes(data[36:40], "little")
            header_size = {0: 1632, 1: 1648, 2: 1660}.get(version, 1632)
            if len(data) < min(header_size, 608):
                malformed = "truncated legacy Android boot header"
            kernel_size = int.from_bytes(data[8:12], "little")
            ramdisk_size = int.from_bytes(data[16:20], "little")
            second_size = int.from_bytes(data[24:28], "little")
            name = data[48:64].split(b"\0", 1)[0].decode("utf-8", "replace")
            cmdline = (data[64:576] + data[608:1632]).split(b"\0", 1)[0].decode("utf-8", "replace")
            cursor = page_size if page_size else 0
            segments.append(("kernel", cursor, kernel_size))
            cursor = _align(cursor + kernel_size, page_size) if page_size else 0
            segments.append(("ramdisk", cursor, ramdisk_size))
            cursor = _align(cursor + ramdisk_size, page_size) if page_size else 0
            segments.append(("second_stage", cursor, second_size))
            cursor = _align(cursor + second_size, page_size) if page_size else 0
            recovery_size = dtb_size = 0
            if version >= 1 and len(data) >= 1648:
                recovery_size = int.from_bytes(data[1632:1636], "little")
                declared_header_size = int.from_bytes(data[1644:1648], "little")
                if declared_header_size:
                    header_size = declared_header_size
                segments.append(("recovery_dtbo", cursor, recovery_size))
                cursor = _align(cursor + recovery_size, page_size)
            if version >= 2 and len(data) >= 1660:
                dtb_size = int.from_bytes(data[1648:1652], "little")
                segments.append(("dtb", cursor, dtb_size))
            result["properties"].update({"product_name": display_text(name, 160), "command_line": display_text(cmdline, 4096), "kernel_bytes": kernel_size, "ramdisk_bytes": ramdisk_size, "second_stage_bytes": second_size, "recovery_dtbo_bytes": recovery_size, "dtb_bytes": dtb_size})
        elif version in {3, 4}:
            page_size = 4096
            kernel_size = int.from_bytes(data[8:12], "little")
            ramdisk_size = int.from_bytes(data[12:16], "little")
            header_size = int.from_bytes(data[20:24], "little")
            expected_header = 1580 if version == 3 else 1584
            if len(data) < expected_header or header_size < expected_header:
                malformed = "truncated or undersized Android boot v3/v4 header"
            cmdline = data[44:1580].split(b"\0", 1)[0].decode("utf-8", "replace")
            cursor = page_size
            segments.append(("kernel", cursor, kernel_size))
            cursor = _align(cursor + kernel_size, page_size)
            segments.append(("ramdisk", cursor, ramdisk_size))
            cursor = _align(cursor + ramdisk_size, page_size)
            signature_size = int.from_bytes(data[1580:1584], "little") if version == 4 and len(data) >= 1584 else 0
            segments.append(("boot_signature", cursor, signature_size))
            result["properties"].update({"command_line": display_text(cmdline, 4096), "kernel_bytes": kernel_size, "ramdisk_bytes": ramdisk_size, "boot_signature_bytes": signature_size})
        else:
            page_size = 0
            header_size = 0
            malformed = f"unsupported Android boot header version {version}"

    if page_size and (page_size < 512 or page_size > 1024 * 1024 or page_size & (page_size - 1)):
        malformed = malformed or "unsafe Android boot page size"
    result["properties"].update({"header_version": version, "header_bytes": header_size, "page_size": page_size, "parser_stop": malformed})
    header_text = []
    if result["properties"].get("product_name"):
        header_text.append(f"product_name={result['properties']['product_name']}")
    if result["properties"].get("command_line"):
        header_text.append(f"command_line={result['properties']['command_line']}")
    header_text.extend(f"{name}: offset={offset}, bytes={size}" for name, offset, size in segments)
    if header_text:
        result["text_records"].append({
            "encoding": "android-boot-header", "offset": 0, "text": display_text("\n".join(header_text), 1_000_000),
            "source": "Android boot header and segment map", "confidence_hint": 10,
        })
    valid_segments = not malformed
    if valid_segments:
        previous_end = 0
        for name, offset, size in segments:
            if offset < previous_end or not _append_segment(result, data, name=name, offset=offset, size=size, budget=budget):
                malformed = f"{name} segment leaves the retained image"
                valid_segments = False
                break
            previous_end = offset + size
        if valid_segments:
            # mkbootimg normally pads each declared component to the page size,
            # including the final one.  Consume only an in-file all-zero pad;
            # non-zero bytes remain evidence-backed trailer data.
            aligned_end = _align(previous_end, page_size) if page_size else previous_end
            logical_end = aligned_end if aligned_end <= len(data) and not any(data[previous_end:aligned_end]) else previous_end
            result["properties"]["logical_file_end"] = logical_end
            result["properties"]["final_padding_bytes"] = logical_end - previous_end
            _append_trailer(result, data, logical_end, label=f"{kind}_trailing_payload")
    result["properties"]["parser_stop"] = malformed
    if malformed:
        result["findings"].append(_finding("warning", "structure", "Android boot traversal stopped", "No segment outside validated page-aligned boundaries was emitted.", reason=malformed))
    else:
        result["findings"].append(_finding("info", "firmware", "Android boot segments recovered", "Page-aligned declared segments were copied for recursive analysis without booting or mounting the image."))
    return result


def parse_uefi_fv(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("uefi_fv")
    if len(data) < 56 or data[40:44] != b"_FVH":
        result["findings"].append(_finding("error", "structure", "Invalid UEFI firmware-volume header", "The _FVH signature at offset 40 is missing."))
        return result
    volume_length = int.from_bytes(data[32:40], "little")
    header_length = int.from_bytes(data[48:50], "little")
    if not 56 <= header_length <= min(volume_length, len(data)) or volume_length < header_length:
        result["findings"].append(_finding("error", "structure", "Unsafe UEFI firmware-volume geometry", "The declared header or volume length is outside retained bounds."))
        return result
    header = data[:header_length]
    checksum = sum(int.from_bytes(header[index:index + 2].ljust(2, b"\0"), "little") for index in range(0, len(header), 2)) & 0xFFFF
    result["properties"].update({
        "filesystem_guid": str(uuid.UUID(bytes_le=data[16:32])), "declared_volume_bytes": volume_length,
        "header_bytes": header_length, "attributes": f"0x{int.from_bytes(data[44:48], 'little'):08x}",
        "header_checksum_valid": checksum == 0, "extended_header_offset": int.from_bytes(data[52:54], "little"),
        "revision": data[55], "logical_file_end": volume_length, "volume_complete": volume_length <= len(data),
    })
    _append_strings(result, data[: min(len(data), volume_length)], source="UEFI firmware-volume strings", confidence=6)
    if volume_length <= len(data):
        _append_trailer(result, data, volume_length, label="uefi_fv_trailing_payload")
    else:
        result["findings"].append(_finding("warning", "structure", "UEFI firmware volume is truncated", "The declared complete volume length exceeds retained bytes."))
    return result


def parse_squashfs(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("squashfs")
    if len(data) < 96 or data[:4] != b"hsqs":
        result["findings"].append(_finding("error", "structure", "Invalid SquashFS v4 superblock", "The little-endian SquashFS magic or 96-byte superblock is missing."))
        return result
    values = struct.unpack_from("<5I6H8Q", data, 0)
    _magic, inodes, created, block_size, fragments, compression, block_log, flags, ids, major, minor, root_inode, bytes_used, id_table, xattr_table, inode_table, directory_table, fragment_table, export_table = values
    compression_names = {1: "zlib", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
    geometry_valid = major == 4 and 4096 <= block_size <= 1024 * 1024 and not block_size & (block_size - 1) and 96 <= bytes_used <= len(data)
    result["properties"].update({
        "version": f"{major}.{minor}", "inodes": inodes, "created_unix": created,
        "block_size": block_size, "block_log": block_log, "fragments": fragments,
        "compression": compression_names.get(compression, f"unknown-{compression}"),
        "flags": f"0x{flags:04x}", "id_count": ids, "root_inode": root_inode,
        "bytes_used": bytes_used, "id_table_offset": id_table, "xattr_table_offset": xattr_table,
        "inode_table_offset": inode_table, "directory_table_offset": directory_table,
        "fragment_table_offset": fragment_table, "export_table_offset": export_table,
        "valid_superblock_geometry": geometry_valid,
    })
    if geometry_valid:
        result["text_records"].append({
            "encoding": "squashfs-superblock", "offset": 0,
            "text": f"version={major}.{minor}\ninodes={inodes}\ncompression={result['properties']['compression']}\nblock_size={block_size}\nbytes_used={bytes_used}",
            "source": "SquashFS superblock", "confidence_hint": 10,
        })
        _append_trailer(result, data, bytes_used, label="squashfs_trailing_payload")
        result["findings"].append(_finding("info", "filesystem", "SquashFS superblock indexed", "Filesystem tables were not decompressed or mounted; use the optional read-only unsquashfs adapter for member listing."))
    else:
        result["findings"].append(_finding("warning", "structure", "SquashFS superblock is inconsistent", "The version, block size, or used-byte boundary failed conservative validation."))
    return result


def parse_warc(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("warc")
    if not data.startswith((b"WARC/1.0\r\n", b"WARC/1.1\r\n", b"WARC/1.0\n", b"WARC/1.1\n")):
        result["findings"].append(_finding("error", "structure", "Invalid WARC header", "The WARC/1.0 or WARC/1.1 record line is missing."))
        return result
    cursor = records = extracted_total = 0
    rows: list[str] = []
    malformed: str | None = None
    deadline = time.monotonic() + (8.0 if profile == "deep" else 3.0)
    while cursor < len(data) and records < 10_000 and time.monotonic() <= deadline:
        while data[cursor:cursor + 2] == b"\r\n":
            cursor += 2
        if cursor >= len(data):
            break
        if not data.startswith((b"WARC/1.0", b"WARC/1.1"), cursor):
            malformed = "expected WARC record version line"
            break
        header_end = data.find(b"\r\n\r\n", cursor, min(len(data), cursor + 64 * 1024))
        separator = 4
        if header_end < 0:
            header_end = data.find(b"\n\n", cursor, min(len(data), cursor + 64 * 1024))
            separator = 2
        if header_end < 0:
            malformed = "WARC record header exceeds 64 KiB or is truncated"
            break
        header_lines = data[cursor:header_end].replace(b"\r\n", b"\n").split(b"\n")
        headers: dict[str, str] = {}
        for line in header_lines[1:500]:
            name, colon, value = line.partition(b":")
            if colon and 0 < len(name) <= 128:
                headers[name.decode("ascii", "replace").casefold()] = value.strip().decode("utf-8", "replace")
        try:
            content_length = int(headers.get("content-length", ""))
        except ValueError:
            malformed = "invalid WARC Content-Length"
            break
        payload_offset = header_end + separator
        if not 0 <= content_length <= 64 * 1024 * 1024 or content_length > len(data) - payload_offset:
            malformed = "WARC content block leaves retained bytes or exceeds 64 MiB"
            break
        payload = data[payload_offset:payload_offset + content_length]
        record_type = headers.get("warc-type", "unknown")
        target = headers.get("warc-target-uri", "")
        content_type = headers.get("content-type", "")
        rows.append(f"record {records}: type={display_text(record_type, 80)}, bytes={content_length}, target={display_text(target, 500)}, content-type={display_text(content_type, 160)}")
        child_payload = payload
        child_offset = payload_offset
        if payload.startswith(b"HTTP/"):
            http_end = payload.find(b"\r\n\r\n", 0, min(len(payload), 64 * 1024))
            if http_end >= 0:
                child_offset += http_end + 4
                child_payload = payload[http_end + 4:]
        child_kind = sniff_kind(child_payload, target)
        if child_payload and len(result["extracted"]) < 64 and extracted_total + len(child_payload) <= 64 * 1024 * 1024:
            result["extracted"].append({
                "label": f"warc_{records:04d}_{safe_label(record_type, 40)}",
                "data": child_payload, "kind": child_kind, "offset": child_offset,
                "transformation": "copy Content-Length-bounded WARC record payload",
                "parameters": {"record_type": display_text(record_type, 80), "target_uri": display_text(target, 500), "content_type": display_text(content_type, 160)},
            })
            extracted_total += len(child_payload)
        cursor = payload_offset + content_length
        records += 1
    result["properties"].update({"records": records, "bytes_consumed": cursor, "payloads_extracted": len(result["extracted"]), "parser_stop": malformed})
    if rows:
        result["text_records"].append({"encoding": "warc-record-index", "offset": 0, "text": display_text("\n".join(rows), 2_000_000), "source": "WARC record headers", "confidence_hint": 10})
    if malformed:
        result["findings"].append(_finding("warning", "structure", "WARC traversal stopped safely", "Completed records were retained before an invalid record boundary.", reason=malformed))
    return result


def parse_chm(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("chm")
    if len(data) < 56 or data[:4] != b"ITSF":
        result["findings"].append(_finding("error", "structure", "Invalid CHM/ITSF header", "The ITSF signature or fixed header is missing."))
        return result
    version = int.from_bytes(data[4:8], "little")
    header_length = int.from_bytes(data[8:12], "little")
    timestamp = int.from_bytes(data[16:20], "little")
    language_id = int.from_bytes(data[20:24], "little")
    result["properties"].update({
        "itsf_version": version, "header_bytes": header_length, "timestamp_field": timestamp,
        "language_id": f"0x{language_id:08x}", "file_size": len(data),
        "valid_header_geometry": 56 <= header_length <= min(len(data), 4096),
    })
    if len(data) >= 96:
        result["properties"].update({
            "directory_guid": str(uuid.UUID(bytes_le=data[24:40])),
            "stream_guid": str(uuid.UUID(bytes_le=data[40:56])),
            "section_0_offset": int.from_bytes(data[56:64], "little"),
            "section_0_bytes": int.from_bytes(data[64:72], "little"),
            "directory_offset": int.from_bytes(data[72:80], "little"),
            "directory_bytes": int.from_bytes(data[80:88], "little"),
            "content_offset": int.from_bytes(data[88:96], "little"),
        })
    _append_strings(result, data, source="CHM/ITSF directory and content strings", confidence=6)
    result["findings"].append(_finding("info", "document", "CHM inspected as an inert container", "HTML, scripts, and links were not rendered or followed; optional extract_chmLib/7-Zip tooling can recover members into bounded artifacts."))
    return result


def parse_djvu(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("djvu")
    if len(data) < 16 or data[:8] != b"AT&TFORM":
        result["findings"].append(_finding("error", "structure", "Invalid DjVu IFF header", "The AT&T FORM signature and form type are missing."))
        return result
    form_size = int.from_bytes(data[8:12], "big")
    form_type = data[12:16].decode("ascii", "replace")
    logical_end = 12 + form_size
    end = min(len(data), logical_end)
    cursor = 16
    chunks: list[str] = []
    malformed: str | None = None
    while cursor + 8 <= end and len(chunks) < 100_000:
        chunk_id = data[cursor:cursor + 4].decode("ascii", "replace")
        size = int.from_bytes(data[cursor + 4:cursor + 8], "big")
        payload_offset = cursor + 8
        if size > end - payload_offset:
            malformed = f"DjVu chunk {chunk_id} leaves the declared FORM"
            break
        payload = data[payload_offset:payload_offset + size]
        chunks.append(f"{chunk_id}: offset={payload_offset}, bytes={size}")
        if chunk_id in {"TXTa", "ANTa"} and size <= 4 * 1024 * 1024:
            text = payload.decode("utf-8", "replace")
            result["text_records"].append({"encoding": "djvu-text-chunk", "offset": payload_offset, "text": display_text(text, 1_000_000), "source": f"DjVu {chunk_id} chunk", "confidence_hint": 9})
        if chunk_id == "FORM" and size >= 4 and size <= 16 * 1024 * 1024 and len(result["extracted"]) < 32:
            # A bundled DJVM page is an ordinary FORM chunk without the
            # four-byte AT&T file prefix.  Restoring that fixed wrapper makes
            # the exact page recursively parseable without decoding pixels.
            nested = b"AT&T" + data[cursor:payload_offset + size]
            subtype = payload[:4].decode("ascii", "replace")
            result["extracted"].append({
                "label": f"djvu_nested_{safe_label(subtype, 20)}", "data": nested, "kind": "djvu", "offset": cursor,
                "transformation": "wrap bundled DjVu FORM chunk with its fixed AT&T file prefix",
                "parameters": {"form_type": display_text(subtype, 20), "source_bytes": 8 + size},
            })
        child_kind = sniff_kind(payload, chunk_id)
        if child_kind not in {"binary", "text", "djvu"} and 8 <= size <= 16 * 1024 * 1024 and len(result["extracted"]) < 32:
            result["extracted"].append({"label": f"djvu_{safe_label(chunk_id, 20)}", "data": payload, "kind": child_kind, "offset": payload_offset, "transformation": f"copy bounded DjVu {safe_label(chunk_id, 20)} chunk", "parameters": {"bytes": size}})
        cursor = payload_offset + size + (size & 1)
    result["properties"].update({"form_type": form_type, "declared_form_bytes": form_size, "logical_file_end": logical_end, "chunks": len(chunks), "parser_stop": malformed, "form_complete": logical_end <= len(data)})
    if chunks:
        result["text_records"].append({"encoding": "djvu-chunk-index", "offset": 16, "text": display_text("\n".join(chunks), 2_000_000), "source": "DjVu IFF chunk inventory", "confidence_hint": 10})
    if logical_end <= len(data):
        _append_trailer(result, data, logical_end, label="djvu_trailing_payload")
    if malformed:
        result["findings"].append(_finding("warning", "structure", "DjVu chunk traversal stopped", "Completed chunks were retained before an invalid boundary.", reason=malformed))
    elif any("TXTz" in row for row in chunks):
        result["findings"].append(_finding("info", "document", "Compressed DjVu text is present", "TXTz uses DjVu BZZ compression; use djvudump/djvutxt for specialist text recovery."))
    return result
