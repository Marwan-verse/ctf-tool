from __future__ import annotations

import datetime as dt
import struct
from typing import Any

from .common import display_text


def _result(kind: str) -> dict[str, Any]:
    return {"kind": kind, "properties": {}, "metadata": {}, "findings": [], "text_records": [], "extracted": [], "repairs": []}


def _finding(severity: str, title: str, description: str, **details: Any) -> dict[str, Any]:
    return {"severity": severity, "category": "program-structure", "title": title, "description": description, "details": details}


def _bounded_overlay(result: dict[str, Any], data: bytes, end: int, label: str, producer: str) -> None:
    end = max(0, min(len(data), end))
    if len(data) - end < 16:
        return
    payload = data[end:]
    result["properties"]["overlay_offset"] = end
    result["properties"]["overlay_size"] = len(payload)
    result["findings"].append(_finding("warning", "Program has overlay data", f"{len(payload)} byte(s) follow the last declared file-backed region.", offset=end))
    result["extracted"].append({"label": label, "data": payload, "offset": end, "producer": producer, "transformation": "extract bytes after declared program regions"})


def parse_pe(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("pe")
    if len(data) < 64 or not data.startswith(b"MZ"):
        raise ValueError("DOS MZ header is missing or truncated")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > len(data) or data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise ValueError("PE signature offset is invalid")
    machine, section_count, timestamp, symbol_offset, symbol_count, optional_size, characteristics = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    if section_count > 512 or optional_size > 4096:
        raise ValueError("PE table limits are implausible")
    machine_names = {0x014C: "x86", 0x8664: "x86-64", 0x01C0: "ARM", 0xAA64: "ARM64", 0x0200: "Itanium"}
    result["properties"].update({
        "machine": machine_names.get(machine, f"0x{machine:04x}"), "machine_code": machine,
        "section_count": section_count, "coff_timestamp": timestamp,
        "coff_timestamp_utc": dt.datetime.fromtimestamp(timestamp, tz=dt.timezone.utc).isoformat() if 0 < timestamp < 4_102_444_800 else None,
        "symbol_table_offset": symbol_offset, "symbol_count": symbol_count,
        "optional_header_size": optional_size, "characteristics": f"0x{characteristics:04x}",
    })
    optional_offset = pe_offset + 24
    section_offset = optional_offset + optional_size
    if section_offset > len(data):
        raise ValueError("optional header extends beyond input")
    if optional_size >= 2:
        magic = struct.unpack_from("<H", data, optional_offset)[0]
        result["properties"]["pe_format"] = {0x10B: "PE32", 0x20B: "PE32+", 0x107: "ROM"}.get(magic, f"0x{magic:04x}")
        if magic in {0x10B, 0x20B} and optional_size >= 70:
            result["properties"]["entry_point_rva"] = struct.unpack_from("<I", data, optional_offset + 16)[0]
            result["properties"]["image_base"] = struct.unpack_from("<Q" if magic == 0x20B else "<I", data, optional_offset + (24 if magic == 0x20B else 28))[0]
            result["properties"]["section_alignment"] = struct.unpack_from("<I", data, optional_offset + 32)[0]
            result["properties"]["file_alignment"] = struct.unpack_from("<I", data, optional_offset + 36)[0]
            result["properties"]["image_size"] = struct.unpack_from("<I", data, optional_offset + 56)[0]
            result["properties"]["subsystem"] = struct.unpack_from("<H", data, optional_offset + 68)[0]
    sections: list[dict[str, Any]] = []
    referenced_end = section_offset + section_count * 40
    for index in range(section_count):
        offset = section_offset + index * 40
        if offset + 40 > len(data):
            result["findings"].append(_finding("warning", "PE section table is truncated", "A declared section header extends beyond the inspected bytes.", index=index))
            break
        name = data[offset:offset + 8].split(b"\x00", 1)[0].decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, offset + 8)
        flags = struct.unpack_from("<I", data, offset + 36)[0]
        file_end = min(len(data), raw_offset + raw_size) if raw_offset <= len(data) else raw_offset + raw_size
        if raw_offset <= len(data) and raw_size <= len(data) - raw_offset:
            referenced_end = max(referenced_end, file_end)
        sections.append({
            "index": index, "name": display_text(name, 32), "virtual_address": virtual_address,
            "virtual_size": virtual_size, "raw_offset": raw_offset, "raw_size": raw_size,
            "characteristics": f"0x{flags:08x}", "executable": bool(flags & 0x20000000),
            "writable": bool(flags & 0x80000000), "readable": bool(flags & 0x40000000),
        })
    result["properties"]["sections"] = sections
    if any(section["executable"] and section["writable"] for section in sections):
        result["findings"].append(_finding("warning", "Writable executable PE section", "At least one section is both writable and executable; inspect it for packing or embedded code."))
    _bounded_overlay(result, data, referenced_end, "pe_overlay", "built-in-pe")
    return result


def parse_elf(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("elf")
    if len(data) < 52 or not data.startswith(b"\x7fELF"):
        raise ValueError("ELF identification bytes are missing or truncated")
    elf_class, byte_order = data[4], data[5]
    if elf_class not in {1, 2} or byte_order not in {1, 2}:
        raise ValueError("unsupported ELF class or byte order")
    endian = "<" if byte_order == 1 else ">"
    header_format = endian + ("HHIIIIIHHHHHH" if elf_class == 1 else "HHIQQQIHHHHHH")
    header_size = struct.calcsize(header_format)
    if 16 + header_size > len(data):
        raise ValueError("ELF header is truncated")
    values = struct.unpack_from(header_format, data, 16)
    elf_type, machine, version, entry, program_offset, section_offset, flags, ehsize, program_entry_size, program_count, section_entry_size, section_count, shstr_index = values
    if program_count > 4096 or section_count > 8192:
        raise ValueError("ELF table counts exceed safety limits")
    machines = {3: "x86", 8: "MIPS", 20: "PowerPC", 40: "ARM", 62: "x86-64", 183: "AArch64", 243: "RISC-V"}
    result["properties"].update({
        "class": "ELF32" if elf_class == 1 else "ELF64", "byte_order": "little" if byte_order == 1 else "big",
        "os_abi": data[7], "type": elf_type, "machine": machines.get(machine, machine), "version": version,
        "entry_point": entry, "flags": f"0x{flags:x}", "header_size": ehsize,
        "program_header_offset": program_offset, "program_header_count": program_count,
        "section_header_offset": section_offset, "section_header_count": section_count,
    })
    referenced_end = max(ehsize, 16 + header_size)
    segments: list[dict[str, Any]] = []
    program_format = endian + ("IIIIIIII" if elf_class == 1 else "IIQQQQQQ")
    expected_program_size = struct.calcsize(program_format)
    if program_entry_size >= expected_program_size:
        for index in range(min(program_count, 4096)):
            offset = program_offset + index * program_entry_size
            if offset + expected_program_size > len(data):
                break
            item = struct.unpack_from(program_format, data, offset)
            p_type = item[0]
            p_offset = item[1] if elf_class == 1 else item[2]
            p_filesz = item[4] if elf_class == 1 else item[5]
            p_flags = item[6] if elf_class == 1 else item[1]
            if p_offset <= len(data) and p_filesz <= len(data) - p_offset:
                referenced_end = max(referenced_end, p_offset + p_filesz)
            segments.append({"index": index, "type": p_type, "file_offset": p_offset, "file_size": p_filesz, "flags": p_flags})
    result["properties"]["segments"] = segments
    section_format = endian + ("IIIIIIIIII" if elf_class == 1 else "IIQQQQIIQQ")
    expected_section_size = struct.calcsize(section_format)
    raw_sections: list[tuple[Any, ...]] = []
    if section_entry_size >= expected_section_size:
        for index in range(min(section_count, 8192)):
            offset = section_offset + index * section_entry_size
            if offset + expected_section_size > len(data):
                break
            item = struct.unpack_from(section_format, data, offset)
            raw_sections.append(item)
            file_offset, file_size = item[4], item[5]
            if file_offset <= len(data) and file_size <= len(data) - file_offset:
                referenced_end = max(referenced_end, file_offset + file_size)
    names = b""
    if 0 <= shstr_index < len(raw_sections):
        name_section = raw_sections[shstr_index]
        name_offset, name_size = name_section[4], name_section[5]
        if name_offset <= len(data) and name_size <= len(data) - name_offset:
            names = data[name_offset:name_offset + min(name_size, 8 * 1024 * 1024)]
    sections: list[dict[str, Any]] = []
    for index, item in enumerate(raw_sections):
        name_offset = item[0]
        end = names.find(b"\x00", name_offset) if name_offset < len(names) else -1
        name = names[name_offset:end if end >= 0 else min(len(names), name_offset + 64)].decode("utf-8", "replace") if name_offset < len(names) else ""
        sections.append({"index": index, "name": display_text(name, 80), "type": item[1], "file_offset": item[4], "file_size": item[5]})
    result["properties"]["sections"] = sections
    _bounded_overlay(result, data, referenced_end, "elf_overlay", "built-in-elf")
    return result


def parse_macho(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("macho")
    if len(data) < 8:
        raise ValueError("Mach-O header is truncated")
    magic = data[:4]
    if magic in {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"}:
        is_64 = magic == b"\xca\xfe\xba\xbf"
        count = struct.unpack_from(">I", data, 4)[0]
        if not 1 <= count <= 128:
            raise ValueError("fat Mach-O architecture count is implausible")
        item_format = ">IIQQII" if is_64 else ">IIIII"
        item_size = struct.calcsize(item_format)
        architectures: list[dict[str, Any]] = []
        referenced_end = 8 + count * item_size
        for index in range(count):
            offset = 8 + index * item_size
            if offset + item_size > len(data):
                break
            item = struct.unpack_from(item_format, data, offset)
            slice_offset, slice_size = item[2], item[3]
            if slice_offset <= len(data) and slice_size <= len(data) - slice_offset:
                referenced_end = max(referenced_end, slice_offset + slice_size)
            architectures.append({"index": index, "cpu_type": item[0], "cpu_subtype": item[1], "offset": slice_offset, "size": slice_size, "alignment_power": item[4]})
        result["properties"].update({"format": "fat64" if is_64 else "fat", "architecture_count": count, "architectures": architectures})
        _bounded_overlay(result, data, referenced_end, "macho_fat_overlay", "built-in-macho")
        return result
    variants = {
        b"\xce\xfa\xed\xfe": ("<", False), b"\xcf\xfa\xed\xfe": ("<", True),
        b"\xfe\xed\xfa\xce": (">", False), b"\xfe\xed\xfa\xcf": (">", True),
    }
    if magic not in variants:
        raise ValueError("Mach-O magic is unsupported")
    endian, is_64 = variants[magic]
    header_format = endian + ("IIIIIII" if is_64 else "IIIIII")
    header_size = 4 + struct.calcsize(header_format)
    if header_size > len(data):
        raise ValueError("Mach-O header is truncated")
    values = struct.unpack_from(header_format, data, 4)
    cpu_type, cpu_subtype, file_type, command_count, commands_size, flags = values[:6]
    if command_count > 8192 or commands_size > len(data):
        raise ValueError("Mach-O load command limits are implausible")
    result["properties"].update({"format": "Mach-O 64" if is_64 else "Mach-O 32", "byte_order": "little" if endian == "<" else "big", "cpu_type": cpu_type, "cpu_subtype": cpu_subtype, "file_type": file_type, "load_command_count": command_count, "load_commands_size": commands_size, "flags": f"0x{flags:08x}"})
    commands: list[dict[str, Any]] = []
    cursor = header_size
    referenced_end = header_size + commands_size
    for index in range(command_count):
        if cursor + 8 > len(data):
            break
        command, size = struct.unpack_from(endian + "II", data, cursor)
        if size < 8 or cursor + size > len(data):
            result["findings"].append(_finding("warning", "Mach-O load command is truncated", "A load command size extends beyond the inspected bytes.", index=index, offset=cursor))
            break
        record: dict[str, Any] = {"index": index, "command": f"0x{command:08x}", "offset": cursor, "size": size}
        if command in {0x1, 0x19}:
            segment_64 = command == 0x19
            minimum = 72 if segment_64 else 56
            if size >= minimum:
                name = data[cursor + 8:cursor + 24].split(b"\x00", 1)[0].decode("ascii", "replace")
                if segment_64:
                    file_offset, file_size = struct.unpack_from(endian + "QQ", data, cursor + 40)
                else:
                    file_offset, file_size = struct.unpack_from(endian + "II", data, cursor + 32)
                record.update({"segment": display_text(name, 32), "file_offset": file_offset, "file_size": file_size})
                if file_offset <= len(data) and file_size <= len(data) - file_offset:
                    referenced_end = max(referenced_end, file_offset + file_size)
        commands.append(record)
        cursor += size
    result["properties"]["load_commands"] = commands
    _bounded_overlay(result, data, referenced_end, "macho_overlay", "built-in-macho")
    return result


def _read_uleb128(data: bytes, offset: int, maximum_bytes: int = 5) -> tuple[int, int]:
    value = 0
    for index in range(maximum_bytes):
        if offset + index >= len(data):
            raise ValueError("truncated LEB128 value")
        byte = data[offset + index]
        value |= (byte & 0x7F) << (index * 7)
        if not byte & 0x80:
            return value, offset + index + 1
    raise ValueError("LEB128 value exceeds safety bound")


def parse_wasm(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("wasm")
    if len(data) < 8 or data[:4] != b"\x00asm":
        raise ValueError("WebAssembly magic is missing")
    result["properties"]["version"] = int.from_bytes(data[4:8], "little")
    cursor = 8
    sections: list[dict[str, Any]] = []
    for index in range(2048):
        if cursor >= len(data):
            break
        section_offset = cursor
        section_id = data[cursor]
        cursor += 1
        size, cursor = _read_uleb128(data, cursor)
        if size > len(data) - cursor:
            result["findings"].append(_finding("warning", "WebAssembly section is truncated", "A section declares more bytes than remain.", index=index, offset=section_offset, declared_size=size))
            break
        payload_offset, payload_end = cursor, cursor + size
        record: dict[str, Any] = {"index": index, "id": section_id, "offset": section_offset, "payload_offset": payload_offset, "size": size}
        if section_id == 0 and size:
            try:
                name_size, name_offset = _read_uleb128(data, payload_offset)
                if name_size <= payload_end - name_offset:
                    name = data[name_offset:name_offset + name_size].decode("utf-8", "replace")
                    record["custom_name"] = display_text(name, 120)
                    result["text_records"].append({"text": display_text(name, 4096), "offset": name_offset, "source": "wasm-custom-section", "encoding": "utf-8"})
                    if name not in {"name", "producers", "sourceMappingURL", "dylink.0", "linking"} and payload_end - (name_offset + name_size) >= 16:
                        result["extracted"].append({"label": f"wasm_custom_{index}_{display_text(name, 40)}", "data": data[name_offset + name_size:payload_end], "offset": name_offset + name_size, "producer": "built-in-wasm", "transformation": "extract custom WebAssembly section payload"})
            except ValueError:
                pass
        sections.append(record)
        cursor = payload_end
    result["properties"]["sections"] = sections
    if cursor < len(data):
        _bounded_overlay(result, data, cursor, "wasm_trailer", "built-in-wasm")
    return result


def parse_dex(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("dex")
    if len(data) < 0x70 or not data.startswith(b"dex\n") or data[7] != 0:
        raise ValueError("DEX header is missing or truncated")
    version = data[4:7].decode("ascii", "replace")
    checksum = struct.unpack_from("<I", data, 8)[0]
    file_size, header_size, endian_tag = struct.unpack_from("<III", data, 32)
    map_offset = struct.unpack_from("<I", data, 52)[0]
    string_count, string_ids_offset = struct.unpack_from("<II", data, 56)
    if string_count > 1_000_000 or string_ids_offset > len(data):
        raise ValueError("DEX string table exceeds safety limits")
    result["properties"].update({"version": version, "checksum_adler32": f"0x{checksum:08x}", "signature_sha1": data[12:32].hex(), "declared_file_size": file_size, "header_size": header_size, "endian_tag": f"0x{endian_tag:08x}", "map_offset": map_offset, "string_count": string_count})
    strings: list[dict[str, Any]] = []
    limit = {"quick": 2_000, "balanced": 10_000, "deep": 40_000}.get(profile, 10_000)
    for index in range(min(string_count, limit)):
        entry_offset = string_ids_offset + index * 4
        if entry_offset + 4 > len(data):
            break
        text_offset = struct.unpack_from("<I", data, entry_offset)[0]
        if text_offset >= len(data):
            continue
        try:
            utf16_size, text_start = _read_uleb128(data, text_offset)
        except ValueError:
            continue
        text_end = data.find(b"\x00", text_start, min(len(data), text_start + 64 * 1024))
        if text_end < 0:
            continue
        text = data[text_start:text_end].decode("utf-8", "replace")
        if text:
            record = {"index": index, "offset": text_start, "utf16_size": utf16_size, "text": display_text(text, 4096)}
            strings.append(record)
            result["text_records"].append({"text": record["text"], "offset": text_start, "source": "dex-string", "encoding": "modified-utf-8"})
    result["properties"]["strings"] = strings[:2_000]
    result["properties"]["strings_truncated"] = string_count > len(strings)
    if 0 < file_size < len(data):
        _bounded_overlay(result, data, file_size, "dex_overlay", "built-in-dex")
    elif file_size > len(data):
        result["findings"].append(_finding("warning", "DEX is truncated", "The declared file size exceeds the inspected input.", declared_size=file_size, available_size=len(data)))
    return result


def parse_java_class(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("java_class")
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("Java class header is missing")
    minor, major, pool_count = struct.unpack_from(">HHH", data, 4)
    if not 1 <= pool_count <= 65_535:
        raise ValueError("constant-pool count is invalid")
    result["properties"].update({"minor_version": minor, "major_version": major, "constant_pool_count": pool_count})
    cursor, index = 10, 1
    utf8_entries: list[dict[str, Any]] = []
    tag_counts: dict[str, int] = {}
    while index < pool_count and cursor < len(data):
        tag_offset = cursor
        tag = data[cursor]
        cursor += 1
        tag_counts[str(tag)] = tag_counts.get(str(tag), 0) + 1
        if tag == 1:
            if cursor + 2 > len(data):
                break
            size = struct.unpack_from(">H", data, cursor)[0]
            cursor += 2
            if size > len(data) - cursor:
                break
            text = data[cursor:cursor + size].decode("utf-8", "replace")
            if text:
                record = {"index": index, "offset": cursor, "text": display_text(text, 4096)}
                utf8_entries.append(record)
                result["text_records"].append({"text": record["text"], "offset": cursor, "source": "java-constant-pool", "encoding": "modified-utf-8"})
            cursor += size
        elif tag in {3, 4}:
            cursor += 4
        elif tag in {5, 6}:
            cursor += 8
            index += 1
        elif tag in {7, 8, 16, 19, 20}:
            cursor += 2
        elif tag in {9, 10, 11, 12, 17, 18}:
            cursor += 4
        elif tag == 15:
            cursor += 3
        else:
            result["findings"].append(_finding("warning", "Unknown Java constant-pool tag", "Parsing stopped at an unsupported constant-pool tag.", tag=tag, index=index, offset=tag_offset))
            break
        if cursor > len(data):
            result["findings"].append(_finding("warning", "Java constant pool is truncated", "A constant-pool item extends beyond the inspected bytes.", index=index, offset=tag_offset))
            break
        index += 1
    result["properties"].update({"constant_pool_tags": tag_counts, "utf8_entries": utf8_entries[:2_000], "parsed_constant_pool_entries": index - 1})
    return result
