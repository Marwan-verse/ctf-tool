from __future__ import annotations

import struct

from app.analyzers.common import extension_for, mime_for, sniff_kind
from app.analyzers.formats import analyze_format


def _minimal_pe() -> bytes:
    data = bytearray(0x220)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 1, 1_700_000_000, 0, 0, 0xF0, 0x22)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<H", data, optional + 68, 3)
    section = optional + 0xF0
    data[section:section + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", data, section + 8, 16, 0x1000, 16, 0x200)
    struct.pack_into("<I", data, section + 36, 0xE0000020)
    data[0x200:0x210] = b"PROGRAM-CONTENT!"
    data[0x210:0x220] = b"flag{overlay}!!!"
    return bytes(data)


def test_program_magic_and_structural_parsers() -> None:
    pe = _minimal_pe()
    assert sniff_kind(pe, "challenge.bin") == "pe"
    pe_result = analyze_format("pe", pe)
    assert pe_result["properties"]["machine"] == "x86-64"
    assert pe_result["properties"]["sections"][0]["executable"] is True
    assert pe_result["extracted"][0]["label"] == "pe_overlay"

    elf = bytearray(64)
    elf[:16] = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    struct.pack_into("<HHIQQQIHHHHHH", elf, 16, 2, 62, 1, 0x401000, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    assert sniff_kind(bytes(elf), "a.out") == "elf"
    assert analyze_format("elf", bytes(elf))["properties"]["machine"] == "x86-64"

    macho = b"\xcf\xfa\xed\xfe" + struct.pack("<IIIIIII", 0x01000007, 3, 2, 0, 0, 0, 0)
    assert sniff_kind(macho, "program") == "macho"
    assert analyze_format("macho", macho)["properties"]["format"] == "Mach-O 64"


def test_wasm_dex_and_java_strings_are_exposed_as_text_records() -> None:
    custom_name = b"ctf"
    payload = bytes([len(custom_name)]) + custom_name + b"flag{wasm_custom}"
    wasm = b"\x00asm\x01\x00\x00\x00" + bytes([0, len(payload)]) + payload
    assert sniff_kind(wasm, "module.bin") == "wasm"
    wasm_result = analyze_format("wasm", wasm)
    assert wasm_result["properties"]["sections"][0]["custom_name"] == "ctf"
    assert wasm_result["extracted"][0]["data"] == b"flag{wasm_custom}"

    java_text = b"flag{java_pool}"
    java = b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 61, 2) + b"\x01" + struct.pack(">H", len(java_text)) + java_text
    assert sniff_kind(java, "Mystery.bin") == "java_class"
    java_result = analyze_format("java_class", java)
    assert java_result["text_records"][0]["text"] == "flag{java_pool}"

    dex = bytearray(0x90)
    dex[:8] = b"dex\n035\x00"
    struct.pack_into("<III", dex, 32, len(dex), 0x70, 0x12345678)
    struct.pack_into("<II", dex, 56, 1, 0x70)
    struct.pack_into("<I", dex, 0x70, 0x74)
    dex[0x74:0x74 + 16] = b"\x0eflag{dex_text}\x00"
    assert sniff_kind(bytes(dex), "classes.bin") == "dex"
    dex_result = analyze_format("dex", bytes(dex))
    assert dex_result["text_records"][0]["text"] == "flag{dex_text}"


def test_video_containers_report_metadata_and_trailer_bytes() -> None:
    ftyp = struct.pack(">I4s4sI4s", 20, b"ftyp", b"isom", 0, b"isom")
    trailer = b"flag{mp4_tail}!!"
    mp4 = ftyp + trailer
    assert sniff_kind(mp4, "clip.mp4") == "mp4"
    mp4_result = analyze_format("mp4", mp4)
    assert mp4_result["properties"]["major_brand"] == "isom"
    assert mp4_result["extracted"][0]["data"] == trailer

    info = b"INAM" + struct.pack("<I", 5) + b"flag\x00" + b"\x00"
    avi_body = b"AVI " + info
    avi = b"RIFF" + struct.pack("<I", len(avi_body)) + avi_body
    assert sniff_kind(avi, "movie.dat") == "avi"
    assert analyze_format("avi", avi)["metadata"]["avi:name"] == "flag"

    webm = b"\x1aE\xdf\xa3\x87\x42\x82\x84webm"
    assert sniff_kind(webm, "video.dat") == "webm"
    assert analyze_format("webm", webm)["properties"]["document_type"] == "webm"


def test_new_types_have_download_extensions_and_mime_types() -> None:
    assert extension_for("java_class") == ".class"
    assert mime_for("wasm") == "application/wasm"
    assert mime_for("webm") == "video/webm"
