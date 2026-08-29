from __future__ import annotations

import base64
import io
import sqlite3
import struct
import tarfile
from email.message import EmailMessage
from pathlib import Path

import pytest

from app.analyzers.common import sniff_kind
from app.analyzers.compression import decompress_lz4
from app.analyzers.external import ExternalToolRunner
from app.analyzers.formats import analyze_format
from app.engine import AnalysisEngine


def _raw_ipv4_packet(source: str, destination: str, protocol: int, payload: bytes, *, source_port: int = 1, destination_port: int = 1, sequence: int = 0) -> bytes:
    """Build the small checksum-free raw IPv4 packets used by PCAP fixtures."""

    source_bytes = bytes(int(part) for part in source.split("."))
    destination_bytes = bytes(int(part) for part in destination.split("."))
    if protocol == 6:
        transport = struct.pack("!HHIIHHHH", source_port, destination_port, sequence, 0, (5 << 12) | 0x18, 65535, 0, 0) + payload
    else:
        transport = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 1, 0, 64, protocol, 0, source_bytes, destination_bytes)
    return header + transport


def _raw_pcap(packets: list[bytes]) -> bytes:
    global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 228)
    records = b"".join(struct.pack("<IIII", index, 0, len(packet), len(packet)) + packet for index, packet in enumerate(packets, 1))
    return global_header + records


def _pcapng_block(block_type: int, body: bytes, endian: str = "<") -> bytes:
    length = ((12 + len(body) + 3) // 4) * 4
    body += b"\x00" * (length - 12 - len(body))
    return struct.pack(f"{endian}II", block_type, length) + body + struct.pack(f"{endian}I", length)


def _raw_pcapng(packet: bytes, *, endian: str = "<") -> bytes:
    bom = 0x1A2B3C4D
    section = _pcapng_block(0x0A0D0D0A, struct.pack(f"{endian}IHHq", bom, 1, 0, -1), endian)
    interface = _pcapng_block(1, struct.pack(f"{endian}HHI", 228, 0, 65535), endian)
    enhanced = _pcapng_block(6, struct.pack(f"{endian}IIIII", 0, 0, 1, len(packet), len(packet)) + packet, endian)
    return section + interface + enhanced


@pytest.mark.parametrize(
    ("payload", "filename", "expected"),
    [
        (b"\xd4\xc3\xb2\xa1" + b"\0" * 20, "capture.bin", "pcap"),
        (b"\x0a\x0d\x0d\x0a" + b"\0" * 24, "capture.bin", "pcapng"),
        (b"SQLite format 3\x00" + b"\0" * 100, "mystery", "sqlite"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 512, "mystery", "ole"),
        (b"regf" + b"\0" * 4092, "mystery", "registry"),
        (b"7z\xbc\xaf'\x1c" + b"\0" * 20, "mystery", "7z"),
        (b"Rar!\x1a\x07\x01\x00" + b"\0" * 20, "mystery", "rar"),
        (b"ElfFile\x00" + b"\0" * 4096, "mystery", "evtx"),
        (b"!BDN" + b"\0" * 512, "mystery", "pst"),
        (b"!<arch>\n" + b"\0" * 60, "mystery", "ar"),
        (b"LZIP\x01\x0c" + b"\0" * 24, "mystery", "lzip"),
        (b"\x04\x22\x4d\x18" + b"\0" * 24, "mystery", "lz4"),
        (b"\x89LZO\x00\r\n\x1a\n" + b"\0" * 32, "mystery", "lzop"),
    ],
)
def test_new_forensic_magic_detection(payload: bytes, filename: str, expected: str) -> None:
    assert sniff_kind(payload, filename) == expected


def test_classic_pcap_header_and_packet_record_are_bounded() -> None:
    global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    packet = b"flag{pcap_record}"
    record = struct.pack("<IIII", 1, 2, len(packet), len(packet)) + packet

    report = analyze_format("pcap", global_header + record)

    assert report["properties"]["packet_records_scanned"] == 1
    assert report["properties"]["captured_payload_bytes"] == len(packet)


def test_pcap_network_payload_flags_are_extracted() -> None:
    payload = b"picoCTF{packet_payload_fixture}"
    report = analyze_format("pcap", _raw_pcap([_raw_ipv4_packet("10.0.0.1", "10.0.0.2", 6, payload, source_port=20, destination_port=21)]))

    assert report["properties"]["tcp_packets"] == 1
    assert any(payload.decode() in finding["details"]["flags"] for finding in report["findings"] if finding["title"] == "Flag-like text recovered from network payload")


def test_pcap_character_spaced_flag_is_normalized() -> None:
    payload = b"p i c o C T F { p 4 c k 3 7 _ 5 h 4 r k _ c e c c a a 7 f }\n"
    report = analyze_format("pcap", _raw_pcap([_raw_ipv4_packet("10.0.0.1", "10.0.0.2", 6, payload)]))

    assert any("picoCTF{p4ck37_5h4rk_ceccaa7f}" in finding["details"]["flags"] for finding in report["findings"])


def test_pcapng_enhanced_packet_block_is_analyzed() -> None:
    payload = b"picoCTF{pcapng_packet_fixture}"
    packet = _raw_ipv4_packet("10.0.0.1", "10.0.0.2", 6, payload, source_port=1234, destination_port=80)

    report = analyze_format("pcapng", _raw_pcapng(packet))

    assert report["properties"]["enhanced_packet_blocks"] == 1
    assert report["properties"]["network_packets"] == 1
    assert any(payload.decode() in finding["details"]["flags"] for finding in report["findings"] if finding["title"] == "Flag-like text recovered from network payload")


def test_pcap_udp_conversation_reassembles_varying_source_ports() -> None:
    packets = [
        _raw_ipv4_packet("10.0.0.1", "10.0.0.2", 17, fragment, source_port=4000 + index, destination_port=22)
        for index, fragment in enumerate((b"picoCTF{udp_", b"conversation_fixture}"))
    ]

    report = analyze_format("pcap", _raw_pcap(packets))

    assert any("picoCTF{udp_conversation_fixture}" in finding["details"]["flags"] for finding in report["findings"] if finding["title"] == "Flag-like text recovered from network payload")


def test_pcap_dns_base64_fragments_are_ordered_and_decoded() -> None:
    def encode_name(name: str) -> bytes:
        return b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"

    encoded = base64.b64encode(b"picoCTF{dns_fixture}").decode("ascii")
    packets = []
    for index, fragment in enumerate((encoded[:8], encoded[8:]), 1):
        question = encode_name(fragment + ".x.example.com") + struct.pack("!HH", 16, 1)
        dns = struct.pack("!HHHHHH", index, 0, 1, 0, 0, 0) + question
        packets.append(_raw_ipv4_packet("10.0.0.1", "8.8.8.8", 17, dns, source_port=4100 + index, destination_port=53))

    report = analyze_format("pcap", _raw_pcap(packets))

    assert report["properties"]["dns_recoveries"] >= 1
    assert any("picoCTF{dns_fixture}" in finding["details"]["flags"] for finding in report["findings"] if finding["title"] == "Flag-like text recovered from network payload")


def test_pcap_tftp_data_is_reassembled_as_child_object() -> None:
    request = b"\x00\x01flag.txt\x00octet\x00"
    data_block = struct.pack("!HH", 3, 1) + b"picoCTF{tftp_fixture}"
    packets = [
        _raw_ipv4_packet("10.0.0.1", "10.0.0.2", 17, request, source_port=40000, destination_port=69),
        _raw_ipv4_packet("10.0.0.2", "10.0.0.1", 17, data_block, source_port=50000, destination_port=40000),
    ]

    report = analyze_format("pcap", _raw_pcap(packets))

    assert report["properties"]["tftp_objects"] == 1
    assert any(item["data"] == b"picoCTF{tftp_fixture}" for item in report["extracted"] if item["label"].startswith("tftp_"))


def test_pcap_timestamp_sorted_base64_fragments_are_recovered() -> None:
    first = base64.b64encode(b"picoCTF{timestamp_")
    second = base64.b64encode(b"fixture}")
    packets = [
        _raw_ipv4_packet("10.0.0.1", "10.0.0.2", 17, second, source_port=4200, destination_port=9000),
        _raw_ipv4_packet("10.0.0.1", "10.0.0.2", 17, first, source_port=4201, destination_port=9000),
    ]
    global_header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 228)
    records = (
        struct.pack("<IIII", 20, 0, len(packets[0]), len(packets[0])) + packets[0]
        + struct.pack("<IIII", 10, 0, len(packets[1]), len(packets[1])) + packets[1]
    )

    report = analyze_format("pcap", global_header + records)

    assert any("picoCTF{timestamp_fixture}" in finding["details"]["flags"] for finding in report["findings"] if finding["title"] == "Flag-like text recovered from network payload")


def test_lz4_uncompressed_frame_is_bounded() -> None:
    payload = b"flag{lz4_frame_fixture}"
    frame = b"\x04\x22\x4d\x18\x60\x40\x00" + struct.pack("<I", 0x80000000 | len(payload)) + payload + b"\x00\x00\x00\x00"

    assert decompress_lz4(frame) == payload


def test_evtx_utf16_base64_fragments_are_reassembled() -> None:
    first = base64.b64encode(b"picoCTF{evtx_").decode("ascii")
    second = base64.b64encode(b"fixture_long}").decode("ascii")
    data = bytearray(8 * 1024)
    data[:8] = b"ElfFile\x00"
    data[4096:4096 + len(first.encode("utf-16le"))] = first.encode("utf-16le")
    offset = 4096 + len(first.encode("utf-16le")) + 16
    data[offset:offset + len(second.encode("utf-16le"))] = second.encode("utf-16le")

    report = analyze_format("evtx", bytes(data), profile="deep")

    assert any(record["text"] == "picoCTF{evtx_fixture_long}" for record in report["text_records"] if record["source"] == "evtx-base64-reassembly")


def test_pcap_rogue_tower_imsi_xor_recovery() -> None:
    plaintext = b"picoCTF{rogue_tower_fixture}"
    key = b"76578566"
    ciphertext = bytes(value ^ key[index % len(key)] for index, value in enumerate(plaintext))
    encoded = base64.b64encode(ciphertext)
    chunks = [encoded[index:index + 9] for index in range(0, len(encoded), 9)]
    packets = [
        _raw_ipv4_packet("192.168.99.1", "255.255.255.255", 17, b"UNAUTHORIZED-TEST-NETWORK PLMN=00101 CELLID=97320 ", source_port=55000, destination_port=55000),
        _raw_ipv4_packet("10.100.163.232", "198.51.100.225", 6, b"GET /api/register HTTP/1.1\r\nUser-Agent: MobileDevice/1.0 (IMSI:310410176578566; CELL:97320)\r\n\r\n", source_port=45678, destination_port=80),
    ]
    packets.extend(
        _raw_ipv4_packet("10.100.163.232", "198.51.100.225", 6, b"POST /upload HTTP/1.1\r\nContent-Length: " + str(len(chunk)).encode() + b"\r\n\r\n" + chunk, source_port=50000 + index, destination_port=443)
        for index, chunk in enumerate(chunks)
    )

    report = analyze_format("pcap", _raw_pcap(packets), profile="deep")

    assert report["properties"]["unauthorized_cell_ids"] == ["97320"]
    assert report["properties"]["xor_recoveries"] == 1
    assert report["extracted"][0]["data"] == plaintext
    assert report["findings"][-1]["details"]["recoveries"][0]["key"] == "76578566"


def test_sqlite_header_parser_surfaces_schema_strings(tmp_path: Path) -> None:
    source = tmp_path / "challenge.sqlite"
    connection = sqlite3.connect(source)
    try:
        connection.execute("CREATE TABLE flags(value TEXT)")
        connection.execute("INSERT INTO flags VALUES ('flag{sqlite_fixture}')")
        connection.commit()
    finally:
        connection.close()

    data = source.read_bytes()
    report = analyze_format("sqlite", data, profile="deep")

    assert sniff_kind(data, source.name) == "sqlite"
    assert report["properties"]["page_size"] in {4096, 8192}
    assert any("CREATE TABLE" in record["text"] for record in report["text_records"])


def test_eml_parser_decodes_body_and_attachment() -> None:
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["To"] = "solver@example.test"
    message["Subject"] = "flag{mail_subject}"
    message.set_content("body flag{mail_body}")
    message.add_attachment(b"flag{mail_attachment}", maintype="application", subtype="octet-stream", filename="clue.bin")
    data = message.as_bytes()

    report = analyze_format("eml", data)

    assert sniff_kind(data, "challenge.eml") == "eml"
    assert any("flag{mail_body}" in record["text"] for record in report["text_records"])
    assert report["extracted"][0]["data"] == b"flag{mail_attachment}"


def test_engine_recursively_reads_tar_members_without_writing_member_paths(tmp_path: Path) -> None:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        payload = b"flag{tar_member_fixture}"
        info = tarfile.TarInfo("../../hostile/flag.txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    source = tmp_path / "challenge.tar"
    source.write_bytes(buffer.getvalue())

    report = AnalysisEngine().run(
        input_path=source,
        output_dir=tmp_path / "output",
        profile="quick",
        flag_prefix=None,
        password=None,
        progress_callback=None,
        is_cancelled=lambda: False,
        options={
            "external_tools": False, "visual_analysis": False, "lsb_analysis": False,
            "ocr": False, "barcodes": False, "decoders": False,
            "crypto_analysis": False, "repairs": False,
        },
    )

    assert any(candidate["value"] == "flag{tar_member_fixture}" for candidate in report["candidates"])
    assert not (tmp_path / "hostile").exists()
    assert any(artifact["name"] == "tar_flag.txt" for artifact in report["artifacts"])


def test_usb_hid_decoder_handles_shift_and_backspace() -> None:
    output = "\n".join(
        [
            "1.5.1|00000b0000000000|",  # h
            "1.5.1|0000000000000000|",
            "1.5.1|02000c0000000000|",  # I
            "1.5.1|0000000000000000|",
            "1.5.1|00002a0000000000|",  # backspace
            "1.5.1|0000000000000000|",
            "1.5.1|00000c0000000000|",  # i
            "1.5.1|0000000000000000|",
            "1.5.1|02001e0000000000|",  # !
        ]
    )

    assert ExternalToolRunner._decode_usb_hid(output) == "[1.5.1]\nhi!"  # noqa: SLF001


def test_raw_partition_offsets_are_derived_from_mbr(tmp_path: Path) -> None:
    image = bytearray(4096)
    image[510:512] = b"\x55\xaa"
    image[446] = 0x80
    image[450] = 0x83
    image[454:458] = (2048).to_bytes(4, "little")
    image[458:462] = (4096).to_bytes(4, "little")
    source = tmp_path / "disk.img"
    source.write_bytes(image)

    assert ExternalToolRunner._raw_partition_offsets(source) == [2048]  # noqa: SLF001
