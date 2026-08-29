from __future__ import annotations

import base64
import binascii
import bz2
import email.policy
import ipaddress
import itertools
import re
import struct
import zlib
from collections import Counter, defaultdict
from email.parser import BytesParser
from typing import Any, Callable, Iterable

from .common import byte_entropy, display_text, iter_ascii_strings, iter_utf16_strings, safe_label, sniff_kind
from .compression import DECODERS, CompressionError


def analyze_format(kind: str, data: bytes, *, profile: str = "balanced") -> dict[str, Any]:
    parser: Callable[[bytes, str], dict[str, Any]] | None = {
        "png": parse_png,
        "jpeg": parse_jpeg,
        "gif": parse_gif,
        "bmp": parse_bmp,
        "webp": parse_webp,
        "tiff": parse_tiff,
        "ico": parse_ico,
        "pdf": parse_pdf,
        "pcap": parse_pcap,
        "pcapng": parse_pcapng,
        "sqlite": parse_sqlite,
        "ole": parse_ole,
        "rtf": parse_rtf,
        "eml": parse_eml,
        "disk": parse_disk,
        "ewf": parse_ewf,
        "registry": parse_registry,
        "memory": parse_memory,
        "evtx": parse_evtx,
        "pst": parse_pst,
        "shar": parse_shar,
        "ar": parse_ar,
        "lzip": parse_lzip,
        "lz4": parse_lz4,
        "lzma": parse_lzma,
        "lzop": parse_lzop,
    }.get(kind)
    if parser is None:
        return _result(kind)
    try:
        return parser(data, profile)
    except Exception as exc:
        result = _result(kind)
        result["findings"].append(_finding(
            "warning", "structure", f"{kind.upper()} parser stopped safely",
            "The built-in structural parser rejected malformed or unsupported data.",
            error=f"{type(exc).__name__}: {display_text(exc, 300)}",
        ))
        result["properties"]["parser_error"] = f"{type(exc).__name__}: {display_text(exc, 300)}"
        return result


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


_PCAP_FLAG_PREFIXES = (b"picoCTF{", b"flag{", b"CTF{", b"HTB{", b"THM{", b"DUCTF{", b"ICC{")
_PCAP_FLAG_RE = re.compile(rb"(?<![A-Za-z0-9_])[A-Za-z][A-Za-z0-9_-]{1,31}\{[^\r\n{}]{2,240}\}")
_PCAP_IMSI_RE = re.compile(rb"\bIMSI\s*[:=]\s*(\d{8,20})", re.IGNORECASE)
_PCAP_CELL_RE = re.compile(rb"\bCELL(?:ID)?\s*[:=]\s*(\d{3,12})", re.IGNORECASE)
_PCAP_MAGIC_PREFIXES = _PCAP_FLAG_PREFIXES + (
    b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF89a", b"GIF87a", b"BM",
    b"PK\x03\x04", b"%PDF-", b"BZh", b"\x1f\x8b", b"Salted__", b"RIFF",
)


def _pcap_transport_fields(protocol: int, segment: bytes) -> dict[str, Any]:
    """Parse a bounded TCP, UDP, or ICMP header from an IP payload."""

    fields: dict[str, Any] = {
        "source_port": None, "destination_port": None, "sequence": None,
        "acknowledgement": None, "tcp_flags": None, "tcp_window": None,
        "icmp_type": None, "icmp_code": None, "icmp_id": None, "icmp_sequence": None,
        "payload": segment, "transport_header_length": 0,
    }
    if protocol == 6:
        if len(segment) < 20:
            return fields
        source_port, destination_port, sequence, acknowledgement = struct.unpack_from("!HHII", segment)
        header_length = ((segment[12] >> 4) & 0x0F) * 4
        if header_length < 20 or header_length > len(segment):
            return fields
        fields.update({
            "source_port": source_port, "destination_port": destination_port,
            "sequence": sequence, "acknowledgement": acknowledgement,
            "tcp_flags": ((segment[12] & 0x01) << 8) | segment[13],
            "tcp_window": int.from_bytes(segment[14:16], "big"),
            "payload": segment[header_length:], "transport_header_length": header_length,
        })
    elif protocol == 17:
        if len(segment) < 8:
            return fields
        source_port, destination_port, udp_length = struct.unpack_from("!HHH", segment)
        udp_end = min(len(segment), udp_length) if udp_length >= 8 else len(segment)
        fields.update({
            "source_port": source_port, "destination_port": destination_port,
            "payload": segment[8:udp_end], "transport_header_length": 8,
            "udp_length": udp_length,
        })
    elif protocol in {1, 58}:  # ICMP / ICMPv6
        if len(segment) < 4:
            return fields
        fields["icmp_type"], fields["icmp_code"] = segment[0], segment[1]
        header_length = 8 if len(segment) >= 8 else 4
        if len(segment) >= 8:
            fields["icmp_id"] = int.from_bytes(segment[4:6], "big")
            fields["icmp_sequence"] = int.from_bytes(segment[6:8], "big")
        fields["payload"] = segment[header_length:]
        fields["transport_header_length"] = header_length
    return fields


def _pcap_network_offset(frame: bytes, linktype: int) -> tuple[int, int] | None:
    """Return ``(offset, IP version)`` for common bounded capture link types."""

    if not frame:
        return None
    if linktype in {101, 228, 229}:  # DLT_RAW / DLT_IPV4 / DLT_IPV6
        version = frame[0] >> 4
        if version in {4, 6} and (linktype == 101 or version == (4 if linktype == 228 else 6)):
            return 0, version
        return None
    if linktype == 1:  # Ethernet II, including 802.1Q/QinQ tags
        if len(frame) < 14:
            return None
        ether_type = int.from_bytes(frame[12:14], "big")
        offset = 14
        while ether_type in {0x8100, 0x88A8, 0x9100} and len(frame) >= offset + 4:
            ether_type = int.from_bytes(frame[offset + 2:offset + 4], "big")
            offset += 4
        if ether_type in {0x0800, 0x86DD}:
            return offset, 4 if ether_type == 0x0800 else 6
        return None
    if linktype == 113:  # Linux cooked capture (SLL v1)
        if len(frame) < 16:
            return None
        protocol = int.from_bytes(frame[14:16], "big")
        if protocol in {0x0800, 0x86DD}:
            return 16, 4 if protocol == 0x0800 else 6
        return None
    if linktype == 276:  # Linux cooked capture (SLL v2)
        if len(frame) < 20:
            return None
        protocol = int.from_bytes(frame[:2], "big")
        if protocol in {0x0800, 0x86DD}:
            return 20, 4 if protocol == 0x0800 else 6
        return None
    if linktype in {0, 108}:  # BSD NULL / LOOP
        if len(frame) < 4:
            return None
        families = {int.from_bytes(frame[:4], "little"), int.from_bytes(frame[:4], "big")}
        if 2 in families:
            return 4, 4
        if families & {10, 24, 28, 30}:
            return 4, 6
        return None
    if linktype in {9, 50}:  # PPP / PPP-HDLC
        offset = 0
        if frame.startswith(b"\xff\x03"):
            offset = 2
        if len(frame) >= offset + 2:
            protocol = int.from_bytes(frame[offset:offset + 2], "big")
            if protocol in {0x0021, 0x0057}:
                return offset + 2, 4 if protocol == 0x0021 else 6
    return None


def _pcap_frame_payload(frame: bytes, linktype: int) -> tuple[int, bytes]:
    """Return a conservative link-layer payload even when it is not IP."""

    if linktype == 1 and len(frame) >= 14:
        offset = 14
        ether_type = int.from_bytes(frame[12:14], "big")
        while ether_type in {0x8100, 0x88A8, 0x9100} and len(frame) >= offset + 4:
            ether_type = int.from_bytes(frame[offset + 2:offset + 4], "big")
            offset += 4
        return offset, frame[offset:]
    if linktype == 113 and len(frame) >= 16:
        return 16, frame[16:]
    if linktype == 276 and len(frame) >= 20:
        return 20, frame[20:]
    if linktype in {0, 108} and len(frame) >= 4:
        return 4, frame[4:]
    return 0, frame


def _pcap_packet_network(frame: bytes, linktype: int) -> dict[str, Any] | None:
    """Return bounded IPv4/IPv6 transport details for common capture link types."""

    located = _pcap_network_offset(frame, linktype)
    if located is None:
        return None
    ip_offset, version = located
    if version == 4:
        if len(frame) < ip_offset + 20 or frame[ip_offset] >> 4 != 4:
            return None
        ihl = (frame[ip_offset] & 0x0F) * 4
        if ihl < 20 or len(frame) < ip_offset + ihl:
            return None
        total_length = int.from_bytes(frame[ip_offset + 2:ip_offset + 4], "big")
        packet_end = min(len(frame), ip_offset + total_length) if total_length >= ihl else len(frame)
        protocol = frame[ip_offset + 9]
        source = str(ipaddress.IPv4Address(frame[ip_offset + 12:ip_offset + 16]))
        destination = str(ipaddress.IPv4Address(frame[ip_offset + 16:ip_offset + 20]))
        fragment_field = int.from_bytes(frame[ip_offset + 6:ip_offset + 8], "big")
        fragment_offset = (fragment_field & 0x1FFF) * 8
        more_fragments = bool(fragment_field & 0x2000)
        transport_offset = ip_offset + ihl
        ip_payload = frame[transport_offset:packet_end]
        transport = _pcap_transport_fields(protocol, ip_payload) if fragment_offset == 0 else _pcap_transport_fields(-1, ip_payload)
        return {
            "ip_version": 4, "source": source, "destination": destination, "protocol": protocol,
            "ttl": frame[ip_offset + 8], "traffic_class": frame[ip_offset + 1],
            "ip_id": int.from_bytes(frame[ip_offset + 4:ip_offset + 6], "big"),
            "fragment_offset": fragment_offset, "more_fragments": more_fragments,
            "ip_payload": ip_payload if (fragment_offset or more_fragments) else b"", "network_offset": ip_offset,
            "payload_offset": transport_offset + int(transport["transport_header_length"]),
            **transport,
        }

    if len(frame) < ip_offset + 40 or frame[ip_offset] >> 4 != 6:
        return None
    declared = int.from_bytes(frame[ip_offset + 4:ip_offset + 6], "big")
    packet_end = min(len(frame), ip_offset + 40 + declared)
    next_header = frame[ip_offset + 6]
    cursor = ip_offset + 40
    fragment_offset = 0
    more_fragments = False
    fragment_id: int | None = None
    extension_count = 0
    while next_header in {0, 43, 44, 51, 60} and extension_count < 8:
        extension_count += 1
        if next_header == 44:
            if cursor + 8 > packet_end:
                return None
            following = frame[cursor]
            fragment_field = int.from_bytes(frame[cursor + 2:cursor + 4], "big")
            fragment_offset = ((fragment_field >> 3) & 0x1FFF) * 8
            more_fragments = bool(fragment_field & 0x01)
            fragment_id = int.from_bytes(frame[cursor + 4:cursor + 8], "big")
            cursor += 8
            next_header = following
            break
        if cursor + 2 > packet_end:
            return None
        following = frame[cursor]
        extension_length = (frame[cursor + 1] + 2) * 4 if next_header == 51 else (frame[cursor + 1] + 1) * 8
        if extension_length < 8 or cursor + extension_length > packet_end:
            return None
        cursor += extension_length
        next_header = following
    source = str(ipaddress.IPv6Address(frame[ip_offset + 8:ip_offset + 24]))
    destination = str(ipaddress.IPv6Address(frame[ip_offset + 24:ip_offset + 40]))
    ip_payload = frame[cursor:packet_end]
    transport = _pcap_transport_fields(next_header, ip_payload) if fragment_offset == 0 else _pcap_transport_fields(-1, ip_payload)
    first_word = int.from_bytes(frame[ip_offset:ip_offset + 4], "big")
    return {
        "ip_version": 6, "source": source, "destination": destination, "protocol": next_header,
        "ttl": frame[ip_offset + 7], "traffic_class": (first_word >> 20) & 0xFF,
        "flow_label": first_word & 0xFFFFF, "ip_id": fragment_id,
        "fragment_offset": fragment_offset, "more_fragments": more_fragments,
        "ip_payload": ip_payload if (fragment_offset or more_fragments) else b"", "network_offset": ip_offset,
        "payload_offset": cursor + int(transport["transport_header_length"]),
        **transport,
    }


def _pcap_http_message(payload: bytes) -> dict[str, Any] | None:
    """Parse one request/response carried in a single bounded payload."""

    match = re.search(rb"(?m)^(GET|POST|PUT|HEAD|HTTP/1\.[01])\s+([^\r\n ]+)", payload)
    if not match:
        return None
    header_end = payload.find(b"\r\n\r\n", match.end())
    if header_end < 0:
        header_end = payload.find(b"\n\n", match.end())
        separator_length = 2
    else:
        separator_length = 4
    if header_end < 0:
        return None
    headers = payload[match.end():header_end].decode("latin-1", "ignore")
    body = payload[header_end + separator_length:]
    header_map: dict[str, str] = {}
    for line in headers.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            header_map[key.strip().lower()] = value.strip()
    content_length = header_map.get("content-length")
    if content_length and content_length.isdigit():
        body = body[:int(content_length)]
    if "chunked" in header_map.get("transfer-encoding", "").lower():
        decoded = bytearray()
        cursor = 0
        for _ in range(4096):
            line_end = body.find(b"\r\n", cursor)
            separator = 2
            if line_end < 0:
                line_end = body.find(b"\n", cursor)
                separator = 1
            if line_end < 0:
                break
            try:
                chunk_size = int(body[cursor:line_end].split(b";", 1)[0].strip(), 16)
            except ValueError:
                break
            cursor = line_end + separator
            if chunk_size == 0 or cursor + chunk_size > len(body):
                break
            decoded.extend(body[cursor:cursor + chunk_size])
            cursor += chunk_size
            if body[cursor:cursor + 2] == b"\r\n":
                cursor += 2
            elif body[cursor:cursor + 1] == b"\n":
                cursor += 1
        if decoded:
            body = bytes(decoded)
    request_method = match.group(1).decode("ascii", "ignore")
    request_target = match.group(2).decode("latin-1", "ignore")
    return {
        "method": request_method, "target": request_target,
        "headers": header_map, "body": body,
    }


def _pcap_xor_recover(ciphertext: bytes, imsis: Iterable[str]) -> list[dict[str, Any]]:
    """Try CTF-known prefixes with decimal IMSI windows as repeating XOR keys."""

    recoveries: list[dict[str, Any]] = []
    seen: set[tuple[str, bytes]] = set()
    for imsi in imsis:
        digits = "".join(character for character in imsi if character.isdigit())
        for start in range(max(1, len(digits) - 7)):
            key_text = digits[start:start + 8]
            if len(key_text) != 8:
                continue
            key = key_text.encode("ascii")
            if (key_text, ciphertext) in seen:
                continue
            seen.add((key_text, ciphertext))
            plaintext = bytes(value ^ key[index % len(key)] for index, value in enumerate(ciphertext))
            if not any(prefix in plaintext for prefix in _PCAP_FLAG_PREFIXES):
                continue
            match = _PCAP_FLAG_RE.search(plaintext)
            if not match:
                continue
            recoveries.append({
                "data": plaintext, "flag": match.group(0).decode("latin-1", "ignore"),
                "key": key_text, "key_source": f"last/substring of IMSI {digits}",
            })
    return recoveries


def _pcap_timestamp_key(packet: dict[str, Any]) -> tuple[int, int, int]:
    value = packet.get("timestamp_key")
    if isinstance(value, tuple) and len(value) >= 2:
        return int(value[0]), int(value[1]), int(packet.get("number", 0))
    timestamp_ns = packet.get("timestamp_ns")
    if isinstance(timestamp_ns, int):
        return timestamp_ns // 1_000_000_000, timestamp_ns % 1_000_000_000, int(packet.get("number", 0))
    return int(packet.get("number", 0)), 0, int(packet.get("number", 0))


def _pcap_printable(data: bytes, ratio: float = 0.55) -> bool:
    if not data:
        return False
    printable = sum(value in {9, 10, 13} or 32 <= value < 127 for value in data)
    return printable >= max(4, int(len(data) * ratio))


def _pcap_flag_values(data: bytes) -> set[str]:
    allowed = tuple(prefix.decode("ascii", "ignore").casefold() for prefix in _PCAP_FLAG_PREFIXES)
    values = {
        value for value in (match.group(0).decode("latin-1", "ignore") for match in _PCAP_FLAG_RE.finditer(data))
        if value.casefold().startswith(allowed)
    }
    if b"{" in data and b"}" in data:
        compact = re.sub(rb"[\x00\x09\x0a\x0d ]+", b"", data)
        values.update(
            value for value in (match.group(0).decode("latin-1", "ignore") for match in _PCAP_FLAG_RE.finditer(compact))
            if value.casefold().startswith(allowed)
        )
    return values


def _pcap_reassemble_tcp(fragments: list[tuple[int | None, int, bytes]]) -> tuple[list[bytes], int, int]:
    """Build contiguous TCP spans while clipping retransmissions and overlaps."""

    usable = [(sequence, number, payload) for sequence, number, payload in fragments if payload]
    if not usable:
        return [], 0, 0
    if not all(isinstance(sequence, int) for sequence, _number, _payload in usable):
        return [b"".join(payload for _sequence, _number, payload in sorted(usable, key=lambda item: item[1]))], 0, 0
    if len({int(sequence) for sequence, _number, _payload in usable}) == 1:
        # Some hand-crafted/partial captures omit meaningful TCP sequence
        # numbers and leave every segment at zero. Preserve capture order in
        # that case instead of treating later segments as retransmissions.
        return [b"".join(payload for _sequence, _number, payload in sorted(usable, key=lambda item: item[1]))], 0, 0
    sequence_values = [int(sequence) for sequence, _number, _payload in usable]
    sequence_min, sequence_max = min(sequence_values), max(sequence_values)
    # A span wider than half the 32-bit sequence space is the practical signal
    # for wraparound; otherwise the smallest sequence is the stream origin,
    # which makes ordinary out-of-order captures deterministic.
    base_sequence = sequence_max if sequence_max - sequence_min > 0x80000000 else sequence_min
    normalized = [
        (((int(sequence) - base_sequence) & 0xFFFFFFFF) + base_sequence, number, payload)
        for sequence, number, payload in usable
    ]
    ordered = sorted(normalized, key=lambda item: (item[0], item[1]))
    spans: list[bytearray] = []
    span_start = int(ordered[0][0])
    span_end = span_start
    overlaps = 0
    gaps = 0
    current = bytearray()
    for sequence_value, _number, payload in ordered:
        sequence = int(sequence_value)
        if not current:
            span_start = sequence
            span_end = sequence
        if sequence > span_end:
            if current:
                spans.append(current)
            gaps += 1
            current = bytearray(payload)
            span_start = sequence
            span_end = sequence + len(payload)
            continue
        overlap = max(0, span_end - sequence)
        if overlap:
            overlaps += 1
        if overlap < len(payload):
            current.extend(payload[overlap:])
            span_end += len(payload) - overlap
    if current:
        spans.append(current)
    return [bytes(span) for span in spans], overlaps, gaps


def _pcap_dns_name(message: bytes, offset: int) -> tuple[list[str], int] | None:
    labels: list[str] = []
    cursor = offset
    end_offset: int | None = None
    visited: set[int] = set()
    for _ in range(128):
        if cursor >= len(message) or cursor in visited:
            return None
        visited.add(cursor)
        length = message[cursor]
        if length == 0:
            return labels, end_offset if end_offset is not None else cursor + 1
        if length & 0xC0 == 0xC0:
            if cursor + 2 > len(message):
                return None
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            if pointer >= len(message):
                return None
            if end_offset is None:
                end_offset = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0 or length > 63 or cursor + 1 + length > len(message):
            return None
        label = message[cursor + 1:cursor + 1 + length]
        labels.append(label.decode("ascii", "backslashreplace"))
        cursor += 1 + length
    return None


def _pcap_dns_message(payload: bytes, *, tcp: bool = False) -> dict[str, Any] | None:
    """Extract bounded DNS questions and useful answer data."""

    if tcp:
        if len(payload) < 2:
            return None
        declared = int.from_bytes(payload[:2], "big")
        payload = payload[2:2 + declared]
    if len(payload) < 12:
        return None
    question_count, answer_count, authority_count, additional_count = struct.unpack_from("!HHHH", payload, 4)
    if sum((question_count, answer_count, authority_count, additional_count)) > 4096:
        return None
    cursor = 12
    questions: list[str] = []
    answers: list[dict[str, Any]] = []
    for _ in range(question_count):
        parsed = _pcap_dns_name(payload, cursor)
        if parsed is None:
            return None
        labels, cursor = parsed
        if cursor + 4 > len(payload):
            return None
        query_type, query_class = struct.unpack_from("!HH", payload, cursor)
        cursor += 4
        questions.append(".".join(labels))
        answers.append({"section": "question", "name": ".".join(labels), "type": query_type, "class": query_class})
    for section, count in (("answer", answer_count), ("authority", authority_count), ("additional", additional_count)):
        for _ in range(count):
            parsed = _pcap_dns_name(payload, cursor)
            if parsed is None:
                return {"questions": questions, "answers": answers}
            labels, cursor = parsed
            if cursor + 10 > len(payload):
                return {"questions": questions, "answers": answers}
            record_type, record_class, ttl, data_length = struct.unpack_from("!HHIH", payload, cursor)
            cursor += 10
            if cursor + data_length > len(payload):
                return {"questions": questions, "answers": answers}
            rdata_offset = cursor
            rdata = payload[cursor:cursor + data_length]
            cursor += data_length
            record: dict[str, Any] = {
                "section": section, "name": ".".join(labels), "type": record_type,
                "class": record_class, "ttl": ttl, "data": rdata,
            }
            if record_type == 16:  # TXT
                values: list[str] = []
                text_cursor = 0
                while text_cursor < len(rdata):
                    length = rdata[text_cursor]
                    text_cursor += 1
                    if text_cursor + length > len(rdata):
                        break
                    values.append(rdata[text_cursor:text_cursor + length].decode("latin-1", "ignore"))
                    text_cursor += length
                record["text"] = "".join(values)
            elif record_type in {2, 5, 12}:  # NS, CNAME, PTR
                decoded = _pcap_dns_name(payload, rdata_offset)
                if decoded:
                    record["text"] = ".".join(decoded[0])
            elif record_type == 15 and len(rdata) >= 3:  # MX
                decoded = _pcap_dns_name(payload, rdata_offset + 2)
                if decoded:
                    record["text"] = ".".join(decoded[0])
            elif record_type == 1 and len(rdata) == 4:
                record["text"] = str(ipaddress.IPv4Address(rdata))
            elif record_type == 28 and len(rdata) == 16:
                record["text"] = str(ipaddress.IPv6Address(rdata))
            answers.append(record)
    return {"questions": questions, "answers": answers}


def _pcap_decode_variants(value: bytes) -> list[tuple[str, bytes]]:
    """Try bounded transforms commonly used by packet-exfiltration CTFs."""

    candidates: list[tuple[str, bytes]] = [("direct", value)]
    compact = re.sub(rb"[\x00\x09\x0a\x0d .:-]+", b"", value.strip())
    if compact and compact != value:
        candidates.append(("remove separators", compact))
    for source_label, source in list(candidates):
        # FindAndOpen-style non-IP frames often prepend a short marker before
        # an otherwise valid Base64 token. Try the bounded 0..3-byte trims
        # used by those captures without doing an unbounded substring search.
        if source_label == "direct" and len(source) > 12:
            for trim in range(1, 4):
                if len(source) - trim >= 8:
                    trimmed = source[trim:]
                    candidates.append((f"trim {trim} leading byte(s)", trimmed))
                    if re.fullmatch(rb"[A-Za-z0-9+/_=-]+", trimmed):
                        try:
                            candidates.append((f"trim {trim} leading byte(s), Base64 decode", base64.b64decode(trimmed + b"=" * (-len(trimmed) % 4), validate=True)))
                        except (ValueError, binascii.Error):
                            pass
                if len(source) - trim >= 8:
                    trimmed = source[:-trim]
                    candidates.append((f"trim {trim} trailing byte(s)", trimmed))
                    if re.fullmatch(rb"[A-Za-z0-9+/_=-]+", trimmed):
                        try:
                            candidates.append((f"trim {trim} trailing byte(s), Base64 decode", base64.b64decode(trimmed + b"=" * (-len(trimmed) % 4), validate=True)))
                        except (ValueError, binascii.Error):
                            pass
        if 2 <= len(source) <= 8 * 1024 * 1024 and len(source) % 2 == 0 and re.fullmatch(rb"[0-9A-Fa-f]+", source):
            try:
                candidates.append((f"{source_label}, hex decode", bytes.fromhex(source.decode("ascii"))))
            except ValueError:
                pass
        if 4 <= len(source) <= 8 * 1024 * 1024 and re.fullmatch(rb"[A-Za-z0-9+/_=-]+", source):
            padded = source + b"=" * (-len(source) % 4)
            try:
                candidates.append((f"{source_label}, Base64 decode", base64.b64decode(padded.replace(b"-", b"+").replace(b"_", b"/"), validate=True)))
            except (ValueError, binascii.Error):
                pass
        if b"%" in source:
            try:
                percent = re.sub(rb"%([0-9A-Fa-f]{2})", lambda match: bytes([int(match.group(1), 16)]), source)
                if percent != source:
                    candidates.append((f"{source_label}, URL percent decode", percent))
            except (TypeError, ValueError):
                pass
        if 8 <= len(source) <= 8 * 1024 * 1024 and re.fullmatch(rb"[A-Za-z2-7=]+", source, re.IGNORECASE):
            try:
                candidates.append((f"{source_label}, Base32 decode", base64.b32decode(source.upper() + b"=" * (-len(source) % 8))))
            except (ValueError, binascii.Error):
                pass
    expanded = list(candidates)
    for label, decoded in candidates[1:]:
        if 2 <= len(decoded) <= 8 * 1024 * 1024:
            for wrapper, bits in (("zlib", 15), ("gzip", 31), ("raw deflate", -15)):
                try:
                    uncompressed = zlib.decompress(decoded, bits)
                except zlib.error:
                    continue
                if len(uncompressed) <= 32 * 1024 * 1024:
                    expanded.append((f"{label}, {wrapper} decompress", uncompressed))
    unique: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()
    for label, decoded in expanded:
        if decoded and decoded not in seen:
            seen.add(decoded)
            unique.append((label, decoded))
    return unique[:24]


def _pcap_magic_byte_variants(value: bytes) -> list[tuple[str, bytes]]:
    """Infer a constant XOR/additive byte key from a known file/flag prefix."""

    variants: list[tuple[str, bytes]] = []
    if len(value) < 4:
        return variants
    for target in _PCAP_MAGIC_PREFIXES:
        if len(value) < len(target):
            continue
        xor_key = value[0] ^ target[0]
        if all((value[index] ^ xor_key) == target[index] for index in range(min(len(target), 12))):
            variants.append((f"constant XOR key 0x{xor_key:02x}", bytes(byte ^ xor_key for byte in value)))
        subtract = (value[0] - target[0]) & 0xFF
        if all(((value[index] - subtract) & 0xFF) == target[index] for index in range(min(len(target), 12))):
            variants.append((f"constant byte subtraction {subtract}", bytes((byte - subtract) & 0xFF for byte in value)))
    return variants


def _pcap_reassemble_ip_fragments(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Create synthetic transport records from complete bounded IP fragment sets."""

    groups: defaultdict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for packet in records:
        if not packet.get("more_fragments") and not packet.get("fragment_offset"):
            continue
        identifier = packet.get("ip_id")
        if identifier is None:
            continue
        groups[(packet.get("ip_version"), packet["source"], packet["destination"], packet["protocol"], identifier)].append(packet)
    rebuilt: list[dict[str, Any]] = []
    incomplete = 0
    for (_version, source, destination, protocol, _identifier), fragments in groups.items():
        if len(fragments) < 2 or not any(int(item.get("fragment_offset", 0)) == 0 for item in fragments) or not any(not item.get("more_fragments") for item in fragments):
            incomplete += 1
            continue
        total = max(int(item.get("fragment_offset", 0)) + len(bytes(item.get("ip_payload") or b"")) for item in fragments)
        if total <= 0 or total > 16 * 1024 * 1024:
            incomplete += 1
            continue
        payload = bytearray(total)
        covered = bytearray(total)
        conflict = False
        for fragment in sorted(fragments, key=lambda item: (int(item.get("fragment_offset", 0)), item.get("number", 0))):
            start = int(fragment.get("fragment_offset", 0))
            chunk = bytes(fragment.get("ip_payload") or b"")
            end = min(total, start + len(chunk))
            for index, value in enumerate(chunk[:end - start], start):
                if covered[index] and payload[index] != value:
                    conflict = True
                    continue
                payload[index] = value
                covered[index] = 1
        if conflict or not all(covered):
            incomplete += 1
            continue
        transport = _pcap_transport_fields(int(protocol), bytes(payload))
        first = min(fragments, key=_pcap_timestamp_key)
        rebuilt.append({
            **first, **transport, "source": source, "destination": destination, "protocol": protocol,
            "payload_offset": first.get("payload_offset", first.get("frame_offset", 0)),
            "synthetic": "IP fragment reassembly", "fragment_count": len(fragments),
            "fragment_offset": 0, "more_fragments": False,
        })
    return rebuilt, incomplete


def _pcap_tftp_objects(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reassemble simple RRQ/WRQ TFTP transfers from UDP DATA blocks."""

    requests: list[dict[str, Any]] = []
    for packet in sorted(records, key=_pcap_timestamp_key):
        if packet.get("protocol") != 17:
            continue
        payload = bytes(packet.get("payload") or b"")
        if len(payload) < 2:
            continue
        opcode = int.from_bytes(payload[:2], "big")
        if opcode in {1, 2} and packet.get("destination_port") == 69:
            fields = payload[2:].split(b"\x00")
            if not fields or not fields[0]:
                continue
            requests.append({
                "opcode": opcode, "filename": fields[0].decode("utf-8", "replace"),
                "client": packet["source"], "client_port": packet.get("source_port"),
                "server": packet["destination"], "packet": packet.get("number", 0),
                "blocks": {}, "server_port": None,
            })
            continue
        if opcode != 3 or len(payload) < 4:
            continue
        block_number = int.from_bytes(payload[2:4], "big")
        for request in reversed(requests):
            if request["opcode"] == 1:
                matches = (
                    packet["source"] == request["server"] and packet["destination"] == request["client"]
                    and packet.get("destination_port") == request["client_port"]
                )
                transfer_port = packet.get("source_port")
            else:
                matches = (
                    packet["source"] == request["client"] and packet["destination"] == request["server"]
                    and packet.get("source_port") == request["client_port"]
                )
                transfer_port = packet.get("destination_port")
            if not matches or (request["server_port"] is not None and transfer_port != request["server_port"]):
                continue
            request["server_port"] = transfer_port
            request["blocks"].setdefault(block_number, payload[4:])
            break
    objects: list[dict[str, Any]] = []
    for request in requests:
        blocks: dict[int, bytes] = request["blocks"]
        if 1 not in blocks:
            continue
        assembled = bytearray()
        block = 1
        complete = False
        while block in blocks and len(assembled) <= 64 * 1024 * 1024:
            chunk = blocks[block]
            assembled.extend(chunk)
            if len(chunk) < 512:
                complete = True
                break
            block += 1
        if assembled:
            objects.append({
                "filename": request["filename"], "data": bytes(assembled),
                "block_count": block, "complete": complete, "packet": request["packet"],
            })
    return objects


def _analyze_capture_records(result: dict[str, Any], records: list[dict[str, Any]], profile: str) -> dict[str, Any]:
    """Shared packet-content analysis used by classic PCAP and PCAPNG."""

    text_limit = 250 if profile == "quick" else 1_000 if profile == "balanced" else 4_000
    text_seen: set[str] = set()
    recovered_seen: set[bytes] = set()
    promoted_flags: set[str] = set()
    promoted_file_signatures: set[tuple[str, bytes]] = set()
    direct_flag_hits: set[str] = set()
    imsis: set[str] = set()
    unauthorized_cells: set[str] = set()
    http_messages: list[dict[str, Any]] = []
    tcp_flows: defaultdict[tuple[Any, ...], list[tuple[int | None, int, bytes]]] = defaultdict(list)
    udp_flows: defaultdict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    dns_entries: list[dict[str, Any]] = []
    payload_bytes = 0
    decoded_recoveries = 0

    def add_text(text_value: str, source: str, offset: int | None, hint: int = 8, transform_chain: list[str] | None = None) -> None:
        if not text_value or text_value in text_seen or len(text_seen) >= text_limit:
            return
        text_seen.add(text_value)
        record: dict[str, Any] = {"source": source, "offset": offset, "text": text_value, "confidence_hint": hint}
        if transform_chain:
            record["transform_chain"] = transform_chain
        result["text_records"].append(record)

    def register_candidate(value: bytes, source: str, offset: int | None, transform: str, *, force_artifact: bool = False) -> bool:
        nonlocal decoded_recoveries
        if not value or len(value) > 64 * 1024 * 1024:
            return False
        flags = _pcap_flag_values(value)
        direct_flag_hits.update(flags)
        kind = sniff_kind(value, source)
        strong_signature = any(
            value.startswith(signature)
            for signature in (
                b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"BM",
                b"RIFF", b"PK\x03\x04", b"PK\x05\x06", b"%PDF-", b"BZh", b"\x1f\x8b",
                b"fLaC", b"OggS", b"MThd", b"SQLite format 3\x00", b"Salted__",
            )
        )
        meaningful_file = len(value) >= 16 and strong_signature and (kind not in {"binary", "text"} or value.startswith(b"Salted__"))
        if not flags and not meaningful_file and not force_artifact:
            return False
        new_flags = flags - promoted_flags
        if flags and not new_flags and not meaningful_file and not force_artifact:
            return False
        signature_key = (kind, value[:16])
        if meaningful_file and not flags and signature_key in promoted_file_signatures and not force_artifact:
            return False
        if _pcap_printable(value) or flags:
            add_text(value.decode("latin-1", "ignore"), source, offset, 11 if flags else 7, [transform] if transform else None)
        if value not in recovered_seen and (flags or meaningful_file or force_artifact):
            recovered_seen.add(value)
            promoted_flags.update(flags)
            if meaningful_file:
                promoted_file_signatures.add(signature_key)
            result["extracted"].append({
                "label": safe_label(f"pcap_{source}_recovered"), "data": value,
                "kind": "text" if flags or _pcap_printable(value) else kind,
                "producer": "pcap-network-forensics", "transformation": transform or "packet stream reconstruction",
                "reason": "A flag-shaped value or recognized file signature validated the bounded recovery.",
            })
            decoded_recoveries += 1
        return bool(flags or meaningful_file)

    def try_variants(value: bytes, source: str, offset: int | None, *, include_direct: bool = False) -> int:
        found = 0
        variants = _pcap_decode_variants(value)
        variants.extend(_pcap_magic_byte_variants(value))
        for index, (transform, decoded) in enumerate(variants):
            if index == 0 and not include_direct:
                continue
            if register_candidate(decoded, source, offset, transform):
                found += 1
        return found

    for packet in records:
        payload = bytes(packet.get("payload") or b"")
        payload_bytes += len(payload)
        if not packet.get("network", True):
            # Keep non-IP Ethernet/PPP data useful for challenges that hide a
            # password or Base64 token outside an IP packet.
            try_variants(payload, "pcap-link-payload", packet.get("frame_offset"))
        for match in _PCAP_IMSI_RE.finditer(payload):
            imsis.add(match.group(1).decode("ascii"))
        for match in re.finditer(rb"UNAUTHORIZED[^\r\n]{0,160}", payload, re.IGNORECASE):
            cell_match = _PCAP_CELL_RE.search(match.group(0))
            if cell_match:
                unauthorized_cells.add(cell_match.group(1).decode("ascii"))
        if _pcap_printable(payload):
            text_value = payload.decode("latin-1", "ignore").replace("\x00", "")
            add_text(text_value, "pcap-payload", packet.get("frame_offset", 0) + int(packet.get("payload_offset", 0)), 8)
            direct_flag_hits.update(_pcap_flag_values(payload))
        if b"{" in payload and b"}" in payload:
            compact = re.sub(rb"[\x09\x0a\x0d ]+", b"", payload)
            if compact != payload:
                add_text(compact.decode("latin-1", "ignore"), "pcap-payload-normalized", packet.get("frame_offset"), 10, ["remove inter-token whitespace"])
                direct_flag_hits.update(_pcap_flag_values(compact))
        source = packet.get("source")
        destination = packet.get("destination")
        protocol = packet.get("protocol")
        if source is not None and destination is not None and protocol == 6:
            flow_key = (source, packet.get("source_port"), destination, packet.get("destination_port"), protocol)
            tcp_flows[flow_key].append((packet.get("sequence"), int(packet.get("number", 0)), payload))
        if source is not None and destination is not None and protocol == 17:
            flow_key = (source, packet.get("source_port"), destination, packet.get("destination_port"), protocol)
            udp_flows[flow_key].append(packet)
        if source is not None and destination is not None and protocol in {6, 17} and (packet.get("source_port") == 53 or packet.get("destination_port") == 53):
            parsed_dns = _pcap_dns_message(payload, tcp=protocol == 6)
            if parsed_dns:
                dns_entries.append({"packet": packet, "parsed": parsed_dns})
        message = _pcap_http_message(payload)
        if message:
            message.update({
                "packet": packet.get("number", 0), "source": source, "destination": destination,
                "source_port": packet.get("source_port"), "destination_port": packet.get("destination_port"),
            })
            http_messages.append(message)

    rebuilt_fragments, incomplete_fragments = _pcap_reassemble_ip_fragments(records)
    if rebuilt_fragments:
        records = records + rebuilt_fragments
        for packet in rebuilt_fragments:
            payload = bytes(packet.get("payload") or b"")
            direct_flag_hits.update(_pcap_flag_values(payload))
            if _pcap_printable(payload):
                add_text(payload.decode("latin-1", "ignore"), "pcap-ip-fragment-reassembly", packet.get("frame_offset"), 9, ["IPv4/IPv6 fragment reassembly"])
            message = _pcap_http_message(payload)
            if message:
                message.update({"packet": packet.get("number", 0), "source": packet.get("source"), "destination": packet.get("destination"), "source_port": packet.get("source_port"), "destination_port": packet.get("destination_port"), "reassembled": True})
                http_messages.append(message)

    # TCP streams: preserve sequence order, clip retransmitted/overlapping
    # bytes, and scan each contiguous span. This handles out-of-order captures
    # without fabricating bytes across a gap.
    tcp_reassemblies = 0
    tcp_overlap_bytes = 0
    tcp_gap_spans = 0
    for flow, fragments in tcp_flows.items():
        if len(fragments) < 2:
            continue
        spans, overlaps, gaps = _pcap_reassemble_tcp(fragments)
        tcp_overlap_bytes += overlaps
        tcp_gap_spans += gaps
        for span_index, assembled in enumerate(spans):
            if not assembled:
                continue
            tcp_reassemblies += 1
            direct_flag_hits.update(_pcap_flag_values(assembled))
            if _pcap_printable(assembled):
                add_text(assembled.decode("latin-1", "ignore"), "pcap-tcp-stream", None, 9, ["TCP sequence reassembly", f"span {span_index + 1}"])
            try_variants(assembled, "tcp-stream", None)
            message = _pcap_http_message(assembled)
            if message:
                message.update({"packet": fragments[0][1], "source": flow[0], "destination": flow[2], "source_port": flow[1], "destination_port": flow[3], "reassembled": True})
                http_messages.append(message)

    # UDP conversations are the usual shark-on-wire-1 pattern. Analyze both
    # directional streams and a canonical bidirectional stream so decoys do
    # not prevent a real flag from being found.
    conversation_groups: defaultdict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for flow, packets in udp_flows.items():
        ordered = sorted(packets, key=_pcap_timestamp_key)
        blob = b"".join(bytes(item.get("payload") or b"") for item in ordered)
        direct_flag_hits.update(_pcap_flag_values(blob))
        printable_stream = _pcap_printable(blob)
        if printable_stream:
            add_text(blob.decode("latin-1", "ignore"), "pcap-udp-stream", None, 8, ["UDP packet-order concatenation"])
        if printable_stream or re.fullmatch(rb"[A-Za-z0-9+/_=\s.-]{16,}", blob):
            try_variants(blob, "udp-stream", None)
        # Keep ports out of the fallback key: shark-on-wire-1 deliberately
        # changes the UDP source port for each character packet.
        endpoint_a = str(flow[0])
        endpoint_b = str(flow[2])
        conversation_groups[tuple(sorted((endpoint_a, endpoint_b)))].extend(ordered)
    for conversation, packets in conversation_groups.items():
        ordered = sorted(packets, key=_pcap_timestamp_key)
        blob = b"".join(bytes(item.get("payload") or b"") for item in ordered)
        direct_flag_hits.update(_pcap_flag_values(blob))
        if _pcap_printable(blob) or re.fullmatch(rb"[A-Za-z0-9+/_=\s.-]{16,}", blob):
            try_variants(blob, "udp-conversation", None)

    # Ph4nt0m-style channels decode every packet independently, then sort the
    # decoded bytes by the packet timestamp before joining them. A capture-order
    # candidate is also tested for captures whose timestamps are unavailable.
    encoded_groups: defaultdict[tuple[Any, ...], list[tuple[dict[str, Any], bytes]]] = defaultdict(list)
    encoded_budget = 32 * 1024 * 1024 if profile == "deep" else 16 * 1024 * 1024 if profile == "balanced" else 4 * 1024 * 1024
    encoded_bytes = 0
    for packet in records:
        token = re.sub(rb"\s+", b"", bytes(packet.get("payload") or b"").strip())
        if len(token) < 4 or not re.fullmatch(rb"[A-Za-z0-9+/_=-]+", token):
            continue
        padded = token + b"=" * (-len(token) % 4)
        try:
            decoded = base64.b64decode(padded.replace(b"-", b"+").replace(b"_", b"/"), validate=True)
        except (ValueError, binascii.Error):
            continue
        if not decoded:
            continue
        if encoded_bytes + len(decoded) > encoded_budget:
            break
        coarse = (packet.get("source"), packet.get("destination"), packet.get("protocol"))
        encoded_groups[coarse].append((packet, decoded))
        encoded_groups[("all",)].append((packet, decoded))
        encoded_bytes += len(decoded)
    timestamp_decodes = 0
    for group, chunks in encoded_groups.items():
        if len(chunks) < 2:
            continue
        candidates = [
            ("capture order", sorted(chunks, key=lambda item: int(item[0].get("number", 0)))),
            ("timestamp order", sorted(chunks, key=lambda item: (_pcap_timestamp_key(item[0]), int(item[0].get("number", 0))))),
        ]
        for ordering, ordered_chunks in candidates:
            joined = b"".join(decoded for _packet, decoded in ordered_chunks)
            if _pcap_flag_values(joined):
                timestamp_decodes += 1
            try_variants(joined, "timestamp-base64-fragments", None)
            direct_flag_hits.update(_pcap_flag_values(joined))

    # UDP source-port channels (shark-on-wire-2) with start/end markers and
    # both common offsets used by published solutions.
    port_recoveries: list[str] = []
    port_groups: defaultdict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for flow, packets in udp_flows.items():
        port_groups[(flow[0], flow[2], flow[3])].extend(packets)
    for group, packets in port_groups.items():
        ordered = sorted(packets, key=_pcap_timestamp_key)
        for base in (5000, 5001):
            values: list[int] = []
            active = False
            for packet in ordered:
                payload = bytes(packet.get("payload") or b"").lower()
                source_port = packet.get("source_port")
                if b"start" in payload:
                    active = True
                    continue
                if b"end" in payload and active:
                    break
                if active and isinstance(source_port, int) and 0 <= source_port - base <= 255:
                    values.append(source_port - base)
            if not values:
                continue
            recovered = bytes(values)
            flags = _pcap_flag_values(recovered)
            if flags:
                port_recoveries.extend(sorted(flags))
                add_text(recovered.decode("latin-1", "ignore"), "pcap-udp-source-port", None, 12, [f"source port minus {base}"])
                direct_flag_hits.update(flags)

    # DNS labels, TXT/CNAME answers, and indexed query fragments.
    dns_groups: defaultdict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    dns_txt_groups: defaultdict[tuple[Any, ...], list[tuple[dict[str, Any], str]]] = defaultdict(list)
    for entry in dns_entries:
        packet = entry["packet"]
        parsed = entry["parsed"]
        for name in parsed.get("questions", []):
            labels = [label for label in name.split(".") if label]
            add_text(name, "pcap-dns-query", packet.get("frame_offset"), 6)
            encoded_labels = []
            if labels and len(labels[0]) >= 4 and re.fullmatch(r"[A-Za-z0-9+/_=-]+", labels[0]):
                encoded_labels = [labels[0]]
            else:
                encoded_labels = [label for label in labels if len(label) >= 4 and re.fullmatch(r"[A-Za-z0-9+/_=-]+", label)]
            # Group by endpoints rather than guessing the authoritative base
            # domain: many CTF domains themselves look like Base32/Base64.
            for part in encoded_labels:
                dns_groups[(packet.get("source"), packet.get("destination"))].append({"packet": packet, "part": part})
        for answer in parsed.get("answers", []):
            text_value = answer.get("text")
            if not isinstance(text_value, str) or not text_value:
                continue
            add_text(text_value, "pcap-dns-answer", packet.get("frame_offset"), 6)
            direct_flag_hits.update(_pcap_flag_values(text_value.encode("latin-1", "ignore")))
            dns_txt_groups[(packet.get("source"), packet.get("destination"), answer.get("name", ""))].append((packet, text_value))
    dns_recoveries = 0
    for group, pieces in dns_groups.items():
        dedup: dict[str, dict[str, Any]] = {}
        for piece in pieces:
            dedup.setdefault(str(piece["part"]), piece)
        ordered = list(dedup.values())
        index_parts: list[tuple[int, str]] = []
        for piece in ordered:
            match = re.match(r"^(\d+)[_-](.+)$", str(piece["part"]))
            if match:
                index_parts.append((int(match.group(1)), match.group(2)))
        variants = ["".join(str(piece["part"]) for piece in sorted(ordered, key=lambda item: _pcap_timestamp_key(item["packet"])))]
        if index_parts:
            variants.append("".join(part for _index, part in sorted(index_parts)))
        for candidate in dict.fromkeys(variants):
            before = len(direct_flag_hits)
            try_variants(candidate.encode("ascii", "ignore"), "pcap-dns-fragments", None)
            direct_flag_hits.update(_pcap_flag_values(candidate.encode("ascii", "ignore")))
            dns_recoveries += int(len(direct_flag_hits) > before)
    for group, pieces in dns_txt_groups.items():
        ordered = sorted(pieces, key=lambda item: _pcap_timestamp_key(item[0]))
        candidate = "".join(text_value for _packet, text_value in ordered)
        try_variants(candidate.encode("latin-1", "ignore"), "pcap-dns-txt", None)
        direct_flag_hits.update(_pcap_flag_values(candidate.encode("latin-1", "ignore")))

    # TFTP RRQ/WRQ/DATA is small enough to reconstruct safely in-process; the
    # resulting files re-enter the normal recursive analyzer (including image
    # stego and document decoders).
    tftp_objects = _pcap_tftp_objects(records)
    for object_info in tftp_objects:
        filename = safe_label(str(object_info["filename"])) or "tftp-object.bin"
        value = bytes(object_info["data"])
        kind = sniff_kind(value, filename)
        result["extracted"].append({
            "label": safe_label(f"tftp_{filename}"), "data": value, "kind": kind,
            "producer": "pcap-tftp-reassembly",
            "transformation": f"TFTP DATA block reassembly ({object_info['block_count']} block(s), complete={object_info['complete']})",
            "reason": "A bounded RRQ/WRQ transfer yielded a contiguous object.",
        })
        if _pcap_printable(value):
            add_text(value.decode("latin-1", "ignore"), "pcap-tftp-object", None, 10, ["TFTP DATA block reassembly"])
        direct_flag_hits.update(_pcap_flag_values(value))

    # Header/field covert channels. Only promote byte streams when a flag or a
    # recognized file signature validates the candidate, preventing constant
    # TTL/IP-ID values from becoming noisy artifacts.
    field_recoveries = 0
    field_groups: defaultdict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for packet in records:
        if packet.get("source") is not None and packet.get("destination") is not None:
            field_groups[(packet.get("source"), packet.get("destination"), packet.get("protocol"))].append(packet)
    for group, packets in field_groups.items():
        ordered = sorted(packets, key=_pcap_timestamp_key)
        if len(ordered) < 4:
            continue
        fields = {
            "ttl": bytes(int(item["ttl"]) & 0xFF for item in ordered if isinstance(item.get("ttl"), int)),
            "ip-id-low": bytes(int(item["ip_id"]) & 0xFF for item in ordered if isinstance(item.get("ip_id"), int)),
            "icmp-id-low": bytes(int(item["icmp_id"]) & 0xFF for item in ordered if isinstance(item.get("icmp_id"), int)),
            "icmp-sequence-low": bytes(int(item["icmp_sequence"]) & 0xFF for item in ordered if isinstance(item.get("icmp_sequence"), int)),
            "tcp-ack-low": bytes(int(item["acknowledgement"]) & 0xFF for item in ordered if isinstance(item.get("acknowledgement"), int)),
        }
        acknowledgements = [int(item["acknowledgement"]) for item in ordered if isinstance(item.get("acknowledgement"), int)]
        if len(acknowledgements) >= 2:
            fields["tcp-ack-delta"] = bytes((current - previous) & 0xFF for previous, current in zip(acknowledgements, acknowledgements[1:]))
        for name, value in fields.items():
            if len(value) < 4:
                continue
            for delta in (0, 1, 42, 64, 65, 128, 255):
                candidate = bytes((item - delta) & 0xFF for item in value)
                if register_candidate(candidate, f"pcap-field-{name}", None, f"{name} byte stream minus {delta}"):
                    field_recoveries += 1

    # IMSI/XOR HTTP uploads from the rogue-cell challenge remain a first-class
    # correlation because the key is not inferable from a generic decoder.
    post_groups: defaultdict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for message in http_messages:
        body = bytes(message.get("body") or b"")
        user_agent = message.get("headers", {}).get("user-agent", "")
        imsi_match = _PCAP_IMSI_RE.search(user_agent.encode("latin-1", "ignore"))
        cell_match = _PCAP_CELL_RE.search(user_agent.encode("latin-1", "ignore"))
        if imsi_match:
            imsis.add(imsi_match.group(1).decode("ascii"))
        cell = cell_match.group(1).decode("ascii") if cell_match else ""
        if message.get("method") == "POST" and body and re.fullmatch(rb"[A-Za-z0-9+/=_-]+", body.strip()):
            post_groups[(str(message.get("destination")), str(message.get("target")), cell)].append({**message, "body": body.strip(), "cell": cell})
    xor_recoveries: list[dict[str, Any]] = []
    for (destination, target, cell), parts in post_groups.items():
        if len(parts) < 2:
            continue
        joined = b"".join(part["body"] for part in sorted(parts, key=lambda part: int(part.get("packet", 0))))
        if len(joined) < 16:
            continue
        try:
            ciphertext = base64.b64decode(joined + b"=" * (-len(joined) % 4), validate=True)
        except (ValueError, binascii.Error):
            continue
        for recovery in _pcap_xor_recover(ciphertext, sorted(imsis)):
            recovery.update({"destination": destination, "target": target, "cell": cell, "chunk_count": len(parts), "encoded_length": len(joined)})
            xor_recoveries.append(recovery)
            direct_flag_hits.add(str(recovery["flag"]))
            result["extracted"].append({"label": "pcap_xor_recovered_flag", "data": recovery["data"], "kind": "text", "producer": "pcap-network-forensics", "transformation": f"concatenate {len(parts)} HTTP POST bodies, Base64 decode, repeating XOR with IMSI-derived key {recovery['key']}", "reason": "Known CTF flag prefix proved the repeating-key recovery."})
            add_text(recovery["data"].decode("latin-1", "ignore"), "pcap-xor-recovery", None, 12, ["HTTP POST body concatenation", "Base64 decode", f"XOR key {recovery['key']}"])

    result["properties"].update({
        "network_payload_bytes": payload_bytes,
        "http_messages": len(http_messages), "http_post_groups": len(post_groups),
        "imsi_values": sorted(imsis), "unauthorized_cell_ids": sorted(unauthorized_cells),
        "xor_recoveries": len(xor_recoveries), "tcp_reassemblies": tcp_reassemblies,
        "tcp_overlap_events": tcp_overlap_bytes, "tcp_gap_spans": tcp_gap_spans,
        "ip_fragment_reassemblies": len(rebuilt_fragments), "incomplete_ip_fragment_sets": incomplete_fragments,
        "udp_source_port_recoveries": len(port_recoveries), "dns_queries_or_records": len(dns_entries),
        "dns_recoveries": dns_recoveries, "tftp_objects": len(tftp_objects),
        "field_stream_recoveries": field_recoveries, "decoded_stream_recoveries": decoded_recoveries,
    })
    if unauthorized_cells:
        result["findings"].append(_finding("warning", "network-identity", "Unauthorized test-network broadcast detected", "A broadcast advertises an unauthorized cellular network. HTTP device identifiers can be correlated with its cell ID.", cell_ids=sorted(unauthorized_cells)))
    if direct_flag_hits:
        result["findings"].append(_finding("info", "network-payload", "Flag-like text recovered from network payload", "A bounded packet, stream, DNS, covert-field, or decoded payload contains a CTF-style flag-shaped value.", flags=sorted(direct_flag_hits)))
    if xor_recoveries:
        result["findings"].append(_finding("info", "network-decoding", "IMSI-derived XOR exfiltration recovered", "HTTP POST fragments were concatenated, Base64-decoded, and decrypted with a repeating decimal key derived from an IMSI.", recoveries=[{key: value for key, value in recovery.items() if key != "data"} for recovery in xor_recoveries]))
    if port_recoveries:
        result["findings"].append(_finding("info", "network-covert-channel", "UDP source-port covert channel recovered", "Printable characters encoded as UDP source-port offsets were recovered between stream markers.", flags=sorted(set(port_recoveries))))
    if tftp_objects:
        result["findings"].append(_finding("info", "network-object", "TFTP object reconstructed", "RRQ/WRQ and DATA blocks were reassembled into child artifacts for recursive analysis.", objects=[{key: value for key, value in item.items() if key != "data"} for item in tftp_objects]))
    if dns_recoveries:
        result["findings"].append(_finding("info", "network-decoding", "DNS exfiltration candidate recovered", "DNS labels or TXT answers were deduplicated, ordered, and tested through bounded Base64/Base32/hex/decompression transforms."))
    return result


def parse_pcap(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Parse classic PCAP records and run the shared bounded CTF recovery pass."""

    result = _result("pcap")
    if len(data) < 24:
        result["findings"].append(_finding("error", "structure", "Truncated PCAP header", "A classic PCAP global header requires 24 bytes."))
        return result
    magics = {
        b"\xd4\xc3\xb2\xa1": ("little", "microseconds"),
        b"\xa1\xb2\xc3\xd4": ("big", "microseconds"),
        b"\x4d\x3c\xb2\xa1": ("little", "nanoseconds"),
        b"\xa1\xb2\x3c\x4d": ("big", "nanoseconds"),
    }
    if data[:4] not in magics:
        result["findings"].append(_finding("error", "structure", "Invalid PCAP magic", "The classic capture global header does not contain a recognized byte-order marker."))
        return result
    byte_order, timestamp_resolution = magics[data[:4]]
    endian = "<" if byte_order == "little" else ">"
    try:
        major, minor, _zone, _sigfigs, snaplen, linktype = struct.unpack_from(f"{endian}HHiIII", data, 4)
    except struct.error:
        result["findings"].append(_finding("error", "structure", "Invalid PCAP global header", "The classic capture header could not be unpacked safely."))
        return result
    result["properties"].update({"version": f"{major}.{minor}", "byte_order": byte_order, "timestamp_resolution": timestamp_resolution, "snaplen": snaplen, "link_type": linktype})
    offset = 24
    packet_count = 0
    captured_bytes = 0
    malformed = False
    limit = 250_000 if profile == "deep" else 50_000
    records: list[dict[str, Any]] = []
    while offset + 16 <= len(data) and packet_count < limit:
        record_offset = offset
        sec, subsec, included, original = struct.unpack_from(f"{endian}IIII", data, offset)
        if included > max(snaplen, 16 * 1024 * 1024) or included > original or offset + 16 + included > len(data):
            malformed = True
            break
        frame_offset = offset + 16
        frame = data[frame_offset:frame_offset + included]
        packet = _pcap_packet_network(frame, linktype)
        if packet is None:
            payload_offset, frame_payload = _pcap_frame_payload(frame, linktype)
            packet = {"source": None, "destination": None, "protocol": None, "source_port": None, "destination_port": None, "sequence": None, "payload": frame_payload, "payload_offset": payload_offset, "network": False}
        else:
            packet["network"] = True
        packet.update({"number": packet_count + 1, "record_offset": record_offset, "frame_offset": frame_offset, "timestamp_key": (sec, subsec), "timestamp_resolution": timestamp_resolution, "frame_length": included})
        records.append(packet)
        captured_bytes += included
        packet_count += 1
        offset += 16 + included
    network_records = [item for item in records if item.get("network")]
    network_flows = {(item.get("source"), item.get("source_port"), item.get("destination"), item.get("destination_port"), item.get("protocol")) for item in network_records if item.get("source") is not None and item.get("payload")}
    result["properties"].update({
        "packet_records_scanned": packet_count, "captured_payload_bytes": captured_bytes,
        "record_scan_truncated": packet_count >= limit and offset < len(data), "network_packets": len(network_records),
        "ipv4_packets": sum(item.get("ip_version") == 4 for item in network_records), "ipv6_packets": sum(item.get("ip_version") == 6 for item in network_records),
        "transport_protocols": dict(Counter(str(item.get("protocol")) for item in network_records if item.get("protocol") is not None)),
        "tcp_packets": sum(item.get("protocol") == 6 for item in network_records), "udp_packets": sum(item.get("protocol") == 17 for item in network_records),
        "icmp_packets": sum(item.get("protocol") in {1, 58} for item in network_records), "network_flows": len(network_flows),
    })
    if malformed:
        result["findings"].append(_finding("warning", "structure", "Malformed or truncated PCAP record", "Packet iteration stopped at an impossible captured-length boundary.", offset=offset))
    return _analyze_capture_records(result, records, profile)


def parse_pcapng(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Parse PCAPNG sections/interfaces/packet blocks and run capture recovery."""

    result = _result("pcapng")
    if len(data) < 28 or data[:4] != b"\x0a\x0d\x0d\x0a":
        result["findings"].append(_finding("error", "structure", "Invalid PCAPNG section header", "The PCAPNG section-header block is missing or truncated."))
        return result
    offset = 0
    blocks = 0
    enhanced_packets = 0
    simple_packets = 0
    packet_blocks = 0
    interfaces_seen = 0
    malformed = False
    limit = 250_000 if profile == "deep" else 50_000
    endian = "<"
    byte_order = "little"
    interfaces: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    comments: list[tuple[str, int]] = []
    secrets: list[bytes] = []

    def options(raw: bytes, start: int, end: int) -> tuple[dict[int, list[bytes]], list[str]]:
        parsed: defaultdict[int, list[bytes]] = defaultdict(list)
        comment_values: list[str] = []
        cursor = start
        while cursor + 4 <= end:
            code, length = struct.unpack_from(f"{endian}HH", raw, cursor)
            cursor += 4
            if code == 0:
                break
            if cursor + length > end:
                break
            value = raw[cursor:cursor + length]
            parsed[code].append(value)
            if code == 1:
                comment_values.append(value.decode("utf-8", "replace"))
            cursor += (length + 3) & ~3
        return parsed, comment_values

    def timestamp_ns(raw_value: int, interface: dict[str, Any]) -> int:
        resolution = int(interface.get("tsresol", 6))
        if resolution & 0x80:
            denominator = 1 << (resolution & 0x7F)
            value = raw_value * 1_000_000_000 // denominator
        elif resolution <= 9:
            value = raw_value * (10 ** (9 - resolution))
        else:
            value = raw_value // (10 ** (resolution - 9))
        return value + int(interface.get("tsoffset", 0)) * 1_000_000_000

    while offset + 12 <= len(data) and blocks < limit:
        if data[offset:offset + 4] == b"\x0a\x0d\x0d\x0a":
            if offset + 12 > len(data):
                malformed = True
                break
            bom = data[offset + 8:offset + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian, byte_order = "<", "little"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian, byte_order = ">", "big"
            else:
                malformed = True
                break
            if offset + 28 > len(data):
                malformed = True
                break
            block_length = struct.unpack_from(f"{endian}I", data, offset + 4)[0]
            interfaces = []
        else:
            block_type, block_length = struct.unpack_from(f"{endian}II", data, offset)
        if block_length < 12 or block_length % 4 or offset + block_length > len(data):
            malformed = True
            break
        trailing = struct.unpack_from(f"{endian}I", data, offset + block_length - 4)[0]
        if trailing != block_length:
            malformed = True
            break
        block_type = struct.unpack_from(f"{endian}I", data, offset)[0]
        body_start = offset + 8
        body_end = offset + block_length - 4
        block_comments: list[str] = []
        if block_type == 0x0A0D0D0A:
            # Section Header Block: the first 16 bytes are fixed. Any options
            # after the 64-bit section length are retained as clue text.
            if body_end >= body_start + 16:
                _parsed, block_comments = options(data, body_start + 16, body_end)
        elif block_type == 1:  # Interface Description Block
            if body_end < body_start + 8:
                malformed = True
                break
            linktype = struct.unpack_from(f"{endian}H", data, body_start)[0]
            snaplen = struct.unpack_from(f"{endian}I", data, body_start + 4)[0]
            parsed, block_comments = options(data, body_start + 8, body_end)
            tsresol = parsed.get(9, [b"\x06"])[0][0] if parsed.get(9) and parsed[9][0] else 6
            tsoffset = int.from_bytes(parsed.get(14, [b"\x00" * 8])[0][:8], byteorder="little" if endian == "<" else "big", signed=True) if parsed.get(14) else 0
            interfaces.append({"linktype": linktype, "snaplen": snaplen, "tsresol": tsresol, "tsoffset": tsoffset})
            interfaces_seen += 1
        elif block_type == 6:  # Enhanced Packet Block
            enhanced_packets += 1
            if body_end < body_start + 20:
                malformed = True
                break
            interface_id, ts_high, ts_low, captured, original = struct.unpack_from(f"{endian}IIIII", data, body_start)
            packet_start = body_start + 20
            packet_end = min(body_end, packet_start + captured)
            interface = interfaces[interface_id] if interface_id < len(interfaces) else {"linktype": 1, "tsresol": 6, "tsoffset": 0}
            frame = data[packet_start:packet_end]
            packet = _pcap_packet_network(frame, int(interface.get("linktype", 1)))
            if packet is None:
                payload_offset, frame_payload = _pcap_frame_payload(frame, int(interface.get("linktype", 1)))
                packet = {"source": None, "destination": None, "protocol": None, "source_port": None, "destination_port": None, "sequence": None, "payload": frame_payload, "payload_offset": payload_offset, "network": False}
            else:
                packet["network"] = True
            timestamp_value = timestamp_ns((ts_high << 32) | ts_low, interface)
            packet.update({"number": len(records) + 1, "record_offset": offset, "frame_offset": packet_start, "timestamp_ns": timestamp_value, "timestamp_key": (timestamp_value // 1_000_000_000, timestamp_value % 1_000_000_000), "interface_id": interface_id, "linktype": interface.get("linktype"), "frame_length": len(frame)})
            records.append(packet)
            _parsed, block_comments = options(data, packet_start + ((captured + 3) & ~3), body_end)
        elif block_type == 3:  # Simple Packet Block
            simple_packets += 1
            if body_end >= body_start + 4 and interfaces:
                original = struct.unpack_from(f"{endian}I", data, body_start)[0]
                packet_start = body_start + 4
                frame = data[packet_start:min(body_end, packet_start + original)]
                interface = interfaces[0]
                packet = _pcap_packet_network(frame, int(interface.get("linktype", 1)))
                if packet is None:
                    payload_offset, frame_payload = _pcap_frame_payload(frame, int(interface.get("linktype", 1)))
                    packet = {"source": None, "destination": None, "protocol": None, "source_port": None, "destination_port": None, "sequence": None, "payload": frame_payload, "payload_offset": payload_offset, "network": False}
                else:
                    packet["network"] = True
                packet.update({"number": len(records) + 1, "record_offset": offset, "frame_offset": packet_start, "timestamp_key": (len(records), 0), "interface_id": 0, "linktype": interface.get("linktype"), "frame_length": len(frame)})
                records.append(packet)
        elif block_type == 2:  # Obsolete Packet Block
            packet_blocks += 1
            if body_end >= body_start + 20 and interfaces:
                interface_id = struct.unpack_from(f"{endian}H", data, body_start)[0]
                ts_high, ts_low, captured, original = struct.unpack_from(f"{endian}IIII", data, body_start + 4)
                packet_start = body_start + 20
                frame = data[packet_start:min(body_end, packet_start + captured)]
                interface = interfaces[interface_id] if interface_id < len(interfaces) else interfaces[0]
                packet = _pcap_packet_network(frame, int(interface.get("linktype", 1)))
                if packet is None:
                    payload_offset, frame_payload = _pcap_frame_payload(frame, int(interface.get("linktype", 1)))
                    packet = {"source": None, "destination": None, "protocol": None, "source_port": None, "destination_port": None, "sequence": None, "payload": frame_payload, "payload_offset": payload_offset, "network": False}
                else:
                    packet["network"] = True
                timestamp_value = timestamp_ns((ts_high << 32) | ts_low, interface)
                packet.update({"number": len(records) + 1, "record_offset": offset, "frame_offset": packet_start, "timestamp_ns": timestamp_value, "timestamp_key": (timestamp_value // 1_000_000_000, timestamp_value % 1_000_000_000), "interface_id": interface_id, "linktype": interface.get("linktype"), "frame_length": len(frame)})
                records.append(packet)
        elif block_type == 0x0000000A:  # Decryption Secrets Block
            if body_end >= body_start + 8:
                secret_length = struct.unpack_from(f"{endian}I", data, body_start + 4)[0]
                secret = data[body_start + 8:min(body_end, body_start + 8 + secret_length)]
                if secret:
                    secrets.append(secret)
                    block_comments.append(secret.decode("utf-8", "replace"))
        elif block_type in {0x00000BAD, 0x40000BAD}:  # custom data blocks
            custom = data[body_start:body_end]
            if custom:
                block_comments.append(custom[:4096].decode("utf-8", "replace"))
        if block_comments:
            comments.extend((comment, offset) for comment in block_comments if comment)
        blocks += 1
        offset += block_length

    result["properties"].update({
        "byte_order": byte_order, "blocks_scanned": blocks, "interfaces": interfaces_seen,
        "enhanced_packet_blocks": enhanced_packets, "simple_packet_blocks": simple_packets,
        "packet_blocks": packet_blocks, "packet_records_scanned": len(records),
        "captured_payload_bytes": sum(int(item.get("frame_length", 0)) for item in records),
        "block_scan_truncated": blocks >= limit and offset < len(data),
        "network_packets": sum(bool(item.get("network")) for item in records),
        "ipv4_packets": sum(item.get("ip_version") == 4 for item in records),
        "ipv6_packets": sum(item.get("ip_version") == 6 for item in records),
        "tcp_packets": sum(item.get("protocol") == 6 for item in records),
        "udp_packets": sum(item.get("protocol") == 17 for item in records),
        "icmp_packets": sum(item.get("protocol") in {1, 58} for item in records),
        "transport_protocols": dict(Counter(str(item.get("protocol")) for item in records if item.get("protocol") is not None)),
        "network_flows": len({(item.get("source"), item.get("source_port"), item.get("destination"), item.get("destination_port"), item.get("protocol")) for item in records if item.get("network") and item.get("payload")}),
        "decryption_secret_blocks": len(secrets),
    })
    for comment, comment_offset in comments:
        result["text_records"].append({"source": "pcapng-comment-or-secret", "offset": comment_offset, "text": comment, "confidence_hint": 9})
    for secret in secrets:
        result["extracted"].append({"label": "pcapng_decryption_secrets", "data": secret, "kind": "text", "producer": "pcapng-dsb", "transformation": "Extract Decryption Secrets Block payload", "reason": "PCAPNG stores TLS/other protocol secrets in a dedicated block."})
    if malformed:
        result["findings"].append(_finding("warning", "structure", "Malformed PCAPNG block", "Block length or mirrored trailer validation failed; packet iteration stopped safely.", offset=offset))
    analyzed = _analyze_capture_records(result, records, profile)
    secret_flags: set[str] = set()
    for secret in secrets:
        secret_flags.update(_pcap_flag_values(secret))
    if secret_flags:
        analyzed["findings"].append(_finding("info", "network-payload", "Flag-like text recovered from PCAPNG secrets", "A bounded Decryption Secrets Block contains a CTF-style flag-shaped value.", flags=sorted(secret_flags)))
    return analyzed


def parse_sqlite(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Inspect SQLite's fixed header and promote bounded schema-like strings."""

    result = _result("sqlite")
    if len(data) < 100 or not data.startswith(b"SQLite format 3\x00"):
        result["findings"].append(_finding("error", "structure", "Invalid SQLite header", "The 100-byte SQLite database header is missing or truncated."))
        return result
    page_size = int.from_bytes(data[16:18], "big") or 65536
    result["properties"].update({
        "page_size": page_size,
        "write_version": data[18], "read_version": data[19],
        "reserved_bytes_per_page": data[20],
        "schema_cookie": int.from_bytes(data[40:44], "big"),
        "schema_format": int.from_bytes(data[44:48], "big"),
        "text_encoding": int.from_bytes(data[56:60], "big"),
        "declared_pages": int.from_bytes(data[28:32], "big"),
    })
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        result["findings"].append(_finding("warning", "structure", "Unusual SQLite page size", "The database header declares a non-standard page size.", page_size=page_size))
    scan_limit = min(len(data), 16 * 1024 * 1024 if profile == "deep" else 4 * 1024 * 1024)
    for record in iter_ascii_strings(data[:scan_limit], minimum=6, limit=2_000):
        lowered = record["text"].lower()
        if any(marker in lowered for marker in ("create table", "create index", "sqlite_", "flag{")):
            result["text_records"].append({**record, "source": "sqlite-raw-record", "confidence_hint": 8})
    result["findings"].append(_finding(
        "info", "database", "SQLite database detected",
        "Deep scans can use the optional read-only SQLite dump adapter to enumerate schema and rows without modifying the source.",
    ))
    return result


def parse_ole(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Parse the OLE Compound File header and surface stream-name strings."""

    result = _result("ole")
    if len(data) < 512 or not data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        result["findings"].append(_finding("error", "structure", "Invalid OLE compound file", "The 512-byte Compound File Binary header is missing or truncated."))
        return result
    byte_order = int.from_bytes(data[28:30], "little")
    sector_shift = int.from_bytes(data[30:32], "little")
    mini_sector_shift = int.from_bytes(data[32:34], "little")
    result["properties"].update({
        "major_version": int.from_bytes(data[26:28], "little"),
        "byte_order_marker": byte_order,
        "sector_size": 1 << sector_shift if sector_shift < 24 else None,
        "mini_sector_size": 1 << mini_sector_shift if mini_sector_shift < 24 else None,
        "fat_sector_count": int.from_bytes(data[44:48], "little"),
        "first_directory_sector": int.from_bytes(data[48:52], "little"),
    })
    if byte_order != 0xFFFE or sector_shift not in {9, 12}:
        result["findings"].append(_finding("warning", "structure", "Unusual OLE header geometry", "The byte-order or sector-size fields are not standard.", byte_order=byte_order, sector_shift=sector_shift))
    scan_limit = min(len(data), 16 * 1024 * 1024 if profile == "deep" else 4 * 1024 * 1024)
    interesting = ("vba", "macro", "encryptedpackage", "encryptioninfo", "ole10native", "objectpool", "powerpoint document", "worddocument")
    for record in iter_utf16_strings(data[:scan_limit], minimum=4, limit=3_000):
        if any(marker in record["text"].lower() for marker in interesting):
            result["text_records"].append({**record, "source": "ole-stream-name", "confidence_hint": 8})
    result["findings"].append(_finding(
        "info", "document", "OLE compound document detected",
        "Deep scans can run Oletools to identify macros, encryption, and embedded objects without opening the document in Office.",
    ))
    return result


def parse_rtf(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Recover bounded visible and hex-escaped text from RTF source."""

    result = _result("rtf")
    if not data.startswith(b"{\\rtf"):
        result["findings"].append(_finding("error", "structure", "Invalid RTF signature", "The document does not begin with an RTF control header."))
        return result
    scan = data[: min(len(data), 16 * 1024 * 1024 if profile == "deep" else 4 * 1024 * 1024)]
    raw = scan.decode("latin-1", "replace")
    decoded_hex = re.sub(
        r"\\'([0-9a-fA-F]{2})",
        lambda match: bytes([int(match.group(1), 16)]).decode("cp1252", "replace"),
        raw,
    )
    visible = re.sub(r"\\[A-Za-z]+-?\d* ?|[{}]", " ", decoded_hex)
    visible = re.sub(r"\s+", " ", visible).strip()
    if visible:
        result["text_records"].append({"encoding": "rtf-text", "offset": 0, "text": display_text(visible, 2_000_000), "source": "rtf-visible-text", "confidence_hint": 8})
    object_count = len(re.findall(br"\\object\b|\\objdata\b", scan, re.IGNORECASE))
    result["properties"]["object_markers"] = object_count
    if object_count:
        result["findings"].append(_finding("info", "embedded-data", "RTF object markers found", "The optional rtfobj adapter can decode and extract these embedded OLE objects.", count=object_count))
    return result


def parse_eml(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Parse RFC 5322/MIME mail and extract bounded attachments in memory."""

    result = _result("eml")
    message = BytesParser(policy=email.policy.default).parsebytes(data)
    for name in ("Subject", "From", "To", "Date", "Message-ID", "Reply-To"):
        value = message.get(name)
        if value is not None:
            rendered = display_text(value, 16_384)
            result["metadata"][name.lower().replace("-", "_")] = rendered
            result["text_records"].append({"encoding": "email-header", "offset": None, "text": rendered, "source": f"eml-header:{name}", "confidence_hint": 8})
    part_limit = 500
    byte_limit = 64 * 1024 * 1024 if profile == "deep" else 16 * 1024 * 1024
    total = 0
    parts = list(itertools.islice(message.walk(), part_limit))
    for index, part in enumerate(parts):
        if part.is_multipart():
            continue
        encoded_payload = part.get_payload(decode=False)
        if isinstance(encoded_payload, (str, bytes)) and len(encoded_payload) > byte_limit * 2:
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        content_type = part.get_content_type()
        filename = part.get_filename()
        if content_type.startswith("text/") and not filename:
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload[:2_000_000].decode(charset, "replace")
            except LookupError:
                text = payload[:2_000_000].decode("utf-8", "replace")
            result["text_records"].append({"encoding": charset, "offset": None, "text": text, "source": f"eml-body:{content_type}", "confidence_hint": 8})
            continue
        if not payload or len(payload) > byte_limit or total + len(payload) > byte_limit:
            continue
        label = safe_label(filename or f"mime_part_{index}")
        result["extracted"].append({
            "label": f"eml_{label}", "data": payload, "producer": "email-parser",
            "transformation": "decode MIME attachment without materializing its supplied path",
            "offset": None, "kind": sniff_kind(payload, filename or ""),
        })
        total += len(payload)
    result["properties"].update({"mime_parts_scanned": len(parts), "attachments_extracted": len(result["extracted"]), "multipart": message.is_multipart()})
    return result


def parse_disk(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Inspect raw MBR/GPT/filesystem signatures without mounting the image."""

    result = _result("disk")
    partitions: list[dict[str, int]] = []
    if len(data) >= 512 and data[510:512] == b"\x55\xaa":
        for index in range(4):
            entry = data[446 + index * 16:462 + index * 16]
            if len(entry) < 16 or entry[4] == 0:
                continue
            start = int.from_bytes(entry[8:12], "little")
            sectors = int.from_bytes(entry[12:16], "little")
            if start and sectors:
                partitions.append({"index": index, "type": entry[4], "start_lba": start, "sectors": sectors})
    result["properties"].update({
        "mbr_signature": len(data) >= 512 and data[510:512] == b"\x55\xaa",
        "gpt_signature": len(data) >= 520 and data[512:520] == b"EFI PART",
        "partitions": partitions,
        "filesystem_hint": (
            "ext" if len(data) >= 1082 and data[1080:1082] == b"\x53\xef" else
            "ntfs" if len(data) >= 11 and data[3:11] == b"NTFS    " else
            "iso9660" if len(data) >= 32774 and data[32769:32774] == b"CD001" else None
        ),
    })
    result["findings"].append(_finding(
        "info", "disk", "Raw disk or filesystem image detected",
        "Deep scans can enumerate partitions, list allocated/deleted names, and recover bounded files with Sleuth Kit without mounting the image.",
        partition_count=len(partitions),
    ))
    return result


def parse_ewf(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("ewf")
    result["properties"]["segment_signature_valid"] = data.startswith(b"EVF\x09\x0d\x0a\xff\x00")
    result["findings"].append(_finding("info", "disk", "Expert Witness image detected", "The optional ewfinfo adapter reads acquisition/media metadata without mounting or altering the evidence."))
    return result


def parse_registry(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("registry")
    if len(data) < 4096 or not data.startswith(b"regf"):
        result["findings"].append(_finding("error", "structure", "Invalid registry hive", "A Windows registry hive requires a complete base block."))
        return result
    result["properties"].update({
        "primary_sequence": int.from_bytes(data[4:8], "little"),
        "secondary_sequence": int.from_bytes(data[8:12], "little"),
        "root_cell_offset": int.from_bytes(data[36:40], "little"),
        "hive_bins_size": int.from_bytes(data[40:44], "little"),
        "checksum": int.from_bytes(data[508:512], "little"),
    })
    result["findings"].append(_finding("info", "registry", "Windows registry hive detected", "Deep scans can enumerate keys and values with the optional read-only reglookup adapter."))
    return result


def parse_memory(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("memory")
    result["properties"].update({"header_magic": data[:8].hex(), "bytes_available_to_built_in_scan": len(data)})
    result["findings"].append(_finding(
        "info", "memory", "Memory or crash dump detected",
        "Deep scans can run offline Volatility 3 triage; the built-in strings/carving pass remains useful when symbols are unavailable.",
    ))
    return result


def parse_shar(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Recover uuencoded members from a GNU shell archive without executing it."""

    result = _result("shar")
    match = re.search(br"(?m)^begin [0-7]{3} ([^\r\n]+)", data)
    if not match or b"#!/bin/sh" not in data[:512]:
        result["findings"].append(_finding("error", "structure", "Invalid shell archive", "The expected GNU shar header and uuencoded member marker were not found."))
        return result
    end = re.search(br"(?m)^end\s*$", data[match.end():])
    if not end:
        result["findings"].append(_finding("warning", "structure", "Truncated uuencoded member", "A shar member begins correctly but has no terminating uuencode end marker."))
        return result
    encoded = data[match.start():match.end() + end.start()]
    decoded = bytearray()
    for line_number, line in enumerate(encoded.splitlines()[1:], 1):
        if line.strip() == b"end":
            break
        if line.startswith(b"X"):
            line = line[1:]
        if not line:
            continue
        try:
            decoded.extend(binascii.a2b_uu(line))
        except (binascii.Error, ValueError):
            result["findings"].append(_finding("warning", "structure", "Malformed uuencoded line", "A uuencode line was skipped safely while recovering the shell archive member.", line_number=line_number))
    if not decoded:
        result["findings"].append(_finding("error", "structure", "Empty shell archive member", "The uuencoded member did not yield any bytes."))
        return result
    name = match.group(1).decode("latin-1", "replace")
    payload = bytes(decoded)
    result["properties"].update({"member_name": name, "decoded_size": len(payload), "uuencode_offset": match.start()})
    result["findings"].append(_finding("info", "archive", "GNU shell archive member recovered", "The embedded uuencoded payload was decoded as data; no shell commands were run."))
    result["extracted"].append({
        "label": f"shar_{safe_label(name)}", "data": payload, "producer": "shar-parser",
        "transformation": "decode uuencoded member from GNU shell archive", "offset": match.start(),
        "kind": sniff_kind(payload, name),
    })
    return result


def parse_ar(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Parse bounded Unix ar members and expose nested compression signatures."""

    result = _result("ar")
    if not data.startswith(b"!<arch>\n"):
        result["findings"].append(_finding("error", "structure", "Invalid ar archive", "A Unix ar archive requires the !<arch> global magic."))
        return result
    cursor = 8
    members = 0
    limit = 250_000 if profile == "deep" else 50_000
    nested_signatures = (
        (b"BZh", "bzip2"), (b"\x1f\x8b", "gzip"), (b"LZIP\x01", "lzip"),
        (b"\x04\x22\x4d\x18", "lz4"), (b"\xfd7zXZ\x00", "xz"),
        (b"\x89LZO\x00\r\n\x1a\n", "lzop"), (b"PK\x03\x04", "zip"),
    )
    while cursor + 60 <= len(data) and members < limit:
        header = data[cursor:cursor + 60]
        if header[58:60] != b"`\n":
            result["findings"].append(_finding("warning", "structure", "Malformed ar member header", "Member iteration stopped at an invalid fixed-width ar header.", offset=cursor))
            break
        raw_name = header[:16].decode("latin-1", "replace").strip()
        size_text = header[48:58].decode("ascii", "ignore").strip()
        if not size_text.isdigit():
            result["findings"].append(_finding("warning", "structure", "Invalid ar member size", "A member declared a non-numeric byte count.", offset=cursor))
            break
        size = int(size_text)
        payload_start = cursor + 60
        payload_end = payload_start + size
        if payload_end > len(data):
            result["findings"].append(_finding("warning", "structure", "Truncated ar member", "A member extends beyond the available archive bytes.", offset=payload_start, size=size))
            break
        payload = data[payload_start:payload_end]
        member_name = raw_name.rstrip("/") or f"member_{members}"
        result["extracted"].append({
            "label": f"ar_{safe_label(member_name)}", "data": payload, "producer": "ar-parser",
            "transformation": f"extract ar member {member_name}", "offset": payload_start,
            "kind": sniff_kind(payload, member_name),
        })
        for signature, nested_kind in nested_signatures:
            nested_offset = payload.find(signature)
            if nested_offset <= 0:
                continue
            nested = payload[nested_offset:]
            result["extracted"].append({
                "label": f"ar_{safe_label(member_name)}_{nested_kind}", "data": nested,
                "producer": "ar-parser", "transformation": f"extract embedded {nested_kind} signature from ar member {member_name}",
                "offset": payload_start + nested_offset, "kind": nested_kind,
            })
            break
        result["text_records"].append({"source": "ar-member", "offset": cursor, "text": member_name, "confidence_hint": 3})
        members += 1
        cursor = payload_end + (size & 1)
    result["properties"].update({"member_count": members, "bytes_scanned": cursor})
    result["findings"].append(_finding("info", "archive", "Unix ar archive detected", "Fixed-width ar members were enumerated and nested compression signatures were exposed."))
    return result


def _parse_compressed_layer(kind: str, data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result(kind)
    decoder = DECODERS[kind]
    try:
        output = decoder(data, 16 * 1024 * 1024 if profile != "deep" else 64 * 1024 * 1024)
    except CompressionError as exc:
        result["findings"].append(_finding("warning", "compression", f"{kind.upper()} stream not expanded", "The bounded decoder rejected this stream or requires an optional native codec.", error=str(exc)))
        return result
    result["properties"].update({"input_size": len(data), "output_size": len(output)})
    result["findings"].append(_finding("info", "compression", f"{kind.upper()} stream decompressed", "The stream was expanded with a bounded standard-library-compatible decoder."))
    result["extracted"].append({
        "label": f"{kind}_decompressed", "data": output, "producer": f"{kind}-decoder",
        "transformation": f"decompress {kind.upper()} stream", "kind": sniff_kind(output),
    })
    return result


def parse_lzip(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    return _parse_compressed_layer("lzip", data, profile)


def parse_lz4(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    return _parse_compressed_layer("lz4", data, profile)


def parse_lzma(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    return _parse_compressed_layer("lzma", data, profile)


def parse_lzop(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    return _parse_compressed_layer("lzop", data, profile)


def parse_evtx(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("evtx")
    if len(data) < 4096 or not data.startswith(b"ElfFile\x00"):
        result["findings"].append(_finding("error", "structure", "Invalid EVTX header", "A Windows Event Log file requires a complete 4 KiB file header."))
        return result
    chunk_magic = b"ElfChnk\x00"
    chunk_offsets = [match.start() for match in re.finditer(re.escape(chunk_magic), data)]
    scan_limit = 50_000 if profile == "deep" else 30_000 if profile == "balanced" else 8_000
    utf16_records = list(iter_utf16_strings(data, minimum=4, limit=scan_limit))
    result["properties"].update({
        "oldest_chunk_number": int.from_bytes(data[8:16], "little"),
        "current_chunk_number": int.from_bytes(data[16:24], "little"),
        "next_record_identifier": int.from_bytes(data[24:32], "little"),
        "header_size": int.from_bytes(data[32:36], "little"),
        "chunk_count": int.from_bytes(data[42:44], "little"),
        "chunk_signatures_found": len(chunk_offsets),
        "utf16_strings_scanned": len(utf16_records),
    })
    # EVTX stores event XML and EventData strings as UTF-16LE templates.  Keep
    # a bounded selection of useful records and decode Base64 values found in
    # those records; this covers flags split across multiple event entries.
    base64_fragments: list[tuple[int, str, str]] = []
    # EventData strings are concatenated by the EVTX string table, so a
    # Base64 token can be adjacent to an ordinary word (for example
    # ``shutdown`` + ``dDAw...``).  Scan token-shaped runs without boundary
    # assertions and let strict Base64 validation discard the surrounding text.
    b64_pattern = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
    # Keep the reassembly filter deliberately simple: decoded Base64 event
    # fragments are short printable ASCII, and the final flag regex performs
    # the stricter validation.
    allowed_fragment = re.compile(r"^[\x20-\x7e]+$")
    for record in utf16_records:
        text = str(record.get("text", ""))
        interesting = (
            "<Event" in text or "EventID" in text or "UserData" in text or
            "powershell" in text.lower() or "cmd.exe" in text.lower() or
            "flag" in text.lower() or "ctf" in text.lower()
        )
        if interesting and len(result["text_records"]) < 5_000:
            result["text_records"].append({
                "source": "evtx-utf16", "offset": record.get("offset"), "text": text,
                "confidence_hint": 5,
            })
        for token_match in b64_pattern.finditer(text):
            raw_token = token_match.group(0)
            # A token may be glued to preceding EventData text.  Try the
            # maximal run first, then bounded suffixes so ``...shutdown`` +
            # ``dDAw...`` still yields the valid Base64 suffix.
            candidates = [(raw_token, 0)]
            if "=" in raw_token and len(raw_token) > 24:
                candidates.extend((raw_token[start:], start) for start in range(1, max(1, len(raw_token) - 15)))
            for token, token_offset in candidates:
                try:
                    decoded = base64.b64decode(token, validate=True).decode("utf-8")
                except (ValueError, UnicodeDecodeError, binascii.Error):
                    continue
                if not decoded or not allowed_fragment.fullmatch(decoded):
                    continue
                if any(char not in "\t\r\n" and not (32 <= ord(char) < 127) for char in decoded):
                    continue
                offset = int(record.get("offset") or 0) + token_match.start() + token_offset
                base64_fragments.append((offset, token, decoded))
                if ("{" in decoded or "}" in decoded or decoded.startswith(("picoCTF", "flag", "CTF"))) and len(result["text_records"]) < 5_000:
                    result["text_records"].append({
                        "source": "evtx-base64", "offset": offset, "text": decoded,
                        "confidence_hint": 10, "transform_chain": ["UTF-16LE event string", "Base64 decode"],
                    })
                # One valid suffix per run is enough; trying later suffixes
                # would only create duplicate or low-quality fragments.
                break
    base64_fragments.sort(key=lambda item: item[0])
    reassembled: list[str] = []
    for index, (offset, _token, decoded) in enumerate(base64_fragments):
        if not decoded.startswith(("picoCTF{", "flag{", "CTF{")):
            continue
        candidate = decoded
        for _next_offset, _next_token, next_decoded in base64_fragments[index + 1:]:
            if len(candidate) >= 280:
                break
            if not allowed_fragment.fullmatch(next_decoded):
                continue
            candidate += next_decoded
            if candidate.endswith("}"):
                reassembled.append(candidate)
                break
    for candidate in dict.fromkeys(reassembled):
        result["text_records"].append({
            "source": "evtx-base64-reassembly", "offset": None, "text": candidate,
            "confidence_hint": 14, "transform_chain": ["Base64 decode event fragments", "ordered reassembly"],
        })
    result["properties"]["base64_fragments_decoded"] = len(base64_fragments)
    result["properties"]["base64_flag_reassemblies"] = len(reassembled)
    result["findings"].append(_finding("info", "event-log", "Windows EVTX log detected", "UTF-16 event strings were scanned and Base64 fragments were decoded and reassembled in file order."))
    return result


def parse_pst(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("pst")
    if len(data) < 512 or not data.startswith(b"!BDN"):
        result["findings"].append(_finding("error", "structure", "Invalid PST/OST header", "The Outlook personal-store magic or fixed header is missing."))
        return result
    result["properties"].update({
        "client_magic": data[8:10].decode("latin-1", "replace"),
        "format_version": int.from_bytes(data[10:12], "little"),
        "client_version": int.from_bytes(data[12:14], "little"),
        "platform_create": data[14], "platform_access": data[15],
    })
    result["findings"].append(_finding("info", "email", "Outlook PST/OST store detected", "Deep scans can list mailboxes and convert messages, attachments, and deleted items into recursively scanned artifacts with libpst."))
    return result


_PNG_RECOVERY_CHUNK_LIMIT = 64 * 1024 * 1024
_PNG_RECOVERY_ANCILLARY_LIMIT = 256


def _plausible_png_ihdr_payload(payload: bytes) -> bool:
    """Return whether a 13-byte PNG IHDR payload is structurally plausible."""

    if len(payload) != 13:
        return False
    try:
        width, height, bit_depth, color_type, compression, filtering, interlace = struct.unpack(">IIBBBBB", payload)
    except struct.error:
        return False
    if not (1 <= width <= 100_000 and 1 <= height <= 100_000):
        return False
    if width * height > 256_000_000:
        return False
    if bit_depth not in {1, 2, 4, 8, 16} or color_type not in {0, 2, 3, 4, 6}:
        return False
    return compression == 0 and filtering == 0 and interlace in {0, 1}


def _valid_png_ihdr(data: bytes) -> bool:
    """Return whether bytes at the canonical PNG IHDR location are plausible.

    This is deliberately stricter than looking for the ASCII string ``IHDR``:
    the dimensions, colour model, and following chunk boundary must all be
    reasonable before a repair candidate is offered.
    """

    if len(data) < 49 or data[12:16] != b"IHDR":
        return False
    if not _plausible_png_ihdr_payload(data[16:29]):
        return False
    next_type = data[37:41]
    if len(next_type) != 4 or not all(byte in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for byte in next_type):
        return False
    # The first chunk's CRC is at 29:33; the next chunk starts at 33.  A
    # complete next chunk gives us a strong anti-false-positive boundary.
    next_length = int.from_bytes(data[33:37], "big")
    return next_length <= 0x7FFFFFFF and 45 + next_length <= len(data)


def _png_crc(raw_type: bytes, payload: bytes) -> int:
    return binascii.crc32(raw_type + payload) & 0xFFFFFFFF


def _png_chunk_layout_at(data: bytes, offset: int, *, max_length: int = _PNG_RECOVERY_CHUNK_LIMIT) -> tuple[int, bytes, int] | None:
    """Read one bounded PNG chunk layout without trusting its CRC."""

    if offset < 0 or offset + 12 > len(data):
        return None
    length = int.from_bytes(data[offset:offset + 4], "big")
    raw_type = data[offset + 4:offset + 8]
    if length > max_length or offset + 12 + length > len(data):
        return None
    if len(raw_type) != 4 or not all(byte in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for byte in raw_type):
        return None
    payload_start = offset + 8
    payload_end = payload_start + length
    return payload_end + 4, raw_type, length


def _valid_png_chunk_at(data: bytes, offset: int, *, max_length: int = _PNG_RECOVERY_CHUNK_LIMIT) -> tuple[int, bytes, int] | None:
    """Validate one complete PNG chunk, including its CRC."""

    parsed = _png_chunk_layout_at(data, offset, max_length=max_length)
    if parsed is None:
        return None
    end, raw_type, length = parsed
    payload_start = offset + 8
    payload_end = payload_start + length
    stored_crc = int.from_bytes(data[payload_end:payload_end + 4], "big")
    return parsed if _png_crc(raw_type, data[payload_start:payload_end]) == stored_crc else None


def _unique_single_byte_crc_repair(raw_type: bytes, payload: bytes, stored_crc: int) -> tuple[int, int, int] | None:
    """Find a unique one-byte payload change proved by the stored CRC."""

    if len(payload) > _PNG_RECOVERY_ANCILLARY_LIMIT:
        return None
    candidate: tuple[int, int, int] | None = None
    mutable = bytearray(payload)
    for index, original in enumerate(mutable):
        for replacement in range(256):
            if replacement == original:
                continue
            mutable[index] = replacement
            if _png_crc(raw_type, bytes(mutable)) == stored_crc:
                if candidate is not None:
                    return None
                candidate = (index, original, replacement)
        mutable[index] = original
    return candidate


def _find_crc_proven_next_chunk(data: bytes, start: int) -> tuple[int, bytes, int] | None:
    """Locate a nearby valid IDAT/IEND boundary without scanning arbitrary payloads."""

    search_end = min(len(data), start + _PNG_RECOVERY_CHUNK_LIMIT + 12)
    candidates: list[tuple[int, bytes, int]] = []
    for marker in (b"IDAT", b"IEND"):
        position = data.find(marker, start + 12, search_end)
        while position >= 0:
            offset = position - 4
            parsed = _valid_png_chunk_at(data, offset)
            if parsed is not None and parsed[1] == marker and offset >= start + 12:
                candidates.append((offset, parsed[1], parsed[2]))
                break
            position = data.find(marker, position + 1, search_end)
    return min(candidates, key=lambda item: item[0]) if candidates else None


def _recover_corrupted_png_structure(data: bytes) -> dict[str, Any] | None:
    """Recover a PNG whose chunk boundaries are damaged but CRCs remain usable.

    The recovery is intentionally narrow: IHDR's CRC must prove the canonical
    type, ancillary edits are limited to a unique one-byte CRC repair, and a
    damaged image-data header must be bounded by a nearby CRC-valid chunk.
    """

    if len(data) < 45 or not _plausible_png_ihdr_payload(data[16:29]):
        return None
    if _png_crc(b"IHDR", data[16:29]) != int.from_bytes(data[29:33], "big"):
        return None

    fixed = bytearray(data)
    signature_repaired = fixed[:8] != b"\x89PNG\r\n\x1a\n"
    ihdr_type_repaired = fixed[12:16] != b"IHDR"
    ihdr_length_repaired = fixed[8:12] != b"\x00\x00\x00\r"
    if signature_repaired:
        fixed[:8] = b"\x89PNG\r\n\x1a\n"
    if ihdr_type_repaired:
        fixed[12:16] = b"IHDR"
    if ihdr_length_repaired:
        fixed[8:12] = b"\x00\x00\x00\r"

    cursor = 33
    recovered_gap = False
    ancillary_repairs: list[dict[str, Any]] = []
    inferred_chunks: list[dict[str, Any]] = []
    chunk_types: list[bytes] = [b"IHDR"]
    while cursor + 12 <= len(data):
        parsed = _png_chunk_layout_at(data, cursor)
        if parsed is not None:
            next_cursor, raw_type, length = parsed
            payload_start = cursor + 8
            payload_end = payload_start + length
            stored_crc = int.from_bytes(data[payload_end:payload_end + 4], "big")
            chunk_payload = data[payload_start:payload_end]
            if _png_crc(raw_type, chunk_payload) != stored_crc:
                # Only ancillary chunks are eligible for a byte-level repair;
                # critical data must be recovered from a stronger boundary.
                if not (raw_type[0] >= ord("a") and length <= _PNG_RECOVERY_ANCILLARY_LIMIT):
                    return None
                repair = _unique_single_byte_crc_repair(raw_type, chunk_payload, stored_crc)
                if repair is None:
                    return None
                relative, original, replacement = repair
                fixed[payload_start + relative] = replacement
                ancillary_repairs.append({
                    "chunk": raw_type.decode("ascii"),
                    "offset": payload_start + relative,
                    "from": f"{original:02x}",
                    "to": f"{replacement:02x}",
                })
            chunk_types.append(raw_type)
            cursor = next_cursor
            if raw_type == b"IEND":
                break
            continue

        if recovered_gap:
            return None
        data_start = cursor + 8
        if data_start + 2 > len(data):
            return None
        cmf, flg = data[data_start:data_start + 2]
        if (cmf & 0x0F) != 8 or (cmf << 8 | flg) % 31 != 0 or (flg & 0x20):
            return None
        next_chunk = _find_crc_proven_next_chunk(data, cursor)
        if next_chunk is None:
            return None
        next_offset, next_type, _ = next_chunk
        inferred_length = next_offset - cursor - 12
        if inferred_length < 2 or inferred_length > _PNG_RECOVERY_CHUNK_LIMIT:
            return None
        inferred_payload = data[data_start:data_start + inferred_length]
        stored_crc = int.from_bytes(data[data_start + inferred_length:data_start + inferred_length + 4], "big")
        if _png_crc(b"IDAT", inferred_payload) != stored_crc:
            return None
        fixed[cursor:cursor + 4] = inferred_length.to_bytes(4, "big")
        fixed[cursor + 4:cursor + 8] = b"IDAT"
        inferred_chunks.append({
            "offset": cursor,
            "type": "IDAT",
            "length": inferred_length,
            "next_chunk_offset": next_offset,
            "next_chunk_type": next_type.decode("ascii"),
        })
        chunk_types.append(b"IDAT")
        recovered_gap = True
        cursor = next_offset

    # Leave the existing simple signature/length repair path responsible for
    # that common case; this candidate is reserved for genuinely multi-stage
    # corruption (a damaged type, CRC-proven payload edit, or broken boundary).
    if not (ihdr_type_repaired or ancillary_repairs or inferred_chunks):
        return None
    if chunk_types.count(b"IHDR") != 1 or b"IDAT" not in chunk_types or b"IEND" not in chunk_types:
        return None

    repaired = bytes(fixed)
    validation = parse_png(repaired, profile="quick")
    properties = validation.get("properties", {})
    if properties.get("bad_crc_count") != 0 or not properties.get("iend_present"):
        return None
    if any(finding.get("severity") == "error" for finding in validation.get("findings", [])):
        return None
    changes: list[str] = []
    if signature_repaired:
        changes.append("restore PNG signature")
    if ihdr_type_repaired:
        changes.append("restore CRC-proven IHDR chunk type")
    if ihdr_length_repaired:
        changes.append("restore canonical IHDR length")
    if ancillary_repairs:
        changes.append(f"repair {len(ancillary_repairs)} ancillary chunk byte using its stored CRC")
    if inferred_chunks:
        changes.append("infer CRC-proven IDAT boundary from the following valid chunk")
    return {
        "label": "png_structure_recovered",
        "data": repaired,
        "kind": "png",
        "producer": "png-recovery",
        "transformation": "; ".join(changes),
        "reason": "PNG dimensions and IHDR CRC prove the header; ancillary-byte CRC evidence and a bounded zlib stream plus the next CRC-valid chunk prove the repaired image-data boundary.",
        "details": {
            "signature_repaired": signature_repaired,
            "ihdr_type_repaired": ihdr_type_repaired,
            "ihdr_length_repaired": ihdr_length_repaired,
            "ancillary_byte_repairs": ancillary_repairs,
            "inferred_chunks": inferred_chunks,
        },
    }


def propose_header_repairs(data: bytes, *, profile: str = "balanced") -> list[dict[str, Any]]:
    """Propose conservative copy-only repairs for damaged media signatures.

    CTF corruption challenges commonly alter only the magic bytes or the
    first PNG chunk length.  These candidates are emitted only when internal
    format evidence proves the intended layout; no arbitrary byte guessing is
    performed.  The caller owns persistence, hashing, and re-validation.
    """

    if not isinstance(data, (bytes, bytearray)) or len(data) > 192 * 1024 * 1024:
        return []
    payload = bytes(data)
    candidates: list[dict[str, Any]] = []

    structural_png = _recover_corrupted_png_structure(payload)
    if structural_png is not None:
        candidates.append(structural_png)
    elif _valid_png_ihdr(payload):
        bad_signature = payload[:8] != b"\x89PNG\r\n\x1a\n"
        bad_length = payload[8:12] != b"\x00\x00\x00\r"
        if bad_signature or bad_length:
            fixed = bytearray(payload)
            changes: list[str] = []
            if bad_signature:
                fixed[:8] = b"\x89PNG\r\n\x1a\n"
                changes.append("restore PNG signature")
            if bad_length:
                fixed[8:12] = b"\x00\x00\x00\r"
                changes.append("restore canonical IHDR length")
            computed_crc = binascii.crc32(b"IHDR" + bytes(fixed[16:29])) & 0xFFFFFFFF
            if bytes(fixed[29:33]) != computed_crc.to_bytes(4, "big"):
                fixed[29:33] = computed_crc.to_bytes(4, "big")
                changes.append("recompute IHDR CRC-32")
            candidates.append({
                "label": "png_header_recovered",
                "data": bytes(fixed),
                "kind": "png",
                "producer": "png-recovery",
                "transformation": "; ".join(changes),
                "reason": "The IHDR marker, dimensions, colour model, and following chunk boundary prove a PNG layout despite damaged header bytes.",
                "details": {"signature_repaired": bad_signature, "ihdr_length_repaired": bad_length},
            })

    # JPEG SOI corruption is often visible as a literal ``\\x`` prefix or two
    # arbitrary bytes immediately before a valid APP0/APP1 JFIF/Exif segment.
    if len(payload) >= 20 and payload[:2] != b"\xff\xd8" and payload[2:3] == b"\xff" and 0xE0 <= payload[3] <= 0xEF:
        declared = int.from_bytes(payload[4:6], "big")
        app_payload_end = 6 + max(0, declared - 2)
        marker_text = payload[6:12]
        known_app = (payload[3] == 0xE0 and payload[6:11] == b"JFIF\x00") or (payload[3] == 0xE1 and marker_text == b"Exif\x00\x00")
        next_marker = payload[app_payload_end:app_payload_end + 2]
        if 8 <= declared <= 0xFFFF and app_payload_end <= len(payload) and known_app and next_marker[:1] == b"\xff":
            fixed = bytearray(payload)
            fixed[:2] = b"\xff\xd8"
            candidates.append({
                "label": "jpeg_soi_recovered",
                "data": bytes(fixed),
                "kind": "jpeg",
                "producer": "jpeg-recovery",
                "transformation": "restore JPEG start-of-image marker (FF D8)",
                "reason": "A valid JFIF/Exif APP segment and following JPEG marker prove the two missing SOI bytes.",
                "details": {"app_marker": f"FF{payload[3]:02X}", "declared_segment_length": declared},
            })

    # BZip2's first four bytes are a tiny, independently checkable header:
    # ``BZh`` followed by a block-size digit.  Some corruption challenges
    # change one of these bytes while leaving the compressed stream intact.
    # Only emit a candidate when every valid header mutation yields the same
    # bounded, complete stream; arbitrary guesses are never persisted.
    if len(payload) >= 16 and not (payload[:3] == b"BZh" and payload[3] in b"123456789"):
        bzip_candidates: list[tuple[bytes, bytes]] = []
        for position in range(4):
            for replacement in range(256):
                if replacement == payload[position]:
                    continue
                fixed = bytearray(payload)
                fixed[position] = replacement
                if fixed[:3] != b"BZh" or fixed[3] not in b"123456789":
                    continue
                try:
                    decoder = bz2.BZ2Decompressor()
                    output = decoder.decompress(bytes(fixed), 8 * 1024 * 1024 + 1)
                    if len(output) <= 8 * 1024 * 1024 and decoder.eof:
                        bzip_candidates.append((bytes(fixed), bytes(output)))
                except (OSError, EOFError, ValueError):
                    continue
        output_groups: dict[bytes, list[bytes]] = {}
        for candidate, output in bzip_candidates:
            output_groups.setdefault(output, []).append(candidate)
        # The BZip2 block-size digit is a decoder hint; all 1–9 values can be
        # valid for a small stream.  Accept that bounded ambiguity only when
        # every valid header yields the exact same decompressed bytes.
        if len(output_groups) == 1 and output_groups:
            valid_headers = next(iter(output_groups.values()))
            repaired_bzip = max(valid_headers, key=lambda value: value[3])
            changed = next((index for index in range(4) if repaired_bzip[index] != payload[index]), None)
            candidates.append({
                "label": "bzip2_header_recovered",
                "data": repaired_bzip,
                "kind": "bzip2",
                "producer": "bzip2-recovery",
                "transformation": "repair one BZip2 header byte and validate complete decompression",
                "reason": "All bounded BZip2 header candidates produced the same complete stream; a canonical valid header was selected.",
                "details": {"changed_header_offset": changed, "block_size_digit": chr(repaired_bzip[3]), "valid_block_size_digits": sorted({chr(item[3]) for item in valid_headers})},
            })

    # BMP height corruption is a standard header-forensics pattern (for
    # example, picoCTF's tunn3l v1s10n).  Derive a height only when the pixel
    # array has an exact row-stride fit and the existing height is unusable.
    bmp_repair = _recover_bmp_dimensions(payload)
    if bmp_repair is not None:
        candidates.append(bmp_repair)
    return candidates


def _recover_bmp_dimensions(data: bytes) -> dict[str, Any] | None:
    if len(data) < 54 or data[:2] != b"BM":
        return None
    dib_size = int.from_bytes(data[14:18], "little")
    if dib_size < 40 or 14 + dib_size > len(data):
        return None
    width = int.from_bytes(data[18:22], "little", signed=True)
    signed_height = int.from_bytes(data[22:26], "little", signed=True)
    planes = int.from_bytes(data[26:28], "little")
    bpp = int.from_bytes(data[28:30], "little")
    compression = int.from_bytes(data[30:34], "little")
    pixel_offset = int.from_bytes(data[10:14], "little")
    if width <= 0 or planes != 1 or bpp not in {1, 4, 8, 16, 24, 32}:
        return None
    if compression not in {0, 3, 6} or pixel_offset < 54 or pixel_offset >= len(data):
        return None
    row_stride = ((width * bpp + 31) // 32) * 4
    available = len(data) - pixel_offset
    if row_stride <= 0 or available <= 0 or available % row_stride:
        return None
    derived_height = available // row_stride
    if not 1 <= derived_height <= 100_000:
        return None
    expected = pixel_offset + row_stride * abs(signed_height) if signed_height else -1
    # Require a clearly unusable/discordant height, avoiding changes to valid
    # BMPs that merely carry a trailer for steganography.
    if signed_height and expected == len(data) and abs(signed_height) == derived_height:
        return None
    if signed_height and 0 < abs(signed_height) <= 100_000 and expected <= len(data):
        return None
    fixed = bytearray(data)
    fixed[22:26] = int(-derived_height if signed_height < 0 else derived_height).to_bytes(4, "little", signed=True)
    return {
        "label": "bmp_dimensions_recovered",
        "data": bytes(fixed),
        "kind": "bmp",
        "producer": "bmp-recovery",
        "transformation": "derive BMP height from exact pixel-array row stride",
        "reason": "Width, bit depth, pixel offset, and the complete pixel-array length prove a unique BMP height while the stored height is unusable.",
        "details": {"width": width, "old_height": signed_height, "derived_height": derived_height, "row_stride": row_stride},
    }


def _bounded_zlib(data: bytes, maximum: int = 2 * 1024 * 1024) -> bytes:
    decoder = zlib.decompressobj()
    output = decoder.decompress(data, maximum + 1)
    if len(output) > maximum or decoder.unconsumed_tail:
        raise ValueError("decompressed text chunk exceeds limit")
    output += decoder.flush(maximum + 1 - len(output))
    if len(output) > maximum:
        raise ValueError("decompressed text chunk exceeds limit")
    return output


def parse_png(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("png")
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        result["findings"].append(_finding("error", "structure", "Invalid PNG signature", "The expected eight-byte PNG signature is missing."))
        return result

    cursor = 8
    chunks: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    bad_crc_offsets: list[int] = []
    iend_end: int | None = None
    width = height = None
    bit_depth = color_type = interlace = None
    animated_frames = None
    sequence_errors = 0
    previous_sequence = -1
    safe_types = {"IHDR", "PLTE", "IDAT", "IEND", "tRNS", "gAMA", "cHRM", "sRGB", "iCCP", "pHYs", "sBIT", "bKGD", "hIST", "tIME", "eXIf", "acTL", "fcTL", "fdAT", "tEXt", "zTXt", "iTXt", "sPLT"}
    repaired = bytearray(data)

    while cursor + 12 <= len(data):
        chunk_offset = cursor
        length = int.from_bytes(data[cursor:cursor + 4], "big")
        raw_type = data[cursor + 4:cursor + 8]
        try:
            chunk_type = raw_type.decode("ascii")
        except UnicodeDecodeError:
            chunk_type = raw_type.hex()
        payload_start = cursor + 8
        payload_end = payload_start + length
        crc_end = payload_end + 4
        if length > 0x7FFFFFFF or crc_end > len(data):
            result["findings"].append(_finding(
                "error", "structure", "Truncated PNG chunk",
                f"Chunk {chunk_type!r} declares {length} bytes beyond the available input.",
                offset=chunk_offset, declared_length=length, available=max(0, len(data) - payload_start),
            ))
            break
        payload = data[payload_start:payload_end]
        stored_crc = int.from_bytes(data[payload_end:crc_end], "big")
        computed_crc = binascii.crc32(raw_type + payload) & 0xFFFFFFFF
        crc_ok = stored_crc == computed_crc
        if not crc_ok:
            bad_crc_offsets.append(payload_end)
            repaired[payload_end:crc_end] = computed_crc.to_bytes(4, "big")
        counts[chunk_type] = counts.get(chunk_type, 0) + 1
        chunks.append({
            "type": chunk_type, "offset": chunk_offset, "length": length,
            "crc_ok": crc_ok, "stored_crc": f"{stored_crc:08x}", "computed_crc": f"{computed_crc:08x}",
        })

        if chunk_type == "IHDR" and length == 13:
            width, height, bit_depth, color_type, compression, filtering, interlace = struct.unpack(">IIBBBBB", payload)
            result["properties"].update({
                "width": width, "height": height, "bit_depth": bit_depth,
                "color_type": color_type, "compression_method": compression,
                "filter_method": filtering, "interlace_method": interlace,
            })
        elif chunk_type == "acTL" and length == 8:
            animated_frames, plays = struct.unpack(">II", payload)
            result["properties"].update({"animation_frames_declared": animated_frames, "animation_plays": plays})
        elif chunk_type in {"fcTL", "fdAT"} and length >= 4:
            sequence = int.from_bytes(payload[:4], "big")
            if previous_sequence >= 0 and sequence != previous_sequence + 1:
                sequence_errors += 1
            previous_sequence = sequence
        elif chunk_type in {"tEXt", "zTXt", "iTXt"}:
            record = _png_text_record(chunk_type, payload, chunk_offset)
            result["text_records"].append(record)
            if record.get("keyword"):
                result["metadata"][f"png:{record['keyword']}"] = record.get("text", "")
        elif chunk_type == "eXIf":
            result["extracted"].append({
                "label": "png_exif_payload", "data": payload, "producer": "png-parser",
                "transformation": "extract eXIf chunk", "offset": payload_start, "kind": "binary",
            })
        elif chunk_type not in safe_types and length:
            is_ancillary = len(raw_type) == 4 and 97 <= raw_type[0] <= 122
            is_private = len(raw_type) == 4 and 97 <= raw_type[1] <= 122
            result["findings"].append(_finding(
                "info" if is_ancillary else "warning", "structure", "Unknown PNG chunk",
                f"Found {'ancillary' if is_ancillary else 'critical'} chunk {chunk_type!r}; custom chunks are common CTF hiding locations.",
                offset=chunk_offset, length=length, private=is_private,
            ))
            if length <= 16 * 1024 * 1024:
                result["extracted"].append({
                    "label": f"png_chunk_{chunk_type}", "data": payload,
                    "producer": "png-parser", "transformation": f"extract {chunk_type} chunk",
                    "offset": payload_start, "kind": sniff_kind(payload),
                })
        if chunk_type == "IEND":
            iend_end = crc_end
            cursor = crc_end
            break
        cursor = crc_end

    result["properties"].update({
        "chunk_count": len(chunks), "chunk_counts": counts, "chunks": chunks[:500],
        "bad_crc_count": len(bad_crc_offsets), "iend_present": iend_end is not None,
        "sequence_errors": sequence_errors,
    })
    if chunks and chunks[0]["type"] != "IHDR":
        result["findings"].append(_finding("error", "structure", "IHDR is not first", "A conforming PNG must begin its chunk stream with IHDR."))
    if counts.get("IHDR", 0) != 1:
        result["findings"].append(_finding("error", "structure", "Unexpected IHDR count", "PNG must contain exactly one IHDR chunk.", count=counts.get("IHDR", 0)))
    if bad_crc_offsets:
        result["findings"].append(_finding(
            "warning", "integrity", "PNG CRC mismatch",
            f"{len(bad_crc_offsets)} chunk CRC value(s) do not match their contents.", offsets=bad_crc_offsets[:50],
        ))
        if profile == "deep":
            result["repairs"].append({
                "label": "png_crc_repaired", "data": bytes(repaired), "producer": "png-parser",
                "transformation": "replace invalid chunk CRC fields with computed CRC-32 values",
                "reason": "One or more PNG chunk CRC fields were invalid; source bytes were preserved separately.",
            })
    if sequence_errors:
        result["findings"].append(_finding("warning", "integrity", "APNG sequence discontinuity", "APNG frame sequence numbers are not consecutive.", count=sequence_errors))
    if iend_end is not None and iend_end < len(data):
        trailer = data[iend_end:]
        result["findings"].append(_finding(
            "warning", "embedded-data", "Data follows PNG IEND",
            f"{len(trailer)} byte(s) occur after the terminal IEND chunk.", offset=iend_end,
            size=len(trailer), detected_kind=sniff_kind(trailer), entropy=round(byte_entropy(trailer), 4),
        ))
        result["extracted"].append({
            "label": "png_trailer", "data": trailer, "producer": "png-parser",
            "transformation": "extract bytes after IEND", "offset": iend_end, "kind": sniff_kind(trailer),
        })
    elif iend_end is None and cursor == len(data) and counts.get("IHDR") == 1:
        iend = b"\x00\x00\x00\x00IEND\xaeB`\x82"
        result["findings"].append(_finding("warning", "integrity", "PNG IEND is missing", "The parsed chunk stream ends without an IEND chunk."))
        result["repairs"].append({
            "label": "png_added_iend", "data": data + iend, "producer": "png-parser",
            "transformation": "append canonical empty IEND chunk", "reason": "The complete chunk stream lacked IEND.",
        })
    return result


def _png_text_record(chunk_type: str, payload: bytes, offset: int) -> dict[str, Any]:
    record: dict[str, Any] = {"source": chunk_type, "offset": offset, "keyword": "", "text": ""}
    try:
        if chunk_type == "tEXt":
            keyword, separator, text = payload.partition(b"\x00")
            record.update({"keyword": keyword.decode("latin-1", "replace"), "text": text.decode("latin-1", "replace"), "valid": bool(separator)})
        elif chunk_type == "zTXt":
            keyword, separator, rest = payload.partition(b"\x00")
            if not separator or len(rest) < 2 or rest[0] != 0:
                raise ValueError("invalid zTXt header")
            text = _bounded_zlib(rest[1:])
            record.update({"keyword": keyword.decode("latin-1", "replace"), "text": text.decode("latin-1", "replace"), "compressed": True, "valid": True})
        else:
            parts = payload.split(b"\x00", 5)
            if len(parts) != 6:
                raise ValueError("invalid iTXt header")
            keyword, compressed, method, language, translated, text = parts
            if compressed == b"\x01":
                if method != b"\x00":
                    raise ValueError("unsupported iTXt compression method")
                text = _bounded_zlib(text)
            record.update({
                "keyword": keyword.decode("latin-1", "replace"), "text": text.decode("utf-8", "replace"),
                "language": language.decode("ascii", "replace"), "translated_keyword": translated.decode("utf-8", "replace"),
                "compressed": compressed == b"\x01", "valid": True,
            })
    except Exception as exc:
        record.update({"valid": False, "error": f"{type(exc).__name__}: {display_text(exc, 200)}", "raw_preview": payload[:256].hex()})
    record["text"] = display_text(record.get("text", ""), 2_000_000)
    record["keyword"] = display_text(record.get("keyword", ""), 80)
    return record


def parse_jpeg(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("jpeg")
    if not data.startswith(b"\xff\xd8"):
        result["findings"].append(_finding("error", "structure", "Invalid JPEG SOI", "JPEG start-of-image marker is missing."))
        return result

    cursor = 2
    markers: list[dict[str, Any]] = [{"marker": "SOI", "code": "ffd8", "offset": 0, "length": 0}]
    comments: list[str] = []
    width = height = components = precision = None
    scan_offset: int | None = None
    malformed = False
    standalone = {0x01, *range(0xD0, 0xD8), 0xD8, 0xD9}

    while cursor < len(data):
        if data[cursor] != 0xFF:
            malformed = True
            break
        marker_start = cursor
        while cursor < len(data) and data[cursor] == 0xFF:
            cursor += 1
        if cursor >= len(data):
            break
        code = data[cursor]
        cursor += 1
        if code == 0x00:
            continue
        marker_name = _jpeg_marker_name(code)
        if code in standalone:
            markers.append({"marker": marker_name, "code": f"ff{code:02x}", "offset": marker_start, "length": 0})
            if code == 0xD9:
                break
            continue
        if cursor + 2 > len(data):
            malformed = True
            break
        declared = int.from_bytes(data[cursor:cursor + 2], "big")
        if declared < 2 or cursor + declared > len(data):
            result["findings"].append(_finding(
                "error", "structure", "Truncated JPEG segment",
                f"Marker {marker_name} has an invalid or truncated length.", offset=marker_start, declared_length=declared,
            ))
            malformed = True
            break
        payload_start = cursor + 2
        payload_end = cursor + declared
        payload = data[payload_start:payload_end]
        markers.append({"marker": marker_name, "code": f"ff{code:02x}", "offset": marker_start, "length": len(payload)})
        if code == 0xFE:
            comment = payload.decode("latin-1", "replace")
            comments.append(comment)
            result["text_records"].append({"source": "COM", "offset": payload_start, "text": comment})
        if code in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF} and len(payload) >= 6:
            precision = payload[0]
            height = int.from_bytes(payload[1:3], "big")
            width = int.from_bytes(payload[3:5], "big")
            components = payload[5]
        if 0xE0 <= code <= 0xEF:
            embedded = _embedded_images(payload)
            for index, (position, piece, embedded_kind) in enumerate(embedded, 1):
                result["extracted"].append({
                    "label": f"jpeg_{marker_name.lower()}_embedded_{index}", "data": piece,
                    "producer": "jpeg-parser", "transformation": f"carve {embedded_kind} from {marker_name}",
                    "offset": payload_start + position, "kind": embedded_kind,
                })
        cursor = payload_end
        if code == 0xDA:  # Entropy-coded scan: locate the first real EOI.
            scan_offset = cursor
            break

    eoi_offset = _find_jpeg_eoi(data, scan_offset or cursor)
    if eoi_offset is not None:
        markers.append({"marker": "EOI", "code": "ffd9", "offset": eoi_offset, "length": 0})
        trailer_start = eoi_offset + 2
        if trailer_start < len(data):
            trailer = data[trailer_start:]
            result["findings"].append(_finding(
                "warning", "embedded-data", "Data follows JPEG EOI",
                f"{len(trailer)} byte(s) occur after end-of-image.", offset=trailer_start,
                size=len(trailer), detected_kind=sniff_kind(trailer), entropy=round(byte_entropy(trailer), 4),
            ))
            result["extracted"].append({
                "label": "jpeg_trailer", "data": trailer, "producer": "jpeg-parser",
                "transformation": "extract bytes after EOI", "offset": trailer_start, "kind": sniff_kind(trailer),
            })
    else:
        result["findings"].append(_finding("warning", "integrity", "JPEG EOI is missing", "No end-of-image marker was found."))
        result["repairs"].append({
            "label": "jpeg_added_eoi", "data": data + b"\xff\xd9", "producer": "jpeg-parser",
            "transformation": "append JPEG EOI marker", "reason": "The source contains an SOI marker but no EOI marker.",
        })

    result["properties"].update({
        "width": width, "height": height, "precision": precision, "components": components,
        "progressive": any(marker["marker"] == "SOF2" for marker in markers),
        "marker_count": len(markers), "markers": markers[:500], "comment_count": len(comments),
        "eoi_present": eoi_offset is not None, "malformed_marker_stream": malformed,
    })
    result["metadata"].update({f"jpeg:comment:{index}": display_text(comment, 4096) for index, comment in enumerate(comments, 1)})
    if malformed:
        result["findings"].append(_finding("warning", "structure", "Unexpected JPEG marker data", "The header marker stream contains unexpected bytes or ends early."))
    # Multiple SOIs are valuable even when the embedded object does not have a neat APP boundary.
    extra_soi = []
    start = 2
    while True:
        offset = data.find(b"\xff\xd8\xff", start)
        if offset < 0:
            break
        extra_soi.append(offset)
        start = offset + 3
        if len(extra_soi) >= 20:
            break
    if extra_soi:
        result["findings"].append(_finding("info", "embedded-data", "Additional JPEG signatures", "Additional SOI signatures may indicate an MPO, thumbnail, or appended image.", offsets=extra_soi))
    return result


def _jpeg_marker_name(code: int) -> str:
    names = {0xD8: "SOI", 0xD9: "EOI", 0xDA: "SOS", 0xDB: "DQT", 0xC4: "DHT", 0xDD: "DRI", 0xFE: "COM", 0xDC: "DNL"}
    if 0xE0 <= code <= 0xEF:
        return f"APP{code - 0xE0}"
    if code in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
        return f"SOF{code - 0xC0}"
    if 0xD0 <= code <= 0xD7:
        return f"RST{code - 0xD0}"
    return names.get(code, f"MARKER_{code:02X}")


def _find_jpeg_eoi(data: bytes, start: int) -> int | None:
    # Within entropy data FF00 is escaped, while FFD0..D7 are restart markers.
    cursor = max(2, start)
    while cursor + 1 < len(data):
        offset = data.find(b"\xff", cursor)
        if offset < 0 or offset + 1 >= len(data):
            return None
        next_byte = data[offset + 1]
        if next_byte == 0xD9:
            return offset
        cursor = offset + 2
    return None


def _embedded_images(payload: bytes) -> list[tuple[int, bytes, str]]:
    results: list[tuple[int, bytes, str]] = []
    for signature, kind, terminator in ((b"\xff\xd8\xff", "jpeg", b"\xff\xd9"), (b"\x89PNG\r\n\x1a\n", "png", b"IEND")):
        offset = payload.find(signature)
        if offset < 0:
            continue
        if kind == "jpeg":
            end = payload.find(terminator, offset + 3)
            piece = payload[offset:end + 2] if end >= 0 else payload[offset:]
        else:
            iend = payload.find(b"IEND", offset + 8)
            piece = payload[offset:iend + 8] if iend >= 0 and iend + 8 <= len(payload) else payload[offset:]
        if len(piece) >= len(signature):
            results.append((offset, piece, kind))
    return results


_PDF_TEXT_KEYS = (b"Title", b"Author", b"Subject", b"Keywords", b"Creator", b"Producer")
_PDF_STREAM_LIMIT = 16 * 1024 * 1024


def _pdf_unescape_literal(raw: bytes) -> bytes:
    """Decode the small escape language used by PDF literal strings."""

    output = bytearray()
    index = 0
    simple = {ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12}
    while index < len(raw):
        value = raw[index]
        index += 1
        if value != 0x5C:  # backslash
            output.append(value)
            continue
        if index >= len(raw):
            break
        escaped = raw[index]
        index += 1
        if escaped in simple:
            output.append(simple[escaped])
        elif escaped in b"()\\":
            output.append(escaped)
        elif 0x30 <= escaped <= 0x37:
            digits = bytearray((escaped,))
            while index < len(raw) and len(digits) < 3 and raw[index] in b"01234567":
                digits.append(raw[index])
                index += 1
            output.append(int(digits, 8) & 0xFF)
        elif escaped in (10, 13):
            if escaped == 13 and index < len(raw) and raw[index] == 10:
                index += 1
        else:
            output.append(escaped)
    return bytes(output)


def _pdf_textual(value: bytes) -> str | None:
    if not value:
        return None
    text = value.decode("utf-8", "replace")
    printable = sum(1 for character in text if character in "\t\r\n" or 32 <= ord(character) <= 126 or ord(character) >= 160)
    if printable / max(1, len(text)) < 0.72:
        return None
    return display_text(text, 2_000_000)


def _pdf_literal_at(data: bytes, start: int) -> tuple[bytes, int] | None:
    if start >= len(data) or data[start] != 0x28:
        return None
    depth = 1
    index = start + 1
    raw = bytearray()
    while index < len(data) and len(raw) <= 2 * 1024 * 1024:
        value = data[index]
        index += 1
        if value == 0x5C:
            raw.append(value)
            if index < len(data):
                raw.append(data[index])
                index += 1
            continue
        if value == 0x28:
            depth += 1
        elif value == 0x29:
            depth -= 1
            if depth == 0:
                return _pdf_unescape_literal(bytes(raw)), index
        raw.append(value)
    return None


def _bounded_pdf_flate(payload: bytes) -> bytes | None:
    try:
        decoder = zlib.decompressobj()
        decoded = decoder.decompress(payload, _PDF_STREAM_LIMIT + 1)
        if len(decoded) > _PDF_STREAM_LIMIT or decoder.unconsumed_tail:
            return None
        decoded += decoder.flush(_PDF_STREAM_LIMIT + 1 - len(decoded))
        return decoded if len(decoded) <= _PDF_STREAM_LIMIT else None
    except (zlib.error, ValueError):
        return None


def parse_pdf(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Perform bounded PDF triage without rendering or executing document code.

    This intentionally mirrors the first-pass workflow in PDF CTF write-ups:
    inspect metadata and literal/hex strings, flag active content, and carve
    embedded streams/trailing archives for the normal recursive pipeline.
    """

    result = _result("pdf")
    if not data.startswith(b"%PDF-"):
        result["findings"].append(_finding("error", "structure", "Invalid PDF header", "The expected %PDF- file header is missing."))
        return result
    version = data[5:8].decode("ascii", "replace")
    eof_offset = data.rfind(b"%%EOF")
    result["properties"].update({
        "version": version,
        "file_size": len(data),
        "eof_present": eof_offset >= 0,
        "eof_offset": eof_offset,
        "object_count": len(re.findall(rb"(?m)^\s*\d+\s+\d+\s+obj\b", data)),
        "stream_count": len(re.findall(rb"(?m)^\s*stream\r?\n", data)),
        "xref_count": data.count(b"xref"),
    })
    if eof_offset < 0:
        result["findings"].append(_finding("warning", "integrity", "PDF EOF marker is missing", "The file has a PDF header but no %%EOF marker."))
    active_tokens = [token.decode("ascii") for token in (b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch") if token in data]
    if active_tokens:
        result["findings"].append(_finding(
            "warning", "document-active-content", "PDF active-content markers detected",
            "The PDF contains scripting or automatic-action names. They were reported as bytes only; no document code was executed.",
            markers=active_tokens,
        ))
    if b"/EmbeddedFile" in data:
        result["findings"].append(_finding(
            "info", "embedded-data", "PDF embedded-file object detected",
            "An EmbeddedFile name occurs in the PDF; bounded stream extraction was enabled.",
        ))

    records: list[dict[str, Any]] = []
    seen_text: set[str] = set()
    for key in _PDF_TEXT_KEYS:
        pattern = re.compile(rb"/" + re.escape(key) + rb"\s*(\([^)]{1,2000000}\)|<[0-9A-Fa-f\s]{4,4000000}>)")
        for match in pattern.finditer(data):
            token = match.group(1)
            if token.startswith(b"("):
                decoded = _pdf_literal_at(token, 0)
                value = decoded[0] if decoded else token[1:-1]
            else:
                try:
                    value = bytes.fromhex(re.sub(rb"\s+", b"", token[1:-1]).decode("ascii"))
                except (ValueError, UnicodeDecodeError):
                    continue
            text = _pdf_textual(value)
            if text and text not in seen_text:
                seen_text.add(text)
                result["text_records"].append({"source": f"PDF metadata:{key.decode()}", "offset": match.start(1), "text": text, "confidence_hint": 9})
                result["metadata"][f"pdf:{key.decode().lower()}"] = text
    # Recover visible literal strings, including flag text in ordinary page or
    # object content streams, while keeping dictionary names out of results.
    literal_attempts = 0
    for index, value in enumerate(data):
        if value != 0x28 or len(records) >= 2_000 or literal_attempts >= 512:
            continue
        literal_attempts += 1
        parsed = _pdf_literal_at(data, index)
        if parsed is None:
            continue
        decoded, end = parsed
        text = _pdf_textual(decoded)
        if text and text not in seen_text and len(text.strip()) >= 4:
            seen_text.add(text)
            result["text_records"].append({"source": "PDF literal string", "offset": index, "text": text, "confidence_hint": 6})
        records.append({"start": index, "end": end})
    # Hex strings are common in PDF puzzles and often hold ASCII/UTF-16 text.
    for match in re.finditer(rb"(?<!<)<([0-9A-Fa-f\s]{8,2000000})>(?!>)", data):
        try:
            value = bytes.fromhex(re.sub(rb"\s+", b"", match.group(1)).decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            continue
        text = _pdf_textual(value)
        if text and text not in seen_text and len(text.strip()) >= 4:
            seen_text.add(text)
            result["text_records"].append({"source": "PDF hex string", "offset": match.start(1), "text": text, "confidence_hint": 6})
        if len(result["text_records"]) >= 2_000:
            break

    # Streams can contain images, nested archives, or Flate-compressed text.
    # Keep only recognizable/textual payloads so arbitrary page streams do not
    # explode the artifact queue.
    stream_number = 0
    cursor = 0
    while stream_number < 128:
        marker = re.search(rb"(?m)^\s*stream\r?\n", data[cursor:])
        if marker is None:
            break
        stream_start = cursor + marker.end()
        end = data.find(b"endstream", stream_start, min(len(data), stream_start + _PDF_STREAM_LIMIT + 1024))
        if end < 0:
            break
        raw = data[stream_start:end].rstrip(b"\r\n")
        context = data[max(0, stream_start - 1024):stream_start]
        payloads: list[tuple[bytes, str]] = [(raw, "raw stream")]
        if b"/FlateDecode" in context:
            decoded = _bounded_pdf_flate(raw)
            if decoded is not None:
                payloads.append((decoded, "FlateDecode stream"))
        for payload, transformation in payloads:
            if not payload or len(payload) > _PDF_STREAM_LIMIT:
                continue
            if transformation == "raw stream" and b"/FlateDecode" in context and len(payloads) > 1:
                continue
            detected = sniff_kind(payload)
            text = _pdf_textual(payload)
            if detected != "binary" or text is not None or b"/EmbeddedFile" in context:
                label = f"pdf_stream_{stream_number:03d}_{detected}"
                result["extracted"].append({
                    "label": label, "data": payload, "producer": "pdf-parser",
                    "transformation": f"extract {transformation}", "offset": stream_start, "kind": detected,
                })
                if text and text not in seen_text:
                    seen_text.add(text)
                    result["text_records"].append({"source": "PDF stream", "offset": stream_start, "text": text, "confidence_hint": 5})
        stream_number += 1
        cursor = end + len(b"endstream")

    if eof_offset >= 0:
        trailer = data[eof_offset + len(b"%%EOF"):].strip()
        if trailer:
            result["findings"].append(_finding(
                "warning", "embedded-data", "Data follows PDF EOF", "Non-whitespace bytes follow the final %%EOF marker and were treated as a possible appended payload.",
                offset=eof_offset + len(b"%%EOF"), size=len(trailer), detected_kind=sniff_kind(trailer),
            ))
            result["extracted"].append({
                "label": "pdf_trailing_data", "data": trailer[:_PDF_STREAM_LIMIT], "producer": "pdf-parser",
                "transformation": "extract bytes after final %%EOF", "offset": eof_offset + len(b"%%EOF"), "kind": sniff_kind(trailer),
            })
    result["properties"]["text_record_count"] = len(result["text_records"])
    result["properties"]["embedded_stream_count"] = len(result["extracted"])
    return result


def parse_gif(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("gif")
    if not data.startswith((b"GIF87a", b"GIF89a")) or len(data) < 13:
        result["findings"].append(_finding("error", "structure", "Invalid GIF header", "GIF signature or logical screen descriptor is missing."))
        return result
    width, height, packed, background, aspect = struct.unpack_from("<HHBBB", data, 6)
    cursor = 13
    global_palette_entries = 2 ** ((packed & 0x07) + 1) if packed & 0x80 else 0
    cursor += global_palette_entries * 3
    frames = 0
    comments = 0
    applications: list[str] = []
    trailer_end: int | None = None
    malformed = False
    extension_counts: dict[str, int] = {}

    while cursor < len(data):
        introducer = data[cursor]
        if introducer == 0x3B:
            trailer_end = cursor + 1
            break
        if introducer == 0x2C:
            if cursor + 10 > len(data):
                malformed = True
                break
            descriptor = data[cursor + 1:cursor + 10]
            left, top, frame_width, frame_height, frame_packed = struct.unpack("<HHHHB", descriptor)
            cursor += 10
            if frame_packed & 0x80:
                cursor += 3 * (2 ** ((frame_packed & 0x07) + 1))
            if cursor >= len(data):
                malformed = True
                break
            lzw_min = data[cursor]
            cursor += 1
            _, cursor, ok = _gif_subblocks(data, cursor)
            if not ok:
                malformed = True
                break
            frames += 1
            continue
        if introducer == 0x21:
            if cursor + 2 > len(data):
                malformed = True
                break
            label = data[cursor + 1]
            cursor += 2
            payload, cursor, ok = _gif_subblocks(data, cursor)
            if not ok:
                malformed = True
                break
            label_name = {0xF9: "graphic-control", 0xFE: "comment", 0xFF: "application", 0x01: "plain-text"}.get(label, f"extension-{label:02x}")
            extension_counts[label_name] = extension_counts.get(label_name, 0) + 1
            if label == 0xFE:
                comments += 1
                text = payload.decode("latin-1", "replace")
                result["text_records"].append({"source": "GIF comment", "offset": cursor - len(payload), "text": text})
                result["metadata"][f"gif:comment:{comments}"] = display_text(text, 4096)
            elif label == 0xFF and payload:
                app = payload[:11].decode("latin-1", "replace")
                applications.append(app)
                # Application payloads are useful CTF hiding places but NETSCAPE looping data is routine.
                if app not in {"NETSCAPE2.0", "ANIMEXTS1.0"} and len(payload) <= 16 * 1024 * 1024:
                    result["extracted"].append({
                        "label": f"gif_application_{len(applications)}", "data": payload,
                        "producer": "gif-parser", "transformation": f"extract GIF application extension {app!r}",
                        "offset": max(0, cursor - len(payload)), "kind": sniff_kind(payload),
                    })
            elif label == 0x01 and payload:
                result["text_records"].append({"source": "GIF plain text", "offset": max(0, cursor - len(payload)), "text": payload.decode("latin-1", "replace")})
            continue
        malformed = True
        result["findings"].append(_finding("warning", "structure", "Unknown GIF block introducer", "The GIF block stream contains an unexpected byte.", offset=cursor, value=f"0x{introducer:02x}"))
        break

    result["properties"].update({
        "version": data[:6].decode("ascii"), "width": width, "height": height,
        "color_resolution": ((packed >> 4) & 0x07) + 1,
        "global_palette_entries": global_palette_entries, "background_index": background,
        "pixel_aspect_byte": aspect, "frame_count": frames, "comment_count": comments,
        "applications": applications, "extension_counts": extension_counts,
        "trailer_present": trailer_end is not None, "malformed_block_stream": malformed,
    })
    if trailer_end is not None and trailer_end < len(data):
        trailer = data[trailer_end:]
        result["findings"].append(_finding("warning", "embedded-data", "Data follows GIF trailer", f"{len(trailer)} byte(s) occur after the GIF trailer.", offset=trailer_end, size=len(trailer), detected_kind=sniff_kind(trailer)))
        result["extracted"].append({"label": "gif_trailer", "data": trailer, "producer": "gif-parser", "transformation": "extract bytes after GIF trailer", "offset": trailer_end, "kind": sniff_kind(trailer)})
    elif trailer_end is None and not malformed:
        result["findings"].append(_finding("warning", "integrity", "GIF trailer is missing", "The GIF block stream ended without byte 0x3B."))
        result["repairs"].append({"label": "gif_added_trailer", "data": data + b"\x3b", "producer": "gif-parser", "transformation": "append GIF trailer byte", "reason": "The complete block stream lacked the trailer byte."})
    if frames > 1:
        result["findings"].append(_finding("info", "animation", "Animated GIF", "Frame differences, delays, and disposal behavior may conceal information.", frame_count=frames))
    return result


def _gif_subblocks(data: bytes, cursor: int) -> tuple[bytes, int, bool]:
    payload = bytearray()
    while cursor < len(data):
        length = data[cursor]
        cursor += 1
        if length == 0:
            return bytes(payload), cursor, True
        if cursor + length > len(data):
            return bytes(payload), len(data), False
        if len(payload) <= 16 * 1024 * 1024:
            payload.extend(data[cursor:cursor + length])
        cursor += length
    return bytes(payload), cursor, False


_BMP_INTERLEAVED_SCAN_LIMIT = 32 * 1024 * 1024


def _trim_interleaved_zip(stream: bytes) -> bytes | None:
    """Return a structurally bounded ZIP prefix from a noisy byte lane.

    Python's ZIP reader only searches for an end record near the physical end
    of a file.  Steganography challenges commonly interleave a short archive
    with an entire image-sized lane, leaving far more than 65 KiB of unrelated
    bytes after the archive.  Validate the central-directory bounds before
    discarding that carrier tail so random ``PK`` bytes do not become artifacts.
    """

    if not stream.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return None
    cursor = 0
    while True:
        eocd = stream.find(b"PK\x05\x06", cursor)
        if eocd < 0:
            return None
        cursor = eocd + 1
        if eocd + 22 > len(stream):
            continue
        disk_number, central_disk, disk_entries, total_entries = struct.unpack_from("<HHHH", stream, eocd + 4)
        central_size, central_offset = struct.unpack_from("<II", stream, eocd + 12)
        comment_length = int.from_bytes(stream[eocd + 20:eocd + 22], "little")
        archive_end = eocd + 22 + comment_length
        if archive_end > len(stream):
            continue
        if disk_number != 0 or central_disk != 0 or disk_entries != total_entries:
            continue
        if central_offset + central_size > eocd:
            continue
        if total_entries and stream[central_offset:central_offset + 4] != b"PK\x01\x02":
            continue
        return stream[:archive_end]


def _bmp_bitfield_masks(data: bytes, dib_size: int, pixel_offset: int, compression: int | None) -> list[int]:
    """Read RGB(A) masks from BITFIELDS BMP headers without trusting offsets."""

    if compression not in (3, 6) or dib_size < 40:
        return []
    mask_offset = 14 + 40
    mask_count = 4 if (dib_size >= 56 or compression == 6) else 3
    available_end = min(len(data), pixel_offset, 14 + max(dib_size, 40))
    # BITMAPINFOHEADER stores its masks immediately after the 40-byte DIB,
    # whereas V2/V3/V4/V5 headers include them at the same absolute offset.
    if dib_size == 40:
        available_end = min(len(data), pixel_offset)
    if mask_offset + mask_count * 4 > available_end:
        return []
    return [int.from_bytes(data[mask_offset + index * 4:mask_offset + index * 4 + 4], "little") for index in range(mask_count)]


def _extract_bmp_interleaved_words(
    data: bytes,
    *,
    pixel_offset: int,
    pixel_end: int,
    pixel_count: int,
) -> list[dict[str, Any]]:
    """Detect file signatures split across either 16-bit word of 32-bit pixels."""

    if pixel_count <= 0 or pixel_end > len(data) or pixel_offset < 0:
        return []
    scan_pixels = min(pixel_count, _BMP_INTERLEAVED_SCAN_LIMIT // 2)
    pixel_bytes = data[pixel_offset:pixel_offset + scan_pixels * 4]
    if len(pixel_bytes) != scan_pixels * 4:
        return []
    recovered: list[dict[str, Any]] = []
    for word_lane in (0, 1):
        byte_offset = word_lane * 2
        stream = bytearray(scan_pixels * 2)
        stream[0::2] = pixel_bytes[byte_offset::4]
        stream[1::2] = pixel_bytes[byte_offset + 1::4]
        lane_data = bytes(stream)
        kind = sniff_kind(lane_data)
        if kind == "zip":
            payload = _trim_interleaved_zip(lane_data)
        else:
            payload = None
        if payload:
            recovered.append({
                "word_lane": word_lane,
                "byte_positions": [byte_offset, byte_offset + 1],
                "data": payload,
                "kind": kind,
                "scanned_bytes": len(lane_data),
                "discarded_carrier_tail": len(lane_data) - len(payload),
            })
    return recovered


def parse_bmp(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("bmp")
    if len(data) < 26 or not data.startswith(b"BM"):
        result["findings"].append(_finding("error", "structure", "Invalid BMP header", "Bitmap signature or DIB header is unavailable."))
        return result
    declared_size = int.from_bytes(data[2:6], "little")
    reserved1 = int.from_bytes(data[6:8], "little")
    reserved2 = int.from_bytes(data[8:10], "little")
    pixel_offset = int.from_bytes(data[10:14], "little")
    dib_size = int.from_bytes(data[14:18], "little")
    width = height = planes = bpp = compression = image_size = colors_used = None
    top_down = False
    if dib_size == 12 and len(data) >= 26:
        width, height, planes, bpp = struct.unpack_from("<HHHH", data, 18)
        compression = 0
    elif dib_size >= 40 and len(data) >= 54:
        width, signed_height, planes, bpp, compression, image_size = struct.unpack_from("<iiHHII", data, 18)
        top_down = signed_height < 0
        height = abs(signed_height)
        colors_used = int.from_bytes(data[46:50], "little")
    else:
        result["findings"].append(_finding("warning", "structure", "Unsupported BMP DIB header", "The DIB header type is truncated or uncommon.", dib_size=dib_size))

    masks = _bmp_bitfield_masks(data, dib_size, pixel_offset, compression)
    used_mask = 0
    for mask in masks:
        used_mask |= mask
    unused_mask = ((1 << bpp) - 1) & ~used_mask if bpp and masks and 0 < bpp <= 32 else None
    result["properties"].update({
        "declared_file_size": declared_size, "actual_file_size": len(data), "pixel_offset": pixel_offset,
        "dib_header_size": dib_size, "width": width, "height": height, "top_down": top_down,
        "planes": planes, "bits_per_pixel": bpp, "compression": compression,
        "declared_image_size": image_size, "colors_used": colors_used,
        "reserved_words": [reserved1, reserved2],
        "bitfield_masks": [f"0x{mask:08x}" for mask in masks],
        "unused_pixel_mask": f"0x{unused_mask:08x}" if unused_mask is not None else None,
    })
    if reserved1 or reserved2:
        result["findings"].append(_finding("info", "structure", "Non-zero BMP reserved fields", "The two reserved header words contain data.", reserved1=reserved1, reserved2=reserved2))
    if declared_size != len(data):
        result["findings"].append(_finding("warning", "integrity", "BMP file-size mismatch", "The header file size differs from the actual byte count.", declared=declared_size, actual=len(data)))
        if len(data) <= 0xFFFFFFFF:
            fixed = bytearray(data)
            fixed[2:6] = len(data).to_bytes(4, "little")
            result["repairs"].append({"label": "bmp_size_repaired", "data": bytes(fixed), "producer": "bmp-parser", "transformation": "set BMP file-size field to actual size", "reason": "The bfSize field did not match the immutable source length."})
    if 0 < declared_size < len(data):
        trailer = data[declared_size:]
        result["findings"].append(_finding("warning", "embedded-data", "Data follows declared BMP size", f"{len(trailer)} byte(s) occur beyond bfSize.", offset=declared_size, size=len(trailer), detected_kind=sniff_kind(trailer)))
        result["extracted"].append({"label": "bmp_trailer", "data": trailer, "producer": "bmp-parser", "transformation": "extract bytes after declared bfSize", "offset": declared_size, "kind": sniff_kind(trailer)})

    # For uncompressed byte-aligned BMPs, collect the per-row alignment bytes.
    if width and height and bpp and compression in (0, 3, 6) and pixel_offset < len(data):
        row_unpadded_bits = abs(width) * bpp
        row_payload = (row_unpadded_bits + 7) // 8
        row_stride = ((row_unpadded_bits + 31) // 32) * 4
        padding_size = row_stride - row_payload
        expected_end = pixel_offset + row_stride * height
        result["properties"].update({"row_stride": row_stride, "row_padding_bytes": padding_size, "expected_pixel_end": expected_end})
        if masks:
            result["findings"].append(_finding(
                "info", "structure", "BMP bitfield channel masks",
                "The bitmap uses explicit channel masks; unassigned pixel bits and byte lanes were inspected for hidden data.",
                masks=[f"0x{mask:08x}" for mask in masks],
                unused_mask=f"0x{unused_mask:08x}" if unused_mask is not None else None,
            ))
        if bpp == 32 and padding_size == 0 and expected_end <= len(data):
            interleaved = _extract_bmp_interleaved_words(
                data,
                pixel_offset=pixel_offset,
                pixel_end=expected_end,
                pixel_count=abs(width) * height,
            )
            for item in interleaved:
                lane = item["word_lane"]
                payload = item["data"]
                result["findings"].append(_finding(
                    "warning", "embedded-data", "File hidden in a BMP word lane",
                    "Taking the same two bytes from every 32-bit pixel produced a validated embedded file.",
                    word_lane=lane,
                    byte_positions=item["byte_positions"],
                    detected_kind=item["kind"],
                    extracted_size=len(payload),
                    scanned_bytes=item["scanned_bytes"],
                    discarded_carrier_tail=item["discarded_carrier_tail"],
                ))
                result["extracted"].append({
                    "label": f"bmp_word_lane_{lane}_{item['kind']}",
                    "data": payload,
                    "producer": "bmp-word-lane-parser",
                    "transformation": f"concatenate byte positions {lane * 2} and {lane * 2 + 1} from every 32-bit pixel, then validate and trim the {item['kind'].upper()} container",
                    "offset": pixel_offset + lane * 2,
                    "kind": item["kind"],
                })
        if padding_size > 0 and expected_end <= len(data) and height <= 2_000_000:
            padding = bytearray()
            for row in range(height):
                start = pixel_offset + row * row_stride + row_payload
                padding.extend(data[start:start + padding_size])
                if len(padding) > 16 * 1024 * 1024:
                    break
            if padding and any(padding):
                result["findings"].append(_finding("info", "steganography", "Non-zero BMP row padding", "Row alignment bytes contain non-zero data and were extracted for inspection.", bytes=len(padding), entropy=round(byte_entropy(padding), 4)))
                result["extracted"].append({"label": "bmp_row_padding", "data": bytes(padding), "producer": "bmp-parser", "transformation": "concatenate row alignment bytes", "offset": pixel_offset + row_payload, "kind": sniff_kind(padding)})
        if expected_end < len(data) and (not declared_size or expected_end < declared_size):
            extra = data[expected_end:declared_size or len(data)]
            if extra:
                result["findings"].append(_finding("info", "embedded-data", "Bytes follow BMP pixel array", "Bytes between the expected pixel array end and declared file end were extracted.", offset=expected_end, size=len(extra)))
                result["extracted"].append({"label": "bmp_post_pixels", "data": extra, "producer": "bmp-parser", "transformation": "extract bytes after calculated pixel array", "offset": expected_end, "kind": sniff_kind(extra)})
    return result


def parse_webp(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("webp")
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        result["findings"].append(_finding("error", "structure", "Invalid WebP RIFF header", "RIFF/WEBP identifiers are missing."))
        return result
    declared_riff_size = int.from_bytes(data[4:8], "little")
    declared_end = declared_riff_size + 8
    cursor = 12
    chunks: list[dict[str, Any]] = []
    width = height = None
    animation = False
    while cursor + 8 <= min(len(data), declared_end):
        fourcc_bytes = data[cursor:cursor + 4]
        fourcc = fourcc_bytes.decode("latin-1")
        length = int.from_bytes(data[cursor + 4:cursor + 8], "little")
        payload_start = cursor + 8
        payload_end = payload_start + length
        padded_end = payload_end + (length & 1)
        if payload_end > len(data) or padded_end > declared_end:
            result["findings"].append(_finding("error", "structure", "Truncated WebP chunk", f"Chunk {fourcc!r} extends beyond its RIFF boundary.", offset=cursor, declared_length=length))
            break
        payload = data[payload_start:payload_end]
        chunks.append({"fourcc": fourcc, "offset": cursor, "length": length})
        if fourcc == "VP8X" and len(payload) >= 10:
            flags = payload[0]
            width = 1 + int.from_bytes(payload[4:7], "little")
            height = 1 + int.from_bytes(payload[7:10], "little")
            animation = bool(flags & 0x02)
            result["properties"].update({
                "icc_flag": bool(flags & 0x20), "alpha_flag": bool(flags & 0x10),
                "exif_flag": bool(flags & 0x08), "xmp_flag": bool(flags & 0x04),
                "animation_flag": animation,
            })
        elif fourcc == "VP8 " and len(payload) >= 10 and payload[3:6] == b"\x9d\x01\x2a":
            width = int.from_bytes(payload[6:8], "little") & 0x3FFF
            height = int.from_bytes(payload[8:10], "little") & 0x3FFF
        elif fourcc == "VP8L" and len(payload) >= 5 and payload[0] == 0x2F:
            bits = int.from_bytes(payload[1:5], "little")
            width = (bits & 0x3FFF) + 1
            height = ((bits >> 14) & 0x3FFF) + 1
        if fourcc in {"EXIF", "XMP ", "ICCP"} and payload:
            result["extracted"].append({"label": f"webp_{fourcc.strip().lower()}", "data": payload, "producer": "webp-parser", "transformation": f"extract WebP {fourcc} chunk", "offset": payload_start, "kind": sniff_kind(payload)})
            if fourcc == "XMP ":
                text = payload.decode("utf-8", "replace")
                result["text_records"].append({"source": "WebP XMP", "offset": payload_start, "text": text})
                result["metadata"]["webp:xmp"] = display_text(text, 16_384)
        cursor = padded_end

    result["properties"].update({
        "width": width, "height": height, "declared_riff_size": declared_riff_size,
        "declared_file_end": declared_end, "actual_file_size": len(data),
        "chunks": chunks[:500], "chunk_count": len(chunks), "animation": animation or any(c["fourcc"] == "ANIM" for c in chunks),
        "frame_chunk_count": sum(1 for c in chunks if c["fourcc"] == "ANMF"),
    })
    if declared_end != len(data):
        result["findings"].append(_finding("warning", "integrity", "WebP RIFF-size mismatch", "The RIFF size does not match the actual file length.", declared_end=declared_end, actual=len(data)))
        if len(data) >= 8 and len(data) - 8 <= 0xFFFFFFFF:
            fixed = bytearray(data)
            fixed[4:8] = (len(data) - 8).to_bytes(4, "little")
            result["repairs"].append({"label": "webp_riff_size_repaired", "data": bytes(fixed), "producer": "webp-parser", "transformation": "set RIFF size to actual file length minus eight", "reason": "The RIFF size field and immutable source length differed."})
    if 12 <= declared_end < len(data):
        trailer = data[declared_end:]
        result["findings"].append(_finding("warning", "embedded-data", "Data follows WebP RIFF", f"{len(trailer)} byte(s) occur beyond the declared RIFF form.", offset=declared_end, size=len(trailer), detected_kind=sniff_kind(trailer)))
        result["extracted"].append({"label": "webp_trailer", "data": trailer, "producer": "webp-parser", "transformation": "extract bytes after declared RIFF end", "offset": declared_end, "kind": sniff_kind(trailer)})
    return result


_TIFF_TAG_NAMES = {
    256: "ImageWidth", 257: "ImageLength", 258: "BitsPerSample", 259: "Compression",
    262: "PhotometricInterpretation", 270: "ImageDescription", 271: "Make", 272: "Model",
    273: "StripOffsets", 277: "SamplesPerPixel", 278: "RowsPerStrip", 279: "StripByteCounts",
    282: "XResolution", 283: "YResolution", 296: "ResolutionUnit", 305: "Software",
    306: "DateTime", 315: "Artist", 320: "ColorMap", 322: "TileWidth", 323: "TileLength",
    324: "TileOffsets", 325: "TileByteCounts", 330: "SubIFDs", 33432: "Copyright",
    34665: "ExifIFD", 34853: "GPSIFD", 700: "XMP", 33723: "IPTC",
}
_TIFF_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8, 13: 4, 16: 8, 17: 8, 18: 8}


def parse_tiff(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("tiff")
    if len(data) < 8 or data[:2] not in {b"II", b"MM"}:
        result["findings"].append(_finding("error", "structure", "Invalid TIFF byte order", "TIFF byte-order marker is unavailable."))
        return result
    endian = "little" if data[:2] == b"II" else "big"
    marker = int.from_bytes(data[2:4], endian)
    bigtiff = marker == 43
    if marker not in (42, 43):
        result["findings"].append(_finding("error", "structure", "Invalid TIFF magic", "TIFF magic is neither 42 nor BigTIFF 43.", magic=marker))
        return result
    if bigtiff:
        if len(data) < 16 or int.from_bytes(data[4:6], endian) != 8:
            result["findings"].append(_finding("error", "structure", "Unsupported BigTIFF header", "BigTIFF offset-size metadata is invalid."))
            return result
        first_ifd = int.from_bytes(data[8:16], endian)
        offset_size = 8
    else:
        first_ifd = int.from_bytes(data[4:8], endian)
        offset_size = 4

    queue = [first_ifd]
    visited: set[int] = set()
    ifds: list[dict[str, Any]] = []
    selected_metadata: dict[str, Any] = {}
    while queue and len(ifds) < 64:
        offset = queue.pop(0)
        if offset == 0 or offset in visited:
            continue
        visited.add(offset)
        if offset >= len(data):
            result["findings"].append(_finding("warning", "structure", "TIFF IFD offset out of range", "An image-file-directory pointer is outside the file.", offset=offset))
            continue
        count_size = 8 if bigtiff else 2
        entry_size = 20 if bigtiff else 12
        if offset + count_size > len(data):
            break
        entry_count = int.from_bytes(data[offset:offset + count_size], endian)
        if entry_count > 100_000:
            result["findings"].append(_finding("error", "structure", "Excessive TIFF tag count", "The IFD tag count exceeds the safety bound.", offset=offset, count=entry_count))
            break
        entries_start = offset + count_size
        entries: list[dict[str, Any]] = []
        for index in range(min(entry_count, 4096)):
            position = entries_start + index * entry_size
            if position + entry_size > len(data):
                break
            tag = int.from_bytes(data[position:position + 2], endian)
            type_id = int.from_bytes(data[position + 2:position + 4], endian)
            if bigtiff:
                count = int.from_bytes(data[position + 4:position + 12], endian)
                value_field = data[position + 12:position + 20]
            else:
                count = int.from_bytes(data[position + 4:position + 8], endian)
                value_field = data[position + 8:position + 12]
            unit = _TIFF_TYPE_SIZES.get(type_id, 0)
            total_size = unit * count if unit and count <= (1 << 48) else 0
            if 0 < total_size <= offset_size:
                raw = value_field[:total_size]
                value_offset = position + entry_size - offset_size
            elif 0 < total_size <= 64 * 1024 * 1024:
                value_offset = int.from_bytes(value_field, endian)
                raw = data[value_offset:value_offset + total_size] if value_offset + total_size <= len(data) else b""
            else:
                value_offset = int.from_bytes(value_field, endian)
                raw = b""
            name = _TIFF_TAG_NAMES.get(tag, f"Tag{tag}")
            value = _tiff_value(type_id, count, raw, endian)
            entry = {"tag": tag, "name": name, "type": type_id, "count": count, "value_offset": value_offset, "value": value}
            entries.append(entry)
            if name in {"ImageDescription", "Make", "Model", "Software", "DateTime", "Artist", "Copyright"} and isinstance(value, str):
                selected_metadata[f"tiff:{name}"] = value
                result["text_records"].append({"source": f"TIFF {name}", "offset": value_offset, "text": value})
            if tag == 330:  # SubIFD offsets
                queue.extend(_tiff_int_list(type_id, count, raw, endian)[:64])
        next_pointer_position = entries_start + entry_count * entry_size
        next_ifd = 0
        if next_pointer_position + offset_size <= len(data):
            next_ifd = int.from_bytes(data[next_pointer_position:next_pointer_position + offset_size], endian)
            if next_ifd:
                queue.append(next_ifd)
        ifds.append({"offset": offset, "entry_count": entry_count, "next_ifd": next_ifd, "entries": entries})

    result["properties"].update({
        "byte_order": "little" if endian == "little" else "big", "bigtiff": bigtiff,
        "first_ifd_offset": first_ifd, "ifd_count": len(ifds), "ifds": ifds,
    })
    for ifd in ifds:
        for entry in ifd["entries"]:
            if entry["name"] == "ImageWidth" and "width" not in result["properties"]:
                result["properties"]["width"] = entry["value"]
            elif entry["name"] == "ImageLength" and "height" not in result["properties"]:
                result["properties"]["height"] = entry["value"]
    result["metadata"].update(selected_metadata)
    if queue:
        result["findings"].append(_finding("warning", "structure", "TIFF IFD traversal bounded", "Additional IFD pointers were not traversed after reaching the safety limit.", remaining=len(queue)))
    return result


def _tiff_int_list(type_id: int, count: int, raw: bytes, endian: str) -> list[int]:
    sizes = {1: 1, 3: 2, 4: 4, 13: 4, 16: 8, 18: 8}
    size = sizes.get(type_id)
    if not size or len(raw) < size:
        return []
    return [int.from_bytes(raw[index * size:(index + 1) * size], endian) for index in range(min(count, len(raw) // size, 4096))]


def _tiff_value(type_id: int, count: int, raw: bytes, endian: str) -> Any:
    if not raw:
        return None
    if type_id == 2:
        return display_text(raw.rstrip(b"\x00").decode("latin-1", "replace"), 16_384)
    integers = _tiff_int_list(type_id, count, raw, endian)
    if integers:
        return integers[0] if len(integers) == 1 else integers[:128]
    if type_id in (5, 10) and len(raw) >= 8:
        signed = type_id == 10
        numerator = int.from_bytes(raw[:4], endian, signed=signed)
        denominator = int.from_bytes(raw[4:8], endian, signed=signed)
        return {"numerator": numerator, "denominator": denominator, "value": numerator / denominator if denominator else None}
    if type_id in (11, 12):
        fmt = ("<" if endian == "little" else ">") + ("f" if type_id == 11 else "d")
        size = 4 if type_id == 11 else 8
        if len(raw) >= size:
            return struct.unpack(fmt, raw[:size])[0]
    return {"hex": raw[:256].hex(), "truncated": len(raw) > 256}


def parse_ico(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    result = _result("ico")
    if len(data) < 6 or data[:4] not in {b"\x00\x00\x01\x00", b"\x00\x00\x02\x00"}:
        result["findings"].append(_finding("error", "structure", "Invalid ICO/CUR header", "Reserved/type header fields are invalid or missing."))
        return result
    image_type = int.from_bytes(data[2:4], "little")
    count = int.from_bytes(data[4:6], "little")
    entries: list[dict[str, Any]] = []
    if count > 4096:
        result["findings"].append(_finding("error", "structure", "Excessive ICO entry count", "Directory count exceeds the safety bound.", count=count))
        return result
    for index in range(count):
        position = 6 + index * 16
        if position + 16 > len(data):
            result["findings"].append(_finding("error", "structure", "Truncated ICO directory", "An icon directory entry is incomplete.", index=index))
            break
        width = data[position] or 256
        height = data[position + 1] or 256
        colors = data[position + 2]
        planes = int.from_bytes(data[position + 4:position + 6], "little")
        bpp = int.from_bytes(data[position + 6:position + 8], "little")
        size = int.from_bytes(data[position + 8:position + 12], "little")
        offset = int.from_bytes(data[position + 12:position + 16], "little")
        valid = offset >= 6 + count * 16 and offset + size <= len(data)
        embedded_kind = sniff_kind(data[offset:offset + min(size, 32)]) if valid else "binary"
        if valid and embedded_kind == "binary" and data[offset:offset + 4] in {b"(\x00\x00\x00", b"|\x00\x00\x00", b"l\x00\x00\x00"}:
            embedded_kind = "bmp"
        entry = {"index": index, "width": width, "height": height, "colors": colors, "planes": planes, "bits_per_pixel": bpp, "size": size, "offset": offset, "valid": valid, "embedded_kind": embedded_kind}
        entries.append(entry)
        if valid:
            payload = data[offset:offset + size]
            result["extracted"].append({"label": f"ico_entry_{index + 1}_{width}x{height}", "data": payload, "producer": "ico-parser", "transformation": f"extract ICO directory entry {index}", "offset": offset, "kind": embedded_kind})
        else:
            result["findings"].append(_finding("warning", "structure", "ICO entry out of range", "An embedded image range is invalid.", index=index, offset=offset, size=size))
    result["properties"].update({"type": "icon" if image_type == 1 else "cursor", "declared_entry_count": count, "entry_count": len(entries), "entries": entries})
    if len(entries) > 1:
        result["findings"].append(_finding("info", "embedded-data", "Multiple ICO images", "Every embedded icon representation was extracted and can be analyzed recursively.", count=len(entries)))
    return result
