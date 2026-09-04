from __future__ import annotations

import base64
import binascii
import bz2
import codecs
import datetime as dt
import email.policy
import html
import io
import ipaddress
import itertools
import json
import re
import sqlite3
import struct
import time
import zipfile
import zlib
from collections import Counter, defaultdict
from email.parser import BytesParser
from typing import Any, Callable, Iterable

from .artifacts import (
    parse_android_backup,
    parse_binarycookies,
    parse_ds_store,
    parse_ese,
    parse_ios_mbdb,
    parse_jumplist,
    parse_leveldb,
    parse_lnk,
    parse_mft,
    parse_mozlz4,
    parse_plist,
    parse_prefetch,
    parse_recycle_bin_i,
    parse_sqlite_journal,
    parse_sqlite_wal,
    parse_systemd_journal,
    parse_thumbcache,
    parse_utmp,
    parse_usn,
    parse_virtual_disk,
)
from .common import byte_entropy, display_text, iter_ascii_strings, iter_utf16_strings, safe_label, sniff_kind
from .compression import DECODERS, CompressionError
from .extended import (
    parse_access_db,
    parse_android_sparse,
    parse_bson,
    parse_dds,
    parse_dicom,
    parse_dtb,
    parse_fits,
    parse_firmware_text,
    parse_git_object,
    parse_hdf5,
    parse_java_serialized,
    parse_ktx,
    parse_netpbm,
    parse_opaque_container,
    parse_openexr,
    parse_psd,
    parse_pyc,
    parse_python_pickle,
    parse_qoi,
    parse_tnef,
    parse_xcf,
    parse_zip_application,
    zip_directory_is_bounded,
)
from .longtail import (
    parse_android_boot,
    parse_arrow_ipc,
    parse_avro,
    parse_chm,
    parse_djvu,
    parse_orc,
    parse_parquet,
    parse_squashfs,
    parse_uefi_fv,
    parse_uimage,
    parse_warc,
)
from .programs import parse_dex, parse_elf, parse_java_class, parse_macho, parse_pe, parse_wasm
from .structured import parse_bencode, parse_cbor, parse_msgpack, parse_protobuf
from .video import parse_avi, parse_ebml_video, parse_iso_bmff


def analyze_format(kind: str, data: bytes, *, profile: str = "balanced") -> dict[str, Any]:
    parser: Callable[[bytes, str], dict[str, Any]] | None = {
        "png": parse_png,
        "jpeg": parse_jpeg,
        "gif": parse_gif,
        "bmp": parse_bmp,
        "webp": parse_webp,
        "tiff": parse_tiff,
        "ico": parse_ico,
        "psd": parse_psd,
        "xcf": parse_xcf,
        "netpbm": parse_netpbm,
        "qoi": parse_qoi,
        "dds": parse_dds,
        "ktx": parse_ktx,
        "openexr": parse_openexr,
        "dicom": parse_dicom,
        "fits": parse_fits,
        "heif": lambda source, selected: parse_iso_bmff(source, selected, kind="heif"),
        "avif": lambda source, selected: parse_iso_bmff(source, selected, kind="avif"),
        "mp4": lambda source, selected: parse_iso_bmff(source, selected, kind="mp4"),
        "mov": lambda source, selected: parse_iso_bmff(source, selected, kind="mov"),
        "matroska": lambda source, selected: parse_ebml_video(source, selected, kind="matroska"),
        "webm": lambda source, selected: parse_ebml_video(source, selected, kind="webm"),
        "avi": parse_avi,
        "pe": parse_pe,
        "elf": parse_elf,
        "macho": parse_macho,
        "wasm": parse_wasm,
        "dex": parse_dex,
        "java_class": parse_java_class,
        "java_serialized": parse_java_serialized,
        "pyc": parse_pyc,
        "python_pickle": parse_python_pickle,
        "git_pack": parse_git_object,
        "git_index": parse_git_object,
        "intel_hex": lambda source, selected: parse_firmware_text(source, selected, kind="intel_hex"),
        "srec": lambda source, selected: parse_firmware_text(source, selected, kind="srec"),
        "android_sparse": parse_android_sparse,
        "dtb": parse_dtb,
        "uimage": parse_uimage,
        "android_boot": parse_android_boot,
        "android_vendor_boot": lambda source, selected: parse_android_boot(source, selected, vendor=True),
        "uefi_fv": parse_uefi_fv,
        "squashfs": parse_squashfs,
        "parquet": parse_parquet,
        "avro": parse_avro,
        "arrow_ipc": parse_arrow_ipc,
        "orc": parse_orc,
        "bencode": parse_bencode,
        "cbor": parse_cbor,
        "msgpack": parse_msgpack,
        "protobuf": parse_protobuf,
        "pdf": parse_pdf,
        "text": parse_text,
        "docx": lambda source, selected: parse_document_package(source, selected, package_kind="docx"),
        "xlsx": lambda source, selected: parse_document_package(source, selected, package_kind="xlsx"),
        "pptx": lambda source, selected: parse_document_package(source, selected, package_kind="pptx"),
        "odt": lambda source, selected: parse_document_package(source, selected, package_kind="odt"),
        "ods": lambda source, selected: parse_document_package(source, selected, package_kind="ods"),
        "odp": lambda source, selected: parse_document_package(source, selected, package_kind="odp"),
        "epub": lambda source, selected: parse_document_package(source, selected, package_kind="epub"),
        "xps": lambda source, selected: parse_zip_application(source, selected, package_kind="xps"),
        "apk": lambda source, selected: parse_zip_application(source, selected, package_kind="apk"),
        "aab": lambda source, selected: parse_zip_application(source, selected, package_kind="aab"),
        "jar": lambda source, selected: parse_zip_application(source, selected, package_kind="jar"),
        "war": lambda source, selected: parse_zip_application(source, selected, package_kind="war"),
        "appx": lambda source, selected: parse_zip_application(source, selected, package_kind="appx"),
        "msix": lambda source, selected: parse_zip_application(source, selected, package_kind="msix"),
        "ipa": lambda source, selected: parse_zip_application(source, selected, package_kind="ipa"),
        "nupkg": lambda source, selected: parse_zip_application(source, selected, package_kind="nupkg"),
        "android_backup": parse_android_backup,
        "binarycookies": parse_binarycookies,
        "ds_store": parse_ds_store,
        "plist": parse_plist,
        "lnk": parse_lnk,
        "jumplist": parse_jumplist,
        "prefetch": parse_prefetch,
        "mft": parse_mft,
        "usn": parse_usn,
        "recycle_bin_i": parse_recycle_bin_i,
        "ese": parse_ese,
        "access_db": parse_access_db,
        "hdf5": parse_hdf5,
        "bson": parse_bson,
        "qcow": lambda source, selected: parse_virtual_disk(source, selected, disk_kind="qcow"),
        "vmdk": lambda source, selected: parse_virtual_disk(source, selected, disk_kind="vmdk"),
        "vhdx": lambda source, selected: parse_virtual_disk(source, selected, disk_kind="vhdx"),
        "vdi": lambda source, selected: parse_virtual_disk(source, selected, disk_kind="vdi"),
        "dmg": lambda source, selected: parse_virtual_disk(source, selected, disk_kind="dmg"),
        "aff": lambda source, selected: parse_virtual_disk(source, selected, disk_kind="aff"),
        "vhd": lambda source, selected: parse_opaque_container(source, selected, kind="vhd"),
        "pcap": parse_pcap,
        "pcapng": parse_pcapng,
        "sqlite": parse_sqlite,
        "sqlite_wal": parse_sqlite_wal,
        "sqlite_journal": parse_sqlite_journal,
        "thumbcache": parse_thumbcache,
        "utmp": parse_utmp,
        "ios_mbdb": parse_ios_mbdb,
        "mozlz4": parse_mozlz4,
        "leveldb": parse_leveldb,
        "ole": parse_ole,
        "rtf": parse_rtf,
        "eml": parse_eml,
        "mbox": parse_mbox,
        "tnef": parse_tnef,
        "warc": parse_warc,
        "chm": parse_chm,
        "djvu": parse_djvu,
        "systemd_journal": parse_systemd_journal,
        "disk": parse_disk,
        "ewf": parse_ewf,
        "registry": parse_registry,
        "memory": parse_memory,
        "evtx": parse_evtx,
        "pst": parse_pst,
        "shar": parse_shar,
        "ar": parse_ar,
        "cab": lambda source, selected: parse_opaque_container(source, selected, kind="cab"),
        "cpio": lambda source, selected: parse_opaque_container(source, selected, kind="cpio"),
        "rpm": lambda source, selected: parse_opaque_container(source, selected, kind="rpm"),
        "xar": lambda source, selected: parse_opaque_container(source, selected, kind="xar"),
        "onenote": lambda source, selected: parse_opaque_container(source, selected, kind="onenote"),
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


def _decode_text_document(data: bytes) -> tuple[str, str]:
    """Decode a textual evidence item without treating arbitrary bytes as text.

    ``sniff_kind`` already establishes the ASCII/whitespace threshold before
    this helper is called.  BOMs and UTF-16's characteristic NUL lanes are
    handled explicitly so text-only CTF challenges keep their original
    readable content instead of being split into individual string fragments.
    """

    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig", "replace"), "utf-8"
    if data.startswith(b"\xff\xfe"):
        return data.decode("utf-16", "replace"), "utf-16-le"
    if data.startswith(b"\xfe\xff"):
        return data.decode("utf-16", "replace"), "utf-16-be"
    sample = data[: min(len(data), 16 * 1024)]
    if sample and sample.count(0) / len(sample) >= 0.20:
        little_endian_nuls = sum(1 for index in range(1, len(sample), 2) if sample[index] == 0)
        big_endian_nuls = sum(1 for index in range(0, len(sample), 2) if sample[index] == 0)
        encoding = "utf-16-le" if little_endian_nuls >= big_endian_nuls else "utf-16-be"
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            pass
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        # The format classifier has already proved this is text. Windows-1252
        # is a useful lossless-ish fallback for older CTF fixtures.
        return data.decode("cp1252", "replace"), "windows-1252"


def _text_document_derivations(text: str) -> list[dict[str, Any]]:
    """Expose encoded markup/JSON text without executing document content.

    These are deliberately small, deterministic normalizations.  They cover
    common CTF fixtures such as HTML entities, XML text broken across tags,
    and JSON ``\\uXXXX`` escapes, while the original document remains the
    primary record.
    """

    derived: list[dict[str, Any]] = []
    bounded = text[:2_000_000]
    if "&" in bounded:
        unescaped = html.unescape(bounded)
        if unescaped != bounded:
            derived.append({
                "encoding": "html-entity-decoded", "offset": 0,
                "text": display_text(unescaped, 2_000_000), "source": "text HTML/XML entity decoding",
                "confidence_hint": 9,
                "transform_chain": ["decode text", "HTML/XML entity unescape"],
            })
    if "<" in bounded and ">" in bounded:
        # Tags are removed as delimiters *and* as empty joins.  The joined
        # form matters when a flag is split across adjacent XML text runs.
        without_tags = re.sub(r"<[^>]{0,4096}>", "", bounded)
        without_tags = html.unescape(without_tags)
        if without_tags and without_tags != bounded:
            derived.append({
                "encoding": "markup-text", "offset": 0,
                "text": display_text(without_tags, 2_000_000), "source": "text markup nodes",
                "confidence_hint": 9,
                "transform_chain": ["decode text", "remove bounded markup tags", "HTML/XML entity unescape"],
            })
    stripped = bounded.lstrip()
    if "\\u" in bounded and stripped[:1] in {"{", "[", "\""}:
        try:
            parsed = json.loads(bounded)
        except (TypeError, ValueError, RecursionError):
            parsed = None
        if parsed is not None:
            values: list[str] = []
            pending: list[Any] = [parsed]
            while pending and len(values) < 2_000:
                current = pending.pop()
                if isinstance(current, str):
                    values.append(current)
                elif isinstance(current, dict):
                    for key, value in list(current.items())[:2_000]:
                        pending.append(value)
                        pending.append(str(key))
                elif isinstance(current, list):
                    pending.extend(reversed(current[:2_000]))
            # A JSON string can deliberately contain a *literal* ``\uXXXX``
            # sequence by escaping its backslash. Decode only that narrow,
            # deterministic form after the JSON parser has already handled
            # normal escapes; do not invoke the broad ``unicode_escape`` codec.
            decoded_values = [
                re.sub(
                    r"\\u([0-9A-Fa-f]{4})",
                    lambda match: chr(int(match.group(1), 16)),
                    value,
                )
                for value in values
            ]
            decoded = "\n".join(value for value in decoded_values if value)
            if decoded:
                derived.append({
                    "encoding": "json-decoded", "offset": 0,
                    "text": display_text(decoded, 2_000_000), "source": "text JSON decoded strings",
                    "confidence_hint": 9,
                    "transform_chain": ["parse JSON without object hooks", "collect string keys and values"],
                })
                compact = "".join(value for value in decoded_values if value)
                if len(values) > 1 and compact and len(compact) <= 2_000_000:
                    derived.append({
                        "encoding": "json-decoded-compact", "offset": 0,
                        "text": compact, "source": "text JSON adjacent strings",
                        "confidence_hint": 8,
                        "transform_chain": ["parse JSON without object hooks", "join adjacent string values"],
                    })
    return derived


def parse_text(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Record complete, bounded plain-text evidence for CTF decoding.

    Unlike the generic strings pass, this preserves newlines and adjacent
    short tokens. That is important for challenges that hide an encoded value
    across lines, whitespace, JSON, XML, CSV, or a short configuration file.
    """

    result = _result("text")
    text, encoding = _decode_text_document(data)
    visible = display_text(text, 2_000_000)
    if not visible:
        result["findings"].append(_finding(
            "warning", "document", "Text document contains no displayable characters",
            "The file was classified as text, but its bounded content has no displayable characters.",
        ))
        return result
    result["properties"].update({
        "encoding": encoding,
        "character_count": len(visible),
        "line_count": visible.count("\n") + (1 if visible else 0),
        "truncated": len(visible) < len(text),
    })
    result["text_records"].append({
        "encoding": encoding,
        "offset": 0,
        "text": visible,
        "source": "plain-text-document",
        "confidence_hint": 9,
    })
    result["text_records"].extend(_text_document_derivations(visible))
    return result


_PCAP_FLAG_PREFIXES = (
    b"picoCTF{", b"flag{", b"CTF{", b"HTB{", b"THM{", b"DUCTF{", b"ICC{",
    b"BH{", b"N0PS{", b"APRK{", b"RaziCTF{", b"UTCTF{", b"HuntressCTF{",
    b"buckeye{", b"irisctf{",
)
_PCAP_FLAG_RE = re.compile(
    rb"(?<![A-Za-z0-9_])(?:picoCTF|flag|CTF|HTB|THM|DUCTF|ICC)\{[^\r\n{}]{2,240}\}",
    re.IGNORECASE,
)
_PCAP_IMSI_RE = re.compile(rb"\bIMSI\s*[:=]\s*(\d{8,20})", re.IGNORECASE)
_PCAP_CELL_RE = re.compile(rb"\bCELL(?:ID)?\s*[:=]\s*(\d{3,12})", re.IGNORECASE)
_PCAP_MAGIC_PREFIXES = _PCAP_FLAG_PREFIXES + (
    b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF89a", b"GIF87a", b"BM",
    b"PK\x03\x04", b"%PDF-", b"BZh", b"\x1f\x8b", b"Salted__", b"RIFF",
    b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a",
)
_PCAP_CLASSIC_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

_PCAP_IP_PROTOCOL_NAMES = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6",
    47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF",
}
_PCAP_DNS_TYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS",
    46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 65: "HTTPS", 255: "ANY",
}
_PCAP_TCP_FLAG_ORDER = (
    (0x002, "SYN"), (0x010, "ACK"), (0x008, "PSH"), (0x001, "FIN"),
    (0x004, "RST"), (0x020, "URG"), (0x040, "ECE"), (0x080, "CWR"),
    (0x100, "NS"),
)


def _pcap_transport_fields(protocol: int, segment: bytes) -> dict[str, Any]:
    """Parse a bounded TCP, UDP, or ICMP header from an IP payload."""

    fields: dict[str, Any] = {
        "source_port": None, "destination_port": None, "sequence": None,
        "acknowledgement": None, "tcp_flags": None, "tcp_window": None,
        "tcp_urgent_pointer": None, "transport_checksum": None,
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
            "transport_checksum": int.from_bytes(segment[16:18], "big"),
            "tcp_urgent_pointer": int.from_bytes(segment[18:20], "big"),
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
            "udp_length": udp_length, "transport_checksum": int.from_bytes(segment[6:8], "big"),
        })
    elif protocol in {1, 58}:  # ICMP / ICMPv6
        if len(segment) < 4:
            return fields
        fields["icmp_type"], fields["icmp_code"] = segment[0], segment[1]
        fields["transport_checksum"] = int.from_bytes(segment[2:4], "big")
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


def _pcap_ethernet_layout(frame: bytes) -> tuple[int, int] | None:
    """Return Ethernet payload offset and final EtherType, VLAN-aware."""

    if len(frame) < 14:
        return None
    offset = 14
    ether_type = int.from_bytes(frame[12:14], "big")
    while ether_type in {0x8100, 0x88A8, 0x9100} and len(frame) >= offset + 4:
        ether_type = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
    return offset, ether_type


def _pcap_special_frame(frame: bytes, linktype: int) -> dict[str, Any] | None:
    """Decode non-IP capture formats that are common in hardware/ICS CTFs."""

    if linktype == 1:
        ethernet = _pcap_ethernet_layout(frame)
        if ethernet is not None:
            offset, ether_type = ethernet
            # ARP encodes host and target addresses outside IP. This is a
            # useful CTF hiding place and should still be visible in traffic
            # tables instead of being reduced to opaque Ethernet bytes.
            if ether_type == 0x0806 and len(frame) >= offset + 8:
                hardware_type, protocol_type = struct.unpack_from("!HH", frame, offset)
                hardware_length, protocol_length, operation = struct.unpack_from("!BBH", frame, offset + 4)
                end = offset + 8 + 2 * (hardware_length + protocol_length)
                if (
                    hardware_type == 1 and protocol_type == 0x0800
                    and hardware_length == 6 and protocol_length == 4 and len(frame) >= end
                ):
                    sender_mac = ":".join(f"{value:02x}" for value in frame[offset + 8:offset + 14])
                    sender_ip = str(ipaddress.IPv4Address(frame[offset + 14:offset + 18]))
                    target_mac = ":".join(f"{value:02x}" for value in frame[offset + 18:offset + 24])
                    target_ip = str(ipaddress.IPv4Address(frame[offset + 24:offset + 28]))
                    return {
                        "source": sender_ip, "destination": target_ip, "protocol": None,
                        "special_protocol": "ARP", "source_port": None, "destination_port": None,
                        "sequence": None, "payload": frame[offset:end], "payload_offset": offset,
                        "network": False, "arp_operation": operation, "arp_sender_mac": sender_mac,
                        "arp_target_mac": target_mac, "arp_sender_ip": sender_ip, "arp_target_ip": target_ip,
                    }
    if linktype == 227 and len(frame) >= 8:  # LINKTYPE_CAN_SOCKETCAN
        raw_id = int.from_bytes(frame[:4], "big")
        length = min(int(frame[4]), 64, max(0, len(frame) - 8))
        can_id = raw_id & 0x1FFFFFFF
        extended = bool(raw_id & 0x80000000)
        payload = frame[8:8 + length]
        width = 8 if extended else 3
        return {
            "source": f"CAN 0x{can_id:0{width}X}", "destination": "CAN bus",
            "protocol": None, "special_protocol": "CAN", "source_port": None,
            "destination_port": None, "sequence": None, "payload": payload,
            "payload_offset": 8, "network": False, "can_id": can_id,
            "can_extended": extended, "can_rtr": bool(raw_id & 0x40000000),
            "can_error": bool(raw_id & 0x20000000), "can_dlc": length,
            "can_fd": length > 8,
        }
    return None


def _pcap_capture_packet(frame: bytes, linktype: int) -> dict[str, Any]:
    special = _pcap_special_frame(frame, linktype)
    if special is not None:
        return special
    packet = _pcap_packet_network(frame, linktype)
    if packet is not None:
        packet["network"] = True
        return packet
    payload_offset, frame_payload = _pcap_frame_payload(frame, linktype)
    return {
        "source": None, "destination": None, "protocol": None,
        "source_port": None, "destination_port": None, "sequence": None,
        "payload": frame_payload, "payload_offset": payload_offset, "network": False,
    }


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
            "ip_checksum": int.from_bytes(frame[ip_offset + 10:ip_offset + 12], "big"),
            "ip_id": int.from_bytes(frame[ip_offset + 4:ip_offset + 6], "big"),
            "ip_flags": (fragment_field >> 13) & 0x07,
            "ip_reserved": bool(fragment_field & 0x8000),
            "dont_fragment": bool(fragment_field & 0x4000),
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
        "ip_checksum": None,
        "flow_label": first_word & 0xFFFFF, "ip_id": fragment_id,
        "ip_flags": None, "ip_reserved": None, "dont_fragment": None,
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
    first_line_end = payload.find(b"\n", match.start())
    first_line = payload[match.start():first_line_end if first_line_end >= 0 else header_end].rstrip(b"\r").decode("latin-1", "ignore")
    response = request_method.startswith("HTTP/")
    status_code = int(request_target) if response and request_target.isdigit() else None
    reason = ""
    if response:
        parts = first_line.split(" ", 2)
        reason = parts[2] if len(parts) > 2 else ""
    content_disposition = header_map.get("content-disposition", "")
    filename_match = re.search(r"filename\*?=(?:UTF-8''|\")?([^\";]+)", content_disposition, re.IGNORECASE)
    return {
        "method": request_method, "target": request_target,
        "first_line": first_line, "response": response, "status_code": status_code,
        "reason": reason, "version": request_method if response else (first_line.rsplit(" ", 1)[-1] if " " in first_line else ""),
        "host": header_map.get("host", ""), "content_type": header_map.get("content-type", ""),
        "filename": filename_match.group(1).strip() if filename_match else "",
        "headers": header_map, "body": body,
    }


def _pcap_http_basic_credential(headers: dict[str, str]) -> tuple[str, str] | None:
    """Decode one bounded HTTP Basic credential without treating it as crypto."""

    value = headers.get("authorization", "").strip()
    scheme, separator, token = value.partition(" ")
    token = re.sub(r"\s+", "", token)
    if not separator or scheme.casefold() != "basic" or not 4 <= len(token) <= 2048:
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", token):
        return None
    try:
        decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
    except (ValueError, binascii.Error):
        return None
    if not 1 <= len(decoded) <= 1024 or b":" not in decoded:
        return None
    username, secret = decoded.split(b":", 1)
    if not username or any(byte < 32 or byte == 127 for byte in decoded):
        return None
    return username.decode("utf-8", "replace"), secret.decode("utf-8", "replace")


def _pcap_tls_version(value: int) -> str:
    return {
        0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
        0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
    }.get(value, f"0x{value:04x}")


def _pcap_tls_extensions(body: bytes, offset: int, *, client: bool) -> dict[str, Any]:
    """Parse display-safe ClientHello/ServerHello extension summaries."""

    if offset + 2 > len(body):
        return {}
    declared = int.from_bytes(body[offset:offset + 2], "big")
    cursor = offset + 2
    end = min(len(body), cursor + declared)
    server_names: list[str] = []
    alpn: list[str] = []
    supported_versions: list[str] = []
    extension_types: list[int] = []
    for _ in range(256):
        if cursor + 4 > end:
            break
        extension_type = int.from_bytes(body[cursor:cursor + 2], "big")
        length = int.from_bytes(body[cursor + 2:cursor + 4], "big")
        cursor += 4
        if cursor + length > end:
            break
        value = body[cursor:cursor + length]
        cursor += length
        extension_types.append(extension_type)
        if extension_type == 0 and len(value) >= 5:  # server_name
            name_cursor = 2
            while name_cursor + 3 <= len(value):
                name_type = value[name_cursor]
                name_length = int.from_bytes(value[name_cursor + 1:name_cursor + 3], "big")
                name_cursor += 3
                if name_cursor + name_length > len(value):
                    break
                if name_type == 0:
                    raw_name = value[name_cursor:name_cursor + name_length]
                    try:
                        server_names.append(raw_name.decode("idna"))
                    except UnicodeError:
                        server_names.append(raw_name.decode("ascii", "replace"))
                name_cursor += name_length
        elif extension_type == 16 and len(value) >= 3:  # ALPN
            alpn_cursor = 2
            while alpn_cursor < len(value):
                item_length = value[alpn_cursor]
                alpn_cursor += 1
                if alpn_cursor + item_length > len(value):
                    break
                alpn.append(value[alpn_cursor:alpn_cursor + item_length].decode("ascii", "replace"))
                alpn_cursor += item_length
        elif extension_type == 43 and value:  # supported_versions
            version_bytes = value
            if client and len(value) >= 1:
                version_bytes = value[1:1 + value[0]]
            for index in range(0, len(version_bytes) - 1, 2):
                supported_versions.append(_pcap_tls_version(int.from_bytes(version_bytes[index:index + 2], "big")))
    result: dict[str, Any] = {"extension_types": extension_types[:128]}
    if server_names:
        result["server_names"] = server_names[:16]
    if alpn:
        result["alpn"] = alpn[:32]
    if supported_versions:
        result["supported_versions"] = supported_versions[:16]
    return result


def _pcap_tls_handshake(handshake_type: int, body: bytes) -> dict[str, Any]:
    names = {
        0: "Hello Request", 1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket",
        8: "Encrypted Extensions", 11: "Certificate", 12: "Server Key Exchange",
        13: "Certificate Request", 14: "Server Hello Done", 15: "Certificate Verify",
        16: "Client Key Exchange", 20: "Finished", 24: "Key Update",
    }
    item: dict[str, Any] = {"type": handshake_type, "name": names.get(handshake_type, f"Handshake {handshake_type}"), "length": len(body)}
    if handshake_type == 1 and len(body) >= 35:
        item["legacy_version"] = _pcap_tls_version(int.from_bytes(body[:2], "big"))
        cursor = 34
        session_length = body[cursor]
        cursor += 1 + session_length
        if cursor + 2 <= len(body):
            cipher_length = int.from_bytes(body[cursor:cursor + 2], "big")
            item["cipher_suite_count"] = cipher_length // 2
            cursor += 2 + cipher_length
        if cursor < len(body):
            compression_length = body[cursor]
            cursor += 1 + compression_length
        item.update(_pcap_tls_extensions(body, cursor, client=True))
    elif handshake_type == 2 and len(body) >= 38:
        item["legacy_version"] = _pcap_tls_version(int.from_bytes(body[:2], "big"))
        cursor = 34
        session_length = body[cursor]
        cursor += 1 + session_length
        if cursor + 3 <= len(body):
            item["cipher_suite"] = f"0x{int.from_bytes(body[cursor:cursor + 2], 'big'):04x}"
            cursor += 3
        item.update(_pcap_tls_extensions(body, cursor, client=False))
    elif handshake_type == 11 and len(body) >= 3:
        item["certificate_list_bytes"] = int.from_bytes(body[:3], "big")
    return item


def _pcap_tls_records(payload: bytes) -> list[dict[str, Any]]:
    """Return bounded TLS record and handshake metadata without decrypting data."""

    records: list[dict[str, Any]] = []
    cursor = 0
    for _ in range(128):
        if cursor + 5 > len(payload):
            break
        content_type = payload[cursor]
        version = int.from_bytes(payload[cursor + 1:cursor + 3], "big")
        length = int.from_bytes(payload[cursor + 3:cursor + 5], "big")
        if content_type not in {20, 21, 22, 23, 24} or version >> 8 != 3 or cursor + 5 + length > len(payload):
            break
        body = payload[cursor + 5:cursor + 5 + length]
        item: dict[str, Any] = {
            "content_type": content_type,
            "content_name": {20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data", 24: "Heartbeat"}.get(content_type, "TLS"),
            "version": _pcap_tls_version(version), "length": length, "handshakes": [],
        }
        if content_type == 22:
            handshake_cursor = 0
            for _handshake in range(64):
                if handshake_cursor + 4 > len(body):
                    break
                handshake_type = body[handshake_cursor]
                handshake_length = int.from_bytes(body[handshake_cursor + 1:handshake_cursor + 4], "big")
                handshake_cursor += 4
                if handshake_cursor + handshake_length > len(body):
                    break
                item["handshakes"].append(_pcap_tls_handshake(handshake_type, body[handshake_cursor:handshake_cursor + handshake_length]))
                handshake_cursor += handshake_length
        records.append(item)
        cursor += 5 + length
    return records


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


def _pcap_timestamp_nanoseconds(packet: dict[str, Any]) -> int | None:
    timestamp_ns = packet.get("timestamp_ns")
    if isinstance(timestamp_ns, int):
        return timestamp_ns
    value = packet.get("timestamp_key")
    if not isinstance(value, tuple) or len(value) < 2:
        return None
    multiplier = 1 if packet.get("timestamp_resolution") == "nanoseconds" else 1_000
    return int(value[0]) * 1_000_000_000 + int(value[1]) * multiplier


def _pcap_pack_bits(bits: list[int], *, most_significant_first: bool) -> bytes:
    packed = bytearray()
    for start in range(0, len(bits) - 7, 8):
        value = 0
        for index, bit in enumerate(bits[start:start + 8]):
            shift = 7 - index if most_significant_first else index
            value |= (int(bit) & 1) << shift
        packed.append(value)
    return bytes(packed)


def _pcap_bit_plane_variants(value: bytes) -> list[tuple[str, bytes]]:
    """Pack varying scalar bit lanes in common CTF bit/direction conventions."""

    if len(value) < 16:
        return []
    variants: list[tuple[str, bytes]] = []
    seen: set[bytes] = set()
    for bit_index in range(8):
        bits = [(byte >> bit_index) & 1 for byte in value]
        if not any(bits) or all(bits):
            continue
        for reversed_order in (False, True):
            ordered = list(reversed(bits)) if reversed_order else bits
            for inverted in (False, True):
                candidate_bits = [bit ^ int(inverted) for bit in ordered]
                for most_significant_first in (True, False):
                    packed = _pcap_pack_bits(candidate_bits, most_significant_first=most_significant_first)
                    if not packed or packed in seen:
                        continue
                    seen.add(packed)
                    variants.append((
                        f"bit {bit_index}, {'reversed, ' if reversed_order else ''}{'inverted, ' if inverted else ''}{'MSB' if most_significant_first else 'LSB'} packing",
                        packed,
                    ))
    return variants


def _pcap_printable(data: bytes, ratio: float = 0.55) -> bool:
    if not data:
        return False
    # A representative bounded sample is enough for deciding whether to try
    # text decoders; scanning multi-megabyte streams repeatedly is not.
    sample = data
    if len(data) > 65_536:
        middle = max(0, len(data) // 2 - 8_192)
        sample = data[:16_384] + data[middle:middle + 16_384] + data[-16_384:]
    printable = sum(value in {9, 10, 13} or 32 <= value < 127 for value in sample)
    return printable >= max(4, int(len(sample) * ratio))


def _pcap_flag_values(data: bytes) -> set[str]:
    # Every accepted CTF token is brace-delimited. Most packet-field lanes are
    # high-entropy binary data, so avoid running two regex passes over them.
    if b"{" not in data or b"}" not in data:
        return set()
    # Avoid brace-by-brace scans over entropy. A valid capture token starts
    # with one of the normal CTF prefixes, so detect that short literal first.
    prefix_variants = tuple(dict.fromkeys(
        candidate for prefix in _PCAP_FLAG_PREFIXES for candidate in (prefix, prefix.lower())
    ))

    def scan(buffer: bytes) -> set[str]:
        found: set[str] = set()
        for prefix in prefix_variants:
            cursor = 0
            while True:
                start = buffer.find(prefix, cursor)
                if start < 0:
                    break
                cursor = start + 1
                if start > 0 and ((65 <= buffer[start - 1] <= 90) or (97 <= buffer[start - 1] <= 122) or (48 <= buffer[start - 1] <= 57) or buffer[start - 1] == 95):
                    continue
                brace = start + len(prefix) - 1
                end = buffer.find(b"}", brace + 3, min(len(buffer), brace + 242))
                if end < 0:
                    continue
                token = buffer[start:end + 1]
                if b"\r" not in token and b"\n" not in token and token.count(b"{") == 1:
                    found.add(token.decode("latin-1", "ignore"))
        return found

    if not any(prefix in data for prefix in prefix_variants):
        return set()
    values = scan(data)
    # Only normalize streams that look like human-readable or NUL-interleaved
    # text. Random binary contains whitespace frequently and made an unbounded
    # normalization pass both expensive and noisy.
    sample = data if len(data) <= 65_536 else data[:32_768] + data[-32_768:]
    non_null = sample.replace(b"\x00", b"")
    null_interleaved = (
        len(non_null) >= 4
        and len(non_null) < len(sample) * 0.8
        and _pcap_printable(non_null, 0.8)
    )
    if (_pcap_printable(sample, 0.7) or null_interleaved) and any(separator in data for separator in (b"\x00", b"\x09", b"\x0a", b"\x0d", b" ")):
        compact = re.sub(rb"[\x00\x09\x0a\x0d ]+", b"", data)
        values.update(scan(compact))
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
    transaction_id, flags, question_count, answer_count, authority_count, additional_count = struct.unpack_from("!HHHHHH", payload, 0)
    if sum((question_count, answer_count, authority_count, additional_count)) > 4096:
        return None
    cursor = 12
    questions: list[str] = []
    question_details: list[dict[str, Any]] = []
    answers: list[dict[str, Any]] = []

    def result_value() -> dict[str, Any]:
        return {
            "transaction_id": transaction_id,
            "flags": flags,
            "response": bool(flags & 0x8000),
            "opcode": (flags >> 11) & 0x0F,
            "authoritative": bool(flags & 0x0400),
            "truncated": bool(flags & 0x0200),
            "recursion_desired": bool(flags & 0x0100),
            "recursion_available": bool(flags & 0x0080),
            "response_code": flags & 0x000F,
            "questions": questions,
            "question_details": question_details,
            "answers": answers,
        }

    for _ in range(question_count):
        parsed = _pcap_dns_name(payload, cursor)
        if parsed is None:
            return None
        labels, cursor = parsed
        if cursor + 4 > len(payload):
            return None
        query_type, query_class = struct.unpack_from("!HH", payload, cursor)
        cursor += 4
        name = ".".join(labels)
        questions.append(name)
        question_details.append({"name": name, "type": query_type, "class": query_class})
        answers.append({"section": "question", "name": name, "type": query_type, "class": query_class})
    for section, count in (("answer", answer_count), ("authority", authority_count), ("additional", additional_count)):
        for _ in range(count):
            parsed = _pcap_dns_name(payload, cursor)
            if parsed is None:
                return result_value()
            labels, cursor = parsed
            if cursor + 10 > len(payload):
                return result_value()
            record_type, record_class, ttl, data_length = struct.unpack_from("!HHIH", payload, cursor)
            cursor += 10
            if cursor + data_length > len(payload):
                return result_value()
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
    return result_value()


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


def _pcap_mqtt_messages(payload: bytes) -> list[dict[str, Any]]:
    """Parse bounded MQTT control packets and expose PUBLISH topic payloads."""

    messages: list[dict[str, Any]] = []
    cursor = 0
    names = {
        1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 5: "PUBREC",
        6: "PUBREL", 7: "PUBCOMP", 8: "SUBSCRIBE", 9: "SUBACK",
        10: "UNSUBSCRIBE", 11: "UNSUBACK", 12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT",
    }
    for _ in range(4096):
        if cursor + 2 > len(payload):
            break
        first = payload[cursor]
        packet_type = first >> 4
        if packet_type not in names:
            break
        length = 0
        multiplier = 1
        length_cursor = cursor + 1
        for _length_byte in range(4):
            if length_cursor >= len(payload):
                return messages
            encoded = payload[length_cursor]
            length_cursor += 1
            length += (encoded & 0x7F) * multiplier
            if not encoded & 0x80:
                break
            multiplier *= 128
        else:
            break
        end = length_cursor + length
        if length > 16 * 1024 * 1024 or end > len(payload):
            break
        body = payload[length_cursor:end]
        item: dict[str, Any] = {"type": packet_type, "name": names[packet_type], "flags": first & 0x0F, "length": length}
        if packet_type == 3 and len(body) >= 2:
            topic_length = int.from_bytes(body[:2], "big")
            if 2 + topic_length <= len(body):
                position = 2 + topic_length
                qos = (first >> 1) & 0x03
                if qos and position + 2 <= len(body):
                    item["packet_id"] = int.from_bytes(body[position:position + 2], "big")
                    position += 2
                item.update({
                    "topic": body[2:2 + topic_length].decode("utf-8", "replace"),
                    "qos": qos, "retain": bool(first & 1), "payload": body[position:],
                })
        messages.append(item)
        cursor = end
    return messages


def _pcap_websocket_frames(payload: bytes) -> list[dict[str, Any]]:
    """Decode RFC 6455 data frames, including client masking and fragments."""

    cursor = 0
    header_end = payload.find(b"\r\n\r\n")
    if header_end >= 0 and b"upgrade: websocket" in payload[:header_end].lower():
        cursor = header_end + 4
    frames: list[dict[str, Any]] = []
    fragmented = bytearray()
    fragmented_opcode: int | None = None
    for _ in range(4096):
        if cursor + 2 > len(payload):
            break
        first, second = payload[cursor], payload[cursor + 1]
        opcode = first & 0x0F
        if first & 0x70 or opcode not in {0, 1, 2, 8, 9, 10}:
            break
        masked = bool(second & 0x80)
        length = second & 0x7F
        cursor += 2
        if length == 126:
            if cursor + 2 > len(payload):
                break
            length = int.from_bytes(payload[cursor:cursor + 2], "big")
            cursor += 2
        elif length == 127:
            if cursor + 8 > len(payload):
                break
            length = int.from_bytes(payload[cursor:cursor + 8], "big")
            cursor += 8
        if length > 16 * 1024 * 1024:
            break
        mask = b""
        if masked:
            if cursor + 4 > len(payload):
                break
            mask = payload[cursor:cursor + 4]
            cursor += 4
        if cursor + length > len(payload):
            break
        value = payload[cursor:cursor + length]
        cursor += length
        if masked:
            value = bytes(byte ^ mask[index % 4] for index, byte in enumerate(value))
        final = bool(first & 0x80)
        if opcode in {1, 2} and not final:
            fragmented_opcode = opcode
            fragmented = bytearray(value)
            continue
        if opcode == 0 and fragmented_opcode is not None:
            fragmented.extend(value)
            if not final:
                continue
            opcode, value = fragmented_opcode, bytes(fragmented)
            fragmented_opcode, fragmented = None, bytearray()
        frames.append({
            "opcode": opcode, "name": {1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong"}.get(opcode, "continuation"),
            "final": final, "masked": masked, "payload": value,
        })
    return frames


def _pcap_modbus_payloads(payload: bytes) -> list[dict[str, Any]]:
    """Extract register/data bytes from bounded Modbus/TCP ADUs."""

    messages: list[dict[str, Any]] = []
    cursor = 0
    for _ in range(4096):
        if cursor + 8 > len(payload):
            break
        transaction = int.from_bytes(payload[cursor:cursor + 2], "big")
        protocol = int.from_bytes(payload[cursor + 2:cursor + 4], "big")
        length = int.from_bytes(payload[cursor + 4:cursor + 6], "big")
        if protocol != 0 or length < 2 or length > 260 or cursor + 6 + length > len(payload):
            break
        unit = payload[cursor + 6]
        pdu = payload[cursor + 7:cursor + 6 + length]
        function = pdu[0]
        data = b""
        if function in {1, 2, 3, 4} and len(pdu) >= 2 and pdu[1] <= len(pdu) - 2:
            data = pdu[2:2 + pdu[1]]
        elif function in {15, 16, 23} and len(pdu) >= 6 and pdu[5] <= len(pdu) - 6:
            data = pdu[6:6 + pdu[5]]
        elif function in {5, 6} and len(pdu) >= 5:
            data = pdu[3:5]
        messages.append({
            "transaction_id": transaction, "unit_id": unit, "function": function,
            "exception": bool(function & 0x80), "data": data, "pdu": pdu,
        })
        cursor += 6 + length
    return messages


def _pcap_dhcp_message(payload: bytes) -> dict[str, Any] | None:
    """Parse the clue-bearing BOOTP/DHCP fields without interpreting leases."""

    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        return None
    message_types = {
        1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK",
        6: "NAK", 7: "Release", 8: "Inform",
    }
    values: dict[int, list[bytes]] = defaultdict(list)
    cursor = 240
    for _ in range(256):
        if cursor >= len(payload):
            break
        code = payload[cursor]
        cursor += 1
        if code == 255:
            break
        if code == 0:
            continue
        if cursor >= len(payload):
            break
        length = payload[cursor]
        cursor += 1
        if cursor + length > len(payload):
            break
        values[code].append(payload[cursor:cursor + length])
        cursor += length

    def text_option(code: int) -> str | None:
        raw = next(iter(values.get(code, [])), b"")
        return raw.decode("utf-8", "replace").strip("\x00") or None

    def address_option(code: int) -> str | None:
        raw = next(iter(values.get(code, [])), b"")
        return str(ipaddress.IPv4Address(raw[:4])) if len(raw) >= 4 else None

    client = payload[28:44].split(b"\x00", 1)[0]
    client_mac = ":".join(f"{value:02x}" for value in client) if client else None
    message_code = next(iter(values.get(53, [])), b"\x00")[:1]
    return {
        "message_type": message_types.get(message_code[0] if message_code else 0, "BOOTP"),
        "message_code": message_code[0] if message_code else None,
        "transaction_id": f"0x{int.from_bytes(payload[4:8], 'big'):08x}",
        "client_mac": client_mac,
        "client_ip": str(ipaddress.IPv4Address(payload[12:16])),
        "your_ip": str(ipaddress.IPv4Address(payload[16:20])),
        "server_ip": str(ipaddress.IPv4Address(payload[20:24])),
        "hostname": text_option(12), "domain": text_option(15),
        "vendor_class": text_option(60), "user_class": text_option(77),
        "bootfile": text_option(67), "requested_ip": address_option(50),
        "server_identifier": address_option(54),
        "option_values": {str(code): [value.hex() for value in entries] for code, entries in values.items()},
    }


def _pcap_coap_message(payload: bytes) -> dict[str, Any] | None:
    """Decode compact CoAP option paths and data from a bounded UDP datagram."""

    if len(payload) < 4 or payload[0] >> 6 != 1 or payload[0] & 0x0F > 8:
        return None
    token_length = payload[0] & 0x0F
    if 4 + token_length > len(payload):
        return None
    cursor = 4 + token_length
    option_number = 0
    path: list[str] = []
    query: list[str] = []
    content_format: int | None = None

    def extended(nibble: int, position: int) -> tuple[int, int] | None:
        if nibble < 13:
            return nibble, position
        if nibble == 13 and position < len(payload):
            return 13 + payload[position], position + 1
        if nibble == 14 and position + 2 <= len(payload):
            return 269 + int.from_bytes(payload[position:position + 2], "big"), position + 2
        return None

    for _ in range(128):
        if cursor >= len(payload) or payload[cursor] == 0xFF:
            break
        initial = payload[cursor]
        cursor += 1
        delta = extended(initial >> 4, cursor)
        if delta is None:
            return None
        delta_value, cursor = delta
        value_length = extended(initial & 0x0F, cursor)
        if value_length is None:
            return None
        length, cursor = value_length
        if cursor + length > len(payload):
            return None
        option_number += delta_value
        value = payload[cursor:cursor + length]
        cursor += length
        if option_number == 11:
            path.append(value.decode("utf-8", "replace"))
        elif option_number == 15:
            query.append(value.decode("utf-8", "replace"))
        elif option_number == 12 and len(value) <= 2:
            content_format = int.from_bytes(value, "big") if value else 0
    body = payload[cursor + 1:] if cursor < len(payload) and payload[cursor] == 0xFF else b""
    code = payload[1]
    return {
        "type": ("Confirmable", "Non-confirmable", "Acknowledgement", "Reset")[payload[0] >> 4 & 0x03],
        "code": f"{code >> 5}.{code & 0x1F:02d}", "message_id": int.from_bytes(payload[2:4], "big"),
        "token": payload[4:4 + token_length].hex(), "path": "/" + "/".join(path),
        "query": "&".join(query), "content_format": content_format, "payload": body,
    }


def _pcap_http2_frames(payload: bytes) -> list[dict[str, Any]]:
    """Return safely framed HTTP/2 DATA payloads from a contiguous cleartext span."""

    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    cursor = len(preface) if payload.startswith(preface) else 0
    frames: list[dict[str, Any]] = []
    names = {0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS", 5: "PUSH_PROMISE", 6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE", 9: "CONTINUATION"}
    for _ in range(16_384):
        if cursor + 9 > len(payload):
            break
        length = int.from_bytes(payload[cursor:cursor + 3], "big")
        frame_type, flags = payload[cursor + 3], payload[cursor + 4]
        stream_id = int.from_bytes(payload[cursor + 5:cursor + 9], "big") & 0x7FFFFFFF
        if length > 16 * 1024 * 1024 or cursor + 9 + length > len(payload) or frame_type > 9:
            break
        body = payload[cursor + 9:cursor + 9 + length]
        cursor += 9 + length
        if frame_type == 0 and flags & 0x08:
            if not body or body[0] >= len(body):
                continue
            body = body[1:len(body) - body[0]]
        frames.append({"type": frame_type, "name": names.get(frame_type, f"TYPE-{frame_type}"), "flags": flags, "stream_id": stream_id, "payload": body})
    return frames


def _pcap_rtp_packet(payload: bytes) -> dict[str, Any] | None:
    if len(payload) < 12 or payload[0] >> 6 != 2:
        return None
    csrc_count = payload[0] & 0x0F
    cursor = 12 + csrc_count * 4
    if cursor > len(payload):
        return None
    if payload[0] & 0x10:
        if cursor + 4 > len(payload):
            return None
        extension_words = int.from_bytes(payload[cursor + 2:cursor + 4], "big")
        cursor += 4 + extension_words * 4
        if cursor > len(payload):
            return None
    end = len(payload)
    if payload[0] & 0x20:
        padding = payload[-1]
        if not padding or padding > end - cursor:
            return None
        end -= padding
    return {
        "payload_type": payload[1] & 0x7F, "marker": bool(payload[1] & 0x80),
        "sequence": int.from_bytes(payload[2:4], "big"),
        "timestamp": int.from_bytes(payload[4:8], "big"),
        "ssrc": int.from_bytes(payload[8:12], "big"), "payload": payload[cursor:end],
    }


def _pcap_g711_sample(value: int, *, alaw: bool) -> int:
    if alaw:
        value ^= 0x55
        magnitude = (value & 0x0F) << 4
        segment = (value & 0x70) >> 4
        magnitude += 8 if segment == 0 else 0x108
        if segment > 1:
            magnitude <<= segment - 1
        return magnitude if value & 0x80 else -magnitude
    value = (~value) & 0xFF
    magnitude = ((value & 0x0F) << 3) + 0x84
    magnitude <<= (value & 0x70) >> 4
    magnitude -= 0x84
    return -magnitude if value & 0x80 else magnitude


def _pcap_pcm_wav(samples: Iterable[int], sample_rate: int = 8000) -> bytes:
    pcm = b"".join(struct.pack("<h", max(-32768, min(32767, int(sample)))) for sample in samples)
    return (
        b"RIFF" + struct.pack("<I", 36 + len(pcm)) + b"WAVEfmt "
        + struct.pack("<IHHIIHH", 16, 1, 1, sample_rate, sample_rate * 2, 2, 16)
        + b"data" + struct.pack("<I", len(pcm)) + pcm
    )


def _pcap_tcp_flag_names(value: Any) -> list[str]:
    if not isinstance(value, int):
        return []
    return [name for bit, name in _PCAP_TCP_FLAG_ORDER if value & bit]


def _pcap_timestamp_seconds(packet: dict[str, Any]) -> float | None:
    timestamp_ns = packet.get("timestamp_ns")
    if isinstance(timestamp_ns, int):
        return timestamp_ns / 1_000_000_000
    value = packet.get("timestamp_key")
    if not isinstance(value, tuple) or len(value) < 2:
        return None
    resolution = packet.get("timestamp_resolution")
    divisor = 1_000_000_000 if resolution == "nanoseconds" else 1_000_000
    return int(value[0]) + int(value[1]) / divisor


def _pcap_payload_previews(payload: bytes, limit: int = 96) -> tuple[str, str, bool]:
    value = payload[:limit]
    text_value = "".join(chr(byte) if byte in {9, 10, 13} or 32 <= byte < 127 else "." for byte in value)
    return text_value, value.hex(), len(payload) > limit


def _pcap_link_name(linktype: Any) -> str:
    return {
        0: "Null/Loopback", 1: "Ethernet", 9: "PPP", 50: "PPP HDLC",
        101: "Raw IP", 108: "Loopback", 113: "Linux SLL", 228: "Raw IPv4",
        189: "USB Linux", 195: "IEEE 802.15.4", 201: "Bluetooth HCI",
        220: "USB Linux mmap", 227: "SocketCAN", 229: "Raw IPv6",
        230: "IEEE 802.15.4 (no FCS)", 251: "Bluetooth LE", 276: "Linux SLL2",
    }.get(linktype, f"LinkType {linktype}" if isinstance(linktype, int) else "Link Layer")


def _pcap_packet_description(packet: dict[str, Any]) -> dict[str, Any]:
    """Build a display-oriented protocol label and Info-column summary."""

    payload = bytes(packet.get("payload") or b"")
    protocol_number = packet.get("protocol")
    transport = _PCAP_IP_PROTOCOL_NAMES.get(protocol_number, f"IP/{protocol_number}" if protocol_number is not None else "Data")
    source_port = packet.get("source_port")
    destination_port = packet.get("destination_port")
    flags = _pcap_tcp_flag_names(packet.get("tcp_flags"))
    result: dict[str, Any] = {"protocol": transport, "transport": transport, "flags": flags}

    if packet.get("special_protocol") == "CAN":
        can_id = int(packet.get("can_id") or 0)
        width = 8 if packet.get("can_extended") else 3
        qualifiers = [
            name for enabled, name in (
                (packet.get("can_extended"), "EFF"), (packet.get("can_rtr"), "RTR"),
                (packet.get("can_error"), "ERR"), (packet.get("can_fd"), "FD"),
            ) if enabled
        ]
        suffix = f" [{', '.join(qualifiers)}]" if qualifiers else ""
        result.update({
            "protocol": "CAN", "transport": "CAN",
            "info": f"0x{can_id:0{width}X}{suffix} DLC={packet.get('can_dlc', len(payload))} Data={payload.hex(' ')}",
        })
        return result

    if packet.get("special_protocol") == "ARP":
        operation = int(packet.get("arp_operation") or 0)
        sender_ip = str(packet.get("arp_sender_ip") or packet.get("source") or "?")
        target_ip = str(packet.get("arp_target_ip") or packet.get("destination") or "?")
        sender_mac = str(packet.get("arp_sender_mac") or "?")
        info = f"Who has {target_ip}? Tell {sender_ip}" if operation == 1 else f"{sender_ip} is at {sender_mac}"
        result.update({"protocol": "ARP", "transport": "ARP", "info": info})
        return result

    dns = None
    if protocol_number in {6, 17} and (source_port == 53 or destination_port == 53):
        dns = _pcap_dns_message(payload, tcp=protocol_number == 6)
    if dns:
        result["protocol"] = "DNS"
        result["dns"] = dns
        question = (dns.get("question_details") or [{}])[0]
        name = str(question.get("name") or "")
        type_name = _PCAP_DNS_TYPE_NAMES.get(question.get("type"), str(question.get("type") or ""))
        if dns.get("response"):
            answer_text = [str(item.get("text")) for item in dns.get("answers", []) if item.get("section") != "question" and item.get("text")]
            result["info"] = f"Standard query response 0x{dns['transaction_id']:04x} {type_name} {name}" + (f" {', '.join(answer_text[:3])}" if answer_text else "")
        else:
            result["info"] = f"Standard query 0x{dns['transaction_id']:04x} {type_name} {name}".rstrip()
        return result

    http = _pcap_http_message(payload)
    if http:
        result["protocol"] = "HTTP"
        result["http"] = http
        if http.get("response"):
            result["info"] = f"{http.get('version') or 'HTTP'} {http.get('status_code') or http.get('target')} {http.get('reason') or ''}".rstrip()
        else:
            host = f" ({http['host']})" if http.get("host") else ""
            result["info"] = f"{http.get('method')} {http.get('target')}{host}"
        return result

    tls = _pcap_tls_records(payload)
    if tls:
        result["protocol"] = "TLS"
        result["tls"] = tls
        handshakes = [handshake for record in tls for handshake in record.get("handshakes", [])]
        names = [str(item.get("name")) for item in handshakes if item.get("name")]
        server_names = [name for item in handshakes for name in item.get("server_names", [])]
        result["info"] = ", ".join(names[:4]) or ", ".join(str(item.get("content_name")) for item in tls[:4])
        if server_names:
            result["info"] += f" SNI={server_names[0]}"
        return result

    if protocol_number == 17 and (source_port == 69 or destination_port == 69) and len(payload) >= 2:
        opcode = int.from_bytes(payload[:2], "big")
        names = {1: "Read Request", 2: "Write Request", 3: "Data", 4: "Acknowledgement", 5: "Error", 6: "Option Acknowledgement"}
        result["protocol"] = "TFTP"
        if opcode in {1, 2}:
            filename = payload[2:].split(b"\x00", 1)[0].decode("utf-8", "replace")
            result["info"] = f"{names[opcode]}, File: {filename}"
        elif opcode in {3, 4} and len(payload) >= 4:
            result["info"] = f"{names[opcode]}, Block: {int.from_bytes(payload[2:4], 'big')}"
        else:
            result["info"] = names.get(opcode, f"Opcode {opcode}")
        return result

    if protocol_number == 17 and (source_port in {67, 68} or destination_port in {67, 68}):
        dhcp = _pcap_dhcp_message(payload)
        if dhcp:
            result.update({
                "protocol": "DHCP", "dhcp": dhcp,
                "info": f"{dhcp['message_type']} xid={dhcp['transaction_id']}"
                + (f" Host={dhcp['hostname']}" if dhcp.get("hostname") else "")
                + (f" Requested={dhcp['requested_ip']}" if dhcp.get("requested_ip") else ""),
            })
            return result

    if protocol_number == 17 and (source_port in {5683, 5684} or destination_port in {5683, 5684}):
        coap = _pcap_coap_message(payload)
        if coap:
            suffix = f"?{coap['query']}" if coap.get("query") else ""
            result.update({
                "protocol": "CoAP", "coap": coap,
                "info": f"{coap['type']} {coap['code']} {coap['path']}{suffix} Len={len(bytes(coap['payload']))}",
            })
            return result

    ports = {source_port, destination_port}
    if protocol_number == 6 and 1883 in ports:
        mqtt = _pcap_mqtt_messages(payload)
        if mqtt:
            publish = next((item for item in mqtt if item.get("name") == "PUBLISH"), mqtt[0])
            result.update({
                "protocol": "MQTT", "mqtt": mqtt,
                "info": f"{publish.get('name')}" + (f" Topic={publish.get('topic')} Len={len(bytes(publish.get('payload') or b''))}" if publish.get("topic") else ""),
            })
            return result
    if protocol_number == 6 and 502 in ports:
        modbus = _pcap_modbus_payloads(payload)
        if modbus:
            item = modbus[0]
            result.update({
                "protocol": "MODBUS", "modbus": modbus,
                "info": f"Transaction {item['transaction_id']} Unit {item['unit_id']} Function {item['function'] & 0x7F}" + (" Exception" if item["exception"] else ""),
            })
            return result
    if protocol_number == 6 and ports & {80, 443, 8080, 8443}:
        http2 = _pcap_http2_frames(payload)
        if http2 and (payload.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") or any(item["name"] == "DATA" for item in http2)):
            data = next((item for item in http2 if item["name"] == "DATA"), http2[0])
            result.update({
                "protocol": "HTTP2", "http2": http2,
                "info": f"{data['name']} Stream={data['stream_id']} Len={len(bytes(data['payload']))}",
            })
            return result
    if protocol_number == 17:
        rtp = _pcap_rtp_packet(payload)
        if rtp and all(isinstance(port, int) and port >= 1024 for port in ports):
            result.update({
                "protocol": "RTP", "rtp": rtp,
                "info": f"PT={rtp['payload_type']} SSRC=0x{rtp['ssrc']:08X} Seq={rtp['sequence']} Time={rtp['timestamp']} Len={len(rtp['payload'])}",
            })
            return result

    service = None
    if payload:
        if protocol_number == 6:
            if 22 in ports and payload.startswith(b"SSH-"):
                service = "SSH"
            elif ports & {20, 21}:
                service = "FTP"
            elif ports & {25, 465, 587}:
                service = "SMTP"
            elif 110 in ports:
                service = "POP"
            elif ports & {143, 993}:
                service = "IMAP"
            elif 445 in ports:
                service = "SMB"
            elif 443 in ports:
                service = "TLS"
        elif protocol_number == 17:
            if ports & {67, 68}:
                service = "DHCP"
            elif 123 in ports:
                service = "NTP"
            elif ports & {161, 162}:
                service = "SNMP"
            elif 443 in ports:
                service = "QUIC"
    if service:
        result["protocol"] = service

    if protocol_number == 6:
        flag_text = f" [{', '.join(flags)}]" if flags else ""
        result["info"] = (
            f"{source_port} → {destination_port}{flag_text} Seq={packet.get('sequence') or 0} "
            f"Ack={packet.get('acknowledgement') or 0} Win={packet.get('tcp_window') or 0} Len={len(payload)}"
        )
    elif protocol_number == 17:
        result["info"] = f"{source_port} → {destination_port} Len={len(payload)}"
    elif protocol_number in {1, 58}:
        type_name = {
            (1, 8): "Echo (ping) request", (1, 0): "Echo (ping) reply",
            (58, 128): "Echo request", (58, 129): "Echo reply",
        }.get((protocol_number, packet.get("icmp_type")), f"Type {packet.get('icmp_type')}")
        result["info"] = f"{type_name}, id=0x{int(packet.get('icmp_id') or 0):04x}, seq={packet.get('icmp_sequence') or 0}, ttl={packet.get('ttl')}"
    else:
        result["info"] = f"{transport} payload ({len(payload)} bytes)"
    return result


def _pcap_traffic_inspection(
    records: list[dict[str, Any]], profile: str, tftp_objects: list[dict[str, Any]],
) -> dict[str, Any]:
    """Produce a bounded, JSON-only traffic model for the capture workspace UI."""

    limits = {
        "packet_rows": 1_000 if profile == "quick" else 5_000 if profile == "balanced" else 15_000,
        "endpoints": 1_024 if profile == "quick" else 4_096 if profile == "balanced" else 16_384,
        "conversations": 1_024 if profile == "quick" else 4_096 if profile == "balanced" else 16_384,
        "summaries": 500 if profile == "quick" else 2_000 if profile == "balanced" else 8_000,
        "events": 1_000 if profile == "quick" else 4_000 if profile == "balanced" else 12_000,
        "stream_preview_bytes": 2_048 if profile == "quick" else 8_192 if profile == "balanced" else 32_768,
    }
    packet_rows: list[dict[str, Any]] = []
    protocol_stats: defaultdict[tuple[str, ...], dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})
    endpoint_stats: dict[str, dict[str, Any]] = {}
    endpoint_overflow = False
    conversations: dict[tuple[Any, ...], dict[str, Any]] = {}
    conversation_overflow = False
    protocol_indexes: Counter[str] = Counter()
    packet_stream_ids: dict[int, str] = {}
    dns_summaries: list[dict[str, Any]] = []
    http_summaries: list[dict[str, Any]] = []
    tls_summaries: list[dict[str, Any]] = []
    object_summaries: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    summary_counts: Counter[str] = Counter()
    first_timestamp = next((value for value in (_pcap_timestamp_seconds(packet) for packet in records) if value is not None), None)

    def add_event(event_type: str, packet: dict[str, Any], title: str, **details: Any) -> None:
        summary_counts["events"] += 1
        if len(events) >= limits["events"]:
            return
        events.append({
            "id": f"event-{summary_counts['events']}", "type": event_type,
            "packet": packet.get("number"), "timestamp_epoch": _pcap_timestamp_seconds(packet),
            "title": title, "details": details,
        })

    def endpoint(address: Any, *, sent: bool, frame_length: int, port: Any, protocols: list[str]) -> None:
        nonlocal endpoint_overflow
        if address is None:
            return
        key = str(address)
        if key not in endpoint_stats:
            if len(endpoint_stats) >= limits["endpoints"]:
                endpoint_overflow = True
                return
            endpoint_stats[key] = {
                "address": key, "sent_packets": 0, "sent_bytes": 0,
                "received_packets": 0, "received_bytes": 0,
                "ports": set(), "protocols": Counter(),
            }
        item = endpoint_stats[key]
        direction = "sent" if sent else "received"
        item[f"{direction}_packets"] += 1
        item[f"{direction}_bytes"] += frame_length
        if isinstance(port, int):
            item["ports"].add(port)
        item["protocols"].update(protocols)

    def conversation_for(packet: dict[str, Any]) -> dict[str, Any] | None:
        nonlocal conversation_overflow
        source, destination = packet.get("source"), packet.get("destination")
        if source is None or destination is None:
            return None
        protocol = str(packet.get("special_protocol") or _PCAP_IP_PROTOCOL_NAMES.get(packet.get("protocol"), f"IP/{packet.get('protocol')}"))
        source_port = packet.get("source_port") if isinstance(packet.get("source_port"), int) else None
        destination_port = packet.get("destination_port") if isinstance(packet.get("destination_port"), int) else None
        source_key = (str(source), source_port if source_port is not None else -1)
        destination_key = (str(destination), destination_port if destination_port is not None else -1)
        left, right = sorted((source_key, destination_key))
        key = (protocol, left, right)
        if key not in conversations:
            if len(conversations) >= limits["conversations"]:
                conversation_overflow = True
                return None
            protocol_indexes[protocol.lower()] += 1
            conversations[key] = {
                "id": f"{protocol.lower()}-{protocol_indexes[protocol.lower()] - 1}", "protocol": protocol,
                "endpoint_a": {"address": left[0], "port": None if left[1] == -1 else left[1]},
                "endpoint_b": {"address": right[0], "port": None if right[1] == -1 else right[1]},
                "packets": 0, "bytes": 0, "payload_bytes": 0,
                "a_to_b": {"packets": 0, "bytes": 0, "payload_bytes": 0},
                "b_to_a": {"packets": 0, "bytes": 0, "payload_bytes": 0},
                "first_packet": packet.get("number"), "last_packet": packet.get("number"),
                "start_time": _pcap_timestamp_seconds(packet), "end_time": _pcap_timestamp_seconds(packet),
                "_a_packets": [], "_b_packets": [], "_flags": set(), "_applications": Counter(),
                "_packet_numbers": [],
            }
        item = conversations[key]
        frame_length = int(packet.get("frame_length", 0))
        payload_length = len(bytes(packet.get("payload") or b""))
        a_to_b = source_key == left
        direction = "a_to_b" if a_to_b else "b_to_a"
        item["packets"] += 1
        item["bytes"] += frame_length
        item["payload_bytes"] += payload_length
        item[direction]["packets"] += 1
        item[direction]["bytes"] += frame_length
        item[direction]["payload_bytes"] += payload_length
        item["last_packet"] = packet.get("number")
        timestamp = _pcap_timestamp_seconds(packet)
        if timestamp is not None:
            item["start_time"] = timestamp if item["start_time"] is None else min(item["start_time"], timestamp)
            item["end_time"] = timestamp if item["end_time"] is None else max(item["end_time"], timestamp)
        item["_flags"].update(_pcap_tcp_flag_names(packet.get("tcp_flags")))
        item["_packet_numbers"].append(packet.get("number"))
        item["_a_packets" if a_to_b else "_b_packets"].append(packet)
        packet_stream_ids[id(packet)] = str(item["id"])
        return item

    def dns_summary(packet: dict[str, Any], parsed: dict[str, Any], stream_id: str | None, *, reassembled: bool = False) -> None:
        summary_counts["dns"] += 1
        if len(dns_summaries) >= limits["summaries"]:
            return
        questions = [
            {"name": item.get("name", ""), "type": item.get("type"), "type_name": _PCAP_DNS_TYPE_NAMES.get(item.get("type"), str(item.get("type"))), "class": item.get("class")}
            for item in parsed.get("question_details", [])[:32]
        ]
        answers = [
            {"section": item.get("section"), "name": item.get("name"), "type": item.get("type"), "type_name": _PCAP_DNS_TYPE_NAMES.get(item.get("type"), str(item.get("type"))), "ttl": item.get("ttl"), "text": item.get("text", "")}
            for item in parsed.get("answers", []) if item.get("section") != "question"
        ][:64]
        dns_summaries.append({
            "packet": packet.get("number"), "stream_id": stream_id, "timestamp_epoch": _pcap_timestamp_seconds(packet),
            "source": packet.get("source"), "destination": packet.get("destination"),
            "transaction_id": parsed.get("transaction_id"), "response": bool(parsed.get("response")),
            "response_code": parsed.get("response_code"), "questions": questions, "answers": answers,
            "reassembled": reassembled,
        })

    def http_summary(packet: dict[str, Any], parsed: dict[str, Any], stream_id: str | None, *, reassembled: bool = False) -> None:
        summary_counts["http"] += 1
        if len(http_summaries) >= limits["summaries"]:
            return
        headers = {str(key)[:128]: str(value)[:512] for key, value in list(parsed.get("headers", {}).items())[:64]}
        body = bytes(parsed.get("body") or b"")
        item = {
            "packet": packet.get("number"), "stream_id": stream_id, "timestamp_epoch": _pcap_timestamp_seconds(packet),
            "source": packet.get("source"), "source_port": packet.get("source_port"),
            "destination": packet.get("destination"), "destination_port": packet.get("destination_port"),
            "first_line": str(parsed.get("first_line", ""))[:1_024], "request": not bool(parsed.get("response")),
            "method": None if parsed.get("response") else parsed.get("method"), "target": None if parsed.get("response") else parsed.get("target"),
            "status_code": parsed.get("status_code"), "reason": parsed.get("reason", ""), "host": parsed.get("host", ""),
            "content_type": parsed.get("content_type", ""), "body_bytes": len(body), "headers": headers,
            "reassembled": reassembled,
        }
        http_summaries.append(item)
        if body and len(object_summaries) < limits["summaries"]:
            filename = str(parsed.get("filename") or "")
            object_summaries.append({
                "source": "HTTP", "packet": packet.get("number"), "stream_id": stream_id,
                "name": filename or f"http-body-{packet.get('number') or 0}", "content_type": parsed.get("content_type", ""),
                "size": len(body), "detected_type": sniff_kind(body, filename), "reassembled": reassembled,
            })

    def tls_summary(packet: dict[str, Any], parsed: list[dict[str, Any]], stream_id: str | None, *, reassembled: bool = False) -> None:
        for record in parsed:
            summary_counts["tls"] += 1
            if len(tls_summaries) >= limits["summaries"]:
                return
            handshakes = record.get("handshakes", [])[:32]
            tls_summaries.append({
                "packet": packet.get("number"), "stream_id": stream_id, "timestamp_epoch": _pcap_timestamp_seconds(packet),
                "source": packet.get("source"), "destination": packet.get("destination"),
                "content_type": record.get("content_type"), "content_name": record.get("content_name"),
                "version": record.get("version"), "length": record.get("length"), "handshakes": handshakes,
                "reassembled": reassembled,
            })

    for packet in records:
        frame_length = int(packet.get("frame_length", 0))
        payload = bytes(packet.get("payload") or b"")
        description = _pcap_packet_description(packet)
        conversation = conversation_for(packet)
        stream_id = str(conversation["id"]) if conversation else None
        if conversation:
            conversation["_applications"][description["protocol"]] += 1
        source, destination = packet.get("source"), packet.get("destination")
        endpoint(source, sent=True, frame_length=frame_length, port=packet.get("source_port"), protocols=[description["transport"], description["protocol"]])
        endpoint(destination, sent=False, frame_length=frame_length, port=packet.get("destination_port"), protocols=[description["transport"], description["protocol"]])

        layers = ["Frame", _pcap_link_name(packet.get("linktype"))]
        if packet.get("network"):
            layers.append("IPv6" if packet.get("ip_version") == 6 else "IPv4")
            layers.append(description["transport"])
            if description["protocol"] != description["transport"]:
                layers.append(description["protocol"])
        else:
            layers.append(str(packet.get("special_protocol") or "Data"))
        for depth in range(1, len(layers) + 1):
            stats = protocol_stats[tuple(layers[:depth])]
            stats["packets"] += 1
            stats["bytes"] += frame_length

        timestamp = _pcap_timestamp_seconds(packet)
        if len(packet_rows) < limits["packet_rows"]:
            preview, hex_preview, preview_truncated = _pcap_payload_previews(payload)
            packet_rows.append({
                "number": packet.get("number"), "timestamp_epoch": timestamp,
                "relative_time": timestamp - first_timestamp if timestamp is not None and first_timestamp is not None else None,
                "source": source, "source_port": packet.get("source_port"),
                "destination": destination, "destination_port": packet.get("destination_port"),
                "protocol": description["protocol"], "transport": description["transport"], "layers": layers,
                "length": frame_length, "payload_length": len(payload), "info": description.get("info", ""),
                "flags": description["flags"], "stream_id": stream_id, "interface_id": packet.get("interface_id"),
                "payload_preview": preview, "payload_hex_preview": hex_preview, "payload_preview_truncated": preview_truncated,
            })

        if description.get("dns"):
            dns_summary(packet, description["dns"], stream_id)
            add_event("dns-response" if description["dns"].get("response") else "dns-query", packet, description.get("info", "DNS"), stream_id=stream_id)
        if description.get("http"):
            http_summary(packet, description["http"], stream_id)
            add_event("http-response" if description["http"].get("response") else "http-request", packet, description.get("info", "HTTP"), stream_id=stream_id)
        if description.get("tls"):
            tls_summary(packet, description["tls"], stream_id)
            if any(record.get("handshakes") for record in description["tls"]):
                add_event("tls-handshake", packet, description.get("info", "TLS handshake"), stream_id=stream_id)
        if description["protocol"] == "TFTP":
            add_event("tftp", packet, description.get("info", "TFTP"), stream_id=stream_id)
        if description.get("mqtt"):
            add_event("mqtt", packet, description.get("info", "MQTT"), stream_id=stream_id)
        if description.get("modbus"):
            add_event("modbus", packet, description.get("info", "Modbus/TCP"), stream_id=stream_id)
        if description.get("rtp"):
            add_event("rtp", packet, description.get("info", "RTP"), stream_id=stream_id)
        if description["protocol"] == "CAN":
            add_event("can", packet, description.get("info", "CAN frame"), can_id=packet.get("can_id"))
        if packet.get("protocol") in {1, 58}:
            add_event("icmp", packet, description.get("info", "ICMP"), stream_id=stream_id)
        for flag in description["flags"]:
            if flag in {"SYN", "FIN", "RST"}:
                add_event(f"tcp-{flag.lower()}", packet, description.get("info", f"TCP {flag}"), stream_id=stream_id)

    stream_summaries: dict[str, list[dict[str, Any]]] = {"tcp": [], "udp": []}
    conversation_rows: list[dict[str, Any]] = []
    seen_reassembled: set[tuple[Any, ...]] = set()
    for item in sorted(conversations.values(), key=lambda value: (int(value.get("first_packet") or 0), str(value["id"]))):
        start_time, end_time = item.get("start_time"), item.get("end_time")
        row = {
            "id": item["id"], "protocol": item["protocol"], "endpoint_a": item["endpoint_a"], "endpoint_b": item["endpoint_b"],
            "packets": item["packets"], "bytes": item["bytes"], "payload_bytes": item["payload_bytes"],
            "a_to_b": item["a_to_b"], "b_to_a": item["b_to_a"], "first_packet": item["first_packet"], "last_packet": item["last_packet"],
            "start_time": start_time, "end_time": end_time,
            "duration": max(0.0, end_time - start_time) if isinstance(start_time, (int, float)) and isinstance(end_time, (int, float)) else None,
            "flags": _pcap_tcp_flag_names(sum(bit for bit, name in _PCAP_TCP_FLAG_ORDER if name in item["_flags"])),
            "applications": dict(item["_applications"].most_common()), "packet_numbers": item["_packet_numbers"][:128],
            "packet_numbers_truncated": len(item["_packet_numbers"]) > 128,
        }
        conversation_rows.append(row)
        if item["protocol"] not in {"TCP", "UDP"}:
            continue
        direction_rows: list[dict[str, Any]] = []
        for direction_name, packets in (("a_to_b", item["_a_packets"]), ("b_to_a", item["_b_packets"])):
            ordered = sorted(packets, key=lambda packet: int(packet.get("number", 0)))
            spans: list[bytes]
            overlaps = gaps = 0
            if item["protocol"] == "TCP":
                spans, overlaps, gaps = _pcap_reassemble_tcp([
                    (packet.get("sequence"), int(packet.get("number", 0)), bytes(packet.get("payload") or b""))
                    for packet in ordered
                ])
            else:
                spans = [b"".join(bytes(packet.get("payload") or b"") for packet in ordered)]
            assembled = b"".join(spans)
            preview_limit = int(limits["stream_preview_bytes"])
            preview, hex_preview, truncated = _pcap_payload_previews(assembled, preview_limit)
            direction_rows.append({
                "direction": direction_name, "packets": len(ordered), "payload_bytes": len(assembled),
                "span_count": len(spans), "overlap_events": overlaps, "gap_spans": gaps,
                "preview": preview, "hex_preview": hex_preview, "preview_truncated": truncated,
            })
            if not ordered:
                continue
            representative = ordered[0]
            for span in spans:
                parsed_http = _pcap_http_message(span)
                key = (item["id"], direction_name, parsed_http.get("first_line") if parsed_http else None)
                if parsed_http and key not in seen_reassembled:
                    seen_reassembled.add(key)
                    http_summary(representative, parsed_http, str(item["id"]), reassembled=True)
                parsed_tls = _pcap_tls_records(span)
                if parsed_tls and (item["id"], direction_name, "tls") not in seen_reassembled:
                    seen_reassembled.add((item["id"], direction_name, "tls"))
                    tls_summary(representative, parsed_tls, str(item["id"]), reassembled=True)
                if 53 in {item["endpoint_a"].get("port"), item["endpoint_b"].get("port")}:
                    parsed_dns = _pcap_dns_message(span, tcp=item["protocol"] == "TCP")
                    if parsed_dns and (item["id"], direction_name, "dns") not in seen_reassembled:
                        seen_reassembled.add((item["id"], direction_name, "dns"))
                        dns_summary(representative, parsed_dns, str(item["id"]), reassembled=True)
        stream_summaries[item["protocol"].lower()].append({**row, "directions": direction_rows})

    for object_info in tftp_objects[:limits["summaries"]]:
        value = bytes(object_info.get("data") or b"")
        filename = str(object_info.get("filename") or "tftp-object")
        object_summaries.append({
            "source": "TFTP", "packet": object_info.get("packet"), "stream_id": None,
            "name": filename, "content_type": "", "size": len(value), "detected_type": sniff_kind(value, filename),
            "complete": bool(object_info.get("complete")), "block_count": object_info.get("block_count"),
        })

    total_packets = len(records)
    total_bytes = sum(int(packet.get("frame_length", 0)) for packet in records)
    hierarchy = []
    for path, stats in sorted(protocol_stats.items(), key=lambda item: (len(item[0]), item[0])):
        hierarchy.append({
            "path": "/".join(path), "parent": "/".join(path[:-1]) or None,
            "protocol": path[-1], "depth": len(path) - 1, "packets": stats["packets"], "bytes": stats["bytes"],
            "packet_percent": round(stats["packets"] * 100 / total_packets, 4) if total_packets else 0.0,
            "byte_percent": round(stats["bytes"] * 100 / total_bytes, 4) if total_bytes else 0.0,
        })
    endpoints = []
    for item in sorted(endpoint_stats.values(), key=lambda value: (-(value["sent_packets"] + value["received_packets"]), value["address"])):
        endpoints.append({
            "address": item["address"], "packets": item["sent_packets"] + item["received_packets"],
            "bytes": item["sent_bytes"] + item["received_bytes"], "sent_packets": item["sent_packets"],
            "sent_bytes": item["sent_bytes"], "received_packets": item["received_packets"], "received_bytes": item["received_bytes"],
            "ports": sorted(item["ports"])[:256], "ports_truncated": len(item["ports"]) > 256,
            "protocols": dict(item["protocols"].most_common()),
        })
    return {
        "schema_version": 1, "packet_rows": packet_rows,
        "packet_rows_truncated": total_packets > len(packet_rows), "protocol_hierarchy": hierarchy,
        "endpoints": endpoints, "endpoints_truncated": endpoint_overflow,
        "conversations": conversation_rows, "conversations_truncated": conversation_overflow,
        "streams": stream_summaries, "dns": dns_summaries, "http": http_summaries, "tls": tls_summaries,
        "objects": object_summaries[:limits["summaries"]], "events": events,
        "truncated": {
            "dns": summary_counts["dns"] > len(dns_summaries), "http": summary_counts["http"] > len(http_summaries),
            "tls": summary_counts["tls"] > len(tls_summaries), "objects": len(object_summaries) > limits["summaries"],
            "events": summary_counts["events"] > len(events),
        },
        "limits": limits,
    }


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
    arp_records: list[dict[str, Any]] = []
    dhcp_messages: list[dict[str, Any]] = []
    coap_messages: list[dict[str, Any]] = []
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
        strong_signature = any(
            value.startswith(signature)
            for signature in (
                b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"BM",
                b"RIFF", b"PK\x03\x04", b"PK\x05\x06", b"%PDF-", b"BZh", b"\x1f\x8b",
                b"fLaC", b"OggS", b"MThd", b"SQLite format 3\x00", b"Salted__",
                *_PCAP_CLASSIC_MAGICS, _PCAPNG_MAGIC,
            )
        )
        flags = _pcap_flag_values(value)
        direct_flag_hits.update(flags)
        # sniff_kind performs several format probes. A candidate without a
        # known prefix cannot be promoted as a file here, so skip those probes.
        kind = sniff_kind(value, source) if strong_signature else "binary"
        minimum_capture_length = 28 if value.startswith(_PCAPNG_MAGIC) else 24 if value.startswith(_PCAP_CLASSIC_MAGICS) else 16
        meaningful_file = len(value) >= minimum_capture_length and strong_signature and (kind not in {"binary", "text"} or value.startswith(b"Salted__"))
        if not flags and not meaningful_file and not force_artifact:
            return False
        new_flags = flags - promoted_flags
        if flags and not new_flags and not meaningful_file and not force_artifact:
            return False
        signature_key = (kind, value[:16])
        if meaningful_file and not flags and signature_key in promoted_file_signatures and not force_artifact:
            return False
        if flags:
            add_text(value.decode("latin-1", "ignore"), source, offset, 11 if flags else 7, [transform] if transform else None)
        if value not in recovered_seen and (flags or meaningful_file or force_artifact):
            recovered_seen.add(value)
            promoted_flags.update(flags)
            if meaningful_file:
                promoted_file_signatures.add(signature_key)
            result["extracted"].append({
                "label": safe_label(f"pcap_{source}_recovered"), "data": value,
                "kind": kind if meaningful_file else "text",
                "producer": "pcap-network-forensics", "transformation": transform or "packet stream reconstruction",
                "reason": "A flag-shaped value or recognized file signature validated the bounded recovery.",
            })
            decoded_recoveries += 1
        return bool(flags or meaningful_file)

    def try_variants(value: bytes, source: str, offset: int | None, *, include_direct: bool = False) -> int:
        found = 0
        # Text encodings are overwhelmingly printable. Avoid the regex-heavy
        # Base64/Base32/hex pipeline for ordinary binary header streams while
        # retaining direct/magic-prefix recovery for them.
        decode_eligible = (
            len(value) <= 8 * 1024 * 1024
            and (_pcap_printable(value, 0.72) or (b"{" in value and b"}" in value))
        )
        variants = _pcap_decode_variants(value) if decode_eligible else [("direct", value)]
        variants.extend(_pcap_magic_byte_variants(value))
        direct_signature = any(value.startswith(prefix) for prefix in _PCAP_MAGIC_PREFIXES)
        for index, (transform, decoded) in enumerate(variants):
            # Direct packet streams are normally covered elsewhere; retain
            # one here when the stream itself begins with a known file/capture
            # signature so nested PCAPs and raw objects are not beaten by a
            # later trim/decode variant with the same signature.
            if index == 0 and not include_direct and not direct_signature:
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
        if packet.get("special_protocol") == "ARP":
            arp_records.append(packet)
            arp_clue = (
                f"ARP operation={packet.get('arp_operation')} sender={packet.get('arp_sender_ip')} "
                f"sender_mac={packet.get('arp_sender_mac')} target={packet.get('arp_target_ip')} "
                f"target_mac={packet.get('arp_target_mac')}"
            )
            add_text(arp_clue, "pcap-arp", packet.get("frame_offset"), 6)
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
        if protocol == 17 and {packet.get("source_port"), packet.get("destination_port")} & {67, 68}:
            dhcp = _pcap_dhcp_message(payload)
            if dhcp:
                dhcp_messages.append({"packet": packet.get("number"), **dhcp})
                clue_values = [
                    str(value) for key, value in dhcp.items()
                    if key in {"hostname", "domain", "vendor_class", "user_class", "bootfile"} and value
                ]
                for clue in clue_values:
                    encoded = clue.encode("utf-8", "replace")
                    add_text(clue, "pcap-dhcp-option", packet.get("frame_offset"), 8)
                    direct_flag_hits.update(_pcap_flag_values(encoded))
                    try_variants(encoded, "dhcp-option", packet.get("frame_offset"), include_direct=True)
        if protocol == 17 and {packet.get("source_port"), packet.get("destination_port")} & {5683, 5684}:
            coap = _pcap_coap_message(payload)
            if coap:
                coap_messages.append({"packet": packet.get("number"), **{key: value for key, value in coap.items() if key != "payload"}})
                body = bytes(coap.get("payload") or b"")
                if body:
                    direct_flag_hits.update(_pcap_flag_values(body))
                    if _pcap_printable(body):
                        add_text(body.decode("utf-8", "replace"), "pcap-coap-payload", packet.get("frame_offset"), 9, ["CoAP option/data decoding"])
                    try_variants(body, "coap-payload", packet.get("frame_offset"), include_direct=True)
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
    tcp_spans_by_flow: dict[tuple[Any, ...], list[bytes]] = {}
    for flow, fragments in tcp_flows.items():
        if len(fragments) < 2:
            payload = bytes(fragments[0][2]) if fragments and fragments[0][2] else b""
            spans, overlaps, gaps = ([payload] if payload else []), 0, 0
        else:
            spans, overlaps, gaps = _pcap_reassemble_tcp(fragments)
        tcp_spans_by_flow[flow] = spans
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
            # A one-packet HTTP message was already collected during packet
            # iteration; only add the stream view when it actually reassembled
            # multiple segments, otherwise POST bodies would be duplicated in
            # correlated exfiltration recoveries.
            if message and len(fragments) > 1:
                message.update({"packet": fragments[0][1], "source": flow[0], "destination": flow[2], "source_port": flow[1], "destination_port": flow[3], "reassembled": True})
                http_messages.append(message)

    # Native HTTP/2 recovery complements the external TShark dissector for
    # cleartext/h2c challenges. Once a connection presents the HTTP/2 preface,
    # DATA frames from either direction are grouped by stream and fed through
    # the ordinary bounded file/flag recovery pipeline.
    http2_connections: set[tuple[str, str]] = set()
    for flow, spans in tcp_spans_by_flow.items():
        if {flow[1], flow[3]} & {80, 443, 8080, 8443} and any(span.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") for span in spans):
            http2_connections.add(tuple(sorted((str(flow[0]), str(flow[2])))))
    http2_streams: defaultdict[tuple[tuple[str, str], int], list[bytes]] = defaultdict(list)
    http2_frames = 0
    for flow, spans in tcp_spans_by_flow.items():
        connection = tuple(sorted((str(flow[0]), str(flow[2]))))
        if connection not in http2_connections:
            continue
        for span in spans:
            for frame in _pcap_http2_frames(span):
                http2_frames += 1
                if frame["name"] == "DATA" and frame["payload"]:
                    http2_streams[(connection, int(frame["stream_id"]))].append(bytes(frame["payload"]))
    http2_exports = 0
    for (connection, stream_id), parts in http2_streams.items():
        assembled = b"".join(parts)
        if not assembled or len(assembled) > 64 * 1024 * 1024:
            continue
        direct_flag_hits.update(_pcap_flag_values(assembled))
        if _pcap_printable(assembled):
            add_text(assembled.decode("latin-1", "ignore"), "pcap-http2-data", None, 9, [f"HTTP/2 stream {stream_id} DATA reassembly"])
        http2_exports += try_variants(assembled, f"http2-stream-{stream_id}", None, include_direct=True)

    # Application formats that routinely appear in PCAP CTFs. They are parsed
    # from contiguous TCP spans rather than trusting packet boundaries.
    mqtt_publishes = 0
    websocket_messages = 0
    modbus_messages = 0
    mqtt_topics: set[str] = set()
    modbus_payloads: list[bytes] = []
    cleartext_credentials: list[dict[str, Any]] = []
    credential_seen: set[tuple[str, str, str]] = set()
    for flow, fragments in tcp_flows.items():
        ports = {flow[1], flow[3]}
        if not ports & {21, 23, 25, 80, 110, 143, 502, 1883}:
            continue
        spans = tcp_spans_by_flow.get(flow, [])
        for span in spans:
            if not span:
                continue
            if 1883 in ports:
                for message in _pcap_mqtt_messages(span):
                    if message.get("name") != "PUBLISH":
                        continue
                    body = bytes(message.get("payload") or b"")
                    topic = str(message.get("topic") or "")
                    mqtt_publishes += 1
                    if topic:
                        mqtt_topics.add(topic)
                        add_text(topic, "pcap-mqtt-topic", None, 7)
                    if body:
                        direct_flag_hits.update(_pcap_flag_values(body))
                        if _pcap_printable(body):
                            add_text(body.decode("latin-1", "ignore"), "pcap-mqtt-publish", None, 9, [f"MQTT PUBLISH topic {topic or '(unnamed)'}"])
                        try_variants(body, "mqtt-publish", None, include_direct=True)
            if 502 in ports:
                for message in _pcap_modbus_payloads(span):
                    modbus_messages += 1
                    body = bytes(message.get("data") or b"")
                    if body:
                        modbus_payloads.append(body)
                        direct_flag_hits.update(_pcap_flag_values(body))
                        try_variants(body, "modbus-register-data", None, include_direct=True)
            if b"upgrade: websocket" in span.lower() or (80 in ports and span[:1] in {b"\x81", b"\x82"}):
                for frame in _pcap_websocket_frames(span):
                    if frame.get("name") not in {"text", "binary"}:
                        continue
                    body = bytes(frame.get("payload") or b"")
                    if not body:
                        continue
                    websocket_messages += 1
                    direct_flag_hits.update(_pcap_flag_values(body))
                    if _pcap_printable(body):
                        add_text(body.decode("latin-1", "ignore"), "pcap-websocket-message", None, 9, ["RFC 6455 frame reassembly"])
                    try_variants(body, "websocket-frame", None, include_direct=True)
            # FTP, SMTP, POP3, IMAP, and Telnet are often deliberately clear
            # text. Preserve candidate credentials as findings instead of
            # attempting password cracking or network interaction.
            if ports & {21, 23, 25, 110, 143} and _pcap_printable(span, 0.85):
                for match in re.finditer(rb"(?im)^(USER|PASS|LOGIN|AUTH(?:\s+PLAIN)?)\s+([^\r\n]{1,256})", span):
                    command = match.group(1).decode("ascii", "ignore").upper()
                    value = match.group(2).decode("utf-8", "replace").strip()
                    key = (str(flow[0]), command, value)
                    if key not in credential_seen and len(cleartext_credentials) < 256:
                        credential_seen.add(key)
                        cleartext_credentials.append({"protocol_ports": sorted(int(port) for port in ports if isinstance(port, int)), "source": str(flow[0]), "destination": str(flow[2]), "command": command, "value": value})
    if modbus_payloads:
        try_variants(b"".join(modbus_payloads), "modbus-register-concatenation", None, include_direct=True)

    # SocketCAN captures have a dedicated data-link type rather than IP. CTFs
    # frequently encode text per arbitration ID, column, or ISO-TP message.
    can_frames = [packet for packet in records if packet.get("special_protocol") == "CAN"]
    can_groups: defaultdict[int, list[dict[str, Any]]] = defaultdict(list)
    for packet in can_frames:
        if isinstance(packet.get("can_id"), int):
            can_groups[int(packet["can_id"])].append(packet)
    can_messages: list[dict[str, Any]] = []
    can_recoveries = 0
    for can_id, packets in can_groups.items():
        ordered = sorted(packets, key=_pcap_timestamp_key)
        payloads = [bytes(packet.get("payload") or b"") for packet in ordered if packet.get("payload") and not packet.get("can_rtr")]
        if not payloads:
            continue
        combined = b"".join(payloads)
        can_recoveries += try_variants(combined, f"can-id-{can_id:03x}-concatenated", None, include_direct=True)
        for column in range(min(64, max(map(len, payloads)))):
            lane = bytes(value[column] for value in payloads if column < len(value))
            if len(lane) >= 4 and len(set(lane)) > 1:
                can_recoveries += try_variants(lane, f"can-id-{can_id:03x}-byte-{column}", None, include_direct=True)
        pending = bytearray()
        expected = 0
        target_length = 0
        for packet in ordered:
            data_value = bytes(packet.get("payload") or b"")
            if not data_value:
                continue
            frame_type = data_value[0] >> 4
            if frame_type == 0:
                length = data_value[0] & 0x0F
                message = data_value[1:1 + length]
                if message:
                    can_messages.append({"can_id": can_id, "packet": packet.get("number"), "kind": "ISO-TP single", "length": len(message), "data_hex": message.hex()})
                    can_recoveries += try_variants(message, f"can-id-{can_id:03x}-isotp", None, include_direct=True)
            elif frame_type == 1 and len(data_value) >= 2:
                target_length = ((data_value[0] & 0x0F) << 8) | data_value[1]
                pending = bytearray(data_value[2:])
                expected = 1
            elif frame_type == 2 and pending and (data_value[0] & 0x0F) == expected % 16:
                pending.extend(data_value[1:])
                expected += 1
                if target_length and len(pending) >= target_length:
                    message = bytes(pending[:target_length])
                    can_messages.append({"can_id": can_id, "packet": packet.get("number"), "kind": "ISO-TP multi", "length": len(message), "data_hex": message.hex()})
                    can_recoveries += try_variants(message, f"can-id-{can_id:03x}-isotp", None, include_direct=True)
                    pending = bytearray()
                    target_length = 0

    # RTP telephone-event payloads carry DTMF digits directly. For PCMU/PCMA
    # streams, emit a standard WAV child artifact so normal audio analysis can
    # continue with codecs/tone decoders without invoking a player.
    rtp_groups: defaultdict[tuple[Any, ...], list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    for flow, packets in udp_flows.items():
        for packet in packets:
            parsed = _pcap_rtp_packet(bytes(packet.get("payload") or b""))
            if not parsed:
                continue
            rtp_groups[(flow[0], flow[1], flow[2], flow[3], parsed["ssrc"], parsed["payload_type"])].append((packet, parsed))
    rtp_dtmf: list[dict[str, Any]] = []
    rtp_audio_exports = 0
    dtmf_seen: set[tuple[Any, ...]] = set()
    symbols = "0123456789*#ABCD"
    for flow, entries in rtp_groups.items():
        ordered = sorted(entries, key=lambda item: (int(item[1]["sequence"]), _pcap_timestamp_key(item[0])))
        payload_type = int(flow[-1])
        if payload_type == 101:
            for packet, parsed in ordered:
                body = bytes(parsed["payload"])
                if len(body) < 4 or body[0] >= len(symbols):
                    continue
                key = (*flow[:-1], parsed["timestamp"], body[0])
                if key in dtmf_seen:
                    continue
                dtmf_seen.add(key)
                rtp_dtmf.append({"packet": packet.get("number"), "stream": f"0x{parsed['ssrc']:08X}", "symbol": symbols[body[0]], "duration": int.from_bytes(body[2:4], "big"), "end": bool(body[1] & 0x80)})
        if payload_type not in {0, 8} or len(ordered) < 2:
            continue
        encoded = b"".join(bytes(parsed["payload"]) for _packet, parsed in ordered)
        if not encoded or len(encoded) > 16 * 1024 * 1024:
            continue
        wav = _pcap_pcm_wav((_pcap_g711_sample(byte, alaw=payload_type == 8) for byte in encoded))
        register_candidate(wav, f"rtp-{'pcma' if payload_type == 8 else 'pcmu'}-stream", None, "RTP G.711 payload reassembly to PCM WAV", force_artifact=True)
        rtp_audio_exports += 1

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

    # BitTorrent DHT requests identify a torrent by its 20-byte info-hash. A
    # published picoCTF challenge requires surfacing this value rather than
    # reconstructing the peer-to-peer transfer itself.
    dht_info_hashes: list[dict[str, Any]] = []
    dht_seen: set[tuple[str, str]] = set()
    for flow, packets in udp_flows.items():
        for packet in packets:
            payload = bytes(packet.get("payload") or b"")
            for match in re.finditer(rb"(?:9:info_hash|9:info-hash)20:(.{20})", payload, re.DOTALL):
                value = match.group(1).hex()
                key = (str(packet.get("source")), value)
                if key in dht_seen or len(dht_info_hashes) >= 1024:
                    continue
                dht_seen.add(key)
                dht_info_hashes.append({"packet": packet.get("number"), "source": packet.get("source"), "destination": packet.get("destination"), "info_hash": value})

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

    # ICMP payload channels range from a direct ping-data concatenation to one
    # changing byte surrounded by the operating system's repeated padding.
    # Try the full stream, per-byte columns, and data after removing the common
    # prefix/suffix. Candidates still require a flag or file signature before
    # they become artifacts, which keeps ordinary ping traffic quiet.
    icmp_stream_recoveries = 0
    icmp_groups: defaultdict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for packet in records:
        if packet.get("protocol") in {1, 58} and packet.get("payload"):
            icmp_groups[(
                packet.get("source"), packet.get("destination"), packet.get("protocol"),
                packet.get("icmp_type"), packet.get("icmp_code"), packet.get("icmp_id"),
            )].append(packet)
    column_limit = 128 if profile == "quick" else 512 if profile == "balanced" else 2_048
    for group, packets in icmp_groups.items():
        ordered = sorted(packets, key=_pcap_timestamp_key)
        payloads = [bytes(packet.get("payload") or b"") for packet in ordered]
        if len(payloads) < 2:
            continue
        candidates: list[tuple[str, bytes]] = [("capture-order payload concatenation", b"".join(payloads))]
        minimum_length = min(map(len, payloads))
        prefix_length = 0
        while prefix_length < minimum_length and len({value[prefix_length] for value in payloads}) == 1:
            prefix_length += 1
        suffix_length = 0
        while suffix_length < minimum_length - prefix_length and len({value[-1 - suffix_length] for value in payloads}) == 1:
            suffix_length += 1
        stripped = b"".join(
            value[prefix_length:len(value) - suffix_length if suffix_length else len(value)] for value in payloads
        )
        if stripped:
            candidates.append((f"remove common prefix ({prefix_length}) and suffix ({suffix_length})", stripped))
        candidates.extend((
            ("first payload byte from each packet", bytes(value[0] for value in payloads if value)),
            ("last payload byte from each packet", bytes(value[-1] for value in payloads if value)),
        ))
        for column in range(min(max(map(len, payloads)), column_limit)):
            lane = bytes(value[column] for value in payloads if column < len(value))
            if len(lane) >= 4:
                candidates.append((f"payload byte column {column}", lane))
        candidate_seen: set[bytes] = set()
        for transform, candidate in candidates:
            if len(candidate) < 4 or len(candidate) > 16 * 1024 * 1024 or candidate in candidate_seen:
                continue
            candidate_seen.add(candidate)
            found = try_variants(candidate, "pcap-icmp-stream", None, include_direct=True)
            if found:
                icmp_stream_recoveries += found

    # Bit-valued header and timing channels occur frequently in harder CTFs:
    # individual TCP flags or an IP flag select bits/chunks, while two timing
    # clusters encode binary zero/one. Try both bit orders, inversion, and
    # reverse packet order, but only retain a result when normal flag/file
    # validation succeeds.
    bit_channel_recoveries = 0

    def packed_bits(bits: list[int], *, least_significant_first: bool = False) -> bytes:
        output = bytearray()
        for start in range(0, len(bits) - 7, 8):
            value = 0
            chunk = bits[start:start + 8]
            if least_significant_first:
                for index, bit in enumerate(chunk):
                    value |= (bit & 1) << index
            else:
                for bit in chunk:
                    value = (value << 1) | (bit & 1)
            output.append(value)
        return bytes(output)

    def try_bits(bits: list[int], source: str, label: str) -> int:
        if len(bits) < 16 or len(bits) > 8 * 1024 * 1024:
            return 0
        found = 0
        seen: set[bytes] = set()
        for order_label, ordered_bits in (("capture order", bits), ("reverse order", list(reversed(bits)))):
            for inversion_label, candidate_bits in (("normal", ordered_bits), ("inverted", [1 - bit for bit in ordered_bits])):
                for packing_label, least_first in (("MSB-first", False), ("LSB-first", True)):
                    candidate = packed_bits(candidate_bits, least_significant_first=least_first)
                    if len(candidate) < 2 or candidate in seen:
                        continue
                    seen.add(candidate)
                    found += int(register_candidate(
                        candidate, source, None,
                        f"{label}: {order_label}, {inversion_label}, {packing_label} bit packing",
                    ))
        return found

    timing_groups: defaultdict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for packet in records:
        if packet.get("source") is not None and packet.get("destination") is not None:
            timing_groups[(packet.get("source"), packet.get("destination"), packet.get("protocol"))].append(packet)
    for group, packets in timing_groups.items():
        ordered = sorted(packets, key=_pcap_timestamp_key)
        if len(ordered) < 17:
            continue
        scalar_lanes: dict[str, list[int]] = {
            "tcp-flags": [int(item["tcp_flags"]) & 0x1FF for item in ordered if isinstance(item.get("tcp_flags"), int)],
            "ip-flags": [int(item["ip_flags"]) & 0x07 for item in ordered if isinstance(item.get("ip_flags"), int)],
        }
        for lane_name, values in scalar_lanes.items():
            if len(values) < 16 or len(set(values)) < 2:
                continue
            width = 9 if lane_name == "tcp-flags" else 3
            for bit_index in range(width):
                bit_channel_recoveries += try_bits(
                    [(value >> bit_index) & 1 for value in values],
                    f"pcap-bit-{lane_name}", f"{lane_name} bit {bit_index}",
                )

        timestamps = [_pcap_timestamp_seconds(item) for item in ordered]
        deltas = [
            float(current) - float(previous)
            for previous, current in zip(timestamps, timestamps[1:])
            if previous is not None and current is not None and float(current) >= float(previous)
        ]
        if len(deltas) < 16:
            continue
        unique = sorted(set(round(value, 9) for value in deltas))
        if len(unique) >= 2:
            gaps = [(unique[index + 1] - unique[index], index) for index in range(len(unique) - 1)]
            largest_gap, split_index = max(gaps)
            if largest_gap > 0:
                threshold = (unique[split_index] + unique[split_index + 1]) / 2
                bit_channel_recoveries += try_bits(
                    [int(value > threshold) for value in deltas],
                    "pcap-timing-channel", f"timestamp delta threshold {threshold:.9f}s",
                )
        # Some challenges write ASCII directly as millisecond/centisecond
        # deltas rather than binary clusters.
        for scale, scale_name in ((1_000, "milliseconds"), (100, "centiseconds"), (1_000_000, "microseconds")):
            values = [int(round(value * scale)) for value in deltas]
            if values and all(0 <= value <= 255 for value in values):
                bit_channel_recoveries += try_variants(
                    bytes(values), f"pcap-timing-{scale_name}", None, include_direct=True,
                )

    # Payload bytes selected by unusual flag values can form a file even when
    # no individual packet contains a recognizable signature (for example the
    # IPv4 reserved/"evil" bit selecting JPEG chunks).
    selector_recoveries = 0
    selectors: tuple[tuple[str, Any], ...] = (
        ("ipv4-reserved-bit", lambda item: bool(item.get("ip_reserved"))),
        ("ipv4-dont-fragment-bit", lambda item: bool(item.get("dont_fragment"))),
        ("tcp-psh-bit", lambda item: isinstance(item.get("tcp_flags"), int) and bool(int(item["tcp_flags"]) & 0x008)),
        ("tcp-rst-bit", lambda item: isinstance(item.get("tcp_flags"), int) and bool(int(item["tcp_flags"]) & 0x004)),
        ("tcp-urg-bit", lambda item: isinstance(item.get("tcp_flags"), int) and bool(int(item["tcp_flags"]) & 0x020)),
    )
    for selector_name, selector in selectors:
        selected = [
            bytes(item.get("payload") or b"") for item in sorted(records, key=_pcap_timestamp_key)
            if selector(item) and item.get("payload")
        ]
        if len(selected) < 2:
            continue
        candidate = b"".join(selected)
        selector_recoveries += try_variants(candidate, f"pcap-selector-{selector_name}", None, include_direct=True)

    # Address-octet channels deliberately vary one endpoint, so they cannot be
    # grouped by the full source/destination pair used for ordinary flows.
    address_channel_recoveries = 0
    address_groups: defaultdict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for packet in records:
        if packet.get("source") is None or packet.get("destination") is None:
            continue
        address_groups[("source", packet.get("destination"), packet.get("protocol"), packet.get("destination_port"))].append(packet)
        address_groups[("destination", packet.get("source"), packet.get("protocol"), packet.get("source_port"))].append(packet)
    for group, packets in address_groups.items():
        if len(packets) < 4:
            continue
        field = str(group[0])
        lane = bytearray()
        for packet in sorted(packets, key=_pcap_timestamp_key):
            try:
                lane.append(ipaddress.ip_address(str(packet.get(field))).packed[-1])
            except ValueError:
                continue
        if len(lane) >= 4 and len(set(lane)) > 1:
            address_channel_recoveries += try_variants(
                bytes(lane), f"pcap-{field}-address-channel", None, include_direct=True,
            )

    # Header/field covert channels. Every raw lane is tested through the same
    # bounded decoder and known-prefix byte-key inference as payload streams.
    # This covers arbitrary constant offsets (for example source octet minus
    # ten), not only a fixed list of hand-picked subtraction values.
    field_recoveries = 0
    field_groups: defaultdict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for packet in records:
        if packet.get("source") is not None and packet.get("destination") is not None:
            field_groups[(packet.get("source"), packet.get("destination"), packet.get("protocol"))].append(packet)
    for group, packets in field_groups.items():
        ordered = sorted(packets, key=_pcap_timestamp_key)
        if len(ordered) < 4:
            continue
        def field_lane(field: str, byte_index: int, width: int) -> bytes:
            shift = (width - 1 - byte_index) * 8
            return bytes((int(item[field]) >> shift) & 0xFF for item in ordered if isinstance(item.get(field), int))

        def address_octets(field: str) -> bytes:
            values = bytearray()
            for item in ordered:
                try:
                    values.append(ipaddress.ip_address(str(item.get(field))).packed[-1])
                except ValueError:
                    continue
            return bytes(values)

        fields: dict[str, bytes] = {
            "ttl": bytes(int(item["ttl"]) & 0xFF for item in ordered if isinstance(item.get("ttl"), int)),
            "traffic-class": bytes(int(item["traffic_class"]) & 0xFF for item in ordered if isinstance(item.get("traffic_class"), int)),
            "source-ip-last-octet": address_octets("source"),
            "destination-ip-last-octet": address_octets("destination"),
            "ip-id-low": bytes(int(item["ip_id"]) & 0xFF for item in ordered if isinstance(item.get("ip_id"), int)),
            "icmp-id-low": bytes(int(item["icmp_id"]) & 0xFF for item in ordered if isinstance(item.get("icmp_id"), int)),
            "icmp-sequence-low": bytes(int(item["icmp_sequence"]) & 0xFF for item in ordered if isinstance(item.get("icmp_sequence"), int)),
            "tcp-ack-low": bytes(int(item["acknowledgement"]) & 0xFF for item in ordered if isinstance(item.get("acknowledgement"), int)),
            "tcp-flags-low": bytes(int(item["tcp_flags"]) & 0xFF for item in ordered if isinstance(item.get("tcp_flags"), int)),
            "icmp-type": bytes(int(item["icmp_type"]) & 0xFF for item in ordered if isinstance(item.get("icmp_type"), int)),
            "icmp-code": bytes(int(item["icmp_code"]) & 0xFF for item in ordered if isinstance(item.get("icmp_code"), int)),
            "payload-length-low": bytes(len(bytes(item.get("payload") or b"")) & 0xFF for item in ordered),
            "frame-length-low": bytes(int(item.get("frame_length", 0)) & 0xFF for item in ordered),
        }
        for field, width, label in (
            ("ip_id", 2, "ip-id"), ("ip_checksum", 2, "ip-checksum"),
            ("source_port", 2, "source-port"), ("destination_port", 2, "destination-port"),
            ("sequence", 4, "tcp-sequence"), ("acknowledgement", 4, "tcp-ack"),
            ("tcp_window", 2, "tcp-window"), ("tcp_urgent_pointer", 2, "tcp-urgent-pointer"),
            ("transport_checksum", 2, "transport-checksum"), ("udp_length", 2, "udp-length"),
            ("flow_label", 4, "ipv6-flow-label"),
        ):
            for byte_index in range(width):
                fields[f"{label}-byte-{byte_index}"] = field_lane(field, byte_index, width)
        acknowledgements = [int(item["acknowledgement"]) for item in ordered if isinstance(item.get("acknowledgement"), int)]
        if len(acknowledgements) >= 2:
            fields["tcp-ack-delta"] = bytes((current - previous) & 0xFF for previous, current in zip(acknowledgements, acknowledgements[1:]))
        for name, value in fields.items():
            if len(value) < 4 or len(set(value)) < 2:
                continue
            field_recoveries += try_variants(value, f"pcap-field-{name}", None, include_direct=True)
            for delta in (1, 42, 64, 65, 128, 255):
                candidate = bytes((item - delta) & 0xFF for item in value)
                if register_candidate(candidate, f"pcap-field-{name}", None, f"{name} byte stream minus {delta}"):
                    field_recoveries += 1

    # HTTP Basic is merely Base64 encoding, not encryption. CTFs frequently
    # place a flag or a password for an exported object in this header, so
    # decode it locally and feed its bounded value into the ordinary candidate
    # pipeline. The properties retain only non-secret routing context.
    http_basic_credentials: list[dict[str, Any]] = []
    http_basic_seen: set[tuple[str, str, str, str]] = set()
    for message in http_messages:
        credential = _pcap_http_basic_credential(dict(message.get("headers") or {}))
        if credential is None:
            continue
        username, secret = credential
        key = (
            str(message.get("source") or ""), str(message.get("destination") or ""),
            str(message.get("target") or ""), f"{username}:{secret}",
        )
        if key in http_basic_seen or len(http_basic_credentials) >= 256:
            continue
        http_basic_seen.add(key)
        http_basic_credentials.append({
            "packet": message.get("packet"), "source": key[0], "destination": key[1],
            "host": str(message.get("host") or ""), "target": key[2], "username": username,
        })
        decoded = f"{username}:{secret}".encode("utf-8", "replace")
        add_text(
            decoded.decode("utf-8", "replace"), "pcap-http-basic-authorization", None, 10,
            ["HTTP Authorization: Basic Base64 decode"],
        )
        direct_flag_hits.update(_pcap_flag_values(decoded))
        try_variants(secret.encode("utf-8", "replace"), "http-basic-secret", None, include_direct=True)

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
        "arp_records": len(arp_records), "dhcp_messages": dhcp_messages[:1_024],
        "coap_messages": coap_messages[:1_024], "http2_frames": http2_frames,
        "http2_data_streams": len(http2_streams), "http2_recoveries": http2_exports,
        "mqtt_publishes": mqtt_publishes, "mqtt_topics": sorted(mqtt_topics)[:1_024],
        "websocket_messages": websocket_messages, "modbus_messages": modbus_messages,
        "cleartext_credentials": cleartext_credentials, "http_basic_credentials": http_basic_credentials,
        "bittorrent_dht_info_hashes": dht_info_hashes,
        "can_frames": len(can_frames), "can_identifiers": sorted(f"0x{identifier:X}" for identifier in can_groups)[:4_096],
        "can_isotp_messages": can_messages[:4_096], "can_recoveries": can_recoveries,
        "rtp_streams": len(rtp_groups), "rtp_dtmf_events": rtp_dtmf[:4_096], "rtp_audio_exports": rtp_audio_exports,
        "field_stream_recoveries": field_recoveries, "icmp_stream_recoveries": icmp_stream_recoveries,
        "bit_or_timing_channel_recoveries": bit_channel_recoveries,
        "flag_selected_payload_recoveries": selector_recoveries,
        "address_channel_recoveries": address_channel_recoveries,
        "decoded_stream_recoveries": decoded_recoveries,
        "traffic_inspection": _pcap_traffic_inspection(records, profile, tftp_objects),
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
    if cleartext_credentials:
        result["findings"].append(_finding("warning", "network-credentials", "Cleartext authentication commands recovered", "FTP/Telnet/mail authentication commands were observed in a reassembled TCP stream.", count=len(cleartext_credentials)))
    if http_basic_credentials:
        result["findings"].append(_finding("warning", "network-credentials", "HTTP Basic authorization decoded", "HTTP Basic credentials are Base64-encoded rather than encrypted. Their decoded values were tested locally for flags and bounded transform candidates; only endpoint and username context is retained in properties.", count=len(http_basic_credentials)))
    if dhcp_messages:
        result["findings"].append(_finding("info", "network-dhcp", "DHCP option evidence decoded", "BOOTP/DHCP hostname, domain, vendor, user-class, boot-file, and server options were decoded and tested as CTF clue channels.", messages=len(dhcp_messages)))
    if coap_messages:
        result["findings"].append(_finding("info", "network-coap", "CoAP paths and payloads decoded", "CoAP URI path/query options and payload markers were parsed from UDP and tested through the normal recovery transforms.", messages=len(coap_messages)))
    if http2_streams:
        result["findings"].append(_finding("info", "network-http2", "HTTP/2 DATA streams reconstructed", "Cleartext HTTP/2 DATA frames were grouped by stream and inspected as candidate files or encoded CTF payloads.", streams=len(http2_streams), frames=http2_frames))
    if dht_info_hashes:
        result["findings"].append(_finding("info", "network-bittorrent", "BitTorrent DHT info-hash recovered", "A DHT bencoded info_hash was extracted; it can identify the requested torrent even when the file itself is not present.", info_hashes=[item["info_hash"] for item in dht_info_hashes[:32]]))
    if can_frames:
        result["findings"].append(_finding("info", "network-can", "SocketCAN frames decoded", "CAN arbitration IDs, payload lanes, and bounded ISO-TP messages were inspected for CTF text or embedded files.", frames=len(can_frames), identifiers=len(can_groups), isotp_messages=len(can_messages)))
    if rtp_dtmf:
        result["findings"].append(_finding("info", "network-voip", "RTP DTMF events decoded", "RFC 2833/4733 telephone-event payloads were converted into keypad symbols.", symbols="".join(str(item["symbol"]) for item in rtp_dtmf)))
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
        packet = _pcap_capture_packet(frame, linktype)
        packet.update({"number": packet_count + 1, "record_offset": record_offset, "frame_offset": frame_offset, "timestamp_key": (sec, subsec), "timestamp_resolution": timestamp_resolution, "linktype": linktype, "frame_length": included})
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
    name_resolution: list[tuple[str, str, int]] = []

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
            def interface_text(code: int) -> str | None:
                value = next(iter(parsed.get(code, [])), b"")
                return value.decode("utf-8", "replace").strip("\x00") or None
            interfaces.append({
                "linktype": linktype, "snaplen": snaplen, "tsresol": tsresol, "tsoffset": tsoffset,
                "name": interface_text(2), "description": interface_text(3),
                "os": interface_text(12), "hardware": interface_text(13),
            })
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
            packet = _pcap_capture_packet(frame, int(interface.get("linktype", 1)))
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
                packet = _pcap_capture_packet(frame, int(interface.get("linktype", 1)))
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
                packet = _pcap_capture_packet(frame, int(interface.get("linktype", 1)))
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
        elif block_type == 4:  # Name Resolution Block
            cursor = body_start
            for _ in range(8_192):
                if cursor + 4 > body_end:
                    break
                record_type, record_length = struct.unpack_from(f"{endian}HH", data, cursor)
                cursor += 4
                if record_type == 0:
                    break
                if cursor + record_length > body_end:
                    break
                value = data[cursor:cursor + record_length]
                cursor += (record_length + 3) & ~3
                if record_type not in {1, 2}:
                    continue
                address_length = 4 if record_type == 1 else 16
                if len(value) <= address_length:
                    continue
                try:
                    address = str(ipaddress.ip_address(value[:address_length]))
                except ValueError:
                    continue
                for raw_name in value[address_length:].split(b"\x00"):
                    name = raw_name.decode("utf-8", "replace").strip()
                    if name:
                        name_resolution.append((address, name, offset))
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
        "interface_details": interfaces,
        "name_resolution_records": [
            {"address": address, "name": name} for address, name, _offset in name_resolution[:4_096]
        ],
    })
    for comment, comment_offset in comments:
        result["text_records"].append({"source": "pcapng-comment-or-secret", "offset": comment_offset, "text": comment, "confidence_hint": 9})
    for secret in secrets:
        result["extracted"].append({"label": "pcapng_decryption_secrets", "data": secret, "kind": "text", "producer": "pcapng-dsb", "transformation": "Extract Decryption Secrets Block payload", "reason": "PCAPNG stores TLS/other protocol secrets in a dedicated block."})
    for address, name, name_offset in name_resolution:
        result["text_records"].append({"source": "pcapng-name-resolution", "offset": name_offset, "text": f"{address}\t{name}", "confidence_hint": 8})
    if malformed:
        result["findings"].append(_finding("warning", "structure", "Malformed PCAPNG block", "Block length or mirrored trailer validation failed; packet iteration stopped safely.", offset=offset))
    analyzed = _analyze_capture_records(result, records, profile)
    secret_flags: set[str] = set()
    for secret in secrets:
        secret_flags.update(_pcap_flag_values(secret))
    for _address, name, _name_offset in name_resolution:
        secret_flags.update(_pcap_flag_values(name.encode("utf-8", "replace")))
    if secret_flags:
        analyzed["findings"].append(_finding("info", "network-payload", "Flag-like text recovered from PCAPNG metadata", "A bounded Decryption Secrets Block or Name Resolution Block contains a CTF-style flag-shaped value.", flags=sorted(secret_flags)))
    return analyzed


_FORENSIC_SQLITE_QUERIES: tuple[tuple[str, frozenset[str], str, dict[str, str]], ...] = (
    (
        "chromium-visit", frozenset({"urls", "visits"}),
        "SELECT v.visit_time, u.url, u.title, u.visit_count, v.transition FROM visits AS v JOIN urls AS u ON u.id = v.url LIMIT ?",
        {"visit_time": "webkit"},
    ),
    (
        "chromium-search", frozenset({"urls", "keyword_search_terms"}),
        "SELECT k.term, u.url FROM keyword_search_terms AS k JOIN urls AS u ON u.id = k.url_id LIMIT ?",
        {},
    ),
    (
        "chromium-download", frozenset({"downloads"}),
        "SELECT target_path, tab_url, referrer, start_time, end_time, total_bytes, state, danger_type FROM downloads LIMIT ?",
        {"start_time": "webkit", "end_time": "webkit"},
    ),
    (
        "firefox-visit", frozenset({"moz_places", "moz_historyvisits"}),
        "SELECT h.visit_date, p.url, p.title, p.visit_count, h.visit_type FROM moz_historyvisits AS h JOIN moz_places AS p ON p.id = h.place_id LIMIT ?",
        {"visit_date": "unix_us"},
    ),
    (
        "firefox-bookmark", frozenset({"moz_places", "moz_bookmarks"}),
        "SELECT b.title, p.url, b.dateAdded, b.lastModified FROM moz_bookmarks AS b LEFT JOIN moz_places AS p ON p.id = b.fk LIMIT ?",
        {"dateAdded": "unix_us", "lastModified": "unix_us"},
    ),
    (
        "firefox-cookie", frozenset({"moz_cookies"}),
        "SELECT host, name, value, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly FROM moz_cookies LIMIT ?",
        {"expiry": "unix_s", "lastAccessed": "unix_us", "creationTime": "unix_us"},
    ),
    (
        "firefox-form-history", frozenset({"moz_formhistory"}),
        "SELECT fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory LIMIT ?",
        {"firstUsed": "unix_us", "lastUsed": "unix_us"},
    ),
    (
        "safari-visit", frozenset({"history_items", "history_visits"}),
        "SELECT v.visit_time, i.url, i.title, i.visit_count FROM history_visits AS v JOIN history_items AS i ON i.id = v.history_item LIMIT ?",
        {"visit_time": "apple"},
    ),
    (
        "windows-timeline", frozenset({"Activity"}),
        "SELECT AppId, Payload, StartTime, EndTime, LastModifiedTime, ClipboardPayload, ActivityType, ActivityStatus FROM Activity LIMIT ?",
        {"StartTime": "unix_s", "EndTime": "unix_s", "LastModifiedTime": "unix_s"},
    ),
    (
        "windows-timeline-core", frozenset({"Activity"}),
        "SELECT AppId, Payload, StartTime, EndTime, LastModifiedTime, ActivityType FROM Activity LIMIT ?",
        {"StartTime": "unix_s", "EndTime": "unix_s", "LastModifiedTime": "unix_s"},
    ),
    (
        "macos-quarantine", frozenset({"LSQuarantineEvent"}),
        "SELECT LSQuarantineTimeStamp, LSQuarantineAgentName, LSQuarantineDataURLString, LSQuarantineOriginURLString, LSQuarantineSenderName FROM LSQuarantineEvent LIMIT ?",
        {"LSQuarantineTimeStamp": "apple"},
    ),
    (
        "ios-message", frozenset({"message", "handle"}),
        "SELECT m.text, m.date, m.is_from_me, m.service, h.id AS handle FROM message AS m LEFT JOIN handle AS h ON h.ROWID = m.handle_id LIMIT ?",
        {"date": "apple_auto"},
    ),
    (
        "ios-message-core", frozenset({"message", "handle"}),
        "SELECT m.text, m.date, m.is_from_me, h.id AS handle FROM message AS m LEFT JOIN handle AS h ON h.ROWID = m.handle_id LIMIT ?",
        {"date": "apple_auto"},
    ),
    (
        "android-sms", frozenset({"sms"}),
        "SELECT _id, address, date, type, body, read FROM sms LIMIT ?",
        {"date": "unix_ms"},
    ),
)


def _browser_time(value: Any, epoch: str) -> str | None:
    try:
        numeric = float(value)
        if epoch == "webkit":
            moment = dt.datetime(1601, 1, 1, tzinfo=dt.UTC) + dt.timedelta(microseconds=numeric)
        elif epoch == "unix_us":
            moment = dt.datetime(1970, 1, 1, tzinfo=dt.UTC) + dt.timedelta(microseconds=numeric)
        elif epoch == "unix_s":
            moment = dt.datetime(1970, 1, 1, tzinfo=dt.UTC) + dt.timedelta(seconds=numeric)
        elif epoch == "unix_ms":
            moment = dt.datetime(1970, 1, 1, tzinfo=dt.UTC) + dt.timedelta(milliseconds=numeric)
        elif epoch == "apple_auto":
            seconds = numeric / 1_000_000_000 if abs(numeric) > 10_000_000_000 else numeric
            moment = dt.datetime(2001, 1, 1, tzinfo=dt.UTC) + dt.timedelta(seconds=seconds)
        else:
            moment = dt.datetime(2001, 1, 1, tzinfo=dt.UTC) + dt.timedelta(seconds=numeric)
    except (TypeError, ValueError, OverflowError):
        return None
    return moment.isoformat().replace("+00:00", "Z")


def _browser_sqlite_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        strings = list(iter_ascii_strings(value[:65_536], minimum=4, limit=20))
        strings.extend(iter_utf16_strings(value[:65_536], minimum=4, limit=20))
        rendered = " | ".join(str(item["text"]) for item in strings)
        return display_text(rendered or f"<blob {len(value)} bytes>", 16_384)
    return display_text(str(value), 16_384)


def _inspect_forensic_sqlite(data: bytes, profile: str, result: dict[str, Any]) -> None:
    """Run fixed, read-only forensic queries against a bounded in-memory snapshot."""

    maximum_database = 128 * 1024 * 1024 if profile == "deep" else 64 * 1024 * 1024
    if len(data) > maximum_database or not hasattr(sqlite3.Connection, "deserialize"):
        result["properties"]["structured_sqlite_scan"] = "skipped-size-or-runtime"
        return
    connection: sqlite3.Connection | None = None
    deadline = time.monotonic() + (8.0 if profile == "deep" else 3.0)
    progress_calls = 0

    def progress() -> int:
        nonlocal progress_calls
        progress_calls += 1
        return int(progress_calls > (20_000 if profile == "deep" else 5_000) or time.monotonic() > deadline)

    try:
        connection = sqlite3.connect(":memory:")
        connection.enable_load_extension(False)
        for limit_name, limit_value in (
            ("SQLITE_LIMIT_ATTACHED", 0),
            ("SQLITE_LIMIT_COLUMN", 128),
            ("SQLITE_LIMIT_COMPOUND_SELECT", 8),
            ("SQLITE_LIMIT_LENGTH", 16 * 1024 * 1024),
            ("SQLITE_LIMIT_SQL_LENGTH", 100_000),
            ("SQLITE_LIMIT_TRIGGER_DEPTH", 0),
            ("SQLITE_LIMIT_VARIABLE_NUMBER", 16),
        ):
            category = getattr(sqlite3, limit_name, None)
            if category is not None:
                connection.setlimit(category, limit_value)
        connection.deserialize(data)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA cell_size_check=ON")
        connection.set_progress_handler(progress, 1_000)
        allowed_actions = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ}

        def authorize(action: int, _arg1: str | None, _arg2: str | None, _database: str | None, _trigger: str | None) -> int:
            return sqlite3.SQLITE_OK if action in allowed_actions else sqlite3.SQLITE_DENY

        connection.set_authorizer(authorize)
        schema_rows = connection.execute(
            "SELECT name, type, sql FROM sqlite_master WHERE type = 'table' LIMIT 1000"
        ).fetchall()
        tables = {
            str(name)
            for name, object_type, sql in schema_rows
            if object_type == "table" and isinstance(name, str)
            and not (isinstance(sql, str) and sql.lstrip().casefold().startswith("create virtual table"))
        }
        result["properties"]["structured_tables_detected"] = sorted(tables & set().union(*(query[1] for query in _FORENSIC_SQLITE_QUERIES)))
        maximum_rows = 20_000 if profile == "deep" else 8_000
        per_query = 5_000 if profile == "deep" else 2_000
        lines: list[str] = []
        rendered_characters = 0
        matched_families: set[str] = set()
        successful_query_groups: set[str] = set()
        query_errors = 0
        for label, required_tables, query, timestamp_columns in _FORENSIC_SQLITE_QUERIES:
            if not required_tables.issubset(tables) or len(lines) >= maximum_rows:
                continue
            query_group = label.removesuffix("-core")
            if label.endswith("-core") and query_group in successful_query_groups:
                continue
            try:
                cursor = connection.execute(query, (min(per_query, maximum_rows - len(lines)),))
                columns = [str(item[0]) for item in cursor.description or ()]
                for row in cursor:
                    fields: list[str] = []
                    for column, value in zip(columns, row):
                        fields.append(f"{column}={_browser_sqlite_value(value)}")
                        if column in timestamp_columns:
                            normalized = _browser_time(value, timestamp_columns[column])
                            if normalized:
                                fields.append(f"{column}_utc={normalized}")
                    rendered = f"artifact={label} " + " ".join(fields)
                    if rendered_characters + len(rendered) <= 4_000_000:
                        lines.append(rendered)
                        rendered_characters += len(rendered)
                    if len(lines) >= maximum_rows:
                        break
                matched_families.add(label.split("-", 1)[0])
                successful_query_groups.add(query_group)
            except sqlite3.DatabaseError:
                query_errors += 1
        result["properties"].update({
            "structured_sqlite_scan": "completed",
            "browser_families": sorted(matched_families & {"chromium", "firefox", "safari"}),
            "structured_families": sorted(matched_families),
            "structured_rows_rendered": len(lines),
            "structured_query_errors": query_errors,
        })
        if lines:
            result["text_records"].append({
                "encoding": "browser-sqlite-rows",
                "offset": None,
                "text": display_text("\n".join(lines), 2_000_000),
                "source": "read-only browser/OS/mobile forensic SQLite queries",
                "confidence_hint": 10,
            })
            result["findings"].append(_finding(
                "info", "database", "Structured forensic SQLite records recovered",
                "Fixed read-only queries recovered supported browser, operating-system timeline, quarantine, or mobile-message rows from an isolated in-memory snapshot.",
                families=sorted(matched_families), rows=len(lines),
            ))
    except sqlite3.DatabaseError as exc:
        result["properties"]["structured_sqlite_scan"] = "rejected"
        result["findings"].append(_finding(
            "warning", "structure", "Structured SQLite scan stopped safely",
            "The database was malformed, unsupported, or exceeded the fixed virtual-machine/time bounds; raw forensic scanning remains available.",
            error=display_text(exc, 300),
        ))
    finally:
        if connection is not None:
            connection.set_progress_handler(None, 0)
            connection.set_authorizer(None)
            connection.close()


def parse_sqlite(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Inspect SQLite structure and recover supported browser timeline rows."""

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
    _inspect_forensic_sqlite(data, profile, result)
    result["findings"].append(_finding(
        "info", "database", "SQLite database detected",
        "Supported browser schemas are queried through a bounded, read-only in-memory snapshot; deep scans can also use the optional SQLite dump adapter.",
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


_DOCUMENT_PACKAGE_ENTRY_LIMIT = 1_000
_DOCUMENT_PACKAGE_TEXT_PART_LIMIT = 96
_DOCUMENT_PACKAGE_MEMBER_LIMIT = 2 * 1024 * 1024
_DOCUMENT_PACKAGE_TOTAL_LIMIT = 8 * 1024 * 1024


def _document_package_family(package_kind: str, names: set[str]) -> str | None:
    if package_kind == "docx" and "word/document.xml" in names:
        return "word"
    if package_kind == "xlsx" and ("xl/workbook.xml" in names or "xl/sharedstrings.xml" in names):
        return "spreadsheet"
    if package_kind == "pptx" and any(name.startswith("ppt/slides/slide") and name.endswith(".xml") for name in names):
        return "presentation"
    if package_kind in {"odt", "ods", "odp"} and "content.xml" in names:
        return "odf"
    if package_kind == "epub" and ("meta-inf/container.xml" in names or any(name.endswith((".xhtml", ".html", ".htm")) for name in names)):
        return "epub"
    return None


def _document_package_text_part(family: str, name: str) -> bool:
    lowered = name.casefold()
    if lowered.startswith(("docprops/", "customxml/")) and lowered.endswith(".xml"):
        return True
    if family == "word":
        return (
            lowered.startswith("word/")
            and lowered.endswith(".xml")
            and "/_rels/" not in lowered
            and not lowered.startswith(("word/theme/", "word/fonts/"))
        )
    if family == "spreadsheet":
        return (
            lowered in {"xl/sharedstrings.xml", "xl/workbook.xml"}
            or lowered.startswith(("xl/worksheets/", "xl/comments", "xl/threadedcomments/"))
            and lowered.endswith(".xml")
        )
    if family == "presentation":
        return (
            lowered.startswith(("ppt/slides/", "ppt/notesslides/", "ppt/comments/"))
            and lowered.endswith(".xml")
            and "/_rels/" not in lowered
        )
    if family == "odf":
        return lowered in {"content.xml", "meta.xml", "settings.xml"}
    if family == "epub":
        return lowered.endswith((".xhtml", ".html", ".htm", ".opf", ".ncx"))
    return False


def _package_xml_values(payload: bytes, local_names: tuple[str, ...]) -> list[str]:
    """Collect simple XML text nodes without resolving XML entities or DTDs."""

    if not payload or not local_names:
        return []
    names = "|".join(re.escape(name) for name in local_names)
    pattern = re.compile(
        rf"<(?:(?:[A-Za-z_][\w.-]*):)?(?:{names})\b[^>]*>(.*?)</(?:(?:[A-Za-z_][\w.-]*):)?(?:{names})\s*>",
        re.IGNORECASE | re.DOTALL,
    )
    source = payload.decode("utf-8", "replace")
    values: list[str] = []
    for match in pattern.finditer(source):
        value = re.sub(r"<[^>]{0,4096}>", "", match.group(1))
        value = display_text(html.unescape(value).strip(), 256_000)
        if value:
            values.append(value)
        if len(values) >= 4_000:
            break
    return values


def _package_markup_text(payload: bytes) -> str:
    source = payload.decode("utf-8", "replace")
    source = re.sub(r"</(?:w:)?(?:p|tr|tc)\s*>", "\n", source, flags=re.IGNORECASE)
    source = re.sub(r"</(?:text:p|text:h|table:table-row|table:table-cell)\s*>", "\n", source, flags=re.IGNORECASE)
    source = re.sub(r"<br\b[^>]*/?>", "\n", source, flags=re.IGNORECASE)
    source = re.sub(r"<[^>]{0,4096}>", "", source)
    return display_text(html.unescape(source).strip(), 2_000_000)


def _append_package_text(
    result: dict[str, Any], package_kind: str, part_name: str, role: str, text: str, *,
    confidence_hint: int = 9, transform_chain: list[str] | None = None,
) -> None:
    if not text:
        return
    result["text_records"].append({
        "encoding": "document-package-text",
        "offset": None,
        "text": display_text(text, 2_000_000),
        "source": f"{package_kind.upper()} {role}:{display_text(part_name, 240)}",
        "confidence_hint": confidence_hint,
        "transform_chain": transform_chain,
    })


def parse_document_package(data: bytes, profile: str = "balanced", *, package_kind: str) -> dict[str, Any]:
    """Inspect OOXML, ODF, and EPUB text parts without rendering a document.

    Document packages are ZIP containers, but CTF flags frequently live in
    review revisions, comments, custom XML, formula strings, or adjacent text
    runs.  This parser reads only bounded in-memory parts; it never extracts a
    supplied path, follows relationships, opens Office, or executes a macro.
    """

    result = _result(package_kind)
    entry_limit = _DOCUMENT_PACKAGE_ENTRY_LIMIT
    member_limit = _DOCUMENT_PACKAGE_MEMBER_LIMIT * (2 if profile == "deep" else 1)
    total_limit = _DOCUMENT_PACKAGE_TOTAL_LIMIT * (4 if profile == "deep" else 1)
    if not zip_directory_is_bounded(data, max_entries=_DOCUMENT_PACKAGE_ENTRY_LIMIT, max_directory_bytes=16 * 1024 * 1024):
        result["findings"].append(_finding(
            "warning", "resource-limit", "Document package directory rejected",
            "The central directory is missing, multi-disk/Zip64, or exceeds the safe entry/byte limits.",
        ))
        return result
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (OSError, ValueError, zipfile.BadZipFile):
        result["findings"].append(_finding(
            "error", "structure", "Invalid document package",
            "The extension indicates a ZIP-based document, but its package directory could not be read.",
        ))
        return result

    with archive:
        infos = archive.infolist()
        names = {info.filename.replace("\\", "/").casefold() for info in infos if not info.is_dir()}
        family = _document_package_family(package_kind, names)
        result["properties"].update({
            "package_entry_count": len(infos),
            "package_family": family,
            "has_macro_project": any(name.endswith("vbaproject.bin") for name in names),
            "embedded_object_parts": sum("/embeddings/" in f"/{name}" for name in names),
            "custom_xml_parts": sum(name.startswith("customxml/") and name.endswith(".xml") for name in names),
        })
        if len(infos) > entry_limit:
            result["findings"].append(_finding(
                "warning", "resource-limit", "Document package entry count bounded",
                "Only the first bounded set of package entries was considered.",
                declared_entries=len(infos), limit=entry_limit,
            ))
        if family is None:
            result["findings"].append(_finding(
                "warning", "structure", "Expected document package parts are missing",
                "The ZIP package does not expose the expected document-content parts for its extension.",
            ))
            return result
        if result["properties"]["has_macro_project"]:
            result["findings"].append(_finding(
                "warning", "document-active-content", "VBA macro project found",
                "A vbaProject.bin part is present. It was not opened or executed.",
            ))
        if result["properties"]["embedded_object_parts"]:
            result["findings"].append(_finding(
                "info", "embedded-data", "Embedded document objects found",
                "Embedded package objects remain available to the bounded recursive archive analyzer.",
                count=result["properties"]["embedded_object_parts"],
            ))
        if result["properties"]["custom_xml_parts"]:
            result["findings"].append(_finding(
                "info", "document", "Custom XML parts found",
                "Custom XML data is often not shown in the document body and was included in text scanning.",
                count=result["properties"]["custom_xml_parts"],
            ))

        text_parts = 0
        skipped = 0
        total_read = 0
        deleted_text_parts = 0
        external_relationships: list[str] = []
        for info in infos[:entry_limit]:
            if info.is_dir():
                continue
            name = info.filename.replace("\\", "/")
            lowered = name.casefold()
            is_relationship = lowered.endswith(".rels")
            if not is_relationship and not _document_package_text_part(family, lowered):
                continue
            if text_parts >= _DOCUMENT_PACKAGE_TEXT_PART_LIMIT:
                skipped += 1
                continue
            if info.flag_bits & 0x1 or info.file_size < 1 or info.file_size > member_limit:
                skipped += 1
                continue
            if info.compress_size and info.file_size / max(1, info.compress_size) > 200:
                skipped += 1
                continue
            remaining = total_limit - total_read
            if remaining <= 0:
                skipped += 1
                continue
            try:
                with archive.open(info, "r") as member:
                    payload = member.read(min(member_limit, remaining) + 1)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                skipped += 1
                continue
            if len(payload) > min(member_limit, remaining):
                payload = payload[:min(member_limit, remaining)]
                skipped += 1
            total_read += len(payload)
            text_parts += 1
            if is_relationship:
                relationship_source = payload.decode("utf-8", "replace")
                for relationship in re.findall(r"<Relationship\b[^>]{0,4096}>", relationship_source, re.IGNORECASE):
                    if not re.search(r"\bTargetMode\s*=\s*[\"']External[\"']", relationship, re.IGNORECASE):
                        continue
                    target = re.search(r"\bTarget\s*=\s*[\"']([^\"']{1,1024})[\"']", relationship, re.IGNORECASE)
                    if target:
                        external_relationships.append(display_text(html.unescape(target.group(1)), 500))
                continue

            if family == "word":
                ordinary = _package_xml_values(payload, ("t", "instrText"))
                deleted = _package_xml_values(payload, ("delText", "delInstrText"))
                if deleted:
                    deleted_text_parts += 1
                    _append_package_text(
                        result, package_kind, name, "revision-deleted-or-field text", "\n".join(deleted),
                        confidence_hint=10,
                        transform_chain=["read bounded XML part", "collect w:delText/w:delInstrText"],
                    )
            elif family == "spreadsheet":
                ordinary = _package_xml_values(payload, ("t", "f", "v"))
                deleted = []
            elif family == "presentation":
                ordinary = _package_xml_values(payload, ("t",))
                deleted = []
            elif family == "odf":
                ordinary = _package_xml_values(payload, ("p", "h", "span"))
                deleted = []
            else:
                ordinary = []
                deleted = []

            if ordinary:
                _append_package_text(
                    result, package_kind, name, "text runs", "\n".join(ordinary),
                    transform_chain=["read bounded XML part", "collect document text nodes"],
                )
                compact = "".join(ordinary)
                if len(ordinary) > 1 and compact:
                    _append_package_text(
                        result, package_kind, name, "adjacent text runs", compact, confidence_hint=9,
                        transform_chain=["read bounded XML part", "join adjacent document text nodes"],
                    )
            else:
                fallback = _package_markup_text(payload)
                _append_package_text(
                    result, package_kind, name, "markup text", fallback, confidence_hint=7,
                    transform_chain=["read bounded markup part", "remove markup tags", "HTML/XML entity unescape"],
                )

        result["properties"].update({
            "text_parts_scanned": text_parts,
            "text_parts_skipped": skipped,
            "text_bytes_read": total_read,
            "external_relationship_count": len(external_relationships),
        })
        if deleted_text_parts:
            result["findings"].append(_finding(
                "info", "document", "Tracked-deletion text recovered",
                "Revision-deleted Word text was kept as a separate CTF scan record.",
                parts=deleted_text_parts,
            ))
        if external_relationships:
            result["findings"].append(_finding(
                "warning", "document-external-reference", "External document relationships found",
                "External relationship targets were reported as text only; no links were followed.",
                count=len(external_relationships), targets=external_relationships[:20],
            ))
    return result


def _rtf_hidden_text(raw: str) -> str:
    """Return text in RTF hidden-text scopes with a small tokenizer."""

    visibility = [False]
    output: list[str] = []
    index = 0
    while index < len(raw) and len(output) < 2_000_000:
        character = raw[index]
        if character == "{":
            visibility.append(visibility[-1])
            index += 1
            continue
        if character == "}":
            if len(visibility) > 1:
                visibility.pop()
            index += 1
            continue
        if character != "\\":
            if visibility[-1]:
                output.append(character)
            index += 1
            continue
        index += 1
        if index >= len(raw):
            break
        escaped = raw[index]
        if escaped in "\\{}":
            if visibility[-1]:
                output.append(escaped)
            index += 1
            continue
        if escaped == "'" and index + 2 < len(raw):
            token = raw[index + 1:index + 3]
            if re.fullmatch(r"[0-9A-Fa-f]{2}", token) and visibility[-1]:
                output.append(bytes([int(token, 16)]).decode("cp1252", "replace"))
            index += 3
            continue
        if not escaped.isalpha():
            index += 1
            continue
        start = index
        while index < len(raw) and raw[index].isalpha():
            index += 1
        word = raw[start:index].casefold()
        number_start = index
        if index < len(raw) and raw[index] in "+-":
            index += 1
        while index < len(raw) and raw[index].isdigit():
            index += 1
        number_text = raw[number_start:index]
        if index < len(raw) and raw[index] == " ":
            index += 1
        if word == "v":
            try:
                visibility[-1] = int(number_text or "1") != 0
            except ValueError:
                visibility[-1] = True
        elif word == "plain":
            visibility[-1] = False
        elif visibility[-1] and word in {"par", "line"}:
            output.append("\n")
        elif visibility[-1] and word == "tab":
            output.append("\t")
        elif visibility[-1] and word == "u":
            try:
                code_point = int(number_text)
                output.append(chr(code_point if code_point >= 0 else code_point + 65_536))
            except (ValueError, OverflowError):
                pass
    return display_text("".join(output).strip(), 2_000_000)


def _rtf_objdata_payloads(data: bytes, maximum: int) -> list[tuple[int, bytes]]:
    """Decode contiguous hexadecimal bytes from RTF objdata as inert bytes."""

    recovered: list[tuple[int, bytes]] = []
    for match in re.finditer(br"\\objdata\b", data, re.IGNORECASE):
        if len(recovered) >= 16:
            break
        segment = data[match.end():match.end() + maximum * 2 + 16_384]
        hex_match = re.match(br"(?:[\t\r\n 0-9A-Fa-f]){16,}", segment)
        if hex_match is None:
            continue
        compact = re.sub(br"\s+", b"", hex_match.group(0))
        if len(compact) % 2:
            compact = compact[:-1]
        if not compact or len(compact) > maximum * 2:
            continue
        try:
            payload = bytes.fromhex(compact.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            continue
        if payload:
            recovered.append((match.start(), payload[:maximum]))
    return recovered


def parse_rtf(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Recover bounded visible, hidden, and embedded RTF evidence."""

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
    hidden = _rtf_hidden_text(raw)
    if hidden:
        result["text_records"].append({
            "encoding": "rtf-hidden-text", "offset": 0, "text": hidden, "source": "rtf-hidden-text",
            "confidence_hint": 10, "transform_chain": ["parse RTF groups", "select hidden-text scopes"],
        })
        result["findings"].append(_finding(
            "info", "document", "RTF hidden text recovered",
            "Text marked with the RTF hidden-text control word was kept as a separate CTF scan record.",
        ))
    object_count = len(re.findall(br"\\object\b|\\objdata\b", scan, re.IGNORECASE))
    result["properties"]["object_markers"] = object_count
    recovered_objects = _rtf_objdata_payloads(scan, 4 * 1024 * 1024 if profile == "deep" else 1 * 1024 * 1024)
    for index, (offset, payload) in enumerate(recovered_objects):
        result["extracted"].append({
            "label": f"rtf_objdata_{index:03d}", "data": payload, "producer": "rtf-parser",
            "transformation": "decode contiguous hexadecimal bytes from RTF objdata group",
            "offset": offset, "kind": sniff_kind(payload),
        })
    result["properties"]["objdata_payloads_recovered"] = len(recovered_objects)
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


def parse_mbox(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Split a bounded Unix MBOX and reuse the safe MIME attachment parser."""

    result = _result("mbox")
    scan_limit = min(len(data), 256 * 1024 * 1024 if profile == "deep" else 64 * 1024 * 1024)
    source = data[:scan_limit]
    maximum_messages = 10_000 if profile == "deep" else 2_000
    separators = list(itertools.islice(
        re.finditer(br"(?m)^From [^\r\n]{1,998}\r?$", source),
        maximum_messages + 1,
    ))
    if not separators or separators[0].start() != 0:
        result["findings"].append(_finding(
            "error", "structure", "Invalid MBOX mailbox",
            "No initial From_ envelope separator was found.",
        ))
        return result
    rendered_characters = 0
    extracted_bytes = 0
    maximum_extracted = 128 * 1024 * 1024 if profile == "deep" else 32 * 1024 * 1024
    messages = 0
    malformed = 0
    for index, separator in enumerate(separators[:maximum_messages]):
        line_end = source.find(b"\n", separator.start())
        if line_end < 0:
            malformed += 1
            continue
        message_end = separators[index + 1].start() if index + 1 < len(separators) else len(source)
        message_bytes = source[line_end + 1:message_end]
        if not message_bytes or len(message_bytes) > 32 * 1024 * 1024:
            malformed += 1
            continue
        try:
            parsed = parse_eml(message_bytes, profile)
        except (LookupError, TypeError, ValueError):
            malformed += 1
            continue
        if parsed.get("properties", {}).get("parser_error"):
            malformed += 1
            continue
        messages += 1
        envelope = display_text(separator.group(0).decode("utf-8", "replace"), 2_048)
        summary_fields = [f"message={index}", f"envelope={envelope}"]
        for key in ("date", "from", "to", "subject", "message_id"):
            value = parsed.get("metadata", {}).get(key)
            if value:
                summary_fields.append(f"{key}={display_text(value, 16_384)}")
        summary = " ".join(summary_fields)
        if rendered_characters + len(summary) <= 4_000_000:
            result["text_records"].append({
                "encoding": "mbox-envelope-and-headers", "offset": separator.start(), "text": summary,
                "source": f"mbox-message:{index}", "confidence_hint": 9,
            })
            rendered_characters += len(summary)
        for record in parsed.get("text_records", []):
            text = display_text(record.get("text", ""), 250_000)
            if not text or rendered_characters + len(text) > 4_000_000:
                continue
            result["text_records"].append({
                **record,
                "text": text,
                "source": f"mbox-message:{index}:{record.get('source', 'mail')}",
            })
            rendered_characters += len(text)
        for artifact_index, artifact in enumerate(parsed.get("extracted", [])):
            payload = artifact.get("data")
            if not isinstance(payload, bytes) or extracted_bytes + len(payload) > maximum_extracted:
                continue
            result["extracted"].append({
                **artifact,
                "label": safe_label(f"mbox_{index:05d}_{artifact_index:03d}_{artifact.get('label', 'attachment')}")[:240],
                "producer": "mbox-email-parser",
                "transformation": "split MBOX envelope and " + str(artifact.get("transformation", "decode MIME attachment")),
            })
            extracted_bytes += len(payload)
    result["properties"].update({
        "envelopes_found": len(separators),
        "messages_parsed": messages,
        "malformed_or_oversized_messages": malformed,
        "attachments_extracted": len(result["extracted"]),
        "extracted_bytes": extracted_bytes,
        "bytes_scanned": scan_limit,
        "truncated": len(data) > scan_limit or len(separators) > maximum_messages,
    })
    result["findings"].append(_finding(
        "info", "email", "MBOX mailbox inspected",
        "Messages were separated in memory and MIME attachments were decoded into isolated child artifacts; no mailbox paths were materialized.",
        messages=messages,
    ))
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


def _registry_filetime(value: int) -> str | None:
    if value <= 0:
        return None
    try:
        timestamp = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=value // 10)
        return timestamp.isoformat().replace("+00:00", "Z")
    except (OverflowError, ValueError):
        return None


def _registry_text(raw: bytes, compressed: bool) -> str:
    encoding = "latin-1" if compressed else "utf-16le"
    return display_text(raw.decode(encoding, "replace").rstrip("\x00"), 65_536)


def _registry_value_text(value_type: int, raw: bytes) -> str:
    """Render bounded registry values without dumping opaque binary or credentials."""

    if value_type in {1, 2, 6}:
        return display_text(raw.decode("utf-16le", "replace").rstrip("\x00"), 250_000)
    if value_type == 7:
        values = [item for item in raw.decode("utf-16le", "replace").split("\x00") if item]
        return display_text(" | ".join(values), 250_000)
    if value_type == 4 and len(raw) >= 4:
        return str(int.from_bytes(raw[:4], "little"))
    if value_type == 5 and len(raw) >= 4:
        return str(int.from_bytes(raw[:4], "big"))
    if value_type == 11 and len(raw) >= 8:
        return str(int.from_bytes(raw[:8], "little"))
    strings = list(iter_ascii_strings(raw[:1_000_000], minimum=4, limit=200))
    strings.extend(iter_utf16_strings(raw[:1_000_000], minimum=4, limit=200))
    rendered = " | ".join(str(item["text"]) for item in strings)
    return display_text(rendered, 250_000) if rendered else f"<{len(raw)} binary bytes>"


def parse_registry(data: bytes, profile: str = "balanced") -> dict[str, Any]:
    """Enumerate bounded REGF cells, including stale values and UserAssist records."""

    result = _result("registry")
    if len(data) < 4096 or not data.startswith(b"regf"):
        result["findings"].append(_finding("error", "structure", "Invalid registry hive", "A Windows registry hive requires a complete base block."))
        return result

    maximum_scan = 256 * 1024 * 1024 if profile == "deep" else 64 * 1024 * 1024
    maximum_cells = 1_000_000 if profile == "deep" else 250_000
    maximum_values = 250_000 if profile == "deep" else 75_000
    maximum_value_bytes = 4 * 1024 * 1024 if profile == "deep" else 1 * 1024 * 1024
    deadline = time.monotonic() + (14.0 if profile == "deep" else 5.0)
    format_major = int.from_bytes(data[20:24], "little")
    format_minor = int.from_bytes(data[24:28], "little")
    legacy_11 = format_major == 1 and format_minor == 1
    record_prefix = 4 if legacy_11 else 0
    hive_bins_size = int.from_bytes(data[40:44], "little")
    declared_end = 4096 + hive_bins_size if hive_bins_size else len(data)
    scan_limit = min(len(data), declared_end, maximum_scan)
    cells: dict[int, dict[str, Any]] = {}
    bin_cursor = 4096
    hbins = 0
    malformed_cells = 0
    timed_out = False

    while bin_cursor + 32 <= scan_limit and len(cells) < maximum_cells:
        if data[bin_cursor:bin_cursor + 4] != b"hbin":
            malformed_cells += 1
            break
        bin_size = int.from_bytes(data[bin_cursor + 8:bin_cursor + 12], "little")
        if bin_size < 4096 or bin_size % 4096 or bin_cursor + bin_size > scan_limit:
            malformed_cells += 1
            break
        hbins += 1
        cell_cursor = bin_cursor + 32
        bin_end = bin_cursor + bin_size
        while cell_cursor + 4 <= bin_end and len(cells) < maximum_cells:
            if len(cells) % 8192 == 0 and time.monotonic() > deadline:
                timed_out = True
                break
            signed_size = int.from_bytes(data[cell_cursor:cell_cursor + 4], "little", signed=True)
            cell_size = abs(signed_size)
            if cell_size < 8 or cell_size % 8 or cell_cursor + cell_size > bin_end:
                malformed_cells += 1
                break
            relative = cell_cursor - 4096
            cells[relative] = {
                "absolute": cell_cursor,
                "start": cell_cursor + 4,
                "end": cell_cursor + cell_size,
                "allocated": signed_size < 0,
            }
            cell_cursor += cell_size
        if timed_out:
            break
        bin_cursor += bin_size

    key_cells: dict[int, dict[str, Any]] = {}
    value_cells: dict[int, dict[str, Any]] = {}
    for relative, cell in cells.items():
        start = int(cell["start"])
        end = int(cell["end"])
        signature = data[start + record_prefix:start + record_prefix + 2]
        if signature == b"nk" and end - start >= record_prefix + 76:
            name_length = int.from_bytes(data[start + record_prefix + 72:start + record_prefix + 74], "little")
            if name_length > end - (start + record_prefix + 76):
                malformed_cells += 1
                continue
            flags = int.from_bytes(data[start + record_prefix + 2:start + record_prefix + 4], "little")
            key_cells[relative] = {
                **cell,
                "name": _registry_text(
                    data[start + record_prefix + 76:start + record_prefix + 76 + name_length],
                    bool(flags & 0x20),
                ),
                "parent": int.from_bytes(data[start + record_prefix + 16:start + record_prefix + 20], "little"),
                "last_write": _registry_filetime(int.from_bytes(data[start + record_prefix + 4:start + record_prefix + 12], "little")),
                "value_count": int.from_bytes(data[start + record_prefix + 36:start + record_prefix + 40], "little"),
                "value_list": int.from_bytes(data[start + record_prefix + 40:start + record_prefix + 44], "little"),
            }
        elif signature == b"vk" and end - start >= record_prefix + 20:
            name_length = int.from_bytes(data[start + record_prefix + 2:start + record_prefix + 4], "little")
            if name_length > end - (start + record_prefix + 20):
                malformed_cells += 1
                continue
            flags = int.from_bytes(data[start + record_prefix + 16:start + record_prefix + 18], "little")
            value_cells[relative] = {
                **cell,
                "name": _registry_text(
                    data[start + record_prefix + 20:start + record_prefix + 20 + name_length],
                    bool(flags & 0x01),
                ),
                "data_size": int.from_bytes(data[start + record_prefix + 4:start + record_prefix + 8], "little"),
                "data_offset": int.from_bytes(data[start + record_prefix + 8:start + record_prefix + 12], "little"),
                "value_type": int.from_bytes(data[start + record_prefix + 12:start + record_prefix + 16], "little"),
            }

    path_cache: dict[int, str] = {}

    def key_path(relative: int) -> str:
        if relative in path_cache:
            return path_cache[relative]
        names: list[str] = []
        seen: set[int] = set()
        cursor = relative
        for _ in range(512):
            if cursor in seen or cursor not in key_cells:
                break
            seen.add(cursor)
            key = key_cells[cursor]
            if key["name"]:
                names.append(str(key["name"]))
            parent = int(key["parent"])
            if parent == 0xFFFFFFFF:
                break
            cursor = parent
        path = "\\".join(reversed(names)) or "<unnamed-key>"
        path_cache[relative] = path
        return path

    def value_data(value: dict[str, Any]) -> bytes | None:
        raw_size = int(value["data_size"])
        size = raw_size & 0x7FFFFFFF
        if size > maximum_value_bytes:
            return None
        if size == 0:
            return b""
        if raw_size & 0x80000000:
            return int(value["data_offset"]).to_bytes(4, "little")[:size]
        data_cell = cells.get(int(value["data_offset"]))
        if not data_cell:
            return None
        start = int(data_cell["start"])
        cell_end = int(data_cell["end"])
        if not legacy_11 and size > 16_344 and data[start:start + 2] == b"db" and cell_end - start >= 8:
            segment_count = int.from_bytes(data[start + 2:start + 4], "little")
            segment_list = cells.get(int.from_bytes(data[start + 4:start + 8], "little"))
            if not segment_list or segment_count <= 0 or segment_count > 65_536:
                return None
            list_start = int(segment_list["start"])
            available = (int(segment_list["end"]) - list_start) // 4
            if segment_count > available:
                return None
            joined = bytearray()
            for index in range(segment_count):
                segment_relative = int.from_bytes(data[list_start + index * 4:list_start + index * 4 + 4], "little")
                segment = cells.get(segment_relative)
                if not segment:
                    return None
                segment_start = int(segment["start"])
                segment_size = min(16_344, size - len(joined), int(segment["end"]) - segment_start)
                if segment_size <= 0:
                    return None
                joined.extend(data[segment_start:segment_start + segment_size])
                if len(joined) == size:
                    break
            return bytes(joined) if len(joined) == size else None
        start += 4 if legacy_11 else 0
        end = min(cell_end, start + size)
        return data[start:end] if end - start == size else None

    type_names = {
        0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY",
        4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN", 6: "REG_LINK", 7: "REG_MULTI_SZ",
        8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR",
        10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD",
    }
    associated_values: set[int] = set()
    lines: list[str] = []
    rendered_characters = 0
    rendered_values = 0
    userassist_records = 0

    def add_line(line: str) -> None:
        nonlocal rendered_characters
        if rendered_characters + len(line) <= 4_000_000:
            lines.append(line)
            rendered_characters += len(line)

    for key_relative, key in key_cells.items():
        if rendered_values >= maximum_values or time.monotonic() > deadline:
            timed_out = timed_out or time.monotonic() > deadline
            break
        path = key_path(key_relative)
        state = "allocated" if key["allocated"] else "deleted"
        add_line(f"key={path} state={state} last_write_utc={key['last_write'] or ''}")
        count = min(int(key["value_count"]), maximum_values - rendered_values)
        value_list = cells.get(int(key["value_list"]))
        if not value_list or count <= 0:
            continue
        list_start = int(value_list["start"])
        if legacy_11:
            list_start += 4
        available = (int(value_list["end"]) - list_start) // 4
        for index in range(min(count, available)):
            value_relative = int.from_bytes(data[list_start + index * 4:list_start + index * 4 + 4], "little")
            value = value_cells.get(value_relative)
            if not value:
                malformed_cells += 1
                continue
            associated_values.add(value_relative)
            raw = value_data(value)
            name = str(value["name"] or "(Default)")
            userassist = "userassist" in path.casefold() and path.casefold().endswith("count")
            if userassist and name != "(Default)":
                try:
                    name = codecs.decode(name, "rot_13")
                except (TypeError, UnicodeError):
                    pass
            rendered = _registry_value_text(int(value["value_type"]), raw) if raw is not None else "<unavailable-or-oversized>"
            value_state = "allocated" if value["allocated"] else "deleted"
            details = ""
            if userassist and raw is not None and len(raw) >= 16:
                run_count = int.from_bytes(raw[4:8], "little")
                focus_count = int.from_bytes(raw[8:12], "little")
                focus_time_ms = int.from_bytes(raw[12:16], "little")
                last_run_offset = 60 if len(raw) >= 68 else 8
                last_run = _registry_filetime(int.from_bytes(raw[last_run_offset:last_run_offset + 8], "little"))
                details = f" userassist_run_count={run_count} focus_count={focus_count} focus_time_ms={focus_time_ms} last_run_utc={last_run or ''}"
                userassist_records += 1
            add_line(
                f"key={path} value={name} type={type_names.get(int(value['value_type']), str(value['value_type']))} "
                f"state={value_state} data={rendered}{details}"
            )
            rendered_values += 1
            if rendered_values >= maximum_values:
                break

    # Unallocated VK cells often retain CTF-relevant deleted values even when their
    # parent list has been replaced. Surface them with no guessed parent path.
    for value_relative, value in value_cells.items():
        if value_relative in associated_values or rendered_values >= maximum_values:
            continue
        raw = value_data(value)
        rendered = _registry_value_text(int(value["value_type"]), raw) if raw is not None else "<unavailable-or-oversized>"
        state = "allocated-orphan" if value["allocated"] else "deleted-orphan"
        add_line(
            f"key=<orphan> value={value['name'] or '(Default)'} "
            f"type={type_names.get(int(value['value_type']), str(value['value_type']))} state={state} data={rendered}"
        )
        rendered_values += 1

    result["properties"].update({
        "primary_sequence": int.from_bytes(data[4:8], "little"),
        "secondary_sequence": int.from_bytes(data[8:12], "little"),
        "format_version": f"{format_major}.{format_minor}",
        "root_cell_offset": int.from_bytes(data[36:40], "little"),
        "hive_bins_size": hive_bins_size,
        "checksum": int.from_bytes(data[508:512], "little"),
        "hbins_scanned": hbins,
        "cells_scanned": len(cells),
        "key_cells": len(key_cells),
        "value_cells": len(value_cells),
        "values_rendered": rendered_values,
        "userassist_records": userassist_records,
        "malformed_cells_or_references": malformed_cells,
        "bytes_scanned": scan_limit,
        "timed_out": timed_out,
        "truncated": len(data) > scan_limit or len(cells) >= maximum_cells or rendered_values >= maximum_values or timed_out,
    })
    if lines:
        result["text_records"].append({
            "encoding": "windows-registry-records", "offset": None,
            "text": display_text("\n".join(lines), 4_000_000),
            "source": "REGF key/value cells and UserAssist records", "confidence_hint": 9,
        })
    if userassist_records:
        result["findings"].append(_finding(
            "info", "execution", "UserAssist execution records decoded",
            "ROT13 value names, execution counts, focus metrics, and last-run FILETIME values were decoded from bounded registry cells.",
            records=userassist_records,
        ))
    result["findings"].append(_finding(
        "info", "registry", "Windows registry hive inspected",
        "Allocated and recoverable stale key/value cells were read directly; the optional reglookup adapter remains an independent read-only cross-check.",
        keys=len(key_cells), values=len(value_cells),
    ))
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
    scan_limit = min(len(data), 16 * 1024 * 1024 if profile == "deep" else 4 * 1024 * 1024)
    records = list(iter_ascii_strings(data[:scan_limit], minimum=6, limit=2_500))
    records.extend(iter_utf16_strings(data[:scan_limit], minimum=6, limit=2_500))
    if records:
        result["text_records"].append({
            "encoding": "pst-bounded-strings", "offset": None,
            "text": display_text("\n".join(str(record["text"]) for record in records), 2_000_000),
            "source": "PST/OST bounded raw strings", "confidence_hint": 5,
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


_PNG_UNCROP_COMPRESSED_LIMIT = 32 * 1024 * 1024
_PNG_UNCROP_OUTPUT_LIMIT = 128 * 1024 * 1024
_PNG_UNCROP_PIXEL_LIMIT = 64_000_000


def _png_chunk(raw_type: bytes, payload: bytes) -> bytes:
    """Build one PNG chunk from trusted, already-bounded inputs."""

    return len(payload).to_bytes(4, "big") + raw_type + payload + _png_crc(raw_type, payload).to_bytes(4, "big")


def _png_channel_count(color_type: int | None) -> int | None:
    return {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type)


def _png_row_size(width: int, bit_depth: int | None, color_type: int | None) -> int | None:
    channels = _png_channel_count(color_type)
    if width <= 0 or not channels or bit_depth not in {1, 2, 4, 8, 16}:
        return None
    return 1 + (width * channels * bit_depth + 7) // 8


def _bounded_png_inflate(parts: list[bytes]) -> bytes | None:
    """Inflate PNG image data while enforcing compressed and output caps."""

    compressed_size = sum(len(part) for part in parts)
    if not parts or compressed_size > _PNG_UNCROP_COMPRESSED_LIMIT:
        return None
    decoder = zlib.decompressobj()
    output = bytearray()
    try:
        for part in parts:
            remaining = _PNG_UNCROP_OUTPUT_LIMIT + 1 - len(output)
            if remaining <= 0:
                return None
            output.extend(decoder.decompress(part, remaining))
            if decoder.unconsumed_tail or len(output) > _PNG_UNCROP_OUTPUT_LIMIT:
                return None
        remaining = _PNG_UNCROP_OUTPUT_LIMIT + 1 - len(output)
        output.extend(decoder.flush(max(1, remaining)))
    except zlib.error:
        return None
    if not decoder.eof or decoder.unused_data or len(output) > _PNG_UNCROP_OUTPUT_LIMIT:
        return None
    return bytes(output)


def _png_filters_are_valid(raw: bytes, row_size: int, rows: int) -> bool:
    if row_size <= 1 or rows <= 0 or len(raw) != row_size * rows:
        return False
    return all(raw[row * row_size] <= 4 for row in range(rows))


def _png_dimension_uncrop_repairs(
    data: bytes,
    *,
    idat_parts: list[bytes],
    width: int | None,
    height: int | None,
    bit_depth: int | None,
    color_type: int | None,
    interlace: int | None,
) -> list[dict[str, Any]]:
    """Recover scanlines/columns still present behind falsified IHDR dimensions.

    The repair is deliberately proof-based: the complete zlib stream must
    inflate within a fixed cap, its length must imply one unique changed
    dimension, and every inferred row must begin with a valid PNG filter byte.
    """

    if (
        len(data) < 33
        or width is None
        or height is None
        or width <= 0
        or height <= 0
        or interlace != 0
        or bit_depth is None
        or color_type is None
        or width * height > _PNG_UNCROP_PIXEL_LIMIT
    ):
        return []
    raw = _bounded_png_inflate(idat_parts)
    channels = _png_channel_count(color_type)
    row_size = _png_row_size(width, bit_depth, color_type)
    if raw is None or channels is None or row_size is None:
        return []

    dimensions: list[tuple[int, int, str]] = []
    if len(raw) % row_size == 0:
        recovered_height = len(raw) // row_size
        if (
            recovered_height > height
            and recovered_height <= 100_000
            and width * recovered_height <= _PNG_UNCROP_PIXEL_LIMIT
            and _png_filters_are_valid(raw, row_size, recovered_height)
        ):
            dimensions.append((width, recovered_height, "height"))

    if len(raw) % height == 0:
        inferred_row_size = len(raw) // height
        payload_bits = max(0, inferred_row_size - 1) * 8
        bits_per_pixel = channels * bit_depth
        if bits_per_pixel and payload_bits % bits_per_pixel == 0:
            recovered_width = payload_bits // bits_per_pixel
            if (
                recovered_width > width
                and recovered_width <= 100_000
                and recovered_width * height <= _PNG_UNCROP_PIXEL_LIMIT
                and _png_filters_are_valid(raw, inferred_row_size, height)
            ):
                dimensions.append((recovered_width, height, "width"))

    repairs: list[dict[str, Any]] = []
    for recovered_width, recovered_height, changed in dimensions:
        ihdr = bytearray(data[16:29])
        ihdr[:4] = recovered_width.to_bytes(4, "big")
        ihdr[4:8] = recovered_height.to_bytes(4, "big")
        fixed = bytearray(data)
        fixed[16:29] = ihdr
        fixed[29:33] = _png_crc(b"IHDR", bytes(ihdr)).to_bytes(4, "big")
        repairs.append({
            "label": f"png_hidden_{'columns' if changed == 'width' else 'scanlines'}_uncropped",
            "data": bytes(fixed),
            "kind": "png",
            "producer": "png-uncrop",
            "transformation": f"restore PNG IHDR {changed} proved by the complete filtered scanline stream",
            "reason": "The existing IDAT stream contains more complete, validly filtered image data than the declared canvas exposes; only the IHDR dimension and its CRC were changed.",
            "details": {
                "recovery_method": "png-hidden-scanlines",
                "old_width": width,
                "old_height": height,
                "recovered_width": recovered_width,
                "recovered_height": recovered_height,
                "inflated_scanline_bytes": len(raw),
                "unknown_pixels_filled": False,
            },
        })
    return repairs


def _png_trailer_deflate_fragment(trailer: bytes) -> bytes | None:
    """Reassemble CRC-valid old IDAT chunks left in an aCropalypse trailer."""

    if len(trailer) < 64 or len(trailer) > _PNG_UNCROP_COMPRESSED_LIMIT:
        return None
    marker = trailer.find(b"IDAT", 12)
    while marker >= 0:
        first_chunk = marker - 4
        parsed = _valid_png_chunk_at(trailer, first_chunk)
        if parsed is None or parsed[1] != b"IDAT":
            marker = trailer.find(b"IDAT", marker + 1)
            continue
        cursor = first_chunk
        complete_idat = bytearray()
        saw_iend = False
        while cursor + 12 <= len(trailer):
            chunk = _valid_png_chunk_at(trailer, cursor)
            if chunk is None:
                break
            end, raw_type, length = chunk
            if raw_type == b"IDAT":
                complete_idat.extend(trailer[cursor + 8:cursor + 8 + length])
            elif raw_type == b"IEND":
                saw_iend = True
                break
            elif raw_type[0] < ord("a"):
                break
            cursor = end
        # The first twelve trailer bytes are the overwritten remainder of the
        # old IDAT length/type/payload/CRC boundary.  The eight bytes before
        # the next complete IDAT type are the prior CRC and next chunk length,
        # not DEFLATE data.
        partial_end = marker - 8
        if saw_iend and partial_end > 12 and complete_idat:
            fragment = trailer[12:partial_end] + bytes(complete_idat)
            # A complete zlib stream ends with Adler-32; raw DEFLATE recovery
            # must omit that checksum because its beginning was overwritten.
            if len(fragment) > 8:
                return fragment[:-4]
        marker = trailer.find(b"IDAT", marker + 1)
    return None


def _shift_lsb_deflate(data: bytes, shift: int) -> bytes:
    """Shift an LSB-first DEFLATE bitstream by zero to seven bits."""

    if shift == 0:
        return data
    if not data:
        return b""
    # Treating the LSB-first byte sequence as one bounded little-endian integer
    # performs the same cross-byte shift in native code.  This avoids a
    # user-controlled Python loop over every byte for every possible bit
    # alignment while retaining the exact PoC bit ordering.
    return (int.from_bytes(data, "little") >> shift).to_bytes(len(data), "little")


def _recover_truncated_deflate_tail(fragment: bytes) -> bytes | None:
    """Recover a bounded DEFLATE tail beginning at a dynamic block boundary.

    This implements the public aCropalypse technique without guessing pixels:
    a known 32-KiB dictionary is supplied through a preceding stored block,
    then only candidates that reach a real DEFLATE end marker are accepted.
    """

    fragment = fragment[:_PNG_UNCROP_COMPRESSED_LIMIT]
    if len(fragment) < 32:
        return None
    dictionary_size = 32 * 1024
    prefix = b"\x00" + dictionary_size.to_bytes(2, "little") + (0xFFFF - dictionary_size).to_bytes(2, "little") + b"X" * dictionary_size
    max_attempts_per_shift = 4_096
    max_scan = min(len(fragment), 8 * 1024 * 1024)
    for shift in range(8):
        shifted = _shift_lsb_deflate(fragment, shift)
        view = memoryview(shifted)
        shift_attempts = 0
        for offset in range(max_scan):
            # 100b is a non-final dynamic-Huffman DEFLATE block header when
            # read least-significant bit first.
            if shifted[offset] & 0x07 != 0x04:
                continue
            shift_attempts += 1
            if shift_attempts > max_attempts_per_shift:
                break
            decoder = zlib.decompressobj(wbits=-15)
            try:
                output = bytearray(decoder.decompress(prefix, _PNG_UNCROP_OUTPUT_LIMIT + dictionary_size + 1))
                remaining = _PNG_UNCROP_OUTPUT_LIMIT + dictionary_size + 1 - len(output)
                if remaining <= 0:
                    continue
                output.extend(decoder.decompress(view[offset:], remaining))
                if decoder.unconsumed_tail or len(output) > _PNG_UNCROP_OUTPUT_LIMIT + dictionary_size:
                    continue
                remaining = _PNG_UNCROP_OUTPUT_LIMIT + dictionary_size + 1 - len(output)
                output.extend(decoder.flush(max(1, remaining)))
            except (zlib.error, ValueError):
                continue
            if not decoder.eof or decoder.unconsumed_tail:
                continue
            if decoder.unused_data and (len(decoder.unused_data) > 1 or any(decoder.unused_data)):
                continue
            recovered = bytes(output[dictionary_size:])
            if 64 <= len(recovered) <= _PNG_UNCROP_OUTPUT_LIMIT:
                return recovered
    return None


def _acropalypse_canvas_width(recovered: bytes, *, current_width: int, current_height: int, channels: int) -> tuple[int, int, int] | None:
    """Infer a unique likely screenshot width from recovered filter bytes."""

    candidates: list[tuple[int, int, int, int]] = []
    max_width = min(8_192, _PNG_UNCROP_PIXEL_LIMIT // max(1, current_height))
    for width in range(max(1, current_width), max_width + 1):
        row_size = 1 + width * channels
        recovered_height = max(current_height, (len(recovered) + row_size - 1) // row_size)
        if recovered_height > 100_000 or width * recovered_height > _PNG_UNCROP_PIXEL_LIMIT:
            continue
        canvas_size = row_size * recovered_height
        recovered_start = canvas_size - len(recovered)
        first_row_start = ((recovered_start + row_size - 1) // row_size) * row_size
        observed = 0
        valid = True
        for row_start in range(first_row_start, canvas_size, row_size):
            value = recovered[row_start - recovered_start]
            observed += 1
            if value > 4 and value != ord("X"):
                valid = False
                break
        if valid and observed >= 3:
            common_width = width in {320, 360, 375, 393, 412, 720, 768, 1080, 1200, 1280, 1440, 1536, 1600, 1920, 2160, 2560, 2880, 3200, 3840, 4096}
            candidates.append((observed, int(common_width), -width, recovered_height))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    best = candidates[0]
    best_width = -best[2]
    # Accidental filter-byte alignments are possible.  Require the best width
    # to have strictly more evidence unless the runner-up observes fewer rows.
    if len(candidates) > 1 and candidates[1][0] == best[0] and candidates[1][1] == best[1]:
        return None
    return best_width, best[3], best[0]


def _png_acropalypse_repair(
    *,
    trailer: bytes,
    width: int | None,
    height: int | None,
    bit_depth: int | None,
    color_type: int | None,
    interlace: int | None,
) -> dict[str, Any] | None:
    """Produce a forensic partial-canvas artifact from validated residue."""

    channels = _png_channel_count(color_type)
    if (
        width is None
        or height is None
        or width <= 0
        or height <= 0
        or bit_depth != 8
        or color_type not in {2, 6}
        or channels not in {3, 4}
        or interlace != 0
    ):
        return None
    fragment = _png_trailer_deflate_fragment(trailer)
    if fragment is None:
        return None
    recovered = _recover_truncated_deflate_tail(fragment)
    if recovered is None:
        return None
    dimensions = _acropalypse_canvas_width(recovered, current_width=width, current_height=height, channels=channels)
    if dimensions is None:
        return None
    recovered_width, recovered_height, filter_rows = dimensions
    row_size = 1 + recovered_width * channels
    canvas_size = row_size * recovered_height
    pixel = b"\xff\x00\xff" if channels == 3 else b"\xff\x00\xff\xff"
    placeholder_row = b"\x00" + pixel * recovered_width
    raw = bytearray(placeholder_row * recovered_height)
    recovered_start = canvas_size - len(recovered)
    raw[recovered_start:] = recovered
    # Unknown dictionary references emerge as X.  Only row filter slots are
    # normalized; unknown pixel bytes remain conspicuous magenta/X evidence.
    for row_start in range(0, canvas_size, row_size):
        if raw[row_start] > 4:
            raw[row_start] = 0
    ihdr = struct.pack(">IIBBBBB", recovered_width, recovered_height, 8, color_type, 0, 0, 0)
    recovered_png = b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + _png_chunk(b"IEND", b"")
    return {
        "label": "png_acropalypse_partial_uncrop",
        "data": recovered_png,
        "kind": "png",
        "producer": "png-uncrop",
        "transformation": "recover the surviving aCropalypse DEFLATE tail and place it on an inferred screenshot canvas",
        "reason": "CRC-valid old IDAT chunks remain after IEND, a truncated DEFLATE tail reaches a valid end marker, and repeated PNG filter bytes prove the inferred row width. Missing pixels are marked rather than invented.",
        "details": {
            "recovery_method": "acropalypse-deflate-tail",
            "old_width": width,
            "old_height": height,
            "recovered_width": recovered_width,
            "recovered_height": recovered_height,
            "surviving_scanline_bytes": len(recovered),
            "validated_filter_rows": filter_rows,
            "unknown_pixels_filled": True,
            "placeholder": "opaque magenta; unresolved dictionary bytes may remain as X",
            "partial_recovery": True,
        },
    }


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
    idat_parts: list[bytes] = []
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
        elif chunk_type == "IDAT":
            idat_parts.append(payload)
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

    dimension_repairs = _png_dimension_uncrop_repairs(
        data,
        idat_parts=idat_parts,
        width=width,
        height=height,
        bit_depth=bit_depth,
        color_type=color_type,
        interlace=interlace,
    )
    if dimension_repairs:
        result["findings"].append(_finding(
            "warning", "forensic-recovery", "PNG canvas hides encoded pixels",
            "The complete IDAT stream proves that filtered rows or columns extend beyond the declared IHDR canvas. A copy-only uncropped artifact was generated.",
            candidates=len(dimension_repairs), recovery_method="png-hidden-scanlines",
        ))
        result["repairs"].extend(dimension_repairs)

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
        if profile != "quick":
            acropalypse_repair = _png_acropalypse_repair(
                trailer=trailer,
                width=width,
                height=height,
                bit_depth=bit_depth,
                color_type=color_type,
                interlace=interlace,
            )
            if acropalypse_repair is not None:
                result["findings"].append(_finding(
                    "warning", "forensic-recovery", "Recoverable cropped screenshot residue",
                    "Old CRC-valid PNG chunks and a recoverable truncated DEFLATE stream remain after IEND. A partial uncropped canvas was generated without inventing missing pixels.",
                    recovery_method="acropalypse-deflate-tail",
                    partial_recovery=True,
                    recovered_width=acropalypse_repair["details"]["recovered_width"],
                    recovered_height=acropalypse_repair["details"]["recovered_height"],
                ))
                result["repairs"].append(acropalypse_repair)
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


def _pdf_content_text_sequences(payload: bytes) -> list[str]:
    """Join literal/hex operands inside bounded PDF text objects."""

    sequences: list[str] = []
    for block in re.finditer(rb"(?<![A-Za-z])BT(?![A-Za-z])(.{0,2000000}?)(?<![A-Za-z])ET(?![A-Za-z])", payload, re.DOTALL):
        body = block.group(1)
        if b"Tj" not in body and b"TJ" not in body and b"'" not in body and b'"' not in body:
            continue
        fragments: list[bytes] = []
        index = 0
        while index < len(body) and len(fragments) < 1_000:
            if body[index] == 0x28:
                parsed = _pdf_literal_at(body, index)
                if parsed is not None:
                    value, index = parsed
                    fragments.append(value)
                    continue
            index += 1
        for match in re.finditer(rb"(?<!<)<([0-9A-Fa-f\s]{4,2000000})>(?!>)", body):
            try:
                fragments.append(bytes.fromhex(re.sub(rb"\s+", b"", match.group(1)).decode("ascii")))
            except (ValueError, UnicodeDecodeError):
                continue
        combined = _pdf_textual(b"".join(fragments))
        if combined and len(combined.strip()) >= 4:
            sequences.append(combined)
        if len(sequences) >= 128:
            break
    return sequences


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
    for sequence in _pdf_content_text_sequences(data):
        if sequence not in seen_text:
            seen_text.add(sequence)
            result["text_records"].append({
                "source": "PDF page text sequence", "offset": None, "text": sequence, "confidence_hint": 9,
                "transform_chain": ["locate PDF BT/ET text object", "join literal and hex text operands"],
            })
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
            for sequence in _pdf_content_text_sequences(payload):
                if sequence not in seen_text:
                    seen_text.add(sequence)
                    result["text_records"].append({
                        "source": f"PDF {transformation} text sequence", "offset": stream_start, "text": sequence,
                        "confidence_hint": 9,
                        "transform_chain": ["extract bounded PDF stream", "locate BT/ET text object", "join literal and hex text operands"],
                    })
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
    max_frame_right = 0
    max_frame_bottom = 0

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
            if frame_width and frame_height:
                max_frame_right = max(max_frame_right, left + frame_width)
                max_frame_bottom = max(max_frame_bottom, top + frame_height)
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
        "maximum_frame_right": max_frame_right, "maximum_frame_bottom": max_frame_bottom,
    })
    recovered_width = max(width, max_frame_right)
    recovered_height = max(height, max_frame_bottom)
    if (
        frames
        and not malformed
        and (recovered_width > width or recovered_height > height)
        and recovered_width <= 0xFFFF
        and recovered_height <= 0xFFFF
        and recovered_width * recovered_height <= _PNG_UNCROP_PIXEL_LIMIT
    ):
        fixed = bytearray(data)
        fixed[6:10] = struct.pack("<HH", recovered_width, recovered_height)
        result["findings"].append(_finding(
            "warning", "forensic-recovery", "GIF frames extend outside the logical canvas",
            "One or more encoded image frames lie beyond the logical screen descriptor. A copy-only artifact expands the canvas to expose them.",
            old_width=width, old_height=height, recovered_width=recovered_width, recovered_height=recovered_height,
        ))
        result["repairs"].append({
            "label": "gif_hidden_canvas_uncropped",
            "data": bytes(fixed),
            "kind": "gif",
            "producer": "gif-uncrop",
            "transformation": "expand the GIF logical screen to the maximum encoded frame extent",
            "reason": "Parsed image descriptors prove that encoded frames extend beyond the declared logical screen; only the two canvas dimensions were changed.",
            "details": {
                "recovery_method": "gif-frame-extents",
                "old_width": width,
                "old_height": height,
                "recovered_width": recovered_width,
                "recovered_height": recovered_height,
                "unknown_pixels_filled": False,
            },
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
    width = height = signed_height = planes = bpp = compression = image_size = colors_used = None
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
        available_pixels = len(data) - pixel_offset
        if (
            dib_size >= 40
            and signed_height is not None
            and image_size
            and image_size == available_pixels
            and available_pixels % row_stride == 0
        ):
            recovered_height = available_pixels // row_stride
            if (
                recovered_height > height
                and recovered_height <= 100_000
                and abs(width) * recovered_height <= _PNG_UNCROP_PIXEL_LIMIT
            ):
                fixed = bytearray(data)
                fixed_height = -recovered_height if signed_height < 0 else recovered_height
                fixed[22:26] = fixed_height.to_bytes(4, "little", signed=True)
                result["findings"].append(_finding(
                    "warning", "forensic-recovery", "BMP header hides complete pixel rows",
                    "The declared image-data size and exact row stride prove that complete rows continue beyond the stored height. A copy-only uncropped artifact was generated.",
                    old_height=height, recovered_height=recovered_height, row_stride=row_stride,
                ))
                result["repairs"].append({
                    "label": "bmp_hidden_rows_uncropped",
                    "data": bytes(fixed),
                    "kind": "bmp",
                    "producer": "bmp-uncrop",
                    "transformation": "restore BMP height from the declared complete pixel-array size and exact row stride",
                    "reason": "biSizeImage equals all bytes available from bfOffBits and contains an exact larger number of complete rows; only the DIB height was changed.",
                    "details": {
                        "recovery_method": "bmp-hidden-rows",
                        "old_width": width,
                        "old_height": height,
                        "recovered_width": abs(width),
                        "recovered_height": recovered_height,
                        "row_stride": row_stride,
                        "unknown_pixels_filled": False,
                    },
                })
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
