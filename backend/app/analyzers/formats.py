from __future__ import annotations

import binascii
import struct
import zlib
from typing import Any, Callable

from .common import byte_entropy, display_text, sniff_kind


def analyze_format(kind: str, data: bytes, *, profile: str = "balanced") -> dict[str, Any]:
    parser: Callable[[bytes, str], dict[str, Any]] | None = {
        "png": parse_png,
        "jpeg": parse_jpeg,
        "gif": parse_gif,
        "bmp": parse_bmp,
        "webp": parse_webp,
        "tiff": parse_tiff,
        "ico": parse_ico,
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


def _valid_png_ihdr(data: bytes) -> bool:
    """Return whether bytes at the canonical PNG IHDR location are plausible.

    This is deliberately stricter than looking for the ASCII string ``IHDR``:
    the dimensions, colour model, and following chunk boundary must all be
    reasonable before a repair candidate is offered.
    """

    if len(data) < 49 or data[12:16] != b"IHDR":
        return False
    try:
        width, height, bit_depth, color_type, compression, filtering, interlace = struct.unpack(">IIBBBBB", data[16:29])
    except struct.error:
        return False
    if not (1 <= width <= 100_000 and 1 <= height <= 100_000):
        return False
    if width * height > 256_000_000:
        return False
    if bit_depth not in {1, 2, 4, 8, 16} or color_type not in {0, 2, 3, 4, 6}:
        return False
    if compression != 0 or filtering != 0 or interlace not in {0, 1}:
        return False
    next_type = data[37:41]
    if len(next_type) != 4 or not all(byte in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for byte in next_type):
        return False
    # The first chunk's CRC is at 29:33; the next chunk starts at 33.  A
    # complete next chunk gives us a strong anti-false-positive boundary.
    next_length = int.from_bytes(data[33:37], "big")
    return next_length <= 0x7FFFFFFF and 45 + next_length <= len(data)


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

    if _valid_png_ihdr(payload):
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
    return candidates


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
