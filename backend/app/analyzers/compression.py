"""Small, bounded decompression helpers used by the forensic analyzers.

The standard library covers most formats seen in CTFs, but not LZIP, LZ4
frames, or LZOP.  These implementations intentionally handle framing and
size limits only; they do not execute or materialize untrusted paths.
"""

from __future__ import annotations

import lzma
import struct
import zlib
from typing import Callable


class CompressionError(ValueError):
    """Raised when a stream is malformed or exceeds a safety bound."""


def _bounded_append(output: bytearray, piece: bytes, maximum: int) -> None:
    if len(output) + len(piece) > maximum:
        raise CompressionError("decompressed output limit exceeded")
    output.extend(piece)


def decompress_lzip(data: bytes, maximum: int = 16 * 1024 * 1024) -> bytes:
    """Decompress a LZIP member using its raw LZMA1 payload."""

    if len(data) < 26 or not data.startswith(b"LZIP\x01"):
        raise CompressionError("invalid LZIP header")
    dictionary_code = data[5] & 0x1F
    if dictionary_code < 12 or dictionary_code > 27:
        raise CompressionError("unsupported LZIP dictionary size")
    dictionary_size = 1 << dictionary_code
    footer = data[-20:]
    stored_crc, stored_size, stored_member_size = struct.unpack("<IQQ", footer)
    if stored_member_size != len(data):
        raise CompressionError("LZIP member size mismatch")
    try:
        output = lzma.decompress(
            data[6:-20],
            format=lzma.FORMAT_RAW,
            filters=[{"id": lzma.FILTER_LZMA1, "dict_size": dictionary_size, "lc": 3, "lp": 0, "pb": 2}],
        )
    except (lzma.LZMAError, ValueError) as exc:
        raise CompressionError(f"LZIP LZMA payload rejected: {exc}") from exc
    if len(output) > maximum:
        raise CompressionError("decompressed output limit exceeded")
    if stored_size != len(output) or (zlib.crc32(output) & 0xFFFFFFFF) != stored_crc:
        raise CompressionError("LZIP footer checksum or size mismatch")
    return output


def _decompress_lz4_block(block: bytes, history: bytearray, maximum: int) -> bytes:
    """Decode one LZ4 block, retaining the preceding frame history."""

    produced = bytearray()
    cursor = 0
    while cursor < len(block):
        token = block[cursor]
        cursor += 1
        literal_length = token >> 4
        if literal_length == 15:
            while True:
                if cursor >= len(block):
                    raise CompressionError("truncated LZ4 literal length")
                extra = block[cursor]
                cursor += 1
                literal_length += extra
                if extra != 255:
                    break
        if cursor + literal_length > len(block):
            raise CompressionError("truncated LZ4 literals")
        _bounded_append(produced, block[cursor:cursor + literal_length], maximum)
        cursor += literal_length
        if cursor == len(block):
            break
        if cursor + 2 > len(block):
            raise CompressionError("truncated LZ4 match offset")
        match_offset = block[cursor] | (block[cursor + 1] << 8)
        cursor += 2
        if match_offset == 0 or match_offset > len(history) + len(produced):
            raise CompressionError("invalid LZ4 match offset")
        match_length = token & 0x0F
        if match_length == 15:
            while True:
                if cursor >= len(block):
                    raise CompressionError("truncated LZ4 match length")
                extra = block[cursor]
                cursor += 1
                match_length += extra
                if extra != 255:
                    break
        match_length += 4
        for _ in range(match_length):
            source_index = len(history) + len(produced) - match_offset
            if source_index < 0 or source_index >= len(history) + len(produced):
                raise CompressionError("invalid LZ4 back-reference")
            if source_index < len(history):
                value = history[source_index]
            else:
                value = produced[source_index - len(history)]
            _bounded_append(produced, bytes((value,)), maximum)
    return bytes(produced)


def decompress_lz4(data: bytes, maximum: int = 16 * 1024 * 1024) -> bytes:
    """Decompress an LZ4 frame (independent or dependent blocks)."""

    if len(data) < 7 or data[:4] != b"\x04\x22\x4D\x18":
        raise CompressionError("invalid LZ4 frame magic")
    flg, bd = data[4], data[5]
    if (flg >> 6) != 1:
        raise CompressionError("unsupported LZ4 frame version")
    cursor = 6
    content_size = None
    if flg & 0x08:
        if cursor + 8 > len(data):
            raise CompressionError("truncated LZ4 content-size field")
        content_size = int.from_bytes(data[cursor:cursor + 8], "little")
        cursor += 8
    if flg & 0x01:
        if cursor + 4 > len(data):
            raise CompressionError("truncated LZ4 dictionary-id field")
        cursor += 4
    if cursor >= len(data):
        raise CompressionError("truncated LZ4 header checksum")
    cursor += 1  # xxHash header checksum; framing remains bounded without an xxHash dependency.
    block_max_code = (bd >> 4) & 0x07
    block_maximums = {4: 64 * 1024, 5: 256 * 1024, 6: 1024 * 1024, 7: 4 * 1024 * 1024}
    if block_max_code not in block_maximums:
        raise CompressionError("invalid LZ4 block-size code")
    frame_history = bytearray()
    output = bytearray()
    while True:
        if cursor + 4 > len(data):
            raise CompressionError("truncated LZ4 block header")
        block_size = int.from_bytes(data[cursor:cursor + 4], "little")
        cursor += 4
        if block_size == 0:
            break
        uncompressed = bool(block_size & 0x80000000)
        block_size &= 0x7FFFFFFF
        if block_size > block_maximums[block_max_code] or cursor + block_size > len(data):
            raise CompressionError("invalid LZ4 block size")
        block = data[cursor:cursor + block_size]
        cursor += block_size
        if uncompressed:
            _bounded_append(output, block, maximum)
            frame_history.extend(block)
        else:
            decoded = _decompress_lz4_block(block, frame_history, maximum - len(output))
            _bounded_append(output, decoded, maximum)
            frame_history.extend(decoded)
        # Keep the history bounded to the LZ4 window while retaining output.
        if len(frame_history) > 64 * 1024:
            del frame_history[:-64 * 1024]
        if flg & 0x10:
            if cursor + 4 > len(data):
                raise CompressionError("truncated LZ4 block checksum")
            cursor += 4
    if flg & 0x04:
        if cursor + 4 > len(data):
            raise CompressionError("truncated LZ4 content checksum")
        cursor += 4
    if content_size is not None and content_size != len(output):
        raise CompressionError("LZ4 content-size mismatch")
    return bytes(output)


def decompress_lzma_alone(data: bytes, maximum: int = 16 * 1024 * 1024) -> bytes:
    """Decompress the legacy 13-byte-header LZMA-alone format."""

    if len(data) < 13:
        raise CompressionError("truncated LZMA-alone stream")
    try:
        output = lzma.decompress(data, format=lzma.FORMAT_ALONE)
    except (lzma.LZMAError, ValueError) as exc:
        raise CompressionError(f"LZMA-alone stream rejected: {exc}") from exc
    if len(output) > maximum:
        raise CompressionError("decompressed output limit exceeded")
    return output


def decompress_lzop(data: bytes, maximum: int = 16 * 1024 * 1024) -> bytes:
    """Read LZOP framing and recover uncompressed blocks.

    LZOP permits blocks whose compressed size equals their original size.  That
    representation is common in small CTF chains and needs no native LZO
    dependency.  Compressed LZO blocks are reported as unsupported rather than
    guessed or executed.
    """

    magic = b"\x89LZO\x00\r\n\x1a\n"
    if len(data) < 41 or not data.startswith(magic):
        raise CompressionError("invalid LZOP header")
    cursor = 9
    try:
        _version, _library, _extract = struct.unpack_from(">HHH", data, cursor)
        cursor += 6
        _method, _level = struct.unpack_from(">BB", data, cursor)
        cursor += 2
        _flags, _mode, _mtime, _gmtdiff = struct.unpack_from(">IIII", data, cursor)
        flags = _flags
        cursor += 16
        name_length = data[cursor]
        cursor += 1
        if cursor + name_length + 4 > len(data):
            raise CompressionError("truncated LZOP filename/header checksum")
        cursor += name_length + 4  # filename and header checksum
    except (IndexError, struct.error) as exc:
        raise CompressionError("truncated LZOP header") from exc
    output = bytearray()
    # LZOP stores the enabled data checksum(s) *between* the size pair and
    # the block bytes.  The small CTF-oriented streams encountered in the
    # wild use one Adler/CRC checksum (flags bit 0); a second checksum is not
    # emitted merely because another high-level flag bit is set.
    checksum_count = 1 if flags & 0x00000003 else 0
    while cursor + 8 <= len(data):
        original_size, compressed_size = struct.unpack_from(">II", data, cursor)
        cursor += 8
        if original_size == 0:
            break
        if cursor + 4 * checksum_count > len(data):
            raise CompressionError("truncated LZOP block checksum")
        cursor += 4 * checksum_count
        if compressed_size > len(data) - cursor:
            raise CompressionError("truncated LZOP block")
        block = data[cursor:cursor + compressed_size]
        cursor += compressed_size
        if compressed_size != original_size:
            raise CompressionError("compressed LZO block requires the optional native LZO decoder")
        _bounded_append(output, block, maximum)
    if not output:
        raise CompressionError("LZOP contained no recoverable blocks")
    return bytes(output)


DECODERS: dict[str, Callable[[bytes, int], bytes]] = {
    "lzip": decompress_lzip,
    "lz4": decompress_lz4,
    "lzma": decompress_lzma_alone,
    "lzop": decompress_lzop,
}
