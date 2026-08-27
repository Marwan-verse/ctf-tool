"""Bounded baseline-JPEG coefficient extraction for forensic triage.

This is intentionally a reader, not a JPEG writer.  It decodes the baseline
entropy stream into quantized DCT coefficients and exposes the coefficient
parity streams used by common JSteg-style challenges.  The parser is bounded
by the caller and treats malformed entropy data as an unsupported candidate.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable


_ZIGZAG = (
    0, 1, 8, 16, 9, 2, 3, 10,
    17, 24, 32, 25, 18, 11, 4, 5,
    12, 19, 26, 33, 40, 48, 41, 34,
    27, 20, 13, 6, 7, 14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36,
    29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46,
    53, 60, 61, 54, 47, 55, 62, 63,
)


@dataclass(frozen=True)
class JPEGComponent:
    component_id: int
    horizontal_sampling: int
    vertical_sampling: int
    quantization_table: int


@dataclass(frozen=True)
class JPEGFrame:
    width: int
    height: int
    precision: int
    components: tuple[JPEGComponent, ...]


class _JPEGError(ValueError):
    pass


class _BitReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0
        self.bits_left = 0
        self.buffer = 0

    def read(self, count: int) -> int:
        if count < 0 or count > 24:
            raise _JPEGError("unsupported bit count")
        value = 0
        for _ in range(count):
            if self.bits_left == 0:
                if self.offset >= len(self.data):
                    raise _JPEGError("truncated entropy stream")
                self.buffer = self.data[self.offset]
                self.offset += 1
                self.bits_left = 8
            self.bits_left -= 1
            value = (value << 1) | ((self.buffer >> self.bits_left) & 1)
        return value


def _huffman_table(lengths: bytes, symbols: bytes) -> dict[tuple[int, int], int]:
    if len(lengths) != 16 or sum(lengths) != len(symbols):
        raise _JPEGError("invalid Huffman table")
    table: dict[tuple[int, int], int] = {}
    code = 0
    cursor = 0
    for size, count in enumerate(lengths, 1):
        for _ in range(count):
            table[(size, code)] = symbols[cursor]
            cursor += 1
            code += 1
        code <<= 1
    return table


def _decode_huffman(reader: _BitReader, table: dict[tuple[int, int], int]) -> int:
    code = 0
    for size in range(1, 17):
        code = (code << 1) | reader.read(1)
        value = table.get((size, code))
        if value is not None:
            return value
    raise _JPEGError("invalid Huffman code")


def _receive_extend(reader: _BitReader, size: int) -> int:
    if size == 0:
        return 0
    value = reader.read(size)
    if value < (1 << (size - 1)):
        value -= (1 << size) - 1
    return value


def _entropy_bytes(data: bytes, start: int, end: int) -> bytes:
    """Return entropy bytes with byte stuffing removed, stopping at EOI."""

    output = bytearray()
    cursor = start
    while cursor < end:
        value = data[cursor]
        cursor += 1
        if value != 0xFF:
            output.append(value)
            continue
        if cursor >= end:
            break
        marker = data[cursor]
        cursor += 1
        if marker == 0x00:
            output.append(0xFF)
        elif 0xD0 <= marker <= 0xD7:
            # Restart markers need predictor resets.  This bounded reader does
            # not silently cross them; callers can report the candidate as
            # unsupported instead of decoding a misleading stream.
            raise _JPEGError("restart markers are not supported")
        else:
            break
    return bytes(output)


def decode_baseline_coefficients(data: bytes, *, max_bytes: int = 64 * 1024 * 1024) -> tuple[JPEGFrame, tuple[tuple[int, tuple[int, ...]], ...]]:
    """Decode a bounded, single-scan baseline JPEG into quantized blocks.

    Returns the frame description and ``(component_id, block)`` entries in
    MCU/component order. Each block is a 64-entry tuple in natural coefficient
    positions (the helper below emits it in zig-zag order). Progressive JPEGs,
    arithmetic coding, restart intervals, and multi-scan files are rejected.
    """

    if len(data) > max_bytes or not data.startswith(b"\xff\xd8"):
        raise _JPEGError("not a bounded JPEG")
    cursor = 2
    frame: JPEGFrame | None = None
    quantization: dict[int, tuple[int, ...]] = {}
    dc_tables: dict[int, dict[tuple[int, int], int]] = {}
    ac_tables: dict[int, dict[tuple[int, int], int]] = {}
    scan_components: list[tuple[int, int, int]] = []
    scan_start: int | None = None
    scan_end: int | None = None
    while cursor + 1 < len(data):
        if data[cursor] != 0xFF:
            raise _JPEGError("unexpected bytes before scan")
        while cursor < len(data) and data[cursor] == 0xFF:
            cursor += 1
        if cursor >= len(data):
            break
        marker = data[cursor]
        cursor += 1
        if marker == 0x00:
            continue
        if marker == 0xD9:
            break
        if marker == 0xDA:
            if cursor + 2 > len(data):
                raise _JPEGError("truncated SOS")
            length = int.from_bytes(data[cursor:cursor + 2], "big")
            if length < 2 or cursor + length > len(data):
                raise _JPEGError("invalid SOS length")
            payload = data[cursor + 2:cursor + length]
            if len(payload) < 3:
                raise _JPEGError("invalid SOS payload")
            count = payload[0]
            if len(payload) != 1 + 2 * count + 3:
                raise _JPEGError("unsupported SOS payload")
            scan_components = []
            for index in range(count):
                component_id = payload[1 + 2 * index]
                selector = payload[2 + 2 * index]
                scan_components.append((component_id, selector >> 4, selector & 0x0F))
            # Baseline scans cover all coefficients in one pass.
            if payload[-3:] != b"\x00\x3f\x00":
                raise _JPEGError("progressive or differential JPEG")
            scan_start = cursor + length
            scan_end = data.find(b"\xff\xd9", scan_start)
            if scan_end < 0:
                raise _JPEGError("missing EOI")
            break
        if marker in {0xD8, *range(0xD0, 0xD8), 0x01}:
            continue
        if cursor + 2 > len(data):
            raise _JPEGError("truncated JPEG segment")
        length = int.from_bytes(data[cursor:cursor + 2], "big")
        if length < 2 or cursor + length > len(data):
            raise _JPEGError("invalid JPEG segment length")
        payload = data[cursor + 2:cursor + length]
        if marker == 0xDB:
            offset = 0
            while offset < len(payload):
                info = payload[offset]
                offset += 1
                precision = info >> 4
                table_id = info & 0x0F
                if precision != 0 or offset + 64 > len(payload):
                    raise _JPEGError("unsupported quantization table")
                # Quantization values are not needed for parity, but parsing
                # them proves the segment is structurally valid.
                quantization[table_id] = tuple(payload[offset:offset + 64])
                offset += 64
        elif marker == 0xC0:
            if len(payload) < 6:
                raise _JPEGError("invalid SOF0")
            precision_value = payload[0]
            component_count = payload[5]
            expected = 6 + 3 * component_count
            if precision_value != 8 or len(payload) != expected or component_count == 0:
                raise _JPEGError("unsupported SOF0")
            components: list[JPEGComponent] = []
            for index in range(component_count):
                base = 6 + 3 * index
                sampling = payload[base + 1]
                components.append(JPEGComponent(payload[base], sampling >> 4, sampling & 0x0F, payload[base + 2]))
            frame = JPEGFrame(int.from_bytes(payload[3:5], "big"), int.from_bytes(payload[1:3], "big"), precision_value, tuple(components))
        elif marker == 0xC4:
            offset = 0
            while offset < len(payload):
                info = payload[offset]
                offset += 1
                if offset + 16 > len(payload):
                    raise _JPEGError("truncated Huffman table")
                lengths = payload[offset:offset + 16]
                offset += 16
                symbol_count = sum(lengths)
                if offset + symbol_count > len(payload):
                    raise _JPEGError("truncated Huffman symbols")
                table = _huffman_table(lengths, payload[offset:offset + symbol_count])
                offset += symbol_count
                (dc_tables if info >> 4 == 0 else ac_tables)[info & 0x0F] = table
        elif marker not in {0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xFE, 0xDD}:
            # APP/COM/DRI are harmless; all other frame types are rejected.
            if 0xC1 <= marker <= 0xCF:
                raise _JPEGError("unsupported JPEG frame")
        cursor += length
    if frame is None or scan_start is None or scan_end is None or not scan_components:
        raise _JPEGError("incomplete baseline JPEG")
    component_map = {component.component_id: component for component in frame.components}
    if any(component_id not in component_map for component_id, _, _ in scan_components):
        raise _JPEGError("SOS component is not in frame")
    if any(component.quantization_table not in quantization for component in frame.components):
        raise _JPEGError("missing quantization table")
    if any(dc not in dc_tables or ac not in ac_tables for _, dc, ac in scan_components):
        raise _JPEGError("missing Huffman table")
    maximum_h = max(component.horizontal_sampling for component in frame.components)
    maximum_v = max(component.vertical_sampling for component in frame.components)
    if maximum_h <= 0 or maximum_v <= 0 or maximum_h > 4 or maximum_v > 4:
        raise _JPEGError("unsupported sampling factors")
    mcu_columns = math.ceil(frame.width / (8 * maximum_h))
    mcu_rows = math.ceil(frame.height / (8 * maximum_v))
    if mcu_columns * mcu_rows * sum(component.horizontal_sampling * component.vertical_sampling for component in frame.components) > 2_000_000:
        raise _JPEGError("coefficient limit exceeded")
    reader = _BitReader(_entropy_bytes(data, scan_start, scan_end))
    predictors = {component.component_id: 0 for component in frame.components}
    blocks: list[tuple[int, tuple[int, ...]]] = []
    for _mcu_y in range(mcu_rows):
        for _mcu_x in range(mcu_columns):
            for component_id, dc_id, ac_id in scan_components:
                component = component_map[component_id]
                dc_table = dc_tables[dc_id]
                ac_table = ac_tables[ac_id]
                for _v in range(component.vertical_sampling):
                    for _h in range(component.horizontal_sampling):
                        coefficients = [0] * 64
                        dc_size = _decode_huffman(reader, dc_table)
                        predictors[component_id] += _receive_extend(reader, dc_size)
                        coefficients[0] = predictors[component_id]
                        position = 1
                        while position < 64:
                            symbol = _decode_huffman(reader, ac_table)
                            run = symbol >> 4
                            size = symbol & 0x0F
                            if size == 0:
                                if run == 0:
                                    break
                                if run != 15:
                                    raise _JPEGError("invalid AC run")
                                position += 16
                                continue
                            position += run
                            if position >= 64:
                                raise _JPEGError("AC coefficient overflow")
                            coefficients[_ZIGZAG[position]] = _receive_extend(reader, size)
                            position += 1
                        blocks.append((component_id, tuple(coefficients)))
    return frame, tuple(blocks)


def coefficient_bitstreams(blocks: Iterable[tuple[int, tuple[int, ...]]]) -> dict[str, bytes]:
    """Build bounded JSteg-style parity streams from decoded blocks."""

    variants: dict[str, bytearray] = {}
    block_list = tuple(blocks)
    first_component = block_list[0][0] if block_list else None
    for name, minimum in (("ac_nonzero", 1), ("ac_abs_gt_one", 2)):
        for component_scope in ("all", "first"):
            bits = bytearray()
            for entry in block_list:
                component_id, block = entry
                if component_scope == "first" and component_id != first_component:
                    continue
                # Blocks are stored in natural (row-major) coefficient
                # positions; JSteg consumes AC values in JPEG zig-zag order.
                for position in range(1, 64):
                    coefficient = block[_ZIGZAG[position]]
                    if abs(coefficient) < minimum:
                        continue
                    bits.append(coefficient & 1)
            for packing, shift in (("msb", 7), ("lsb", 0)):
                packed = bytearray((len(bits) + 7) // 8)
                for index, bit in enumerate(bits):
                    packed[index // 8] |= bit << (shift - (index % 8) if packing == "msb" else index % 8)
                variants[f"{name}:{component_scope}:{packing}"] = packed
    return dict(variants)


__all__ = ["JPEGFrame", "JPEGComponent", "decode_baseline_coefficients", "coefficient_bitstreams"]
