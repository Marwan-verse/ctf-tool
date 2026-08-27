from __future__ import annotations

import io
import struct
from pathlib import Path

from app.analyzers.visual import _iter_low_color_binary_variants, analyze_visual


def _gif_with_white_local_palette(indices: bytes) -> bytes:
    """Build one GIF frame whose visually identical palette hides its indexes."""

    codes = [256, *indices, 257]
    packed = 0
    bit_count = 0
    compressed = bytearray()
    for code in codes:
        packed |= code << bit_count
        bit_count += 9
        while bit_count >= 8:
            compressed.append(packed & 0xFF)
            packed >>= 8
            bit_count -= 8
    if bit_count:
        compressed.append(packed & 0xFF)
    if len(compressed) > 255:
        raise ValueError("test GIF must fit in one data subblock")
    return b"".join((
        b"GIF89a",
        struct.pack("<HHBBB", len(indices), 1, 0, 0, 0),
        b"\x2c" + struct.pack("<HHHHB", 0, 0, len(indices), 1, 0x87),
        b"\xff" * (256 * 3),
        bytes((8, len(compressed))) + bytes(compressed) + b"\x00\x3b",
    ))


def test_palette_index_bytes_are_preserved_for_steganography(tmp_path: Path) -> None:
    from PIL import Image

    payload = b"flag{palette_indexes}" + b"\0\0\0"
    image = Image.frombytes("P", (len(payload), 1), payload)
    image.putpalette([component for value in range(256) for component in (value, value, value)])
    path = tmp_path / "palette-indices.png"
    image.save(path, format="PNG")

    report = analyze_visual(
        path,
        profile="balanced",
        max_megapixels=1,
        lsb_analysis=False,
        ocr=False,
        barcodes=False,
        color_remap_variants=0,
    )

    assert report["status"] == "completed"
    assert report["properties"]["palette_index_analysis"]["palette_entries"] == 256
    assert any(view["label"] == "palette_indices" for view in report["visuals"])
    assert any(record["source"] == "palette-index-bytes" and record["text"] == "flag{palette_indexes}" for record in report["text_records"])
    assert any(stream["label"] == "palette_index_bytes" for stream in report["stego_streams"])


def test_channel_bitplane_xor_cancels_shared_noise(tmp_path: Path) -> None:
    from PIL import Image

    message_bits = (0, 1, 0, 0, 0, 0, 0, 1)  # ASCII A
    noise_bits = (1, 0, 1, 1, 0, 1, 0, 0)
    image = Image.new("RGBA", (len(message_bits), 1))
    image.putdata([
        (0, 64 | (message ^ noise), 0, 254 | noise)
        for message, noise in zip(message_bits, noise_bits, strict=True)
    ])
    path = tmp_path / "channel-xor.png"
    image.save(path, format="PNG")

    report = analyze_visual(
        path,
        profile="balanced",
        max_megapixels=1,
        lsb_analysis=False,
        ocr=False,
        barcodes=False,
        color_remap_variants=0,
    )

    xored = next(view for view in report["visuals"] if view["label"] == "bitplane_xor_green_alpha_0")
    decoded = Image.open(io.BytesIO(xored["data"]))
    assert tuple(1 if value else 0 for value in decoded.convert("L").tobytes()) == message_bits


def test_gif_local_palette_indices_survive_pillow_frame_compositing(tmp_path: Path) -> None:
    path = tmp_path / "white-local-palette.gif"
    path.write_bytes(_gif_with_white_local_palette(b"flag{gif_local_indices}"))

    report = analyze_visual(
        path,
        profile="balanced",
        max_megapixels=1,
        lsb_analysis=False,
        ocr=False,
        barcodes=False,
        color_remap_variants=0,
    )

    assert report["status"] == "completed"
    assert report["properties"]["gif_palette_index_analysis"]["decoded_frames"] == 1
    assert any(view["label"] == "gif_palette_indices_000_remap" for view in report["visuals"])
    assert any(record["source"] == "gif-palette-index:frame-0" and record["text"] == "flag{gif_local_indices}" for record in report["text_records"])


def test_low_color_qr_mapping_enumeration_is_bounded_and_complete_for_three_colors() -> None:
    from PIL import Image

    image = Image.new("RGB", (3, 1))
    image.putdata(((255, 0, 0), (0, 255, 0), (0, 0, 255)))

    variants = list(_iter_low_color_binary_variants(image, "deep", Image))

    assert len(variants) == 6
    assert len({variant.tobytes() for _name, variant in variants}) == 6
    assert all(set(variant.tobytes()) <= {0, 255} for _name, variant in variants)


def test_baseline_jpeg_coefficient_reader_exposes_jsteg_candidates(tmp_path: Path) -> None:
    from PIL import Image
    from app.analyzers.jpeg_coeff import coefficient_bitstreams, decode_baseline_coefficients

    image = Image.new("RGB", (32, 24))
    image.putdata([
        ((x * 37 + y * 13) & 0xFF, (x * 11 + y * 61) & 0xFF, (x * 73 + y * 7) & 0xFF)
        for y in range(24) for x in range(32)
    ])
    path = tmp_path / "coefficient-carrier.jpg"
    image.save(path, format="JPEG", quality=90, subsampling=0)

    frame, blocks = decode_baseline_coefficients(path.read_bytes())
    assert (frame.width, frame.height) == (32, 24)
    assert len(blocks) == 36
    streams = coefficient_bitstreams(blocks)
    assert streams["ac_abs_gt_one:first:lsb"]

    report = analyze_visual(
        path,
        profile="balanced",
        max_megapixels=1,
        lsb_analysis=False,
        ocr=False,
        barcodes=False,
        color_remap_variants=0,
    )
    details = next(item["details"] for item in report["submethods"] if item["id"] == "jpeg_coefficients")
    assert details["status"] == "completed"
    assert details["blocks"] == 36
