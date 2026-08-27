from __future__ import annotations

import io
import math
import re
import time
import warnings
from pathlib import Path
from typing import Any, Iterable

from .common import byte_entropy, display_text, iter_ascii_strings, normalize_json, sha256_bytes, sniff_kind, utc_now
from .jpeg_coeff import coefficient_bitstreams, decode_baseline_coefficients


def analyze_visual(
    path: Any,
    *,
    profile: str,
    max_megapixels: int,
    enabled: bool = True,
    lsb_analysis: bool = True,
    ocr: bool = True,
    barcodes: bool = True,
    ocr_language: str = "eng",
    color_remap_variants: int = 8,
) -> dict[str, Any]:
    """Decode pixels safely and produce bounded, useful visual transformations."""
    started_at = utc_now()
    start = time.monotonic()
    result: dict[str, Any] = {
        "id": "pillow-visual", "name": "Pixel, frame, channel, and bit-plane analysis",
        "category": "visual", "status": "missing", "applicable": True,
        "started_at": started_at, "duration_ms": 0, "summary": "",
        "tool": {"executable": "Pillow", "resolved": None, "version": None},
        "metadata": {}, "properties": {}, "text_records": [], "visuals": [],
        "stego_streams": [], "findings": [], "integrations": {}, "submethods": [],
    }
    if not enabled:
        result["status"] = "skipped"
        result["summary"] = "Decoded-pixel analysis was disabled in this job's settings."
        return result
    try:
        import PIL  # type: ignore
        from PIL import ExifTags, Image, ImageChops, ImageEnhance, ImageFilter, ImageOps  # type: ignore
    except ImportError:
        result["summary"] = "Optional Python package Pillow is not installed; pixel-level analysis was skipped."
        return result

    result["tool"]["version"] = getattr(PIL, "__version__", None)
    result["integrations"]["pillow"] = {"status": "available", "version": getattr(PIL, "__version__", None)}
    old_limit = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = max(1_000_000, max_megapixels * 1_000_000)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(path) as opened:
                width, height = opened.size
                pixel_count = width * height
                if width <= 0 or height <= 0 or pixel_count > max_megapixels * 1_000_000:
                    raise ValueError(f"decoded dimensions {width}x{height} exceed the {max_megapixels} MP safety limit")
                frame_count = int(getattr(opened, "n_frames", 1) or 1)
                result["properties"].update({
                    "format": opened.format, "width": width, "height": height, "mode": opened.mode,
                    "frame_count": frame_count, "animated": bool(getattr(opened, "is_animated", False)),
                })
                info = {}
                for key, value in list(opened.info.items())[:300]:
                    if key.lower() in {"icc_profile", "exif"} and isinstance(value, bytes):
                        info[key] = {"size": len(value), "sha256": sha256_bytes(value)}
                    else:
                        info[key] = normalize_json(value)
                        if isinstance(value, (str, bytes)):
                            text = value.decode("utf-8", "replace") if isinstance(value, bytes) else value
                            result["text_records"].append({"source": f"Pillow info:{key}", "offset": None, "text": display_text(text, 2_000_000)})
                result["metadata"]["pillow_info"] = info
                try:
                    exif = opened.getexif()
                    exif_values = {}
                    for tag, value in list(exif.items())[:1000]:
                        name = ExifTags.TAGS.get(tag, str(tag))
                        exif_values[name] = normalize_json(value)
                        if isinstance(value, (str, bytes)):
                            text = value.decode("utf-8", "replace") if isinstance(value, bytes) else value
                            result["text_records"].append({"source": f"EXIF:{name}", "offset": None, "text": display_text(text, 2_000_000)})
                    result["metadata"]["exif"] = exif_values
                except Exception as exc:
                    result["metadata"]["exif_error"] = f"{type(exc).__name__}: {display_text(exc, 300)}"

                opened.seek(0)
                palette_source = opened.copy() if opened.mode == "P" else None
                base = opened.convert("RGBA")
                result["visuals"].append(_visual("safe_preview", "Safe decoded preview", base, "Pillow", {"operation": "decode and convert to RGBA"}))
                palette_details = _add_palette_index_analysis(result, palette_source, profile, Image)
                if palette_details is not None:
                    result["submethods"].append({
                        "id": "palette_indices", "name": "Palette-index analysis", "category": "steganography",
                        "status": "completed", "applicable": True, "started_at": started_at, "duration_ms": 0,
                        "summary": (
                            f"Inspected {palette_details['inspected_bytes']} original palette-index byte(s); "
                            f"generated {palette_details['view_count']} index view(s) and found "
                            f"{palette_details['text_record_count']} noteworthy text record(s)."
                        ),
                        "tool": {"executable": "Pillow", "resolved": "built-in", "version": getattr(PIL, "__version__", None)},
                        "details": palette_details,
                    })
                gif_index_details = _add_gif_frame_index_analysis(
                    result, path, profile, Image, max_megapixels
                ) if opened.format == "GIF" else None
                if gif_index_details is not None:
                    result["submethods"].append({
                        "id": "gif_palette_indices", "name": "GIF frame palette-index analysis", "category": "steganography",
                        "status": "completed", "applicable": True, "started_at": started_at, "duration_ms": 0,
                        "summary": (
                            f"Decoded original index planes from {gif_index_details['frame_count']} GIF frame(s); "
                            f"generated {gif_index_details['view_count']} view(s)."
                        ),
                        "tool": {"executable": "built-in GIF LZW reader", "resolved": "built-in", "version": None},
                        "details": gif_index_details,
                    })
                decomposer_start = len(result["visuals"])
                _add_pixel_visuals(result, base, profile, Image, ImageOps, ImageChops, ImageEnhance, ImageFilter)
                decomposer_views = len(result["visuals"]) - decomposer_start
                result["submethods"].append({
                    "id": "decomposer", "name": "Bit-layer decomposer", "category": "visual",
                    "status": "completed", "applicable": True, "started_at": started_at, "duration_ms": 0,
                    "summary": f"Generated {decomposer_views} channel, threshold, edge, transparency, and bit-plane view(s).",
                    "tool": {"executable": "Pillow", "resolved": "built-in", "version": getattr(PIL, "__version__", None)},
                    "details": {"view_count": decomposer_views},
                })
                remap_count = _add_color_remaps(result, base, color_remap_variants, ImageOps)
                result["submethods"].append({
                    "id": "color_remapping", "name": "Color remapping", "category": "visual",
                    "status": "completed" if remap_count else "skipped", "applicable": True,
                    "started_at": started_at if remap_count else None, "duration_ms": 0,
                    "summary": (
                        f"Generated {remap_count} deterministic high-contrast color remapping variant(s)."
                        if remap_count else "Color remapping was configured for zero variants."
                    ),
                    "tool": {"executable": "Pillow", "resolved": "built-in", "version": getattr(PIL, "__version__", None)},
                    "details": {"variant_count": remap_count},
                })
                _add_frames(result, opened, profile, Image, ImageChops)
                if lsb_analysis:
                    _add_lsb_analysis(result, base, profile)
                else:
                    result["integrations"]["built-in-lsb"] = {"status": "skipped", "reason": "Disabled in job settings."}
                if opened.format == "JPEG" and profile != "quick":
                    coefficient_details = _add_jpeg_coefficient_analysis(result, path, profile)
                    if coefficient_details is not None:
                        result["submethods"].append({
                            "id": "jpeg_coefficients", "name": "JPEG DCT coefficient parity", "category": "steganography",
                            "status": coefficient_details["status"], "applicable": True,
                            "started_at": started_at, "duration_ms": coefficient_details["duration_ms"],
                            "summary": coefficient_details["summary"],
                            "tool": {"executable": "built-in baseline JPEG reader", "resolved": "built-in", "version": None},
                            "details": coefficient_details,
                        })
                _add_optional_cv(result, base, profile)
                _add_ocr_and_barcodes(
                    result,
                    base,
                    profile,
                    Image,
                    ImageOps,
                    run_ocr=ocr,
                    run_barcodes=barcodes,
                    ocr_language=ocr_language,
                )
                result["status"] = "completed"
                result["summary"] = (
                    f"Decoded {width}x{height} {opened.mode} image; generated {len(result['visuals'])} "
                    f"bounded visual view(s) and {len(result['stego_streams'])} noteworthy bitstream(s)."
                )
    except Exception as exc:
        result["status"] = "failed"
        result["summary"] = f"Pixel decoder rejected the input safely: {type(exc).__name__}: {display_text(exc, 400)}"
        result["findings"].append({
            "severity": "warning", "category": "decode", "title": "Pixel decoding failed",
            "description": "Structural byte analysis remains available, but decoded-pixel methods could not run.",
            "details": {"error": f"{type(exc).__name__}: {display_text(exc, 300)}"},
        })
    finally:
        Image.MAX_IMAGE_PIXELS = old_limit
        result["duration_ms"] = int((time.monotonic() - start) * 1000)
    return result


def _visual(label: str, title: str, image: Any, producer: str, parameters: dict[str, Any]) -> dict[str, Any]:
    buffer = io.BytesIO()
    # PNG output is decoded/re-encoded and therefore safe for browser preview.
    image.save(buffer, format="PNG", optimize=False)
    return {
        "label": label, "title": title, "data": buffer.getvalue(), "producer": producer,
        "transformation": parameters.get("operation", title), "parameters": parameters,
        "width": image.width, "height": image.height, "kind": "png",
    }


def _add_color_remaps(result: dict[str, Any], base: Any, requested: int, ImageOps: Any) -> int:
    count = max(0, min(8, int(requested)))
    if count == 0:
        return 0
    grayscale = ImageOps.autocontrast(ImageOps.grayscale(base))
    palettes = [
        ("#071a13", "#b9ff66", "#ffffff"),
        ("#050816", "#22d3ee", "#fef08a"),
        ("#190a26", "#f472b6", "#fde68a"),
        ("#001b2e", "#60a5fa", "#f8fafc"),
        ("#1f1300", "#fb923c", "#fff7ed"),
        ("#101010", "#ef4444", "#facc15"),
        ("#00120b", "#34d399", "#dbeafe"),
        ("#160505", "#a78bfa", "#f0fdf4"),
    ]
    for index, (black, mid, white) in enumerate(palettes[:count], start=1):
        remapped = ImageOps.colorize(grayscale, black=black, white=white, mid=mid, blackpoint=0, midpoint=128, whitepoint=255)
        result["visuals"].append(_visual(
            f"color_remap_{index}",
            f"Color remapping {index}",
            remapped,
            "Pillow",
            {"operation": "deterministic three-tone color remap", "black": black, "mid": mid, "white": white},
        ))
    return count


def _add_palette_index_analysis(result: dict[str, Any], source: Any | None, profile: str, Image: Any) -> dict[str, Any] | None:
    """Inspect original palette indexes before RGBA conversion discards them.

    Paletted PNG/GIF/BMP challenges can encode ASCII directly in the index
    plane.  Looking only at converted RGB values loses that ordering, so keep a
    bounded copy of the original one-byte index stream for inspection.
    """

    if source is None or source.mode != "P":
        return None
    raw_indices = source.tobytes()
    palette = source.getpalette() or []
    palette_entries = min(256, len(palette) // 3)
    maximum_stream = 4 * 1024 * 1024 if profile != "deep" else 8 * 1024 * 1024
    inspected = raw_indices[:maximum_stream]
    index_image = Image.frombytes("L", source.size, raw_indices)
    result["visuals"].append(_visual(
        "palette_indices",
        "Original palette indexes",
        index_image,
        "Pillow",
        {"operation": "render original palette-index bytes as grayscale", "palette_entries": palette_entries},
    ))

    bit_indices = [0] if profile == "quick" else ([0, 1, 7] if profile == "balanced" else list(range(8)))
    for bit in bit_indices:
        plane = index_image.point(lambda value, selected=bit: 255 if value & (1 << selected) else 0)
        result["visuals"].append(_visual(
            f"palette_index_bitplane_{bit}",
            f"Palette-index bit plane {bit}",
            plane,
            "Pillow",
            {"operation": "extract bit plane from original palette indexes", "bit": bit},
        ))

    records = list(iter_ascii_strings(inspected, minimum=4, limit=1000))
    interesting = [
        record for record in records
        if "{" in record["text"] or "}" in record["text"] or len(record["text"]) >= 12
    ]
    for record in interesting[:250]:
        result["text_records"].append({
            "source": "palette-index-bytes", "offset": record["offset"],
            "text": display_text(record["text"], 16_384),
            "transform_chain": ["preserve original palette-index order"],
        })

    detected = sniff_kind(inspected)
    sample = inspected[:8192]
    text_ratio = sum(1 for value in sample if value in (9, 10, 13) or 32 <= value <= 126) / len(sample) if sample else 0.0
    braces = any("{" in record["text"] and "}" in record["text"] for record in records)
    if detected != "binary" or text_ratio >= 0.65 or braces:
        result["stego_streams"].append({
            "label": "palette_index_bytes", "title": "Original palette-index bytes", "data": inspected,
            "producer": "built-in-palette-index", "transformation": "preserve original palette-index byte order",
            "kind": detected,
            "parameters": {
                "palette_entries": palette_entries,
                "truncated": len(raw_indices) > len(inspected),
            },
            "entropy": round(byte_entropy(inspected[:1_000_000]), 5), "text_ratio": round(text_ratio, 5),
        })
    result["properties"]["palette_index_analysis"] = {
        "palette_entries": palette_entries,
        "inspected_bytes": len(inspected),
        "truncated": len(raw_indices) > len(inspected),
    }
    return {
        "palette_entries": palette_entries,
        "inspected_bytes": len(inspected),
        "truncated": len(raw_indices) > len(inspected),
        "view_count": 1 + len(bit_indices),
        "text_record_count": len(interesting),
    }


def _add_gif_frame_index_analysis(
    result: dict[str, Any],
    path: Any,
    profile: str,
    Image: Any,
    max_megapixels: int,
) -> dict[str, Any] | None:
    """Recover GIF frame indices before compositing can discard local palettes.

    Pillow correctly renders GIF animation but commonly promotes later local-
    palette frames to RGB. CTFs can make every palette entry visually identical
    and hide an image in those original index values, so decode the bounded
    GIF LZW stream directly for a separate, non-destructive view.
    """

    try:
        source_path = Path(path)
        file_size = source_path.stat().st_size
        if file_size <= 0 or file_size > 64 * 1024 * 1024:
            return None
        data = source_path.read_bytes()
    except (OSError, TypeError, ValueError):
        return None

    frame_limit = 2 if profile == "quick" else (8 if profile == "balanced" else 16)
    pixel_limit = min(max(1, int(max_megapixels)) * 1_000_000, 8 * 1024 * 1024)
    frames = _gif_index_frames(data, frame_limit=frame_limit, pixel_limit=pixel_limit)
    if not frames:
        return None

    bit_indices = [0] if profile == "quick" else ([0, 1, 7] if profile == "balanced" else list(range(8)))
    maximum_stream = 4 * 1024 * 1024 if profile != "deep" else 8 * 1024 * 1024
    view_count = 0
    stream_count = 0
    text_record_count = 0
    for frame in frames:
        index_image = Image.frombytes("L", (frame["width"], frame["height"]), frame["indices"])
        prefix = f"gif_palette_indices_{frame['index']:03d}"
        result["visuals"].append(_visual(
            prefix,
            f"GIF frame {frame['index']} original palette indexes",
            index_image,
            "built-in GIF LZW reader",
            {"operation": "render decoded GIF palette-index bytes as grayscale", **frame["parameters"]},
        ))
        view_count += 1
        colorful = Image.frombytes("P", (frame["width"], frame["height"]), frame["indices"])
        colorful.putpalette(_distinct_palette())
        result["visuals"].append(_visual(
            f"{prefix}_remap",
            f"GIF frame {frame['index']} deterministic palette remap",
            colorful.convert("RGB"),
            "built-in GIF LZW reader",
            {"operation": "remap original GIF indexes to a deterministic distinct palette", **frame["parameters"]},
        ))
        view_count += 1
        for bit in bit_indices:
            plane = index_image.point(lambda value, selected=bit: 255 if value & (1 << selected) else 0)
            result["visuals"].append(_visual(
                f"{prefix}_bitplane_{bit}",
                f"GIF frame {frame['index']} palette-index bit plane {bit}",
                plane,
                "built-in GIF LZW reader",
                {"operation": "extract bit plane from decoded GIF palette indexes", "bit": bit, **frame["parameters"]},
            ))
            view_count += 1

        stream = frame["indices"][:maximum_stream]
        records = list(iter_ascii_strings(stream, minimum=4, limit=1000))
        interesting = [
            record for record in records
            if "{" in record["text"] or "}" in record["text"] or len(record["text"]) >= 12
        ]
        for record in interesting[:250]:
            result["text_records"].append({
                "source": f"gif-palette-index:frame-{frame['index']}", "offset": record["offset"],
                "text": display_text(record["text"], 16_384),
                "transform_chain": ["decode original GIF LZW palette indexes"],
            })
        text_record_count += len(interesting)
        detected = sniff_kind(stream)
        sample = stream[:8192]
        text_ratio = sum(1 for value in sample if value in (9, 10, 13) or 32 <= value <= 126) / len(sample) if sample else 0.0
        braces = any("{" in record["text"] and "}" in record["text"] for record in records)
        if detected != "binary" or text_ratio >= 0.65 or braces:
            result["stego_streams"].append({
                "label": f"gif_palette_index_bytes_{frame['index']:03d}",
                "title": f"GIF frame {frame['index']} original palette-index bytes",
                "data": stream,
                "producer": "built-in GIF LZW reader",
                "transformation": "decode original GIF LZW palette-index byte order",
                "kind": detected,
                "parameters": {**frame["parameters"], "truncated": len(frame["indices"]) > len(stream)},
                "entropy": round(byte_entropy(stream[:1_000_000]), 5), "text_ratio": round(text_ratio, 5),
            })
            stream_count += 1

    result["properties"]["gif_palette_index_analysis"] = {
        "decoded_frames": len(frames), "frame_limit": frame_limit, "pixel_limit": pixel_limit,
    }
    return {
        "frame_count": len(frames), "frame_limit": frame_limit, "pixel_limit": pixel_limit,
        "view_count": view_count, "stream_count": stream_count, "text_record_count": text_record_count,
    }


def _distinct_palette() -> list[int]:
    """Return a fixed high-contrast palette without depending on challenge data."""

    palette: list[int] = []
    for value in range(256):
        palette.extend(((value * 73 + 29) & 0xFF, (value * 151 + 71) & 0xFF, (value * 199 + 113) & 0xFF))
    return palette


def _gif_index_frames(data: bytes, *, frame_limit: int, pixel_limit: int) -> list[dict[str, Any]]:
    """Decode a bounded subset of raw GIF image-data blocks to index planes."""

    if len(data) < 13 or not data.startswith((b"GIF87a", b"GIF89a")):
        return []
    cursor = 13
    logical_packed = data[10]
    global_entries = 2 ** ((logical_packed & 0x07) + 1) if logical_packed & 0x80 else 0
    global_palette_length = global_entries * 3
    if cursor + global_palette_length > len(data):
        return []
    cursor += global_palette_length
    frames: list[dict[str, Any]] = []
    decoded_pixels = 0
    source_frame = 0
    while cursor < len(data) and len(frames) < frame_limit:
        introducer = data[cursor]
        cursor += 1
        if introducer == 0x3B:
            break
        if introducer == 0x21:
            if cursor >= len(data):
                break
            cursor += 1  # extension label
            _, cursor, complete = _gif_subblocks_bounded(data, cursor, 16 * 1024 * 1024)
            if not complete:
                break
            continue
        if introducer != 0x2C or cursor + 9 > len(data):
            break
        left = int.from_bytes(data[cursor:cursor + 2], "little")
        top = int.from_bytes(data[cursor + 2:cursor + 4], "little")
        width = int.from_bytes(data[cursor + 4:cursor + 6], "little")
        height = int.from_bytes(data[cursor + 6:cursor + 8], "little")
        packed = data[cursor + 8]
        cursor += 9
        local_entries = 2 ** ((packed & 0x07) + 1) if packed & 0x80 else 0
        local_palette_length = local_entries * 3
        if cursor + local_palette_length >= len(data):
            break
        cursor += local_palette_length
        lzw_minimum = data[cursor]
        cursor += 1
        compressed, cursor, complete = _gif_subblocks_bounded(data, cursor, 16 * 1024 * 1024)
        expected_pixels = width * height
        permitted = (
            complete and width > 0 and height > 0 and expected_pixels <= pixel_limit - decoded_pixels
            and lzw_minimum in range(2, 9)
        )
        if permitted:
            decoded = _decode_gif_lzw(compressed, lzw_minimum, expected_pixels)
            if decoded is not None:
                indices = _deinterlace_gif_indexes(decoded, width, height) if packed & 0x40 else decoded
                if indices is not None:
                    frames.append({
                        "index": source_frame, "width": width, "height": height, "indices": indices,
                        "parameters": {
                            "left": left, "top": top, "interlaced": bool(packed & 0x40),
                            "palette_scope": "local" if local_entries else "global",
                            "palette_entries": local_entries or global_entries,
                        },
                    })
                    decoded_pixels += expected_pixels
        source_frame += 1
    return frames


def _gif_subblocks_bounded(data: bytes, cursor: int, maximum_bytes: int) -> tuple[bytes, int, bool]:
    payload = bytearray()
    while cursor < len(data):
        length = data[cursor]
        cursor += 1
        if length == 0:
            return bytes(payload), cursor, True
        if cursor + length > len(data) or len(payload) + length > maximum_bytes:
            return bytes(payload), min(len(data), cursor + length), False
        payload.extend(data[cursor:cursor + length])
        cursor += length
    return bytes(payload), cursor, False


def _decode_gif_lzw(payload: bytes, minimum_code_size: int, expected_pixels: int) -> bytes | None:
    """Decode GIF's LSB-packed LZW codes with an exact output limit."""

    clear_code = 1 << minimum_code_size
    end_code = clear_code + 1
    dictionary: dict[int, bytes] = {}
    code_size = minimum_code_size + 1
    next_code = end_code + 1
    previous: bytes | None = None
    output = bytearray()
    bit_offset = 0
    while bit_offset + code_size <= len(payload) * 8:
        byte_offset = bit_offset // 8
        packed = int.from_bytes(payload[byte_offset:byte_offset + 3], "little")
        code = (packed >> (bit_offset % 8)) & ((1 << code_size) - 1)
        bit_offset += code_size
        if code == clear_code:
            dictionary = {value: bytes((value,)) for value in range(clear_code)}
            code_size = minimum_code_size + 1
            next_code = end_code + 1
            previous = None
            continue
        if code == end_code:
            break
        entry = dictionary.get(code)
        if entry is None:
            if previous is None or code != next_code:
                return None
            entry = previous + previous[:1]
        output.extend(entry)
        if len(output) >= expected_pixels:
            return bytes(output[:expected_pixels])
        if previous is not None and next_code < 4096:
            dictionary[next_code] = previous + entry[:1]
            next_code += 1
            if next_code == (1 << code_size) and code_size < 12:
                code_size += 1
        previous = entry
    return bytes(output) if len(output) == expected_pixels else None


def _deinterlace_gif_indexes(indices: bytes, width: int, height: int) -> bytes | None:
    if len(indices) != width * height:
        return None
    ordered = bytearray(len(indices))
    cursor = 0
    for start, stride in ((0, 8), (4, 8), (2, 4), (1, 2)):
        for row in range(start, height, stride):
            ordered[row * width:(row + 1) * width] = indices[cursor:cursor + width]
            cursor += width
    return bytes(ordered) if cursor == len(indices) else None


def _add_pixel_visuals(result: dict[str, Any], base: Any, profile: str, Image: Any, ImageOps: Any, ImageChops: Any, ImageEnhance: Any, ImageFilter: Any) -> None:
    rgba = base.convert("RGBA")
    red, green, blue, alpha = rgba.split()
    channels = {"red": red, "green": green, "blue": blue}
    alpha_extrema = alpha.getextrema()
    if alpha_extrema != (255, 255):
        channels["alpha"] = alpha
    for name, channel in channels.items():
        result["visuals"].append(_visual(f"channel_{name}", f"{name.title()} channel", channel, "Pillow", {"operation": "extract channel", "channel": name}))

    grayscale = ImageOps.grayscale(rgba)
    contrast = ImageOps.autocontrast(grayscale)
    result["visuals"].append(_visual("autocontrast", "Grayscale autocontrast", contrast, "Pillow", {"operation": "grayscale and autocontrast"}))
    result["visuals"].append(_visual("negative", "Inverted grayscale", ImageOps.invert(grayscale), "Pillow", {"operation": "grayscale and invert"}))
    if profile != "quick":
        result["visuals"].append(_visual("threshold_128", "Binary threshold 128", grayscale.point(lambda value: 255 if value >= 128 else 0), "Pillow", {"operation": "threshold", "threshold": 128}))
        edges = grayscale.filter(ImageFilter.FIND_EDGES)
        result["visuals"].append(_visual("edges", "Edge map", ImageOps.autocontrast(edges), "Pillow", {"operation": "find edges and autocontrast"}))

    if alpha_extrema != (255, 255):
        transparent_mask = alpha.point(lambda value: 255 if value == 0 else 0)
        hidden = Image.new("RGB", rgba.size, "black")
        hidden.paste(rgba.convert("RGB"), mask=transparent_mask)
        result["visuals"].append(_visual("transparent_rgb", "RGB under fully transparent pixels", hidden, "Pillow", {"operation": "show RGB where alpha equals zero"}))
        transparent_pixels = alpha.tobytes().count(0)
        result["properties"]["fully_transparent_pixels"] = transparent_pixels
        if transparent_pixels:
            result["findings"].append({
                "severity": "info", "category": "steganography", "title": "RGB data under transparency",
                "description": "Fully transparent pixels retain RGB values; a dedicated view was generated.",
                "details": {"fully_transparent_pixels": transparent_pixels},
            })

    bit_indices = [0] if profile == "quick" else ([0, 1, 7] if profile == "balanced" else list(range(8)))
    bit_planes: dict[int, dict[str, Any]] = {}
    for channel_name, channel in channels.items():
        for bit in bit_indices:
            plane = channel.point(lambda value, selected=bit: 255 if value & (1 << selected) else 0)
            result["visuals"].append(_visual(
                f"bitplane_{channel_name}_{bit}", f"{channel_name.title()} bit plane {bit}", plane,
                "Pillow", {"operation": "extract bit plane", "channel": channel_name, "bit": bit},
            ))
            bit_planes.setdefault(bit, {})[channel_name] = plane.convert("1")

    # Some challenges put a shared noise mask into two channel bit planes. A
    # pairwise XOR cancels that mask and exposes the intended text/image (for
    # example, a G bit 0 XOR A bit 0 payload). This is deterministic and does
    # not alter the uploaded evidence.
    if profile != "quick":
        channel_pairs = (("red", "green"), ("red", "blue"), ("green", "blue"), ("red", "alpha"), ("green", "alpha"), ("blue", "alpha"))
        for bit, planes in bit_planes.items():
            for left_name, right_name in channel_pairs:
                left = planes.get(left_name)
                right = planes.get(right_name)
                if left is None or right is None:
                    continue
                xored = ImageChops.logical_xor(left, right).convert("L")
                result["visuals"].append(_visual(
                    f"bitplane_xor_{left_name}_{right_name}_{bit}",
                    f"{left_name.title()} XOR {right_name.title()} bit plane {bit}",
                    xored,
                    "Pillow",
                    {
                        "operation": "XOR two channel bit planes",
                        "channels": [left_name, right_name],
                        "bit": bit,
                    },
                ))

    # Per-channel histograms and LSB balance are compact statistical evidence.
    statistics = {}
    for channel_name, channel in channels.items():
        histogram = channel.histogram()[:256]
        even = sum(histogram[0::2])
        odd = sum(histogram[1::2])
        total = even + odd
        statistics[channel_name] = {
            "minimum": channel.getextrema()[0], "maximum": channel.getextrema()[1],
            "lsb_zero": even, "lsb_one": odd,
            "lsb_one_ratio": round(odd / total, 6) if total else None,
            "histogram": histogram,
        }
    result["properties"]["channel_statistics"] = statistics


def _add_frames(result: dict[str, Any], opened: Any, profile: str, Image: Any, ImageChops: Any) -> None:
    frame_count = int(getattr(opened, "n_frames", 1) or 1)
    if frame_count <= 1:
        return
    limit = 8 if profile == "quick" else (32 if profile == "balanced" else 80)
    previous = None
    delays: list[int] = []
    disposals: list[Any] = []
    for index in range(min(frame_count, limit)):
        opened.seek(index)
        frame = opened.convert("RGBA")
        delays.append(int(opened.info.get("duration", 0) or 0))
        disposals.append(getattr(opened, "disposal_method", opened.info.get("disposal")))
        result["visuals"].append(_visual(f"frame_{index:04d}", f"Animation frame {index}", frame, "Pillow", {"operation": "extract animation frame", "frame": index, "duration_ms": delays[-1]}))
        if previous is not None and profile != "quick":
            difference = ImageChops.difference(previous, frame).convert("RGB")
            if difference.getbbox() is not None:
                result["visuals"].append(_visual(f"frame_diff_{index - 1:04d}_{index:04d}", f"Frame difference {index - 1} → {index}", difference, "Pillow", {"operation": "absolute frame difference", "from_frame": index - 1, "to_frame": index}))
        previous = frame.copy()
    result["properties"].update({"frame_delays_ms": delays, "frame_disposals": disposals, "frames_processed": min(frame_count, limit), "frames_truncated": frame_count > limit})


def _add_lsb_analysis(result: dict[str, Any], base: Any, profile: str) -> None:
    rgba = base.convert("RGBA")
    raw_channels = {name: channel.tobytes() for name, channel in zip(("R", "G", "B", "A"), rgba.split())}
    alpha_useful = any(value != 255 for value in raw_channels["A"][:1_000_000])
    orders = ["RGB", "R", "G", "B"]
    if profile != "quick":
        orders.extend(["BGR", "RGBA"] if alpha_useful else ["BGR"])
    if profile == "deep" and alpha_useful:
        orders.extend(["ARGB", "A"])
    bits = [0] if profile == "quick" else ([0, 1, 7] if profile == "balanced" else list(range(8)))
    pack_orders = ["msb-first"] if profile == "quick" else ["msb-first", "lsb-first"]
    maximum_stream = 4 * 1024 * 1024 if profile != "deep" else 8 * 1024 * 1024
    max_bits = maximum_stream * 8
    noteworthy = 0
    for channel_order in orders:
        source_channels = [raw_channels[name] for name in channel_order]
        pixel_count = min(len(channel) for channel in source_channels)
        for bit in bits:
            for pack_order in pack_orders:
                packed = _pack_channel_bits(source_channels, pixel_count, bit, pack_order, max_bits)
                label = f"lsb:{channel_order}:bit{bit}:{pack_order}"
                records = list(iter_ascii_strings(packed, minimum=4, limit=1000))
                interesting_records = [record for record in records if "{" in record["text"] or "}" in record["text"] or len(record["text"]) >= 12]
                for record in interesting_records[:250]:
                    result["text_records"].append({
                        "source": label, "offset": record["offset"], "text": display_text(record["text"], 16_384),
                        "transform_chain": [f"extract bit {bit} from {channel_order}", pack_order],
                    })
                detected = sniff_kind(packed)
                sample = packed[:8192]
                text_ratio = sum(1 for value in sample if value in (9, 10, 13) or 32 <= value <= 126) / len(sample) if sample else 0.0
                braces = any("{" in record["text"] and "}" in record["text"] for record in records)
                if noteworthy < 24 and (detected != "binary" or text_ratio >= 0.65 or braces):
                    result["stego_streams"].append({
                        "label": label.replace(":", "_"), "title": label, "data": packed,
                        "producer": "built-in-lsb", "transformation": label, "kind": detected,
                        "parameters": {"channel_order": channel_order, "bit": bit, "packing": pack_order, "truncated": pixel_count * len(source_channels) > max_bits},
                        "entropy": round(byte_entropy(packed[:1_000_000]), 5), "text_ratio": round(text_ratio, 5),
                    })
                    noteworthy += 1


def _add_jpeg_coefficient_analysis(result: dict[str, Any], path: Any, profile: str) -> dict[str, Any] | None:
    """Expose JSteg-style AC parity streams from a baseline JPEG.

    This is deliberately a read-only, bounded decoder. It complements the
    optional external ``jsteg``/``steghide`` tools and gives a useful stream
    when those binaries are unavailable. The first scan component, skipping
    -1/0/1 coefficients and packing least-significant-bit first, is the
    canonical JSteg candidate; a second all-component stream helps with
    challenge-specific variants.
    """

    started = time.monotonic()
    try:
        source = Path(path)
        if source.stat().st_size > 64 * 1024 * 1024:
            return {"status": "skipped", "duration_ms": 0, "summary": "JPEG coefficient reader skipped files larger than 64 MiB."}
        frame, blocks = decode_baseline_coefficients(source.read_bytes())
        streams = coefficient_bitstreams(blocks)
    except (OSError, TypeError, ValueError) as exc:
        return {
            "status": "skipped", "duration_ms": int((time.monotonic() - started) * 1000),
            "summary": f"Baseline JPEG coefficient parity was unavailable: {type(exc).__name__}: {display_text(exc, 240)}",
        }

    candidates = ("ac_abs_gt_one:first:lsb", "ac_abs_gt_one:first:msb", "ac_abs_gt_one:all:lsb")
    emitted = 0
    flag_hits = 0
    text_records = 0
    for label in candidates:
        payload = streams.get(label, b"")
        if not payload:
            continue
        records = list(iter_ascii_strings(payload, minimum=8, limit=100))
        flag_matches = [match.group(0).decode("latin-1", "replace") for match in re.finditer(rb"(?:picoCTF|flag|CTF|HTB|THM)\{[^}]{1,300}\}", payload, re.IGNORECASE)]
        flag_hits += len(flag_matches)
        interesting = [record for record in records if len(record["text"]) >= 12 or "{" in record["text"] or "}" in record["text"]]
        for record in interesting[:20]:
            result["text_records"].append({
                "source": f"jpeg-coefficients:{label}", "offset": record["offset"],
                "text": display_text(record["text"], 16_384),
                "transform_chain": ["decode baseline JPEG DCT coefficients", "extract non-zero AC parity", label.rsplit(":", 1)[-1]],
            })
        text_records += len(interesting)
        text_ratio = sum(1 for value in payload[:8192] if value in (9, 10, 13) or 32 <= value <= 126) / min(len(payload), 8192)
        # Deep mode intentionally retains the canonical stream for manual
        # inspection even when the payload is compressed or encrypted.
        if profile == "deep" or flag_matches or text_ratio >= 0.55:
            result["stego_streams"].append({
                "label": f"jpeg_coeff_{label.replace(':', '_')}",
                "title": f"JPEG DCT AC parity ({label})", "data": payload,
                "producer": "built-in baseline JPEG reader", "transformation": "extract quantized AC coefficient parity",
                "kind": sniff_kind(payload),
                "parameters": {"frame": {"width": frame.width, "height": frame.height}, "variant": label, "truncated": False},
                "entropy": round(byte_entropy(payload[:1_000_000]), 5), "text_ratio": round(text_ratio, 5),
            })
            emitted += 1
        if flag_matches:
            result["findings"].append({
                "severity": "high", "category": "steganography", "title": "Flag-shaped text in JPEG coefficient stream",
                "description": "A flag-shaped token was recovered from quantized JPEG AC coefficient parity.",
                "details": {"variant": label, "matches": flag_matches[:10]},
            })
    details = {
        "status": "completed", "duration_ms": int((time.monotonic() - started) * 1000),
        "summary": f"Decoded {len(blocks)} baseline JPEG block(s); emitted {emitted} bounded coefficient stream(s).",
        "blocks": len(blocks), "width": frame.width, "height": frame.height,
        "components": len(frame.components), "stream_count": emitted,
        "flag_hits": flag_hits, "text_record_count": text_records,
    }
    result["properties"]["jpeg_coefficient_analysis"] = details
    return details


def _pack_channel_bits(channels: list[bytes], pixel_count: int, bit: int, pack_order: str, maximum_bits: int) -> bytes:
    total_bits = min(maximum_bits, pixel_count * len(channels))
    total_bytes = total_bits // 8
    if total_bytes <= 0:
        return b""
    # NumPy offers a large speedup but is strictly optional.
    try:
        import numpy as np  # type: ignore

        arrays = [np.frombuffer(channel, dtype=np.uint8, count=pixel_count) for channel in channels]
        interleaved = np.stack(arrays, axis=1).reshape(-1)[:total_bytes * 8]
        extracted = (interleaved >> bit) & 1
        packed = np.packbits(extracted, bitorder="big" if pack_order == "msb-first" else "little")
        return packed.tobytes()
    except (ImportError, Exception):
        output = bytearray(total_bytes)
        channel_count = len(channels)
        for byte_index in range(total_bytes):
            value = 0
            base = byte_index * 8
            for bit_index in range(8):
                linear = base + bit_index
                pixel = linear // channel_count
                channel = linear % channel_count
                extracted = (channels[channel][pixel] >> bit) & 1
                if pack_order == "msb-first":
                    value |= extracted << (7 - bit_index)
                else:
                    value |= extracted << bit_index
            output[byte_index] = value
        return bytes(output)


def _add_optional_cv(result: dict[str, Any], base: Any, profile: str) -> None:
    try:
        import cv2  # type: ignore
        import numpy as np  # type: ignore

        result["integrations"]["opencv"] = {"status": "available", "version": getattr(cv2, "__version__", None)}
        result["integrations"]["numpy"] = {"status": "available", "version": getattr(np, "__version__", None)}
        array = np.array(base.convert("RGB"))
        gray = cv2.cvtColor(array, cv2.COLOR_RGB2GRAY)
        result["properties"]["opencv"] = {
            "mean_luminance": round(float(gray.mean()), 5), "std_luminance": round(float(gray.std()), 5),
        }
        if profile == "deep":
            edges = cv2.Canny(gray, 50, 150)
            try:
                from PIL import Image  # type: ignore

                result["visuals"].append(_visual("opencv_canny", "OpenCV Canny edges", Image.fromarray(edges), "OpenCV", {"operation": "Canny edge detection", "thresholds": [50, 150]}))
            except Exception:
                pass
    except ImportError:
        result["integrations"]["opencv"] = {"status": "missing", "reason": "OpenCV and/or NumPy are not installed."}
    except Exception as exc:
        result["integrations"]["opencv"] = {"status": "failed", "reason": f"{type(exc).__name__}: {display_text(exc, 300)}"}


def _add_ocr_and_barcodes(
    result: dict[str, Any],
    base: Any,
    profile: str,
    Image: Any,
    ImageOps: Any,
    *,
    run_ocr: bool,
    run_barcodes: bool,
    ocr_language: str,
) -> None:
    grayscale = ImageOps.grayscale(base)
    variants: list[tuple[str, Any]] = [("original", base.convert("RGB")), ("autocontrast", ImageOps.autocontrast(grayscale))]
    if profile != "quick":
        variants.extend([
            ("threshold-96", grayscale.point(lambda value: 255 if value >= 96 else 0)),
            ("threshold-160", grayscale.point(lambda value: 255 if value >= 160 else 0)),
            ("rotate-90", ImageOps.autocontrast(grayscale).rotate(90, expand=True)),
            ("rotate-180", ImageOps.autocontrast(grayscale).rotate(180, expand=True)),
            ("rotate-270", ImageOps.autocontrast(grayscale).rotate(270, expand=True)),
        ])

    if not run_ocr:
        result["integrations"]["pytesseract"] = {"status": "skipped", "reason": "Disabled in job settings."}
    try:
        if not run_ocr:
            raise ImportError
        import pytesseract  # type: ignore

        result["integrations"]["pytesseract"] = {"status": "available", "version": getattr(pytesseract, "__version__", None)}
        ocr_limit = 2 if profile == "quick" else len(variants)
        for name, variant in variants[:ocr_limit]:
            try:
                text = pytesseract.image_to_string(
                    variant,
                    lang=ocr_language,
                    config="--psm 6",
                    timeout=15 if profile != "deep" else 30,
                )
                if text.strip():
                    result["text_records"].append({"source": f"OCR:{name}", "offset": None, "text": display_text(text, 1_000_000), "confidence_hint": -8})
            except RuntimeError as exc:
                result["integrations"]["pytesseract"]["last_error"] = display_text(exc, 300)
            except Exception as exc:
                result["integrations"]["pytesseract"] = {"status": "failed", "reason": f"{type(exc).__name__}: {display_text(exc, 300)}"}
                break
    except ImportError:
        if not run_ocr:
            pass
        else:
            result["integrations"]["pytesseract"] = {"status": "missing", "reason": "pytesseract is not installed."}

    barcode_count = 0
    if not run_barcodes:
        result["integrations"]["pyzbar"] = {"status": "skipped", "reason": "Disabled in job settings."}
    try:
        if not run_barcodes:
            raise ImportError
        from pyzbar.pyzbar import decode as zbar_decode  # type: ignore

        result["integrations"]["pyzbar"] = {"status": "available"}
        for name, variant in variants[:4]:
            try:
                for barcode in zbar_decode(variant):
                    payload = barcode.data.decode("utf-8", "replace")
                    result["text_records"].append({
                        "source": f"barcode:{getattr(barcode, 'type', 'unknown')}:{name}",
                        "offset": None, "text": display_text(payload, 1_000_000), "confidence_hint": 15,
                    })
                    barcode_count += 1
            except Exception as exc:
                result["integrations"]["pyzbar"] = {"status": "failed", "reason": f"{type(exc).__name__}: {display_text(exc, 300)}"}
                break
    except (ImportError, OSError) as exc:
        if run_barcodes:
            result["integrations"]["pyzbar"] = {"status": "missing", "reason": f"pyzbar or its native ZBar library is unavailable: {display_text(exc, 200)}"}

    # OpenCV QR decoding is a useful independent fallback/cross-check.
    binary_mapping_candidates = 0
    binary_mapping_hits = 0
    try:
        if not run_barcodes:
            raise ImportError
        import cv2  # type: ignore
        import numpy as np  # type: ignore

        detector = cv2.QRCodeDetector()
        seen_opencv_payloads: set[str] = set()

        def decode_opencv_variant(name: str, variant: Any, *, retain_on_hit: bool) -> int:
            nonlocal barcode_count
            payloads: list[str] = []
            array = np.array(variant.convert("RGB"))
            try:
                success, decoded, _points, _ = detector.detectAndDecodeMulti(array)
                if success:
                    payloads.extend(payload for payload in decoded if payload)
            except (AttributeError, ValueError):
                payload, _points, _ = detector.detectAndDecode(array)
                if payload:
                    payloads.append(payload)
            new_payloads = 0
            for payload in payloads:
                if payload in seen_opencv_payloads:
                    continue
                seen_opencv_payloads.add(payload)
                result["text_records"].append({
                    "source": f"barcode:QR:opencv:{name}", "offset": None,
                    "text": display_text(payload, 1_000_000), "confidence_hint": 15,
                })
                barcode_count += 1
                new_payloads += 1
            if new_payloads and retain_on_hit:
                result["visuals"].append(_visual(
                    f"qr_color_mapping_hit_{len(result['visuals']):03d}",
                    f"Decoded QR color mapping {name}",
                    variant,
                    "OpenCV",
                    {"operation": "map a bounded low-color image subset to black and white", "mapping": name},
                ))
            return new_payloads

        for name, variant in variants[:4]:
            try:
                decode_opencv_variant(name, variant, retain_on_hit=False)
            except Exception:
                continue

        if profile != "quick":
            for name, variant in _iter_low_color_binary_variants(base, profile, Image):
                binary_mapping_candidates += 1
                try:
                    if decode_opencv_variant(name, variant, retain_on_hit=True):
                        binary_mapping_hits += 1
                except Exception:
                    continue
    except (ImportError, Exception):
        pass
    result["properties"]["barcode_results"] = barcode_count
    result["properties"]["qr_color_mapping_candidates"] = binary_mapping_candidates
    result["properties"]["qr_color_mapping_hits"] = binary_mapping_hits


def _iter_low_color_binary_variants(base: Any, profile: str, Image: Any) -> Iterable[tuple[str, Any]]:
    """Yield bounded black/white mappings for images with at most eight colors."""

    rgb = base.convert("RGB")
    pixel_count = rgb.width * rgb.height
    if pixel_count <= 0 or pixel_count > 4_000_000:
        return
    counted = rgb.getcolors(maxcolors=9)
    if counted is None or not 3 <= len(counted) <= 8:
        return
    colors = sorted(color for _count, color in counted)
    color_to_index = {color: index for index, color in enumerate(colors)}
    flattened = rgb.get_flattened_data() if hasattr(rgb, "get_flattened_data") else rgb.getdata()
    indexed = bytes(color_to_index[color] for color in flattened)
    possible = (1 << len(colors)) - 2  # omit all-black and all-white mappings
    maximum_candidates = 64 if profile == "balanced" else 254
    operation_budget = 8_000_000 if profile == "balanced" else 32_000_000
    limit = min(possible, maximum_candidates, max(1, operation_budget // pixel_count))
    if limit >= possible:
        masks = list(range(1, possible + 1))
    elif limit == 1:
        masks = [1]
    else:
        masks = sorted({1 + round(index * (possible - 1) / (limit - 1)) for index in range(limit)})
    for mask in masks:
        mapped = bytes(255 if mask & (1 << color_index) else 0 for color_index in indexed)
        yield f"colors-{len(colors)}-mask-{mask:0{max(1, (len(colors) + 3) // 4)}x}", Image.frombytes("L", rgb.size, mapped)
