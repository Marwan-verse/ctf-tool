from __future__ import annotations

import io
import math
import time
import warnings
from typing import Any, Iterable

from .common import byte_entropy, display_text, iter_ascii_strings, normalize_json, sha256_bytes, sniff_kind, utc_now


def analyze_visual(path: Any, *, profile: str, max_megapixels: int) -> dict[str, Any]:
    """Decode pixels safely and produce bounded, useful visual transformations."""
    started_at = utc_now()
    start = time.monotonic()
    result: dict[str, Any] = {
        "id": "pillow-visual", "name": "Pixel, frame, channel, and bit-plane analysis",
        "category": "visual", "status": "missing", "applicable": True,
        "started_at": started_at, "duration_ms": 0, "summary": "",
        "tool": {"executable": "Pillow", "resolved": None, "version": None},
        "metadata": {}, "properties": {}, "text_records": [], "visuals": [],
        "stego_streams": [], "findings": [], "integrations": {},
    }
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
                base = opened.convert("RGBA")
                result["visuals"].append(_visual("safe_preview", "Safe decoded preview", base, "Pillow", {"operation": "decode and convert to RGBA"}))
                _add_pixel_visuals(result, base, profile, Image, ImageOps, ImageChops, ImageEnhance, ImageFilter)
                _add_frames(result, opened, profile, Image, ImageChops)
                _add_lsb_analysis(result, base, profile)
                _add_optional_cv(result, base, profile)
                _add_ocr_and_barcodes(result, base, profile, Image, ImageOps)
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
        transparent_pixels = sum(1 for value in alpha.getdata() if value == 0)
        result["properties"]["fully_transparent_pixels"] = transparent_pixels
        if transparent_pixels:
            result["findings"].append({
                "severity": "info", "category": "steganography", "title": "RGB data under transparency",
                "description": "Fully transparent pixels retain RGB values; a dedicated view was generated.",
                "details": {"fully_transparent_pixels": transparent_pixels},
            })

    bit_indices = [0] if profile == "quick" else ([0, 1, 7] if profile == "balanced" else list(range(8)))
    for channel_name, channel in channels.items():
        for bit in bit_indices:
            plane = channel.point(lambda value, selected=bit: 255 if value & (1 << selected) else 0)
            result["visuals"].append(_visual(
                f"bitplane_{channel_name}_{bit}", f"{channel_name.title()} bit plane {bit}", plane,
                "Pillow", {"operation": "extract bit plane", "channel": channel_name, "bit": bit},
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


def _add_ocr_and_barcodes(result: dict[str, Any], base: Any, profile: str, Image: Any, ImageOps: Any) -> None:
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

    try:
        import pytesseract  # type: ignore

        result["integrations"]["pytesseract"] = {"status": "available", "version": getattr(pytesseract, "__version__", None)}
        ocr_limit = 2 if profile == "quick" else len(variants)
        for name, variant in variants[:ocr_limit]:
            try:
                text = pytesseract.image_to_string(variant, config="--psm 6", timeout=15 if profile != "deep" else 30)
                if text.strip():
                    result["text_records"].append({"source": f"OCR:{name}", "offset": None, "text": display_text(text, 1_000_000), "confidence_hint": -8})
            except RuntimeError as exc:
                result["integrations"]["pytesseract"]["last_error"] = display_text(exc, 300)
            except Exception as exc:
                result["integrations"]["pytesseract"] = {"status": "failed", "reason": f"{type(exc).__name__}: {display_text(exc, 300)}"}
                break
    except ImportError:
        result["integrations"]["pytesseract"] = {"status": "missing", "reason": "pytesseract is not installed."}

    barcode_count = 0
    try:
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
        result["integrations"]["pyzbar"] = {"status": "missing", "reason": f"pyzbar or its native ZBar library is unavailable: {display_text(exc, 200)}"}

    # OpenCV QR decoding is a useful independent fallback/cross-check.
    try:
        import cv2  # type: ignore
        import numpy as np  # type: ignore

        detector = cv2.QRCodeDetector()
        array = np.array(base.convert("RGB"))
        try:
            success, decoded, points, _ = detector.detectAndDecodeMulti(array)
            if success:
                for payload in decoded:
                    if payload:
                        result["text_records"].append({"source": "barcode:QR:opencv", "offset": None, "text": display_text(payload, 1_000_000), "confidence_hint": 15})
                        barcode_count += 1
        except (AttributeError, ValueError):
            payload, points, _ = detector.detectAndDecode(array)
            if payload:
                result["text_records"].append({"source": "barcode:QR:opencv", "offset": None, "text": display_text(payload, 1_000_000), "confidence_hint": 15})
                barcode_count += 1
    except (ImportError, Exception):
        pass
    result["properties"]["barcode_results"] = barcode_count
