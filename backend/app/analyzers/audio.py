"""Bounded PCM audio forensics, signal detection, and review artifacts."""

from __future__ import annotations

import io
import math
import struct
import time
import wave
from pathlib import Path
from typing import Any

import numpy as np
from PIL import Image, ImageDraw

from .common import display_text, normalize_json, utc_now
from .sstv import decode_sstv


AUDIO_KINDS = frozenset({"audio", "wav", "aiff", "flac", "ogg", "mp3", "aac", "m4a", "au", "asf", "amr", "caf", "midi"})
MAX_DECODE_FRAMES = 5_000_000
MAX_SSTV_SOURCE_FRAMES = 15_000_000
MAX_LSB_BYTES = 8 * 1024 * 1024
_DTMF_ROWS = (697.0, 770.0, 852.0, 941.0)
_DTMF_COLUMNS = (1209.0, 1336.0, 1477.0, 1633.0)
_DTMF_SYMBOLS = (
    ("1", "2", "3", "A"),
    ("4", "5", "6", "B"),
    ("7", "8", "9", "C"),
    ("*", "0", "#", "D"),
)
_MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}


def inspect_audio_container(path: Path, kind: str) -> dict[str, Any]:
    """Return small, format-aware header facts without trusting the filename."""

    size = path.stat().st_size
    with path.open("rb") as handle:
        head = handle.read(min(size, 1024 * 1024))
    details: dict[str, Any] = {"detected_type": kind, "file_size": size}
    if kind == "wav" and len(head) >= 12:
        declared_size = int.from_bytes(head[4:8], "little") + 8
        chunks: list[dict[str, Any]] = []
        cursor = 12
        while cursor + 8 <= len(head) and len(chunks) < 128:
            chunk_id = head[cursor:cursor + 4].decode("latin-1", "replace")
            chunk_size = int.from_bytes(head[cursor + 4:cursor + 8], "little")
            chunks.append({"id": display_text(chunk_id, 20), "offset": cursor, "size": chunk_size})
            if chunk_id == "fmt " and cursor + 24 <= len(head):
                details["format_code"] = int.from_bytes(head[cursor + 8:cursor + 10], "little")
            cursor += 8 + chunk_size + (chunk_size & 1)
            if cursor > len(head):
                break
        details.update({
            "riff_declared_size": declared_size,
            "riff_size_matches": declared_size == size,
            "trailing_bytes": max(0, size - declared_size),
            "chunks": chunks,
        })
    elif kind == "flac" and len(head) >= 42 and head[:4] == b"fLaC":
        stream_info = head[8:42]
        packed = int.from_bytes(stream_info[10:18], "big")
        sample_rate = (packed >> 44) & 0xFFFFF
        channels = ((packed >> 41) & 0x7) + 1
        bits_per_sample = ((packed >> 36) & 0x1F) + 1
        total_samples = packed & ((1 << 36) - 1)
        details.update({
            "sample_rate": sample_rate,
            "channels": channels,
            "bits_per_sample": bits_per_sample,
            "total_samples": total_samples,
            "duration_seconds": round(total_samples / sample_rate, 6) if sample_rate else None,
        })
    elif kind == "mp3" and head.startswith(b"ID3") and len(head) >= 10:
        tag_size = sum((head[6 + index] & 0x7F) << (21 - 7 * index) for index in range(4))
        details.update({"id3_version": f"2.{head[3]}.{head[4]}", "id3_tag_bytes": tag_size + 10})
    elif kind == "ogg" and len(head) >= 27:
        details.update({
            "ogg_version": head[4],
            "bitstream_serial": int.from_bytes(head[14:18], "little"),
            "first_page_segments": head[26],
        })
    elif kind == "m4a" and len(head) >= 12:
        details.update({
            "major_brand": head[8:12].decode("latin-1", "replace"),
            "first_box_size": int.from_bytes(head[:4], "big"),
        })
    elif kind == "midi" and len(head) >= 14:
        details.update({
            "header_length": int.from_bytes(head[4:8], "big"),
            "format": int.from_bytes(head[8:10], "big"),
            "tracks": int.from_bytes(head[10:12], "big"),
            "division": int.from_bytes(head[12:14], "big"),
        })
    return details


def analyze_audio(
    path: Path,
    *,
    kind: str,
    profile: str,
    enabled: bool,
    spectrogram_enabled: bool,
    signal_decoders: bool,
    sstv_enabled: bool,
    channel_exports: bool,
    audacity_bundle: bool,
    lsb_enabled: bool,
    analysis_seconds: int,
    fft_size: int,
    channel_mode: str,
    lsb_bits: int,
    sstv_mode: str = "auto",
    sstv_max_images: int = 2,
    sstv_slant_correction: bool = True,
) -> dict[str, Any]:
    """Analyze PCM WAV directly and describe other containers for external decoding."""

    started_at = utc_now()
    started = time.monotonic()
    result: dict[str, Any] = {
        "id": "built-in-audio",
        "name": "Built-in audio signal laboratory",
        "category": "audio",
        "status": "skipped" if not enabled else "completed",
        "applicable": kind in AUDIO_KINDS or enabled,
        "started_at": started_at if enabled else None,
        "duration_ms": 0,
        "summary": "Audio analysis was disabled in this job's settings." if not enabled else "Audio container inspected.",
        "tool": {"executable": "NumPy + Pillow + Python wave", "resolved": "built-in", "version": "1"},
        "details": {},
        "metadata": {},
        "findings": [],
        "visuals": [],
        "artifacts": [],
        "stego_streams": [],
        "text_records": [],
        "signals": {},
        "submethods": [],
    }
    if not enabled:
        return result

    container = inspect_audio_container(path, kind)
    result["metadata"] = {"container": container}
    if kind != "wav":
        result["summary"] = (
            f"Recognized {kind.upper()} audio/container data. Install FFmpeg/FFprobe or SoX for decoded waveform and spectrogram analysis."
        )
        result["submethods"] = _submethods_without_pcm(spectrogram_enabled, signal_decoders, sstv_enabled, channel_exports, audacity_bundle, lsb_enabled)
        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        return result

    try:
        with wave.open(str(path), "rb") as source:
            channels = source.getnchannels()
            sample_width = source.getsampwidth()
            sample_rate = source.getframerate()
            total_frames = source.getnframes()
            compression = source.getcomptype()
            if channels < 1 or channels > 32 or sample_rate < 1 or sample_rate > 768_000:
                raise ValueError("WAV channel count or sample rate is outside safe analysis bounds")
            frame_limit = min(total_frames, sample_rate * max(15, min(300, int(analysis_seconds))), MAX_DECODE_FRAMES)
            frames = source.readframes(frame_limit)
    except (EOFError, OSError, ValueError, wave.Error) as exc:
        result["status"] = "failed"
        result["summary"] = "The WAV header was recognized, but bounded PCM decoding failed safely."
        result["findings"].append(_finding(
            "error", "audio-structure", "WAV PCM decode failed",
            "The container is malformed, compressed with an unsupported codec, or outside configured safety limits.",
            error=f"{type(exc).__name__}: {display_text(exc, 300)}",
        ))
        result["submethods"] = _submethods_without_pcm(spectrogram_enabled, signal_decoders, sstv_enabled, channel_exports, audacity_bundle, lsb_enabled)
        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        return result

    try:
        samples, integer_samples, bit_depth = _decode_pcm(frames, sample_width, channels)
    except ValueError as exc:
        result["status"] = "failed"
        result["summary"] = "The WAV uses a sample encoding that the bounded PCM decoder does not support."
        result["findings"].append(_finding("warning", "audio-structure", "Unsupported PCM layout", str(exc)))
        result["submethods"] = _submethods_without_pcm(spectrogram_enabled, signal_decoders, sstv_enabled, channel_exports, audacity_bundle, lsb_enabled)
        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        return result

    duration = total_frames / sample_rate if sample_rate else 0.0
    analyzed_duration = len(samples) / sample_rate if sample_rate else 0.0
    selected = _select_channel(samples, channel_mode)
    statistics = _signal_statistics(samples, selected, sample_rate)
    properties = {
        "container": "wav",
        "channels": channels,
        "sample_rate": sample_rate,
        "sample_width_bytes": sample_width,
        "bit_depth": bit_depth,
        "total_frames": total_frames,
        "duration_seconds": round(duration, 6),
        "analyzed_frames": len(samples),
        "analyzed_seconds": round(analyzed_duration, 6),
        "analysis_truncated": len(samples) < total_frames,
        "compression": compression,
        "channel_mode": channel_mode,
    }
    result["metadata"].update({"properties": properties, "statistics": statistics})

    result["visuals"].append({
        "label": "audio_waveform",
        "title": "Waveform overview",
        "data": _render_waveform(samples, sample_rate),
        "producer": "built-in-audio",
        "transformation": "render bounded channel waveform envelope",
        "parameters": {"channels": channels, "sample_rate": sample_rate, "analyzed_seconds": round(analyzed_duration, 3)},
        "width": 1600,
        "height": 520,
    })
    if spectrogram_enabled:
        result["visuals"].append({
            "label": "audio_spectrogram",
            "title": "Log-frequency spectrogram",
            "data": _render_spectrogram(selected, sample_rate, max(256, min(4096, int(fft_size)))),
            "producer": "built-in-audio",
            "transformation": "short-time Fourier transform with logarithmic intensity mapping",
            "parameters": {"fft_size": fft_size, "sample_rate": sample_rate, "channel_mode": channel_mode},
            "width": 1600,
            "height": 820,
        })

    signals: dict[str, Any] = {
        "frequency_peaks": _frequency_peaks(selected, sample_rate),
        "silent_segments": _silent_segments(selected, sample_rate),
        "ultrasonic_energy_ratio": _ultrasonic_ratio(selected, sample_rate),
        "dtmf": {"symbols": "", "events": []},
        "morse": {"text": "", "pattern": "", "events": []},
        "sstv": {"candidate": False, "leader_frames": 0, "sync_frames": 0},
    }
    if signal_decoders:
        signals["dtmf"] = _decode_dtmf(selected, sample_rate)
        signals["morse"] = _decode_morse(selected, sample_rate)
    if sstv_enabled:
        sstv_samples = selected
        sstv_sample_rate = sample_rate
        if len(samples) < total_frames and analysis_seconds > analyzed_duration:
            try:
                extended = _read_sstv_pcm(path, analysis_seconds=analysis_seconds, channel_mode=channel_mode)
            except (EOFError, OSError, ValueError, wave.Error):
                extended = None
            if extended is not None:
                sstv_samples, sstv_sample_rate = extended
        sstv_result = decode_sstv(
            sstv_samples,
            sstv_sample_rate,
            mode_name=sstv_mode,
            max_images=sstv_max_images,
            slant_correction=sstv_slant_correction,
        )
        sstv_result["analyzed_seconds"] = round(len(sstv_samples) / sstv_sample_rate, 5)
        sstv_result["streaming_downsample"] = sstv_sample_rate != sample_rate
        decoded_images = list(sstv_result.pop("images", []))
        signals["sstv"] = sstv_result
        for decoded_image in decoded_images:
            result["visuals"].append({
                "label": decoded_image["label"],
                "title": decoded_image["title"],
                "data": decoded_image["data"],
                "producer": "built-in-sstv",
                "transformation": "decode SSTV frequency-modulated scan lines into RGB pixels",
                "parameters": decoded_image.get("parameters", {}),
                "width": decoded_image.get("width"),
                "height": decoded_image.get("height"),
            })
    result["signals"] = normalize_json(signals)

    labels: list[tuple[float, float, str]] = []
    for segment in signals["silent_segments"][:80]:
        labels.append((float(segment["start_seconds"]), float(segment["end_seconds"]), "Low-energy / silence region"))
    for event in signals["dtmf"].get("events", [])[:80]:
        labels.append((float(event["start_seconds"]), float(event["end_seconds"]), f"DTMF {event['symbol']}"))
    if signals["sstv"].get("candidate"):
        labels.append((0.0, min(analyzed_duration, 12.0), "Possible SSTV leader / sync tones"))

    if statistics["clipping_ratio"] >= 0.001:
        result["findings"].append(_finding(
            "warning", "audio-signal", "Clipped samples detected",
            f"Approximately {statistics['clipping_ratio'] * 100:.3f}% of analyzed samples are at full scale.",
            clipping_ratio=statistics["clipping_ratio"],
        ))
    if statistics.get("stereo_correlation") is not None and float(statistics["stereo_correlation"]) < -0.85:
        result["findings"].append(_finding(
            "warning", "audio-phase", "Strong stereo phase inversion",
            "Left and right channels are strongly anti-correlated; inspect the difference channel for hidden content.",
            stereo_correlation=statistics["stereo_correlation"],
        ))
    if signals["dtmf"].get("symbols"):
        decoded = str(signals["dtmf"]["symbols"])
        result["findings"].append(_finding("info", "audio-decoding", "DTMF sequence detected", f"Decoded bounded DTMF sequence: {decoded}", symbols=decoded))
        result["text_records"].append({"source": "audio:dtmf", "offset": None, "text": decoded, "confidence_hint": 9})
    if signals["morse"].get("text"):
        decoded = str(signals["morse"]["text"])
        result["findings"].append(_finding("info", "audio-decoding", "Morse-like keying detected", f"Decoded tentative Morse text: {decoded}", text=decoded, pattern=signals["morse"].get("pattern")))
        result["text_records"].append({"source": "audio:morse", "offset": None, "text": decoded, "confidence_hint": 6})
    if signals["sstv"].get("images_decoded"):
        modes = ", ".join(str(mode) for mode in signals["sstv"].get("decoded_modes", []))
        result["findings"].append(_finding(
            "high", "audio-sstv", "SSTV image recovered",
            f"Decoded {signals['sstv']['images_decoded']} SSTV image(s) from the audio signal ({modes or 'mode unavailable'}).",
            images_decoded=signals["sstv"]["images_decoded"],
            decoded_modes=signals["sstv"].get("decoded_modes", []),
            headers=signals["sstv"].get("headers", []),
        ))
    elif signals["sstv"].get("candidate"):
        result["findings"].append(_finding(
            "warning", "audio-sstv", "Possible SSTV transmission",
            "SSTV leader, sync, or VIS evidence was detected, but a complete image was not recovered. Try a manual mode or a longer analysis duration.",
            **signals["sstv"],
        ))
    if float(signals["ultrasonic_energy_ratio"]) >= 0.03:
        result["findings"].append(_finding(
            "info", "audio-spectrum", "Notable ultrasonic-band energy",
            "Energy above 18 kHz is elevated; inspect the full spectrogram for hidden high-frequency content.",
            ultrasonic_energy_ratio=signals["ultrasonic_energy_ratio"],
        ))
    if container.get("trailing_bytes", 0):
        result["findings"].append(_finding(
            "warning", "embedded-data", "Bytes follow the declared RIFF container",
            f"{container['trailing_bytes']} byte(s) occur after the WAV RIFF size and may contain appended data.",
            trailing_bytes=container["trailing_bytes"],
        ))

    if lsb_enabled:
        # CTF WAV stego commonly stores one bit in every *payload byte*, not
        # only in the decoded integer sample. Enumerate those byte planes
        # while keeping the output bounded and preserving frame order.
        requested_bits = max(1, min(8, int(lsb_bits)))
        raw_payload = np.frombuffer(frames, dtype=np.uint8)
        for bit in range(requested_bits):
            packed = _pcm_byte_lsb_stream(raw_payload, bit)
            if packed:
                result["stego_streams"].append({
                    "label": f"audio_pcm_lsb_bit{bit}",
                    "data": packed,
                    "producer": "built-in-audio-lsb",
                    "transformation": f"extract PCM payload-byte bit {bit} in interleaved frame order",
                    "kind": "binary",
                    "parameters": {"bit": bit, "channels": channels, "sample_width_bytes": sample_width, "payload_bytes": int(raw_payload.size), "packing": "msb-first"},
                })
        # Stereo challenges frequently hide the message in one channel.  The
        # channel-separated byte streams are deterministic and capped at four
        # channels, with no external process or unbounded allocation.
        if channels >= 2 and sample_width >= 1 and raw_payload.size % (channels * sample_width) == 0:
            frame_bytes = channels * sample_width
            channel_bytes = raw_payload.reshape(-1, frame_bytes).reshape(-1, channels, sample_width)
            for channel_index in range(min(channels, 4)):
                separated = channel_bytes[:, channel_index, :].reshape(-1)
                for bit in range(requested_bits):
                    packed = _pcm_byte_lsb_stream(separated, bit)
                    if packed:
                        result["stego_streams"].append({
                            "label": f"audio_pcm_lsb_channel{channel_index + 1}_bit{bit}",
                            "data": packed,
                            "producer": "built-in-audio-lsb",
                            "transformation": f"extract PCM payload-byte bit {bit} from channel {channel_index + 1} in frame order",
                            "kind": "binary",
                            "parameters": {"bit": bit, "channel": channel_index + 1, "channels": channels, "sample_width_bytes": sample_width, "payload_bytes": int(separated.size), "packing": "msb-first"},
                        })

    if channel_exports:
        export_channels: list[tuple[str, np.ndarray]] = [("mono_mix", np.mean(samples, axis=1, keepdims=True))]
        if channels >= 2:
            export_channels.extend([
                ("left_channel", samples[:, 0:1]),
                ("right_channel", samples[:, 1:2]),
                ("stereo_difference", ((samples[:, 0] - samples[:, 1]) * 0.5)[:, None]),
            ])
        for label, channel_data in export_channels:
            result["artifacts"].append({
                "label": f"audio_{label}", "data": _wav_bytes(channel_data, sample_rate), "kind": "wav",
                "producer": "built-in-audio", "transformation": f"export {label.replace('_', ' ')} as 16-bit PCM WAV",
            })
    if audacity_bundle:
        result["artifacts"].extend([
            {
                "label": "audacity_review_normalized", "data": _wav_bytes(_normalize(samples), sample_rate), "kind": "wav",
                "producer": "built-in-audio", "transformation": "normalize decoded PCM for Audacity review",
            },
            {
                "label": "audacity_review_reversed", "data": _wav_bytes(_normalize(samples[::-1]), sample_rate), "kind": "wav",
                "producer": "built-in-audio", "transformation": "reverse decoded PCM for Audacity review",
            },
            {
                "label": "audacity_labels", "data": _audacity_labels(labels), "kind": "text",
                "producer": "built-in-audio", "transformation": "create Audacity-compatible label track from signal events",
            },
        ])

    result["summary"] = (
        f"Decoded {channels}-channel {bit_depth}-bit PCM at {sample_rate:,} Hz; analyzed {analyzed_duration:.2f} of {duration:.2f} seconds, "
        f"generated {len(result['visuals'])} visual(s), {len(result['artifacts'])} review artifact(s), and {len(result['stego_streams'])} LSB stream(s)."
    )
    result["details"] = {"properties": properties, "statistics": statistics, "signals": result["signals"]}
    result["submethods"] = _submethods_with_pcm(result, spectrogram_enabled, signal_decoders, sstv_enabled, channel_exports, audacity_bundle, lsb_enabled)
    result["duration_ms"] = int((time.monotonic() - started) * 1000)
    return result


def _decode_pcm(frames: bytes, sample_width: int, channels: int) -> tuple[np.ndarray, np.ndarray, int]:
    usable = len(frames) - (len(frames) % (sample_width * channels))
    frames = frames[:usable]
    if sample_width == 1:
        raw = np.frombuffer(frames, dtype=np.uint8).astype(np.int64)
        normalized = (raw.astype(np.float32) - 128.0) / 128.0
        integer = raw
        bit_depth = 8
    elif sample_width == 2:
        raw = np.frombuffer(frames, dtype="<i2").astype(np.int64)
        normalized = raw.astype(np.float32) / 32768.0
        integer = raw
        bit_depth = 16
    elif sample_width == 3:
        triples = np.frombuffer(frames, dtype=np.uint8).reshape(-1, 3).astype(np.int64)
        raw = triples[:, 0] | (triples[:, 1] << 8) | (triples[:, 2] << 16)
        raw = np.where(raw & 0x800000, raw - 0x1000000, raw)
        normalized = raw.astype(np.float32) / 8388608.0
        integer = raw
        bit_depth = 24
    elif sample_width == 4:
        raw = np.frombuffer(frames, dtype="<i4").astype(np.int64)
        normalized = raw.astype(np.float32) / 2147483648.0
        integer = raw
        bit_depth = 32
    else:
        raise ValueError(f"Unsupported PCM sample width: {sample_width} byte(s).")
    if raw.size == 0:
        raise ValueError("No complete PCM frames were available.")
    return normalized.reshape(-1, channels), integer.reshape(-1, channels), bit_depth


def _read_sstv_pcm(path: Path, *, analysis_seconds: int, channel_mode: str) -> tuple[np.ndarray, int] | None:
    """Read a long WAV as bounded mono chunks and decimate for SSTV timing.

    General audio statistics retain the stricter in-memory frame ceiling. SSTV
    modes can last almost five minutes, so this path keeps only one selected
    channel at no more than 16 kHz while reading at most 15 million frames.
    """

    parts: list[np.ndarray] = []
    with wave.open(str(path), "rb") as source:
        channels = source.getnchannels()
        sample_width = source.getsampwidth()
        sample_rate = source.getframerate()
        total_frames = source.getnframes()
        if channels < 1 or channels > 32 or sample_rate < 6_000 or sample_rate > 768_000:
            return None
        frame_limit = min(total_frames, sample_rate * max(15, min(300, int(analysis_seconds))), MAX_SSTV_SOURCE_FRAMES)
        stride = max(1, math.ceil(sample_rate / 16_000))
        retained_rate = round(sample_rate / stride)
        frame_offset = 0
        remaining = frame_limit
        while remaining > 0:
            requested = min(262_144, remaining)
            frames = source.readframes(requested)
            if not frames:
                break
            decoded, _integer, _bit_depth = _decode_pcm(frames, sample_width, channels)
            start = (-frame_offset) % stride
            parts.append(_select_channel(decoded, channel_mode)[start::stride].astype(np.float32, copy=True))
            consumed = len(decoded)
            frame_offset += consumed
            remaining -= consumed
            if consumed < requested:
                break
    if not parts:
        return None
    retained = np.concatenate(parts)
    if retained.size > MAX_SSTV_SOURCE_FRAMES:
        retained = retained[:MAX_SSTV_SOURCE_FRAMES]
    return retained, retained_rate


def _select_channel(samples: np.ndarray, mode: str) -> np.ndarray:
    if samples.shape[1] == 1:
        return samples[:, 0]
    if mode == "left":
        return samples[:, 0]
    if mode == "right":
        return samples[:, 1]
    if mode == "difference":
        return (samples[:, 0] - samples[:, 1]) * 0.5
    return np.mean(samples, axis=1)


def _signal_statistics(samples: np.ndarray, selected: np.ndarray, sample_rate: int) -> dict[str, Any]:
    absolute = np.abs(selected)
    peak = float(np.max(absolute)) if absolute.size else 0.0
    rms = float(np.sqrt(np.mean(np.square(selected, dtype=np.float64)))) if selected.size else 0.0
    zero_crossings = float(np.mean(np.signbit(selected[1:]) != np.signbit(selected[:-1]))) if selected.size > 1 else 0.0
    clipping_ratio = float(np.mean(absolute >= 0.999)) if absolute.size else 0.0
    per_channel = []
    for index in range(samples.shape[1]):
        channel = samples[:, index]
        channel_peak = float(np.max(np.abs(channel)))
        channel_rms = float(np.sqrt(np.mean(np.square(channel, dtype=np.float64))))
        per_channel.append({
            "channel": index + 1, "peak": round(channel_peak, 7), "rms": round(channel_rms, 7),
            "dc_offset": round(float(np.mean(channel)), 7),
        })
    stereo_correlation: float | None = None
    if samples.shape[1] >= 2 and np.std(samples[:, 0]) > 1e-9 and np.std(samples[:, 1]) > 1e-9:
        stereo_correlation = float(np.corrcoef(samples[:, 0], samples[:, 1])[0, 1])
    return {
        "peak": round(peak, 7), "rms": round(rms, 7),
        "rms_dbfs": round(20 * math.log10(max(rms, 1e-12)), 3),
        "crest_factor_db": round(20 * math.log10(max(peak, 1e-12) / max(rms, 1e-12)), 3),
        "dc_offset": round(float(np.mean(selected)), 7),
        "zero_crossing_rate": round(zero_crossings, 7),
        "clipping_ratio": round(clipping_ratio, 8),
        "stereo_correlation": round(stereo_correlation, 6) if stereo_correlation is not None else None,
        "sample_rate": sample_rate,
        "channels": per_channel,
    }


def _render_waveform(samples: np.ndarray, sample_rate: int) -> bytes:
    width, height = 1600, 520
    image = Image.new("RGB", (width, height), "#10291f")
    draw = ImageDraw.Draw(image)
    plot_left, plot_right, plot_top, plot_bottom = 76, width - 26, 54, height - 44
    draw.text((26, 20), "REMANENCE · WAVEFORM", fill="#d9f99d")
    for fraction in (0.0, 0.25, 0.5, 0.75, 1.0):
        x = int(plot_left + (plot_right - plot_left) * fraction)
        draw.line((x, plot_top, x, plot_bottom), fill="#244d3c", width=1)
        seconds = len(samples) / sample_rate * fraction if sample_rate else 0
        draw.text((x - 12, plot_bottom + 10), f"{seconds:.1f}s", fill="#89a095")
    channels = min(samples.shape[1], 4)
    lane_height = (plot_bottom - plot_top) / channels
    colors = ("#d9f99d", "#f3b958", "#69c48f", "#f18f8f")
    columns = plot_right - plot_left
    for channel in range(channels):
        lane_mid = plot_top + lane_height * (channel + 0.5)
        draw.line((plot_left, lane_mid, plot_right, lane_mid), fill="#315b49", width=1)
        draw.text((18, lane_mid - 6), f"CH {channel + 1}", fill=colors[channel])
        data = samples[:, channel]
        edges = np.linspace(0, len(data), columns + 1, dtype=np.int64)
        scale = lane_height * 0.43
        for column in range(columns):
            segment = data[edges[column]:edges[column + 1]]
            if not segment.size:
                continue
            low = lane_mid - float(np.max(segment)) * scale
            high = lane_mid - float(np.min(segment)) * scale
            draw.line((plot_left + column, low, plot_left + column, high), fill=colors[channel], width=1)
    return _png_bytes(image)


def _render_spectrogram(samples: np.ndarray, sample_rate: int, fft_size: int) -> bytes:
    if len(samples) < fft_size:
        samples = np.pad(samples, (0, fft_size - len(samples)))
    maximum_columns = 1480
    hop = max(fft_size // 4, math.ceil(max(1, len(samples) - fft_size) / maximum_columns))
    starts = np.arange(0, max(1, len(samples) - fft_size + 1), hop, dtype=np.int64)[:maximum_columns]
    window = np.hanning(fft_size).astype(np.float32)
    spectrum = np.empty((fft_size // 2 + 1, len(starts)), dtype=np.float32)
    for index, start in enumerate(starts):
        frame = samples[start:start + fft_size]
        if len(frame) < fft_size:
            frame = np.pad(frame, (0, fft_size - len(frame)))
        spectrum[:, index] = np.abs(np.fft.rfft(frame * window)).astype(np.float32)
    db = 20.0 * np.log10(spectrum + 1e-9)
    ceiling = float(np.max(db))
    normalized = np.clip((db - (ceiling - 100.0)) / 100.0, 0.0, 1.0)
    normalized = np.flipud(normalized)
    red = np.clip(18 + normalized * 229, 0, 255)
    green = np.clip(31 + np.power(normalized, 0.62) * 205, 0, 255)
    blue = np.clip(28 + np.power(normalized, 2.2) * 90, 0, 255)
    rgb = np.stack((red, green, blue), axis=2).astype(np.uint8)
    heatmap = Image.fromarray(rgb, mode="RGB").resize((1480, 720), Image.Resampling.BILINEAR)
    image = Image.new("RGB", (1600, 820), "#10291f")
    image.paste(heatmap, (92, 54))
    draw = ImageDraw.Draw(image)
    draw.text((26, 20), f"REMANENCE · SPECTROGRAM · FFT {fft_size}", fill="#d9f99d")
    nyquist = sample_rate / 2
    for fraction in (0.0, 0.25, 0.5, 0.75, 1.0):
        y = int(54 + 720 * (1.0 - fraction))
        draw.line((88, y, 1576, y), fill="#ffffff22", width=1)
        draw.text((22, y - 5), f"{nyquist * fraction / 1000:.1f}k", fill="#89a095")
    duration = len(samples) / sample_rate if sample_rate else 0
    for fraction in (0.0, 0.25, 0.5, 0.75, 1.0):
        x = int(92 + 1480 * fraction)
        draw.text((x - 10, 786), f"{duration * fraction:.1f}s", fill="#89a095")
    return _png_bytes(image)


def _frequency_peaks(samples: np.ndarray, sample_rate: int) -> list[dict[str, float]]:
    if sample_rate < 1 or samples.size < 64:
        return []
    maximum = min(samples.size, 524_288)
    data = samples[:maximum].astype(np.float64)
    data -= np.mean(data)
    magnitudes = np.abs(np.fft.rfft(data * np.hanning(len(data))))
    frequencies = np.fft.rfftfreq(len(data), 1.0 / sample_rate)
    magnitudes[frequencies < 20] = 0
    peak = float(np.max(magnitudes))
    if peak <= 1e-12:
        return []
    order = np.argsort(magnitudes)[::-1]
    results: list[dict[str, float]] = []
    for index in order:
        frequency = float(frequencies[index])
        if any(abs(frequency - item["frequency_hz"]) < max(8.0, sample_rate / len(data) * 5) for item in results):
            continue
        results.append({
            "frequency_hz": round(frequency, 3),
            "relative_db": round(20 * math.log10(max(float(magnitudes[index]), 1e-12) / peak), 3),
        })
        if len(results) >= 10:
            break
    return results


def _silent_segments(samples: np.ndarray, sample_rate: int) -> list[dict[str, float]]:
    window = max(32, int(sample_rate * 0.05))
    if samples.size < window:
        return []
    count = samples.size // window
    reshaped = samples[:count * window].reshape(count, window)
    rms = np.sqrt(np.mean(np.square(reshaped, dtype=np.float64), axis=1))
    threshold = max(0.0001, min(0.01, float(np.max(rms)) * 0.015))
    quiet = rms <= threshold
    results: list[dict[str, float]] = []
    start: int | None = None
    for index, state in enumerate(np.append(quiet, False)):
        if state and start is None:
            start = index
        elif not state and start is not None:
            duration = (index - start) * window / sample_rate
            if duration >= 0.25:
                results.append({
                    "start_seconds": round(start * window / sample_rate, 4),
                    "end_seconds": round(index * window / sample_rate, 4),
                    "duration_seconds": round(duration, 4),
                })
            start = None
        if len(results) >= 80:
            break
    return results


def _decode_dtmf(samples: np.ndarray, sample_rate: int) -> dict[str, Any]:
    window = max(128, int(sample_rate * 0.08))
    hop = max(64, int(sample_rate * 0.04))
    frequencies = np.asarray((*_DTMF_ROWS, *_DTMF_COLUMNS), dtype=np.float64)
    indices = np.arange(window, dtype=np.float64)
    kernels = np.exp(-2j * np.pi * frequencies[:, None] * indices[None, :] / sample_rate)
    raw: list[tuple[str | None, float, float]] = []
    for start in range(0, max(0, len(samples) - window + 1), hop):
        segment = samples[start:start + window]
        if float(np.sqrt(np.mean(np.square(segment, dtype=np.float64)))) < 0.008:
            raw.append((None, start / sample_rate, (start + window) / sample_rate))
            continue
        amplitudes = 2.0 * np.abs(kernels @ segment) / window
        rows = amplitudes[:4].tolist()
        columns = amplitudes[4:].tolist()
        row_order = np.argsort(rows)[::-1]
        column_order = np.argsort(columns)[::-1]
        row_best, row_second = rows[int(row_order[0])], rows[int(row_order[1])]
        column_best, column_second = columns[int(column_order[0])], columns[int(column_order[1])]
        if row_best < 0.025 or column_best < 0.025 or row_best < row_second * 1.55 or column_best < column_second * 1.55:
            symbol = None
        else:
            symbol = _DTMF_SYMBOLS[int(row_order[0])][int(column_order[0])]
        raw.append((symbol, start / sample_rate, (start + window) / sample_rate))
    events: list[dict[str, Any]] = []
    current: str | None = None
    start_time = end_time = 0.0
    count = 0
    for symbol, frame_start, frame_end in [*raw, (None, 0.0, 0.0)]:
        if symbol == current:
            end_time = frame_end
            count += 1
            continue
        if current is not None and count >= 2:
            events.append({"symbol": current, "start_seconds": round(start_time, 4), "end_seconds": round(end_time, 4)})
        current, start_time, end_time, count = symbol, frame_start, frame_end, 1
    return {"symbols": "".join(str(item["symbol"]) for item in events), "events": events[:100]}


def _decode_morse(samples: np.ndarray, sample_rate: int) -> dict[str, Any]:
    window = max(32, int(sample_rate * 0.01))
    count = samples.size // window
    if count < 20:
        return {"text": "", "pattern": "", "events": []}
    envelope = np.sqrt(np.mean(np.square(samples[:count * window].reshape(count, window), dtype=np.float64), axis=1))
    peak = float(np.max(envelope))
    if peak < 0.01:
        return {"text": "", "pattern": "", "events": []}
    active = envelope >= max(float(np.median(envelope)) * 2.5, peak * 0.28)
    transitions: list[tuple[bool, int, int]] = []
    state = bool(active[0])
    start = 0
    for index, value in enumerate(np.append(active, not state)):
        value = bool(value)
        if value != state:
            transitions.append((state, start, index))
            state, start = value, index
    on_lengths = np.array([end - begin for value, begin, end in transitions if value], dtype=np.float64)
    if len(on_lengths) < 3 or len(on_lengths) > 300:
        return {"text": "", "pattern": "", "events": []}
    dot = max(1.0, float(np.percentile(on_lengths, 30)))
    pattern_words: list[list[str]] = [[]]
    current = ""
    events: list[dict[str, Any]] = []
    for value, begin, end in transitions:
        units = (end - begin) / dot
        if value:
            mark = "." if units < 2.1 else "-"
            current += mark
            events.append({"mark": mark, "start_seconds": round(begin * window / sample_rate, 4), "end_seconds": round(end * window / sample_rate, 4)})
        elif units >= 5.0:
            if current:
                pattern_words[-1].append(current)
                current = ""
            if pattern_words[-1]:
                pattern_words.append([])
        elif units >= 2.0 and current:
            pattern_words[-1].append(current)
            current = ""
    if current:
        pattern_words[-1].append(current)
    pattern_words = [word for word in pattern_words if word]
    decoded_words = ["".join(_MORSE.get(code, "?") for code in word) for word in pattern_words]
    decoded = " ".join(decoded_words)
    pattern = " / ".join(" ".join(word) for word in pattern_words)
    if len(decoded.replace(" ", "")) < 2 or decoded.count("?") > len(decoded.replace(" ", "")) // 2:
        return {"text": "", "pattern": display_text(pattern, 500), "events": events[:200]}
    return {"text": display_text(decoded, 500), "pattern": display_text(pattern, 1000), "events": events[:200]}


def _ultrasonic_ratio(samples: np.ndarray, sample_rate: int) -> float:
    if sample_rate < 38_000 or samples.size < 1024:
        return 0.0
    data = samples[:min(samples.size, 524_288)].astype(np.float64)
    power = np.square(np.abs(np.fft.rfft(data * np.hanning(len(data)))))
    frequencies = np.fft.rfftfreq(len(data), 1.0 / sample_rate)
    total = float(np.sum(power[frequencies >= 20]))
    ultrasonic = float(np.sum(power[frequencies >= 18_000]))
    return round(ultrasonic / total, 8) if total > 1e-20 else 0.0


def _pcm_lsb_stream(samples: np.ndarray, bit: int) -> bytes:
    flattened = samples.reshape(-1)
    maximum_bits = min(flattened.size, MAX_LSB_BYTES * 8)
    if maximum_bits < 8:
        return b""
    values = (np.right_shift(flattened[:maximum_bits], bit) & 1).astype(np.uint8)
    return np.packbits(values, bitorder="big").tobytes()


def _pcm_byte_lsb_stream(payload: np.ndarray, bit: int) -> bytes:
    """Pack a bounded bit plane from raw PCM payload bytes.

    ``wave.readframes`` excludes the RIFF header, so this mirrors the bytewise
    extraction used by common WAV steganography challenges without accidentally
    leaking container metadata into the candidate stream.
    """

    if payload.size < 8:
        return b""
    maximum_bits = min(int(payload.size), MAX_LSB_BYTES * 8)
    values = ((payload[:maximum_bits] >> int(bit)) & 1).astype(np.uint8)
    return np.packbits(values, bitorder="big").tobytes()


def _normalize(samples: np.ndarray) -> np.ndarray:
    peak = float(np.max(np.abs(samples))) if samples.size else 0.0
    return samples if peak <= 1e-12 else samples * (0.98 / peak)


def _wav_bytes(samples: np.ndarray, sample_rate: int) -> bytes:
    safe = np.clip(samples, -1.0, 1.0)
    pcm = (safe * 32767.0).astype("<i2").tobytes()
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as target:
        target.setnchannels(samples.shape[1] if samples.ndim == 2 else 1)
        target.setsampwidth(2)
        target.setframerate(sample_rate)
        target.writeframes(pcm)
    return buffer.getvalue()


def _audacity_labels(labels: list[tuple[float, float, str]]) -> bytes:
    if not labels:
        labels = [(0.0, 0.0, "No automatic signal events were detected")]
    text = "".join(f"{start:.6f}\t{end:.6f}\t{display_text(label, 200)}\n" for start, end, label in labels[:200])
    return text.encode("utf-8")


def _png_bytes(image: Image.Image) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=False)
    return buffer.getvalue()


def _finding(severity: str, category: str, title: str, description: str, **details: Any) -> dict[str, Any]:
    return {"severity": severity, "category": category, "title": title, "description": description, "details": normalize_json(details)}


def _method(method_id: str, name: str, category: str, status: str, summary: str, details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "id": method_id, "name": name, "category": category, "status": status,
        "applicable": status != "skipped", "started_at": utc_now() if status != "skipped" else None,
        "duration_ms": 0, "summary": summary,
        "tool": {"executable": "Remanence built-in", "resolved": "built-in", "version": "1"},
        "details": normalize_json(details or {}),
    }


def _submethods_without_pcm(spectrogram: bool, decoders: bool, sstv: bool, channels: bool, audacity: bool, lsb: bool) -> list[dict[str, Any]]:
    return [
        _method("audio-waveform", "PCM waveform and statistics", "audio", "skipped", "Direct PCM decoding is currently available for WAV input; FFmpeg/SoX can decode other formats."),
        _method("audio-spectrogram", "Spectrogram renderer", "audio-spectrum", "skipped", "A decoded PCM stream is required." if spectrogram else "Spectrogram generation was disabled."),
        _method("audio-signal-decoders", "DTMF and Morse signal decoders", "audio-decoding", "skipped", "A decoded PCM stream is required." if decoders else "Signal decoders were disabled."),
        _method("audio-sstv", "RX-SSTV-compatible image decoder", "audio-sstv", "skipped", "A decoded PCM stream is required." if sstv else "SSTV decoding was disabled."),
        _method("audio-pcm-lsb", "PCM byte/sample bit extraction", "steganography", "skipped", "A decoded PCM payload is required." if lsb else "PCM LSB extraction was disabled."),
        _method("audio-channel-exports", "Channel isolation exports", "audio", "skipped", "A decoded PCM stream is required." if channels else "Channel exports were disabled."),
        _method("audio-audacity", "Audacity review bundle", "audio", "skipped", "A decoded PCM stream is required." if audacity else "Audacity-compatible exports were disabled."),
    ]


def _submethods_with_pcm(result: dict[str, Any], spectrogram: bool, decoders: bool, sstv: bool, channels: bool, audacity: bool, lsb: bool) -> list[dict[str, Any]]:
    signals = result["signals"]
    return [
        _method("audio-waveform", "PCM waveform and statistics", "audio", "completed", "Decoded PCM statistics and a bounded waveform overview."),
        _method("audio-spectrogram", "Spectrogram renderer", "audio-spectrum", "completed" if spectrogram else "skipped", "Rendered a bounded STFT spectrogram." if spectrogram else "Spectrogram generation was disabled."),
        _method("audio-signal-decoders", "DTMF and Morse signal decoders", "audio-decoding", "completed" if decoders else "skipped", f"Decoded {len(signals['dtmf'].get('events', []))} DTMF event(s); Morse output: {signals['morse'].get('text') or 'none'}." if decoders else "Signal decoders were disabled.", {"dtmf": signals["dtmf"], "morse": signals["morse"]}),
        _method(
            "audio-sstv", "RX-SSTV-compatible image decoder", "audio-sstv", "completed" if sstv else "skipped",
            (
                f"Recovered {signals['sstv'].get('images_decoded', 0)} SSTV image(s): {', '.join(signals['sstv'].get('decoded_modes', []))}."
                if signals["sstv"].get("images_decoded")
                else ("SSTV signal evidence was detected, but no complete image was recovered." if signals["sstv"].get("candidate") else ("No SSTV-like VIS/leader/sync pattern was detected." if sstv else "SSTV decoding was disabled."))
            ),
            signals["sstv"],
        ),
        _method("audio-pcm-lsb", "PCM byte/sample bit extraction", "steganography", "completed" if lsb else "skipped", f"Extracted {len(result['stego_streams'])} bounded PCM byte/channel bit-plane stream(s)." if lsb else "PCM LSB extraction was disabled."),
        _method("audio-channel-exports", "Channel isolation exports", "audio", "completed" if channels else "skipped", "Exported mono, channel, and stereo-difference review WAVs." if channels else "Channel exports were disabled."),
        _method("audio-audacity", "Audacity review bundle", "audio", "completed" if audacity else "skipped", "Created normalized/reversed PCM WAVs and an Audacity-compatible label track." if audacity else "Audacity-compatible exports were disabled."),
    ]
