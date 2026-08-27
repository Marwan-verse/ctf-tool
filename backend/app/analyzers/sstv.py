"""Bounded Slow-Scan Television (SSTV) demodulation for PCM audio.

The decoder follows the standard 1500 Hz black / 2300 Hz white mapping,
decodes the 7-bit VIS header, and aligns every radio line to its 1200 Hz sync
pulse.  Mode timings are the public Martin, Scottie, Robot, and PD timings also
used by slowrx.  This module is deliberately self-contained: uploaded audio is
never passed to a GUI process and output is returned as verified PNG bytes.
"""

from __future__ import annotations

import io
import math
from dataclasses import dataclass
from typing import Any, Literal

import numpy as np
from PIL import Image


SstvModeName = Literal[
    "auto", "robot36", "robot72", "martin1", "martin2",
    "scottie1", "scottie2", "scottiedx", "pd120", "pd180", "pd240",
]

MAX_SSTV_SAMPLES = 5_000_000
MAX_SSTV_PIXELS = 800 * 616
_ANALYTIC_CHUNK = 262_144
_ANALYTIC_OVERLAP = 2_048


@dataclass(frozen=True)
class SstvMode:
    key: str
    name: str
    vis_code: int
    width: int
    height: int
    line_seconds: float
    sync_seconds: float
    porch_seconds: float
    pixel_seconds: float
    separator_seconds: float
    layout: Literal["rgb", "robot36", "robot72", "pd"]
    sync_position: Literal["start", "scottie"] = "start"

    @property
    def radio_lines(self) -> int:
        return self.height // 2 if self.layout == "pd" else self.height

    @property
    def channel_seconds(self) -> float:
        return self.width * self.pixel_seconds


MODES: dict[str, SstvMode] = {
    "robot36": SstvMode("robot36", "Robot 36", 0x08, 320, 240, 0.150, 0.009, 0.003, 0.000_137_5, 0.006, "robot36"),
    "robot72": SstvMode("robot72", "Robot 72", 0x0C, 320, 240, 0.300, 0.009, 0.003, 0.000_287_5, 0.0047, "robot72"),
    "martin1": SstvMode("martin1", "Martin M1", 0x2C, 320, 256, 0.446_446, 0.004_862, 0.000_572, 0.000_457_6, 0.000_572, "rgb"),
    "martin2": SstvMode("martin2", "Martin M2", 0x28, 320, 256, 0.226_798_6, 0.004_862, 0.000_572, 0.000_228_8, 0.000_572, "rgb"),
    "scottie1": SstvMode("scottie1", "Scottie S1", 0x3C, 320, 256, 0.428_38, 0.009, 0.0015, 0.000_432, 0.0015, "rgb", "scottie"),
    "scottie2": SstvMode("scottie2", "Scottie S2", 0x38, 320, 256, 0.277_692, 0.009, 0.0015, 0.000_275_2, 0.0015, "rgb", "scottie"),
    "scottiedx": SstvMode("scottiedx", "Scottie DX", 0x4C, 320, 256, 1.0503, 0.009, 0.0015, 0.001_080_53, 0.0015, "rgb", "scottie"),
    "pd120": SstvMode("pd120", "PD-120", 0x5F, 640, 496, 0.50848, 0.020, 0.00208, 0.00019, 0.0, "pd"),
    "pd180": SstvMode("pd180", "PD-180", 0x60, 640, 496, 0.75424, 0.020, 0.00208, 0.000286, 0.0, "pd"),
    "pd240": SstvMode("pd240", "PD-240", 0x61, 640, 496, 1.000, 0.020, 0.00208, 0.000382, 0.0, "pd"),
}
MODES_BY_VIS = {mode.vis_code: mode for mode in MODES.values()}


def decode_sstv(
    samples: np.ndarray,
    sample_rate: int,
    *,
    mode_name: str = "auto",
    max_images: int = 2,
    slant_correction: bool = True,
) -> dict[str, Any]:
    """Decode bounded SSTV transmissions from one normalized mono PCM stream."""

    empty = {
        "candidate": False,
        "status": "no_signal",
        "images_decoded": 0,
        "decoded_modes": [],
        "leader_frames": 0,
        "sync_frames": 0,
        "sync_offsets_seconds": [],
        "headers": [],
        "images": [],
        "method": "VIS header + sync-edge-locked SSTV demodulation",
    }
    if sample_rate < 6_000 or samples.size < sample_rate // 2:
        return empty | {"status": "insufficient_audio", "reason": "At least 0.5 seconds of PCM audio at 6 kHz is required."}

    selected = np.asarray(samples[:MAX_SSTV_SAMPLES], dtype=np.float32).reshape(-1)
    if not np.any(np.abs(selected) > 1e-5):
        return empty

    frequency, amplitude = _instantaneous_frequency(selected, sample_rate)
    track, hop_seconds = _frequency_track(frequency, amplitude, sample_rate)
    headers = _find_vis_headers(track, hop_seconds)
    requested = MODES.get(str(mode_name).lower())
    max_images = max(1, min(4, int(max_images)))

    leader_frames = int(np.count_nonzero(np.abs(track - 1900.0) <= 90.0))
    sync_indices = np.flatnonzero(np.abs(track - 1200.0) <= 100.0)
    sync_offsets = [round(float(index) * hop_seconds, 4) for index in sync_indices[:80]]
    public_headers = [
        {
            "offset_seconds": round(float(header["offset_seconds"]), 4),
            "image_start_seconds": round(float(header["image_start_seconds"]), 4),
            "vis_code": int(header["vis_code"]),
            "vis_hex": f"0x{int(header['vis_code']):02X}",
            "mode": MODES_BY_VIS.get(int(header["vis_code"])).name if int(header["vis_code"]) in MODES_BY_VIS else None,
            "parity_valid": bool(header["parity_valid"]),
            "confidence": round(float(header["confidence"]), 4),
            "frequency_shift_hz": round(float(header["frequency_shift_hz"]), 3),
        }
        for header in headers[:12]
    ]

    decode_jobs: list[tuple[dict[str, Any], SstvMode]] = []
    for header in headers:
        detected = MODES_BY_VIS.get(int(header["vis_code"]))
        mode = requested or detected
        if mode is None or (not header["parity_valid"] and requested is None):
            continue
        if any(abs(float(header["image_start_seconds"]) - float(existing[0]["image_start_seconds"])) < 0.75 for existing in decode_jobs):
            continue
        decode_jobs.append((header, mode))
        if len(decode_jobs) >= max_images:
            break

    # A manual mode can recover a damaged/missing VIS code. Prefer the first
    # plausible header; otherwise use the first sync pulse as the line anchor.
    if requested and not decode_jobs:
        if headers:
            decode_jobs.append((headers[0], requested))
        else:
            start = _manual_image_start(track, hop_seconds, requested)
            if start is not None:
                decode_jobs.append(({
                    "offset_seconds": max(0.0, start - 0.91),
                    "image_start_seconds": start,
                    "vis_code": requested.vis_code,
                    "parity_valid": False,
                    "confidence": 0.3,
                    "frequency_shift_hz": 0.0,
                }, requested))

    decoded: list[dict[str, Any]] = []
    for index, (header, mode) in enumerate(decode_jobs):
        image_result = _decode_image(
            frequency,
            amplitude,
            sample_rate,
            mode,
            float(header["image_start_seconds"]),
            float(header["frequency_shift_hz"]),
            slant_correction=slant_correction,
        )
        if image_result is None:
            continue
        image_result.update({
            "label": f"sstv_decoded_{index + 1}_{mode.key}",
            "title": f"Recovered SSTV image · {mode.name}",
            "mode": mode.name,
            "mode_key": mode.key,
            "vis_code": mode.vis_code,
            "header_offset_seconds": round(float(header["offset_seconds"]), 4),
            "frequency_shift_hz": round(float(header["frequency_shift_hz"]), 3),
            "vis_confidence": round(float(header["confidence"]), 4),
        })
        decoded.append(image_result)

    candidate = bool(headers or decoded or leader_frames >= 20)
    status = "decoded" if decoded else ("signal_detected" if candidate else "no_signal")
    return {
        "candidate": candidate,
        "status": status,
        "images_decoded": len(decoded),
        "decoded_modes": [item["mode"] for item in decoded],
        "leader_frames": leader_frames,
        "sync_frames": int(sync_indices.size),
        "sync_offsets_seconds": sync_offsets,
        "headers": public_headers,
        "images": decoded,
        "requested_mode": requested.name if requested else "Auto (VIS)",
        "slant_correction": bool(slant_correction),
        "analyzed_samples": int(selected.size),
        "analysis_truncated": samples.size > selected.size,
        "method": "VIS header + sync-edge-locked SSTV demodulation",
    }


def _instantaneous_frequency(samples: np.ndarray, sample_rate: int) -> tuple[np.ndarray, np.ndarray]:
    """Return instantaneous frequency/amplitude using bounded overlap chunks."""

    centered = samples.astype(np.float64, copy=True)
    centered -= float(np.mean(centered))
    frequency = np.empty(centered.size, dtype=np.float32)
    amplitude = np.empty(centered.size, dtype=np.float32)
    for core_start in range(0, centered.size, _ANALYTIC_CHUNK):
        core_end = min(centered.size, core_start + _ANALYTIC_CHUNK)
        segment_start = max(0, core_start - _ANALYTIC_OVERLAP)
        segment_end = min(centered.size, core_end + _ANALYTIC_OVERLAP)
        segment = centered[segment_start:segment_end]
        fft_size = 1 << max(1, (len(segment) - 1).bit_length())
        spectrum = np.fft.fft(segment, n=fft_size)
        multiplier = np.zeros(fft_size, dtype=np.float64)
        multiplier[0] = 1.0
        if fft_size % 2 == 0:
            multiplier[fft_size // 2] = 1.0
            multiplier[1:fft_size // 2] = 2.0
        else:
            multiplier[1:(fft_size + 1) // 2] = 2.0
        analytic = np.fft.ifft(spectrum * multiplier)[:len(segment)]
        local_frequency = np.empty(len(segment), dtype=np.float64)
        if len(segment) > 1:
            local_frequency[1:] = np.angle(analytic[1:] * np.conj(analytic[:-1])) * sample_rate / (2.0 * math.pi)
            local_frequency[0] = local_frequency[1]
        else:
            local_frequency[0] = 0.0
        source_start = core_start - segment_start
        source_end = source_start + (core_end - core_start)
        frequency[core_start:core_end] = local_frequency[source_start:source_end].astype(np.float32)
        amplitude[core_start:core_end] = np.abs(analytic[source_start:source_end]).astype(np.float32)
    invalid = ~np.isfinite(frequency) | (frequency < 400.0) | (frequency > min(4_000.0, sample_rate * 0.48))
    frequency[invalid] = np.nan
    return frequency, amplitude


def _frequency_track(frequency: np.ndarray, amplitude: np.ndarray, sample_rate: int) -> tuple[np.ndarray, float]:
    hop_seconds = 0.010
    hop = max(1, round(sample_rate * hop_seconds))
    radius = max(2, round(sample_rate * 0.007))
    track = np.full(max(1, math.ceil(len(frequency) / hop)), np.nan, dtype=np.float32)
    amplitude_floor = max(1e-5, float(np.percentile(amplitude, 20)) * 0.5)
    for output_index, center in enumerate(range(0, len(frequency), hop)):
        start, end = max(0, center - radius), min(len(frequency), center + radius + 1)
        local_frequency = frequency[start:end]
        weights = amplitude[start:end]
        valid = np.isfinite(local_frequency) & (weights >= amplitude_floor)
        if np.count_nonzero(valid) >= 3:
            safe_weights = np.square(weights[valid].astype(np.float64)) + 1e-12
            track[output_index] = float(np.average(local_frequency[valid], weights=safe_weights))
    return track, hop_seconds


def _find_vis_headers(track: np.ndarray, hop_seconds: float) -> list[dict[str, Any]]:
    if hop_seconds <= 0 or track.size < 92:
        return []
    scale = 0.010 / hop_seconds
    if not 0.95 <= scale <= 1.05:
        return []
    candidates: list[dict[str, Any]] = []
    for start in range(0, len(track) - 92):
        leader_one = track[start + 5:start + 25]
        leader_two = track[start + 35:start + 58]
        if np.count_nonzero(np.isfinite(leader_one)) < 12 or np.count_nonzero(np.isfinite(leader_two)) < 14:
            continue
        observed = float(np.nanmedian(np.concatenate((leader_one, leader_two))))
        shift = observed - 1900.0
        leader_error = float(np.nanmedian(np.abs(np.concatenate((leader_one, leader_two)) - observed)))
        if abs(shift) > 220.0 or leader_error > 85.0:
            continue
        start_tone = _track_value(track, start + 62)
        stop_tone = _track_value(track, start + 90)
        if start_tone is None or stop_tone is None:
            continue
        start_error = abs(start_tone - (1200.0 + shift))
        stop_error = abs(stop_tone - (1200.0 + shift))
        if start_error > 180.0 or stop_error > 180.0:
            continue
        bits: list[int] = []
        bit_errors: list[float] = []
        for bit_index in range(7):
            value = _track_value(track, start + 66 + bit_index * 3)
            if value is None:
                break
            error_one = abs(value - (1100.0 + shift))
            error_zero = abs(value - (1300.0 + shift))
            bits.append(1 if error_one < error_zero else 0)
            bit_errors.append(min(error_one, error_zero))
        if len(bits) != 7 or max(bit_errors, default=999.0) > 175.0:
            continue
        parity_value = _track_value(track, start + 87)
        if parity_value is None:
            continue
        parity_bit = 1 if abs(parity_value - (1100.0 + shift)) < abs(parity_value - (1300.0 + shift)) else 0
        parity_error = min(abs(parity_value - (1100.0 + shift)), abs(parity_value - (1300.0 + shift)))
        code = sum(bit << index for index, bit in enumerate(bits))
        parity_valid = (sum(bits) + parity_bit) % 2 == 0
        mean_error = float(np.mean([leader_error, start_error, stop_error, parity_error, *bit_errors]))
        confidence = max(0.0, min(1.0, 1.0 - mean_error / 210.0))
        offset = start * hop_seconds
        candidate = {
            "offset_seconds": offset,
            "image_start_seconds": offset + 0.910,
            "vis_code": code,
            "parity_valid": parity_valid,
            "confidence": confidence,
            "frequency_shift_hz": shift,
        }
        if candidates and abs(offset - float(candidates[-1]["offset_seconds"])) < 0.5:
            if confidence > float(candidates[-1]["confidence"]):
                candidates[-1] = candidate
        else:
            candidates.append(candidate)
        if len(candidates) >= 16:
            break
    return candidates


def _track_value(track: np.ndarray, index: int) -> float | None:
    start, end = max(0, index - 1), min(len(track), index + 2)
    values = track[start:end]
    if not np.any(np.isfinite(values)):
        return None
    return float(np.nanmedian(values))


def _manual_image_start(track: np.ndarray, hop_seconds: float, mode: SstvMode) -> float | None:
    target = np.flatnonzero(np.isfinite(track) & (np.abs(track - 1200.0) <= 110.0))
    if not target.size:
        return None
    minimum_run = max(1, round(mode.sync_seconds / hop_seconds * 0.5))
    run_start = int(target[0])
    previous = run_start
    for raw in target[1:]:
        value = int(raw)
        if value != previous + 1:
            if previous - run_start + 1 >= minimum_run and run_start * hop_seconds > 0.5:
                sync_time = run_start * hop_seconds
                if mode.sync_position == "scottie":
                    return max(0.0, sync_time - (2 * mode.separator_seconds + 2 * mode.channel_seconds))
                return sync_time
            run_start = value
        previous = value
    return None


def _decode_image(
    frequency: np.ndarray,
    amplitude: np.ndarray,
    sample_rate: int,
    mode: SstvMode,
    image_start_seconds: float,
    frequency_shift_hz: float,
    *,
    slant_correction: bool,
) -> dict[str, Any] | None:
    if mode.width * mode.height > MAX_SSTV_PIXELS:
        return None
    duration = len(frequency) / sample_rate
    if image_start_seconds < 0 or image_start_seconds >= duration:
        return None
    rgb = np.zeros((mode.height, mode.width, 3), dtype=np.uint8)
    y_plane = np.zeros((mode.height, mode.width), dtype=np.uint8)
    cr_plane = np.full((mode.height, mode.width), 128, dtype=np.uint8)
    cb_plane = np.full((mode.height, mode.width), 128, dtype=np.uint8)
    decoded_rows = 0
    sync_locked = 0
    sync_errors: list[float] = []
    radio_lines_decoded = 0
    last_required = _last_channel_end(mode)

    for radio_line in range(mode.radio_lines):
        nominal_start = image_start_seconds + radio_line * mode.line_seconds
        # A capture can end exactly on the final channel boundary.  The
        # decoder only samples channel centres, so allow that endpoint (plus
        # one sample of floating-point/rasterization tolerance) instead of
        # silently dropping the last complete row.
        if nominal_start + last_required > duration + (1.0 / sample_rate):
            break
        line_start = nominal_start
        if slant_correction:
            corrected, quality = _align_line_sync(
                frequency,
                amplitude,
                sample_rate,
                mode,
                nominal_start,
                frequency_shift_hz,
            )
            if corrected is not None:
                line_start = corrected
                sync_locked += 1
                sync_errors.append(abs(corrected - nominal_start) * 1000.0)

        if mode.layout == "rgb":
            channels = _rgb_channel_offsets(mode)
            green = _sample_channel(frequency, line_start + channels[0], mode.pixel_seconds, mode.width, sample_rate, frequency_shift_hz)
            blue = _sample_channel(frequency, line_start + channels[1], mode.pixel_seconds, mode.width, sample_rate, frequency_shift_hz)
            red = _sample_channel(frequency, line_start + channels[2], mode.pixel_seconds, mode.width, sample_rate, frequency_shift_hz)
            if green is None or blue is None or red is None:
                break
            rgb[radio_line, :, 0] = red
            rgb[radio_line, :, 1] = green
            rgb[radio_line, :, 2] = blue
            decoded_rows = radio_line + 1
        elif mode.layout == "robot72":
            channel = mode.channel_seconds
            start = mode.sync_seconds + mode.porch_seconds
            y_value = _sample_channel(frequency, line_start + start, mode.pixel_seconds, mode.width, sample_rate, frequency_shift_hz)
            cr_value = _sample_channel(frequency, line_start + start + channel + mode.separator_seconds, mode.pixel_seconds, mode.width, sample_rate, frequency_shift_hz)
            cb_value = _sample_channel(frequency, line_start + start + 2 * channel + 2 * mode.separator_seconds, mode.pixel_seconds, mode.width, sample_rate, frequency_shift_hz)
            if y_value is None or cr_value is None or cb_value is None:
                break
            rgb[radio_line] = _ycbcr_to_rgb(y_value, cr_value, cb_value)
            decoded_rows = radio_line + 1
        elif mode.layout == "robot36":
            start = mode.sync_seconds + mode.porch_seconds
            y_value = _sample_channel(frequency, line_start + start, mode.pixel_seconds * 2.0, mode.width, sample_rate, frequency_shift_hz)
            chroma = _sample_channel(
                frequency,
                line_start + start + mode.width * mode.pixel_seconds * 2.0 + mode.separator_seconds,
                mode.pixel_seconds,
                mode.width,
                sample_rate,
                frequency_shift_hz,
            )
            if y_value is None or chroma is None:
                break
            y_plane[radio_line] = y_value
            target_plane = cr_plane if radio_line % 2 == 0 else cb_plane
            target_plane[radio_line] = chroma
            if radio_line + 1 < mode.height:
                target_plane[radio_line + 1] = chroma
            decoded_rows = radio_line + 1
        else:  # PD: one radio line carries two image rows.
            channel = mode.channel_seconds
            start = mode.sync_seconds + mode.porch_seconds
            y_first = _sample_channel(frequency, line_start + start, mode.pixel_seconds, mode.width, sample_rate, frequency_shift_hz)
            cr_value = _sample_channel(frequency, line_start + start + channel, mode.pixel_seconds, mode.width, sample_rate, frequency_shift_hz)
            cb_value = _sample_channel(frequency, line_start + start + 2 * channel, mode.pixel_seconds, mode.width, sample_rate, frequency_shift_hz)
            y_second = _sample_channel(frequency, line_start + start + 3 * channel, mode.pixel_seconds, mode.width, sample_rate, frequency_shift_hz)
            if y_first is None or cr_value is None or cb_value is None or y_second is None:
                break
            row = radio_line * 2
            rgb[row] = _ycbcr_to_rgb(y_first, cr_value, cb_value)
            rgb[row + 1] = _ycbcr_to_rgb(y_second, cr_value, cb_value)
            decoded_rows = row + 2
        radio_lines_decoded += 1

    if mode.layout == "robot36" and decoded_rows:
        rgb[:decoded_rows] = _ycbcr_to_rgb(y_plane[:decoded_rows], cr_plane[:decoded_rows], cb_plane[:decoded_rows])
    if decoded_rows < 8:
        return None

    cropped = rgb[:decoded_rows]
    image = Image.fromarray(cropped, mode="RGB")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG", optimize=False)
    expected_radio_lines = mode.radio_lines
    completion = radio_lines_decoded / expected_radio_lines if expected_radio_lines else 0.0
    return {
        "data": buffer.getvalue(),
        "width": mode.width,
        "height": decoded_rows,
        "expected_height": mode.height,
        "decoded_rows": decoded_rows,
        "radio_lines_decoded": radio_lines_decoded,
        "completion_ratio": round(completion, 5),
        "sync_lock_ratio": round(sync_locked / max(1, radio_lines_decoded), 5) if slant_correction else None,
        "mean_sync_correction_ms": round(float(np.mean(sync_errors)), 4) if sync_errors else None,
        "parameters": {
            "mode": mode.name,
            "vis_code": mode.vis_code,
            "decoded_rows": decoded_rows,
            "expected_rows": mode.height,
            "completion_ratio": round(completion, 5),
            "sync_lock_ratio": round(sync_locked / max(1, radio_lines_decoded), 5) if slant_correction else None,
            "frequency_shift_hz": round(frequency_shift_hz, 3),
        },
    }


def _last_channel_end(mode: SstvMode) -> float:
    if mode.layout == "rgb":
        return _rgb_channel_offsets(mode)[2] + mode.channel_seconds
    start = mode.sync_seconds + mode.porch_seconds
    if mode.layout == "robot36":
        return start + mode.width * mode.pixel_seconds * 3.0 + mode.separator_seconds
    if mode.layout == "robot72":
        return start + mode.channel_seconds * 3.0 + mode.separator_seconds * 2.0
    return start + mode.channel_seconds * 4.0


def _rgb_channel_offsets(mode: SstvMode) -> tuple[float, float, float]:
    channel = mode.channel_seconds
    if mode.sync_position == "scottie":
        return (
            mode.separator_seconds,
            2 * mode.separator_seconds + channel,
            2 * mode.separator_seconds + 2 * channel + mode.sync_seconds + mode.porch_seconds,
        )
    start = mode.sync_seconds + mode.porch_seconds
    return start, start + channel + mode.separator_seconds, start + 2 * channel + 2 * mode.separator_seconds


def _align_line_sync(
    frequency: np.ndarray,
    amplitude: np.ndarray,
    sample_rate: int,
    mode: SstvMode,
    nominal_line_start: float,
    shift_hz: float,
) -> tuple[float | None, float]:
    """Find the *leading edge* of the line sync pulse.

    A sync pulse is a constant 1200 Hz tone.  Searching for the lowest
    rolling frequency error (the old implementation) therefore had no unique
    answer: every window wholly inside the pulse scored almost identically.
    The selected point moved with Hilbert-phase ripple and produced horizontal
    tearing when each row was sampled from a different offset.  Treat the
    pulse as a bounded run instead and use its first sample as the timing
    anchor.  Tiny gaps are bridged to tolerate dropouts, while implausible run
    lengths are rejected so a random 1200 Hz tone cannot become a line lock.
    """
    sync_offset = 0.0
    if mode.sync_position == "scottie":
        sync_offset = 2 * mode.separator_seconds + 2 * mode.channel_seconds
    expected = nominal_line_start + sync_offset
    radius = min(0.045, max(0.012, mode.line_seconds * 0.055))
    start = max(0, round((expected - radius) * sample_rate))
    end = min(len(frequency), round((expected + radius + mode.sync_seconds) * sample_rate))
    if end - start <= max(8, round(mode.sync_seconds * sample_rate * 0.5)) + 2:
        return None, 0.0
    local_frequency = frequency[start:end]
    local_amplitude = amplitude[start:end]
    target = 1200.0 + shift_hz
    floor = max(1e-6, float(np.percentile(local_amplitude, 15)) * 0.35)
    valid = (
        np.isfinite(local_frequency)
        & (np.abs(local_frequency.astype(np.float64) - target) <= 125.0)
        & (local_amplitude >= floor)
    )

    # A short invalid run is usually a phase unwrap/dropout, not the end of
    # the pulse.  Fill only interior gaps; never expand a run at either edge.
    gap_limit = max(1, round(sample_rate * 0.00035))
    transitions = np.flatnonzero(valid[1:] != valid[:-1])
    for gap_start, gap_end in zip(np.r_[0, transitions + 1], np.r_[transitions + 1, len(valid)]):
        if valid[gap_start] or gap_end - gap_start > gap_limit:
            continue
        if gap_start > 0 and gap_end < len(valid) and valid[gap_start - 1] and valid[gap_end]:
            valid[gap_start:gap_end] = True

    transitions = np.flatnonzero(valid[1:] != valid[:-1])
    min_samples = max(3, round(mode.sync_seconds * sample_rate * 0.50))
    max_samples = max(min_samples + 1, round(mode.sync_seconds * sample_rate * 1.65))
    candidates: list[tuple[float, int, int, float]] = []
    for run_start, run_end in zip(np.r_[0, transitions + 1], np.r_[transitions + 1, len(valid)]):
        if not valid[run_start]:
            continue
        run_length = int(run_end - run_start)
        if run_length < min_samples or run_length > max_samples:
            continue
        actual = (start + int(run_start)) / sample_rate
        duration_error = abs((run_length / sample_rate) - mode.sync_seconds) / max(mode.sync_seconds, 1e-6)
        position_error = abs(actual - expected) / max(mode.sync_seconds, 1e-6)
        # Prefer a leading edge close to the predicted line and a run close to
        # the published sync duration.  The position term dominates so a
        # later video tone cannot win merely by being longer.
        score = position_error + duration_error * 0.35
        candidates.append((score, int(run_start), run_length, actual))
    if not candidates:
        return None, 0.0

    _, _, run_length, sync_start = min(candidates, key=lambda item: item[0])
    duration_ratio = run_length / max(mode.sync_seconds * sample_rate, 1.0)
    quality = max(0.0, min(1.0, 1.0 - abs(1.0 - duration_ratio) * 0.8))
    return sync_start - sync_offset, quality


def _sample_channel(
    frequency: np.ndarray,
    start_seconds: float,
    pixel_seconds: float,
    width: int,
    sample_rate: int,
    shift_hz: float,
) -> np.ndarray | None:
    end_seconds = start_seconds + width * pixel_seconds
    if start_seconds < 0 or end_seconds > len(frequency) / sample_rate + (2.0 / sample_rate):
        return None
    centers = (start_seconds + (np.arange(width, dtype=np.float64) + 0.5) * pixel_seconds) * sample_rate
    offsets = (-0.22, 0.0, 0.22)
    estimates = []
    for offset in offsets:
        query = centers + offset * pixel_seconds * sample_rate
        lower = np.floor(query).astype(np.int64)
        upper = np.minimum(lower + 1, len(frequency) - 1)
        fraction = query - lower
        estimates.append(frequency[lower] * (1.0 - fraction) + frequency[upper] * fraction)
    tones = np.nanmedian(np.stack(estimates, axis=0), axis=0) - shift_hz
    values = np.clip((tones - 1500.0) * (255.0 / 800.0), 0.0, 255.0)
    values[~np.isfinite(values)] = 0.0
    return np.rint(values).astype(np.uint8)


def _ycbcr_to_rgb(y: np.ndarray, cr: np.ndarray, cb: np.ndarray) -> np.ndarray:
    y_value = y.astype(np.float32)
    cr_value = cr.astype(np.float32) - 128.0
    cb_value = cb.astype(np.float32) - 128.0
    red = y_value + 1.402 * cr_value
    green = y_value - 0.714_136 * cr_value - 0.344_136 * cb_value
    blue = y_value + 1.772 * cb_value
    return np.clip(np.stack((red, green, blue), axis=-1), 0.0, 255.0).astype(np.uint8)
