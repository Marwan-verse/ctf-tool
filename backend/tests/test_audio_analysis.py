from __future__ import annotations

import math
import struct
import wave
from io import BytesIO
from pathlib import Path

import numpy as np
from PIL import Image

from app.analyzers.audio import analyze_audio
from app.analyzers.sstv import MODES, _align_line_sync, decode_sstv
from app.engine import AnalysisEngine


def _write_dtmf_wav(path: Path) -> None:
    sample_rate = 8_000
    samples: list[int] = []
    for index in range(sample_rate):
        time_value = index / sample_rate
        if 0.1 <= time_value < 0.7:
            value = 0.34 * math.sin(2 * math.pi * 697 * time_value) + 0.34 * math.sin(2 * math.pi * 1209 * time_value)
        else:
            value = 0.0
        samples.append(max(-32768, min(32767, round(value * 32767))))
    with wave.open(str(path), "wb") as target:
        target.setnchannels(1)
        target.setsampwidth(2)
        target.setframerate(sample_rate)
        target.writeframes(b"".join(struct.pack("<h", value) for value in samples))
    with path.open("ab") as target:
        target.write(b"flag{audio_pipeline}\n")


def _synthetic_martin_m2(sample_rate: int = 12_000) -> np.ndarray:
    mode_line_seconds = 0.226_798_6
    sync_seconds = 0.004_862
    porch_seconds = 0.000_572
    pixel_seconds = 0.000_228_8
    separator_seconds = 0.000_572
    width = 320
    vis_code = 0x28
    pieces: list[np.ndarray] = []

    def tone(frequency: float, seconds: float) -> None:
        pieces.append(np.full(max(1, round(seconds * sample_rate)), frequency, dtype=np.float64))

    tone(1900, 0.300)
    tone(1200, 0.010)
    tone(1900, 0.300)
    tone(1200, 0.030)
    bits = [(vis_code >> index) & 1 for index in range(7)]
    for bit in bits:
        tone(1100 if bit else 1300, 0.030)
    tone(1100 if sum(bits) % 2 else 1300, 0.030)
    tone(1200, 0.030)

    channel_values = (72, 148, 224)  # Martin transmits G, B, R.
    channel_seconds = width * pixel_seconds
    channel_starts = (
        sync_seconds + porch_seconds,
        sync_seconds + porch_seconds + channel_seconds + separator_seconds,
        sync_seconds + porch_seconds + 2 * channel_seconds + 2 * separator_seconds,
    )
    samples_per_line = round(mode_line_seconds * sample_rate)
    line_time = np.arange(samples_per_line, dtype=np.float64) / sample_rate
    for _line in range(256):
        frequencies = np.full(samples_per_line, 1500.0, dtype=np.float64)
        frequencies[line_time < sync_seconds] = 1200.0
        for value, start in zip(channel_values, channel_starts, strict=True):
            mask = (line_time >= start) & (line_time < start + channel_seconds)
            frequencies[mask] = 1500.0 + value * (800.0 / 255.0)
        pieces.append(frequencies)
    tone(1900, 0.050)
    instantaneous = np.concatenate(pieces)
    phase = np.cumsum(2.0 * math.pi * instantaneous / sample_rate)
    return (0.72 * np.sin(phase)).astype(np.float32)


def test_builtin_audio_generates_signal_visuals_and_review_artifacts(tmp_path: Path) -> None:
    source = tmp_path / "tones.wav"
    _write_dtmf_wav(source)

    result = analyze_audio(
        source,
        kind="wav",
        profile="balanced",
        enabled=True,
        spectrogram_enabled=True,
        signal_decoders=True,
        sstv_enabled=True,
        channel_exports=True,
        audacity_bundle=True,
        lsb_enabled=True,
        analysis_seconds=30,
        fft_size=1024,
        channel_mode="mix",
        lsb_bits=2,
    )

    assert result["status"] == "completed"
    assert result["metadata"]["properties"]["sample_rate"] == 8_000
    assert len(result["visuals"]) == 2
    assert result["signals"]["dtmf"]["symbols"] == "1"
    assert len(result["stego_streams"]) == 2
    assert any(item["label"] == "audacity_labels" for item in result["artifacts"])
    assert any(item["title"] == "Bytes follow the declared RIFF container" for item in result["findings"])


def test_audio_lsb_extracts_raw_payload_bytes_from_each_stereo_channel(tmp_path: Path) -> None:
    source = tmp_path / "stereo-lsb.wav"
    message = b"flag{stereo_pcm_bytes}"
    channels = 2
    sample_width = 2
    frame_count = 2_000
    raw = bytearray(frame_count * channels * sample_width)
    bits = [(byte >> shift) & 1 for byte in message for shift in range(7, -1, -1)]
    # The first channel's raw bytes are separated from the interleaved stream
    # in the analyzer; write one message bit into each of those bytes.
    for index, bit in enumerate(bits):
        frame = index // sample_width
        offset = index % sample_width
        raw[frame * channels * sample_width + offset] |= bit
    with wave.open(str(source), "wb") as target:
        target.setnchannels(channels)
        target.setsampwidth(sample_width)
        target.setframerate(8_000)
        target.writeframes(bytes(raw))

    result = analyze_audio(
        source,
        kind="wav",
        profile="balanced",
        enabled=True,
        spectrogram_enabled=False,
        signal_decoders=False,
        sstv_enabled=False,
        channel_exports=False,
        audacity_bundle=False,
        lsb_enabled=True,
        analysis_seconds=15,
        fft_size=512,
        channel_mode="mix",
        lsb_bits=1,
    )

    assert any(
        item["label"] == "audio_pcm_lsb_channel1_bit0" and message in item["data"]
        for item in result["stego_streams"]
    )


def test_engine_routes_audio_to_audio_pipeline_and_finds_raw_flag(tmp_path: Path) -> None:
    source = tmp_path / "challenge.wav"
    _write_dtmf_wav(source)

    report = AnalysisEngine().run(
        input_path=source,
        output_dir=tmp_path / "output",
        profile="quick",
        flag_prefix="flag",
        password=None,
        progress_callback=None,
        is_cancelled=lambda: False,
        options={
            "evidence_type": "audio",
            "external_tools": False,
            "audio_analysis_seconds": 30,
            "audio_spectrogram_fft": 1024,
            "audio_lsb_bits": 1,
            "max_artifacts": 45,
        },
    )

    methods = {method["id"]: method for method in report["methods"]}
    assert report["status"] == "completed"
    assert report["section"] == "audio"
    assert report["source"]["detected_type"] == "wav"
    assert methods["audio-waveform"]["status"] == "completed"
    assert methods["audio-spectrogram"]["status"] == "completed"
    assert any(candidate["value"] == "flag{audio_pipeline}" for candidate in report["candidates"])
    assert report["coverage"]["supported_audio_formats"]
    assert report["visual_views"]


def test_sstv_vis_audio_is_demodulated_into_a_png() -> None:
    sample_rate = 12_000
    samples = _synthetic_martin_m2(sample_rate)

    result = decode_sstv(samples, sample_rate, mode_name="auto", max_images=1, slant_correction=True)

    assert result["status"] == "decoded"
    assert result["images_decoded"] == 1
    assert result["decoded_modes"] == ["Martin M2"]
    assert result["headers"][0]["vis_code"] == 0x28
    assert result["headers"][0]["parity_valid"] is True
    recovered = result["images"][0]
    assert recovered["width"] == 320
    assert recovered["height"] >= 250
    with Image.open(BytesIO(recovered["data"])) as image:
        assert image.format == "PNG"
        red, green, blue = image.convert("RGB").getpixel((160, 120))
    assert red > blue > green


def test_sstv_sync_alignment_uses_leading_edge_not_interior_minimum() -> None:
    sample_rate = 12_000
    mode = MODES["robot36"]
    frequency = np.full(sample_rate * 2, np.nan, dtype=np.float32)
    amplitude = np.ones_like(frequency)
    pulse_start = round(1.004 * sample_rate)
    pulse_end = pulse_start + round(mode.sync_seconds * sample_rate)
    frequency[pulse_start:pulse_end] = 1_200.0

    aligned, quality = _align_line_sync(frequency, amplitude, sample_rate, mode, 1.0, 0.0)

    assert aligned is not None
    assert abs(aligned - pulse_start / sample_rate) <= 1 / sample_rate
    assert quality > 0.9
