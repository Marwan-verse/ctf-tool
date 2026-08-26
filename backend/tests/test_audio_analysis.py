from __future__ import annotations

import math
import struct
import wave
from pathlib import Path

from app.analyzers.audio import analyze_audio
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
