from __future__ import annotations

import binascii
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.engine import AnalysisEngine
from app.schemas import AnalysisOptions


def test_options_forbid_unknown_fields_and_unsafe_ocr_language() -> None:
    with pytest.raises(ValidationError):
        AnalysisOptions.model_validate({"unknown_stage": True})
    with pytest.raises(ValidationError):
        AnalysisOptions.model_validate({"ocr_language": "eng; touch owned"})


def test_audio_options_enforce_bounded_duration_and_known_fft_sizes() -> None:
    with pytest.raises(ValidationError):
        AnalysisOptions.model_validate({"audio_analysis_seconds": 301})
    with pytest.raises(ValidationError):
        AnalysisOptions.model_validate({"audio_spectrogram_fft": 123})
    with pytest.raises(ValidationError):
        AnalysisOptions.model_validate({"audio_sstv_mode": "definitely-not-a-mode"})
    with pytest.raises(ValidationError):
        AnalysisOptions.model_validate({"audio_sstv_max_images": 5})

    options = AnalysisOptions.model_validate(
        {
            "evidence_type": "audio",
            "audio_analysis_seconds": 90,
            "audio_spectrogram_fft": 4096,
            "audio_channel_mode": "difference",
            "audio_lsb_bits": 4,
            "audio_sstv_mode": "robot36",
            "audio_sstv_max_images": 3,
        }
    )
    assert options.audio_analysis_seconds == 90
    assert options.audio_channel_mode == "difference"
    assert options.audio_sstv_mode == "robot36"
    assert options.audio_sstv_max_images == 3


def test_corrupted_evidence_type_is_valid_and_overrides_audio_magic(tmp_path: Path) -> None:
    options = AnalysisOptions.model_validate({"evidence_type": "corrupted"})
    assert options.evidence_type == "corrupted"

    source = tmp_path / "damaged.wav"
    source.write_bytes(b"RIFF" + (4).to_bytes(4, "little") + b"WAVE")
    report = AnalysisEngine().run(
        input_path=source,
        output_dir=tmp_path / "output",
        profile="quick",
        flag_prefix=None,
        password=None,
        progress_callback=None,
        is_cancelled=lambda: False,
        options={
            "evidence_type": "corrupted",
            "structure_analysis": False,
            "visual_analysis": False,
            "lsb_analysis": False,
            "ocr": False,
            "barcodes": False,
            "recursive_extraction": False,
            "decoders": False,
            "crypto_analysis": False,
            "repairs": False,
            "external_tools": False,
        },
    )

    method_ids = {method["id"] for method in report["methods"]}
    assert report["status"] == "completed"
    assert report["section"] == "corrupted"
    assert report["coverage"]["section"] == "corrupted"
    assert report["source"]["detected_type"] == "wav"
    assert "built-in-core" in method_ids
    assert "audio-waveform" not in method_ids


def test_corrupted_deep_scan_creates_copy_only_png_repair(malformed_png: Path, tmp_path: Path) -> None:
    source_bytes = malformed_png.read_bytes()
    output_dir = tmp_path / "output"

    report = AnalysisEngine().run(
        input_path=malformed_png,
        output_dir=output_dir,
        profile="deep",
        flag_prefix=None,
        password=None,
        progress_callback=None,
        is_cancelled=lambda: False,
        options={
            "evidence_type": "corrupted",
            "visual_analysis": False,
            "lsb_analysis": False,
            "ocr": False,
            "barcodes": False,
            "recursive_extraction": False,
            "decoders": False,
            "crypto_analysis": False,
            "external_tools": False,
        },
    )

    repair_artifacts = [artifact for artifact in report["artifacts"] if artifact["repair_candidate"]]
    assert report["status"] == "completed"
    assert report["section"] == "corrupted"
    assert report["coverage"]["section"] == "corrupted"
    assert report["coverage"]["original_mutated"] is False
    assert len(repair_artifacts) == 1
    assert (output_dir / repair_artifacts[0]["relative_path"]).read_bytes() != source_bytes
    assert malformed_png.read_bytes() == source_bytes


def test_engine_replays_recovered_png_for_pixel_analysis(clean_png: Path, tmp_path: Path) -> None:
    source = tmp_path / "headerless-image.bin"
    damaged = bytearray(clean_png.read_bytes())
    damaged[:8] = b"\x89PB\x11\r\n\x1a\n"
    damaged[8:12] = b"\x00\x12\x13\x14"
    source.write_bytes(bytes(damaged))

    report = AnalysisEngine().run(
        input_path=source,
        output_dir=tmp_path / "output",
        profile="quick",
        flag_prefix=None,
        password=None,
        progress_callback=None,
        is_cancelled=lambda: False,
        options={
            "evidence_type": "corrupted",
            "external_tools": False,
            "lsb_analysis": False,
            "ocr": False,
            "barcodes": False,
            "recursive_extraction": False,
            "decoders": False,
            "crypto_analysis": False,
        },
    )

    structure = next(method for method in report["methods"] if method["id"] == "built-in-structure")
    repairs = [artifact for artifact in report["artifacts"] if artifact["repair_candidate"]]
    assert report["status"] == "completed"
    assert report["source"]["detected_type"] == "binary"
    assert structure["details"]["analyzed_type"] == "png"
    assert structure["details"]["header_recovery_used"] is True
    assert repairs and repairs[0]["detected_type"] == "png"
    assert report["visual_views"]
    assert source.read_bytes() == bytes(damaged)


def test_engine_persists_uncrop_dimensions_and_preserves_source(clean_png: Path, tmp_path: Path) -> None:
    source = tmp_path / "hidden-rows.png"
    hidden = bytearray(clean_png.read_bytes())
    original_width = int.from_bytes(hidden[16:20], "big")
    original_height = int.from_bytes(hidden[20:24], "big")
    ihdr = bytearray(hidden[16:29])
    ihdr[4:8] = (1).to_bytes(4, "big")
    hidden[16:29] = ihdr
    hidden[29:33] = (binascii.crc32(b"IHDR" + ihdr) & 0xFFFFFFFF).to_bytes(4, "big")
    source.write_bytes(bytes(hidden))

    report = AnalysisEngine().run(
        input_path=source,
        output_dir=tmp_path / "output",
        profile="quick",
        flag_prefix=None,
        password=None,
        progress_callback=None,
        is_cancelled=lambda: False,
        options={
            "external_tools": False,
            "lsb_analysis": False,
            "ocr": False,
            "barcodes": False,
            "recursive_extraction": False,
            "decoders": False,
            "crypto_analysis": False,
        },
    )

    [repair] = [artifact for artifact in report["artifacts"] if artifact.get("name") == "png_hidden_scanlines_uncropped"]
    parameters = repair["lineage"][0]["parameters"]
    assert repair["repair_candidate"] is True
    assert parameters["recovered_width"] == original_width
    assert parameters["recovered_height"] == original_height
    assert parameters["unknown_pixels_filled"] is False
    assert source.read_bytes() == bytes(hidden)


def test_engine_honors_disabled_stages_and_custom_budgets(clean_png: Path, tmp_path: Path) -> None:
    report = AnalysisEngine().run(
        input_path=clean_png,
        output_dir=tmp_path / "output",
        profile="quick",
        flag_prefix="flag",
        password=None,
        progress_callback=None,
        is_cancelled=lambda: False,
        options={
            "structure_analysis": False,
            "visual_analysis": False,
            "recursive_extraction": False,
            "decoders": False,
            "crypto_analysis": False,
            "external_tools": False,
            "repairs": False,
            "max_recursion_depth": 1,
            "max_artifacts": 25,
            "tool_timeout_seconds": 5,
        },
    )

    methods = {method["id"]: method for method in report["methods"]}
    assert report["status"] == "completed"
    assert methods["built-in-structure"]["status"] == "skipped"
    assert methods["recursive-analysis"]["status"] == "skipped"
    assert methods["pillow-visual"]["status"] == "skipped"
    assert methods["pcrt"]["status"] == "skipped"
    assert methods["decomposer"]["status"] == "skipped"
    assert methods["color_remapping"]["status"] == "skipped"
    assert methods["spectrogram"]["status"] == "skipped"
    assert methods["bounded-decoder"]["status"] == "skipped"
    assert methods["crypto-analysis"]["status"] == "skipped"
    assert all(methods[spec_id]["status"] == "skipped" for spec_id in report["coverage"]["optional_tools_declared"])
    assert report["coverage"]["limits"]["recursion_depth"] == 1
    assert report["coverage"]["limits"]["max_artifacts"] == 25
    assert report["coverage"]["limits"]["tool_timeout_seconds"] == 5
