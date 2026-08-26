from __future__ import annotations

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
