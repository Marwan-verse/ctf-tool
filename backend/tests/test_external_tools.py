from __future__ import annotations

import shutil
import sys
from pathlib import Path

from app.analyzers.external import ExternalToolRunner, TOOL_SPECS


def test_missing_optional_tools_are_reported_without_failing(
    monkeypatch,
    clean_png: Path,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    runner = ExternalToolRunner(timeout=1)

    methods = runner.run_all(clean_png, kind="png", profile="quick", password=None, work_dir=tmp_path)

    assert len(methods) == len(TOOL_SPECS)
    assert all(method["status"] in {"missing", "skipped"} for method in methods)
    assert {method["id"] for method in methods} == {spec.tool_id for spec in TOOL_SPECS}


def test_pre_requested_cancellation_never_launches_an_external_tool(clean_png: Path, tmp_path: Path) -> None:
    runner = ExternalToolRunner(timeout=1, is_cancelled=lambda: True)

    methods = runner.run_all(clean_png, kind="png", profile="deep", password=None, work_dir=tmp_path)

    assert methods
    assert all(method["status"] == "cancelled" and method["command"] == [] for method in methods)


def test_external_output_is_hard_limited(tmp_path: Path) -> None:
    runner = ExternalToolRunner(timeout=5, output_limit=64 * 1024)

    result = runner._execute(  # noqa: SLF001 - focused process-boundary test
        [sys.executable, "-c", "import sys; sys.stdout.write('A' * 200000)"],
        cwd=tmp_path,
    )

    assert result["output_truncated"] is True
    assert len(result["stdout"].encode()) <= 64 * 1024


def test_password_and_private_paths_are_redacted_from_audit_command(tmp_path: Path) -> None:
    input_path = tmp_path / "--hostile image.jpg"
    temp_dir = tmp_path / "private-output"
    password = "super-secret-passphrase"
    argv = ["stegseek", "--extract", str(input_path), str(temp_dir / "payload"), "-p", password]

    public = ExternalToolRunner._redacted_argv(  # noqa: SLF001 - redaction is a security contract
        "stegseek", argv, password, input_path, temp_dir
    )

    rendered = " ".join(public)
    assert password not in rendered
    assert str(tmp_path) not in rendered
    assert "<redacted>" in public
    assert "<input>/--hostile image.jpg" in public
