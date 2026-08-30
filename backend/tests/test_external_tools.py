from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

from app.analyzers.external import ExternalToolRunner, ResolvedTool, TOOL_SPECS, resolve_executable


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


def test_tool_resolution_can_use_a_path_added_after_process_start(monkeypatch, tmp_path: Path) -> None:
    executable = tmp_path / ("late-tool.exe" if os.name == "nt" else "late-tool")
    executable.write_bytes(b"placeholder")
    calls: list[tuple[str, str | None]] = []

    def fake_which(name: str, path: str | None = None) -> str | None:
        calls.append((name, path))
        return str(executable) if path and str(tmp_path) in path else None

    monkeypatch.setattr("app.analyzers.external.shutil.which", fake_which)
    monkeypatch.setenv("PATH", str(tmp_path))

    assert resolve_executable("late-tool") == executable
    assert len(calls) >= 2
    assert calls[-1][1] is not None


def test_tool_resolution_checks_standard_windows_install_folders(monkeypatch, tmp_path: Path) -> None:
    if os.name != "nt":
        pytest.skip("Windows install-folder probing is platform-specific")
    install_root = tmp_path / "Program Files"
    tool_dir = install_root / "7-Zip"
    tool_dir.mkdir(parents=True)
    executable = tool_dir / ("7z.exe" if os.name == "nt" else "7z")
    executable.write_bytes(b"placeholder")

    monkeypatch.setenv("ProgramW6432", str(install_root))
    monkeypatch.setenv("PROGRAMFILES", str(install_root))
    monkeypatch.setenv("ProgramFiles(x86)", str(tmp_path / "Program Files (x86)"))
    monkeypatch.setattr("app.analyzers.external.shutil.which", lambda _name, path=None: str(executable) if path and str(tool_dir) in path else None)

    assert resolve_executable("7z") == executable


def test_pre_requested_cancellation_never_launches_an_external_tool(clean_png: Path, tmp_path: Path) -> None:
    runner = ExternalToolRunner(timeout=1, is_cancelled=lambda: True)

    methods = runner.run_all(clean_png, kind="png", profile="deep", password=None, work_dir=tmp_path)

    assert methods
    assert all(method["status"] == "cancelled" and method["command"] == [] for method in methods)


def test_tool_selection_is_recorded_as_skipped_without_lookup(monkeypatch, clean_png: Path, tmp_path: Path) -> None:
    looked_up: list[str] = []
    monkeypatch.setattr(shutil, "which", lambda name: looked_up.append(name) or None)
    runner = ExternalToolRunner(timeout=1)

    methods = runner.run_all(
        clean_png,
        kind="png",
        profile="deep",
        password=None,
        work_dir=tmp_path,
        selected_tools=set(),
    )

    assert looked_up == []
    assert all(method["status"] == "skipped" for method in methods)
    assert all("settings" in method["summary"] for method in methods)


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


def test_wsl_embedded_output_paths_are_translated_without_a_shell() -> None:
    resolution = ResolvedTool(source="wsl", launcher=Path("C:/Windows/System32/wsl.exe"), executable="/usr/bin/7z")

    argv = ExternalToolRunner._launch_argv(  # noqa: SLF001 - process-boundary contract
        resolution,
        ["e", "-oC:\\case output", "http,C:\\http output", "C:\\input\\capture.pcap"],
    )

    assert argv == [
        "C:\\Windows\\System32\\wsl.exe", "--", "/usr/bin/7z", "e",
        "-o/mnt/c/case output", "http,/mnt/c/http output", "/mnt/c/input/capture.pcap",
    ]


def test_tshark_field_adapters_avoid_shell_metacharacter_separator(monkeypatch, tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    invocations: list[list[str]] = []

    monkeypatch.setattr(
        "app.analyzers.external.resolve_tool",
        lambda executable, **_kwargs: ResolvedTool(
            source="native", launcher=Path(sys.executable), executable=executable
        ),
    )
    runner = ExternalToolRunner(timeout=1)

    def fake_execute(argv, *, cwd, timeout=None, stdin_data=None):
        invocations.append(list(argv))
        return {
            "status": "completed", "return_code": 0, "stdout": "", "stderr": "",
            "output_truncated": False,
        }

    monkeypatch.setattr(runner, "_execute", fake_execute)
    runner.run_all(
        capture,
        kind="pcap",
        profile="deep",
        password=None,
        work_dir=tmp_path,
        selected_tools={"tshark_fields", "tshark_usb_hid"},
    )

    assert len(invocations) == 2
    assert all("separator=/t" in argv for argv in invocations)
    assert all(not any("|" in argument for argument in argv) for argv in invocations)


def test_tshark_usb_mouse_reports_render_an_svg_artifact() -> None:
    output = "\n".join(f"1.5.1\t01{index % 4:02x}{(index * 3) % 8:02x}" for index in range(16))

    drawings = ExternalToolRunner._decode_usb_mouse_svg(output)  # noqa: SLF001 - bounded decoder contract

    assert drawings
    assert drawings[0][0].endswith(".svg")
    assert drawings[0][1].startswith(b"<svg")


def test_tshark_traffic_workspace_adapters_use_fixed_bounded_arguments(monkeypatch, tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 24)
    invocations: list[list[str]] = []

    monkeypatch.setattr(
        "app.analyzers.external.resolve_tool",
        lambda executable, **_kwargs: ResolvedTool(
            source="native", launcher=Path(sys.executable), executable=executable
        ),
    )
    runner = ExternalToolRunner(timeout=1)

    def fake_execute(argv, *, cwd, timeout=None, stdin_data=None):
        invocations.append(list(argv))
        return {
            "status": "completed", "return_code": 0, "stdout": "", "stderr": "",
            "output_truncated": False,
        }

    monkeypatch.setattr(runner, "_execute", fake_execute)
    selected = {
        "tshark_packet_details", "tshark_statistics", "tshark_expert",
        "tshark_credentials", "tshark_rtp", "tshark_authentication", "tshark_ftp_objects",
    }
    runner.run_all(
        capture,
        kind="pcapng",
        profile="deep",
        password=None,
        work_dir=tmp_path,
        selected_tools=selected,
    )

    main_calls = [argv for argv in invocations if "-r" in argv]
    assert len(main_calls) == len(selected)
    packet_details = next(argv for argv in main_calls if "json" in argv)
    assert packet_details[packet_details.index("-c") + 1] == "2000"
    assert "--json-compact" in packet_details and "-x" in packet_details
    statistics = next(argv for argv in main_calls if "io,phs" in argv)
    assert "conv,tcp" in statistics and "endpoints,udp" in statistics
    assert any("expert" in argv for argv in main_calls)
    assert any("credentials" in argv for argv in main_calls)
    assert any("rtp,streams" in argv for argv in main_calls)
    assert any("ntlmssp kerberos ldap http smb smb2" in argv for argv in main_calls)
    assert any("ftp-data," in argument for argv in main_calls for argument in argv)


def test_zsteg_mode_uses_explicit_all_or_lsb_switch(monkeypatch, clean_png: Path, tmp_path: Path) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: sys.executable if name == "zsteg" else None)
    runner = ExternalToolRunner(timeout=1)

    def fake_execute(argv, *, cwd, timeout=None, stdin_data=None):
        return {"status": "completed", "return_code": 0, "stdout": "zsteg output", "stderr": "", "output_truncated": False}

    monkeypatch.setattr(runner, "_execute", fake_execute)
    all_result = runner.run_all(
        clean_png, kind="png", profile="deep", password=None, work_dir=tmp_path,
        selected_tools={"zsteg"}, zsteg_mode="all",
    )
    lsb_result = runner.run_all(
        clean_png, kind="png", profile="deep", password=None, work_dir=tmp_path,
        selected_tools={"zsteg"}, zsteg_mode="lsb",
    )

    assert next(method for method in all_result if method["id"] == "zsteg")["command"][1] == "-a"
    assert next(method for method in lsb_result if method["id"] == "zsteg")["command"][1] == "--lsb"


def test_wsl_tools_run_from_stable_job_directory(monkeypatch, clean_png: Path, tmp_path: Path) -> None:
    """Do not leave WSL holding the disposable per-tool output directory."""

    def fake_resolve(executable: str, **_kwargs: object) -> ResolvedTool | None:
        if executable == "pngcheck":
            return ResolvedTool(source="wsl", launcher=Path("C:/Windows/System32/wsl.exe"), executable="/usr/bin/pngcheck")
        return None

    monkeypatch.setattr("app.analyzers.external.resolve_tool", fake_resolve)
    runner = ExternalToolRunner(timeout=1)
    working_directories: list[Path] = []

    def fake_execute(argv, *, cwd, timeout=None, stdin_data=None):
        working_directories.append(cwd)
        return {"status": "completed", "return_code": 0, "stdout": "pngcheck 3.0", "stderr": "", "output_truncated": False}

    monkeypatch.setattr(runner, "_execute", fake_execute)
    methods = runner.run_all(
        clean_png,
        kind="png",
        profile="quick",
        password=None,
        work_dir=tmp_path,
        selected_tools={"pngcheck"},
    )

    result = next(method for method in methods if method["id"] == "pngcheck")
    assert result["status"] == "completed"
    assert working_directories and all(directory == tmp_path for directory in working_directories)


def test_web_repair_tools_use_fixed_output_paths_and_emit_derived_artifacts(
    monkeypatch, clean_png: Path, tmp_path: Path
) -> None:
    def fake_resolve(executable: str, **_kwargs: object) -> ResolvedTool:
        return ResolvedTool(source="native", launcher=Path(sys.executable), executable=executable)

    monkeypatch.setattr("app.analyzers.external.resolve_tool", fake_resolve)
    runner = ExternalToolRunner(timeout=1)
    invocations: list[list[str]] = []

    def fake_execute(argv, *, cwd, timeout=None, stdin_data=None):
        invocations.append(list(argv))
        if any(flag in argv for flag in ("--version", "-version")):
            return {"status": "completed", "return_code": 0, "stdout": "repair-tool 1", "stderr": "", "output_truncated": False}
        if "--out" in argv:
            output_path = Path(argv[argv.index("--out") + 1])
        elif any(argument.startswith("--out=") for argument in argv):
            output_path = Path(next(argument.split("=", 1)[1] for argument in argv if argument.startswith("--out=")))
        else:
            output_path = Path(argv[argv.index("-out") + 1])
        output_path.write_bytes(clean_png.read_bytes())
        return {"status": "completed", "return_code": 0, "stdout": "rewritten", "stderr": "", "output_truncated": False}

    monkeypatch.setattr(runner, "_execute", fake_execute)
    for tool_id in ("pngfix", "optipng"):
        result = next(
            method
            for method in runner.run_all(
                clean_png,
                kind="png",
                profile="deep",
                password=None,
                work_dir=tmp_path,
                selected_tools={tool_id},
            )
            if method["id"] == tool_id
        )
        assert result["status"] == "completed"
        assert result["extracted"]
        assert result["extracted"][0]["producer"] == tool_id
        assert result["extracted"][0]["kind"] == "png"

    assert any(any(argument.startswith("--out=") for argument in argv) for argv in invocations)
    assert any("-out" in argv for argv in invocations)


def test_tool_output_scrubs_supplied_password(tmp_path: Path) -> None:
    scrubbed = ExternalToolRunner._sanitize(  # noqa: SLF001 - output redaction contract
        "tool echoed super-secret-passphrase", tmp_path / "input.jpg", tmp_path / "private", "super-secret-passphrase"
    )
    assert "super-secret-passphrase" not in scrubbed
    assert "<redacted>" in scrubbed


def test_7zip_non_archive_is_a_clean_negative_result() -> None:
    status, summary = ExternalToolRunner._normalize_outcome(  # noqa: SLF001 - outcome contract
        "7z",
        "completed",
        2,
        "",
        "ERROR: source.upload : Cannot open the file as archive",
    )

    assert status == "no_findings"
    assert summary == "Input is not an archive; no embedded archive was listed."


def test_unexpected_nonzero_exit_remains_failed() -> None:
    status, summary = ExternalToolRunner._normalize_outcome(  # noqa: SLF001 - outcome contract
        "7z", "completed", 2, "", "Access is denied"
    )

    assert status == "failed"
    assert summary is None


def test_zbar_no_symbol_exit_is_presented_as_no_findings(
    monkeypatch, clean_png: Path, tmp_path: Path
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: sys.executable if name == "zbarimg" else None)
    runner = ExternalToolRunner(timeout=1)

    def fake_execute(argv, *, cwd, timeout=None, stdin_data=None):
        if "--version" in argv:
            return {"status": "completed", "return_code": 0, "stdout": "zbar 0.23", "stderr": "", "output_truncated": False}
        return {"status": "completed", "return_code": 4, "stdout": "", "stderr": "", "output_truncated": False}

    monkeypatch.setattr(runner, "_execute", fake_execute)
    methods = runner.run_all(
        clean_png,
        kind="png",
        profile="deep",
        password=None,
        work_dir=tmp_path,
        selected_tools={"zbarimg"},
    )
    result = next(method for method in methods if method["id"] == "zbarimg")

    assert result["status"] == "no_findings"
    assert result["return_code"] == 4
    assert result["summary"] == "No barcode or QR symbol was detected."


def test_foremost_depth_recurses_over_recovered_files(
    monkeypatch, clean_png: Path, tmp_path: Path
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: sys.executable if name == "foremost" else None)
    runner = ExternalToolRunner(timeout=5)
    invocations: list[list[str]] = []

    def fake_execute(argv, *, cwd, timeout=None, stdin_data=None):
        invocations.append(list(argv))
        if "-V" in argv:
            return {"status": "completed", "return_code": 0, "stdout": "foremost 1.5.7", "stderr": "", "output_truncated": False}
        output_index = argv.index("-o") + 1
        output_dir = Path(argv[output_index])
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "payload.bin").write_bytes(b"PK\\x03\\x04nested")
        return {"status": "completed", "return_code": 0, "stdout": "recovered", "stderr": "", "output_truncated": False}

    monkeypatch.setattr(runner, "_execute", fake_execute)
    methods = runner.run_all(
        clean_png,
        kind="png",
        profile="balanced",
        password=None,
        work_dir=tmp_path,
        selected_tools={"foremost"},
        max_extracted_files=5,
        foremost_depth=3,
    )
    result = next(method for method in methods if method["id"] == "foremost")

    assert result["status"] == "completed"
    assert result["details"]["configured_depth"] == 3
    assert result["details"]["depth_reached"] == 3
    assert result["details"]["inputs_scanned"] == 3
    assert result["extracted_count"] == 3
    assert len([argv for argv in invocations if "-o" in argv]) == 3


def test_steghide_automatically_tries_empty_passphrase(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: sys.executable if name == "steghide" else None)
    runner = ExternalToolRunner(timeout=1)
    launched: list[list[str]] = []

    def fake_execute(argv, *, cwd, timeout=None, stdin_data=None):
        launched.append(list(argv))
        if "--version" in argv:
            return {"status": "completed", "return_code": 0, "stdout": "steghide 0.5.1", "stderr": "", "output_truncated": False}
        output_path = Path(argv[argv.index("-xf") + 1])
        output_path.write_bytes(b"ZeroDays{synthetic_empty_passphrase_test}")
        return {"status": "completed", "return_code": 0, "stdout": "embedded file extracted", "stderr": "", "output_truncated": False}

    monkeypatch.setattr(runner, "_execute", fake_execute)

    methods = runner.run_all(
        tmp_path / "input.jpg",
        kind="jpeg",
        profile="deep",
        password=None,
        work_dir=tmp_path,
        selected_tools={"steghide"},
    )
    result = next(method for method in methods if method["id"] == "steghide")

    assert result["status"] == "completed"
    assert result["details"]["passphrase_strategy"] == "automatic_empty"
    assert result["extracted"][0]["data"] == b"ZeroDays{synthetic_empty_passphrase_test}"
    extraction = next(argv for argv in launched if "extract" in argv)
    assert extraction[extraction.index("-p") + 1] == ""
    assert "<redacted>" in result["command"]


def test_steghide_resolution_checks_managed_tools_directory(monkeypatch, tmp_path: Path) -> None:
    tool_dir = tmp_path / "steghide" / "bin"
    tool_dir.mkdir(parents=True)
    executable = tool_dir / ("steghide.exe" if os.name == "nt" else "steghide")
    executable.write_bytes(b"placeholder")

    monkeypatch.setenv("FORENSCOPE_TOOLS_DIR", str(tmp_path))
    monkeypatch.setattr(
        "app.analyzers.external.shutil.which",
        lambda name, path=None: str(executable) if name == "steghide" and path and str(tool_dir) in path else None,
    )

    assert resolve_executable("steghide") == executable


def test_steghide_extracts_payload_and_redacts_passphrase(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(shutil, "which", lambda name: sys.executable if name == "steghide" else None)
    runner = ExternalToolRunner(timeout=1)
    launched: list[list[str]] = []

    def fake_execute(argv, *, cwd, timeout=None, stdin_data=None):
        launched.append(list(argv))
        if "--version" in argv:
            return {"status": "completed", "return_code": 0, "stdout": "steghide 0.5.1", "stderr": "", "output_truncated": False}
        output_path = Path(argv[argv.index("-xf") + 1])
        output_path.write_bytes(b"flag{steghide_payload}")
        return {"status": "completed", "return_code": 0, "stdout": "embedded file extracted", "stderr": "", "output_truncated": False}

    monkeypatch.setattr(runner, "_execute", fake_execute)
    methods = runner.run_all(
        tmp_path / "input.jpg",
        kind="jpeg",
        profile="deep",
        password="correct horse battery staple",
        work_dir=tmp_path,
        selected_tools={"steghide"},
    )
    result = next(method for method in methods if method["id"] == "steghide")

    assert result["status"] == "completed"
    assert result["extracted"][0]["data"] == b"flag{steghide_payload}"
    assert "correct horse battery staple" not in " ".join(result["command"])
    assert "<redacted>" in result["command"]
    assert any("extract" in invocation for invocation in launched)
