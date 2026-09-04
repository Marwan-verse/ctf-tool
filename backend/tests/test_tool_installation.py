from __future__ import annotations

import base64
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.analyzers.external import ResolvedTool
from app.schemas import ToolInstallRequest
from app import tool_installation


def test_tool_install_request_is_strict_and_deduplicated() -> None:
    request = ToolInstallRequest.model_validate(
        {"tool_ids": [" PNGCHECK ", "pngcheck"], "confirmed": True}
    )
    assert request.tool_ids == ["pngcheck"]

    with pytest.raises(ValidationError):
        ToolInstallRequest.model_validate({"tool_ids": ["pngcheck"], "confirmed": "yes"})


def test_install_uses_only_fixed_wsl_package_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    wsl = Path("C:/Windows/System32/wsl.exe")
    installed = ResolvedTool(source="wsl", launcher=wsl, executable="/usr/bin/pngcheck")
    availability = iter(({"pngcheck": None}, {"pngcheck": installed}, {"pngcheck": installed}))
    commands: list[list[str]] = []

    monkeypatch.setattr(tool_installation, "_availability", lambda _ids=None: next(availability))
    monkeypatch.setattr(tool_installation, "resolve_executable", lambda name: wsl if name == "wsl" else None)
    monkeypatch.setattr(tool_installation, "_wsl_root_available", lambda _wsl: True)

    def fake_wsl(_wsl: Path, arguments: list[str], *, timeout: int) -> dict[str, object]:
        commands.append(arguments)
        return {"status": "completed", "return_code": 0, "output": "ok", "duration_ms": 1}

    monkeypatch.setattr(tool_installation, "_run_wsl", fake_wsl)

    report = tool_installation.install_tools(["pngcheck"])

    assert report["status"] == "completed"
    assert report["installed_count"] == 1
    assert report["items"][0]["status"] == "installed"
    install_command = next(command for command in commands if "install" in command)
    assert install_command[-1] == "pngcheck"
    assert "shell" not in install_command


def test_unknown_id_never_becomes_a_command(monkeypatch: pytest.MonkeyPatch) -> None:
    availability = iter(({}, {}, {}))
    monkeypatch.setattr(tool_installation, "_availability", lambda _ids=None: next(availability))
    monkeypatch.setattr(tool_installation, "resolve_executable", lambda _name: None)

    report = tool_installation.install_tools(["not-a-real-package; whoami"])

    assert report["status"] == "failed"
    assert report["items"][0]["status"] == "unavailable"
    assert report["items"][0]["channel"] is None


def test_pinned_wsl_build_script_is_base64_transport_encoded(monkeypatch: pytest.MonkeyPatch) -> None:
    wsl = Path("C:/Windows/System32/wsl.exe")
    captured: list[str] = []

    def fake_wsl(_wsl: Path, arguments: list[str], *, timeout: int) -> dict[str, object]:
        captured.extend(arguments)
        return {"status": "completed", "return_code": 0, "output": "ok", "duration_ms": 1}

    monkeypatch.setattr(tool_installation, "_run_wsl", fake_wsl)
    script = "build_dir=$(mktemp -d)\necho $build_dir"

    tool_installation._run_wsl_script(wsl, script, timeout=30)  # noqa: SLF001 - validates shell-boundary encoding

    assert captured[:2] == ["sh", "-lc"]
    assert "$" not in captured[2]
    encoded = captured[2].split("'")[1]
    assert base64.b64decode(encoded).decode("utf-8") == script


def test_web_repair_tools_are_backed_by_fixed_wsl_packages() -> None:
    for tool_id, package in {
        "pngfix": "libpng-tools",
        "optipng": "optipng",
        "gifsicle_repair": "gifsicle",
        "zipfix": "zip",
        "zipfix_deep": "zip",
    }.items():
        assert tool_id in tool_installation.INSTALLABLE_TOOL_IDS
        assert tool_installation.WSL_APT_PACKAGES[tool_id] == (package,)
        assert tool_installation.install_strategy(tool_id) == "Kali WSL package"


def test_extended_forensics_tools_are_allowlisted_to_fixed_packages() -> None:
    expected = {
        "capinfos": "wireshark-common",
        "tshark_usb_hid": "tshark",
        "tshark_packet_details": "tshark",
        "tshark_statistics": "tshark",
        "tshark_expert": "tshark",
        "tshark_credentials": "tshark",
        "tshark_rtp": "tshark",
        "tshark_authentication": "tshark",
        "tshark_http2_ranges": "tshark",
        "tshark_ftp_objects": "tshark",
        "tshark_tftp_objects": "tshark",
        "tshark_imf_objects": "tshark",
        "tshark_dicom_objects": "tshark",
        "tcpflow": "tcpflow",
        "hcxpcapngtool": "hcxtools",
        "pcapfix": "pcapfix",
        "sqlite3": "sqlite3",
        "h5dump": "hdf5-tools",
        "h5dump_values": "hdf5-tools",
        "mdb_tables": "mdbtools",
        "mdb_schema": "mdbtools",
        "dcmdump": "dcmtk",
        "exrheader": "openexr",
        "fdtdump": "device-tree-compiler",
        "dumpimage": "u-boot-tools",
        "unsquashfs": "squashfs-tools",
        "djvudump": "djvulibre-bin",
        "djvutxt": "djvulibre-bin",
        "olevba": "oletools",
        "rtfobj": "oletools",
        "mmls": "sleuthkit",
        "tsk_recover": "sleuthkit",
        "ewfinfo": "ewf-tools",
        "reglookup": "reglookup",
        "readpst": "pst-utils",
    }
    for tool_id, package in expected.items():
        assert tool_installation.WSL_APT_PACKAGES[tool_id] == (package,)
        assert tool_id in tool_installation.INSTALLABLE_TOOL_IDS
        assert tool_installation.install_strategy(tool_id) == "Kali WSL package"

    assert tool_installation.VOLATILITY3_VERSION == "2.28.0"
    assert "volatility3==2.28.0" in tool_installation.VOLATILITY3_INSTALL_SCRIPT
    assert tool_installation.PYTHON_EVTX_VERSION == "0.8.1"
    assert "python-evtx==0.8.1" in tool_installation.PYTHON_EVTX_INSTALL_SCRIPT
    assert tool_installation.WINGET_PACKAGE_IDS["tshark"] == "WiresharkFoundation.Wireshark"
    assert tool_installation.WINGET_PACKAGE_IDS["tshark_packet_details"] == "WiresharkFoundation.Wireshark"
    assert tool_installation.WINGET_PACKAGE_IDS["tshark_http2_ranges"] == "WiresharkFoundation.Wireshark"


def test_endpoint_and_virtual_disk_tools_use_fixed_wsl_packages() -> None:
    expected = {
        "lnkinfo": "liblnk-utils",
        "sccainfo": "libscca-utils",
        "plistutil": "libplist-utils",
        "esedbinfo": "libesedb-utils",
        "qemu_img_info": "qemu-utils",
        "bulk_extractor": "bulk-extractor",
        "journalctl": "systemd",
    }
    for tool_id, package in expected.items():
        assert tool_installation.WSL_APT_PACKAGES[tool_id] == (package,)
        assert tool_id in tool_installation.INSTALLABLE_TOOL_IDS
        assert tool_installation.install_strategy(tool_id) == "Kali WSL package"


def test_shared_winget_audio_package_is_installed_once(monkeypatch: pytest.MonkeyPatch) -> None:
    tool_ids = ["ffprobe", "ffmpeg_spectrogram", "ffmpeg_pcm"]
    winget = Path("C:/Windows/System32/winget.exe")
    ffmpeg = ResolvedTool(source="native", launcher=Path("C:/tools/ffmpeg.exe"), executable="ffmpeg")
    ffprobe = ResolvedTool(source="native", launcher=Path("C:/tools/ffprobe.exe"), executable="ffprobe")
    resolved = {"ffprobe": ffprobe, "ffmpeg_spectrogram": ffmpeg, "ffmpeg_pcm": ffmpeg}
    availability = iter((dict.fromkeys(tool_ids), dict.fromkeys(tool_ids), resolved))
    installs: list[str] = []

    monkeypatch.setattr(tool_installation, "_availability", lambda _ids=None: next(availability))
    monkeypatch.setattr(tool_installation, "resolve_executable", lambda name: winget if name == "winget" else None)
    monkeypatch.setattr(
        tool_installation,
        "_run_winget_install",
        lambda _winget, package_id: installs.append(package_id)
        or {"status": "completed", "return_code": 0, "output": "ok", "duration_ms": 1},
    )

    report = tool_installation.install_tools(tool_ids)

    assert installs == ["Gyan.FFmpeg"]
    assert report["status"] == "completed"
    assert report["installed_count"] == 3
