"""Allowlisted, non-interactive installation of optional forensic tools.

The browser may select only declared tool IDs. Package names, repositories,
commands, and build scripts are fixed in this module and never come from the
request body.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .analyzers.external import TOOL_SPECS, discover_wsl_tools, resolve_executable, resolve_tool, tool_environment


WSL_APT_PACKAGES: dict[str, tuple[str, ...]] = {
    "file": ("file",),
    "exiftool": ("libimage-exiftool-perl",),
    "exiv2": ("exiv2",),
    "strings": ("binutils",),
    "identify": ("imagemagick",),
    "pngcheck": ("pngcheck",),
    "pngcrush": ("pngcrush",),
    "jpeginfo": ("jpeginfo",),
    "jpegtran": ("libjpeg-turbo-progs",),
    "djpeg": ("libjpeg-turbo-progs",),
    "stegseek": ("stegseek",),
    "steghide": ("steghide",),
    "outguess": ("outguess",),
    "binwalk": ("binwalk",),
    "foremost": ("foremost",),
    "7z": ("7zip",),
    "tiffinfo": ("libtiff-tools",),
    "tiffdump": ("libtiff-tools",),
    "webpinfo": ("webp",),
    "webpmux": ("webp",),
    "gifsicle": ("gifsicle",),
    "tesseract": ("tesseract-ocr",),
    "zbarimg": ("zbar-tools",),
    "ffprobe": ("ffmpeg",),
    "ffmpeg_spectrogram": ("ffmpeg",),
    "ffmpeg_pcm": ("ffmpeg",),
    "sox_stats": ("sox", "libsox-fmt-all"),
    "sox_spectrogram": ("sox", "libsox-fmt-all"),
    "mediainfo": ("mediainfo",),
    "multimon_ng": ("multimon-ng",),
    "minimodem": ("minimodem",),
}

# These identifiers are fixed package-manager coordinates. No package name or
# URL supplied by the frontend is ever passed to WinGet.
WINGET_PACKAGE_IDS: dict[str, str] = {
    "file": "Git.Git",
    "exiftool": "OliverBetz.ExifTool",
    "exiv2": "Exiv2.Exiv2",
    "strings": "Microsoft.Sysinternals.Suite",
    "identify": "ImageMagick.ImageMagick",
    "openstego": "syvaidya.openstego",
    "7z": "7zip.7zip",
    "tesseract": "tesseract-ocr.tesseract",
    "ffprobe": "Gyan.FFmpeg",
    "ffmpeg_spectrogram": "Gyan.FFmpeg",
    "ffmpeg_pcm": "Gyan.FFmpeg",
    "sox_stats": "ChrisBagwell.SoX",
    "sox_spectrogram": "ChrisBagwell.SoX",
    "mediainfo": "MediaArea.MediaInfo",
}

SPECIAL_WSL_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "zsteg": ("ruby", "ruby-dev", "build-essential"),
    "jsteg": ("golang-go",),
    "jpseek": ("git", "build-essential", "autoconf"),
}

JSTEG_MODULE = "lukechampine.com/jsteg/cmd/jsteg@v1.1.0"
ZSTEG_VERSION = "0.2.14"
JPSEEK_COMMIT = "33a11e1bad146f5e9c0d3fe6475812a1cedb9b7e"
JPSEEK_BUILD_SCRIPT = rf"""
set -eu
build_dir="$(mktemp -d /tmp/forenscope-jphs.XXXXXX)"
cleanup() {{ rm -rf -- "$build_dir"; }}
trap cleanup EXIT
git clone --quiet https://github.com/h3xx/jphs.git "$build_dir"
cd "$build_dir"
git checkout --quiet {JPSEEK_COMMIT}
cd jpeg-8a
./configure >/dev/null
make -s
cd ..
sed -i 's/open(seekfilename,O_WRONLY|O_TRUNC|O_CREAT)/open(seekfilename,O_WRONLY|O_TRUNC|O_CREAT, 0644)/' jpseek.c
sed -i 's/^LIBS = .*/JPEG_OBJS = $(filter-out jpeg-8a\/cjpeg.o jpeg-8a\/djpeg.o jpeg-8a\/jpegtran.o jpeg-8a\/rdjpgcom.o jpeg-8a\/wrjpgcom.o,$(wildcard jpeg-8a\/*.o))/' Makefile
sed -i 's/^LDFLAGS = .*/LDFLAGS =/' Makefile
sed -i 's/^jphide: \(.*\)$/jphide: \1 $(JPEG_OBJS)/' Makefile
sed -i 's/^jpseek: \(.*\)$/jpseek: \1 $(JPEG_OBJS)/' Makefile
make -s all
install -m 0755 jpseek /usr/local/bin/jpseek
""".strip()

INSTALLABLE_TOOL_IDS = frozenset(
    {*WSL_APT_PACKAGES, *WINGET_PACKAGE_IDS, *SPECIAL_WSL_DEPENDENCIES}
)


def install_strategy(tool_id: str) -> str | None:
    """Describe the preferred unattended installation channel."""

    if tool_id in WSL_APT_PACKAGES:
        return "Kali WSL package"
    if tool_id in SPECIAL_WSL_DEPENDENCIES:
        return "Kali WSL managed build"
    if tool_id in WINGET_PACKAGE_IDS:
        return "Windows Package Manager"
    return None


def _terminate_tree(process: subprocess.Popen[Any]) -> None:
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                check=False,
                timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        return
    try:
        process.terminate()
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
        except OSError:
            pass


def _run_process(argv: list[str], *, timeout: int) -> dict[str, Any]:
    """Run one fixed installer command with bounded time and captured output."""

    output_limit = 64 * 1024
    started = time.monotonic()
    with tempfile.TemporaryFile(mode="w+b") as output_file:
        kwargs: dict[str, Any] = {
            "args": argv,
            "stdin": subprocess.DEVNULL,
            "stdout": output_file,
            "stderr": subprocess.STDOUT,
            "shell": False,
            "close_fds": True,
            "env": tool_environment(),
        }
        if os.name == "nt":
            kwargs["creationflags"] = (
                getattr(subprocess, "CREATE_NO_WINDOW", 0)
                | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            )
        try:
            process = subprocess.Popen(**kwargs)
        except OSError as exc:
            return {
                "status": "failed",
                "return_code": None,
                "output": f"{type(exc).__name__}: {str(exc)[:500]}",
                "duration_ms": int((time.monotonic() - started) * 1000),
            }
        status = "completed"
        try:
            process.wait(timeout=max(1, timeout))
        except subprocess.TimeoutExpired:
            status = "timed_out"
            _terminate_tree(process)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        output_file.seek(0)
        output = output_file.read(output_limit + 1).decode("utf-8", "replace")
        if len(output) > output_limit:
            output = output[:output_limit] + "\n… output truncated"
        if status == "completed" and process.returncode != 0:
            status = "failed"
        return {
            "status": status,
            "return_code": process.returncode,
            "output": output.strip(),
            "duration_ms": int((time.monotonic() - started) * 1000),
        }


def _wsl_root_available(wsl: Path) -> bool:
    result = _run_process([str(wsl), "-u", "root", "--", "id", "-u"], timeout=180)
    return result["status"] == "completed" and result["output"].strip().splitlines()[-1:] == ["0"]


def _run_wsl(wsl: Path, arguments: list[str], *, timeout: int) -> dict[str, Any]:
    return _run_process([str(wsl), "-u", "root", "--", *arguments], timeout=timeout)


def _run_winget_install(winget: Path, package_id: str) -> dict[str, Any]:
    return _run_process(
        [
            str(winget),
            "install",
            "--id",
            package_id,
            "--exact",
            "--source",
            "winget",
            "--silent",
            "--accept-source-agreements",
            "--accept-package-agreements",
            "--disable-interactivity",
        ],
        timeout=900,
    )


def _availability(tool_ids: list[str] | None = None) -> dict[str, Any]:
    selected = set(tool_ids) if tool_ids is not None else None
    specs = [spec for spec in TOOL_SPECS if selected is None or spec.tool_id in selected]
    availability = {spec.tool_id: resolve_tool(spec.executable, wsl_tools={}) for spec in specs}
    missing_specs = [spec for spec in specs if availability[spec.tool_id] is None]
    if missing_specs:
        wsl_tools = discover_wsl_tools(tuple(spec.executable for spec in missing_specs))
        for spec in missing_specs:
            availability[spec.tool_id] = resolve_tool(spec.executable, wsl_tools=wsl_tools)
    return availability


def _diagnostic(results: list[dict[str, Any]]) -> str | None:
    failed = [result for result in results if result.get("status") != "completed"]
    if not failed:
        return None
    output = str(failed[-1].get("output") or "The package manager did not complete successfully.")
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return "\n".join(lines[-8:])[-2000:]


def install_tools(tool_ids: list[str]) -> dict[str, Any]:
    """Install requested tools from fixed package sources and re-detect them."""

    requested = list(dict.fromkeys(tool_ids))
    before = _availability(requested)
    missing = [tool_id for tool_id in requested if before.get(tool_id) is None]
    if not missing:
        items = [
            {
                "id": tool_id,
                "status": "already_available",
                "channel": None,
                "source": before[tool_id].source,
                "resolved": before[tool_id].display,
                "message": f"Already available through {before[tool_id].source}.",
                "diagnostic": None,
            }
            for tool_id in requested
        ]
        return {
            "status": "completed",
            "message": "Every requested forensic tool is installed and detected.",
            "installed_count": 0,
            "already_available_count": len(items),
            "available_count": len(items),
            "requested_count": len(items),
            "unresolved_count": 0,
            "managers": [],
            "items": items,
        }
    command_results: dict[str, list[dict[str, Any]]] = {tool_id: [] for tool_id in requested}
    channels: dict[str, str] = {}

    wsl = resolve_executable("wsl")
    wsl_ready = bool(wsl and _wsl_root_available(wsl))
    if wsl and wsl_ready:
        apt_packages: set[str] = set()
        apt_targets: list[str] = []
        for tool_id in missing:
            packages = WSL_APT_PACKAGES.get(tool_id) or SPECIAL_WSL_DEPENDENCIES.get(tool_id)
            if packages:
                apt_packages.update(packages)
                apt_targets.append(tool_id)
                channels[tool_id] = "Kali WSL"
        if apt_packages:
            update = _run_wsl(
                wsl,
                ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "update"],
                timeout=300,
            )
            for tool_id in apt_targets:
                command_results[tool_id].append(update)
            if update["status"] == "completed":
                install = _run_wsl(
                    wsl,
                    [
                        "env",
                        "DEBIAN_FRONTEND=noninteractive",
                        "apt-get",
                        "install",
                        "-y",
                        "--no-install-recommends",
                        *sorted(apt_packages),
                    ],
                    timeout=900,
                )
                for tool_id in apt_targets:
                    command_results[tool_id].append(install)

        if "zsteg" in missing:
            result = _run_wsl(
                wsl,
                ["gem", "install", "--no-document", "zsteg", "-v", ZSTEG_VERSION],
                timeout=600,
            )
            command_results["zsteg"].append(result)
            channels["zsteg"] = "Kali WSL / RubyGems"
        if "jsteg" in missing:
            result = _run_wsl(
                wsl,
                ["env", "GOBIN=/usr/local/bin", "go", "install", JSTEG_MODULE],
                timeout=600,
            )
            command_results["jsteg"].append(result)
            channels["jsteg"] = "Kali WSL / Go module"
        if "jpseek" in missing:
            result = _run_wsl(wsl, ["sh", "-lc", JPSEEK_BUILD_SCRIPT], timeout=900)
            command_results["jpseek"].append(result)
            channels["jpseek"] = "Kali WSL / pinned source build"

    # Prefer WSL for its maintained forensic packages. Use a silent native
    # install only for tools still unavailable and mapped to a fixed ID.
    after_wsl = _availability(requested)
    winget = resolve_executable("winget")
    winget_ran = False
    if winget:
        package_targets: dict[str, list[str]] = {}
        for tool_id in missing:
            if after_wsl.get(tool_id) is not None:
                continue
            package_id = WINGET_PACKAGE_IDS.get(tool_id)
            if not package_id:
                continue
            package_targets.setdefault(package_id, []).append(tool_id)
        for package_id, target_ids in package_targets.items():
            result = _run_winget_install(winget, package_id)
            for tool_id in target_ids:
                command_results[tool_id].append(result)
                channels[tool_id] = "Windows Package Manager"
            winget_ran = True

    final = _availability(requested) if winget_ran else after_wsl
    items: list[dict[str, Any]] = []
    installed_count = 0
    for tool_id in requested:
        initial = before.get(tool_id)
        resolved = final.get(tool_id)
        if initial is not None:
            item_status = "already_available"
            message = f"Already available through {initial.source}."
        elif resolved is not None:
            item_status = "installed"
            installed_count += 1
            message = f"Installed and detected through {resolved.source}."
        elif tool_id not in INSTALLABLE_TOOL_IDS:
            item_status = "unavailable"
            message = "No unattended package mapping is available for this tool."
        elif not command_results[tool_id]:
            item_status = "unavailable"
            if not wsl_ready and tool_id not in WINGET_PACKAGE_IDS:
                message = "Kali WSL with root package access is required for this tool."
            else:
                message = "No supported package manager was available."
        else:
            item_status = "failed"
            message = "Installation ran, but the tool was not detected afterward."
        items.append(
            {
                "id": tool_id,
                "status": item_status,
                "channel": channels.get(tool_id),
                "source": resolved.source if resolved else None,
                "resolved": resolved.display if resolved else None,
                "message": message,
                "diagnostic": _diagnostic(command_results[tool_id]),
            }
        )

    available_count = sum(final.get(tool_id) is not None for tool_id in requested)
    unresolved_count = len(requested) - available_count
    if unresolved_count == 0:
        report_status = "completed"
        message = "Every requested forensic tool is installed and detected."
    elif available_count:
        report_status = "partial"
        message = f"{available_count} of {len(requested)} requested tools are available; review the remaining diagnostics."
    else:
        report_status = "failed"
        message = "The requested tools could not be installed automatically."
    managers = sorted({channel for channel in channels.values() if channel})
    return {
        "status": report_status,
        "message": message,
        "installed_count": installed_count,
        "already_available_count": sum(item["status"] == "already_available" for item in items),
        "available_count": available_count,
        "requested_count": len(requested),
        "unresolved_count": unresolved_count,
        "managers": managers,
        "items": items,
    }
