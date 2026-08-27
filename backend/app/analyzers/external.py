from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any

from .common import cancel_requested, display_text, normalize_json, sniff_kind, utc_now


@dataclass(frozen=True, slots=True)
class ToolSpec:
    tool_id: str
    executable: str
    name: str
    category: str
    kinds: frozenset[str] | None
    profiles: frozenset[str]
    source_url: str | None = None


@dataclass(frozen=True, slots=True)
class ResolvedTool:
    """A native executable or a command exposed by the default WSL distro."""

    source: str
    launcher: Path
    executable: str

    @property
    def display(self) -> str:
        if self.source == "native":
            return str(self.launcher)
        if self.source == "ruby":
            return f"{self.executable} (Ruby)"
        return f"WSL: {self.executable}"


IMAGE_KINDS = frozenset({"png", "jpeg", "gif", "bmp", "webp", "tiff", "ico"})
AUDIO_KINDS = frozenset({"audio", "wav", "aiff", "flac", "ogg", "mp3", "aac", "m4a", "au", "asf", "amr", "caf", "midi"})


TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec("file", "file", "libmagic file identification", "identity", None, frozenset({"quick", "balanced", "deep"})),
    ToolSpec("exiftool", "exiftool", "ExifTool metadata", "metadata", None, frozenset({"quick", "balanced", "deep"})),
    ToolSpec("exiv2", "exiv2", "Exiv2 metadata cross-check", "metadata", IMAGE_KINDS, frozenset({"balanced", "deep"})),
    ToolSpec("strings", "strings", "GNU/Unix strings cross-check", "strings", None, frozenset({"quick", "balanced", "deep"})),
    ToolSpec("identify", "identify", "ImageMagick decoded-image inspection", "identity", IMAGE_KINDS, frozenset({"balanced", "deep"})),
    ToolSpec("pngcheck", "pngcheck", "pngcheck structure validation", "structure", frozenset({"png"}), frozenset({"quick", "balanced", "deep"})),
    ToolSpec("pngcrush", "pngcrush", "pngcrush lossless validation", "structure", frozenset({"png"}), frozenset({"deep"}), "https://pmt.sourceforge.io/pngcrush/"),
    ToolSpec("pngfix", "pngfix", "libpng PNG zlib recovery", "repair", frozenset({"png"}), frozenset({"balanced", "deep"}), "https://github.com/pnggroup/libpng"),
    ToolSpec("optipng", "optipng", "OptiPNG error-recovery rewrite", "repair", frozenset({"png"}), frozenset({"balanced", "deep"}), "https://optipng.sourceforge.net/"),
    ToolSpec("jpeginfo", "jpeginfo", "jpeginfo structure validation", "structure", frozenset({"jpeg"}), frozenset({"quick", "balanced", "deep"})),
    ToolSpec("jpegtran", "jpegtran", "jpegtran lossless normalization", "repair", frozenset({"jpeg"}), frozenset({"balanced", "deep"}), "https://www.ijg.org/"),
    ToolSpec("djpeg", "djpeg", "libjpeg pixel decode validation", "structure", frozenset({"jpeg"}), frozenset({"deep"})),
    ToolSpec("zsteg", "zsteg", "zsteg lossless steganography", "steganography", frozenset({"png", "bmp"}), frozenset({"balanced", "deep"})),
    ToolSpec("stegseek", "stegseek", "Stegseek JPEG extraction", "steganography", frozenset({"jpeg"}), frozenset({"balanced", "deep"})),
    ToolSpec("steghide", "steghide", "Steghide password extraction", "steganography", frozenset({"jpeg", "bmp", "wav", "au"}), frozenset({"balanced", "deep"})),
    ToolSpec("outguess", "outguess", "OutGuess password extraction", "steganography", frozenset({"jpeg"}), frozenset({"balanced", "deep"})),
    ToolSpec("jpseek", "jpseek", "JPHide/JPSeek payload extraction", "steganography", frozenset({"jpeg"}), frozenset({"balanced", "deep"})),
    ToolSpec("jsteg", "jsteg", "JSteg JPEG coefficient extraction", "steganography", frozenset({"jpeg"}), frozenset({"balanced", "deep"})),
    ToolSpec("openstego", "openstego", "OpenStego RandomLSB extraction", "steganography", frozenset({"png", "bmp"}), frozenset({"balanced", "deep"})),
    ToolSpec("binwalk", "binwalk", "Binwalk signature scan", "embedded-data", None, frozenset({"balanced", "deep"})),
    ToolSpec("foremost", "foremost", "Foremost recursive header/footer carving", "embedded-data", None, frozenset({"balanced", "deep"})),
    ToolSpec("7z", "7z", "7-Zip embedded/archive listing", "embedded-data", None, frozenset({"deep"})),
    ToolSpec("tiffinfo", "tiffinfo", "libtiff tiffinfo", "structure", frozenset({"tiff"}), frozenset({"balanced", "deep"})),
    ToolSpec("tiffdump", "tiffdump", "libtiff directory dump", "structure", frozenset({"tiff"}), frozenset({"deep"})),
    ToolSpec("webpinfo", "webpinfo", "WebP RIFF inspection", "structure", frozenset({"webp"}), frozenset({"quick", "balanced", "deep"})),
    ToolSpec("webpmux", "webpmux", "WebP container and animation inspection", "structure", frozenset({"webp"}), frozenset({"balanced", "deep"})),
    ToolSpec("gifsicle", "gifsicle", "Gifsicle animation inspection", "animation", frozenset({"gif"}), frozenset({"balanced", "deep"}), "https://www.lcdf.org/gifsicle/"),
    ToolSpec("gifsicle_repair", "gifsicle", "Gifsicle tolerant GIF rewrite", "repair", frozenset({"gif"}), frozenset({"balanced", "deep"}), "https://www.lcdf.org/gifsicle/"),
    ToolSpec("zipfix", "zip", "Info-ZIP archive repair", "repair", frozenset({"zip"}), frozenset({"deep"}), "https://infozip.sourceforge.net/"),
    ToolSpec("zipfix_deep", "zip", "Info-ZIP deep archive repair", "repair", frozenset({"zip"}), frozenset({"deep"}), "https://infozip.sourceforge.net/"),
    ToolSpec("tesseract", "tesseract", "Tesseract OCR command-line cross-check", "ocr", IMAGE_KINDS, frozenset({"balanced", "deep"})),
    ToolSpec("zbarimg", "zbarimg", "ZBar barcode command-line cross-check", "barcodes", IMAGE_KINDS, frozenset({"balanced", "deep"})),
    ToolSpec("ffprobe", "ffprobe", "FFprobe stream and codec inspection", "audio-metadata", AUDIO_KINDS, frozenset({"quick", "balanced", "deep"})),
    ToolSpec("ffmpeg_spectrogram", "ffmpeg", "FFmpeg full-band spectrogram", "audio-spectrum", AUDIO_KINDS, frozenset({"quick", "balanced", "deep"})),
    ToolSpec("ffmpeg_pcm", "ffmpeg", "FFmpeg Audacity-compatible PCM conversion", "audio", AUDIO_KINDS, frozenset({"balanced", "deep"})),
    ToolSpec("sox_stats", "sox", "SoX signal statistics", "audio-signal", AUDIO_KINDS, frozenset({"balanced", "deep"})),
    ToolSpec("sox_spectrogram", "sox", "SoX high-resolution spectrogram", "audio-spectrum", AUDIO_KINDS, frozenset({"deep"})),
    ToolSpec("mediainfo", "mediainfo", "MediaInfo audio container inspection", "audio-metadata", AUDIO_KINDS, frozenset({"balanced", "deep"})),
    ToolSpec("multimon_ng", "multimon-ng", "multimon-ng DTMF and AFSK decoder", "audio-decoding", frozenset({"wav"}), frozenset({"deep"})),
    ToolSpec("minimodem", "minimodem", "minimodem 1200-baud FSK decoder", "audio-decoding", frozenset({"wav"}), frozenset({"deep"})),
)


def _path_entries(raw: str | None) -> list[str]:
    """Return safe, existing PATH entries from an environment value."""

    if not raw:
        return []
    entries: list[str] = []
    for value in raw.split(os.pathsep):
        expanded = os.path.expandvars(value.strip().strip('"'))
        if not expanded:
            continue
        try:
            path = Path(expanded).expanduser()
            if path.is_dir():
                entries.append(str(path))
        except OSError:
            continue
    return entries


def _windows_environment_path() -> tuple[str, ...]:
    """Read the current user/system PATH after an installer changes it.

    A long-running API process keeps the PATH inherited at startup. Windows
    installers commonly update the registry instead, so consult those values
    as a fallback without mutating the process environment.
    """

    if os.name != "nt":
        return ()
    try:
        import winreg
    except ImportError:
        return ()

    values: list[str] = []
    for hive, subkey in (
        (winreg.HKEY_CURRENT_USER, r"Environment"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
    ):
        try:
            with winreg.OpenKey(hive, subkey) as key:
                value, _ = winreg.QueryValueEx(key, "Path")
        except (OSError, FileNotFoundError):
            continue
        if isinstance(value, str):
            values.extend(_path_entries(value))
    return tuple(values)


def _tool_search_path() -> str:
    """Build a PATH for detection using live environment and install paths."""

    entries: list[str] = []
    seen: set[str] = set()
    for value in [
        *_path_entries(os.environ.get("PATH")),
        *_windows_environment_path(),
        *_path_entries(os.environ.get("FORENSCOPE_TOOL_PATHS")),
    ]:
        key = value.casefold() if os.name == "nt" else value
        if key in seen:
            continue
        seen.add(key)
        entries.append(value)
    return os.pathsep.join(entries)


def _well_known_tool_directories(executable: str) -> tuple[str, ...]:
    """Return common Windows install folders that installers do not add to PATH."""

    if os.name != "nt":
        return ()
    local_app_data = os.environ.get("LOCALAPPDATA")
    user_profile = os.environ.get("USERPROFILE")
    program_files = os.environ.get("ProgramW6432") or os.environ.get("PROGRAMFILES")
    program_files_x86 = os.environ.get("ProgramFiles(x86)")
    local = Path(local_app_data) if local_app_data else None
    home = Path(user_profile) if user_profile else None
    pf = Path(program_files) if program_files else None
    pf86 = Path(program_files_x86) if program_files_x86 else None
    program_roots = [root for root in (pf, pf86) if root]
    user_program_roots = ([local / "Programs"] if local else [])

    directories: list[Path] = []
    configured_tools_root = os.environ.get("FORENSCOPE_TOOLS_DIR")
    managed_tools_root = (
        Path(configured_tools_root).expanduser()
        if configured_tools_root
        else Path(__file__).resolve().parents[3] / ".tools"
    )
    if executable == "exiftool":
        directories.extend(root / "ExifTool" for root in [*user_program_roots, *program_roots])
    elif executable == "identify":
        for root in (pf, pf86):
            if root and root.is_dir():
                directories.extend(root.glob("ImageMagick-*"))
    elif executable in {"7z"}:
        directories.extend(root / "7-Zip" for root in program_roots)
    elif executable == "tesseract":
        directories.extend(root / "Tesseract-OCR" for root in program_roots)
    elif executable == "openstego":
        directories.extend(root / "OpenStego" for root in [*user_program_roots, *program_roots])
    elif executable == "steghide":
        # The verified upstream Windows archive has this fixed layout. Keeping
        # it inside the project avoids changing the user's system PATH.
        directories.extend((
            managed_tools_root / "steghide" / "bin",
            managed_tools_root / "steghide-0.5.1-win32" / "steghide",
        ))
    elif executable == "exiv2":
        directories.extend(root / "Exiv2" for root in [*user_program_roots, *program_roots])
    elif executable == "file":
        directories.extend(root / "Git" / "usr" / "bin" for root in program_roots)
    elif executable == "strings":
        directories.extend(root / "Sysinternals" for root in program_roots)
    elif executable in {"ffmpeg", "ffprobe"}:
        directories.extend(root / "FFmpeg" / "bin" for root in [*user_program_roots, *program_roots])
        directories.append(Path("C:/ffmpeg/bin"))
    elif executable == "mediainfo":
        directories.extend(root / "MediaInfo" for root in [*user_program_roots, *program_roots])
    elif executable == "sox":
        for root in program_roots:
            if root.is_dir():
                directories.extend(root.glob("sox-*"))

    # Common portable/package-manager shims cover tools such as zsteg and
    # steghide without recursively scanning arbitrary user directories.
    if home:
        directories.extend((home / "scoop" / "shims", home / "bin"))
    if local:
        directories.append(local / "Microsoft" / "WinGet" / "Links")
    chocolatey = os.environ.get("ChocolateyInstall")
    if chocolatey:
        directories.append(Path(chocolatey) / "bin")
    directories.append(Path(sys.executable).resolve().parent)

    result: list[str] = []
    seen: set[str] = set()
    for directory in directories:
        try:
            if not directory.is_dir():
                continue
            value = str(directory)
            key = value.casefold()
            if key not in seen:
                seen.add(key)
                result.append(value)
        except OSError:
            continue
    return tuple(result)


def resolve_executable(executable: str) -> Path | None:
    """Resolve an optional CLI from refreshed and standard install paths."""

    resolved = shutil.which(executable)
    if resolved:
        return Path(resolved)
    search_entries = [entry for entry in _tool_search_path().split(os.pathsep) if entry]
    search_entries.extend(_well_known_tool_directories(executable))
    search_path = os.pathsep.join(dict.fromkeys(search_entries))
    if not search_path:
        return None
    try:
        resolved = shutil.which(executable, path=search_path)
    except TypeError:
        # Keeps small test doubles and embedded callers compatible with the
        # one-argument shutil.which signature.
        resolved = None
    return Path(resolved) if resolved else None


def _windows_path_to_wsl(value: str) -> str:
    """Translate a local drive path to the default WSL automount path."""

    if os.name != "nt" or not re.match(r"^[A-Za-z]:[\\/]", value):
        return value
    path = PureWindowsPath(value)
    drive = path.drive.rstrip(":").lower()
    suffix = "/".join(path.parts[1:])
    return f"/mnt/{drive}/{suffix}" if suffix else f"/mnt/{drive}"


def discover_wsl_tools(executables: list[str] | tuple[str, ...]) -> dict[str, str]:
    """Discover fixed executable names in the default WSL distribution."""

    names = list(dict.fromkeys(name for name in executables if re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", name)))
    if os.name != "nt" or not names:
        return {}
    wsl = resolve_executable("wsl")
    if wsl is None:
        return {}
    # Names are regex-allowlisted above, so they can be embedded as fixed shell
    # tokens without accepting arbitrary script text from the API caller.
    script = "; ".join(
        f'printf "{name}\\t"; command -v {name} 2>/dev/null || true; printf "\\n"'
        for name in names
    )
    kwargs: dict[str, Any] = {
        "args": [str(wsl), "--", "sh", "-c", script],
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "shell": False,
        "close_fds": True,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        # A cold WSL distribution can take well over 20 seconds to start on
        # Windows, especially while another forensic job is active. Treating
        # that startup delay as "all tools missing" is misleading.
        result = subprocess.run(timeout=120, check=False, **kwargs)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    discovered: dict[str, str] = {}
    allowed = set(names)
    for line in result.stdout.splitlines():
        name, separator, path = line.partition("\t")
        if separator and name in allowed and path.startswith("/"):
            discovered[name] = path
    return discovered


def resolve_tool(executable: str, *, wsl_tools: dict[str, str] | None = None) -> ResolvedTool | None:
    """Resolve a tool natively first and then through the default WSL distro."""

    native = resolve_executable(executable)
    if native is not None:
        if os.name == "nt" and executable == "zsteg" and native.suffix.casefold() in {".bat", ".cmd"}:
            ruby = resolve_executable("ruby")
            script = native.with_suffix("")
            if ruby and script.is_file():
                return ResolvedTool(source="ruby", launcher=ruby, executable=str(script))
        return ResolvedTool(source="native", launcher=native, executable=str(native))
    discovered = wsl_tools if wsl_tools is not None else discover_wsl_tools((executable,))
    linux_path = discovered.get(executable)
    wsl = resolve_executable("wsl") if linux_path else None
    if linux_path and wsl:
        return ResolvedTool(source="wsl", launcher=wsl, executable=linux_path)
    return None


def tool_environment() -> dict[str, str]:
    """Expose detected dependency folders to child tools such as zsteg."""

    environment = os.environ.copy()
    entries = [entry for entry in _tool_search_path().split(os.pathsep) if entry]
    for spec in TOOL_SPECS:
        entries.extend(_well_known_tool_directories(spec.executable))
    deduplicated: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        key = entry.casefold() if os.name == "nt" else entry
        if key not in seen:
            seen.add(key)
            deduplicated.append(entry)
    environment["PATH"] = os.pathsep.join(deduplicated)
    return environment


class ExternalToolRunner:
    """Run optional forensic CLIs using fixed argument arrays and hard bounds."""

    def __init__(self, *, timeout: int, output_limit: int = 2 * 1024 * 1024, is_cancelled: Any = None) -> None:
        self.timeout = max(1, timeout)
        self.output_limit = max(64 * 1024, output_limit)
        self.is_cancelled = is_cancelled
        self._version_cache: dict[str, str | None] = {}

    def run_all(
        self,
        path: Path,
        *,
        kind: str,
        profile: str,
        password: str | None,
        work_dir: Path,
        ocr_language: str = "eng",
        selected_tools: set[str] | None = None,
        zsteg_mode: str = "all",
        allow_extraction: bool = True,
        max_extracted_files: int = 32,
        foremost_depth: int = 2,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        wsl_tools: dict[str, str] | None = None
        for spec in TOOL_SPECS:
            if cancel_requested(self.is_cancelled):
                results.append(self._not_run(spec, "cancelled", "Job cancellation was requested."))
                continue
            if selected_tools is not None and spec.tool_id not in selected_tools:
                results.append(self._not_run(spec, "skipped", "Disabled in this job's analysis settings."))
                continue
            if not allow_extraction and spec.tool_id in {"foremost", "jpseek", "openstego", "outguess", "steghide", "stegseek", "ffmpeg_spectrogram", "ffmpeg_pcm", "sox_spectrogram"}:
                results.append(self._not_run(spec, "skipped", "External payload extraction is disabled in this job's settings."))
                continue
            if spec.kinds is not None and kind not in spec.kinds:
                results.append(self._not_run(spec, "skipped", f"Not applicable to detected {kind} input."))
                continue
            if profile not in spec.profiles:
                results.append(self._not_run(spec, "skipped", f"Disabled by the {profile} scan profile."))
                continue
            resolution = resolve_tool(spec.executable, wsl_tools={})
            if resolution is None:
                if wsl_tools is None:
                    wsl_tools = discover_wsl_tools(tuple(candidate.executable for candidate in TOOL_SPECS))
                resolution = resolve_tool(spec.executable, wsl_tools=wsl_tools)
            if resolution is None:
                results.append(self._not_run(spec, "missing", f"Optional executable {spec.executable!r} was not found natively or in WSL."))
                continue
            results.append(
                self._run_spec(
                    spec,
                    resolution,
                    path,
                    profile,
                    password,
                    work_dir,
                    ocr_language,
                    zsteg_mode,
                    max_extracted_files,
                    foremost_depth,
                )
            )
        return results

    def _run_spec(
        self,
        spec: ToolSpec,
        resolution: ResolvedTool,
        input_path: Path,
        profile: str,
        password: str | None,
        work_dir: Path,
        ocr_language: str,
        zsteg_mode: str,
        max_extracted_files: int,
        foremost_depth: int,
    ) -> dict[str, Any]:
        extracted_path: Path | None = None
        extracted_dir: Path | None = None
        stdin_data: bytes | None = None
        configured_foremost_depth = max(1, min(4, int(foremost_depth)))
        foremost_inputs_scanned = 0
        foremost_depth_reached = 0
        foremost_recursive_failures = 0
        with tempfile.TemporaryDirectory(prefix=f"{spec.tool_id}-", dir=str(work_dir)) as temp_name:
            temp_dir = Path(temp_name)
            # WSL can retain its Windows current-working-directory handle briefly
            # after a child exits. Running it from a disposable per-tool folder
            # then makes Windows refuse the folder cleanup. All paths below are
            # absolute and the job directory is server-controlled, so use the
            # stable job directory as the WSL CWD while retaining the isolated
            # per-tool directory for outputs.
            execution_cwd = work_dir if resolution.source == "wsl" else temp_dir
            executable = resolution.executable
            if spec.tool_id == "file":
                argv = [executable, "--brief", "--mime-type", str(input_path)]
            elif spec.tool_id == "exiftool":
                argv = [executable, "-j", "-G1", "-s", str(input_path)]
            elif spec.tool_id == "exiv2":
                argv = [executable, "-pa", str(input_path)]
            elif spec.tool_id == "strings":
                argv = [executable, "-a", "-n", "4", str(input_path)]
            elif spec.tool_id == "identify":
                argv = [executable, "-verbose", str(input_path)]
            elif spec.tool_id == "pngcheck":
                argv = [executable, "-v", str(input_path)]
            elif spec.tool_id == "pngcrush":
                argv = [executable, "-n", "-v", str(input_path)]
            elif spec.tool_id == "pngfix":
                extracted_path = temp_dir / "pngfix_repaired.png"
                argv = [executable, f"--out={extracted_path}", str(input_path)]
            elif spec.tool_id == "optipng":
                extracted_path = temp_dir / "optipng_repaired.png"
                argv = [executable, "-fix", "-force", "-out", str(extracted_path), "--", str(input_path)]
            elif spec.tool_id == "jpeginfo":
                argv = [executable, "-c", str(input_path)]
            elif spec.tool_id == "jpegtran":
                extracted_path = temp_dir / "jpegtran_normalized.jpg"
                argv = [executable, "-copy", "all", "-outfile", str(extracted_path), str(input_path)]
            elif spec.tool_id == "djpeg":
                extracted_path = temp_dir / "djpeg_decoded.ppm"
                argv = [executable, "-verbose", "-outfile", str(extracted_path), str(input_path)]
            elif spec.tool_id == "zsteg":
                argv = [executable, "--lsb" if zsteg_mode == "lsb" else "-a", str(input_path)]
            elif spec.tool_id == "stegseek":
                if password is not None:
                    extracted_path = temp_dir / "stegseek_payload.bin"
                    argv = [executable, "--quiet", "--extract", str(input_path), str(extracted_path), "-p", password]
                elif profile == "deep":
                    argv = [executable, "--seed", str(input_path)]
                else:
                    return self._not_run(spec, "skipped", "A password was not supplied; seed scanning is reserved for Deep mode.", executable=resolution.display)
            elif spec.tool_id == "steghide":
                # Empty-passphrase Steghide payloads are common in beginner CTFs.
                # Passing -p explicitly also prevents an interactive prompt.
                steghide_password = password if password is not None else ""
                extracted_path = temp_dir / "steghide_payload.bin"
                argv = [
                    executable, "extract", "-sf", str(input_path), "-p", steghide_password,
                    "-xf", str(extracted_path), "-f",
                ]
            elif spec.tool_id == "outguess":
                if password is None:
                    return self._not_run(spec, "skipped", "A passphrase is required for bounded OutGuess extraction.", executable=resolution.display)
                extracted_path = temp_dir / "outguess_payload.bin"
                argv = [executable, "-k", password, "-r", str(input_path), str(extracted_path)]
            elif spec.tool_id == "jpseek":
                extracted_path = temp_dir / "jpseek_payload.bin"
                argv = [executable, str(input_path), str(extracted_path)]
                stdin_data = ((password or "") + "\n").encode("utf-8")
            elif spec.tool_id == "jsteg":
                argv = [executable, "reveal", str(input_path)]
            elif spec.tool_id == "openstego":
                extracted_dir = temp_dir / "openstego-output"
                extracted_dir.mkdir()
                argv = [
                    executable, "extract", "-a", "randomlsb", "--cryptalgo", "AES128",
                    "-sf", str(input_path), "-xd", str(extracted_dir), "-p", password or "",
                ]
            elif spec.tool_id == "binwalk":
                argv = [executable, "--signature", "--quiet", str(input_path)]
            elif spec.tool_id == "foremost":
                extracted_dir = temp_dir / "foremost-output"
                extracted_dir.mkdir()
                first_output_dir = extracted_dir / "depth-1-source"
                argv = [executable, "-Q", "-i", str(input_path), "-o", str(first_output_dir)]
            elif spec.tool_id == "7z":
                argv = [executable, "l", "-slt", "--", str(input_path)]
            elif spec.tool_id == "tiffinfo":
                argv = [executable, str(input_path)]
            elif spec.tool_id == "tiffdump":
                argv = [executable, str(input_path)]
            elif spec.tool_id == "webpinfo":
                argv = [executable, str(input_path)]
            elif spec.tool_id == "webpmux":
                argv = [executable, "-info", str(input_path)]
            elif spec.tool_id == "gifsicle":
                argv = [executable, "--info", str(input_path)]
            elif spec.tool_id == "gifsicle_repair":
                extracted_path = temp_dir / "gifsicle_repaired.gif"
                argv = [executable, "--careful", "--output", str(extracted_path), "--", str(input_path)]
            elif spec.tool_id == "zipfix":
                extracted_path = temp_dir / "zipfix_repaired.zip"
                argv = [executable, "-F", str(input_path), "--out", str(extracted_path)]
            elif spec.tool_id == "zipfix_deep":
                extracted_path = temp_dir / "zipfix_deep_repaired.zip"
                argv = [executable, "-FF", str(input_path), "--out", str(extracted_path)]
            elif spec.tool_id == "tesseract":
                argv = [executable, str(input_path), "stdout", "-l", ocr_language, "--psm", "6"]
            elif spec.tool_id == "zbarimg":
                argv = [executable, "--quiet", "--raw", str(input_path)]
            elif spec.tool_id == "ffprobe":
                argv = [executable, "-v", "error", "-show_format", "-show_streams", "-of", "json", str(input_path)]
            elif spec.tool_id == "ffmpeg_spectrogram":
                extracted_path = temp_dir / "ffmpeg_spectrogram.png"
                argv = [
                    executable, "-hide_banner", "-nostdin", "-y", "-i", str(input_path),
                    "-lavfi", "showspectrumpic=s=1600x800:legend=1:scale=log:color=channel",
                    "-frames:v", "1", str(extracted_path),
                ]
            elif spec.tool_id == "ffmpeg_pcm":
                extracted_path = temp_dir / "ffmpeg_audacity_review.wav"
                argv = [
                    executable, "-hide_banner", "-nostdin", "-y", "-i", str(input_path),
                    "-vn", "-c:a", "pcm_s16le", str(extracted_path),
                ]
            elif spec.tool_id == "sox_stats":
                argv = [executable, str(input_path), "-n", "stats"]
            elif spec.tool_id == "sox_spectrogram":
                extracted_path = temp_dir / "sox_spectrogram.png"
                argv = [
                    executable, str(input_path), "-n", "spectrogram", "-x", "1600", "-y", "800",
                    "-z", "120", "-o", str(extracted_path),
                ]
            elif spec.tool_id == "mediainfo":
                argv = [executable, "--Output=JSON", str(input_path)]
            elif spec.tool_id == "multimon_ng":
                argv = [executable, "-q", "-a", "DTMF", "-a", "AFSK1200", "-a", "AFSK2400", "-t", "wav", str(input_path)]
            elif spec.tool_id == "minimodem":
                argv = [executable, "--rx", "1200", "-f", str(input_path)]
            else:
                return self._not_run(spec, "skipped", "No fixed invocation is registered.", executable=resolution.display)

            started_at = utc_now()
            start = time.monotonic()
            launch_argv = self._launch_argv(resolution, argv[1:])
            execution = self._execute(launch_argv, cwd=execution_cwd, stdin_data=stdin_data)
            if spec.tool_id == "foremost":
                foremost_inputs_scanned = 1
                foremost_depth_reached = 1 if execution["status"] == "completed" else 0
                current_inputs = self._foremost_payload_files(first_output_dir, max_extracted_files)
                scan_budget = max(1, min(64, int(max_extracted_files)))
                deadline = start + self.timeout
                for depth in range(2, configured_foremost_depth + 1):
                    if not current_inputs or foremost_inputs_scanned >= scan_budget:
                        break
                    next_inputs: list[Path] = []
                    for candidate_index, candidate in enumerate(current_inputs):
                        if foremost_inputs_scanned >= scan_budget or cancel_requested(self.is_cancelled):
                            break
                        remaining_seconds = int(deadline - time.monotonic())
                        if remaining_seconds < 1:
                            break
                        output_dir = extracted_dir / f"depth-{depth}-{candidate_index:03d}"
                        recursive_argv = [
                            executable, "-Q", "-i", str(candidate), "-o", str(output_dir)
                        ]
                        recursive_execution = self._execute(
                            self._launch_argv(resolution, recursive_argv[1:]),
                            cwd=execution_cwd,
                            timeout=remaining_seconds,
                        )
                        foremost_inputs_scanned += 1
                        heading = f"\n\n[Foremost depth {depth}: {candidate.name}]\n"
                        for stream in ("stdout", "stderr"):
                            addition = heading + recursive_execution[stream]
                            combined = execution[stream] + addition
                            if len(combined.encode("utf-8", "replace")) > self.output_limit:
                                execution["output_truncated"] = True
                            execution[stream] = display_text(combined, self.output_limit)
                        execution["output_truncated"] = bool(
                            execution["output_truncated"] or recursive_execution["output_truncated"]
                        )
                        if recursive_execution["status"] == "completed":
                            foremost_depth_reached = max(foremost_depth_reached, depth)
                            next_inputs.extend(
                                self._foremost_payload_files(
                                    output_dir,
                                    scan_budget - foremost_inputs_scanned,
                                )
                            )
                        else:
                            foremost_recursive_failures += 1
                            if recursive_execution["status"] == "cancelled":
                                execution["status"] = "cancelled"
                                break
                    current_inputs = next_inputs
                    if execution["status"] == "cancelled" or time.monotonic() >= deadline:
                        break
            duration_ms = int((time.monotonic() - start) * 1000)
            stdout = self._sanitize(execution["stdout"], input_path, temp_dir, password)
            stderr = self._sanitize(execution["stderr"], input_path, temp_dir, password)
            public_argv = self._redacted_argv(spec.tool_id, argv, password, input_path, temp_dir)
            if resolution.source == "wsl":
                public_argv = ["wsl.exe", "--", resolution.executable, *public_argv[1:]]
            status = execution["status"]
            if spec.tool_id == "zbarimg" and status == "completed" and execution["return_code"] == 4:
                status, outcome_summary = "no_findings", "No barcode or QR symbol was detected."
            else:
                status, outcome_summary = self._normalize_outcome(
                    spec.tool_id, status, execution["return_code"], stdout, stderr
                )
            method: dict[str, Any] = {
                "id": spec.tool_id,
                "name": spec.name,
                "category": spec.category,
                "status": status,
                "applicable": True,
                "started_at": started_at,
                "duration_ms": duration_ms,
                "tool": {
                    "executable": spec.executable,
                    "resolved": resolution.display,
                    "source": resolution.source,
                    "version": self._version(spec, resolution, execution_cwd),
                },
                "command": public_argv,
                "return_code": execution["return_code"],
                "stdout": display_text(stdout, self.output_limit),
                "stderr": display_text(stderr, self.output_limit),
                "output_truncated": execution["output_truncated"],
                "summary": outcome_summary or self._summary(status, execution["return_code"], stdout, stderr),
                "metadata": {},
                "details": (
                    {
                        "configured_depth": configured_foremost_depth,
                        "depth_reached": foremost_depth_reached,
                        "inputs_scanned": foremost_inputs_scanned,
                        "recursive_failures": foremost_recursive_failures,
                        "scan_budget": max(1, min(64, int(max_extracted_files))),
                    }
                    if spec.tool_id == "foremost"
                    else ({
                        "passphrase_strategy": "supplied" if password is not None else "automatic_empty",
                    } if spec.tool_id == "steghide" else {})
                ),
                "extracted": [],
            }
            if spec.tool_id in {"exiftool", "ffprobe", "mediainfo"} and stdout:
                try:
                    parsed = json.loads(stdout)
                    if spec.tool_id == "exiftool" and isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                        metadata = dict(parsed[0])
                        metadata.pop("SourceFile", None)
                        method["metadata"] = normalize_json(metadata)
                    elif spec.tool_id in {"ffprobe", "mediainfo"} and isinstance(parsed, dict):
                        method["metadata"] = normalize_json(parsed)
                except (ValueError, TypeError) as exc:
                    method["metadata_parse_error"] = f"{type(exc).__name__}: {display_text(exc, 200)}"
            if extracted_path and extracted_path.is_file():
                try:
                    size = extracted_path.stat().st_size
                    if 0 < size <= 96 * 1024 * 1024:
                        payload = extracted_path.read_bytes()
                        labels = {
                            "stegseek": ("stegseek_payload", "extract Steghide-compatible payload with supplied password"),
                            "steghide": ("steghide_payload", "extract embedded payload with supplied Steghide password"),
                            "outguess": ("outguess_payload", "extract embedded payload with supplied OutGuess password"),
                            "jpegtran": ("jpegtran_normalized", "losslessly normalize JPEG markers and entropy stream"),
                            "djpeg": ("djpeg_decoded", "decode JPEG pixels to a PPM validation artifact"),
                            "pngfix": ("pngfix_repaired", "repair recoverable PNG zlib/header issues with libpng pngfix"),
                            "optipng": ("optipng_repaired", "recover and rewrite a damaged PNG with OptiPNG -fix"),
                            "gifsicle_repair": ("gifsicle_repaired", "rewrite a GIF with Gifsicle's tolerant parser"),
                            "zipfix": ("zipfix_repaired", "repair a ZIP with Info-ZIP -F"),
                            "zipfix_deep": ("zipfix_deep_repaired", "scan and repair a ZIP with Info-ZIP -FF"),
                            "jpseek": ("jpseek_payload", "extract a JPHide payload with JPSeek"),
                            "ffmpeg_spectrogram": ("ffmpeg_spectrogram", "render a full-band FFmpeg spectrogram"),
                            "ffmpeg_pcm": ("ffmpeg_audacity_review", "convert decoded audio to Audacity-compatible 16-bit PCM WAV"),
                            "sox_spectrogram": ("sox_spectrogram", "render a high-resolution SoX spectrogram"),
                        }
                        label, transformation = labels.get(spec.tool_id, (f"{spec.tool_id}_output", "external tool output"))
                        method["extracted"].append({
                            "label": label, "data": payload, "producer": spec.tool_id,
                            "transformation": transformation,
                            "offset": None, "kind": sniff_kind(payload),
                        })
                        if spec.tool_id == "steghide":
                            strategy = "the supplied passphrase" if password is not None else "the automatic empty-passphrase attempt"
                            method["summary"] = f"Steghide extracted a {size}-byte payload using {strategy}."
                    elif size:
                        method["extraction_warning"] = f"Extracted payload size {size} exceeded the adapter limit."
                except OSError as exc:
                    method["extraction_warning"] = f"Could not read extracted payload: {display_text(exc, 200)}"
            if extracted_dir and extracted_dir.is_dir():
                extracted_count = 0
                extracted_bytes = 0
                extraction_limit = max(1, min(64, int(max_extracted_files)))
                for candidate in sorted(extracted_dir.rglob("*")):
                    if extracted_count >= extraction_limit:
                        method["extraction_warning"] = f"Only the first {extraction_limit} extracted files were retained."
                        break
                    try:
                        if (
                            candidate.is_symlink()
                            or not candidate.is_file()
                            or (spec.tool_id == "foremost" and candidate.name.casefold() == "audit.txt")
                        ):
                            continue
                        size = candidate.stat().st_size
                        if size <= 0 or size > 96 * 1024 * 1024 or extracted_bytes + size > 192 * 1024 * 1024:
                            continue
                        payload = candidate.read_bytes()
                    except OSError:
                        continue
                    relative_name = candidate.relative_to(extracted_dir).as_posix().replace("/", "_")
                    method["extracted"].append({
                        "label": f"{spec.tool_id}_{relative_name}",
                        "data": payload,
                        "producer": spec.tool_id,
                        "transformation": f"recover file with {spec.name}",
                        "offset": None,
                        "kind": sniff_kind(payload),
                    })
                    extracted_count += 1
                    extracted_bytes += size
                method["extracted_count"] = extracted_count
                if spec.tool_id == "foremost":
                    if method["status"] == "completed" and extracted_count == 0:
                        method["status"] = "no_findings"
                        method["summary"] = (
                            f"Foremost scanned {foremost_inputs_scanned} input(s) through "
                            f"{foremost_depth_reached} of {configured_foremost_depth} configured level(s); "
                            "no recoverable file signatures were found."
                        )
                    elif method["status"] == "completed":
                        method["summary"] = (
                            f"Foremost scanned {foremost_inputs_scanned} input(s) through "
                            f"{foremost_depth_reached} of {configured_foremost_depth} configured level(s) "
                            f"and recovered {extracted_count} bounded file(s)."
                        )
            return method

    @staticmethod
    def _foremost_payload_files(root: Path, limit: int) -> list[Path]:
        """Return bounded Foremost payloads, excluding its audit log."""

        retained: list[Path] = []
        for candidate in sorted(root.rglob("*")) if root.is_dir() else []:
            if len(retained) >= max(0, limit):
                break
            try:
                if (
                    candidate.is_symlink()
                    or not candidate.is_file()
                    or candidate.name.casefold() == "audit.txt"
                ):
                    continue
                size = candidate.stat().st_size
                if size <= 0 or size > 96 * 1024 * 1024:
                    continue
            except OSError:
                continue
            retained.append(candidate)
        return retained

    @staticmethod
    def _launch_argv(resolution: ResolvedTool, arguments: list[str]) -> list[str]:
        if resolution.source == "native":
            return [str(resolution.launcher), *arguments]
        if resolution.source == "ruby":
            return [str(resolution.launcher), resolution.executable, *arguments]
        converted = [_windows_path_to_wsl(value) for value in arguments]
        return [str(resolution.launcher), "--", resolution.executable, *converted]

    @staticmethod
    def _normalize_outcome(
        tool_id: str,
        status: str,
        return_code: int | None,
        stdout: str,
        stderr: str,
    ) -> tuple[str, str | None]:
        if status != "completed" or return_code in (0, None):
            return status, None
        combined = f"{stdout}\n{stderr}".lower()
        expected_negative: dict[str, tuple[str, ...]] = {
            "7z": ("cannot open the file as archive", "is not archive"),
            "stegseek": ("could not find a valid steghide file", "no steghide data found"),
            "steghide": ("could not extract any data", "could not extract data with that passphrase"),
            "openstego": ("no embedded data found", "does not contain embedded data"),
        }
        if any(pattern in combined for pattern in expected_negative.get(tool_id, ())):
            summaries = {
                "7z": "Input is not an archive; no embedded archive was listed.",
                "stegseek": "No Steghide-compatible payload was found.",
                "steghide": "No payload matched the supplied Steghide passphrase.",
                "openstego": "No OpenStego payload was found.",
            }
            return "no_findings", summaries[tool_id]
        return "failed", None

    def _execute(
        self,
        argv: list[str],
        *,
        cwd: Path,
        timeout: int | None = None,
        stdin_data: bytes | None = None,
    ) -> dict[str, Any]:
        status = "completed"
        output_truncated = False
        return_code: int | None = None
        with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(mode="w+b") as stderr_file:
            kwargs: dict[str, Any] = {
                "args": argv,
                "cwd": str(cwd),
                "stdin": subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                "stdout": stdout_file,
                "stderr": stderr_file,
                "shell": False,
                "close_fds": True,
                "env": tool_environment(),
            }
            if os.name == "nt":
                kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            else:
                kwargs["start_new_session"] = True
            try:
                process = subprocess.Popen(**kwargs)
            except OSError as exc:
                return {"status": "failed", "return_code": None, "stdout": "", "stderr": f"{type(exc).__name__}: {display_text(exc, 500)}", "output_truncated": False}
            if stdin_data is not None and process.stdin is not None:
                try:
                    process.stdin.write(stdin_data[:16 * 1024 + 1])
                    process.stdin.close()
                except (BrokenPipeError, OSError):
                    pass
            deadline = time.monotonic() + (timeout or self.timeout)
            while process.poll() is None:
                if cancel_requested(self.is_cancelled):
                    status = "cancelled"
                    self._terminate(process)
                    break
                if time.monotonic() >= deadline:
                    status = "timed_out"
                    self._terminate(process)
                    break
                try:
                    if os.fstat(stdout_file.fileno()).st_size + os.fstat(stderr_file.fileno()).st_size > self.output_limit * 2:
                        status = "failed"
                        output_truncated = True
                        self._terminate(process)
                        break
                except OSError:
                    pass
                time.sleep(0.05)
            try:
                return_code = process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                return_code = process.wait(timeout=2)
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout_raw = stdout_file.read(self.output_limit + 1)
            stderr_raw = stderr_file.read(self.output_limit + 1)
            if len(stdout_raw) > self.output_limit or len(stderr_raw) > self.output_limit:
                output_truncated = True
            return {
                "status": status, "return_code": return_code,
                "stdout": stdout_raw[:self.output_limit].decode("utf-8", "replace"),
                "stderr": stderr_raw[:self.output_limit].decode("utf-8", "replace"),
                "output_truncated": output_truncated,
            }

    @staticmethod
    def _terminate(process: subprocess.Popen[Any]) -> None:
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                    check=False,
                    timeout=3,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
            return
        try:
            process.terminate()
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
            except OSError:
                pass

    def _version(self, spec: ToolSpec, resolution: ResolvedTool, cwd: Path) -> str | None:
        if spec.tool_id in self._version_cache:
            return self._version_cache[spec.tool_id]
        if spec.tool_id == "jpseek":
            self._version_cache[spec.tool_id] = None
            return None
        version_args = {
            "exiftool": ["-ver"], "gifsicle": ["--version"], "file": ["--version"],
            "strings": ["--version"], "pngcheck": ["-h"], "jpeginfo": ["--version"],
            "zsteg": ["--version"], "stegseek": ["--version"], "binwalk": ["--version"],
            "tiffinfo": ["--version"], "webpinfo": ["-version"],
            "exiv2": ["--version"], "identify": ["-version"], "pngcrush": ["-version"],
            "jpegtran": ["-version"], "djpeg": ["-version"], "steghide": ["--version"],
            "outguess": ["-h"], "7z": [], "tiffdump": ["--version"], "webpmux": ["-version"],
            "tesseract": ["--version"], "zbarimg": ["--version"],
            "foremost": ["-V"], "jpseek": [], "jsteg": ["--help"], "openstego": ["--version"],
            "ffprobe": ["-version"], "ffmpeg_spectrogram": ["-version"], "ffmpeg_pcm": ["-version"],
            "sox_stats": ["--version"], "sox_spectrogram": ["--version"],
            "mediainfo": ["--Version"], "multimon_ng": ["--help"], "minimodem": ["--version"],
        }.get(spec.tool_id, ["--version"])
        result = self._execute(self._launch_argv(resolution, version_args), cwd=cwd, timeout=4)
        combined = (result["stdout"] or result["stderr"]).strip().splitlines()
        version = display_text(combined[0], 300) if combined else None
        self._version_cache[spec.tool_id] = version
        return version

    @staticmethod
    def _not_run(spec: ToolSpec, status: str, summary: str, executable: str | None = None) -> dict[str, Any]:
        return {
            "id": spec.tool_id, "name": spec.name, "category": spec.category,
            "status": status, "applicable": status != "skipped", "started_at": None,
            "duration_ms": 0, "tool": {"executable": spec.executable, "resolved": executable, "version": None},
            "command": [], "return_code": None, "stdout": "", "stderr": "",
            "output_truncated": False, "summary": summary, "metadata": {}, "extracted": [],
        }

    @staticmethod
    def _redacted_argv(tool_id: str, argv: list[str], password: str | None, input_path: Path, temp_dir: Path) -> list[str]:
        redacted: list[str] = []
        hide_next = False
        for value in argv:
            if hide_next:
                redacted.append("<redacted>")
                hide_next = False
                continue
            if value in {"-p", "-k"}:
                redacted.append(value)
                hide_next = True
            elif password is not None and value == password:
                redacted.append("<redacted>")
            elif value == str(input_path):
                redacted.append(f"<input>/{input_path.name}")
            elif str(temp_dir) in value:
                redacted.append("<temporary-output>")
            else:
                redacted.append(value)
        return redacted

    @staticmethod
    def _sanitize(text: str, input_path: Path, temp_dir: Path, password: str | None = None) -> str:
        sanitized = text.replace(str(input_path), f"<input>/{input_path.name}")
        sanitized = sanitized.replace(str(temp_dir), "<temporary>")
        sanitized = sanitized.replace(_windows_path_to_wsl(str(input_path)), f"<input>/{input_path.name}")
        sanitized = sanitized.replace(_windows_path_to_wsl(str(temp_dir)), "<temporary>")
        if password:
            sanitized = sanitized.replace(password, "<redacted>")
        return sanitized

    @staticmethod
    def _summary(status: str, return_code: int | None, stdout: str, stderr: str) -> str:
        if status == "timed_out":
            return "Tool exceeded its wall-time limit and was terminated."
        if status == "cancelled":
            return "Tool was terminated after cancellation was requested."
        if status == "failed":
            detail = (stderr or stdout).strip().splitlines()
            suffix = f" {display_text(detail[0], 240)}" if detail else ""
            return f"Tool exited with code {return_code}.{suffix}"
        line_count = len((stdout + "\n" + stderr).splitlines())
        return f"Tool completed and produced {line_count} line(s) of bounded output."
