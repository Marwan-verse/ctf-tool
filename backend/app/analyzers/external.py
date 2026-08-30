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

from .common import cancel_requested, display_text, normalize_json, safe_label, sniff_kind, utc_now


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
PDF_KINDS = frozenset({"pdf"})
TEXT_KINDS = frozenset({"text", "svg"})
NETWORK_KINDS = frozenset({"pcap", "pcapng"})
ARCHIVE_KINDS = frozenset({"zip", "7z", "rar", "tar", "gzip", "bzip2", "xz", "zstd"})
OFFICE_KINDS = frozenset({"ole", "rtf", "zip"})
DISK_KINDS = frozenset({"disk", "ewf"})
MEMORY_KINDS = frozenset({"memory"})


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
    ToolSpec("7z_extract", "7z", "7-Zip bounded flat archive extraction", "embedded-data", ARCHIVE_KINDS, frozenset({"deep"}), "https://7-zip.org/"),
    ToolSpec("tiffinfo", "tiffinfo", "libtiff tiffinfo", "structure", frozenset({"tiff"}), frozenset({"balanced", "deep"})),
    ToolSpec("tiffdump", "tiffdump", "libtiff directory dump", "structure", frozenset({"tiff"}), frozenset({"deep"})),
    ToolSpec("webpinfo", "webpinfo", "WebP RIFF inspection", "structure", frozenset({"webp"}), frozenset({"quick", "balanced", "deep"})),
    ToolSpec("webpmux", "webpmux", "WebP container and animation inspection", "structure", frozenset({"webp"}), frozenset({"balanced", "deep"})),
    ToolSpec("gifsicle", "gifsicle", "Gifsicle animation inspection", "animation", frozenset({"gif"}), frozenset({"balanced", "deep"}), "https://www.lcdf.org/gifsicle/"),
    ToolSpec("gifsicle_repair", "gifsicle", "Gifsicle tolerant GIF rewrite", "repair", frozenset({"gif"}), frozenset({"balanced", "deep"}), "https://www.lcdf.org/gifsicle/"),
    ToolSpec("zipfix", "zip", "Info-ZIP archive repair", "repair", frozenset({"zip"}), frozenset({"deep"}), "https://infozip.sourceforge.net/"),
    ToolSpec("zipfix_deep", "zip", "Info-ZIP deep archive repair", "repair", frozenset({"zip"}), frozenset({"deep"}), "https://infozip.sourceforge.net/"),
    ToolSpec("pdfinfo", "pdfinfo", "Poppler PDF metadata and page inspection", "metadata", PDF_KINDS, frozenset({"quick", "balanced", "deep"}), "https://poppler.freedesktop.org/"),
    ToolSpec("pdftotext", "pdftotext", "Poppler PDF text extraction", "strings", PDF_KINDS, frozenset({"balanced", "deep"}), "https://poppler.freedesktop.org/"),
    ToolSpec("pdfimages", "pdfimages", "Poppler PDF embedded-image extraction", "embedded-data", PDF_KINDS, frozenset({"deep"}), "https://poppler.freedesktop.org/"),
    ToolSpec("pdfdetach_list", "pdfdetach", "Poppler PDF attachment listing", "embedded-data", PDF_KINDS, frozenset({"deep"}), "https://poppler.freedesktop.org/"),
    ToolSpec("pdfdetach", "pdfdetach", "Poppler PDF attachment extraction", "embedded-data", PDF_KINDS, frozenset({"deep"}), "https://poppler.freedesktop.org/"),
    ToolSpec("qpdf", "qpdf", "qpdf PDF structure and repair check", "repair", PDF_KINDS, frozenset({"deep"}), "https://qpdf.readthedocs.io/"),
    ToolSpec("stegsnow", "stegsnow", "SNOW whitespace steganography decoder", "steganography", TEXT_KINDS, frozenset({"deep"}), "http://www.darkside.com.au/snow/"),
    ToolSpec("capinfos", "capinfos", "Wireshark capture metadata", "network-metadata", NETWORK_KINDS, frozenset({"quick", "balanced", "deep"}), "https://www.wireshark.org/docs/man-pages/capinfos.html"),
    ToolSpec("tshark", "tshark", "TShark packet and protocol summary", "network", NETWORK_KINDS, frozenset({"balanced", "deep"}), "https://www.wireshark.org/docs/man-pages/tshark.html"),
    ToolSpec("tshark_fields", "tshark", "TShark forensic field extraction", "network", NETWORK_KINDS, frozenset({"deep"}), "https://www.wireshark.org/docs/man-pages/tshark.html"),
    ToolSpec("tshark_packet_details", "tshark", "TShark Wireshark-grade packet dissection JSON", "network", NETWORK_KINDS, frozenset({"deep"}), "https://www.wireshark.org/docs/man-pages/tshark.html"),
    ToolSpec("tshark_statistics", "tshark", "TShark protocol/endpoints/conversations statistics", "network-metadata", NETWORK_KINDS, frozenset({"balanced", "deep"}), "https://www.wireshark.org/docs/man-pages/tshark.html"),
    ToolSpec("tshark_expert", "tshark", "TShark expert information and anomaly report", "network", NETWORK_KINDS, frozenset({"balanced", "deep"}), "https://www.wireshark.org/docs/man-pages/tshark.html"),
    ToolSpec("tshark_credentials", "tshark", "TShark cleartext credential recovery", "network-decoding", NETWORK_KINDS, frozenset({"deep"}), "https://www.wireshark.org/docs/man-pages/tshark.html"),
    ToolSpec("tshark_rtp", "tshark", "TShark RTP stream and loss statistics", "network-media", NETWORK_KINDS, frozenset({"deep"}), "https://www.wireshark.org/docs/man-pages/tshark.html"),
    ToolSpec("tshark_authentication", "tshark", "TShark NTLM/Kerberos authentication dissections", "network-auth", NETWORK_KINDS, frozenset({"deep"}), "https://www.wireshark.org/docs/man-pages/tshark.html"),
    ToolSpec("tshark_http2_ranges", "tshark", "TShark HTTP/2 Content-Range file reassembly", "embedded-data", NETWORK_KINDS, frozenset({"deep"}), "https://www.wireshark.org/docs/man-pages/tshark.html"),
    ToolSpec("tshark_usb_hid", "tshark", "TShark USB HID keystroke recovery", "network-decoding", NETWORK_KINDS, frozenset({"deep"}), "https://www.wireshark.org/docs/man-pages/tshark.html"),
    ToolSpec("tshark_http_objects", "tshark", "TShark HTTP object extraction", "embedded-data", NETWORK_KINDS, frozenset({"deep"}), "https://www.wireshark.org/docs/man-pages/tshark.html"),
    ToolSpec("tshark_ftp_objects", "tshark", "TShark FTP-DATA object extraction", "embedded-data", NETWORK_KINDS, frozenset({"deep"}), "https://www.wireshark.org/docs/man-pages/tshark.html"),
    ToolSpec("tshark_smb_objects", "tshark", "TShark SMB object extraction", "embedded-data", NETWORK_KINDS, frozenset({"deep"}), "https://www.wireshark.org/docs/man-pages/tshark.html"),
    ToolSpec("tshark_tftp_objects", "tshark", "TShark TFTP object extraction", "embedded-data", NETWORK_KINDS, frozenset({"deep"}), "https://www.wireshark.org/docs/man-pages/tshark.html"),
    ToolSpec("tshark_imf_objects", "tshark", "TShark email object extraction", "embedded-data", NETWORK_KINDS, frozenset({"deep"}), "https://www.wireshark.org/docs/man-pages/tshark.html"),
    ToolSpec("tshark_dicom_objects", "tshark", "TShark DICOM object extraction", "embedded-data", NETWORK_KINDS, frozenset({"deep"}), "https://www.wireshark.org/docs/man-pages/tshark.html"),
    ToolSpec("tcpflow", "tcpflow", "tcpflow bidirectional TCP stream extraction", "embedded-data", NETWORK_KINDS, frozenset({"deep"}), "https://github.com/simsong/tcpflow"),
    ToolSpec("hcxpcapngtool", "hcxpcapngtool", "WPA/PMKID and EAPOL hash extraction", "network-auth", NETWORK_KINDS, frozenset({"deep"}), "https://github.com/ZerBea/hcxtools"),
    ToolSpec("pcapfix", "pcapfix", "pcapfix non-destructive capture repair", "repair", NETWORK_KINDS, frozenset({"balanced", "deep"}), "https://github.com/Rup0rt/pcapfix"),
    ToolSpec("sqlite3", "sqlite3", "SQLite read-only safe database dump", "database", frozenset({"sqlite"}), frozenset({"balanced", "deep"}), "https://www.sqlite.org/cli.html"),
    ToolSpec("oleid", "oleid", "Oletools document risk indicators", "document", OFFICE_KINDS, frozenset({"balanced", "deep"}), "https://github.com/decalage2/oletools"),
    ToolSpec("olevba", "olevba", "Oletools VBA extraction and deobfuscation", "document", OFFICE_KINDS, frozenset({"deep"}), "https://github.com/decalage2/oletools"),
    ToolSpec("oleobj", "oleobj", "Oletools embedded OLE object extraction", "embedded-data", frozenset({"ole", "zip"}), frozenset({"deep"}), "https://github.com/decalage2/oletools"),
    ToolSpec("rtfobj", "rtfobj", "Oletools RTF object extraction", "embedded-data", frozenset({"rtf"}), frozenset({"deep"}), "https://github.com/decalage2/oletools"),
    ToolSpec("mmls", "mmls", "Sleuth Kit partition layout", "disk", DISK_KINDS, frozenset({"quick", "balanced", "deep"}), "https://www.sleuthkit.org/"),
    ToolSpec("fsstat", "fsstat", "Sleuth Kit filesystem metadata", "disk", frozenset({"disk"}), frozenset({"balanced", "deep"}), "https://www.sleuthkit.org/"),
    ToolSpec("fls", "fls", "Sleuth Kit recursive allocated/deleted file listing", "disk", frozenset({"disk"}), frozenset({"deep"}), "https://www.sleuthkit.org/"),
    ToolSpec("tsk_recover", "tsk_recover", "Sleuth Kit allocated/deleted file recovery", "embedded-data", frozenset({"disk"}), frozenset({"deep"}), "https://www.sleuthkit.org/"),
    ToolSpec("ewfinfo", "ewfinfo", "libewf acquisition and media metadata", "disk", frozenset({"ewf"}), frozenset({"quick", "balanced", "deep"}), "https://github.com/libyal/libewf"),
    ToolSpec("reglookup", "reglookup", "Read-only Windows registry hive enumeration", "registry", frozenset({"registry"}), frozenset({"balanced", "deep"}), "https://projects.sentinelchicken.org/reglookup/"),
    ToolSpec("evtx_dump", "evtx_dump.py", "python-evtx event XML rendering", "event-log", frozenset({"evtx"}), frozenset({"balanced", "deep"}), "https://github.com/williballenthin/python-evtx"),
    ToolSpec("lspst", "lspst", "libpst Outlook store listing", "email", frozenset({"pst"}), frozenset({"balanced", "deep"}), "https://www.five-ten-sg.com/libpst/"),
    ToolSpec("readpst", "readpst", "libpst deleted-mail and attachment extraction", "embedded-data", frozenset({"pst"}), frozenset({"deep"}), "https://www.five-ten-sg.com/libpst/"),
    ToolSpec("volatility3_banners", "vol", "Volatility 3 memory banner scan", "memory", MEMORY_KINDS, frozenset({"deep"}), "https://github.com/volatilityfoundation/volatility3"),
    ToolSpec("volatility3_windows", "vol", "Volatility 3 offline Windows process triage", "memory", MEMORY_KINDS, frozenset({"deep"}), "https://github.com/volatilityfoundation/volatility3"),
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
    ToolSpec("minimodem_300", "minimodem", "minimodem 300-baud Bell 103 FSK decoder", "audio-decoding", frozenset({"wav"}), frozenset({"deep"})),
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
    elif executable in {"tshark", "capinfos"}:
        directories.extend(root / "Wireshark" for root in program_roots)
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
            if not allow_extraction and spec.tool_id in {
                "foremost", "jpseek", "openstego", "outguess", "steghide", "stegseek",
                "ffmpeg_spectrogram", "ffmpeg_pcm", "sox_spectrogram", "pdfimages", "pdfdetach",
                "7z_extract", "tshark_http_objects", "tshark_ftp_objects", "tshark_smb_objects", "tshark_tftp_objects",
                "tshark_imf_objects", "tshark_dicom_objects", "tshark_http2_ranges", "tcpflow", "hcxpcapngtool",
                "pcapfix", "oleobj", "rtfobj", "tsk_recover",
                "readpst",
            }:
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
        disk_offsets: list[int] = []
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
            elif spec.tool_id == "stegsnow":
                argv = [executable, "-C", "-Q"]
                if password is not None:
                    argv.extend(["-p", password])
                argv.append(str(input_path))
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
            elif spec.tool_id == "7z_extract":
                extracted_dir = temp_dir / "7z-flat-output"
                extracted_dir.mkdir()
                argv = [executable, "e", "-y", "-bd", "-bb0", f"-o{extracted_dir}"]
                if password is not None:
                    argv.append(f"-p{password}")
                argv.extend(["--", str(input_path)])
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
            elif spec.tool_id == "pdfinfo":
                argv = [executable, str(input_path)]
            elif spec.tool_id == "pdftotext":
                extracted_path = temp_dir / "pdftotext.txt"
                argv = [executable, "-enc", "UTF-8", "-nopgbrk", str(input_path), str(extracted_path)]
            elif spec.tool_id == "pdfimages":
                extracted_dir = temp_dir / "pdfimages-output"
                extracted_dir.mkdir()
                argv = [executable, "-all", str(input_path), str(extracted_dir / "image")]
            elif spec.tool_id == "pdfdetach":
                extracted_dir = temp_dir / "pdfdetach-output"
                extracted_dir.mkdir()
                argv = [executable, "-saveall", "-o", str(extracted_dir), str(input_path)]
            elif spec.tool_id == "pdfdetach_list":
                argv = [executable, "-list", str(input_path)]
            elif spec.tool_id == "qpdf":
                argv = [executable, "--check", str(input_path)]
            elif spec.tool_id == "capinfos":
                argv = [executable, "-M", str(input_path)]
            elif spec.tool_id == "tshark":
                argv = [executable, "-n", "-r", str(input_path), "-c", "5000"]
            elif spec.tool_id == "tshark_fields":
                argv = [
                    executable, "-n", "-r", str(input_path), "-c", "20000",
                    "-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "occurrence=a",
                    "-e", "frame.number", "-e", "frame.time_epoch", "-e", "frame.protocols",
                    "-e", "ip.src", "-e", "ip.dst", "-e", "ipv6.src", "-e", "ipv6.dst",
                    "-e", "tcp.stream", "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.seq",
                    "-e", "udp.stream", "-e", "udp.srcport", "-e", "udp.dstport",
                    "-e", "dns.qry.name", "-e", "dns.qry.type", "-e", "dns.resp.name",
                    "-e", "dns.a", "-e", "dns.aaaa", "-e", "dns.cname", "-e", "dns.txt",
                    "-e", "http.request.method", "-e", "http.host", "-e", "http.request.uri",
                    "-e", "http.request.full_uri", "-e", "http.response.code", "-e", "http.content_type",
                    "-e", "ftp.request.command", "-e", "ftp.request.arg",
                    "-e", "ftp.response.code", "-e", "ftp.response.arg",
                    "-e", "smtp.req.command", "-e", "smtp.req.parameter",
                    "-e", "smtp.response.code", "-e", "smtp.rsp.parameter",
                    "-e", "imf.from", "-e", "imf.to", "-e", "imf.subject", "-e", "imf.content.type",
                    "-e", "irc.request", "-e", "irc.response",
                    "-e", "icmp.type", "-e", "icmp.code", "-e", "icmp.ident", "-e", "icmp.seq",
                    "-e", "icmpv6.type", "-e", "icmpv6.code",
                    "-e", "tls.handshake.type", "-e", "tls.handshake.extensions_server_name",
                    "-e", "data.data", "-e", "tcp.payload", "-e", "udp.payload",
                    "-e", "tcp.reassembled.data", "-e", "http.file_data",
                ]
            elif spec.tool_id == "tshark_packet_details":
                # TShark uses Wireshark's dissectors. Keep this JSON export
                # bounded while retaining the protocol tree and raw bytes for
                # detailed CTF review in the traffic workspace.
                argv = [
                    executable, "-n", "-r", str(input_path), "-c", "2000",
                    "-T", "json", "--json-compact", "--no-duplicate-keys", "-x",
                    "-j", (
                        "frame eth sll ip ipv6 tcp udp icmp icmpv6 arp dns dhcp http http2 "
                        "tls ftp smtp imf irc smb smb2 tftp usb usbhid wlan eapol rtp sip "
                        "mqtt modbus bt-dht kerberos ntlmssp websocket data"
                    ),
                ]
            elif spec.tool_id == "tshark_statistics":
                argv = [
                    executable, "-n", "-q", "-r", str(input_path),
                    "-z", "io,phs", "-z", "endpoints,ip", "-z", "endpoints,ipv6",
                    "-z", "endpoints,tcp", "-z", "endpoints,udp", "-z", "conv,ip",
                    "-z", "conv,ipv6", "-z", "conv,tcp", "-z", "conv,udp",
                    "-z", "io,stat,1",
                ]
            elif spec.tool_id == "tshark_expert":
                argv = [executable, "-n", "-q", "-r", str(input_path), "-z", "expert"]
            elif spec.tool_id == "tshark_credentials":
                argv = [executable, "-n", "-q", "-r", str(input_path), "-z", "credentials"]
            elif spec.tool_id == "tshark_rtp":
                argv = [executable, "-n", "-q", "-r", str(input_path), "-z", "rtp,streams"]
            elif spec.tool_id == "tshark_authentication":
                argv = [
                    executable, "-n", "-r", str(input_path), "-c", "5000", "-T", "json",
                    "--json-compact", "--no-duplicate-keys", "-j", "ntlmssp kerberos ldap http smb smb2",
                ]
            elif spec.tool_id == "tshark_http2_ranges":
                # A known CTF pattern splits a response into one/two byte
                # HTTP/2 DATA frames and uses Content-Range as the ordering
                # oracle. TShark's dissector exposes both fields after TLS
                # secrets have been injected or supplied to Wireshark.
                argv = [
                    executable, "-2", "-n", "-r", str(input_path), "-c", "100000",
                    "-Y", "http2.headers.range && http2.data.data", "-T", "fields",
                    "-E", "separator=/t", "-E", "occurrence=f",
                    "-e", "frame.number", "-e", "http2.streamid",
                    "-e", "http2.headers.range", "-e", "http2.data.data",
                ]
            elif spec.tool_id == "tshark_usb_hid":
                argv = [
                    executable, "-n", "-r", str(input_path), "-c", "50000",
                    "-Y", "usb.capdata || usbhid.data", "-T", "fields",
                    "-E", "separator=/t", "-e", "usb.src", "-e", "usb.capdata", "-e", "usbhid.data",
                ]
            elif spec.tool_id in {
                "tshark_http_objects", "tshark_ftp_objects", "tshark_smb_objects", "tshark_tftp_objects",
                "tshark_imf_objects", "tshark_dicom_objects",
            }:
                protocol = {
                    "tshark_http_objects": "http",
                    "tshark_ftp_objects": "ftp-data",
                    "tshark_smb_objects": "smb",
                    "tshark_tftp_objects": "tftp",
                    "tshark_imf_objects": "imf",
                    "tshark_dicom_objects": "dicom",
                }[spec.tool_id]
                extracted_dir = temp_dir / f"tshark-{protocol}-objects"
                extracted_dir.mkdir()
                argv = [executable, "-2", "-n", "-r", str(input_path), "-q", "--export-objects", f"{protocol},{extracted_dir}"]
            elif spec.tool_id == "tcpflow":
                extracted_dir = temp_dir / "tcpflow-output"
                extracted_dir.mkdir()
                argv = [executable, "-r", str(input_path), "-o", str(extracted_dir)]
            elif spec.tool_id == "hcxpcapngtool":
                extracted_path = temp_dir / "capture.22000"
                argv = [executable, "-o", str(extracted_path), str(input_path)]
            elif spec.tool_id == "pcapfix":
                suffix = ".pcapng" if input_path.suffix.casefold() == ".pcapng" else ".pcap"
                extracted_path = temp_dir / f"pcapfix_repaired{suffix}"
                argv = [
                    executable, "--deep-scan", "--outfile", str(extracted_path), str(input_path),
                ]
            elif spec.tool_id == "sqlite3":
                argv = [executable, "-readonly", "-safe", str(input_path), ".dump"]
            elif spec.tool_id == "oleid":
                argv = [executable, str(input_path)]
            elif spec.tool_id == "olevba":
                argv = [executable, "--decode"]
                if password is not None:
                    argv.extend(["-p", password])
                argv.append(str(input_path))
            elif spec.tool_id == "oleobj":
                extracted_dir = temp_dir / "oleobj-output"
                extracted_dir.mkdir()
                argv = [executable, "-d", str(extracted_dir), str(input_path)]
            elif spec.tool_id == "rtfobj":
                extracted_dir = temp_dir / "rtfobj-output"
                extracted_dir.mkdir()
                argv = [executable, "-s", "all", "-d", str(extracted_dir), str(input_path)]
            elif spec.tool_id == "mmls":
                argv = [executable, str(input_path)]
            elif spec.tool_id == "fsstat":
                disk_offsets = self._raw_partition_offsets(input_path)
                argv = [executable, *(["-o", str(disk_offsets[0])] if disk_offsets else []), str(input_path)]
            elif spec.tool_id == "fls":
                disk_offsets = self._raw_partition_offsets(input_path)
                argv = [executable, "-r", "-p", *(["-o", str(disk_offsets[0])] if disk_offsets else []), str(input_path)]
            elif spec.tool_id == "tsk_recover":
                disk_offsets = self._raw_partition_offsets(input_path)
                extracted_dir = temp_dir / "tsk-recover-output"
                extracted_dir.mkdir()
                target = extracted_dir / (f"partition-{disk_offsets[0]}" if disk_offsets else "filesystem")
                target.mkdir()
                argv = [executable, "-e", *(["-o", str(disk_offsets[0])] if disk_offsets else []), str(input_path), str(target)]
            elif spec.tool_id == "ewfinfo":
                argv = [executable, str(input_path)]
            elif spec.tool_id == "reglookup":
                argv = [executable, str(input_path)]
            elif spec.tool_id == "evtx_dump":
                argv = [executable, str(input_path)]
            elif spec.tool_id == "lspst":
                argv = [executable, "-l", str(input_path)]
            elif spec.tool_id == "readpst":
                extracted_dir = temp_dir / "readpst-output"
                extracted_dir.mkdir()
                argv = [executable, "-D", "-e", "-j", "1", "-q", "-o", str(extracted_dir), str(input_path)]
            elif spec.tool_id == "volatility3_banners":
                argv = [executable, "--offline", "-f", str(input_path), "banners.Banners"]
            elif spec.tool_id == "volatility3_windows":
                argv = [executable, "--offline", "-f", str(input_path), "windows.pslist.PsList"]
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
            elif spec.tool_id == "minimodem_300":
                argv = [executable, "--rx", "300", "-f", str(input_path)]
            else:
                return self._not_run(spec, "skipped", "No fixed invocation is registered.", executable=resolution.display)

            started_at = utc_now()
            start = time.monotonic()
            launch_argv = self._launch_argv(resolution, argv[1:])
            execution = self._execute(launch_argv, cwd=execution_cwd, stdin_data=stdin_data)
            if spec.tool_id in {"fsstat", "fls", "tsk_recover"} and len(disk_offsets) > 1:
                successful = int(execution["status"] == "completed")
                deadline = start + self.timeout
                for offset in disk_offsets[1:8]:
                    remaining_seconds = int(deadline - time.monotonic())
                    if remaining_seconds < 1 or cancel_requested(self.is_cancelled):
                        break
                    if spec.tool_id == "fsstat":
                        extra_argv = [executable, "-o", str(offset), str(input_path)]
                    elif spec.tool_id == "fls":
                        extra_argv = [executable, "-r", "-p", "-o", str(offset), str(input_path)]
                    else:
                        assert extracted_dir is not None
                        target = extracted_dir / f"partition-{offset}"
                        target.mkdir()
                        extra_argv = [executable, "-e", "-o", str(offset), str(input_path), str(target)]
                    extra = self._execute(
                        self._launch_argv(resolution, extra_argv[1:]),
                        cwd=execution_cwd,
                        timeout=remaining_seconds,
                    )
                    successful += int(extra["status"] == "completed")
                    heading = f"\n\n[Partition sector offset {offset}]\n"
                    for stream in ("stdout", "stderr"):
                        combined = execution[stream] + heading + extra[stream]
                        if len(combined.encode("utf-8", "replace")) > self.output_limit:
                            execution["output_truncated"] = True
                        execution[stream] = display_text(combined, self.output_limit)
                    execution["output_truncated"] = bool(execution["output_truncated"] or extra["output_truncated"])
                    if extra["status"] == "cancelled":
                        execution["status"] = "cancelled"
                        break
                if successful and execution["status"] not in {"cancelled", "timed_out"}:
                    execution["status"] = "completed"
                    execution["return_code"] = 0
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
            mouse_drawings: list[tuple[str, bytes, int]] = []
            http2_range_files: list[tuple[str, bytes, int]] = []
            if spec.tool_id == "tshark_usb_hid" and stdout:
                decoded_hid = self._decode_usb_hid(stdout)
                if decoded_hid:
                    stdout = display_text(stdout + "\n\n[Decoded USB HID keystrokes]\n" + decoded_hid, self.output_limit)
                mouse_drawings = self._decode_usb_mouse_svg(stdout)
                if mouse_drawings:
                    stdout = display_text(stdout + f"\n\n[USB mouse drawings] {len(mouse_drawings)} SVG artifact(s) recovered.", self.output_limit)
            elif spec.tool_id == "tshark_http2_ranges" and stdout:
                http2_range_files = self._decode_http2_range_artifacts(stdout)
                if http2_range_files:
                    stdout = display_text(stdout + f"\n\n[HTTP/2 Content-Range recovery] {len(http2_range_files)} complete file artifact(s) recovered.", self.output_limit)
            elif spec.tool_id == "tshark_fields" and stdout:
                decoded_payloads = self._decode_tshark_payloads(stdout)
                if decoded_payloads:
                    stdout = display_text(stdout + "\n\n[Decoded packet payload text]\n" + decoded_payloads, self.output_limit)
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
                    } if spec.tool_id == "steghide" else ({
                        "partition_offsets": disk_offsets[:8],
                    } if spec.tool_id in {"fsstat", "fls", "tsk_recover"} else {}))
                ),
                "extracted": [],
            }
            for label, drawing, movement_count in mouse_drawings:
                method["extracted"].append({
                    "label": label, "data": drawing, "producer": "tshark_usb_hid",
                    "transformation": f"Accumulate {movement_count} USB HID relative mouse reports into SVG paths",
                    "offset": None, "kind": "svg",
                })
            for label, recovered, fragment_count in http2_range_files:
                method["extracted"].append({
                    "label": label, "data": recovered, "producer": "tshark_http2_ranges",
                    "transformation": f"Place {fragment_count} HTTP/2 DATA fragment(s) at Content-Range byte offsets",
                    "offset": None, "kind": sniff_kind(recovered, label),
                })
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
                            "hcxpcapngtool": ("wifi_handshake_hashcat_22000", "extract WPA PMKID/EAPOL material in hashcat mode 22000 format"),
                            "pcapfix": ("pcapfix_repaired", "repair a damaged PCAP/PCAPNG with pcapfix"),
                            "pdftotext": ("pdftotext_text", "extract PDF page text with Poppler"),
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
    def _raw_partition_offsets(path: Path) -> list[int]:
        """Return bounded MBR/GPT filesystem starts without mounting the image."""

        try:
            with path.open("rb") as handle:
                head = handle.read(1024 * 1024)
        except OSError:
            return []
        offsets: list[int] = []
        if len(head) >= 512 and head[510:512] == b"\x55\xaa":
            for index in range(4):
                entry = head[446 + index * 16:462 + index * 16]
                if len(entry) < 16 or entry[0] not in {0, 0x80} or entry[4] in {0, 0xEE}:
                    continue
                start = int.from_bytes(entry[8:12], "little")
                sectors = int.from_bytes(entry[12:16], "little")
                if start and sectors:
                    offsets.append(start)
        if len(head) >= 1024 and head[512:520] == b"EFI PART":
            entry_lba = int.from_bytes(head[584:592], "little")
            entry_count = min(int.from_bytes(head[592:596], "little"), 128)
            entry_size = int.from_bytes(head[596:600], "little")
            start_at = entry_lba * 512
            if 128 <= entry_size <= 4096 and start_at < len(head):
                for index in range(entry_count):
                    entry = head[start_at + index * entry_size:start_at + (index + 1) * entry_size]
                    if len(entry) < 48 or entry[:16] == b"\x00" * 16:
                        continue
                    first_lba = int.from_bytes(entry[32:40], "little")
                    last_lba = int.from_bytes(entry[40:48], "little")
                    if first_lba and last_lba >= first_lba:
                        offsets.append(first_lba)
        return sorted(dict.fromkeys(offsets))[:8]

    @staticmethod
    def _decode_tshark_payloads(output: str) -> str:
        """Decode bounded hex-valued TShark fields into candidate text."""

        recovered: list[str] = []
        seen: set[bytes] = set()
        total = 0
        for line in output.splitlines()[1:20_001]:
            for field in re.split(r"[|\t]", line):
                normalized = re.sub(r"[:,\s]", "", field)
                if len(normalized) < 8 or len(normalized) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", normalized):
                    continue
                try:
                    payload = bytes.fromhex(normalized)[:256 * 1024]
                except ValueError:
                    continue
                if payload in seen:
                    continue
                seen.add(payload)
                printable = sum(byte in b"\t\r\n" or 32 <= byte <= 126 for byte in payload)
                if not payload or printable / len(payload) < 0.55:
                    continue
                text_value = payload.decode("utf-8", "replace")
                recovered.append(display_text(text_value, 64 * 1024))
                total += len(text_value)
                if total >= 1024 * 1024 or len(recovered) >= 200:
                    return "\n".join(recovered)
        return "\n".join(recovered)

    @staticmethod
    def _decode_http2_range_artifacts(output: str) -> list[tuple[str, bytes, int]]:
        """Reassemble complete HTTP/2 objects from TShark's range/data fields."""

        # Key by HTTP/2 stream and declared object size. This prevents a
        # challenge that interleaves multiple downloads from combining them.
        groups: dict[tuple[str, int], tuple[bytearray, bytearray, int]] = {}
        range_re = re.compile(r"bytes\s*=\s*(\d+)\s*-\s*(\d+)\s*/\s*(\d+)", re.IGNORECASE)
        for line in output.splitlines()[:100_000]:
            fields = re.split(r"[|\t]", line)
            if len(fields) < 4:
                continue
            stream_id = fields[1].strip() or "unknown"
            matched = range_re.search(fields[2])
            encoded = re.sub(r"[:,\s]", "", fields[3])
            if not matched or len(encoded) % 2 or not re.fullmatch(r"[0-9A-Fa-f]+", encoded):
                continue
            start, end, total = (int(value) for value in matched.groups())
            if total <= 0 or total > 64 * 1024 * 1024 or start < 0 or end < start or end >= total:
                continue
            try:
                value = bytes.fromhex(encoded)
            except ValueError:
                continue
            if len(value) != end - start + 1:
                continue
            key = (stream_id, total)
            if key not in groups:
                groups[key] = (bytearray(total), bytearray(total), 0)
            target, present, fragments = groups[key]
            # First observed bytes win on a duplicate conflicting fragment so
            # a later retransmission cannot mutate a complete artifact.
            for index, byte in enumerate(value, start):
                if not present[index]:
                    target[index] = byte
                    present[index] = 1
            groups[key] = (target, present, fragments + 1)

        artifacts: list[tuple[str, bytes, int]] = []
        for (stream_id, total), (value, present, fragments) in sorted(groups.items()):
            if not all(present):
                continue
            label = f"http2_stream_{safe_label(stream_id) or 'unknown'}_range_{total}.bin"
            artifacts.append((label, bytes(value), fragments))
        return artifacts[:32]

    @staticmethod
    def _decode_usb_hid(output: str) -> str:
        """Decode conventional 8-byte boot-keyboard reports from TShark fields."""

        unshifted = {
            **{code: chr(ord("a") + code - 4) for code in range(4, 30)},
            **{code: value for code, value in zip(range(30, 40), "1234567890", strict=True)},
            40: "\n", 42: "\b", 43: "\t", 44: " ", 45: "-", 46: "=",
            47: "[", 48: "]", 49: "\\", 51: ";", 52: "'", 53: "`",
            54: ",", 55: ".", 56: "/",
        }
        shifted = {
            **{code: value.upper() for code, value in unshifted.items() if 4 <= code <= 29},
            **{code: value for code, value in zip(range(30, 40), "!@#$%^&*()", strict=True)},
            40: "\n", 42: "\b", 43: "\t", 44: " ", 45: "_", 46: "+",
            47: "{", 48: "}", 49: "|", 51: ":", 52: '"', 53: "~",
            54: "<", 55: ">", 56: "?",
        }
        states: dict[str, set[int]] = {}
        texts: dict[str, list[str]] = {}
        valid_counts: dict[str, int] = {}
        for line in output.splitlines()[:50_000]:
            fields = re.split(r"[|\t]", line)
            source = fields[0].strip() if fields else "unknown"
            candidates = fields[1:] if len(fields) > 1 else fields
            raw = next((value for value in candidates if value.strip()), "")
            normalized = re.sub(r"[:\s]", "", raw)
            if len(normalized) != 16 or not re.fullmatch(r"[0-9A-Fa-f]{16}", normalized):
                continue
            report = bytes.fromhex(normalized)
            if report[1] != 0 or any(code > 0xE7 for code in report[2:]):
                continue
            valid_counts[source] = valid_counts.get(source, 0) + 1
            current = {code for code in report[2:] if code}
            previous = states.get(source, set())
            mapping = shifted if report[0] & 0x22 else unshifted
            target = texts.setdefault(source, [])
            for code in report[2:]:
                if not code or code in previous:
                    continue
                value = mapping.get(code)
                if value == "\b":
                    if target:
                        target.pop()
                elif value:
                    target.append(value)
            states[source] = current
        decoded: list[str] = []
        for source, values in sorted(texts.items()):
            rendered = "".join(values).strip()
            if valid_counts.get(source, 0) >= 3 and len(rendered) >= 3:
                decoded.append(f"[{source or 'unknown device'}]\n{display_text(rendered, 64 * 1024)}")
        return "\n\n".join(decoded)

    @staticmethod
    def _decode_usb_mouse_svg(output: str) -> list[tuple[str, bytes, int]]:
        """Render likely HID relative-mouse reports to isolated SVG artifacts."""

        reports: dict[str, list[bytes]] = {}
        for line in output.splitlines()[:50_000]:
            fields = re.split(r"[|\t]", line)
            source = fields[0].strip() if fields else "unknown"
            raw = next((value for value in fields[1:] if value.strip()), "")
            normalized = re.sub(r"[:\s]", "", raw)
            if len(normalized) not in {6, 8, 10, 16} or not re.fullmatch(r"[0-9A-Fa-f]+", normalized):
                continue
            reports.setdefault(source, []).append(bytes.fromhex(normalized))

        def signed(value: int) -> int:
            return value - 256 if value >= 128 else value

        artifacts: list[tuple[str, bytes, int]] = []
        for source, values in sorted(reports.items()):
            # Boot mice use buttons, X, Y; report-ID prefixed variants shift
            # those fields right one byte. Select the layout with more bounded
            # non-zero movement, avoiding keyboard reports which use a reserved
            # zero byte and key codes instead of relative deltas.
            choices: list[tuple[int, list[tuple[int, int, bool]]]] = []
            for start in (0, 1):
                movements: list[tuple[int, int, bool]] = []
                for report in values:
                    if len(report) < start + 3:
                        continue
                    dx, dy = signed(report[start + 1]), signed(report[start + 2])
                    if abs(dx) > 100 or abs(dy) > 100:
                        continue
                    movements.append((dx, dy, bool(report[start] & 1)))
                useful = sum(bool(dx or dy) for dx, dy, _pressed in movements)
                choices.append((useful, movements))
            useful, movements = max(choices, key=lambda item: item[0], default=(0, []))
            if useful < 8:
                continue
            points = [(0, 0)]
            drawn = [(0, 0)]
            x = y = 0
            for dx, dy, pressed in movements:
                x += dx
                y -= dy  # HID Y is down; SVG Y is also down after inversion.
                points.append((x, y))
                if pressed:
                    drawn.append((x, y))
            xs, ys = zip(*points, strict=True)
            width, height = max(xs) - min(xs), max(ys) - min(ys)
            if max(width, height) < 12:
                continue
            margin = 12
            view_box = f"{min(xs) - margin} {min(ys) - margin} {max(1, width + margin * 2)} {max(1, height + margin * 2)}"
            encode = lambda items: " ".join(f"{px},{py}" for px, py in items)
            svg = (
                f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view_box}" width="800" height="600">'
                '<rect width="100%" height="100%" fill="white"/>'
                f'<polyline fill="none" stroke="#9ca3af" stroke-width="1" points="{encode(points)}"/>'
                f'<polyline fill="none" stroke="#111827" stroke-width="2" points="{encode(drawn)}"/>'
                '</svg>'
            ).encode("utf-8")
            artifacts.append((f"usb_mouse_{safe_label(source) or 'device'}_drawing.svg", svg, useful))
        return artifacts[:16]

    @staticmethod
    def _launch_argv(resolution: ResolvedTool, arguments: list[str]) -> list[str]:
        if resolution.source == "native":
            return [str(resolution.launcher), *arguments]
        if resolution.source == "ruby":
            return [str(resolution.launcher), resolution.executable, *arguments]
        converted = [ExternalToolRunner._wsl_argument(value) for value in arguments]
        return [str(resolution.launcher), "--", resolution.executable, *converted]

    @staticmethod
    def _wsl_argument(value: str) -> str:
        """Translate fixed CLI options that embed a Windows output path."""

        direct = _windows_path_to_wsl(value)
        if direct != value:
            return direct
        for prefix in ("-o", "--out="):
            if value.startswith(prefix):
                suffix = value[len(prefix):]
                converted = _windows_path_to_wsl(suffix)
                if converted != suffix:
                    return prefix + converted
        head, separator, suffix = value.rpartition(",")
        if separator:
            converted = _windows_path_to_wsl(suffix)
            if converted != suffix:
                return head + separator + converted
        return value

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
            elif password is not None and value == f"-p{password}":
                redacted.append("-p<redacted>")
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
