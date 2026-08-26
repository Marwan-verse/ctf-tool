from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
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


TOOL_SPECS: tuple[ToolSpec, ...] = (
    ToolSpec("file", "file", "libmagic file identification", "identity", None, frozenset({"quick", "balanced", "deep"})),
    ToolSpec("exiftool", "exiftool", "ExifTool metadata", "metadata", None, frozenset({"quick", "balanced", "deep"})),
    ToolSpec("exiv2", "exiv2", "Exiv2 metadata cross-check", "metadata", None, frozenset({"balanced", "deep"})),
    ToolSpec("strings", "strings", "GNU/Unix strings cross-check", "strings", None, frozenset({"quick", "balanced", "deep"})),
    ToolSpec("identify", "identify", "ImageMagick decoded-image inspection", "identity", None, frozenset({"balanced", "deep"})),
    ToolSpec("pngcheck", "pngcheck", "pngcheck structure validation", "structure", frozenset({"png"}), frozenset({"quick", "balanced", "deep"})),
    ToolSpec("pngcrush", "pngcrush", "pngcrush lossless validation", "structure", frozenset({"png"}), frozenset({"deep"})),
    ToolSpec("jpeginfo", "jpeginfo", "jpeginfo structure validation", "structure", frozenset({"jpeg"}), frozenset({"quick", "balanced", "deep"})),
    ToolSpec("jpegtran", "jpegtran", "jpegtran lossless normalization", "repair", frozenset({"jpeg"}), frozenset({"balanced", "deep"})),
    ToolSpec("djpeg", "djpeg", "libjpeg pixel decode validation", "structure", frozenset({"jpeg"}), frozenset({"deep"})),
    ToolSpec("zsteg", "zsteg", "zsteg lossless steganography", "steganography", frozenset({"png", "bmp"}), frozenset({"balanced", "deep"})),
    ToolSpec("stegseek", "stegseek", "Stegseek JPEG extraction", "steganography", frozenset({"jpeg"}), frozenset({"balanced", "deep"})),
    ToolSpec("steghide", "steghide", "Steghide password extraction", "steganography", frozenset({"jpeg", "bmp"}), frozenset({"balanced", "deep"})),
    ToolSpec("outguess", "outguess", "OutGuess password extraction", "steganography", frozenset({"jpeg"}), frozenset({"balanced", "deep"})),
    ToolSpec("jpseek", "jpseek", "JPHide/JPSeek payload extraction", "steganography", frozenset({"jpeg"}), frozenset({"balanced", "deep"})),
    ToolSpec("jsteg", "jsteg", "JSteg JPEG coefficient extraction", "steganography", frozenset({"jpeg"}), frozenset({"balanced", "deep"})),
    ToolSpec("openstego", "openstego", "OpenStego RandomLSB extraction", "steganography", frozenset({"png", "bmp"}), frozenset({"balanced", "deep"})),
    ToolSpec("binwalk", "binwalk", "Binwalk signature scan", "embedded-data", None, frozenset({"balanced", "deep"})),
    ToolSpec("foremost", "foremost", "Foremost header/footer carving", "embedded-data", None, frozenset({"deep"})),
    ToolSpec("7z", "7z", "7-Zip embedded/archive listing", "embedded-data", None, frozenset({"deep"})),
    ToolSpec("tiffinfo", "tiffinfo", "libtiff tiffinfo", "structure", frozenset({"tiff"}), frozenset({"balanced", "deep"})),
    ToolSpec("tiffdump", "tiffdump", "libtiff directory dump", "structure", frozenset({"tiff"}), frozenset({"deep"})),
    ToolSpec("webpinfo", "webpinfo", "WebP RIFF inspection", "structure", frozenset({"webp"}), frozenset({"quick", "balanced", "deep"})),
    ToolSpec("webpmux", "webpmux", "WebP container and animation inspection", "structure", frozenset({"webp"}), frozenset({"balanced", "deep"})),
    ToolSpec("gifsicle", "gifsicle", "Gifsicle animation inspection", "animation", frozenset({"gif"}), frozenset({"balanced", "deep"})),
    ToolSpec("tesseract", "tesseract", "Tesseract OCR command-line cross-check", "ocr", None, frozenset({"balanced", "deep"})),
    ToolSpec("zbarimg", "zbarimg", "ZBar barcode command-line cross-check", "barcodes", None, frozenset({"balanced", "deep"})),
)


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
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for spec in TOOL_SPECS:
            if cancel_requested(self.is_cancelled):
                results.append(self._not_run(spec, "cancelled", "Job cancellation was requested."))
                continue
            if selected_tools is not None and spec.tool_id not in selected_tools:
                results.append(self._not_run(spec, "skipped", "Disabled in this job's analysis settings."))
                continue
            if not allow_extraction and spec.tool_id in {"foremost", "jpseek", "openstego", "outguess", "steghide", "stegseek"}:
                results.append(self._not_run(spec, "skipped", "External payload extraction is disabled in this job's settings."))
                continue
            if spec.kinds is not None and kind not in spec.kinds:
                results.append(self._not_run(spec, "skipped", f"Not applicable to detected {kind} input."))
                continue
            if profile not in spec.profiles:
                results.append(self._not_run(spec, "skipped", f"Disabled by the {profile} scan profile."))
                continue
            executable = shutil.which(spec.executable)
            if executable is None:
                results.append(self._not_run(spec, "missing", f"Optional executable {spec.executable!r} was not found on PATH."))
                continue
            results.append(
                self._run_spec(
                    spec,
                    Path(executable),
                    path,
                    profile,
                    password,
                    work_dir,
                    ocr_language,
                    zsteg_mode,
                    max_extracted_files,
                )
            )
        return results

    def _run_spec(
        self,
        spec: ToolSpec,
        executable: Path,
        input_path: Path,
        profile: str,
        password: str | None,
        work_dir: Path,
        ocr_language: str,
        zsteg_mode: str,
        max_extracted_files: int,
    ) -> dict[str, Any]:
        extracted_path: Path | None = None
        extracted_dir: Path | None = None
        stdin_data: bytes | None = None
        with tempfile.TemporaryDirectory(prefix=f"{spec.tool_id}-", dir=str(work_dir)) as temp_name:
            temp_dir = Path(temp_name)
            if spec.tool_id == "file":
                argv = [str(executable), "--brief", "--mime-type", str(input_path)]
            elif spec.tool_id == "exiftool":
                argv = [str(executable), "-j", "-G1", "-s", str(input_path)]
            elif spec.tool_id == "exiv2":
                argv = [str(executable), "-pa", str(input_path)]
            elif spec.tool_id == "strings":
                argv = [str(executable), "-a", "-n", "4", str(input_path)]
            elif spec.tool_id == "identify":
                argv = [str(executable), "-verbose", str(input_path)]
            elif spec.tool_id == "pngcheck":
                argv = [str(executable), "-v", str(input_path)]
            elif spec.tool_id == "pngcrush":
                argv = [str(executable), "-n", "-v", str(input_path)]
            elif spec.tool_id == "jpeginfo":
                argv = [str(executable), "-c", str(input_path)]
            elif spec.tool_id == "jpegtran":
                extracted_path = temp_dir / "jpegtran_normalized.jpg"
                argv = [str(executable), "-copy", "all", "-outfile", str(extracted_path), str(input_path)]
            elif spec.tool_id == "djpeg":
                extracted_path = temp_dir / "djpeg_decoded.ppm"
                argv = [str(executable), "-verbose", "-outfile", str(extracted_path), str(input_path)]
            elif spec.tool_id == "zsteg":
                argv = [str(executable), "--lsb" if zsteg_mode == "lsb" else "-a", str(input_path)]
            elif spec.tool_id == "stegseek":
                if password is not None:
                    extracted_path = temp_dir / "stegseek_payload.bin"
                    argv = [str(executable), "--quiet", "--extract", str(input_path), str(extracted_path), "-p", password]
                elif profile == "deep":
                    argv = [str(executable), "--seed", str(input_path)]
                else:
                    return self._not_run(spec, "skipped", "A password was not supplied; seed scanning is reserved for Deep mode.", executable=str(executable))
            elif spec.tool_id == "steghide":
                if password is None:
                    return self._not_run(spec, "skipped", "A passphrase is required for bounded Steghide extraction.", executable=str(executable))
                extracted_path = temp_dir / "steghide_payload.bin"
                argv = [str(executable), "extract", "-sf", str(input_path), "-p", password, "-xf", str(extracted_path), "-f"]
            elif spec.tool_id == "outguess":
                if password is None:
                    return self._not_run(spec, "skipped", "A passphrase is required for bounded OutGuess extraction.", executable=str(executable))
                extracted_path = temp_dir / "outguess_payload.bin"
                argv = [str(executable), "-k", password, "-r", str(input_path), str(extracted_path)]
            elif spec.tool_id == "jpseek":
                extracted_path = temp_dir / "jpseek_payload.bin"
                argv = [str(executable), str(input_path), str(extracted_path)]
                stdin_data = ((password or "") + "\n").encode("utf-8")
            elif spec.tool_id == "jsteg":
                argv = [str(executable), "reveal", str(input_path)]
            elif spec.tool_id == "openstego":
                extracted_dir = temp_dir / "openstego-output"
                extracted_dir.mkdir()
                argv = [
                    str(executable), "extract", "-a", "randomlsb", "--cryptalgo", "AES128",
                    "-sf", str(input_path), "-xd", str(extracted_dir), "-p", password or "",
                ]
            elif spec.tool_id == "binwalk":
                argv = [str(executable), "--signature", "--quiet", str(input_path)]
            elif spec.tool_id == "foremost":
                extracted_dir = temp_dir / "foremost-output"
                argv = [str(executable), "-Q", "-i", str(input_path), "-o", str(extracted_dir)]
            elif spec.tool_id == "7z":
                argv = [str(executable), "l", "-slt", "--", str(input_path)]
            elif spec.tool_id == "tiffinfo":
                argv = [str(executable), str(input_path)]
            elif spec.tool_id == "tiffdump":
                argv = [str(executable), str(input_path)]
            elif spec.tool_id == "webpinfo":
                argv = [str(executable), str(input_path)]
            elif spec.tool_id == "webpmux":
                argv = [str(executable), "-info", str(input_path)]
            elif spec.tool_id == "gifsicle":
                argv = [str(executable), "--info", str(input_path)]
            elif spec.tool_id == "tesseract":
                argv = [str(executable), str(input_path), "stdout", "-l", ocr_language, "--psm", "6"]
            elif spec.tool_id == "zbarimg":
                argv = [str(executable), "--quiet", "--raw", str(input_path)]
            else:
                return self._not_run(spec, "skipped", "No fixed invocation is registered.", executable=str(executable))

            started_at = utc_now()
            start = time.monotonic()
            execution = self._execute(argv, cwd=temp_dir, stdin_data=stdin_data)
            duration_ms = int((time.monotonic() - start) * 1000)
            stdout = self._sanitize(execution["stdout"], input_path, temp_dir, password)
            stderr = self._sanitize(execution["stderr"], input_path, temp_dir, password)
            public_argv = self._redacted_argv(spec.tool_id, argv, password, input_path, temp_dir)
            status = execution["status"]
            if spec.tool_id == "zbarimg" and status == "completed" and execution["return_code"] == 4:
                execution["return_code"] = 0
            if status == "completed" and execution["return_code"] not in (0, None):
                status = "failed"
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
                    "resolved": str(executable),
                    "version": self._version(spec, executable),
                },
                "command": public_argv,
                "return_code": execution["return_code"],
                "stdout": display_text(stdout, self.output_limit),
                "stderr": display_text(stderr, self.output_limit),
                "output_truncated": execution["output_truncated"],
                "summary": self._summary(status, execution["return_code"], stdout, stderr),
                "metadata": {},
                "extracted": [],
            }
            if spec.tool_id == "exiftool" and stdout:
                try:
                    parsed = json.loads(stdout)
                    if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                        metadata = dict(parsed[0])
                        metadata.pop("SourceFile", None)
                        method["metadata"] = normalize_json(metadata)
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
                            "jpseek": ("jpseek_payload", "extract a JPHide payload with JPSeek"),
                        }
                        label, transformation = labels.get(spec.tool_id, (f"{spec.tool_id}_output", "external tool output"))
                        method["extracted"].append({
                            "label": label, "data": payload, "producer": spec.tool_id,
                            "transformation": transformation,
                            "offset": None, "kind": sniff_kind(payload),
                        })
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
                        if candidate.is_symlink() or not candidate.is_file():
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
            return method

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
        try:
            process.terminate()
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
            except OSError:
                pass

    def _version(self, spec: ToolSpec, executable: Path) -> str | None:
        if spec.tool_id in self._version_cache:
            return self._version_cache[spec.tool_id]
        if spec.tool_id == "jpseek":
            self._version_cache[spec.tool_id] = None
            return None
        version_args = {
            "exiftool": ["-ver"], "gifsicle": ["--version"], "file": ["--version"],
            "strings": ["--version"], "pngcheck": ["-V"], "jpeginfo": ["--version"],
            "zsteg": ["--version"], "stegseek": ["--version"], "binwalk": ["--version"],
            "tiffinfo": ["--version"], "webpinfo": ["-version"],
            "exiv2": ["--version"], "identify": ["-version"], "pngcrush": ["-version"],
            "jpegtran": ["-version"], "djpeg": ["-version"], "steghide": ["--version"],
            "outguess": ["-h"], "7z": [], "tiffdump": ["--version"], "webpmux": ["-version"],
            "tesseract": ["--version"], "zbarimg": ["--version"],
            "foremost": ["-V"], "jpseek": [], "jsteg": ["--help"], "openstego": ["--version"],
        }.get(spec.tool_id, ["--version"])
        result = self._execute([str(executable), *version_args], cwd=executable.parent, timeout=4)
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
