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
    ToolSpec("strings", "strings", "GNU/Unix strings cross-check", "strings", None, frozenset({"quick", "balanced", "deep"})),
    ToolSpec("pngcheck", "pngcheck", "pngcheck structure validation", "structure", frozenset({"png"}), frozenset({"quick", "balanced", "deep"})),
    ToolSpec("jpeginfo", "jpeginfo", "jpeginfo structure validation", "structure", frozenset({"jpeg"}), frozenset({"quick", "balanced", "deep"})),
    ToolSpec("zsteg", "zsteg", "zsteg lossless steganography", "steganography", frozenset({"png", "bmp"}), frozenset({"balanced", "deep"})),
    ToolSpec("stegseek", "stegseek", "Stegseek JPEG extraction", "steganography", frozenset({"jpeg"}), frozenset({"balanced", "deep"})),
    ToolSpec("binwalk", "binwalk", "Binwalk signature scan", "embedded-data", None, frozenset({"balanced", "deep"})),
    ToolSpec("tiffinfo", "tiffinfo", "libtiff tiffinfo", "structure", frozenset({"tiff"}), frozenset({"balanced", "deep"})),
    ToolSpec("webpinfo", "webpinfo", "WebP RIFF inspection", "structure", frozenset({"webp"}), frozenset({"quick", "balanced", "deep"})),
    ToolSpec("gifsicle", "gifsicle", "Gifsicle animation inspection", "animation", frozenset({"gif"}), frozenset({"balanced", "deep"})),
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
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for spec in TOOL_SPECS:
            if cancel_requested(self.is_cancelled):
                results.append(self._not_run(spec, "cancelled", "Job cancellation was requested."))
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
            results.append(self._run_spec(spec, Path(executable), path, profile, password, work_dir))
        return results

    def _run_spec(
        self,
        spec: ToolSpec,
        executable: Path,
        input_path: Path,
        profile: str,
        password: str | None,
        work_dir: Path,
    ) -> dict[str, Any]:
        extracted_path: Path | None = None
        with tempfile.TemporaryDirectory(prefix=f"{spec.tool_id}-", dir=str(work_dir)) as temp_name:
            temp_dir = Path(temp_name)
            if spec.tool_id == "file":
                argv = [str(executable), "--brief", "--mime-type", str(input_path)]
            elif spec.tool_id == "exiftool":
                argv = [str(executable), "-j", "-G1", "-s", str(input_path)]
            elif spec.tool_id == "strings":
                argv = [str(executable), "-a", "-n", "4", str(input_path)]
            elif spec.tool_id == "pngcheck":
                argv = [str(executable), "-v", str(input_path)]
            elif spec.tool_id == "jpeginfo":
                argv = [str(executable), "-c", str(input_path)]
            elif spec.tool_id == "zsteg":
                argv = [str(executable), "-a", str(input_path)]
            elif spec.tool_id == "stegseek":
                if password is not None:
                    extracted_path = temp_dir / "stegseek_payload.bin"
                    argv = [str(executable), "--quiet", "--extract", str(input_path), str(extracted_path), "-p", password]
                elif profile == "deep":
                    argv = [str(executable), "--seed", str(input_path)]
                else:
                    return self._not_run(spec, "skipped", "A password was not supplied; seed scanning is reserved for Deep mode.", executable=str(executable))
            elif spec.tool_id == "binwalk":
                argv = [str(executable), "--signature", "--quiet", str(input_path)]
            elif spec.tool_id == "tiffinfo":
                argv = [str(executable), str(input_path)]
            elif spec.tool_id == "webpinfo":
                argv = [str(executable), str(input_path)]
            elif spec.tool_id == "gifsicle":
                argv = [str(executable), "--info", str(input_path)]
            else:
                return self._not_run(spec, "skipped", "No fixed invocation is registered.", executable=str(executable))

            started_at = utc_now()
            start = time.monotonic()
            execution = self._execute(argv, cwd=temp_dir)
            duration_ms = int((time.monotonic() - start) * 1000)
            stdout = self._sanitize(execution["stdout"], input_path, temp_dir)
            stderr = self._sanitize(execution["stderr"], input_path, temp_dir)
            public_argv = self._redacted_argv(spec.tool_id, argv, password, input_path, temp_dir)
            status = execution["status"]
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
                        method["extracted"].append({
                            "label": "stegseek_payload", "data": payload, "producer": "stegseek",
                            "transformation": "extract Steghide-compatible payload with supplied password",
                            "offset": None, "kind": sniff_kind(payload),
                        })
                    elif size:
                        method["extraction_warning"] = f"Extracted payload size {size} exceeded the adapter limit."
                except OSError as exc:
                    method["extraction_warning"] = f"Could not read extracted payload: {display_text(exc, 200)}"
            return method

    def _execute(self, argv: list[str], *, cwd: Path, timeout: int | None = None) -> dict[str, Any]:
        status = "completed"
        output_truncated = False
        return_code: int | None = None
        with tempfile.TemporaryFile(mode="w+b") as stdout_file, tempfile.TemporaryFile(mode="w+b") as stderr_file:
            kwargs: dict[str, Any] = {
                "args": argv,
                "cwd": str(cwd),
                "stdin": subprocess.DEVNULL,
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
        version_args = {
            "exiftool": ["-ver"], "gifsicle": ["--version"], "file": ["--version"],
            "strings": ["--version"], "pngcheck": ["-V"], "jpeginfo": ["--version"],
            "zsteg": ["--version"], "stegseek": ["--version"], "binwalk": ["--version"],
            "tiffinfo": ["--version"], "webpinfo": ["-version"],
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
            if value == "-p":
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
    def _sanitize(text: str, input_path: Path, temp_dir: Path) -> str:
        sanitized = text.replace(str(input_path), f"<input>/{input_path.name}")
        sanitized = sanitized.replace(str(temp_dir), "<temporary>")
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
