"""Report normalization, artifact discovery, and safe export generation."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import html
import json
import math
import mimetypes
import os
import zipfile
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from .security import normalize_display_filename, require_regular_file, resolve_under


REPORT_CSS = """
:root{color-scheme:dark;--bg:#070b14;--panel:#101827;--panel2:#151f32;--line:#26344e;--text:#edf3ff;--muted:#9aabc6;--cyan:#4de3d1;--purple:#a78bfa;--amber:#fbbf24;--red:#fb7185}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0,#14213c 0,transparent 34%),var(--bg);color:var(--text);font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{width:min(1120px,calc(100% - 32px));margin:36px auto 72px}header{padding:28px;border:1px solid var(--line);border-radius:20px;background:linear-gradient(135deg,rgba(77,227,209,.09),rgba(167,139,250,.07)),var(--panel)}
h1{margin:0 0 4px;font-size:32px;letter-spacing:-.04em}h2{margin:0 0 18px;font-size:20px}p{margin:6px 0}.eyebrow{color:var(--cyan);font-size:12px;font-weight:800;letter-spacing:.14em;text-transform:uppercase}.muted{color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin-top:20px}.metric,.card{border:1px solid var(--line);background:rgba(16,24,39,.9);border-radius:14px;padding:16px}.metric span{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.08em}.metric strong{display:block;margin-top:5px;font-size:16px;overflow-wrap:anywhere}
section{margin-top:24px;border:1px solid var(--line);border-radius:18px;background:rgba(16,24,39,.82);padding:22px}.badge{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:999px;padding:4px 9px;font-size:12px;font-weight:700}.completed{color:var(--cyan)}.failed,.cancelled{color:var(--red)}
table{width:100%;border-collapse:collapse}th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.07em}code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:#c4b5fd;overflow-wrap:anywhere}
pre{max-height:680px;overflow:auto;border:1px solid var(--line);border-radius:12px;padding:16px;background:#060a12;color:#cbd5e1;font:12px/1.55 ui-monospace,SFMono-Regular,Consolas,monospace;white-space:pre-wrap;word-break:break-word}.empty{color:var(--muted);font-style:italic}.flag{font-size:17px;color:var(--cyan)}footer{margin-top:22px;color:var(--muted);font-size:12px;text-align:center}
""".strip()


def report_csp() -> str:
    digest = base64.b64encode(hashlib.sha256(REPORT_CSS.encode("utf-8")).digest()).decode("ascii")
    return (
        "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; "
        f"style-src 'sha256-{digest}'"
    )


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def json_safe(value: Any, *, base_dir: Path | None = None, depth: int = 0) -> Any:
    """Convert analyzer output to bounded, serializable values without raw bytes."""

    if depth > 16:
        return "<maximum nesting depth reached>"
    if value is None or isinstance(value, (str, bool, int)):
        if isinstance(value, str) and len(value) > 200_000:
            return value[:200_000] + f"\n… <{len(value) - 200_000} characters omitted>"
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, Path):
        resolved = value.resolve(strict=False)
        if base_dir is not None:
            root = base_dir.resolve(strict=False)
            if root in resolved.parents:
                return resolved.relative_to(root).as_posix()
        return value.name
    if isinstance(value, bytes):
        return {"encoding": "hex", "size": len(value), "preview": value[:64].hex()}
    if isinstance(value, Enum):
        return json_safe(value.value, base_dir=base_dir, depth=depth + 1)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return json_safe(dataclasses.asdict(value), base_dir=base_dir, depth=depth + 1)
    if hasattr(value, "model_dump"):
        return json_safe(value.model_dump(mode="json"), base_dir=base_dir, depth=depth + 1)
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 5_000:
                result["_truncated"] = f"{len(value) - 5_000} entries omitted"
                break
            result[str(key)] = json_safe(item, base_dir=base_dir, depth=depth + 1)
        return result
    if isinstance(value, (list, tuple, set, frozenset)):
        sequence = list(value)
        converted = [json_safe(item, base_dir=base_dir, depth=depth + 1) for item in sequence[:5_000]]
        if len(sequence) > 5_000:
            converted.append({"_truncated": f"{len(sequence) - 5_000} entries omitted"})
        return converted
    return str(value)


_SENSITIVE_INPUT_KEYS = {
    "input_password",
    "provided_password",
    "password_input",
    "supplied_password",
    "password_supplied",
}


def redact_sensitive_inputs(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): ("<redacted>" if str(key).lower() in _SENSITIVE_INPUT_KEYS else redact_sensitive_inputs(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive_inputs(item) for item in value]
    return value


def normalize_report(raw_report: Any, *, job_dir: Path, max_bytes: int) -> dict[str, Any]:
    safe = redact_sensitive_inputs(json_safe(raw_report, base_dir=job_dir))
    report: dict[str, Any]
    if isinstance(safe, dict):
        report = safe
    else:
        report = {"summary": safe}
    report.setdefault("schema_version", "1.0")
    report.setdefault("generated_at", _utc_now())
    errors = report.get("errors")
    report["partial"] = bool(report.get("partial") or (isinstance(errors, list) and errors))

    encoded = json.dumps(report, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) <= max_bytes:
        return report

    compact = _compact_report(report)
    compact["report_truncated"] = True
    compact["report_original_bytes"] = len(encoded)
    compact["partial"] = True
    encoded = json.dumps(compact, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > max_bytes:
        return {
            "schema_version": "1.0",
            "generated_at": _utc_now(),
            "partial": True,
            "report_truncated": True,
            "report_original_bytes": len(encoded),
            "summary": "Analyzer output exceeded the configured report limit.",
        }
    return compact


def _compact_report(value: Any, *, depth: int = 0) -> Any:
    if depth > 8:
        return "<nested data omitted>"
    if isinstance(value, str):
        return value if len(value) <= 20_000 else value[:20_000] + "\n… <output truncated>"
    if isinstance(value, dict):
        compact: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 500:
                compact["_truncated"] = "Additional fields omitted"
                break
            compact[str(key)] = _compact_report(item, depth=depth + 1)
        return compact
    if isinstance(value, list):
        result = [_compact_report(item, depth=depth + 1) for item in value[:500]]
        if len(value) > 500:
            result.append({"_truncated": f"{len(value) - 500} entries omitted"})
        return result
    return value


def sha256_file(path: Path, *, is_cancelled: Callable[[], bool] | None = None) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def sniff_media_type(path: Path) -> tuple[str, bool]:
    try:
        with path.open("rb") as handle:
            head = handle.read(16)
    except OSError:
        return "application/octet-stream", False
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png", True
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg", True
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif", True
    if len(head) >= 12 and head.startswith(b"RIFF") and head[8:12] == b"WEBP":
        return "image/webp", True
    guessed, _ = mimetypes.guess_type(path.name)
    if guessed in {"text/html", "image/svg+xml", "application/xhtml+xml"}:
        return guessed, False
    return guessed or "application/octet-stream", False


def deterministic_artifact_id(job_id: str, relative_path: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"forenscope:{job_id}:{relative_path}"))


def input_artifact_record(
    *,
    job_id: str,
    original_filename: str,
    relative_path: str,
    content_type: str,
    size_bytes: int,
    sha256: str,
) -> dict[str, Any]:
    return {
        "id": deterministic_artifact_id(job_id, relative_path),
        "job_id": job_id,
        "parent_id": None,
        "name": original_filename,
        "kind": "original",
        "relative_path": relative_path,
        "media_type": content_type or "application/octet-stream",
        "size_bytes": size_bytes,
        "sha256": sha256,
        "previewable": False,
        "metadata": {"immutable_source": True},
    }


_PATH_KEYS = ("relative_path", "path", "output_path", "file")


def _artifact_descriptor_map(report: Mapping[str, Any], output_dir: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    roots: list[Any] = []
    for key in ("artifacts", "artifact_tree", "outputs", "extracted_files"):
        if key in report:
            roots.append(report[key])

    def visit(value: Any) -> None:
        if isinstance(value, list):
            for item in value:
                visit(item)
            return
        if not isinstance(value, dict):
            return
        raw_path = next((value.get(key) for key in _PATH_KEYS if isinstance(value.get(key), str)), None)
        if raw_path:
            candidate = Path(raw_path)
            try:
                absolute = candidate.resolve(strict=False) if candidate.is_absolute() else (output_dir / candidate).resolve(strict=False)
                root = output_dir.resolve(strict=False)
                if root in absolute.parents:
                    result[absolute.relative_to(root).as_posix()] = value
            except (OSError, ValueError):
                pass
        for key in ("children", "artifacts", "outputs", "items"):
            if key in value:
                visit(value[key])

    for root_value in roots:
        visit(root_value)
    return result


def discover_artifacts(
    *,
    job_id: str,
    job_dir: Path,
    output_dir: Path,
    report: Mapping[str, Any],
    maximum: int,
    is_cancelled: Callable[[], bool] | None = None,
) -> list[dict[str, Any]]:
    """Index regular output files without following links or trusting report paths."""

    if not output_dir.exists():
        return []
    descriptors = _artifact_descriptor_map(report, output_dir)
    artifacts: list[dict[str, Any]] = []
    root = output_dir.resolve(strict=True)
    for directory, directory_names, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        directory_names[:] = [name for name in directory_names if not (directory_path / name).is_symlink()]
        for filename in sorted(filenames):
            if len(artifacts) >= maximum:
                return artifacts
            if is_cancelled is not None and is_cancelled():
                return artifacts
            raw_path = directory_path / filename
            if raw_path.is_symlink():
                continue
            try:
                path = resolve_under(root, raw_path.relative_to(root), must_exist=True)
                if not path.is_file():
                    continue
                stat = path.stat()
            except (OSError, ValueError):
                continue
            output_relative = path.relative_to(root).as_posix()
            job_relative = f"output/{output_relative}"
            descriptor = descriptors.get(output_relative, {})
            media_type, previewable = sniff_media_type(path)
            declared_media = descriptor.get("media_type") or descriptor.get("mime_type")
            if isinstance(declared_media, str) and media_type == "application/octet-stream":
                media_type = declared_media[:127]
            raw_name = descriptor.get("name") or descriptor.get("label") or path.name
            name = normalize_display_filename(str(raw_name), fallback="artifact.bin")
            kind = str(descriptor.get("kind") or descriptor.get("type") or "artifact")[:80]
            metadata = {
                str(key): value
                for key, value in descriptor.items()
                if key not in {*_PATH_KEYS, "children", "artifacts", "outputs", "items", "name", "label", "kind", "type"}
            }
            artifacts.append(
                {
                    "id": deterministic_artifact_id(job_id, job_relative),
                    "job_id": job_id,
                    "parent_id": descriptor.get("parent_id") if isinstance(descriptor.get("parent_id"), str) else None,
                    "name": name,
                    "kind": kind,
                    "relative_path": job_relative,
                    "media_type": media_type,
                    "size_bytes": stat.st_size,
                    "sha256": sha256_file(path, is_cancelled=is_cancelled),
                    "previewable": previewable,
                    "metadata": json_safe(metadata, base_dir=job_dir),
                }
            )
    return artifacts


def artifact_public_record(artifact: Mapping[str, Any]) -> dict[str, Any]:
    job_id = str(artifact["job_id"])
    artifact_id = str(artifact["id"])
    base = f"/api/jobs/{job_id}/artifacts/{artifact_id}"
    return {
        "id": artifact_id,
        "job_id": job_id,
        "parent_id": artifact.get("parent_id"),
        "name": artifact["name"],
        "kind": artifact.get("kind", "artifact"),
        "media_type": artifact.get("media_type", "application/octet-stream"),
        "size_bytes": int(artifact.get("size_bytes", 0)),
        "sha256": artifact.get("sha256", ""),
        "created_at": artifact.get("created_at", ""),
        "metadata": artifact.get("metadata") or {},
        "artifact_url": base,
        "download_url": f"{base}/download",
        "preview_url": f"{base}/preview" if artifact.get("previewable") else None,
    }


_PUBLIC_JOB_FIELDS = (
    "id",
    "status",
    "profile",
    "original_filename",
    "content_type",
    "size_bytes",
    "sha256",
    "flag_prefix",
    "options",
    "progress",
    "current_stage",
    "cancel_requested",
    "created_at",
    "updated_at",
    "started_at",
    "completed_at",
    "result",
)


def job_public_record(job: Mapping[str, Any], artifacts: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    job_id = str(job["id"])
    public = {field: job.get(field) for field in _PUBLIC_JOB_FIELDS}
    public["cancel_requested"] = bool(public.get("cancel_requested"))
    if job.get("error_code"):
        public["error"] = {
            "code": str(job["error_code"]),
            "message": str(job.get("error_message") or "Analysis failed"),
        }
    else:
        public["error"] = None
    public["artifacts"] = [artifact_public_record(artifact) for artifact in artifacts]
    public["events_url"] = f"/api/jobs/{job_id}/events"
    public["report_urls"] = {
        "json": f"/api/jobs/{job_id}/report.json",
        "html": f"/api/jobs/{job_id}/report.html",
        "zip": f"/api/jobs/{job_id}/report.zip",
    }
    return public


def build_export_payload(job: Mapping[str, Any], artifacts: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    public_job = job_public_record(job, artifacts)
    return {
        "schema_version": "1.0",
        "exported_at": _utc_now(),
        "application": {"name": "Forenscope", "section": "image"},
        "job": {key: value for key, value in public_job.items() if key not in {"result", "artifacts"}},
        "result": public_job.get("result"),
        "artifacts": public_job["artifacts"],
    }


def _flag_candidates(result: Any) -> list[dict[str, Any]]:
    if not isinstance(result, dict):
        return []
    values = result.get("candidates") or result.get("flag_candidates") or []
    if not isinstance(values, list):
        return []
    candidates: list[dict[str, Any]] = []
    for value in values:
        if isinstance(value, str):
            candidates.append({"value": value, "confidence": "unknown", "source": "analysis"})
        elif isinstance(value, dict):
            candidates.append(value)
    return candidates[:1_000]


def render_html_report(payload: Mapping[str, Any]) -> str:
    job = payload.get("job") if isinstance(payload.get("job"), dict) else {}
    result = payload.get("result")
    artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), list) else []
    candidates = _flag_candidates(result)

    def e(value: Any) -> str:
        return html.escape("" if value is None else str(value), quote=True)

    candidate_rows = "".join(
        "<tr>"
        f"<td><code class=\"flag\">{e(candidate.get('value') or candidate.get('flag') or candidate.get('text'))}</code></td>"
        f"<td>{e(candidate.get('confidence', 'unknown'))}</td>"
        f"<td>{e(candidate.get('source') or candidate.get('method') or 'analysis')}</td>"
        "</tr>"
        for candidate in candidates
    )
    artifact_rows = "".join(
        "<tr>"
        f"<td>{e(item.get('name'))}</td><td>{e(item.get('kind'))}</td>"
        f"<td>{e(item.get('media_type'))}</td><td>{e(item.get('size_bytes'))}</td>"
        f"<td><code>{e(item.get('sha256'))}</code></td>"
        "</tr>"
        for item in artifacts
        if isinstance(item, dict)
    )
    candidate_table = (
        "<table><thead><tr><th>Candidate</th><th>Confidence</th><th>Source</th></tr></thead>"
        f"<tbody>{candidate_rows}</tbody></table>"
        if candidate_rows
        else '<p class="empty">No candidate flags were reported.</p>'
    )
    artifact_table = (
        "<table><thead><tr><th>Name</th><th>Kind</th><th>Media type</th><th>Bytes</th>"
        f"<th>SHA-256</th></tr></thead><tbody>{artifact_rows}</tbody></table>"
        if artifact_rows
        else '<p class="empty">No artifacts were indexed.</p>'
    )
    detailed_json = html.escape(json.dumps(payload, ensure_ascii=False, indent=2), quote=False)
    status = str(job.get("status") or "unknown")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Forenscope report — {e(job.get('original_filename'))}</title><style>{REPORT_CSS}</style></head>
<body><main><header><div class="eyebrow">Forenscope · Image analysis</div><h1>Forensic analysis report</h1>
<p class="muted">Reproducible evidence summary for <strong>{e(job.get('original_filename'))}</strong></p>
<div class="grid"><div class="metric"><span>Status</span><strong class="{e(status)}">{e(status.upper())}</strong></div>
<div class="metric"><span>Profile</span><strong>{e(job.get('profile'))}</strong></div>
<div class="metric"><span>SHA-256</span><strong><code>{e(job.get('sha256'))}</code></strong></div>
<div class="metric"><span>Artifacts</span><strong>{len(artifacts)}</strong></div></div></header>
<section><h2>Candidate flags</h2>{candidate_table}</section>
<section><h2>Artifacts</h2>{artifact_table}</section>
<section><h2>Complete structured result</h2><pre>{detailed_json}</pre></section>
<footer>Generated locally by Forenscope at {e(payload.get('exported_at'))}. The source evidence was not modified.</footer>
</main></body></html>"""


def report_json_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def write_report_zip(
    target: Path,
    *,
    payload: Mapping[str, Any],
    artifacts: Sequence[Mapping[str, Any]],
    job_dir: Path,
) -> None:
    """Write an export bundle using generated archive names only."""

    manifest_entries: list[dict[str, Any]] = []
    with zipfile.ZipFile(target, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr("report.json", report_json_bytes(payload))
        archive.writestr("report.html", render_html_report(payload).encode("utf-8"))
        for artifact in artifacts:
            try:
                relative_path = str(artifact["relative_path"])
                source = require_regular_file(job_dir, relative_path)
            except (KeyError, OSError, ValueError):
                continue
            artifact_id = str(artifact.get("id") or deterministic_artifact_id(str(artifact["job_id"]), relative_path))
            safe_name = normalize_display_filename(str(artifact.get("name") or source.name), fallback="artifact.bin")
            archive_name = f"artifacts/{artifact_id}/{safe_name}"
            archive.write(source, archive_name)
            manifest_entries.append(
                {
                    "id": artifact_id,
                    "archive_path": archive_name,
                    "name": safe_name,
                    "size_bytes": int(artifact.get("size_bytes", source.stat().st_size)),
                    "sha256": str(artifact.get("sha256") or sha256_file(source)),
                    "kind": str(artifact.get("kind") or "artifact"),
                }
            )
        manifest = {
            "schema_version": "1.0",
            "job_id": payload.get("job", {}).get("id") if isinstance(payload.get("job"), dict) else None,
            "source_sha256": payload.get("job", {}).get("sha256") if isinstance(payload.get("job"), dict) else None,
            "artifacts": manifest_entries,
        }
        archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"))
