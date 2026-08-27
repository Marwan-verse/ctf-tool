from __future__ import annotations

import bz2
import gzip
import io
import json
import lzma
import os
import re
import time
import uuid
import zipfile
from collections import Counter, deque
from pathlib import Path
from typing import Any, Callable, Iterable

from .analyzers.common import (
    AnalyzerCancelled,
    PROFILE_LIMITS,
    bounded_read,
    cancel_requested,
    check_cancelled,
    display_text,
    extension_for,
    mime_for,
    normalize_json,
    safe_label,
    sha256_bytes,
    sha256_file,
    sniff_kind,
    utc_now,
)
from .analyzers.audio import AUDIO_KINDS, analyze_audio
from .analyzers.core import BoundedDecoder, CandidateCollector, inspect_bytes
from .analyzers.crypto import analyze_encrypted_payloads
from .analyzers.external import ExternalToolRunner, TOOL_SPECS
from .analyzers.formats import analyze_format
from .analyzers.visual import analyze_visual


SUPPORTED_IMAGE_FORMATS = ["PNG/APNG", "JPEG/MPO", "GIF", "BMP", "WebP", "TIFF/BigTIFF", "ICO/CUR"]
SUPPORTED_AUDIO_FORMATS = ["WAV/PCM", "AIFF/AIFC", "FLAC", "Ogg/Opus", "MP3", "AAC/M4A", "AU", "WMA/ASF", "AMR", "CAF", "MIDI"]


class ArtifactStore:
    """Write immutable derived artifacts with deduplication and lineage."""

    def __init__(self, output_dir: Path, job_id: str, limits: dict[str, int], source_path: Path, source_kind: str, source_sha: str) -> None:
        self.output_dir = output_dir.resolve()
        self.artifact_dir = (self.output_dir / f"{job_id}_artifacts").resolve()
        if not _is_relative_to(self.artifact_dir, self.output_dir):
            raise ValueError("artifact directory resolved outside output directory")
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.limits = limits
        self.artifacts: list[dict[str, Any]] = []
        self._by_id: dict[str, dict[str, Any]] = {}
        self._by_hash: dict[str, str] = {}
        self._counter = 0
        self.total_derived_bytes = 0
        source_id = self._next_id()
        source = {
            "id": source_id,
            "kind": "source",
            "detected_type": source_kind,
            "mime_type": mime_for(source_kind, source_path.name),
            "name": display_text(source_path.name, 255),
            "size": source_path.stat().st_size,
            "sha256": source_sha,
            "relative_path": None,
            "parent_ids": [],
            "lineage": [{"parent_id": None, "producer": "ingest", "transformation": "immutable source evidence", "offset": 0}],
            "depth": 0,
            "safe_preview": False,
            "repair_candidate": False,
            "deduplicated": False,
        }
        self.source_id = source_id
        self.artifacts.append(source)
        self._by_id[source_id] = source
        self._by_hash[source_sha] = source_id

    def _next_id(self) -> str:
        self._counter += 1
        return f"artifact-{self._counter:04d}"

    def get(self, artifact_id: str) -> dict[str, Any]:
        return self._by_id[artifact_id]

    def add_bytes(
        self,
        data: bytes,
        *,
        label: str,
        parent_id: str,
        producer: str,
        transformation: str,
        offset: int | None = None,
        kind: str | None = None,
        depth: int | None = None,
        safe_preview: bool = False,
        repair_candidate: bool = False,
        parameters: dict[str, Any] | None = None,
        reason: str | None = None,
    ) -> tuple[str | None, bool, str | None]:
        if not isinstance(data, bytes):
            data = bytes(data)
        if not data:
            return None, False, "empty artifact"
        if len(data) > self.limits["max_single_artifact"]:
            return None, False, f"single-artifact limit exceeded ({len(data)} bytes)"
        digest = sha256_bytes(data)
        lineage = {
            "parent_id": parent_id, "producer": safe_label(producer),
            "transformation": display_text(transformation, 1000), "offset": offset,
            "parameters": normalize_json(parameters or {}),
        }
        if reason:
            lineage["reason"] = display_text(reason, 1000)
        if digest in self._by_hash:
            artifact_id = self._by_hash[digest]
            artifact = self._by_id[artifact_id]
            if lineage not in artifact["lineage"] and len(artifact["lineage"]) < 100:
                artifact["lineage"].append(lineage)
            if parent_id not in artifact["parent_ids"] and len(artifact["parent_ids"]) < 100:
                artifact["parent_ids"].append(parent_id)
            artifact["deduplicated"] = True
            return artifact_id, False, None
        if len(self.artifacts) >= self.limits["max_artifacts"]:
            return None, False, "artifact-count limit exceeded"
        if self.total_derived_bytes + len(data) > self.limits["max_artifact_bytes"]:
            return None, False, "total derived-byte limit exceeded"
        detected = kind or sniff_kind(data, label)
        if detected == "binary" and safe_preview:
            safe_preview = False
        artifact_id = self._next_id()
        filename = f"{artifact_id}_{safe_label(label)}{extension_for(detected)}"
        target = (self.artifact_dir / filename).resolve()
        if not _is_relative_to(target, self.artifact_dir):
            return None, False, "generated path failed containment check"
        with open(target, "xb") as handle:
            handle.write(data)
            handle.flush()
        parent = self._by_id[parent_id]
        artifact = {
            "id": artifact_id,
            "kind": "repair" if repair_candidate else ("visual" if safe_preview else "derived"),
            "detected_type": detected,
            "mime_type": mime_for(detected, filename),
            "name": display_text(label, 255),
            "size": len(data),
            "sha256": digest,
            "relative_path": target.relative_to(self.output_dir).as_posix(),
            "parent_ids": [parent_id],
            "lineage": [lineage],
            "depth": parent.get("depth", 0) + 1 if depth is None else depth,
            "safe_preview": bool(safe_preview),
            "repair_candidate": bool(repair_candidate),
            "deduplicated": False,
        }
        self.artifacts.append(artifact)
        self._by_id[artifact_id] = artifact
        self._by_hash[digest] = artifact_id
        self.total_derived_bytes += len(data)
        return artifact_id, True, None


class AnalysisEngine:
    """Synchronous, local-first media and corrupted-file forensics orchestrator.

    The engine never mutates the source. Every generated byte sequence is
    bounded, written under ``output_dir``, hashed, and linked to its parent.
    Missing optional dependencies are reportable coverage states, not errors.
    """

    def run(
        self,
        input_path: Path | str,
        output_dir: Path | str,
        profile: str,
        flag_prefix: str | None,
        password: str | None,
        progress_callback: Callable[..., Any] | None,
        is_cancelled: Callable[[], bool] | Any,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        profile = (profile or "balanced").lower().strip()
        if profile not in PROFILE_LIMITS:
            raise ValueError(f"unknown analysis profile {profile!r}; expected quick, balanced, or deep")
        source_path = Path(input_path).expanduser().resolve(strict=True)
        if not source_path.is_file():
            raise ValueError("input_path must identify a regular file")
        destination = Path(output_dir).expanduser().resolve()
        destination.mkdir(parents=True, exist_ok=True)
        if not destination.is_dir():
            raise ValueError("output_dir must identify a directory")

        analysis_options = {
            "structure_analysis": True,
            "visual_analysis": True,
            "lsb_analysis": True,
            "ocr": True,
            "barcodes": True,
            "recursive_extraction": True,
            "decoders": True,
            "crypto_analysis": True,
            "repairs": True,
            "external_tools": True,
            "external_extraction": True,
            "external_output_kib": 1024,
            "max_external_files": 32,
            "foremost_depth": 2,
            "color_remap_variants": 8,
            "zsteg_mode": "all",
            "ocr_language": "eng",
            "selected_external_tools": None,
        }
        if isinstance(options, dict):
            analysis_options.update(options)
        limits = dict(PROFILE_LIMITS[profile])
        if isinstance(analysis_options.get("max_recursion_depth"), int):
            limits["recursion_depth"] = max(1, min(4, int(analysis_options["max_recursion_depth"])))
        if isinstance(analysis_options.get("max_artifacts"), int):
            limits["max_artifacts"] = max(25, min(500, int(analysis_options["max_artifacts"])))
        if isinstance(analysis_options.get("tool_timeout_seconds"), int):
            limits["tool_timeout"] = max(5, min(180, int(analysis_options["tool_timeout_seconds"])))
        probe_data, _ = bounded_read(source_path, min(limits["read_bytes"], 1024 * 1024))
        probe_kind = sniff_kind(probe_data, source_path.name)
        evidence_type = str(analysis_options.get("evidence_type") or "auto")
        if evidence_type == "audio" or (evidence_type != "corrupted" and probe_kind in AUDIO_KINDS):
            return self._run_audio(
                source_path=source_path,
                destination=destination,
                profile=profile,
                flag_prefix=flag_prefix,
                password=password,
                progress_callback=progress_callback,
                is_cancelled=is_cancelled,
                analysis_options=analysis_options,
                limits=limits,
            )
        report_section = "corrupted" if evidence_type == "corrupted" else "image"
        job_id = f"analysis-{uuid.uuid4().hex[:12]}"
        started_at = utc_now()
        start_monotonic = time.monotonic()
        logs: list[dict[str, Any]] = []
        methods: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        visual_views: list[dict[str, Any]] = []
        metadata: dict[str, Any] = {}
        errors: list[dict[str, str]] = []
        collector = CandidateCollector(flag_prefix)

        self._emit(progress_callback, 1, "ingest", "Hashing immutable source evidence")
        check_cancelled(is_cancelled)
        source_size = source_path.stat().st_size
        source_sha = sha256_file(source_path)
        source_data, read_truncated = bounded_read(source_path, limits["read_bytes"])
        source_kind = sniff_kind(source_data, source_path.name)
        store = ArtifactStore(destination, job_id, limits, source_path, source_kind, source_sha)
        source_id = store.source_id
        report_status = "running"
        source_extension = source_path.suffix.lower()

        def log(level: str, message: str, method_id: str | None = None, **details: Any) -> None:
            if len(logs) >= 5_000:
                return
            logs.append({
                "timestamp": utc_now(), "level": level, "method_id": method_id,
                "message": display_text(message, 1000), "details": normalize_json(details),
            })

        def add_finding(item: dict[str, Any], artifact_id: str = source_id, method_id: str = "built-in-structure") -> None:
            finding = {
                "id": f"finding-{len(findings) + 1:04d}",
                "severity": item.get("severity", "info"),
                "category": item.get("category", "general"),
                "title": display_text(item.get("title", "Finding"), 200),
                "description": display_text(item.get("description", ""), 2000),
                "artifact_id": artifact_id,
                "method_id": method_id,
                "details": normalize_json(item.get("details", {})),
            }
            findings.append(finding)

        log("info", "Source hashed; original bytes will not be modified.", "ingest", sha256=source_sha, size=source_size)
        if read_truncated:
            add_finding({
                "severity": "warning", "category": "resource-limit", "title": "Byte inspection was bounded",
                "description": f"The source is larger than the {limits['read_bytes']} byte profile read limit. Full-file hashing completed, but byte parsers inspect only the bounded prefix.",
                "details": {"source_size": source_size, "inspected_bytes": len(source_data)},
            }, source_id, "built-in-core")

        extension_kind = _kind_from_extension(source_extension)
        if extension_kind and extension_kind != source_kind:
            add_finding({
                "severity": "warning", "category": "identity", "title": "Extension and content disagree",
                "description": f"Filename extension suggests {extension_kind}, while magic bytes indicate {source_kind}.",
                "details": {"extension": source_extension, "extension_kind": extension_kind, "detected_kind": source_kind},
            }, source_id, "built-in-core")

        core_details: dict[str, Any] = {}
        format_root: dict[str, Any] | None = None
        derived_queue: deque[tuple[str, bytes, str, int]] = deque()
        processed_artifacts: set[str] = set()
        all_string_seeds: list[dict[str, Any]] = []
        repair_artifact_ids: list[str] = []

        try:
            self._emit(progress_callback, 6, "core", "Scanning raw bytes, signatures, entropy, and strings")
            check_cancelled(is_cancelled)
            core_start = time.monotonic()
            core_details = inspect_bytes(source_data, max_strings=limits["max_strings"])
            collector.scan_bytes(source_data, source_artifact_id=source_id, method="raw-bytes")
            for record in core_details["strings"]:
                collector.scan_text(
                    record["text"], source_artifact_id=source_id, method=f"strings:{record['encoding']}",
                    offset=record["offset"], confidence_hint=3,
                )
            all_string_seeds.extend(core_details["strings"])
            methods.append({
                "id": "built-in-core", "name": "Hashes, magic signatures, entropy, and strings",
                "category": "identity", "status": "completed", "applicable": True,
                "started_at": started_at, "duration_ms": int((time.monotonic() - core_start) * 1000),
                "summary": f"Inspected {len(source_data)} byte(s), found {len(core_details['strings'])} string(s) and {len(core_details['magic_offsets'])} embedded signature hit(s).",
                "tool": {"executable": "Python stdlib", "resolved": None, "version": None},
                "details": {
                    "entropy": core_details["entropy"], "byte_frequency": core_details["byte_frequency"],
                    "magic_offsets": core_details["magic_offsets"],
                    "strings": [{**record, "text": display_text(record["text"], 4096)} for record in core_details["strings"][:2_000]],
                    "reported_strings_truncated": len(core_details["strings"]) > 2_000 or core_details["strings_truncated"],
                },
            })

            self._emit(progress_callback, 18, "structure", f"Parsing {source_kind.upper()} structure")
            check_cancelled(is_cancelled)
            structure_start = time.monotonic()
            if not analysis_options["structure_analysis"]:
                structure_status = "skipped"
                structure_summary = "Image-specific structural parsing was disabled in this job's settings."
                format_root = None
            elif read_truncated:
                structure_status = "skipped"
                structure_summary = "Structural parsing was skipped because the profile did not read the complete source."
                format_root = None
            else:
                format_root = analyze_format(source_kind, source_data, profile=profile)
                structure_status = "completed" if source_kind in {"png", "jpeg", "gif", "bmp", "webp", "tiff", "ico"} else "skipped"
                structure_summary = (
                    f"Parsed {source_kind} structure with {len(format_root['findings'])} notable finding(s), "
                    f"{len(format_root['extracted'])} extracted object(s), and {len(format_root['repairs'])} repair candidate(s)."
                    if structure_status == "completed" else f"No image-specific parser is registered for detected type {source_kind}."
                )
                for finding in format_root["findings"]:
                    add_finding(finding, source_id, "built-in-structure")
                metadata.update({f"built-in:{key}": value for key, value in format_root["metadata"].items()})
                for record in format_root["text_records"]:
                    method_name = _text_method(record.get("source", "structure"))
                    collector.scan_text(
                        record.get("text", ""), source_artifact_id=source_id, method=method_name,
                        offset=record.get("offset"), transform_chain=record.get("transform_chain"),
                        confidence_hint=int(record.get("confidence_hint", 8)),
                    )
                    all_string_seeds.append(record)
                for extracted in format_root["extracted"]:
                    artifact_id, created, reason = store.add_bytes(
                        extracted["data"], label=extracted["label"], parent_id=source_id,
                        producer=extracted.get("producer", "built-in-structure"),
                        transformation=extracted.get("transformation", "extract structured payload"),
                        offset=extracted.get("offset"), kind=extracted.get("kind"), depth=1,
                    )
                    if artifact_id:
                        collector.scan_bytes(extracted["data"], source_artifact_id=artifact_id, method="structured-extraction", confidence_hint=8)
                        if created:
                            derived_queue.append((artifact_id, extracted["data"], extracted.get("kind") or sniff_kind(extracted["data"]), 1))
                    elif reason:
                        log("warning", f"Skipped derived artifact {extracted['label']}: {reason}", "built-in-structure")
                for repair in format_root["repairs"] if analysis_options["repairs"] else []:
                    artifact_id, _, reason = store.add_bytes(
                        repair["data"], label=repair["label"], parent_id=source_id,
                        producer=repair.get("producer", "built-in-structure"),
                        transformation=repair.get("transformation", "create repair candidate"),
                        kind=source_kind, depth=1, repair_candidate=True, reason=repair.get("reason"),
                    )
                    if artifact_id:
                        repair_artifact_ids.append(artifact_id)
                        add_finding({
                            "severity": "info", "category": "repair", "title": "Derived repair candidate created",
                            "description": "A separate, hashed repair candidate was written; the original evidence was not modified.",
                            "details": {"repair_artifact_id": artifact_id, "transformation": repair.get("transformation"), "reason": repair.get("reason")},
                        }, source_id, "built-in-structure")
                    elif reason:
                        log("warning", f"Skipped repair candidate {repair['label']}: {reason}", "built-in-structure")
            methods.append({
                "id": "built-in-structure", "name": "Built-in image structure parser", "category": "structure",
                "status": structure_status, "applicable": structure_status != "skipped",
                "started_at": utc_now(), "duration_ms": int((time.monotonic() - structure_start) * 1000),
                "summary": structure_summary, "tool": {"executable": "Python stdlib", "resolved": None, "version": None},
                "details": normalize_json({"detected_type": source_kind, "properties": format_root["properties"] if format_root else {}}),
            })
            pcrt_applicable = source_kind == "png" and format_root is not None
            pcrt_repairs = len(format_root["repairs"]) if pcrt_applicable else 0
            methods.append({
                "id": "pcrt", "name": "PCRT-compatible PNG check and repair", "category": "repair",
                "status": "completed" if pcrt_applicable else "skipped", "applicable": source_kind == "png",
                "started_at": utc_now() if pcrt_applicable else None, "duration_ms": 0,
                "summary": (
                    f"Validated PNG chunks, CRCs, dimensions, trailing data, and {pcrt_repairs} repair candidate(s); "
                    f"repair output was {'enabled' if analysis_options['repairs'] else 'disabled'}."
                    if pcrt_applicable
                    else "PCRT-style PNG repair is only applicable to a completely read PNG input."
                ),
                "tool": {"executable": "Forenscope built-in", "resolved": "built-in", "version": "1"},
                "artifact_ids": repair_artifact_ids,
                "details": {"repairs_detected": pcrt_repairs, "repair_generation_enabled": bool(analysis_options["repairs"])},
            })

            if profile == "deep" and not read_truncated and analysis_options["recursive_extraction"]:
                self._emit(progress_callback, 27, "carving", "Carving bounded embedded signatures")
                carved_count = self._carve_signatures(core_details["magic_offsets"], source_data, source_id, store, derived_queue, log)
                methods.append({
                    "id": "built-in-carver", "name": "Bounded signature carver", "category": "embedded-data",
                    "status": "completed", "applicable": True, "started_at": utc_now(), "duration_ms": 0,
                    "summary": f"Created {carved_count} bounded carved artifact(s) from non-zero signature offsets.",
                    "tool": {"executable": "Python stdlib", "resolved": None, "version": None}, "details": {},
                })
            else:
                methods.append({
                    "id": "built-in-carver", "name": "Bounded signature carver", "category": "embedded-data",
                    "status": "skipped", "applicable": True, "started_at": None, "duration_ms": 0,
                    "summary": "Signature carving requires Deep mode and recursive extraction to be enabled.",
                    "tool": {"executable": "Python stdlib", "resolved": None, "version": None}, "details": {},
                })

            self._emit(progress_callback, 32, "recursive", "Analyzing extracted artifacts and safe archive members")
            recursive_start = time.monotonic()
            recursive_processed = 0
            archive_members = 0
            while analysis_options["recursive_extraction"] and derived_queue and len(store.artifacts) < limits["max_artifacts"]:
                check_cancelled(is_cancelled)
                artifact_id, artifact_data, artifact_kind, depth = derived_queue.popleft()
                if artifact_id in processed_artifacts or depth > limits["recursion_depth"]:
                    continue
                processed_artifacts.add(artifact_id)
                recursive_processed += 1
                collector.scan_bytes(artifact_data, source_artifact_id=artifact_id, method="recursive-raw", confidence_hint=5)
                local_core = inspect_bytes(artifact_data, max_strings=min(2_000, limits["max_strings"]))
                for record in local_core["strings"]:
                    collector.scan_text(record["text"], source_artifact_id=artifact_id, method=f"recursive-strings:{record['encoding']}", offset=record["offset"], confidence_hint=5)
                    if len(all_string_seeds) < limits["max_strings"] * 2:
                        all_string_seeds.append({**record, "artifact_id": artifact_id})
                if artifact_kind in {"png", "jpeg", "gif", "bmp", "webp", "tiff", "ico"}:
                    nested = analyze_format(artifact_kind, artifact_data, profile=profile)
                    for finding in nested["findings"]:
                        add_finding(finding, artifact_id, "recursive-structure")
                    for record in nested["text_records"]:
                        collector.scan_text(record.get("text", ""), source_artifact_id=artifact_id, method=_text_method(record.get("source", "recursive-structure")), offset=record.get("offset"), confidence_hint=8)
                        if len(all_string_seeds) < limits["max_strings"] * 2:
                            all_string_seeds.append({**record, "artifact_id": artifact_id})
                    if depth < limits["recursion_depth"]:
                        for extracted in nested["extracted"]:
                            child_id, created, reason = store.add_bytes(
                                extracted["data"], label=extracted["label"], parent_id=artifact_id,
                                producer=extracted.get("producer", "recursive-structure"),
                                transformation=extracted.get("transformation", "recursive structured extraction"),
                                offset=extracted.get("offset"), kind=extracted.get("kind"), depth=depth + 1,
                            )
                            if child_id and created:
                                derived_queue.append((child_id, extracted["data"], extracted.get("kind") or sniff_kind(extracted["data"]), depth + 1))
                            elif reason:
                                log("warning", f"Skipped nested artifact {extracted['label']}: {reason}", "recursive-structure")
                if artifact_kind in {"zip", "gzip", "bzip2", "xz"} and depth < limits["recursion_depth"]:
                    members = self._expand_archive(artifact_data, artifact_kind, artifact_id, depth, store, derived_queue, add_finding, log, password=password)
                    archive_members += members
            methods.append({
                "id": "recursive-analysis", "name": "Recursive artifact and archive analysis", "category": "embedded-data",
                "status": "completed" if analysis_options["recursive_extraction"] else "skipped",
                "applicable": True, "started_at": utc_now() if analysis_options["recursive_extraction"] else None,
                "duration_ms": int((time.monotonic() - recursive_start) * 1000),
                "summary": (
                    f"Recursively inspected {recursive_processed} artifact(s) and safely extracted {archive_members} archive member(s)."
                    if analysis_options["recursive_extraction"]
                    else "Recursive extraction was disabled in this job's settings."
                ),
                "tool": {"executable": "Python stdlib", "resolved": None, "version": None},
                "details": {"recursion_depth_limit": limits["recursion_depth"], "artifacts_processed": recursive_processed, "archive_members": archive_members},
            })

            self._emit(progress_callback, 46, "visual", "Generating safe pixel, channel, bit-plane, frame, OCR, and barcode views")
            check_cancelled(is_cancelled)
            visual_result = analyze_visual(
                source_path,
                profile=profile,
                max_megapixels=limits["visual_megapixels"],
                enabled=bool(analysis_options["visual_analysis"]),
                lsb_analysis=bool(analysis_options["lsb_analysis"]),
                ocr=bool(analysis_options["ocr"]),
                barcodes=bool(analysis_options["barcodes"]),
                ocr_language=str(analysis_options["ocr_language"]),
                color_remap_variants=int(analysis_options["color_remap_variants"]),
            )
            for item in visual_result.pop("findings", []):
                add_finding(item, source_id, "pillow-visual")
            metadata.update({f"pillow:{key}": value for key, value in visual_result.get("metadata", {}).items()})
            visual_records = visual_result.pop("text_records", [])
            all_string_seeds.extend(visual_records[: limits["max_strings"]])
            for record in visual_records:
                method_name = _text_method(record.get("source", "visual"))
                collector.scan_text(
                    record.get("text", ""), source_artifact_id=source_id, method=method_name,
                    offset=record.get("offset"), transform_chain=record.get("transform_chain"),
                    confidence_hint=int(record.get("confidence_hint", 0)),
                )
            raw_visuals = visual_result.pop("visuals", [])
            visual_submethods = visual_result.pop("submethods", [])
            for order, item in enumerate(raw_visuals):
                artifact_id, _, reason = store.add_bytes(
                    item["data"], label=item["label"], parent_id=source_id,
                    producer=item.get("producer", "Pillow"), transformation=item.get("transformation", "visual transform"),
                    kind="png", safe_preview=True, parameters=item.get("parameters"),
                )
                if artifact_id:
                    artifact = store.get(artifact_id)
                    visual_views.append({
                        "id": f"visual-{len(visual_views) + 1:04d}", "artifact_id": artifact_id,
                        "title": display_text(item.get("title", item["label"]), 200),
                        "category": _visual_category(item["label"]), "order": order,
                        "width": item.get("width"), "height": item.get("height"),
                        "parameters": normalize_json(item.get("parameters", {})),
                        "relative_path": artifact["relative_path"],
                    })
                elif reason:
                    log("warning", f"Skipped visual view {item['label']}: {reason}", "pillow-visual")
            stego_streams = visual_result.pop("stego_streams", [])
            for stream in stego_streams:
                hits = collector.scan_bytes(
                    stream["data"], source_artifact_id=source_id, method="built-in-lsb",
                    transform_chain=[stream["transformation"]], confidence_hint=5,
                )
                artifact_id, _, reason = store.add_bytes(
                    stream["data"], label=stream["label"], parent_id=source_id,
                    producer=stream.get("producer", "built-in-lsb"),
                    transformation=stream["transformation"], kind=stream.get("kind"),
                    parameters=stream.get("parameters"),
                )
                if artifact_id and hits:
                    add_finding({
                        "severity": "info", "category": "steganography", "title": "Flag-like text in pixel bitstream",
                        "description": "A bounded channel/bit-order extraction produced flag-like text.",
                        "details": {"stream_artifact_id": artifact_id, "transformation": stream["transformation"]},
                    }, source_id, "built-in-lsb")
                elif reason:
                    log("warning", f"Skipped bitstream artifact {stream['label']}: {reason}", "built-in-lsb")
            methods.append(_public_method(visual_result))
            if visual_submethods:
                methods.extend(_public_method(method) for method in visual_submethods)
            else:
                methods.extend([
                    {
                        "id": "decomposer", "name": "Bit-layer decomposer", "category": "visual",
                        "status": "skipped", "applicable": True, "started_at": None, "duration_ms": 0,
                        "summary": "Bit-layer decomposition did not run because decoded-pixel analysis was unavailable or disabled.",
                        "tool": {"executable": "Forenscope built-in", "resolved": "built-in", "version": "1"}, "details": {},
                    },
                    {
                        "id": "color_remapping", "name": "Color remapping", "category": "visual",
                        "status": "skipped", "applicable": True, "started_at": None, "duration_ms": 0,
                        "summary": "Color remapping did not run because decoded-pixel analysis was unavailable, disabled, or configured for zero variants.",
                        "tool": {"executable": "Forenscope built-in", "resolved": "built-in", "version": "1"}, "details": {},
                    },
                ])

            self._emit(progress_callback, 63, "decoders", "Exploring bounded text encodings and compression layers")
            check_cancelled(is_cancelled)
            decode_start = time.monotonic()
            decoder = BoundedDecoder(
                max_depth=limits["decode_depth"], max_nodes=limits["decode_nodes"],
                max_output=min(limits["max_single_artifact"], 16 * 1024 * 1024),
            )
            decoded_nodes = decoder.explore(all_string_seeds) if analysis_options["decoders"] else []
            decoded_artifact_map: dict[str, str] = {}
            decoder_artifacts = 0
            for node in decoded_nodes:
                check_cancelled(is_cancelled)
                seed_artifact = source_id
                # Seeds gathered from recursive artifacts carry their source id.
                if node.parent_id and node.parent_id in decoded_artifact_map:
                    seed_artifact = decoded_artifact_map[node.parent_id]
                hits = collector.scan_bytes(
                    node.data, source_artifact_id=seed_artifact, method="decoder",
                    base_offset=node.source_offset or 0, transform_chain=node.chain, confidence_hint=6,
                )
                kind = sniff_kind(node.data)
                text_ratio = _text_ratio(node.data)
                if hits or kind != "binary" or text_ratio >= 0.72:
                    artifact_id, created, reason = store.add_bytes(
                        node.data, label=f"decoded_{node.transform}_{node.node_id}", parent_id=seed_artifact,
                        producer="bounded-decoder", transformation=node.transform,
                        offset=node.source_offset, kind=kind, parameters={"chain": node.chain, "depth": node.depth},
                    )
                    if artifact_id:
                        decoded_artifact_map[node.node_id] = artifact_id
                        decoder_artifacts += int(created)
                    elif reason:
                        log("warning", f"Skipped decoded artifact {node.node_id}: {reason}", "bounded-decoder")
            methods.append({
                "id": "bounded-decoder", "name": "Recursive encoding and compression decoder", "category": "decoding",
                "status": "completed" if analysis_options["decoders"] else "skipped",
                "applicable": True, "started_at": utc_now() if analysis_options["decoders"] else None,
                "duration_ms": int((time.monotonic() - decode_start) * 1000),
                "summary": (
                    f"Explored {len(decoded_nodes)} unique bounded transform result(s) and retained {decoder_artifacts} artifact(s)."
                    if analysis_options["decoders"]
                    else "Recursive text and compression decoding was disabled in this job's settings."
                ),
                "tool": {"executable": "Python stdlib", "resolved": None, "version": None},
                "details": {"max_depth": limits["decode_depth"], "max_nodes": limits["decode_nodes"], "result_count": len(decoded_nodes)},
            })

            self._emit(progress_callback, 72, "external-tools", "Running applicable optional forensic tools")
            check_cancelled(is_cancelled)
            runner = ExternalToolRunner(
                timeout=limits["tool_timeout"],
                output_limit=max(64, min(2048, int(analysis_options["external_output_kib"]))) * 1024,
                is_cancelled=is_cancelled,
            )
            selected_tools = analysis_options.get("selected_external_tools")
            selected_tool_ids = set(selected_tools) if isinstance(selected_tools, list) else None
            if not analysis_options["external_tools"]:
                selected_tool_ids = set()
            else:
                excluded_tool_ids: set[str] = set()
                if not analysis_options["structure_analysis"]:
                    excluded_tool_ids.update(
                        spec.tool_id
                        for spec in TOOL_SPECS
                        if spec.category in {"metadata", "structure", "animation"}
                    )
                if not analysis_options["lsb_analysis"]:
                    excluded_tool_ids.add("zsteg")
                if not analysis_options["ocr"]:
                    excluded_tool_ids.add("tesseract")
                if not analysis_options["barcodes"]:
                    excluded_tool_ids.add("zbarimg")
                if not analysis_options["recursive_extraction"]:
                    excluded_tool_ids.update({"binwalk", "foremost", "7z"})
                if not analysis_options["repairs"]:
                    excluded_tool_ids.add("jpegtran")
                if excluded_tool_ids:
                    selected_tool_ids = (
                        {spec.tool_id for spec in TOOL_SPECS}
                        if selected_tool_ids is None
                        else selected_tool_ids
                    ) - excluded_tool_ids
            external_results = runner.run_all(
                source_path,
                kind=source_kind,
                profile=profile,
                password=password,
                work_dir=destination,
                ocr_language=str(analysis_options["ocr_language"]),
                selected_tools=selected_tool_ids,
                zsteg_mode=str(analysis_options["zsteg_mode"]),
                allow_extraction=bool(analysis_options["external_extraction"]),
                max_extracted_files=int(analysis_options["max_external_files"]),
                foremost_depth=int(analysis_options["foremost_depth"]),
            )
            for method in external_results:
                check_cancelled(is_cancelled) if method["status"] not in {"cancelled"} else None
                method_id = method["id"]
                collector.scan_text(method.get("stdout", ""), source_artifact_id=source_id, method=method_id, confidence_hint=4)
                collector.scan_text(method.get("stderr", ""), source_artifact_id=source_id, method=method_id, confidence_hint=2)
                for key, value in method.get("metadata", {}).items():
                    metadata[f"exiftool:{key}"] = value
                    for text_value in _iter_text_values(value):
                        collector.scan_text(text_value, source_artifact_id=source_id, method="metadata", confidence_hint=10, context=f"{key}: {text_value}")
                        if len(all_string_seeds) < limits["max_strings"] * 2:
                            all_string_seeds.append({"source": f"metadata:{key}", "offset": None, "text": text_value})
                extracted_items = method.pop("extracted", [])
                extracted_artifact_ids: list[str] = []
                for extracted in extracted_items:
                    artifact_id, created, reason = store.add_bytes(
                        extracted["data"], label=extracted["label"], parent_id=source_id,
                        producer=extracted.get("producer", method_id), transformation=extracted.get("transformation", "external extraction"),
                        offset=extracted.get("offset"), kind=extracted.get("kind"), depth=1,
                    )
                    if artifact_id:
                        extracted_artifact_ids.append(artifact_id)
                        collector.scan_bytes(extracted["data"], source_artifact_id=artifact_id, method=method_id, confidence_hint=12)
                    elif reason:
                        log("warning", f"Skipped {method_id} artifact {extracted['label']}: {reason}", method_id)
                method["artifact_ids"] = extracted_artifact_ids
                method["extracted_count"] = len(extracted_artifact_ids)
                if method["status"] in {"failed", "timed_out"}:
                    log("warning", method["summary"], method_id, return_code=method.get("return_code"))
                methods.append(_public_method(method))

            self._emit(progress_callback, 90, "crypto", "Detecting possible encrypted payloads and trying bounded recovery")
            check_cancelled(is_cancelled)
            crypto_start = time.monotonic()
            crypto_inputs: list[dict[str, Any]] = ([{
                "artifact_id": source_id, "label": "source", "kind": source_kind, "data": source_data,
            }] if analysis_options["crypto_analysis"] else [])
            crypto_budget = 64 * 1024 * 1024
            # Image containers are skipped by the crypto analyzer itself; do
            # not let their large compressed byte buffer consume the payload
            # budget needed for metadata, LSB, and extracted artifacts.
            crypto_bytes = (
                min(len(source_data), 4 * 1024 * 1024)
                if analysis_options["crypto_analysis"] and source_kind not in {"png", "jpeg", "gif", "bmp", "webp", "tiff", "ico"}
                else 0
            )
            known_artifact_ids = {str(artifact.get("id")) for artifact in store.artifacts}
            if analysis_options["crypto_analysis"]:
                for seed in all_string_seeds[:2_000]:
                    text_value = str(seed.get("text") or "").encode("utf-8", "replace")
                    if not text_value or crypto_bytes + len(text_value) > crypto_budget:
                        continue
                    crypto_inputs.append({
                        "artifact_id": seed.get("artifact_id") or source_id,
                        "label": f"{seed.get('source') or 'extracted string'}",
                        "kind": "text", "data": text_value,
                    })
                    crypto_bytes += len(text_value)
                for artifact in store.artifacts[1:]:
                    if crypto_bytes >= crypto_budget:
                        break
                    relative_path = artifact.get("relative_path")
                    if not relative_path:
                        continue
                    try:
                        artifact_path = (destination / str(relative_path)).resolve(strict=True)
                        if not _is_relative_to(artifact_path, destination) or not artifact_path.is_file():
                            continue
                        read_limit = min(4 * 1024 * 1024, crypto_budget - crypto_bytes)
                        artifact_data, _ = bounded_read(artifact_path, read_limit)
                    except (OSError, ValueError):
                        continue
                    if not artifact_data:
                        continue
                    crypto_inputs.append({
                        "artifact_id": artifact.get("id") or source_id,
                        "label": artifact.get("name") or "derived artifact",
                        "kind": artifact.get("detected_type") or "binary", "data": artifact_data,
                    })
                    crypto_bytes += len(artifact_data)
            crypto_result = analyze_encrypted_payloads(
                crypto_inputs,
                passphrase=password,
                enabled=bool(analysis_options["crypto_analysis"]),
            )
            crypto_detections = crypto_result.pop("detections", [])
            crypto_decryptions = crypto_result.pop("decryptions", [])
            crypto_artifact_ids: list[str] = []
            if crypto_detections:
                add_finding({
                    "severity": "info", "category": "crypto", "title": "Possible encrypted payload detected",
                    "description": "One or more extracted payloads have ciphertext-like signals. Supply a passphrase in scan setup to attempt bounded recovery.",
                    "details": {"payload_count": len(crypto_detections), "decrypted_count": len(crypto_decryptions)},
                }, source_id, "crypto-analysis")
            for decryption in crypto_decryptions:
                plaintext = decryption.pop("data", b"")
                if not isinstance(plaintext, bytes) or not plaintext:
                    continue
                parent_id = str(decryption.get("artifact_id") or source_id)
                if parent_id not in known_artifact_ids:
                    parent_id = source_id
                algorithm = str(decryption.get("algorithm") or "bounded decryption")
                artifact_id, _, reason = store.add_bytes(
                    plaintext,
                    label=f"decrypted_{algorithm}",
                    parent_id=parent_id,
                    producer="crypto-analysis",
                    transformation=f"decrypt {algorithm}",
                    kind=sniff_kind(plaintext),
                    parameters={"algorithm": algorithm, "encoding": decryption.get("encoding")},
                )
                if artifact_id:
                    crypto_artifact_ids.append(artifact_id)
                    hits = collector.scan_bytes(
                        plaintext, source_artifact_id=artifact_id, method="crypto-decryption",
                        transform_chain=[algorithm], confidence_hint=18,
                    )
                    if hits:
                        add_finding({
                            "severity": "high", "category": "crypto", "title": "Flag-like text recovered by decryption",
                            "description": "A bounded decryption attempt produced flag-shaped text; inspect the linked decrypted artifact and candidate provenance.",
                            "details": {"algorithm": algorithm, "decrypted_artifact_id": artifact_id},
                        }, parent_id, "crypto-decryption")
                elif reason:
                    log("warning", f"Skipped decrypted artifact: {reason}", "crypto-analysis")
            methods.append({
                "id": "crypto-analysis", "name": "Encrypted payload detection and recovery", "category": "crypto",
                "status": "completed" if analysis_options["crypto_analysis"] else "skipped", "applicable": True,
                "started_at": utc_now() if analysis_options["crypto_analysis"] else None,
                "duration_ms": int((time.monotonic() - crypto_start) * 1000),
                "summary": crypto_result.get("summary", "Encrypted-payload analysis was skipped."),
                "tool": {"executable": "Python stdlib + cryptography", "resolved": None, "version": None},
                "artifact_ids": crypto_artifact_ids,
                "details": {
                    "detections": crypto_detections[:100],
                    "decryption_results": crypto_decryptions[:64],
                    "attempts": crypto_result.get("attempts", 0),
                    "dependency_missing": crypto_result.get("dependency_missing", False),
                    "input_count": len(crypto_inputs),
                    "input_bytes": crypto_bytes,
                },
            })

            # Metadata collected late can contain layered encoding; run a small second pass.
            late_seeds = [seed for seed in all_string_seeds if str(seed.get("source", "")).startswith("metadata:")]
            if late_seeds and analysis_options["decoders"]:
                for node in BoundedDecoder(max_depth=min(2, limits["decode_depth"]), max_nodes=min(30, limits["decode_nodes"])).explore(late_seeds):
                    collector.scan_bytes(node.data, source_artifact_id=source_id, method="metadata-decoder", transform_chain=node.chain, confidence_hint=8)

            methods.extend([
                {
                    "id": "spectrogram", "name": "Spectrogram", "category": "audio",
                    "status": "skipped", "applicable": False, "started_at": None, "duration_ms": 0,
                    "summary": "Spectrogram analysis is available from Forenscope's Audio section and is not applicable to image evidence.",
                    "tool": {"executable": "FFmpeg", "resolved": None, "version": None}, "details": {},
                },
                {
                    "id": "pdfinfo", "name": "pdfinfo", "category": "document",
                    "status": "skipped", "applicable": False, "started_at": None, "duration_ms": 0,
                    "summary": "pdfinfo is not applicable to the image section.",
                    "tool": {"executable": "pdfinfo", "resolved": None, "version": None}, "details": {},
                },
                {
                    "id": "pdfid", "name": "PDFiD", "category": "document",
                    "status": "skipped", "applicable": False, "started_at": None, "duration_ms": 0,
                    "summary": "PDFiD is not applicable to the image section.",
                    "tool": {"executable": "pdfid", "resolved": None, "version": None}, "details": {},
                },
            ])

            report_status = "completed"
            self._emit(progress_callback, 98, "report", "Normalizing findings, coverage, and artifact lineage")
        except AnalyzerCancelled:
            report_status = "cancelled"
            log("info", "Analysis stopped at a cooperative cancellation boundary.", "engine")
        except Exception as exc:
            report_status = "failed"
            error = {"type": type(exc).__name__, "message": display_text(exc, 1000)}
            errors.append(error)
            log("error", f"Unexpected analysis error: {error['type']}: {error['message']}", "engine")

        completed_at = utc_now()
        candidates = collector.results()
        method_status_counts = Counter(method.get("status", "unknown") for method in methods)
        severity_counts = Counter(finding.get("severity", "info") for finding in findings)
        confidence_counts = Counter(candidate.get("confidence", "low") for candidate in candidates)
        missing_optional = [method["id"] for method in methods if method.get("status") == "missing"]
        coverage = {
            "profile": profile,
            "section": report_section,
            "supported_image_formats": SUPPORTED_IMAGE_FORMATS,
            "method_status_counts": dict(method_status_counts),
            "missing_optional_tools": missing_optional,
            "optional_tools_declared": [spec.tool_id for spec in TOOL_SPECS],
            "analysis_options": normalize_json(analysis_options),
            "limits": {
                "read_bytes": limits["read_bytes"], "max_artifacts": limits["max_artifacts"],
                "max_derived_bytes": limits["max_artifact_bytes"], "max_single_artifact": limits["max_single_artifact"],
                "decode_depth": limits["decode_depth"], "decode_nodes": limits["decode_nodes"],
                "recursion_depth": limits["recursion_depth"], "tool_timeout_seconds": limits["tool_timeout"],
                "visual_megapixels": limits["visual_megapixels"],
            },
            "source_read_complete": not read_truncated,
            "original_mutated": False,
        }
        report = {
            "schema_version": "1.0.0",
            "job_id": job_id,
            "section": report_section,
            "status": report_status,
            "profile": profile,
            "started_at": started_at,
            "completed_at": completed_at,
            "duration_ms": int((time.monotonic() - start_monotonic) * 1000),
            "source": {
                "artifact_id": source_id, "name": display_text(source_path.name, 255),
                "size": source_size, "sha256": source_sha, "detected_type": source_kind,
                "mime_type": mime_for(source_kind, source_path.name), "extension": source_extension,
                "extension_matches_content": not extension_kind or extension_kind == source_kind,
                "inspected_bytes": len(source_data), "inspection_truncated": read_truncated,
                "first_32_bytes_hex": source_data[:32].hex(),
            },
            "summary": {
                "candidate_count": len(candidates), "high_confidence_candidates": confidence_counts.get("high", 0),
                "finding_count": len(findings), "finding_severity_counts": dict(severity_counts),
                "artifact_count": len(store.artifacts), "derived_artifact_count": max(0, len(store.artifacts) - 1),
                "derived_bytes": store.total_derived_bytes, "visual_view_count": len(visual_views),
                "method_status_counts": dict(method_status_counts),
            },
            "metadata": normalize_json(metadata),
            "methods": normalize_json(methods),
            "findings": normalize_json(findings),
            "candidates": normalize_json(candidates),
            "artifacts": normalize_json(store.artifacts),
            "visual_views": normalize_json(visual_views),
            "logs": normalize_json(logs),
            "coverage": normalize_json(coverage),
            "errors": errors,
        }
        self._emit(progress_callback, 100, report_status, f"Analysis {report_status}", terminal=True)
        return report

    def _run_audio(
        self,
        *,
        source_path: Path,
        destination: Path,
        profile: str,
        flag_prefix: str | None,
        password: str | None,
        progress_callback: Callable[..., Any] | None,
        is_cancelled: Callable[[], bool] | Any,
        analysis_options: dict[str, Any],
        limits: dict[str, int],
    ) -> dict[str, Any]:
        """Run the bounded audio-specific pipeline while preserving shared evidence semantics."""

        job_id = f"analysis-{uuid.uuid4().hex[:12]}"
        started_at = utc_now()
        started = time.monotonic()
        logs: list[dict[str, Any]] = []
        methods: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        visual_views: list[dict[str, Any]] = []
        metadata: dict[str, Any] = {}
        errors: list[dict[str, str]] = []
        collector = CandidateCollector(flag_prefix)

        self._emit(progress_callback, 1, "audio-ingest", "Hashing immutable audio evidence")
        check_cancelled(is_cancelled)
        source_size = source_path.stat().st_size
        source_sha = sha256_file(source_path)
        source_data, read_truncated = bounded_read(source_path, limits["read_bytes"])
        detected_source_kind = sniff_kind(source_data, source_path.name)
        source_kind = detected_source_kind if detected_source_kind in AUDIO_KINDS else "audio"
        store = ArtifactStore(destination, job_id, limits, source_path, source_kind, source_sha)
        source_id = store.source_id
        all_string_seeds: list[dict[str, Any]] = []
        crypto_inputs: list[dict[str, Any]] = [{"artifact_id": source_id, "label": "audio source", "kind": source_kind, "data": source_data}]
        report_status = "running"

        def log(level: str, message: str, method_id: str | None = None, **details: Any) -> None:
            if len(logs) >= 5_000:
                return
            logs.append({
                "timestamp": utc_now(), "level": level, "method_id": method_id,
                "message": display_text(message, 1000), "details": normalize_json(details),
            })

        def add_finding(item: dict[str, Any], artifact_id: str = source_id, method_id: str = "built-in-audio") -> None:
            findings.append({
                "id": f"finding-{len(findings) + 1:04d}",
                "severity": item.get("severity", "info"),
                "category": item.get("category", "audio"),
                "title": display_text(item.get("title", "Audio finding"), 200),
                "description": display_text(item.get("description", ""), 2000),
                "artifact_id": artifact_id,
                "method_id": method_id,
                "details": normalize_json(item.get("details", {})),
            })

        log("info", "Audio source hashed; the original bytes will not be modified.", "audio-ingest", sha256=source_sha, size=source_size)
        if read_truncated:
            add_finding({
                "severity": "warning", "category": "resource-limit", "title": "Raw byte inspection was bounded",
                "description": f"Full-file hashing completed, but raw parsers inspected only {len(source_data)} of {source_size} byte(s).",
                "details": {"source_size": source_size, "inspected_bytes": len(source_data)},
            }, source_id, "built-in-core")

        try:
            self._emit(progress_callback, 8, "audio-core", "Scanning raw bytes, strings, signatures, and entropy")
            check_cancelled(is_cancelled)
            core_started = time.monotonic()
            core = inspect_bytes(source_data, max_strings=limits["max_strings"])
            collector.scan_bytes(source_data, source_artifact_id=source_id, method="audio-raw-bytes")
            for record in core["strings"]:
                collector.scan_text(
                    record["text"], source_artifact_id=source_id, method=f"audio-strings:{record['encoding']}",
                    offset=record["offset"], confidence_hint=3,
                )
            all_string_seeds.extend(core["strings"])
            methods.append({
                "id": "built-in-core", "name": "Hashes, signatures, entropy, and audio strings",
                "category": "identity", "status": "completed", "applicable": True,
                "started_at": started_at, "duration_ms": int((time.monotonic() - core_started) * 1000),
                "summary": f"Inspected {len(source_data)} byte(s), found {len(core['strings'])} string(s) and {len(core['magic_offsets'])} embedded signature hit(s).",
                "tool": {"executable": "Python stdlib", "resolved": "built-in", "version": None},
                "details": {
                    "entropy": core["entropy"], "byte_frequency": core["byte_frequency"],
                    "magic_offsets": core["magic_offsets"],
                    "strings": [{**item, "text": display_text(item["text"], 4096)} for item in core["strings"][:2_000]],
                    "reported_strings_truncated": len(core["strings"]) > 2_000 or core["strings_truncated"],
                },
            })

            self._emit(progress_callback, 24, "audio-signal", "Decoding PCM, waveform, spectrum, tones, phase, and sample bit planes")
            check_cancelled(is_cancelled)
            audio_result = analyze_audio(
                source_path,
                kind=source_kind,
                profile=profile,
                enabled=True,
                spectrogram_enabled=bool(analysis_options.get("audio_spectrogram", True) and analysis_options.get("visual_analysis", True)),
                signal_decoders=bool(analysis_options.get("audio_signal_decoders", True)),
                sstv_enabled=bool(analysis_options.get("audio_sstv", True)),
                channel_exports=bool(analysis_options.get("audio_channel_exports", True)),
                audacity_bundle=bool(analysis_options.get("audio_audacity_bundle", True)),
                lsb_enabled=bool(analysis_options.get("lsb_analysis", True)),
                analysis_seconds=int(analysis_options.get("audio_analysis_seconds", 180)),
                fft_size=int(analysis_options.get("audio_spectrogram_fft", 2048)),
                channel_mode=str(analysis_options.get("audio_channel_mode", "mix")),
                lsb_bits=int(analysis_options.get("audio_lsb_bits", 2)),
                sstv_mode=str(analysis_options.get("audio_sstv_mode", "auto")),
                sstv_max_images=int(analysis_options.get("audio_sstv_max_images", 2)),
                sstv_slant_correction=bool(analysis_options.get("audio_sstv_slant_correction", True)),
            )
            audio_metadata = audio_result.pop("metadata", {})
            audio_signals = audio_result.pop("signals", {})
            audio_findings = audio_result.pop("findings", [])
            audio_visuals = audio_result.pop("visuals", [])
            audio_artifacts = audio_result.pop("artifacts", [])
            audio_streams = audio_result.pop("stego_streams", [])
            audio_text = audio_result.pop("text_records", [])
            audio_submethods = audio_result.pop("submethods", [])
            metadata.update({f"audio:{key}": value for key, value in audio_metadata.items()})
            for item in audio_findings:
                add_finding(item, source_id, "built-in-audio")
            for record in audio_text:
                all_string_seeds.append(record)
                collector.scan_text(
                    str(record.get("text") or ""), source_artifact_id=source_id,
                    method=str(record.get("source") or "audio-signal"), confidence_hint=int(record.get("confidence_hint", 5)),
                )
            for order, item in enumerate(audio_visuals):
                artifact_id, _, reason = store.add_bytes(
                    item["data"], label=item["label"], parent_id=source_id,
                    producer=item.get("producer", "built-in-audio"),
                    transformation=item.get("transformation", "render audio evidence"),
                    kind="png", safe_preview=True, parameters=item.get("parameters"),
                )
                if artifact_id:
                    artifact = store.get(artifact_id)
                    visual_views.append({
                        "id": f"visual-{len(visual_views) + 1:04d}", "artifact_id": artifact_id,
                        "title": display_text(item.get("title", item["label"]), 200),
                        "category": (
                            "audio-sstv-image" if str(item["label"]).startswith("sstv_decoded_")
                            else ("audio-spectrogram" if "spectrogram" in item["label"] else "audio-waveform")
                        ),
                        "order": order, "width": item.get("width"), "height": item.get("height"),
                        "parameters": normalize_json(item.get("parameters", {})), "relative_path": artifact["relative_path"],
                    })
                elif reason:
                    log("warning", f"Skipped audio visual {item['label']}: {reason}", "built-in-audio")
            for item in audio_artifacts:
                payload = item.get("data", b"")
                artifact_id, _, reason = store.add_bytes(
                    payload, label=item["label"], parent_id=source_id,
                    producer=item.get("producer", "built-in-audio"),
                    transformation=item.get("transformation", "create audio review artifact"),
                    kind=item.get("kind"), parameters=item.get("parameters"),
                )
                if artifact_id:
                    collector.scan_bytes(payload, source_artifact_id=artifact_id, method="audio-review-artifact", confidence_hint=3)
                    if item.get("kind") not in AUDIO_KINDS:
                        crypto_inputs.append({"artifact_id": artifact_id, "label": item["label"], "kind": item.get("kind") or "binary", "data": payload})
                elif reason:
                    log("warning", f"Skipped audio artifact {item['label']}: {reason}", "built-in-audio")
            for item in audio_streams:
                payload = item.get("data", b"")
                hits = collector.scan_bytes(
                    payload, source_artifact_id=source_id, method="audio-pcm-lsb",
                    transform_chain=[str(item.get("transformation") or "PCM bit extraction")], confidence_hint=7,
                )
                artifact_id, _, reason = store.add_bytes(
                    payload, label=item["label"], parent_id=source_id,
                    producer=item.get("producer", "built-in-audio-lsb"),
                    transformation=item.get("transformation", "extract audio sample bits"),
                    kind=item.get("kind"), parameters=item.get("parameters"),
                )
                if artifact_id:
                    crypto_inputs.append({"artifact_id": artifact_id, "label": item["label"], "kind": "binary", "data": payload})
                    if hits:
                        add_finding({
                            "severity": "high", "category": "steganography", "title": "Flag-like text in PCM sample bits",
                            "description": "A bounded least-significant-bit stream contains flag-shaped text.",
                            "details": {"stream_artifact_id": artifact_id, "transformation": item.get("transformation")},
                        }, source_id, "audio-pcm-lsb")
                elif reason:
                    log("warning", f"Skipped PCM bit stream {item['label']}: {reason}", "audio-pcm-lsb")
            methods.append(_public_method(audio_result))
            methods.extend(_public_method(item) for item in audio_submethods)

            self._emit(progress_callback, 57, "audio-decoders", "Exploring text encodings recovered from tags and signal decoders")
            check_cancelled(is_cancelled)
            decoder_started = time.monotonic()
            decoder = BoundedDecoder(
                max_depth=limits["decode_depth"], max_nodes=limits["decode_nodes"],
                max_output=min(limits["max_single_artifact"], 16 * 1024 * 1024),
            )
            decoded_nodes = decoder.explore(all_string_seeds) if analysis_options.get("decoders", True) else []
            decoded_artifacts = 0
            for node in decoded_nodes:
                hits = collector.scan_bytes(
                    node.data, source_artifact_id=source_id, method="audio-bounded-decoder",
                    base_offset=node.source_offset or 0, transform_chain=node.chain, confidence_hint=6,
                )
                kind = sniff_kind(node.data)
                if hits or kind != "binary" or _text_ratio(node.data) >= 0.72:
                    artifact_id, created, _ = store.add_bytes(
                        node.data, label=f"audio_decoded_{node.transform}_{node.node_id}", parent_id=source_id,
                        producer="bounded-decoder", transformation=node.transform,
                        offset=node.source_offset, kind=kind, parameters={"chain": node.chain, "depth": node.depth},
                    )
                    decoded_artifacts += int(bool(artifact_id and created))
                    if artifact_id:
                        crypto_inputs.append({"artifact_id": artifact_id, "label": f"decoded {node.transform}", "kind": kind, "data": node.data})
            methods.append({
                "id": "bounded-decoder", "name": "Recursive audio text and tag decoder", "category": "decoding",
                "status": "completed" if analysis_options.get("decoders", True) else "skipped", "applicable": True,
                "started_at": utc_now() if analysis_options.get("decoders", True) else None,
                "duration_ms": int((time.monotonic() - decoder_started) * 1000),
                "summary": f"Explored {len(decoded_nodes)} bounded transform result(s) and retained {decoded_artifacts} artifact(s)." if analysis_options.get("decoders", True) else "Recursive decoding was disabled.",
                "tool": {"executable": "Python stdlib", "resolved": "built-in", "version": None},
                "details": {"result_count": len(decoded_nodes), "artifact_count": decoded_artifacts},
            })

            self._emit(progress_callback, 70, "audio-tools", "Running applicable audio, metadata, carving, and modem tools")
            check_cancelled(is_cancelled)
            selected = analysis_options.get("selected_external_tools")
            selected_ids = set(selected) if isinstance(selected, list) else None
            if not analysis_options.get("external_tools", True):
                selected_ids = set()
            else:
                excluded: set[str] = set()
                if not analysis_options.get("audio_spectrogram", True) or not analysis_options.get("visual_analysis", True):
                    excluded.update({"ffmpeg_spectrogram", "sox_spectrogram"})
                if not analysis_options.get("audio_signal_decoders", True):
                    excluded.update({"multimon_ng", "minimodem"})
                if not analysis_options.get("audio_audacity_bundle", True) and (source_kind == "wav" or not analysis_options.get("audio_sstv", True)):
                    excluded.add("ffmpeg_pcm")
                if not analysis_options.get("recursive_extraction", True):
                    excluded.update({"binwalk", "foremost", "7z"})
                if excluded:
                    selected_ids = ({spec.tool_id for spec in TOOL_SPECS} if selected_ids is None else selected_ids) - excluded
            runner = ExternalToolRunner(
                timeout=limits["tool_timeout"],
                output_limit=max(64, min(2048, int(analysis_options.get("external_output_kib", 1024)))) * 1024,
                is_cancelled=is_cancelled,
            )
            external_results = runner.run_all(
                source_path, kind=source_kind, profile=profile, password=password, work_dir=destination,
                ocr_language=str(analysis_options.get("ocr_language", "eng")), selected_tools=selected_ids,
                zsteg_mode=str(analysis_options.get("zsteg_mode", "all")),
                allow_extraction=bool(analysis_options.get("external_extraction", True)),
                max_extracted_files=int(analysis_options.get("max_external_files", 32)),
                foremost_depth=int(analysis_options.get("foremost_depth", 2)),
            )
            sstv_transcode_attempted = False
            for method in external_results:
                method_id = str(method["id"])
                collector.scan_text(method.get("stdout", ""), source_artifact_id=source_id, method=method_id, confidence_hint=5)
                collector.scan_text(method.get("stderr", ""), source_artifact_id=source_id, method=method_id, confidence_hint=2)
                for key, value in method.get("metadata", {}).items():
                    metadata[f"{method_id}:{key}"] = value
                    for text_value in _iter_text_values(value):
                        collector.scan_text(text_value, source_artifact_id=source_id, method=f"{method_id}-metadata", confidence_hint=8)
                        if len(all_string_seeds) < limits["max_strings"] * 2:
                            all_string_seeds.append({"source": f"metadata:{method_id}:{key}", "offset": None, "text": text_value})
                extracted_items = method.pop("extracted", [])
                artifact_ids: list[str] = []
                for extracted in extracted_items:
                    payload = extracted["data"]
                    extracted_kind = extracted.get("kind") or sniff_kind(payload)
                    artifact_id, _, reason = store.add_bytes(
                        payload, label=extracted["label"], parent_id=source_id,
                        producer=extracted.get("producer", method_id),
                        transformation=extracted.get("transformation", "external audio extraction"),
                        offset=extracted.get("offset"), kind=extracted_kind, depth=1,
                        safe_preview=extracted_kind in {"png", "jpeg", "gif", "bmp", "webp"},
                    )
                    if artifact_id:
                        artifact = store.get(artifact_id)
                        artifact_ids.append(artifact_id)
                        collector.scan_bytes(payload, source_artifact_id=artifact_id, method=method_id, confidence_hint=10)
                        if extracted_kind not in AUDIO_KINDS:
                            crypto_inputs.append({"artifact_id": artifact_id, "label": extracted["label"], "kind": extracted_kind, "data": payload})
                        if extracted_kind in {"png", "jpeg", "gif", "bmp", "webp"}:
                            visual_views.append({
                                "id": f"visual-{len(visual_views) + 1:04d}", "artifact_id": artifact_id,
                                "title": display_text(extracted["label"], 200), "category": "audio-spectrogram",
                                "order": len(visual_views), "width": None, "height": None,
                                "parameters": {"producer": method_id}, "relative_path": artifact["relative_path"],
                            })
                        if (
                            not sstv_transcode_attempted
                            and source_kind != "wav"
                            and method_id == "ffmpeg_pcm"
                            and extracted_kind == "wav"
                            and analysis_options.get("audio_sstv", True)
                        ):
                            sstv_transcode_attempted = True
                            decoded_path = (destination / str(artifact["relative_path"])).resolve()
                            if _is_relative_to(decoded_path, destination.resolve()):
                                transcoded = analyze_audio(
                                    decoded_path,
                                    kind="wav",
                                    profile=profile,
                                    enabled=True,
                                    spectrogram_enabled=False,
                                    signal_decoders=False,
                                    sstv_enabled=True,
                                    channel_exports=False,
                                    audacity_bundle=False,
                                    lsb_enabled=False,
                                    analysis_seconds=int(analysis_options.get("audio_analysis_seconds", 180)),
                                    fft_size=int(analysis_options.get("audio_spectrogram_fft", 2048)),
                                    channel_mode=str(analysis_options.get("audio_channel_mode", "mix")),
                                    lsb_bits=1,
                                    sstv_mode=str(analysis_options.get("audio_sstv_mode", "auto")),
                                    sstv_max_images=int(analysis_options.get("audio_sstv_max_images", 2)),
                                    sstv_slant_correction=bool(analysis_options.get("audio_sstv_slant_correction", True)),
                                )
                                transcoded_signals = transcoded.get("signals", {}).get("sstv", {})
                                if transcoded_signals.get("images_decoded") or not audio_signals.get("sstv", {}).get("images_decoded"):
                                    audio_signals["sstv"] = transcoded_signals
                                recovered_ids: list[str] = []
                                for recovered in transcoded.get("visuals", []):
                                    if not str(recovered.get("label", "")).startswith("sstv_decoded_"):
                                        continue
                                    recovered_id, _, recovered_reason = store.add_bytes(
                                        recovered["data"], label=recovered["label"], parent_id=artifact_id,
                                        producer="built-in-sstv-after-ffmpeg",
                                        transformation="decode FFmpeg-normalized PCM SSTV scan lines into RGB pixels",
                                        kind="png", safe_preview=True, parameters=recovered.get("parameters"),
                                    )
                                    if recovered_id:
                                        recovered_ids.append(recovered_id)
                                        recovered_artifact = store.get(recovered_id)
                                        visual_views.append({
                                            "id": f"visual-{len(visual_views) + 1:04d}", "artifact_id": recovered_id,
                                            "title": display_text(recovered.get("title", recovered["label"]), 200),
                                            "category": "audio-sstv-image", "order": len(visual_views),
                                            "width": recovered.get("width"), "height": recovered.get("height"),
                                            "parameters": normalize_json(recovered.get("parameters", {})),
                                            "relative_path": recovered_artifact["relative_path"],
                                        })
                                    elif recovered_reason:
                                        log("warning", f"Skipped transcoded SSTV image: {recovered_reason}", "audio-sstv-transcoded")
                                for finding in transcoded.get("findings", []):
                                    if finding.get("category") == "audio-sstv":
                                        add_finding(finding, artifact_id, "audio-sstv-transcoded")
                                methods.append({
                                    "id": "audio-sstv-transcoded", "name": "SSTV decoder after FFmpeg PCM normalization",
                                    "category": "audio-sstv", "status": "completed", "applicable": True,
                                    "started_at": utc_now(), "duration_ms": int(transcoded.get("duration_ms", 0)),
                                    "summary": (
                                        f"Recovered {len(recovered_ids)} SSTV image(s) from FFmpeg-normalized PCM."
                                        if recovered_ids else "FFmpeg produced PCM successfully, but no complete SSTV image was recovered."
                                    ),
                                    "tool": {"executable": "Forenscope built-in + FFmpeg PCM", "resolved": "built-in", "version": "1"},
                                    "details": normalize_json(transcoded_signals), "artifact_ids": recovered_ids,
                                })
                    elif reason:
                        log("warning", f"Skipped {method_id} artifact {extracted['label']}: {reason}", method_id)
                method["artifact_ids"] = artifact_ids
                method["extracted_count"] = len(artifact_ids)
                if method["status"] in {"failed", "timed_out"}:
                    log("warning", method["summary"], method_id, return_code=method.get("return_code"))
                methods.append(_public_method(method))

            self._emit(progress_callback, 91, "audio-crypto", "Checking extracted bitstreams and decoded data for encryption")
            check_cancelled(is_cancelled)
            crypto_started = time.monotonic()
            crypto_result = analyze_encrypted_payloads(
                crypto_inputs[:96], passphrase=password, enabled=bool(analysis_options.get("crypto_analysis", True)),
            )
            detections = crypto_result.pop("detections", [])
            decryptions = crypto_result.pop("decryptions", [])
            decryption_ids: list[str] = []
            known_ids = {str(item.get("id")) for item in store.artifacts}
            if detections:
                add_finding({
                    "severity": "info", "category": "crypto", "title": "Possible encrypted audio payload detected",
                    "description": "One or more extracted sample-bit or decoded payloads have ciphertext-like signals.",
                    "details": {"payload_count": len(detections), "decrypted_count": len(decryptions)},
                }, source_id, "crypto-analysis")
            for decryption in decryptions:
                plaintext = decryption.pop("data", b"")
                if not isinstance(plaintext, bytes) or not plaintext:
                    continue
                parent_id = str(decryption.get("artifact_id") or source_id)
                if parent_id not in known_ids:
                    parent_id = source_id
                algorithm = str(decryption.get("algorithm") or "bounded decryption")
                artifact_id, _, _ = store.add_bytes(
                    plaintext, label=f"audio_decrypted_{algorithm}", parent_id=parent_id,
                    producer="crypto-analysis", transformation=f"decrypt {algorithm}", kind=sniff_kind(plaintext),
                )
                if artifact_id:
                    decryption_ids.append(artifact_id)
                    collector.scan_bytes(plaintext, source_artifact_id=artifact_id, method="audio-crypto-decryption", transform_chain=[algorithm], confidence_hint=18)
            methods.append({
                "id": "crypto-analysis", "name": "Encrypted audio payload detection and recovery", "category": "crypto",
                "status": "completed" if analysis_options.get("crypto_analysis", True) else "skipped", "applicable": True,
                "started_at": utc_now() if analysis_options.get("crypto_analysis", True) else None,
                "duration_ms": int((time.monotonic() - crypto_started) * 1000),
                "summary": crypto_result.get("summary", "Encrypted-payload analysis was skipped."),
                "tool": {"executable": "Python stdlib + cryptography", "resolved": "built-in", "version": None},
                "artifact_ids": decryption_ids,
                "details": {"detections": detections[:100], "decryption_results": decryptions[:64], "attempts": crypto_result.get("attempts", 0)},
            })
            report_status = "completed"
            self._emit(progress_callback, 98, "audio-report", "Normalizing audio evidence, labels, artifacts, and coverage")
        except AnalyzerCancelled:
            report_status = "cancelled"
            log("info", "Audio analysis stopped at a cooperative cancellation boundary.", "engine")
        except Exception as exc:
            report_status = "failed"
            error = {"type": type(exc).__name__, "message": display_text(exc, 1000)}
            errors.append(error)
            log("error", f"Unexpected audio analysis error: {error['type']}: {error['message']}", "engine")

        completed_at = utc_now()
        candidates = collector.results()
        method_status_counts = Counter(method.get("status", "unknown") for method in methods)
        severity_counts = Counter(finding.get("severity", "info") for finding in findings)
        confidence_counts = Counter(candidate.get("confidence", "low") for candidate in candidates)
        missing_optional = [method["id"] for method in methods if method.get("status") == "missing"]
        coverage = {
            "profile": profile, "section": "audio", "supported_audio_formats": SUPPORTED_AUDIO_FORMATS,
            "method_status_counts": dict(method_status_counts), "missing_optional_tools": missing_optional,
            "optional_tools_declared": [spec.tool_id for spec in TOOL_SPECS],
            "analysis_options": normalize_json(analysis_options),
            "limits": {
                "read_bytes": limits["read_bytes"], "max_artifacts": limits["max_artifacts"],
                "max_derived_bytes": limits["max_artifact_bytes"], "max_single_artifact": limits["max_single_artifact"],
                "decode_depth": limits["decode_depth"], "decode_nodes": limits["decode_nodes"],
                "tool_timeout_seconds": limits["tool_timeout"], "audio_analysis_seconds": int(analysis_options.get("audio_analysis_seconds", 180)),
            },
            "source_read_complete": not read_truncated, "original_mutated": False,
        }
        report = {
            "schema_version": "1.0.0", "job_id": job_id, "section": "audio",
            "status": report_status, "profile": profile, "started_at": started_at, "completed_at": completed_at,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "source": {
                "artifact_id": source_id, "name": display_text(source_path.name, 255), "size": source_size,
                "sha256": source_sha, "detected_type": source_kind, "mime_type": mime_for(source_kind, source_path.name),
                "extension": source_path.suffix.lower(), "extension_matches_content": True,
                "inspected_bytes": len(source_data), "inspection_truncated": read_truncated,
                "first_32_bytes_hex": source_data[:32].hex(),
            },
            "summary": {
                "candidate_count": len(candidates), "high_confidence_candidates": confidence_counts.get("high", 0),
                "finding_count": len(findings), "finding_severity_counts": dict(severity_counts),
                "artifact_count": len(store.artifacts), "derived_artifact_count": max(0, len(store.artifacts) - 1),
                "derived_bytes": store.total_derived_bytes, "visual_view_count": len(visual_views),
                "method_status_counts": dict(method_status_counts),
            },
            "audio_analysis": normalize_json({
                "metadata": {key.removeprefix("audio:"): value for key, value in metadata.items() if key.startswith("audio:")},
                "signals": audio_signals if "audio_signals" in locals() else {},
            }),
            "metadata": normalize_json(metadata), "methods": normalize_json(methods),
            "findings": normalize_json(findings), "candidates": normalize_json(candidates),
            "artifacts": normalize_json(store.artifacts), "visual_views": normalize_json(visual_views),
            "logs": normalize_json(logs), "coverage": normalize_json(coverage), "errors": errors,
        }
        self._emit(progress_callback, 100, report_status, f"Audio analysis {report_status}", terminal=True)
        return report

    @staticmethod
    def _emit(callback: Callable[..., Any] | None, percent: int, stage: str, message: str, terminal: bool = False) -> None:
        if callback is None:
            return
        event = {"progress": max(0, min(100, int(percent))), "stage": stage, "message": message, "terminal": terminal, "timestamp": utc_now()}
        try:
            callback(event)
        except TypeError:
            try:
                callback(event["progress"], event["message"])
            except Exception:
                pass
        except Exception:
            # Progress transport cannot invalidate a completed forensic result.
            pass

    @staticmethod
    def _carve_signatures(
        hits: list[dict[str, Any]], data: bytes, parent_id: str, store: ArtifactStore,
        queue: deque[tuple[str, bytes, str, int]], log: Callable[..., None],
    ) -> int:
        count = 0
        supported = {"png": "png", "jpeg": "jpeg", "gif87a": "gif", "gif89a": "gif", "zip": "zip", "pdf": "pdf", "gzip": "gzip", "bzip2": "bzip2", "xz": "xz"}
        for hit in hits:
            offset = int(hit["offset"])
            kind = supported.get(hit["kind"])
            if not kind or offset == 0 or count >= 12:
                continue
            carved = _bounded_carve(data, offset, kind, store.limits["max_single_artifact"])
            if not carved:
                continue
            artifact_id, created, reason = store.add_bytes(
                carved, label=f"carved_{kind}_at_{offset:x}", parent_id=parent_id,
                producer="built-in-carver", transformation=f"carve {kind} from signature at byte offset {offset}",
                offset=offset, kind=kind, depth=1,
            )
            if artifact_id and created:
                queue.append((artifact_id, carved, kind, 1))
                count += 1
            elif reason:
                log("warning", f"Skipped carved object at {offset}: {reason}", "built-in-carver")
        return count

    @staticmethod
    def _expand_archive(
        data: bytes, kind: str, parent_id: str, depth: int, store: ArtifactStore,
        queue: deque[tuple[str, bytes, str, int]], add_finding: Callable[..., None], log: Callable[..., None],
        *, password: str | None = None,
    ) -> int:
        count = 0
        if kind == "zip":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    infos = archive.infolist()
                    if len(infos) > 1000:
                        add_finding({
                            "severity": "warning", "category": "resource-limit", "title": "ZIP entry count bounded",
                            "description": "Only the first 1,000 entries were considered.", "details": {"declared_entries": len(infos)},
                        }, parent_id, "recursive-analysis")
                    for info in infos[:1000]:
                        if info.is_dir():
                            continue
                        mode = (info.external_attr >> 16) & 0o170000
                        if mode == 0o120000:
                            log("warning", f"Skipped symbolic-link ZIP member {display_text(info.filename, 200)}", "recursive-analysis")
                            continue
                        if info.flag_bits & 0x1:
                            if not password:
                                log("info", f"Skipped encrypted ZIP member {display_text(info.filename, 200)}; no archive password was supplied.", "recursive-analysis")
                                continue
                        if info.file_size > store.limits["max_single_artifact"]:
                            log("warning", f"Skipped oversized ZIP member {display_text(info.filename, 200)}", "recursive-analysis", size=info.file_size)
                            continue
                        if info.compress_size and info.file_size / max(1, info.compress_size) > 2000:
                            log("warning", f"Skipped extreme-ratio ZIP member {display_text(info.filename, 200)}", "recursive-analysis", ratio=info.file_size / info.compress_size)
                            continue
                        try:
                            member_password = password.encode("utf-8") if info.flag_bits & 0x1 and password else None
                            with archive.open(info, "r", pwd=member_password) as member:
                                payload = member.read(store.limits["max_single_artifact"] + 1)
                        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                            log("warning", f"Could not read ZIP member {display_text(info.filename, 200)}: {display_text(exc, 300)}", "recursive-analysis")
                            continue
                        if len(payload) > store.limits["max_single_artifact"]:
                            continue
                        detected = sniff_kind(payload, info.filename)
                        artifact_id, created, reason = store.add_bytes(
                            payload, label=f"zip_{Path(info.filename).name or 'member'}", parent_id=parent_id,
                            producer="zipfile", transformation="read archive member without materializing its path",
                            kind=detected, depth=depth + 1,
                            parameters={"archive_name": display_text(info.filename, 500), "crc32": f"{info.CRC:08x}", "compressed_size": info.compress_size},
                        )
                        if artifact_id and created:
                            queue.append((artifact_id, payload, detected, depth + 1))
                            count += 1
                        elif reason:
                            log("warning", f"Skipped ZIP member artifact: {reason}", "recursive-analysis")
            except (zipfile.BadZipFile, OSError, ValueError) as exc:
                add_finding({
                    "severity": "warning", "category": "archive", "title": "ZIP parsing failed safely",
                    "description": "The candidate ZIP could not be traversed by the bounded stdlib reader.",
                    "details": {"error": f"{type(exc).__name__}: {display_text(exc, 300)}"},
                }, parent_id, "recursive-analysis")
            return count

        decompressors = {
            "gzip": lambda value: _read_stream_bounded(gzip.GzipFile(fileobj=io.BytesIO(value)), store.limits["max_single_artifact"]),
            "bzip2": lambda value: _decompress_incremental(bz2.BZ2Decompressor(), value, store.limits["max_single_artifact"]),
            "xz": lambda value: _decompress_incremental(lzma.LZMADecompressor(), value, store.limits["max_single_artifact"]),
        }
        try:
            payload = decompressors[kind](data)
            detected = sniff_kind(payload)
            artifact_id, created, reason = store.add_bytes(
                payload, label=f"{kind}_decompressed", parent_id=parent_id, producer="stdlib-decompressor",
                transformation=f"bounded {kind} decompression", kind=detected, depth=depth + 1,
            )
            if artifact_id and created:
                queue.append((artifact_id, payload, detected, depth + 1))
                count += 1
            elif reason:
                log("warning", f"Skipped decompressed artifact: {reason}", "recursive-analysis")
        except (OSError, EOFError, ValueError, lzma.LZMAError) as exc:
            add_finding({
                "severity": "warning", "category": "archive", "title": f"{kind.upper()} decompression failed safely",
                "description": "The compressed artifact was malformed or exceeded a configured limit.",
                "details": {"error": f"{type(exc).__name__}: {display_text(exc, 300)}"},
            }, parent_id, "recursive-analysis")
        return count


def _public_method(method: dict[str, Any]) -> dict[str, Any]:
    return normalize_json({key: value for key, value in method.items() if key not in {"data", "extracted", "visuals", "stego_streams", "text_records", "findings"}})


def _kind_from_extension(extension: str) -> str | None:
    return {
        ".png": "png", ".apng": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".jpe": "jpeg", ".mpo": "jpeg",
        ".gif": "gif", ".bmp": "bmp", ".dib": "bmp", ".webp": "webp",
        ".tif": "tiff", ".tiff": "tiff", ".ico": "ico", ".cur": "ico",
    }.get(extension)


def _text_method(source: str) -> str:
    lowered = source.lower()
    if "barcode" in lowered or "qr" in lowered:
        return "barcode"
    if "ocr" in lowered:
        return "ocr"
    if "png" in lowered and ("text" in lowered or "itxt" in lowered or "ztxt" in lowered or "text" in lowered):
        return "png-text"
    if "jpeg" in lowered or source == "COM":
        return "jpeg-comment"
    if "exif" in lowered or "metadata" in lowered or "info:" in lowered or "tiff" in lowered:
        return "metadata"
    if "lsb:" in lowered:
        return "built-in-lsb"
    return "structured-text"


def _visual_category(label: str) -> str:
    if label.startswith("frame_diff"):
        return "frame-difference"
    if label.startswith("frame_"):
        return "frame"
    if label.startswith("bitplane"):
        return "bit-plane"
    if label.startswith("channel") or label == "transparent_rgb":
        return "channel"
    if label == "safe_preview":
        return "preview"
    return "enhancement"


def _iter_text_values(value: Any, depth: int = 0) -> Iterable[str]:
    if depth > 5:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for nested in list(value.values())[:500]:
            yield from _iter_text_values(nested, depth + 1)
    elif isinstance(value, list):
        for nested in value[:500]:
            yield from _iter_text_values(nested, depth + 1)


def _text_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    sample = data[:8192]
    return sum(1 for value in sample if value in (9, 10, 13) or 32 <= value <= 126) / len(sample)


def _bounded_carve(data: bytes, offset: int, kind: str, maximum: int) -> bytes:
    available = data[offset:offset + maximum]
    if kind == "png":
        iend = available.find(b"IEND", 8)
        if iend >= 0 and iend + 8 <= len(available):
            return available[:iend + 8]
    elif kind == "jpeg":
        eoi = available.find(b"\xff\xd9", 3)
        if eoi >= 0:
            return available[:eoi + 2]
    elif kind == "gif":
        # Full parsing will locate a correct block trailer; a bounded suffix is safer than guessing 0x3B here.
        return available
    elif kind == "pdf":
        eof = available.find(b"%%EOF", 5)
        if eof >= 0:
            end = eof + 5
            while end < len(available) and available[end] in b"\r\n \t":
                end += 1
            return available[:end]
    return available


def _read_stream_bounded(stream: Any, maximum: int) -> bytes:
    try:
        data = stream.read(maximum + 1)
    finally:
        stream.close()
    if len(data) > maximum:
        raise ValueError("decompressed output limit exceeded")
    return data


def _decompress_incremental(decoder: Any, data: bytes, maximum: int) -> bytes:
    output = bytearray()
    cursor = 0
    while cursor < len(data):
        block = data[cursor:cursor + 64 * 1024]
        cursor += len(block)
        try:
            piece = decoder.decompress(block, max_length=maximum + 1 - len(output))
        except TypeError:
            piece = decoder.decompress(block)
        output.extend(piece)
        if len(output) > maximum:
            raise ValueError("decompressed output limit exceeded")
    return bytes(output)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


__all__ = ["AnalysisEngine"]
