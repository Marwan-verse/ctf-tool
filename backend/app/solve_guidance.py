from __future__ import annotations

from collections import Counter
from typing import Any


_SUCCESS = {"completed", "success", "succeeded", "no_findings"}
_LIMITED = {"failed", "timeout", "tool_error", "missing", "skipped"}


def _text(value: Any, limit: int = 240) -> str:
    rendered = str(value or "").replace("\x00", "").strip()
    return rendered[:limit]


def _recommendation(
    identifier: str,
    priority: int,
    title: str,
    reason: str,
    *,
    target_tab: str,
    method_ids: list[str] | None = None,
    tool_ids: list[str] | None = None,
    action: str = "review",
) -> dict[str, Any]:
    return {
        "id": identifier,
        "priority": max(1, min(100, priority)),
        "title": title,
        "reason": reason,
        "action": action,
        "target_tab": target_tab,
        "method_ids": (method_ids or [])[:12],
        "tool_ids": (tool_ids or [])[:12],
    }


def build_solve_guidance(report: dict[str, Any]) -> dict[str, Any]:
    """Build a bounded graph and next-step queue from a completed local report.

    Challenge-controlled text is used only as a bounded label. It can never
    become a command, path, URL, or network request.
    """

    source = report.get("source") if isinstance(report.get("source"), dict) else {}
    artifacts = [item for item in report.get("artifacts", []) if isinstance(item, dict)][:500]
    methods = [item for item in report.get("methods", []) if isinstance(item, dict)][:500]
    findings = [item for item in report.get("findings", []) if isinstance(item, dict)][:500]
    candidates = [item for item in report.get("candidates", []) if isinstance(item, dict)][:200]
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    known_nodes: set[str] = set()

    def add_node(node: dict[str, Any]) -> None:
        identifier = _text(node.get("id"), 100)
        if not identifier or identifier in known_nodes or len(nodes) >= 1_200:
            return
        known_nodes.add(identifier)
        nodes.append({**node, "id": identifier})

    def add_edge(source_id: Any, target_id: Any, relation: str) -> None:
        left, right = _text(source_id, 100), _text(target_id, 100)
        if left and right and left != right and len(edges) < 2_000:
            edges.append({"source": left, "target": right, "relation": relation})

    for artifact in artifacts:
        artifact_id = _text(artifact.get("id"), 100)
        add_node({
            "id": artifact_id,
            "type": "artifact",
            "label": _text(artifact.get("name") or artifact.get("detected_type") or artifact_id),
            "status": "repair" if artifact.get("repair_candidate") else _text(artifact.get("kind") or "derived", 40),
            "kind": _text(artifact.get("detected_type"), 60),
            "depth": int(artifact.get("depth") or 0),
        })
        parent_ids = artifact.get("parent_ids", [])
        for parent_id in parent_ids[:50] if isinstance(parent_ids, list) else []:
            add_edge(parent_id, artifact_id, "derived")
        lineage_items = artifact.get("lineage", [])
        for lineage in lineage_items[:50] if isinstance(lineage_items, list) else []:
            if not isinstance(lineage, dict):
                continue
            producer = _text(lineage.get("producer"), 100)
            if producer:
                method_node = f"method:{producer}"
                add_node({"id": method_node, "type": "method", "label": producer, "status": "observed"})
                add_edge(method_node, artifact_id, "produced")

    method_statuses: Counter[str] = Counter()
    missing_tools: list[str] = []
    limited_methods: list[str] = []
    for method in methods:
        method_id = _text(method.get("id") or method.get("tool_id") or method.get("name"), 100)
        if not method_id:
            continue
        status = _text(method.get("status") or "unknown", 40).casefold()
        method_statuses[status] += 1
        node_id = f"method:{method_id}"
        add_node({
            "id": node_id,
            "type": "method",
            "label": _text(method.get("name") or method_id),
            "status": status,
            "category": _text(method.get("category"), 60),
        })
        artifact_ids = method.get("artifact_ids")
        if isinstance(artifact_ids, list):
            for artifact_id in artifact_ids[:50]:
                add_edge(node_id, artifact_id, "produced")
        if status == "missing":
            missing_tools.append(method_id)
        elif status in _LIMITED:
            limited_methods.append(method_id)

    for index, finding in enumerate(findings):
        finding_id = _text(finding.get("id") or f"finding-{index + 1:04d}", 100)
        add_node({
            "id": finding_id,
            "type": "finding",
            "label": _text(finding.get("title") or finding.get("category") or "Finding"),
            "status": _text(finding.get("severity") or "info", 40),
        })
        add_edge(finding.get("artifact_id"), finding_id, "supports")
        method_id = _text(finding.get("method_id"), 100)
        if method_id:
            add_edge(f"method:{method_id}", finding_id, "reported")

    for index, candidate in enumerate(candidates):
        candidate_id = _text(candidate.get("id") or f"candidate-{index + 1:04d}", 100)
        add_node({
            "id": candidate_id,
            "type": "candidate",
            "label": _text(candidate.get("value") or candidate.get("text") or "Flag candidate", 120),
            "status": _text(candidate.get("confidence") or "candidate", 40),
            "score": candidate.get("score"),
        })
        add_edge(candidate.get("source_artifact_id") or candidate.get("artifact_id"), candidate_id, "contains")

    detected = _text(source.get("detected_type") or "binary", 60).casefold()
    repair_count = sum(1 for artifact in artifacts if artifact.get("repair_candidate"))
    derived_count = sum(1 for artifact in artifacts if artifact.get("kind") != "source")
    recommendations: list[dict[str, Any]] = []

    if candidates:
        recommendations.append(_recommendation(
            "verify-candidate", 100, "Verify the strongest flag candidate",
            "Check its provenance and challenge prefix before submitting it.",
            target_tab="candidates", action="verify",
        ))
    if repair_count:
        recommendations.append(_recommendation(
            "review-repairs", 94, "Inspect recovered and uncropped copies",
            f"{repair_count} copy-only repair candidate(s) preserve bytes the original structure may hide.",
            target_tab="repairs", action="inspect",
        ))
    if derived_count:
        recommendations.append(_recommendation(
            "pivot-artifacts", 88, "Pivot through derived artifacts",
            f"Follow the parent links for {derived_count} derived artifact(s), prioritizing deep and compact payloads.",
            target_tab="artifacts", action="pivot",
        ))
    if detected in {"pcap", "pcapng"}:
        recommendations.append(_recommendation(
            "inspect-traffic", 92, "Follow suspicious streams and exported objects",
            "Use display filters, endpoint pivots, stream reassembly, credential views, and object export.",
            target_tab="traffic", method_ids=["tshark_fields", "tshark_packet_details", "tshark_statistics"],
            tool_ids=["tshark", "zeek"], action="investigate",
        ))
    if detected in {"pe", "elf", "macho", "wasm", "dex", "java_class", "pyc"}:
        recommendations.append(_recommendation(
            "inspect-program", 91, "Inspect program structure without executing it",
            "Review imports, sections, strings, overlays, and capability matches; keep dynamic analysis isolated.",
            target_tab="metadata", tool_ids=["capa", "floss", "yara_x"], action="inspect",
        ))
    if detected in {"mp4", "mov", "matroska", "webm", "avi"}:
        recommendations.append(_recommendation(
            "inspect-video", 89, "Inspect streams, metadata, frames, and trailer bytes",
            "Compare container structure with FFprobe, then review frames and bytes beyond the declared container.",
            target_tab="visual", tool_ids=["ffprobe", "ffmpeg_frames"], action="inspect",
        ))
    if detected in {"memory", "disk", "ewf", "qcow", "vmdk", "vhd", "vhdx", "vdi", "dmg", "aff", "evtx", "registry"}:
        recommendations.append(_recommendation(
            "build-timeline", 86, "Correlate timestamps and endpoint artifacts",
            "Normalize event time, preserve source offsets, and pivot on users, paths, processes, and network indicators.",
            target_tab="metadata", tool_ids=["plaso"], action="correlate",
        ))
    if detected in {"apk", "aab", "jar", "war", "ipa", "appx", "msix", "nupkg", "xps", "cab", "cpio", "rpm", "xar"}:
        recommendations.append(_recommendation(
            "inspect-package", 87, "Inspect package manifests and recovered members",
            "Start with manifest/configuration text, signatures, executable members, and nested child artifacts.",
            target_tab="document", tool_ids=["7z_extract", "oleid"], action="inspect",
        ))
    if detected in {"hdf5", "parquet", "avro", "arrow_ipc", "orc", "bson", "access_db", "sqlite", "sqlite_wal", "sqlite_journal", "leveldb", "ese"}:
        recommendations.append(_recommendation(
            "inspect-database", 86, "Review structured records and database sidecars",
            "Search keys, inert schema/footer text, values, deleted/WAL records, and extracted binary fields before using a specialist reader.",
            target_tab="metadata", tool_ids=["sqlite3", "esedbinfo"], action="inspect",
        ))
    if detected in {"java_serialized", "python_pickle"}:
        recommendations.append(_recommendation(
            "inspect-serialization", 90, "Review serialization tokens without loading the object",
            "Prioritize string operands, global/class references, reducers, and embedded byte payloads; do not deserialize challenge data on the host.",
            target_tab="metadata", action="inspect",
        ))
    if detected in {"intel_hex", "srec", "android_sparse", "dtb", "uimage", "android_boot", "android_vendor_boot", "uefi_fv", "squashfs"}:
        recommendations.append(_recommendation(
            "inspect-firmware", 89, "Pivot into the reconstructed firmware image",
            "Review validated segments or device-tree properties, then inspect CRCs, boot arguments, embedded blobs, and nested filesystems.",
            target_tab="artifacts", tool_ids=["binwalk", "foremost", "fdtdump", "dumpimage", "unsquashfs"], action="pivot",
        ))
    if detected in {"warc", "chm", "djvu"}:
        recommendations.append(_recommendation(
            "inspect-longtail-document", 88, "Review recovered document records and members",
            "Start with bounded text/header records, then pivot into exact WARC payloads or specialist member listings without rendering active content.",
            target_tab="document", tool_ids=["7z_extract", "djvudump"], action="inspect",
        ))
    if detected in {"dicom", "fits"}:
        recommendations.append(_recommendation(
            "inspect-scientific-image", 90, "Inspect scientific-image metadata and exact boundaries",
            "Review DICOM text VRs or FITS cards, dimensions, non-zero preambles, pixel/data offsets, and evidence-backed trailing payloads.",
            target_tab="document", tool_ids=["dcmdump", "identify"], action="inspect",
        ))
    if detected in {"qoi", "dds", "ktx", "openexr"}:
        recommendations.append(_recommendation(
            "inspect-texture-image", 88, "Inspect texture structure, metadata, and residue",
            "Compare declared geometry and metadata with the logical end of the image, then pivot into any carved trailer or embedded value.",
            target_tab="metadata", tool_ids=["identify", "exrheader"], action="inspect",
        ))
    if detected == "tnef":
        recommendations.append(_recommendation(
            "inspect-tnef", 90, "Inspect recovered winmail.dat attachments",
            "Verify per-attribute checksums, message text, attachment names, and the recursively analyzed attachment artifacts.",
            target_tab="artifacts", action="pivot",
        ))
    if missing_tools:
        recommendations.append(_recommendation(
            "install-missing", 72, "Review unavailable optional analyzers",
            f"{len(missing_tools)} applicable optional analyzer(s) were unavailable; install only relevant tools.",
            target_tab="methods", tool_ids=missing_tools[:12], action="install",
        ))
    if limited_methods:
        recommendations.append(_recommendation(
            "review-limits", 68, "Review limited or failed coverage",
            f"{len(limited_methods)} method(s) were skipped, timed out, or failed; their output explains remaining gaps.",
            target_tab="methods", method_ids=limited_methods[:12], action="review",
        ))
    if not candidates:
        recommendations.append(_recommendation(
            "deepen-search", 62, "Continue from the evidence graph",
            "Search text and metadata, pivot into derived artifacts, or rerun Deep with a known prefix/passphrase.",
            target_tab="overview", action="continue",
        ))

    recommendations.sort(key=lambda item: (-int(item["priority"]), item["id"]))
    completed = sum(count for status, count in method_statuses.items() if status in _SUCCESS)
    return {
        "version": 1,
        "summary": f"{len(artifacts)} artifact(s), {len(findings)} finding(s), {len(candidates)} candidate(s), and {completed} completed method(s) connected into a bounded solve graph.",
        "nodes": nodes,
        "edges": edges,
        "recommendations": recommendations[:12],
        "coverage_gaps": {"missing_tools": missing_tools[:50], "limited_methods": limited_methods[:50]},
        "safety": {"evidence_driven_commands": False, "network_access": False, "original_mutated": False},
    }
