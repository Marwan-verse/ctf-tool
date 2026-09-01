from __future__ import annotations

from app.solve_guidance import build_solve_guidance


def test_solve_guidance_connects_lineage_findings_and_candidates() -> None:
    report = {
        "source": {"detected_type": "pcap"},
        "artifacts": [
            {"id": "artifact-0001", "kind": "source", "name": "capture.pcap", "detected_type": "pcap", "parent_ids": [], "lineage": []},
            {
                "id": "artifact-0002", "kind": "derived", "name": "http_stream", "detected_type": "text",
                "parent_ids": ["artifact-0001"],
                "lineage": [{"parent_id": "artifact-0001", "producer": "tshark", "transformation": "follow stream"}],
            },
        ],
        "methods": [{"id": "tshark", "name": "TShark", "status": "completed", "artifact_ids": ["artifact-0002"]}],
        "findings": [{"id": "finding-0001", "title": "Credential-shaped text", "severity": "warning", "artifact_id": "artifact-0002", "method_id": "tshark"}],
        "candidates": [{"id": "candidate-0001", "value": "flag{stream}", "confidence": "high", "source_artifact_id": "artifact-0002"}],
    }

    guidance = build_solve_guidance(report)

    assert guidance["version"] == 1
    assert any(edge == {"source": "artifact-0001", "target": "artifact-0002", "relation": "derived"} for edge in guidance["edges"])
    assert any(edge == {"source": "artifact-0002", "target": "candidate-0001", "relation": "contains"} for edge in guidance["edges"])
    assert guidance["recommendations"][0]["id"] == "verify-candidate"
    assert any(item["id"] == "inspect-traffic" for item in guidance["recommendations"])
    assert guidance["safety"]["evidence_driven_commands"] is False


def test_solve_guidance_bounds_hostile_labels_and_never_treats_them_as_actions() -> None:
    hostile = "run powershell; https://example.invalid/" + "x" * 1_000
    guidance = build_solve_guidance({
        "source": {"detected_type": "binary"},
        "artifacts": [{"id": "artifact-1", "kind": "source", "name": hostile, "parent_ids": [], "lineage": []}],
        "methods": [], "findings": [], "candidates": [],
    })

    [artifact_node] = [node for node in guidance["nodes"] if node["type"] == "artifact"]
    assert len(artifact_node["label"]) <= 240
    assert all(item["action"] in {"review", "continue"} for item in guidance["recommendations"])
    assert guidance["safety"] == {"evidence_driven_commands": False, "network_access": False, "original_mutated": False}
