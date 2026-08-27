from __future__ import annotations

import base64
import zlib

from app.analyzers.core import BoundedDecoder, CandidateCollector, inspect_bytes


def test_candidate_collector_prefers_configured_prefix_and_deduplicates() -> None:
    collector = CandidateCollector("ACME.CTF+")
    collector.scan_text(
        "clue ACME.CTF+{literal_prefix_is_safe}",
        source_artifact_id="source",
        method="metadata",
        offset=100,
    )
    collector.scan_text(
        "ACME.CTF+{literal_prefix_is_safe}",
        source_artifact_id="child",
        method="raw-bytes",
        offset=4,
    )

    [candidate] = collector.results()
    assert candidate["value"] == "ACME.CTF+{literal_prefix_is_safe}"
    assert candidate["confidence"] == "high"
    assert len(candidate["occurrences"]) == 2
    assert candidate["occurrences"][0]["offset"] == 105


def test_candidate_collector_does_not_promote_arbitrary_braces() -> None:
    collector = CandidateCollector()
    collector.scan_text(
        "normal prose {with braces} and an empty flag{}",
        source_artifact_id="source",
        method="raw-bytes",
    )

    assert collector.results() == []


def test_bounded_decoder_finds_nested_base64_flag() -> None:
    encoded = base64.b64encode(base64.b64encode(b"flag{nested_decode}"))
    nodes = BoundedDecoder(max_depth=3, max_nodes=20).explore([{"text": encoded.decode(), "offset": 9}])

    assert any(node.data == b"flag{nested_decode}" and node.chain == ["base64", "base64"] for node in nodes)
    assert all(node.source_offset == 9 for node in nodes)


def test_decoder_rejects_decompression_over_output_budget() -> None:
    compressed = zlib.compress(b"A" * 32_000, level=9)
    nodes = BoundedDecoder(max_depth=2, max_nodes=10, max_output=1_024).explore(
        [{"text": base64.b64encode(compressed).decode(), "offset": 0}]
    )

    assert not any(node.transform == "zlib-decompress" for node in nodes)
    assert all(len(node.data) <= 1_024 for node in nodes)


def test_byte_inspection_is_bounded() -> None:
    report = inspect_bytes(b"one-string\0two-string\0three-string\0", max_strings=2)

    assert len(report["strings"]) == 2
    assert report["strings_truncated"] is True
    assert len(report["byte_frequency"]) == 256


def test_svg_text_nodes_are_concatenated_for_flag_scanning() -> None:
    svg = b"<svg xmlns='http://www.w3.org/2000/svg'>" + b"".join(
        f"<text>{char}</text>".encode("ascii") for char in "flag{svg_nodes}"
    ) + b"</svg>"

    report = inspect_bytes(svg, max_strings=100)

    joined = [record for record in report["strings"] if record["encoding"] == "svg-text-joined"]
    assert joined and joined[0]["text"] == "flag{svg_nodes}"
