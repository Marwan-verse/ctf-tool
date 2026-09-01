from __future__ import annotations

from app.analyzers.common import extension_for, mime_for, sniff_kind
from app.analyzers.formats import analyze_format


def test_bencode_torrent_structure_and_text_are_exposed() -> None:
    payload = b"d4:flag14:flag{bencoded}e"

    assert sniff_kind(payload, "challenge.torrent") == "bencode"
    result = analyze_format("bencode", payload)

    assert result["properties"]["consumed_bytes"] == len(payload)
    assert result["properties"]["value"]["dictionary"][0]["key"] == "flag"
    assert any(record["text"] == "flag{bencoded}" for record in result["text_records"])


def test_self_described_cbor_is_detected_without_an_extension() -> None:
    payload = b"\xd9\xd9\xf7\xa1\x64flag\x6aflag{cbor}"

    assert sniff_kind(payload, "challenge.bin") == "cbor"
    result = analyze_format("cbor", payload)

    assert result["properties"]["self_described"] is True
    assert result["properties"]["value"]["tag"] == 55799
    assert any(record["text"] == "flag{cbor}" for record in result["text_records"])


def test_messagepack_and_protobuf_use_explicit_file_type_hints() -> None:
    msgpack = b"\x81\xa4flag\xadflag{msgpack}"
    protobuf = b"\x0a\x0eflag{protobuf}"

    assert sniff_kind(msgpack, "challenge.msgpack") == "msgpack"
    msgpack_result = analyze_format("msgpack", msgpack)
    assert any(record["text"] == "flag{msgpack}" for record in msgpack_result["text_records"])

    assert sniff_kind(protobuf, "challenge.pb") == "protobuf"
    protobuf_result = analyze_format("protobuf", protobuf)
    assert protobuf_result["properties"]["schema_available"] is False
    assert protobuf_result["properties"]["fields"][0]["field_number"] == 1
    assert any(record["text"] == "flag{protobuf}" for record in protobuf_result["text_records"])


def test_structured_parsers_stop_at_depth_and_node_limits() -> None:
    nested_bencode = b"l" * 34 + b"0:" + b"e" * 34
    bencode_result = analyze_format("bencode", nested_bencode, profile="quick")
    assert "parser_error" in bencode_result["properties"]

    oversized_cbor_array = b"\x99\x07\xd1"
    cbor_result = analyze_format("cbor", oversized_cbor_array, profile="quick")
    assert "parser_error" in cbor_result["properties"]

    many_protobuf_fields = b"\x08\x01" * 2_001
    protobuf_result = analyze_format("protobuf", many_protobuf_fields, profile="quick")
    assert protobuf_result["properties"]["field_count"] == 2_000
    assert any(finding["title"] == "Protocol Buffers field limit reached" for finding in protobuf_result["findings"])


def test_structured_types_have_mime_and_download_extensions() -> None:
    assert mime_for("cbor") == "application/cbor"
    assert mime_for("msgpack") == "application/msgpack"
    assert mime_for("protobuf") == "application/x-protobuf"
    assert extension_for("bencode") == ".torrent"
