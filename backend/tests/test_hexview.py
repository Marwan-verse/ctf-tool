from __future__ import annotations

from pathlib import Path

import pytest

from app.hexview import inspect_file, parse_search


def test_hex_view_returns_window_matches_and_anomalies(tmp_path: Path) -> None:
    path = tmp_path / "payload.bin"
    path.write_bytes(b"header flag{hex_view}" + (b"\0" * 120) + b"PK\x03\x04" + bytes(range(256)) * 20)

    payload = inspect_file(path, offset=0, length=64, search="flag{hex_view}", search_mode="text")

    assert payload["total_size"] == path.stat().st_size
    assert payload["length"] == 64
    assert payload["rows"][0]["offset"] == 0
    assert payload["rows"][0]["bytes"] == list(path.read_bytes()[:16])
    assert "integrity" in payload
    assert payload["matches"][0]["offset"] == 7
    assert any(item["kind"] == "long-zero-run" for item in payload["anomalies"])
    assert any(item["kind"] == "embedded-signature" and item["offset"] > 0 for item in payload["anomalies"])


def test_hex_search_accepts_common_separators_and_rejects_unsafe_values() -> None:
    assert parse_search("89 50:4e 47 0d-0a 1a 0a", "hex") == b"\x89PNG\r\n\x1a\n"
    with pytest.raises(ValueError):
        parse_search("abc", "hex")
    with pytest.raises(ValueError):
        parse_search("not-a-mode", "other")


def test_hex_view_clamps_offset_and_can_skip_anomaly_scan(tmp_path: Path) -> None:
    path = tmp_path / "small.bin"
    path.write_bytes(b"0123456789")

    payload = inspect_file(path, offset=999, length=8192, include_anomalies=False)

    assert payload["offset"] == 10
    assert payload["length"] == 0
    assert payload["rows"] == []
    assert payload["anomalies"] == []
    assert payload["anomaly_scan"] == {"enabled": False, "count": 0, "bounded": True}
