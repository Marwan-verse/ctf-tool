from __future__ import annotations

import base64
import binascii
import bz2
import codecs
import gzip
import html
import io
import lzma
import re
import urllib.parse
import zlib
from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable

from .common import (
    byte_entropy,
    display_text,
    find_magic_offsets,
    iter_ascii_strings,
    iter_utf16_strings,
    sha256_bytes,
    sniff_kind,
)


_GENERIC_FLAG = re.compile(
    r"(?<![A-Za-z0-9_])(?:flag|ctf|picoCTF|HTB|THM|DUCTF|uiuctf|ictf|corctf|SEKAI|grey|buckeye|iris|amateursCTF)"
    r"\{[ -~]{1,240}?\}",
    re.IGNORECASE,
)
_BROAD_FLAG = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z][A-Za-z0-9_-]{1,31}\{[A-Za-z0-9_@!#$%&*+.,:;?=/\\|~^'\"()\[\]<> -]{2,200}\}")
_MAX_CANDIDATE_LENGTH = 280


class CandidateCollector:
    """Find, score, and deduplicate flag-like values with full provenance."""

    def __init__(self, configured_prefix: str | None = None) -> None:
        prefix = (configured_prefix or "").strip()
        self.prefix = prefix[:64]
        self._configured = (
            re.compile(r"(?<![A-Za-z0-9_])" + re.escape(self.prefix) + r"\{[ -~]{1,240}?\}", re.IGNORECASE)
            if self.prefix else None
        )
        self._items: dict[str, dict[str, Any]] = {}

    def scan_text(
        self,
        text: str,
        *,
        source_artifact_id: str,
        method: str,
        offset: int | None = None,
        transform_chain: list[str] | None = None,
        confidence_hint: int = 0,
        context: str | None = None,
    ) -> int:
        if not text:
            return 0
        # Search bounded windows. A pathological tool log must not dominate time.
        text = text[:2_000_000]
        matches: dict[tuple[int, int], tuple[str, bool]] = {}
        if self._configured:
            for match in self._configured.finditer(text):
                matches[(match.start(), match.end())] = (match.group(0), True)
        for regex in (_GENERIC_FLAG, _BROAD_FLAG):
            for match in regex.finditer(text):
                matches.setdefault((match.start(), match.end()), (match.group(0), False))

        inserted = 0
        for (start, end), (value, exact_prefix) in sorted(matches.items()):
            value = value.strip()
            if not self._plausible(value):
                continue
            occurrence_offset = offset + start if offset is not None else None
            score, reasons = self._score(value, exact_prefix, method, confidence_hint)
            occurrence = {
                "artifact_id": source_artifact_id,
                "method": method,
                "offset": occurrence_offset,
                "transform_chain": list(transform_chain or []),
                "context": display_text(context or text[max(0, start - 40):min(len(text), end + 40)], 320),
            }
            key = value
            if key in self._items:
                existing = self._items[key]
                if occurrence not in existing["occurrences"] and len(existing["occurrences"]) < 50:
                    existing["occurrences"].append(occurrence)
                if score > existing["score"]:
                    existing["score"] = score
                    existing["confidence"] = _confidence(score)
                    existing["reasons"] = reasons
            else:
                self._items[key] = {
                    "value": value,
                    "score": score,
                    "confidence": _confidence(score),
                    "reasons": reasons,
                    "occurrences": [occurrence],
                    "confirmed": False,
                    "dismissed": False,
                }
                inserted += 1
        return inserted

    def scan_bytes(
        self,
        data: bytes,
        *,
        source_artifact_id: str,
        method: str,
        base_offset: int = 0,
        transform_chain: list[str] | None = None,
        confidence_hint: int = 0,
    ) -> int:
        total = 0
        # Latin-1 preserves byte-to-character offsets for printable ASCII flags.
        total += self.scan_text(
            data.decode("latin-1", "ignore"), source_artifact_id=source_artifact_id,
            method=method, offset=base_offset, transform_chain=transform_chain,
            confidence_hint=confidence_hint,
        )
        # UTF-16 strings need their explicit byte offsets.
        for record in iter_utf16_strings(data, minimum=4, limit=2_000):
            total += self.scan_text(
                record["text"], source_artifact_id=source_artifact_id,
                method=f"{method}:{record['encoding']}", offset=base_offset + record["offset"],
                transform_chain=transform_chain, confidence_hint=confidence_hint,
            )
        return total

    def results(self) -> list[dict[str, Any]]:
        ordered = sorted(self._items.values(), key=lambda item: (-item["score"], item["value"].lower()))
        results: list[dict[str, Any]] = []
        for index, item in enumerate(ordered, 1):
            result = dict(item)
            result["id"] = f"candidate-{index:04d}"
            results.append(result)
        return results

    @staticmethod
    def _plausible(value: str) -> bool:
        if len(value) < 7 or len(value) > _MAX_CANDIDATE_LENGTH:
            return False
        if value.count("{") != 1 or value.count("}") != 1 or not value.endswith("}"):
            return False
        body = value[value.find("{") + 1:-1]
        if not body.strip() or body.isspace():
            return False
        # Long natural-language sentences surrounded by braces are typically metadata.
        if len(body) > 120 and body.count(" ") > 20:
            return False
        return all(ch in "\t" or 32 <= ord(ch) <= 126 for ch in value)

    def _score(self, value: str, exact_prefix: bool, method: str, hint: int) -> tuple[int, list[str]]:
        score = 45 + max(-15, min(20, hint))
        reasons = ["matches a bounded flag-shaped pattern"]
        prefix = value.split("{", 1)[0]
        if exact_prefix or (self.prefix and prefix.lower() == self.prefix.lower()):
            score += 35
            reasons.append("matches the configured competition prefix")
        elif prefix.lower() in {"flag", "ctf", "picoctf", "htb", "thm", "ductf"}:
            score += 18
            reasons.append("uses a common CTF prefix")
        deterministic = {"raw-bytes", "metadata", "png-text", "jpeg-comment", "svg-text", "barcode", "archive-member"}
        if method.split(":", 1)[0] in deterministic:
            score += 10
            reasons.append("came from a deterministic extraction")
        if method == "ocr":
            score -= 8
            reasons.append("OCR output can contain recognition errors")
        body = value[value.find("{") + 1:-1]
        if " " not in body:
            score += 4
        if len(set(body)) < 3:
            score -= 10
        return max(0, min(100, score)), reasons


def _confidence(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 55:
        return "medium"
    return "low"


def inspect_bytes(data: bytes, *, max_strings: int) -> dict[str, Any]:
    ascii_records = list(iter_ascii_strings(data, minimum=4, limit=max_strings))
    remaining = max(0, max_strings - len(ascii_records))
    utf16_records = list(iter_utf16_strings(data, minimum=4, limit=min(remaining, max_strings // 2)))
    remaining = max(0, max_strings - len(ascii_records) - len(utf16_records))
    svg_records = _svg_text_records(data, limit=min(remaining, 2_000))
    records = sorted(ascii_records + utf16_records + svg_records, key=lambda item: (item["offset"], item["encoding"]))
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    return {
        "entropy": round(byte_entropy(data), 5),
        "byte_frequency": byte_counts,
        "magic_offsets": find_magic_offsets(data),
        "strings": records,
        "strings_truncated": len(records) >= max_strings,
    }


def _svg_text_records(data: bytes, *, limit: int) -> list[dict[str, Any]]:
    """Extract ordered SVG text nodes without invoking an XML parser.

    SVG is frequently used as an image container in CTFs, with one flag
    character per ``<text>`` node.  A bounded tag regex avoids XXE/entity
    expansion and network resolution while still recovering visible text.
    """

    if limit <= 0:
        return []
    sample = data[: min(len(data), 8 * 1024 * 1024)]
    lowered = sample.lower()
    if b"<svg" not in lowered or b"<text" not in lowered:
        return []
    node_pattern = re.compile(rb"<text\b[^>]*>(.*?)</text\s*>", re.IGNORECASE | re.DOTALL)
    fragment_pattern = re.compile(rb"<tspan\b[^>]*>(.*?)</tspan\s*>", re.IGNORECASE | re.DOTALL)
    node_values: list[tuple[int, str]] = []
    records: list[dict[str, Any]] = []
    compact_values: set[str] = set()

    def decode_markup(raw: bytes) -> str:
        without_tags = re.sub(rb"<[^>]{0,512}>", b"", raw)
        return html.unescape(without_tags.decode("utf-8", "replace")).strip()

    def add_compact(text: str, offset: int, *, fragments: int) -> None:
        # Some SVG CTFs put a space after every character or divide the flag
        # among tspans. Only emit a whitespace-free derivative when braces
        # make it flag-shaped; ordinary SVG prose remains unchanged.
        compact = "".join(character for character in text if not character.isspace())
        if (
            compact == text
            or compact in compact_values
            or not (7 <= len(compact) <= _MAX_CANDIDATE_LENGTH)
            or "{" not in compact
            or not compact.endswith("}")
            or len(records) >= limit
        ):
            return
        compact_values.add(compact)
        records.append({
            "source": "SVG compact ordered text",
            "offset": offset,
            "encoding": "svg-text-compact",
            "text": display_text(compact, _MAX_CANDIDATE_LENGTH),
            "confidence_hint": 12,
            "transform_chain": [
                f"extract ordered SVG text from {fragments} fragment(s)",
                "remove whitespace separators",
            ],
        })

    for match in node_pattern.finditer(sample):
        if len(node_values) >= limit:
            break
        text = decode_markup(match.group(1))
        if not text:
            continue
        offset = int(match.start(1))
        node_values.append((offset, text))
        records.append({"source": "SVG text node", "offset": offset, "encoding": "svg-text", "text": display_text(text, 16_384), "confidence_hint": 8})
        fragments = [decode_markup(fragment.group(1)) for fragment in fragment_pattern.finditer(match.group(1))]
        fragments = [fragment for fragment in fragments if fragment]
        ordered_text = "".join(fragments) if fragments else text
        add_compact(ordered_text, offset, fragments=max(1, len(fragments)))
    if len(node_values) >= 2:
        joined = "".join(value for _, value in node_values)
        if joined and len(records) < limit:
            records.append({"source": "SVG ordered text nodes", "offset": node_values[0][0], "encoding": "svg-text-joined", "text": display_text(joined, 2_000_000), "confidence_hint": 10})
            add_compact(joined, node_values[0][0], fragments=len(node_values))
    return records


@dataclass(slots=True)
class DecodedNode:
    node_id: str
    parent_id: str | None
    depth: int
    transform: str
    chain: list[str]
    data: bytes
    source_offset: int | None = None


class BoundedDecoder:
    """Explore common CTF encodings without unbounded decompression or fan-out."""

    _token_patterns = (
        re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{12,8192}={0,2}(?![A-Za-z0-9+/=])"),
        re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{12,8192}(?![0-9A-Fa-f])"),
        re.compile(r"(?<![A-Z2-7=])[A-Z2-7]{16,8192}={0,7}(?![A-Z2-7=])", re.IGNORECASE),
    )

    def __init__(self, *, max_depth: int, max_nodes: int, max_output: int = 16 * 1024 * 1024) -> None:
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.max_output = max_output

    def explore(self, seeds: Iterable[dict[str, Any]]) -> list[DecodedNode]:
        queue: deque[DecodedNode] = deque()
        seen: set[str] = set()
        results: list[DecodedNode] = []

        for seed_index, seed in enumerate(seeds):
            if len(queue) >= self.max_nodes:
                break
            text = str(seed.get("text", "")).strip()
            if not text or len(text) > 100_000:
                continue
            for token, local_offset in self._interesting_tokens(text):
                raw = token.encode("ascii", "ignore")
                digest = sha256_bytes(raw)
                if digest in seen:
                    continue
                seen.add(digest)
                queue.append(DecodedNode(
                    node_id=f"seed-{seed_index}-{local_offset}", parent_id=None, depth=0,
                    transform="source-string", chain=[], data=raw,
                    # The source string record owns the evidence offset. Token
                    # offsets are relative to a decoded/display value and are
                    # not guaranteed to map byte-for-byte to the source file.
                    source_offset=seed.get("offset"),
                ))

        counter = 0
        while queue and len(results) < self.max_nodes:
            parent = queue.popleft()
            if parent.depth >= self.max_depth:
                continue
            for transform, output in self._transforms(parent.data):
                if not output or output == parent.data or len(output) > self.max_output:
                    continue
                digest = sha256_bytes(output)
                if digest in seen:
                    continue
                seen.add(digest)
                counter += 1
                node = DecodedNode(
                    node_id=f"decoded-{counter:04d}", parent_id=parent.node_id,
                    depth=parent.depth + 1, transform=transform,
                    chain=parent.chain + [transform], data=output,
                    source_offset=parent.source_offset,
                )
                results.append(node)
                if len(results) >= self.max_nodes:
                    break
                if node.depth < self.max_depth and (self._text_score(output) >= 0.65 or sniff_kind(output) != "binary"):
                    queue.append(node)
        return results

    def _interesting_tokens(self, text: str) -> list[tuple[str, int]]:
        found: dict[tuple[int, str], None] = {}
        stripped = text.strip()
        if 6 <= len(stripped) <= 8192:
            found[(text.find(stripped), stripped)] = None
        for pattern in self._token_patterns:
            for match in pattern.finditer(text):
                found[(match.start(), match.group(0))] = None
                if len(found) >= 100:
                    break
        if "%" in text and len(stripped) <= 8192:
            found[(text.find(stripped), stripped)] = None
        return [(token, offset) for (offset, token) in found][:100]

    def _transforms(self, data: bytes) -> list[tuple[str, bytes]]:
        outputs: list[tuple[str, bytes]] = []
        text: str | None
        try:
            text = data.decode("ascii").strip()
        except UnicodeDecodeError:
            text = None

        if text:
            compact = re.sub(r"\s+", "", text)
            if len(compact) >= 8 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", compact):
                try:
                    padded = compact + "=" * (-len(compact) % 4)
                    outputs.append(("base64", base64.b64decode(padded, validate=True)))
                except (ValueError, binascii.Error):
                    pass
            if len(compact) >= 8 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
                try:
                    outputs.append(("hex", bytes.fromhex(compact)))
                except ValueError:
                    pass
            if len(compact) >= 16 and re.fullmatch(r"[A-Z2-7]+=*", compact, re.IGNORECASE):
                try:
                    outputs.append(("base32", base64.b32decode(compact.upper() + "=" * (-len(compact) % 8))))
                except (ValueError, binascii.Error):
                    pass
            if len(text) >= 10:
                try:
                    outputs.append(("base85", base64.b85decode(text)))
                except (ValueError, binascii.Error):
                    pass
            if "%" in text or "+" in text:
                try:
                    decoded = urllib.parse.unquote_to_bytes(text.replace("+", " "))
                    outputs.append(("url-percent", decoded))
                except Exception:
                    pass
            if re.fullmatch(r"(?:[01]{8}[\s_-]*){2,}", text):
                try:
                    groups = re.findall(r"[01]{8}", text)
                    outputs.append(("binary-ascii", bytes(int(group, 2) for group in groups)))
                except ValueError:
                    pass
            if re.fullmatch(r"(?:[0-7]{3}[\s_-]*){2,}", text):
                try:
                    groups = re.findall(r"[0-7]{3}", text)
                    values = [int(group, 8) for group in groups]
                    if all(value <= 255 for value in values):
                        outputs.append(("octal-ascii", bytes(values)))
                except ValueError:
                    pass
            # Once a common flag pattern is already visible, ROT/reversal only
            # manufacture lower-quality lookalikes (for example flag -> synt).
            # Unknown-prefix brace strings remain eligible for these CTF transforms.
            already_plain_flag = bool(_GENERIC_FLAG.fullmatch(text))
            if not already_plain_flag and (any(ch in text for ch in "{}") or re.fullmatch(r"[A-Za-z0-9_{}-]{7,500}", text)):
                outputs.append(("rot13", codecs.decode(text, "rot_13").encode("utf-8")))
                outputs.append(("reverse", text[::-1].encode("utf-8")))

        compressed = self._decompress(data)
        if compressed is not None:
            outputs.append(compressed)
        # Preserve order while removing identical transform outputs.
        unique: list[tuple[str, bytes]] = []
        digests: set[str] = set()
        for name, output in outputs:
            digest = sha256_bytes(output)
            if digest not in digests:
                unique.append((name, output))
                digests.add(digest)
        return unique

    def _decompress(self, data: bytes) -> tuple[str, bytes] | None:
        try:
            if data.startswith(b"\x1f\x8b"):
                return "gzip-decompress", self._zlib_bounded(data, 16 + zlib.MAX_WBITS)
            if data.startswith(b"x\x01") or data.startswith(b"x\x9c") or data.startswith(b"x\xda"):
                return "zlib-decompress", self._zlib_bounded(data, zlib.MAX_WBITS)
            if data.startswith(b"BZh"):
                return "bzip2-decompress", self._incremental_bounded(bz2.BZ2Decompressor(), data)
            if data.startswith(b"\xfd7zXZ\x00"):
                return "xz-decompress", self._incremental_bounded(lzma.LZMADecompressor(), data)
            if data.startswith(b"(\xb5/\xfd"):
                try:
                    import zstandard  # type: ignore

                    reader = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(data))
                    output = reader.read(self.max_output + 1)
                    if len(output) > self.max_output:
                        return None
                    return "zstd-decompress", output
                except (ImportError, Exception):
                    return None
        except (OSError, EOFError, ValueError, zlib.error, lzma.LZMAError):
            return None
        return None

    def _zlib_bounded(self, data: bytes, window_bits: int) -> bytes:
        decoder = zlib.decompressobj(window_bits)
        output = decoder.decompress(data, self.max_output + 1)
        if len(output) > self.max_output or (decoder.unconsumed_tail and len(output) >= self.max_output):
            raise ValueError("decompressed output limit exceeded")
        output += decoder.flush(max(0, self.max_output + 1 - len(output)))
        if len(output) > self.max_output:
            raise ValueError("decompressed output limit exceeded")
        return output

    def _incremental_bounded(self, decoder: Any, data: bytes) -> bytes:
        output = bytearray()
        cursor = 0
        while cursor < len(data):
            block = data[cursor:cursor + 64 * 1024]
            cursor += len(block)
            try:
                piece = decoder.decompress(block, max_length=self.max_output + 1 - len(output))
            except TypeError:
                piece = decoder.decompress(block)
            output.extend(piece)
            if len(output) > self.max_output:
                raise ValueError("decompressed output limit exceeded")
        return bytes(output)

    @staticmethod
    def _text_score(data: bytes) -> float:
        if not data:
            return 0.0
        sample = data[:8192]
        return sum(1 for byte in sample if byte in (9, 10, 13) or 32 <= byte <= 126) / len(sample)
