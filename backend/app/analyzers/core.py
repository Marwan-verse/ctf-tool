from __future__ import annotations

import base64
import binascii
import bz2
import codecs
import gzip
import html
import io
import lzma
import math
import re
import urllib.parse
import unicodedata
import zlib
from collections import Counter, deque
from dataclasses import dataclass
from typing import Any, Iterable

from .common import (
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
        include_utf16: bool = True,
    ) -> int:
        total = 0
        # Latin-1 preserves byte-to-character offsets for printable ASCII flags.
        total += self.scan_text(
            data[:2_000_000].decode("latin-1", "ignore"), source_artifact_id=source_artifact_id,
            method=method, offset=base_offset, transform_chain=transform_chain,
            confidence_hint=confidence_hint,
        )
        # UTF-16 strings need their explicit byte offsets.
        if include_utf16:
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
        deterministic = {"raw-bytes", "metadata", "png-text", "jpeg-comment", "svg-text", "whitespace-steg", "unicode-normalization", "barcode", "archive-member"}
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
    whitespace_records = _whitespace_steg_records(data, limit=min(max_strings, 128))
    unicode_records = _unicode_confusable_records(data, limit=min(max_strings, 128))
    records = sorted(
        ascii_records + utf16_records + svg_records + whitespace_records + unicode_records,
        key=lambda item: (item["offset"], item["encoding"]),
    )[:max_strings]
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in byte_counts
        if count and length
    )
    return {
        "entropy": round(entropy, 5),
        "byte_frequency": byte_counts,
        "magic_offsets": find_magic_offsets(data),
        "strings": records,
        "strings_truncated": len(records) >= max_strings,
    }


def _unicode_confusable_records(data: bytes, *, limit: int) -> list[dict[str, Any]]:
    """Expose bounded Unicode NFKC/confusable normalization for text CTFs.

    Full-width Latin, mathematical alphabets, and visually similar code
    points are frequently mixed into otherwise ordinary flag text. This is a
    presentation-only normalization: source bytes remain immutable and no
    invisible/control characters are executed.
    """

    if limit <= 0 or not data:
        return []
    try:
        text = data[: 4 * 1024 * 1024].decode("utf-8")
    except UnicodeDecodeError:
        return []
    if not any(ord(character) > 127 for character in text):
        return []
    normalized = unicodedata.normalize("NFKC", text)
    confusables = {
        "а": "a", "е": "e", "і": "i", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
        "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y",
        "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "χ": "x", "υ": "y",
    }
    normalized = "".join(confusables.get(character, character) for character in normalized)
    if normalized == text:
        return []
    printable = sum(1 for character in normalized if character in "\t\r\n" or 32 <= ord(character) <= 126 or ord(character) >= 160)
    if printable / max(1, len(normalized)) < 0.78:
        return []
    candidate = display_text(normalized, 2_000_000)
    flag_like = bool(_GENERIC_FLAG.search(candidate) or _BROAD_FLAG.search(candidate))
    if not flag_like and len(candidate.strip()) < 12:
        return []
    return [{
        "source": "unicode-confusables",
        "offset": 0,
        "encoding": "unicode-normalization",
        "text": candidate,
        "confidence_hint": 12 if flag_like else 5,
        "transform_chain": ["UTF-8 decode", "Unicode NFKC normalization", "common Cyrillic/Greek confusable mapping"],
    }]


def _whitespace_steg_records(data: bytes, *, limit: int) -> list[dict[str, Any]]:
    """Recover bounded two-symbol whitespace bitstreams from text files.

    CTFs frequently replace ordinary spaces with a visually identical Unicode
    space (or use tabs/space pairs) and encode one bit per character.  The
    decoder only considers streams with two well-populated whitespace classes,
    tries both polarity/bit-order conventions, and emits printable or
    flag-shaped results.  It never treats arbitrary binary bytes as text.
    """

    if limit <= 0 or not isinstance(data, (bytes, bytearray)) or not data:
        return []
    # Keep the temporary character/bit lists bounded well below the per-job
    # artifact budget; a whitespace channel rarely needs more than 1 MiB.
    sample = bytes(data[: 4 * 1024 * 1024])
    try:
        text = sample.decode("utf-8")
    except UnicodeDecodeError:
        return []

    stream_specs: list[tuple[str, str, str, list[str]]] = []
    counts = Counter(character for character in text if character.isspace() and character not in "\r\n")
    ordinary_space = counts.get(" ", 0)
    if ordinary_space >= 8:
        # Unicode whitespace substitutions are the common “whitepages” form.
        for character, count in counts.most_common(8):
            if character == " " or ord(character) <= 127 or count < 8:
                continue
            stream_specs.append(("unicode-whitespace", "U+0020", f"U+{ord(character):04X}", [" ", character]))

    # SNOW-style payloads normally use only spaces and tabs at line ends.
    trailing: list[str] = []
    for line in text.splitlines():
        match = re.search(r"[ \t]+$", line)
        if match:
            trailing.append(match.group(0))
    trailing_text = "".join(trailing)
    trailing_counts = Counter(trailing_text)
    if trailing_counts.get(" ", 0) >= 8 and trailing_counts.get("\t", 0) >= 8:
        stream_specs.append(("line-trailing", "U+0020", "U+0009", [" ", "\t"]))

    # Zero-width binary channels do not satisfy str.isspace().
    zero_width = ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"]
    zero_counts = Counter(character for character in text if character in zero_width)
    present_zero = [character for character, count in zero_counts.most_common(4) if count >= 8]
    if len(present_zero) >= 2:
        stream_specs.append(("zero-width", f"U+{ord(present_zero[0]):04X}", f"U+{ord(present_zero[1]):04X}", present_zero[:2]))

    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for family, first_name, second_name, symbols in stream_specs:
        stream = "".join(character for character in text if character in symbols)
        if family == "line-trailing":
            stream = trailing_text
        stream = stream[: 1 * 1024 * 1024]
        if len(stream) < 64:
            continue
        symbol_counts = Counter(stream)
        if any(symbol_counts.get(symbol, 0) < 8 for symbol in symbols):
            continue
        for inverted in (False, True):
            for lsb_first in (False, True):
                bits = [1 if character == symbols[1] else 0 for character in stream]
                if inverted:
                    bits = [1 - bit for bit in bits]
                decoded = bytearray()
                for cursor in range(0, len(bits) - 7, 8):
                    group = bits[cursor:cursor + 8]
                    if lsb_first:
                        group.reverse()
                    decoded.append(sum(bit << (7 - index) for index, bit in enumerate(group)))
                if not decoded:
                    continue
                candidate = bytes(decoded).decode("utf-8", "replace").strip("\x00 \t\r\n")
                if not candidate or candidate in seen:
                    continue
                printable = sum(1 for character in candidate if character in "\t\r\n" or 32 <= ord(character) <= 126) / len(candidate)
                flag_like = bool(_GENERIC_FLAG.search(candidate) or _BROAD_FLAG.search(candidate))
                if not flag_like and (len(candidate) < 12 or printable < 0.78):
                    continue
                seen.add(candidate)
                records.append({
                    "source": "whitespace-bitstream",
                    "offset": 0,
                    "encoding": "whitespace-bits",
                    "text": display_text(candidate, 2_000_000),
                    "confidence_hint": 14 if flag_like else 6,
                    "transform_chain": [
                        f"extract {family} symbols {first_name}/{second_name}",
                        "invert bit mapping" if inverted else "preserve bit mapping",
                        "pack LSB-first" if lsb_first else "pack MSB-first",
                    ],
                })
                if len(records) >= limit:
                    return records
    return records


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

        seed_list = list(seeds)
        # Binary and event-log string scanners commonly split one logical
        # value at line or record boundaries.  Rejoin adjacent hex lines from
        # the same artifact before exploring transforms, while retaining each
        # original seed for provenance and avoiding arbitrary concatenation.
        grouped: dict[str, list[dict[str, Any]]] = {}
        for seed in seed_list:
            artifact_id = seed.get("artifact_id") or seed.get("source_artifact_id")
            if artifact_id:
                grouped.setdefault(str(artifact_id), []).append(seed)
        for artifact_id, records in grouped.items():
            if len(records) < 2:
                continue
            ordered = sorted(records, key=lambda item: int(item.get("offset") or 0))
            combined = "\n".join(str(item.get("text", "")) for item in ordered if item.get("text"))
            compact = re.sub(r"\s+", "", combined)
            if len(compact) >= 24 and len(compact) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", compact):
                seed_list.append({
                    "text": combined, "offset": ordered[0].get("offset"),
                    "artifact_id": artifact_id, "source": "rejoined-string-records",
                })

        for seed_index, seed in enumerate(seed_list):
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
