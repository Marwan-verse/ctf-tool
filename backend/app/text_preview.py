"""Safe, bounded readable-text previews for forensic evidence artifacts.

This module intentionally does not render a document or execute document
content. It returns plain text extracted from a small, fixed-size slice of the
artifact so the browser can display it in a React ``<pre>`` element.
"""

from __future__ import annotations

import html
import re
import struct
import zipfile
from pathlib import Path
from typing import Any

from .analyzers.common import display_text, iter_utf16_strings, sniff_kind
from .analyzers.formats import _decode_text_document, analyze_format


MAX_PREVIEW_BYTES = 2 * 1024 * 1024
MAX_PREVIEW_CHARS = 500_000
MAX_PACKAGE_ENTRIES = 32
MAX_PACKAGE_ENTRY_BYTES = 512 * 1024
MAX_PACKAGE_DIRECTORY_ENTRIES = 1_000
MAX_PACKAGE_DIRECTORY_BYTES = 4 * 1024 * 1024

_DOCUMENT_EXTENSIONS = {
    ".txt", ".text", ".md", ".markdown", ".rst", ".log", ".csv", ".tsv",
    ".json", ".jsonl", ".ndjson", ".xml", ".yaml", ".yml", ".ini", ".cfg",
    ".conf", ".properties", ".toml", ".html", ".htm", ".xhtml", ".tex",
    ".pdf", ".rtf", ".doc", ".xls", ".ppt", ".docx", ".docm", ".dotx", ".dotm",
    ".xlsx", ".xlsm", ".xltx", ".xltm", ".pptx", ".pptm", ".ppsx", ".ppsm",
    ".odt", ".ods", ".odp", ".epub", ".xps", ".oxps", ".one", ".onetoc2", ".eml", ".mbox", ".pst", ".ost",
    ".apk", ".aab", ".jar", ".war", ".ipa", ".appx", ".msix", ".nupkg",
}
_OOXML_EXTENSIONS = {".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm", ".pptx", ".pptm", ".ppsx", ".ppsm"}
_ODF_EXTENSIONS = {".odt", ".ods", ".odp"}
_PACKAGE_KINDS = {"docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "xps", "apk", "aab", "jar", "war", "ipa", "appx", "msix", "nupkg"}


class TextPreviewUnavailableError(ValueError):
    """Raised when an artifact is not a supported readable document."""


def _read_bounded(path: Path) -> tuple[bytes, bool]:
    with path.open("rb") as handle:
        data = handle.read(MAX_PREVIEW_BYTES + 1)
    return data[:MAX_PREVIEW_BYTES], len(data) > MAX_PREVIEW_BYTES


def _clip(value: str, maximum: int = MAX_PREVIEW_CHARS) -> tuple[str, bool]:
    safe = display_text(value, maximum)
    return safe, len(safe) < len(value)


def _strip_markup(payload: bytes) -> str:
    """Extract text nodes from an OOXML/ODF/EPUB markup part.

    OOXML is XML but parsing arbitrary attacker-controlled XML is unnecessary
    for a preview. The replacement order retains paragraph/table boundaries;
    escaped document text is decoded only after tags are removed.
    """

    source = payload.decode("utf-8", "replace")
    # XPS stores rendered glyph text in UnicodeString attributes rather than
    # ordinary XML text nodes. Preserve those values before removing tags.
    xps_glyph_text = [
        html.unescape(match.group(2))
        for match in re.finditer(r"\bUnicodeString\s*=\s*(['\"])(.*?)\1", source, re.IGNORECASE | re.DOTALL)
    ][:10_000]
    source = re.sub(r"<(?:w:)?(?:tab|br|cr)\b[^>]*/?>", "\t", source, flags=re.IGNORECASE)
    source = re.sub(r"</(?:w:)?(?:p|tr|tc)\s*>", "\n", source, flags=re.IGNORECASE)
    source = re.sub(r"</(?:text:p|text:h|table:table-row|table:table-cell)\s*>", "\n", source, flags=re.IGNORECASE)
    source = re.sub(r"<br\b[^>]*/?>", "\n", source, flags=re.IGNORECASE)
    source = re.sub(r"<[^>]{0,4096}>", "", source)
    source = html.unescape(source).replace("\r\n", "\n").replace("\r", "\n")
    source = re.sub(r"[ \t]+\n", "\n", source)
    source = re.sub(r"\n{3,}", "\n\n", source)
    if xps_glyph_text:
        source = "\n".join(xps_glyph_text + ([source] if source.strip() else []))
    return display_text(source.strip(), MAX_PREVIEW_CHARS)


def _package_member_names(archive: zipfile.ZipFile, extension: str) -> list[str]:
    names = [item.filename for item in archive.infolist() if not item.is_dir()]
    lowered = {name.casefold(): name for name in names}
    if extension in {".docx", ".docm", ".dotx", ".dotm"} or "word/document.xml" in lowered:
        return [
            name for name in names
            if (
                name.casefold().startswith("word/")
                and name.casefold().endswith(".xml")
                and "/_rels/" not in name.casefold()
                and not name.casefold().startswith(("word/theme/", "word/fonts/"))
            )
            or name.casefold().startswith(("docprops/", "customxml/")) and name.casefold().endswith(".xml")
        ]
    if extension in {".xlsx", ".xlsm", ".xltx", ".xltm"} or "xl/sharedstrings.xml" in lowered:
        return [
            name for name in names
            if name.casefold() in {"xl/sharedstrings.xml", "xl/workbook.xml"}
            or name.casefold().startswith(("xl/worksheets/", "xl/comments", "xl/threadedcomments/")) and name.casefold().endswith(".xml")
            or name.casefold().startswith(("docprops/", "customxml/")) and name.casefold().endswith(".xml")
        ]
    if extension in {".pptx", ".pptm", ".ppsx", ".ppsm"} or any(name.casefold().startswith("ppt/slides/slide") for name in names):
        return [
            name for name in names
            if (
                name.casefold().startswith(("ppt/slides/", "ppt/notesslides/", "ppt/comments/"))
                and name.casefold().endswith(".xml")
                and "/_rels/" not in name.casefold()
            )
            or name.casefold().startswith(("docprops/", "customxml/")) and name.casefold().endswith(".xml")
        ]
    if extension in _ODF_EXTENSIONS or "content.xml" in lowered:
        return [lowered[name] for name in ("content.xml", "meta.xml", "settings.xml") if name in lowered]
    if extension == ".epub" or "meta-inf/container.xml" in lowered:
        return [name for name in names if name.casefold().endswith((".xhtml", ".html", ".htm", ".opf", ".ncx"))]
    if extension in {".xps", ".oxps"} or any("fixedpage" in name.casefold() for name in names):
        return [name for name in names if name.casefold().endswith((".fpage", ".fdoc", ".fdseq", ".xml", ".rels"))]
    if extension in {".apk", ".aab", ".jar", ".war", ".ipa", ".appx", ".msix", ".nupkg"}:
        return [
            name for name in names
            if name.casefold().endswith((".xml", ".json", ".txt", ".properties", ".mf", ".html", ".xhtml"))
            or any(marker in name.casefold() for marker in ("manifest", "package", "content_types"))
        ]
    return []


def _validate_package_directory(path: Path) -> None:
    """Reject oversized/multi-disk package indexes before opening ZipFile."""

    size = path.stat().st_size
    if size < 22:
        raise TextPreviewUnavailableError("The document package is too small to contain a ZIP directory.")
    with path.open("rb") as handle:
        handle.seek(max(0, size - (65_535 + 22)))
        tail = handle.read(65_535 + 22)
    eocd = tail.rfind(b"PK\x05\x06")
    if eocd < 0 or eocd + 22 > len(tail):
        raise TextPreviewUnavailableError("The document package has no readable ZIP directory.")
    disk, central_disk, disk_entries, entries, central_size, central_offset, comment_size = struct.unpack_from("<HHHHIIH", tail, eocd + 4)
    if (
        disk != 0 or central_disk != 0 or disk_entries != entries
        or entries >= 0xFFFF or central_size >= 0xFFFFFFFF or central_offset >= 0xFFFFFFFF
        or entries > MAX_PACKAGE_DIRECTORY_ENTRIES or central_size > MAX_PACKAGE_DIRECTORY_BYTES
        or eocd + 22 + comment_size > len(tail) or central_offset + central_size > size
    ):
        raise TextPreviewUnavailableError("The document package directory exceeds preview safety limits.")


def _preview_package(path: Path, extension: str) -> tuple[str, list[str], bool]:
    _validate_package_directory(path)
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        raise TextPreviewUnavailableError("The document package could not be read safely.") from exc
    with archive:
        names = _package_member_names(archive, extension)
        if not names:
            raise TextPreviewUnavailableError("This ZIP artifact is not a recognized readable document package.")
        chunks: list[str] = []
        labels: list[str] = []
        truncated = False
        total_bytes = 0
        for name in names[:MAX_PACKAGE_ENTRIES]:
            try:
                info = archive.getinfo(name)
            except KeyError:
                continue
            mode = (info.external_attr >> 16) & 0o170000
            if (
                info.flag_bits & 0x1
                or mode == 0o120000
                or info.file_size < 1
                or info.file_size > MAX_PACKAGE_ENTRY_BYTES
                or info.compress_size and info.file_size / max(1, info.compress_size) > 200
            ):
                truncated = True
                continue
            remaining = MAX_PREVIEW_BYTES - total_bytes
            if remaining <= 0:
                truncated = True
                break
            try:
                with archive.open(info, "r") as member:
                    payload = member.read(min(remaining, MAX_PACKAGE_ENTRY_BYTES) + 1)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                truncated = True
                continue
            if len(payload) > min(remaining, MAX_PACKAGE_ENTRY_BYTES):
                payload = payload[: min(remaining, MAX_PACKAGE_ENTRY_BYTES)]
                truncated = True
            total_bytes += len(payload)
            text = _strip_markup(payload)
            if not text:
                continue
            chunks.append(f"[{name}]\n{text}")
            labels.append(name)
        if not chunks:
            raise TextPreviewUnavailableError("No readable text was found in the bounded document package entries.")
    return "\n\n".join(chunks), labels, truncated or len(names) > MAX_PACKAGE_ENTRIES


def _preview_parser_records(kind: str, data: bytes) -> tuple[str, list[str]]:
    result = analyze_format(kind, data)
    seen: set[str] = set()
    chunks: list[str] = []
    labels: list[str] = []
    remaining = MAX_PREVIEW_CHARS
    for record in result.get("text_records", []):
        text = str(record.get("text") or "")
        cleaned = display_text(text, remaining)
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        source = display_text(record.get("source") or kind, 160)
        chunks.append(f"[{source}]\n{cleaned}")
        labels.append(source)
        remaining -= len(cleaned)
        if remaining <= 0:
            break
    return "\n\n".join(chunks), labels


def _preview_legacy_ole(data: bytes) -> tuple[str, list[str]]:
    text, labels = _preview_parser_records("ole", data)
    if text:
        return text, labels
    chunks: list[str] = []
    remaining = MAX_PREVIEW_CHARS
    for record in iter_utf16_strings(data, minimum=8, limit=2_000):
        value = display_text(record.get("text"), remaining)
        if not value:
            continue
        chunks.append(value)
        remaining -= len(value)
        if remaining <= 0:
            break
    return "\n".join(chunks), ["legacy Office UTF-16 strings"] if chunks else []


def build_text_preview(path: Path, *, filename: str) -> dict[str, Any]:
    """Return a safe, plain-text document preview for one local artifact.

    The caller has already resolved ``path`` under the job directory. This
    function performs no networking, follows no document links, and limits
    source bytes, ZIP member count, decompressed member bytes, and response
    characters independently.
    """

    data, source_truncated = _read_bounded(path)
    extension = Path(filename).suffix.casefold()
    kind = sniff_kind(data, filename)
    labels: list[str] = []
    encoding = ""
    extraction_truncated = False

    if kind == "text":
        text, encoding = _decode_text_document(data)
        labels = ["plain text"]
    elif kind in {"pdf", "rtf", "eml", "mbox", "pst", "onenote"}:
        text, labels = _preview_parser_records(kind, data)
        encoding = "extracted document text"
    elif kind == "ole" or extension in {".doc", ".xls", ".ppt"}:
        text, labels = _preview_legacy_ole(data)
        encoding = "legacy Office strings"
    elif kind in _PACKAGE_KINDS or (kind == "zip" and extension in (_OOXML_EXTENSIONS | _ODF_EXTENSIONS | {".epub"})):
        text, labels, extraction_truncated = _preview_package(path, extension)
        encoding = "extracted document package text"
        # ZIP-directory validation plus per-member bounds makes it safe to
        # inspect large packages without treating the source-byte cap as a
        # preview cap.
        source_truncated = False
    elif extension in _DOCUMENT_EXTENSIONS:
        # A text extension whose bytes do not satisfy the conservative text
        # classifier should not be decoded blindly.
        raise TextPreviewUnavailableError("The uploaded document does not contain safely readable text.")
    else:
        raise TextPreviewUnavailableError("This artifact does not have a supported text/document preview.")

    if not text:
        text = "No readable text was extracted from the bounded document content."
    text, character_truncated = _clip(text)
    return {
        "name": filename,
        "kind": kind,
        "encoding": encoding or "extracted text",
        "text": text,
        "character_count": len(text),
        "line_count": text.count("\n") + (1 if text else 0),
        "truncated": source_truncated or extraction_truncated or character_truncated,
        "sources": labels[:MAX_PACKAGE_ENTRIES],
    }
