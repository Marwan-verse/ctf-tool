from __future__ import annotations

import hashlib
import math
import mimetypes
import os
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator


PROFILE_LIMITS: dict[str, dict[str, int]] = {
    "quick": {
        "read_bytes": 32 * 1024 * 1024,
        "max_strings": 5_000,
        "max_artifacts": 45,
        "max_artifact_bytes": 192 * 1024 * 1024,
        "max_single_artifact": 48 * 1024 * 1024,
        "decode_depth": 2,
        "decode_nodes": 30,
        "recursion_depth": 4,
        "tool_timeout": 20,
        "visual_megapixels": 24,
    },
    "balanced": {
        "read_bytes": 96 * 1024 * 1024,
        "max_strings": 15_000,
        "max_artifacts": 100,
        "max_artifact_bytes": 500 * 1024 * 1024,
        "max_single_artifact": 96 * 1024 * 1024,
        "decode_depth": 3,
        "decode_nodes": 100,
        "recursion_depth": 12,
        "tool_timeout": 60,
        "visual_megapixels": 40,
    },
    "deep": {
        "read_bytes": 192 * 1024 * 1024,
        "max_strings": 40_000,
        "max_artifacts": 220,
        "max_artifact_bytes": 1024 * 1024 * 1024,
        "max_single_artifact": 192 * 1024 * 1024,
        "decode_depth": 4,
        "decode_nodes": 300,
        "recursion_depth": 12,
        "tool_timeout": 180,
        "visual_megapixels": 64,
    },
}


MIME_BY_KIND = {
    "png": "image/png",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "bmp": "image/bmp",
    "webp": "image/webp",
    "tiff": "image/tiff",
    "ico": "image/x-icon",
    "psd": "image/vnd.adobe.photoshop",
    "xcf": "image/x-xcf",
    "netpbm": "image/x-portable-anymap",
    "heif": "image/heif",
    "avif": "image/avif",
    "wav": "audio/wav",
    "aiff": "audio/aiff",
    "flac": "audio/flac",
    "ogg": "audio/ogg",
    "mp3": "audio/mpeg",
    "aac": "audio/aac",
    "m4a": "audio/mp4",
    "au": "audio/basic",
    "asf": "audio/x-ms-wma",
    "amr": "audio/amr",
    "caf": "audio/x-caf",
    "midi": "audio/midi",
    "mp4": "video/mp4",
    "mov": "video/quicktime",
    "matroska": "video/x-matroska",
    "webm": "video/webm",
    "avi": "video/x-msvideo",
    "pe": "application/vnd.microsoft.portable-executable",
    "elf": "application/x-elf",
    "macho": "application/x-mach-binary",
    "wasm": "application/wasm",
    "dex": "application/vnd.android.dex",
    "java_class": "application/java-vm",
    "java_serialized": "application/x-java-serialized-object",
    "pyc": "application/x-python-code",
    "python_pickle": "application/x-python-pickle",
    "git_pack": "application/x-git-packed-objects",
    "git_index": "application/x-git-index",
    "intel_hex": "application/x-intel-hex",
    "srec": "application/x-motorola-s-record",
    "bencode": "application/x-bittorrent",
    "cbor": "application/cbor",
    "msgpack": "application/msgpack",
    "protobuf": "application/x-protobuf",
    "zip": "application/zip",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "odt": "application/vnd.oasis.opendocument.text",
    "ods": "application/vnd.oasis.opendocument.spreadsheet",
    "odp": "application/vnd.oasis.opendocument.presentation",
    "epub": "application/epub+zip",
    "xps": "application/vnd.ms-xpsdocument",
    "apk": "application/vnd.android.package-archive",
    "aab": "application/zip",
    "jar": "application/java-archive",
    "war": "application/java-archive",
    "appx": "application/vnd.ms-appx",
    "msix": "application/vnd.ms-appx",
    "ipa": "application/x-ios-app",
    "nupkg": "application/zip",
    "gzip": "application/gzip",
    "zlib": "application/zlib",
    "bzip2": "application/x-bzip2",
    "xz": "application/x-xz",
    "zstd": "application/zstd",
    "7z": "application/x-7z-compressed",
    "rar": "application/vnd.rar",
    "tar": "application/x-tar",
    "pdf": "application/pdf",
    "pcap": "application/vnd.tcpdump.pcap",
    "pcapng": "application/x-pcapng",
    "sqlite": "application/vnd.sqlite3",
    "sqlite_wal": "application/x-sqlite3-wal",
    "sqlite_journal": "application/x-sqlite3-journal",
    "thumbcache": "application/x-windows-thumbnail-cache",
    "utmp": "application/x-linux-utmp",
    "ios_mbdb": "application/x-ios-backup-manifest",
    "mozlz4": "application/x-mozilla-jsonlz4",
    "leveldb": "application/x-leveldb",
    "ds_store": "application/x-apple-ds-store",
    "binarycookies": "application/x-apple-binarycookies",
    "ole": "application/x-ole-storage",
    "rtf": "application/rtf",
    "eml": "message/rfc822",
    "mbox": "application/mbox",
    "systemd_journal": "application/x-systemd-journal",
    "disk": "application/x-raw-disk-image",
    "ewf": "application/x-ewf",
    "registry": "application/x-windows-registry-hive",
    "memory": "application/x-memory-dump",
    "evtx": "application/x-windows-event-log",
    "pst": "application/vnd.ms-outlook",
    "lnk": "application/x-ms-shortcut",
    "jumplist": "application/x-ms-jumplist",
    "prefetch": "application/x-windows-prefetch",
    "plist": "application/x-plist",
    "android_backup": "application/x-android-backup",
    "mft": "application/x-ntfs-mft",
    "usn": "application/x-ntfs-usn-journal",
    "recycle_bin_i": "application/x-windows-recycle-bin-metadata",
    "ese": "application/x-esedb",
    "access_db": "application/x-msaccess",
    "hdf5": "application/x-hdf5",
    "bson": "application/bson",
    "qcow": "application/x-qemu-disk",
    "vmdk": "application/x-vmdk",
    "vhd": "application/x-vhd",
    "vhdx": "application/x-vhdx",
    "vdi": "application/x-virtualbox-vdi",
    "dmg": "application/x-apple-diskimage",
    "aff": "application/x-aff",
    "onenote": "application/onenote",
    "shar": "application/x-shar",
    "ar": "application/x-archive",
    "cab": "application/vnd.ms-cab-compressed",
    "cpio": "application/x-cpio",
    "rpm": "application/x-rpm",
    "xar": "application/x-xar",
    "lzip": "application/x-lzip",
    "lz4": "application/x-lz4",
    "lzma": "application/x-lzma",
    "lzop": "application/x-lzop",
    "text": "text/plain",
    "binary": "application/octet-stream",
}


class AnalyzerCancelled(RuntimeError):
    """Raised at a cooperative cancellation boundary."""


def cancel_requested(check: Any) -> bool:
    if check is None:
        return False
    try:
        if callable(check):
            return bool(check())
        if hasattr(check, "is_set"):
            return bool(check.is_set())
        return bool(check)
    except Exception:
        # A broken UI callback must not silently cancel a forensic job.
        return False


def check_cancelled(check: Any) -> None:
    if cancel_requested(check):
        raise AnalyzerCancelled("analysis cancelled")


def utc_now() -> str:
    # Millisecond precision is enough for an audit report and is stable JSON.
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int(time.time_ns() / 1_000_000) % 1000:03d}Z"


def sha256_file(path: os.PathLike[str] | str, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk_size)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bounded_read(path: os.PathLike[str] | str, maximum: int) -> tuple[bytes, bool]:
    with open(path, "rb") as handle:
        data = handle.read(maximum + 1)
    return data[:maximum], len(data) > maximum


def bounded_read_and_sha256(
    path: os.PathLike[str] | str,
    maximum: int,
    chunk_size: int = 1024 * 1024,
) -> tuple[bytes, bool, str, int]:
    """Read a bounded prefix while hashing and sizing the complete file once."""

    if maximum < 0:
        raise ValueError("maximum must be non-negative")
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    digest = hashlib.sha256()
    retained = bytearray()
    total = 0
    with open(path, "rb") as handle:
        while block := handle.read(chunk_size):
            digest.update(block)
            total += len(block)
            if len(retained) < maximum:
                retained.extend(block[: maximum - len(retained)])
    return bytes(retained), total > maximum, digest.hexdigest(), total


def sniff_kind(data: bytes, filename: str = "") -> str:
    extension = Path(filename).suffix.lower()
    basename = Path(filename).name.casefold()
    if basename.endswith((".automaticdestinations-ms", ".customdestinations-ms")):
        return "jumplist"
    if data.startswith(b"mbdb\x05\x00"):
        return "ios_mbdb"
    if data.startswith(b"\0\0\0\x01Bud1") or data.startswith(b"Bud1"):
        return "ds_store"
    if data.startswith(b"cook") and len(data) >= 12:
        cookie_pages = int.from_bytes(data[4:8], "big")
        if cookie_pages <= 20_000 and 8 + cookie_pages * 4 <= len(data):
            return "binarycookies"
    if data.startswith(b"LPKSHHRH"):
        return "systemd_journal"
    if data.startswith(b"mozLz40\0"):
        return "mozlz4"
    if data.startswith((b"CMMM", b"IMMM")) or (len(data) >= 8 and data[4:8] == b"IMMM"):
        return "thumbcache"
    if re.fullmatch(r"(?:u|w|b)tmpx?(?:\.\d+)?", basename) or extension in {".utmp", ".wtmp", ".btmp"}:
        return "utmp"
    leveldb_table_magic = b"\x57\xfb\x80\x8b\x24\x75\x47\xdb"
    if data.endswith(leveldb_table_magic) or extension in {".ldb", ".sst"}:
        return "leveldb"
    if (basename.startswith("manifest-") or extension == ".log") and len(data) >= 7:
        first_length = int.from_bytes(data[4:6], "little")
        if data[6] in {1, 2, 3, 4} and first_length <= min(len(data) - 7, 32_761):
            return "leveldb"
    if data.startswith(b"ANDROID BACKUP\n"):
        return "android_backup"
    if data.startswith(b"bplist00"):
        return "plist"
    plist_head = data[:8192].lstrip(b"\xef\xbb\xbf\x00\t\r\n ")
    if plist_head.startswith(b"<?xml") and b"<plist" in plist_head.lower():
        return "plist"
    if (
        len(data) >= 76
        and data[:4] == b"L\0\0\0"
        and data[4:20] == bytes.fromhex("0114020000000000c000000000000046")
    ):
        return "lnk"
    if data.startswith(b"MAM\x04") and extension == ".pf":
        return "prefetch"
    if len(data) >= 8 and data[4:8] == b"SCCA":
        return "prefetch"
    if len(data) >= 8 and data[4:8] == b"\xef\xcd\xab\x89":
        return "ese"
    if data.startswith(b"QFI\xfb"):
        return "qcow"
    if data.startswith(b"KDMV") or data.startswith(b"# Disk DescriptorFile"):
        return "vmdk"
    if data.startswith(b"vhdxfile"):
        return "vhdx"
    if data.startswith(b"<<< Oracle VM VirtualBox Disk Image >>>"):
        return "vdi"
    if extension == ".vhd" or (len(data) >= 512 and (data[:8] == b"conectix" or data[-512:-504] == b"conectix")):
        return "vhd"
    if data.startswith(b"AFF10") or extension in {".aff", ".aff4"}:
        return "aff"
    if (extension == ".dmg" and data) or len(data) >= 512 and data[-512:-508] == b"koly":
        return "dmg"
    if (basename == "$mft" or extension == ".mft") and data[:4] in {b"FILE", b"BAAD"}:
        return "mft"
    if basename in {"$j", "$usnjrnl", "$usnjrnl:$j"} or extension in {".usn", ".usnjrnl"}:
        return "usn"
    if basename.startswith("$i") and len(data) >= 24 and int.from_bytes(data[:8], "little") in {1, 2}:
        return "recycle_bin_i"
    if data.startswith(b"#!/bin/sh") and b"begin " in data[:64 * 1024] and b"uudecode" in data[:64 * 1024]:
        return "shar"
    if data.startswith(b"!<arch>\n"):
        return "ar"
    if data.startswith(b"MSCF"):
        return "cab"
    if data.startswith((b"070701", b"070702", b"070707", b"\x71\xc7", b"\xc7\x71")):
        return "cpio"
    if data.startswith(b"\xed\xab\xee\xdb"):
        return "rpm"
    if data.startswith(b"xar!"):
        return "xar"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if data.startswith(b"BM"):
        return "bmp"
    if data.startswith(b"8BPS"):
        return "psd"
    if data.startswith(b"gimp xcf "):
        return "xcf"
    if len(data) >= 3 and data[:2] in {b"P1", b"P2", b"P3", b"P4", b"P5", b"P6", b"P7"} and data[2] in b" \t\r\n#":
        return "netpbm"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return "wav"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"AVI ":
        return "avi"
    if len(data) >= 12 and data[:4] == b"FORM" and data[8:12] in {b"AIFF", b"AIFC"}:
        return "aiff"
    if data.startswith(b"fLaC"):
        return "flac"
    if data.startswith(b"OggS"):
        return "ogg"
    if data.startswith(b"ID3") or (len(data) >= 2 and data[0] == 0xFF and data[1] & 0xE6 == 0xE2):
        return "mp3"
    if len(data) >= 2 and data[0] == 0xFF and data[1] & 0xF6 == 0xF0:
        return "aac"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12]
        if extension == ".avif" or brand in {b"avif", b"avis"}:
            return "avif"
        if extension in {".heif", ".heic", ".heifs", ".heics"} or brand in {b"heic", b"heix", b"hevc", b"hevx", b"mif1", b"msf1"}:
            return "heif"
        if extension in {".m4a", ".m4b", ".m4p"}:
            return "m4a"
        if extension == ".mov" or brand == b"qt  ":
            return "mov"
        return "mp4"
    if data.startswith(b".snd"):
        return "au"
    if data.startswith(b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c"):
        return "asf"
    if data.startswith(b"#!AMR\n"):
        return "amr"
    if data.startswith(b"caff"):
        return "caf"
    if data.startswith(b"MThd"):
        return "midi"
    if data.startswith(b"\x1aE\xdf\xa3"):
        header = data[:4096].lower()
        if extension == ".webm" or b"webm" in header:
            return "webm"
        return "matroska"
    if data.startswith(b"MZ") and len(data) >= 64:
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if 0x40 <= pe_offset <= min(len(data) - 4, 16 * 1024 * 1024) and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
            return "pe"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if (
        data.startswith(b"\xca\xfe\xba\xbe")
        and len(data) >= 10
        and 45 <= int.from_bytes(data[6:8], "big") <= 100
        and int.from_bytes(data[8:10], "big") > 0
    ):
        return "java_class"
    if data[:4] in {
        b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
        b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf",
    }:
        return "macho"
    if data.startswith(b"\x00asm"):
        return "wasm"
    if data.startswith(b"dex\n") and len(data) >= 8 and data[7] == 0:
        return "dex"
    if data.startswith(b"\xac\xed\x00\x05"):
        return "java_serialized"
    if data.startswith(b"PACK") and len(data) >= 12 and 2 <= int.from_bytes(data[4:8], "big") <= 3:
        return "git_pack"
    if data.startswith(b"DIRC") and len(data) >= 12 and 2 <= int.from_bytes(data[4:8], "big") <= 4:
        return "git_index"
    if any(data[offset:offset + 8] == b"\x89HDF\r\n\x1a\n" for offset in (0, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)):
        return "hdf5"
    if len(data) >= 32 and data[4:20].startswith((b"Standard Jet DB", b"Standard ACE DB")):
        return "access_db"
    if data.startswith(b"\xd9\xd9\xf7"):
        return "cbor"
    if data.startswith(b"d8:announce"):
        return "bencode"
    if data.startswith((b"II*\x00", b"MM\x00*", b"II+\x00", b"MM\x00+")):
        return "tiff"
    if data.startswith(b"\x00\x00\x01\x00") or data.startswith(b"\x00\x00\x02\x00"):
        return "ico"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        return {
            ".docx": "docx", ".xlsx": "xlsx", ".pptx": "pptx",
            ".docm": "docx", ".dotx": "docx", ".dotm": "docx",
            ".xlsm": "xlsx", ".xltx": "xlsx", ".xltm": "xlsx",
            ".pptm": "pptx", ".ppsx": "pptx", ".ppsm": "pptx",
            ".odt": "odt", ".ods": "ods", ".odp": "odp", ".epub": "epub",
            ".xps": "xps", ".oxps": "xps", ".apk": "apk", ".aab": "aab",
            ".jar": "jar", ".war": "war", ".ear": "jar", ".ipa": "ipa",
            ".appx": "appx", ".appxbundle": "appx", ".msix": "msix", ".msixbundle": "msix",
            ".nupkg": "nupkg", ".vsix": "nupkg",
        }.get(extension, "zip")
    if data.startswith(b"7z\xbc\xaf'\x1c"):
        return "7z"
    if data.startswith(b"Rar!\x1a\x07"):
        return "rar"
    if data.startswith(b"LZIP\x01"):
        return "lzip"
    if data.startswith(b"\x04\x22\x4d\x18"):
        return "lz4"
    if data.startswith(b"\x89LZO\x00\r\n\x1a\n"):
        return "lzop"
    if len(data) >= 13 and data[0] in {0x5D, 0x5E, 0x5F, 0x60, 0x61}:
        dictionary_size = int.from_bytes(data[1:5], "little")
        if 4096 <= dictionary_size <= 128 * 1024 * 1024 and dictionary_size & (dictionary_size - 1) == 0:
            return "lzma"
    if len(data) >= 265 and data[257:263] in {b"ustar\x00", b"ustar "}:
        return "tar"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if len(data) >= 2 and data[0] == 0x78 and ((data[0] << 8) + data[1]) % 31 == 0:
        return "zlib"
    if data.startswith(b"BZh"):
        return "bzip2"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if data.startswith(b"(\xb5/\xfd"):
        return "zstd"
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    if data[:4] in {b"7\x7f\x06\x82", b"7\x7f\x06\x83"}:
        return "sqlite_wal"
    if data.startswith(b"\xd9\xd5\x05\xf9 \xa1c\xd7"):
        return "sqlite_journal"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if data.startswith(b"{\\rtf"):
        return "rtf"
    if data.startswith(b"\x0a\x0d\x0d\x0a"):
        return "pcapng"
    if data[:4] in {
        b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
    }:
        return "pcap"
    if data.startswith(b"EVF\x09\x0d\x0a\xff\x00"):
        return "ewf"
    if data.startswith(b"regf"):
        return "registry"
    if data.startswith(b"ElfFile\x00"):
        return "evtx"
    if data.startswith(b"!BDN"):
        return "pst"
    if data.startswith(bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")):
        return "onenote"
    if data.startswith((b"MDMP", b"PAGEDUMP", b"PAGEDU64")):
        return "memory"
    if _looks_like_disk_image(data):
        return "disk"
    if extension in {".mbox", ".mbx"} or _looks_like_mbox(data[:64 * 1024]):
        return "mbox"
    if extension == ".eml" or _looks_like_email(data[:64 * 1024]):
        return "eml"
    markup_head = data[:8192].lstrip(b"\xef\xbb\xbf\x00\t\r\n ").lower()
    if b"<svg" in markup_head and (markup_head.startswith((b"<svg", b"<?xml", b"<!--"))):
        return "svg"
    if data and extension in {".torrent", ".bencode"} and data[:1] in b"dli0123456789":
        return "bencode"
    if extension in {".cbor", ".cborseq", ".cose"}:
        return "cbor"
    if extension in {".msgpack", ".mpk"}:
        return "msgpack"
    if extension in {".pb", ".protobuf"}:
        return "protobuf"
    if extension == ".bson" and len(data) >= 5:
        declared = int.from_bytes(data[:4], "little", signed=True)
        if 5 <= declared <= len(data) and data[declared - 1] == 0:
            return "bson"
    if extension in {".pkl", ".pickle"}:
        return "python_pickle"
    if extension == ".pyc":
        return "pyc"
    if extension in {".hex", ".ihex", ".ihx"} and re.match(br"(?m)^:[0-9A-Fa-f]{10,}$", data[:8192]):
        return "intel_hex"
    if extension in {".srec", ".s19", ".s28", ".s37", ".mot"} and re.match(br"(?m)^S[0-9][0-9A-Fa-f]{8,}$", data[:8192]):
        return "srec"
    if data and _looks_textual(data[:8192]):
        return "text"
    return {
        ".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg", ".jpe": "jpeg",
        ".gif": "gif", ".bmp": "bmp", ".webp": "webp", ".svg": "svg",
        ".tif": "tiff", ".tiff": "tiff", ".ico": "ico", ".cur": "ico",
        ".psd": "psd", ".psb": "psd", ".xcf": "xcf",
        ".pbm": "netpbm", ".pgm": "netpbm", ".ppm": "netpbm", ".pnm": "netpbm", ".pam": "netpbm",
        ".heif": "heif", ".heic": "heif", ".heifs": "heif", ".heics": "heif", ".avif": "avif",
        ".wav": "wav", ".wave": "wav", ".aif": "aiff", ".aiff": "aiff", ".aifc": "aiff",
        ".flac": "flac", ".ogg": "ogg", ".oga": "ogg", ".opus": "ogg",
        ".mp3": "mp3", ".aac": "aac", ".m4a": "m4a", ".m4b": "m4a",
        ".mp4": "mp4", ".mov": "mov", ".mkv": "matroska", ".webm": "webm", ".avi": "avi",
        ".au": "au", ".snd": "au", ".wma": "asf", ".amr": "amr", ".caf": "caf",
        ".mid": "midi", ".midi": "midi",
        ".7z": "7z", ".rar": "rar", ".tar": "tar", ".cab": "cab", ".cpio": "cpio", ".rpm": "rpm", ".xar": "xar",
        ".lzip": "lzip", ".lz4": "lz4", ".lzma": "lzma", ".lzo": "lzop", ".lzop": "lzop",
        ".tgz": "gzip", ".tbz": "bzip2", ".tbz2": "bzip2", ".txz": "xz",
        ".pcap": "pcap", ".cap": "pcap", ".pcapng": "pcapng",
        ".sqlite": "sqlite", ".sqlite3": "sqlite", ".db": "sqlite",
        ".sqlite-wal": "sqlite_wal", ".db-wal": "sqlite_wal",
        ".sqlite-journal": "sqlite_journal", ".db-journal": "sqlite_journal",
        ".mbdb": "ios_mbdb", ".binarycookies": "binarycookies", ".dsstore": "ds_store",
        ".utmp": "utmp", ".wtmp": "utmp", ".btmp": "utmp",
        ".jsonlz4": "mozlz4", ".baklz4": "mozlz4", ".mozlz4": "mozlz4",
        ".ldb": "leveldb", ".sst": "leveldb",
        ".h5": "hdf5", ".hdf": "hdf5", ".hdf5": "hdf5", ".he5": "hdf5",
        ".bson": "bson", ".mdb": "access_db", ".accdb": "access_db",
        ".doc": "ole", ".xls": "ole", ".ppt": "ole", ".msg": "ole",
        ".rtf": "rtf", ".eml": "eml", ".mbox": "mbox", ".mbx": "mbox", ".journal": "systemd_journal",
        ".lnk": "lnk", ".pf": "prefetch", ".plist": "plist", ".ab": "android_backup",
        ".automaticdestinations-ms": "jumplist", ".customdestinations-ms": "jumplist",
        ".mft": "mft", ".usn": "usn", ".usnjrnl": "usn", ".edb": "ese",
        ".img": "disk", ".dd": "disk", ".iso": "disk", ".vhd": "vhd",
        ".vhdx": "vhdx", ".vmdk": "vmdk", ".qcow": "qcow", ".qcow2": "qcow",
        ".vdi": "vdi", ".dmg": "dmg", ".aff": "aff", ".aff4": "aff",
        ".e01": "ewf", ".ex01": "ewf", ".s01": "ewf",
        ".dat": "binary", ".hive": "registry",
        ".vmem": "memory", ".mem": "memory", ".lime": "memory", ".dmp": "memory", ".raw": "memory",
        ".evtx": "evtx", ".pst": "pst", ".ost": "pst",
        ".one": "onenote", ".onetoc2": "onenote",
        ".exe": "pe", ".dll": "pe", ".sys": "pe", ".efi": "pe",
        ".elf": "elf", ".so": "elf", ".o": "elf", ".dylib": "macho", ".wasm": "wasm",
        ".dex": "dex", ".class": "java_class",
        ".ser": "java_serialized", ".serialized": "java_serialized", ".pyc": "pyc",
        ".pkl": "python_pickle", ".pickle": "python_pickle",
        ".pack": "git_pack", ".idx": "git_index",
        ".hex": "intel_hex", ".ihex": "intel_hex", ".ihx": "intel_hex",
        ".srec": "srec", ".s19": "srec", ".s28": "srec", ".s37": "srec", ".mot": "srec",
        ".torrent": "bencode", ".bencode": "bencode",
        ".cbor": "cbor", ".cborseq": "cbor", ".cose": "cbor",
        ".msgpack": "msgpack", ".mpk": "msgpack",
        ".pb": "protobuf", ".protobuf": "protobuf",
    }.get(extension, "binary")


def _looks_like_email(data: bytes) -> bool:
    """Recognize an RFC 5322-style message without treating arbitrary text as mail."""

    if not data:
        return False
    head = data.replace(b"\r\n", b"\n")
    separator = head.find(b"\n\n")
    header = head[:separator if separator >= 0 else min(len(head), 16 * 1024)]
    names = set()
    for line in header.splitlines()[:200]:
        match = re.match(br"^([A-Za-z][A-Za-z0-9-]{0,63}):", line)
        if match:
            names.add(match.group(1).lower())
    return bool({b"from", b"to", b"subject", b"date", b"message-id"} & names) and (
        b"mime-version" in names or b"content-type" in names or len(names) >= 4
    )


def _looks_like_mbox(data: bytes) -> bool:
    """Recognize an MBOX From_ envelope followed by an RFC-style message."""

    if not data.startswith(b"From "):
        return False
    line_end = data.find(b"\n")
    if line_end < 6 or line_end > 1000:
        return False
    return _looks_like_email(data[line_end + 1:])


def _looks_like_disk_image(data: bytes) -> bool:
    """Recognize common raw disk/filesystem headers using bounded invariants."""

    if len(data) >= 520 and data[512:520] == b"EFI PART":
        return True
    if len(data) >= 512 and data[510:512] == b"\x55\xaa":
        entries = data[446:510]
        plausible = 0
        for offset in range(0, len(entries), 16):
            entry = entries[offset:offset + 16]
            if len(entry) < 16 or entry[0] not in {0x00, 0x80} or entry[4] == 0:
                continue
            start = int.from_bytes(entry[8:12], "little")
            sectors = int.from_bytes(entry[12:16], "little")
            if start > 0 and sectors > 0:
                plausible += 1
        if plausible:
            return True
    if len(data) >= 1082 and data[1080:1082] == b"\x53\xef":
        return True
    if len(data) >= 11 and data[3:11] == b"NTFS    ":
        return True
    if len(data) >= 11 and data[3:11] == b"EXFAT   ":
        return True
    if len(data) >= 90 and (data[54:62].startswith(b"FAT") or data[82:90].startswith(b"FAT")):
        return True
    if len(data) >= 36 and data[32:36] == b"NXSB":
        return True
    if len(data) >= 1026 and data[1024:1026] in {b"BD", b"H+", b"HX"}:
        return True
    if data.startswith(b"XFSB") or data.startswith((b"hsqs", b"sqsh", b"\x45\x3d\xcd\x28")):
        return True
    if len(data) >= 65_608 and data[65_600:65_608] == b"_BHRfS_M":
        return True
    if data.startswith(b"LUKS\xba\xbe") or (len(data) >= 11 and data[3:11] == b"-FVE-FS-"):
        return True
    if len(data) >= 32774 and data[32769:32774] == b"CD001":
        return True
    return False


def mime_for(kind: str, filename: str = "") -> str:
    return MIME_BY_KIND.get(kind) or mimetypes.guess_type(filename)[0] or "application/octet-stream"


def extension_for(kind: str) -> str:
    return {
        "png": ".png", "jpeg": ".jpg", "gif": ".gif", "bmp": ".bmp",
        "webp": ".webp", "svg": ".svg", "tiff": ".tiff", "ico": ".ico", "zip": ".zip",
        "psd": ".psd", "xcf": ".xcf", "netpbm": ".pnm", "heif": ".heif", "avif": ".avif",
        "docx": ".docx", "xlsx": ".xlsx", "pptx": ".pptx",
        "odt": ".odt", "ods": ".ods", "odp": ".odp", "epub": ".epub",
        "xps": ".xps", "apk": ".apk", "aab": ".aab", "jar": ".jar", "war": ".war",
        "appx": ".appx", "msix": ".msix", "ipa": ".ipa", "nupkg": ".nupkg",
        "wav": ".wav", "aiff": ".aiff", "flac": ".flac", "ogg": ".ogg",
        "mp3": ".mp3", "aac": ".aac", "m4a": ".m4a", "au": ".au",
        "asf": ".wma", "amr": ".amr", "caf": ".caf", "midi": ".mid",
        "mp4": ".mp4", "mov": ".mov", "matroska": ".mkv", "webm": ".webm", "avi": ".avi",
        "pe": ".exe", "elf": ".elf", "macho": ".macho", "wasm": ".wasm",
        "dex": ".dex", "java_class": ".class",
        "java_serialized": ".ser", "pyc": ".pyc", "python_pickle": ".pickle",
        "git_pack": ".pack", "git_index": ".idx", "intel_hex": ".hex", "srec": ".srec",
        "bencode": ".torrent", "cbor": ".cbor", "msgpack": ".msgpack", "protobuf": ".pb",
        "gzip": ".gz", "zlib": ".zlib", "bzip2": ".bz2", "xz": ".xz", "zstd": ".zst",
        "7z": ".7z", "rar": ".rar", "tar": ".tar", "shar": ".shar", "ar": ".a",
        "cab": ".cab", "cpio": ".cpio", "rpm": ".rpm", "xar": ".xar",
        "lzip": ".lz", "lz4": ".lz4", "lzma": ".lzma", "lzop": ".lzo",
        "pdf": ".pdf", "pcap": ".pcap", "pcapng": ".pcapng", "sqlite": ".sqlite",
        "sqlite_wal": ".sqlite-wal", "sqlite_journal": ".sqlite-journal",
        "thumbcache": ".db", "utmp": ".wtmp", "ios_mbdb": ".mbdb",
        "mozlz4": ".jsonlz4", "leveldb": ".ldb", "ds_store": ".DS_Store",
        "binarycookies": ".binarycookies",
        "hdf5": ".h5", "bson": ".bson", "access_db": ".accdb",
        "ole": ".ole", "rtf": ".rtf", "eml": ".eml", "mbox": ".mbox",
        "systemd_journal": ".journal", "disk": ".img", "ewf": ".E01",
        "registry": ".hive", "memory": ".mem", "text": ".txt",
        "evtx": ".evtx", "pst": ".pst",
        "lnk": ".lnk", "prefetch": ".pf", "plist": ".plist", "android_backup": ".ab",
        "jumplist": ".automaticDestinations-ms",
        "mft": ".mft", "usn": ".usn", "ese": ".edb", "qcow": ".qcow2",
        "recycle_bin_i": ".recycle-bin-i",
        "vmdk": ".vmdk", "vhd": ".vhd", "vhdx": ".vhdx", "vdi": ".vdi", "dmg": ".dmg", "aff": ".aff4",
        "onenote": ".one",
    }.get(kind, ".bin")


def safe_label(value: str, maximum: int = 80) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip()).strip("._")
    return (value or "artifact")[:maximum]


def display_text(value: Any, maximum: int = 4096) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    value = str(value).replace("\x00", "\\0")
    # Keep tabs/newlines; remove terminal control sequences and bidi controls.
    value = "".join(ch for ch in value if ch in "\n\r\t" or (ord(ch) >= 32 and ch not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"))
    return value[:maximum]


def byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _looks_textual(data: bytes) -> bool:
    if not data:
        return False
    acceptable = sum(1 for byte in data if byte in (9, 10, 13) or 32 <= byte <= 126)
    return acceptable / len(data) >= 0.88


def iter_ascii_strings(data: bytes, minimum: int = 4, limit: int = 10_000) -> Iterator[dict[str, Any]]:
    if limit <= 0:
        return
    pattern = re.compile(rb"[\x09\x20-\x7e]{%d,}" % max(1, minimum))
    for emitted, match in enumerate(pattern.finditer(data), 1):
        yield {"encoding": "ascii", "offset": match.start(), "text": match.group().decode("ascii", "replace")}
        if emitted >= limit:
            return


def iter_utf16_strings(data: bytes, minimum: int = 4, limit: int = 5_000) -> Iterator[dict[str, Any]]:
    if limit <= 0:
        return
    minimum = max(1, minimum)
    patterns = (
        ("utf-16-le", re.compile(rb"(?:[\x09\x20-\x7e]\x00){%d,}" % minimum), slice(None, None, 2)),
        ("utf-16-be", re.compile(rb"(?:\x00[\x09\x20-\x7e]){%d,}" % minimum), slice(1, None, 2)),
    )
    emitted = 0
    for encoding, pattern, text_slice in patterns:
        for match in pattern.finditer(data):
            yield {
                "encoding": encoding,
                "offset": match.start(),
                "text": match.group()[text_slice].decode("ascii", "replace"),
            }
            emitted += 1
            if emitted >= limit:
                return


def find_magic_offsets(data: bytes, maximum_per_kind: int = 20) -> list[dict[str, Any]]:
    signatures = {
        "png": b"\x89PNG\r\n\x1a\n", "jpeg": b"\xff\xd8\xff", "gif87a": b"GIF87a",
        "gif89a": b"GIF89a", "zip": b"PK\x03\x04", "pdf": b"%PDF-",
        "gzip": b"\x1f\x8b\x08", "bzip2": b"BZh", "xz": b"\xfd7zXZ\x00",
        "7zip": b"7z\xbc\xaf'\x1c", "rar": b"Rar!\x1a\x07", "sqlite": b"SQLite format 3\x00",
        "pcapng": b"\x0a\x0d\x0d\x0a", "ole": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        "registry": b"regf", "evtx": b"ElfFile\x00", "pst": b"!BDN",
    }
    hits: list[dict[str, Any]] = []
    for name, signature in signatures.items():
        start = 0
        for _ in range(maximum_per_kind):
            offset = data.find(signature, start)
            if offset < 0:
                break
            hits.append({"kind": name, "offset": offset, "signature_hex": signature.hex()})
            start = offset + 1
    return sorted(hits, key=lambda item: (item["offset"], item["kind"]))


def normalize_json(value: Any, depth: int = 0) -> Any:
    """Convert third-party metadata values into deterministic JSON primitives."""
    if depth > 8:
        return display_text(value, 256)
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {"encoding": "hex", "value": value[:256].hex(), "truncated": len(value) > 256}
    if isinstance(value, dict):
        return {display_text(key, 128): normalize_json(val, depth + 1) for key, val in list(value.items())[:500]}
    if isinstance(value, (list, tuple, set)):
        return [normalize_json(item, depth + 1) for item in list(value)[:500]]
    return display_text(value)


def iter_chunks(iterable: Iterable[Any], size: int) -> Iterator[list[Any]]:
    bucket: list[Any] = []
    for item in iterable:
        bucket.append(item)
        if len(bucket) == size:
            yield bucket
            bucket = []
    if bucket:
        yield bucket
