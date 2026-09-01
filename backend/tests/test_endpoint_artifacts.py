from __future__ import annotations

import codecs
import io
import hashlib
import plistlib
import sqlite3
import struct
import tarfile
import zlib

from app.analyzers.common import sniff_kind
from app.analyzers.formats import analyze_format


def _android_backup() -> bytes:
    archive_bytes = io.BytesIO()
    with tarfile.open(fileobj=archive_bytes, mode="w") as archive:
        payload = b"flag{android_backup_fixture}\n"
        info = tarfile.TarInfo("apps/example/files/flag.txt")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    return b"ANDROID BACKUP\n5\n1\nnone\n" + zlib.compress(archive_bytes.getvalue())


def _ds_store() -> bytes:
    name = "flag{ds_store_deleted_name}.txt".encode("utf-16-be")
    comment = "flag{ds_store_comment}".encode("utf-16-be")
    record = (
        (len(name) // 2).to_bytes(4, "big") + name + b"cmmt" + b"ustr"
        + (len(comment) // 2).to_bytes(4, "big") + comment
    )
    return b"\0\0\0\x01Bud1" + b"\0" * 32 + record + b"\0" * 32


def _binarycookies() -> bytes:
    strings = [b"ctf.example\0", b"challenge\0", b"/\0", b"flag{binarycookies_value}\0"]
    offsets: list[int] = []
    string_data = bytearray()
    for value in strings:
        offsets.append(56 + len(string_data))
        string_data.extend(value)
    record_size = 56 + len(string_data)
    record = struct.pack(
        "<IIIIIIIIQdd", record_size, 0, 0x05, 0, *offsets, 0, 800_000_000.0, 700_000_000.0,
    ) + bytes(string_data)
    page = b"\0\0\x01\0" + (1).to_bytes(4, "little") + (16).to_bytes(4, "little") + b"\0" * 4 + record
    checksum = sum(page[::4]) & 0xFFFFFFFF
    return b"cook" + (1).to_bytes(4, "big") + len(page).to_bytes(4, "big") + page + checksum.to_bytes(4, "big") + b"\x07\x17\x20\x05"


def _systemd_journal() -> bytes:
    def journal_object(object_type: int, payload: bytes, *, fixed_size: int) -> bytes:
        size = fixed_size + len(payload)
        record = bytearray(size)
        record[0] = object_type
        record[8:16] = size.to_bytes(8, "little")
        record[fixed_size:] = payload
        return bytes(record) + b"\0" * ((-size) % 8)

    message = journal_object(1, b"MESSAGE=flag{systemd_journal_message}", fixed_size=64)
    unit = journal_object(1, b"_SYSTEMD_UNIT=ctf.service", fixed_size=64)
    entry = bytearray(64)
    entry[0] = 3
    entry[8:16] = (64).to_bytes(8, "little")
    entry[16:24] = (17).to_bytes(8, "little")
    entry[24:32] = (1_700_000_000_123_456).to_bytes(8, "little")
    objects = message + unit + bytes(entry)
    header = bytearray(256)
    header[:8] = b"LPKSHHRH"
    header[16] = 2
    header[88:96] = len(header).to_bytes(8, "little")
    header[96:104] = len(objects).to_bytes(8, "little")
    header[144:152] = (3).to_bytes(8, "little")
    header[152:160] = (1).to_bytes(8, "little")
    return bytes(header) + objects


def _registry_hive(*, legacy_11: bool = False, segmented: bool = False) -> bytes:
    hbin_size = 32768 if segmented else 4096
    hive = bytearray(4096 + hbin_size)
    hive[:4] = b"regf"
    hive[4:8] = (1).to_bytes(4, "little")
    hive[8:12] = (1).to_bytes(4, "little")
    hive[20:24] = (1).to_bytes(4, "little")
    hive[24:28] = (1 if legacy_11 else 3).to_bytes(4, "little")
    hive[40:44] = hbin_size.to_bytes(4, "little")
    hive[4096:4100] = b"hbin"
    hive[4104:4108] = hbin_size.to_bytes(4, "little")
    relative = 32

    def add_cell(payload: bytes) -> int:
        nonlocal relative
        cell_size = (4 + len(payload) + 7) & ~7
        absolute = 4096 + relative
        hive[absolute:absolute + 4] = (-cell_size).to_bytes(4, "little", signed=True)
        hive[absolute + 4:absolute + 4 + len(payload)] = payload
        previous = relative
        relative += cell_size
        return previous

    key_name = b"UserAssist\\Count"
    record_prefix = 4 if legacy_11 else 0
    key = bytearray(record_prefix + 76 + len(key_name))
    key[record_prefix:record_prefix + 2] = b"nk"
    key[record_prefix + 2:record_prefix + 4] = (0x20).to_bytes(2, "little")
    key[record_prefix + 4:record_prefix + 12] = (133_000_000_000_000_000).to_bytes(8, "little")
    key[record_prefix + 16:record_prefix + 20] = (0xFFFFFFFF).to_bytes(4, "little")
    key[record_prefix + 36:record_prefix + 40] = (2 if segmented else 1).to_bytes(4, "little")
    key[record_prefix + 72:record_prefix + 74] = len(key_name).to_bytes(2, "little")
    key[record_prefix + 76:] = key_name
    key_relative = add_cell(bytes(key))
    value_list_relative = add_cell(b"\0" * ((4 if legacy_11 else 0) + (8 if segmented else 4)))

    decoded_name = r"C:\flag{registry_userassist}.exe"
    encoded_name = codecs.encode(decoded_name, "rot_13").encode("ascii")
    value = bytearray(record_prefix + 20 + len(encoded_name))
    value[record_prefix:record_prefix + 2] = b"vk"
    value[record_prefix + 2:record_prefix + 4] = len(encoded_name).to_bytes(2, "little")
    value[record_prefix + 4:record_prefix + 8] = (72).to_bytes(4, "little")
    value[record_prefix + 12:record_prefix + 16] = (3).to_bytes(4, "little")
    value[record_prefix + 16:record_prefix + 18] = (1).to_bytes(2, "little")
    value[record_prefix + 20:] = encoded_name
    value_relative = add_cell(bytes(value))

    userassist = bytearray(72)
    userassist[4:8] = (7).to_bytes(4, "little")
    userassist[8:12] = (3).to_bytes(4, "little")
    userassist[12:16] = (1250).to_bytes(4, "little")
    userassist[60:68] = (133_000_000_000_000_000).to_bytes(8, "little")
    data_relative = add_cell((b"\0" * record_prefix) + bytes(userassist))

    segmented_value_relative: int | None = None
    if segmented:
        segmented_name = codecs.encode("segmented_flag", "rot_13").encode("ascii")
        segmented_value = bytearray(20 + len(segmented_name))
        segmented_value[:2] = b"vk"
        segmented_value[2:4] = len(segmented_name).to_bytes(2, "little")
        segmented_value[4:8] = (20_000).to_bytes(4, "little")
        segmented_value[12:16] = (3).to_bytes(4, "little")
        segmented_value[16:18] = (1).to_bytes(2, "little")
        segmented_value[20:] = segmented_name
        segmented_value_relative = add_cell(bytes(segmented_value))
        data_block_relative = add_cell(b"db" + (2).to_bytes(2, "little") + b"\0" * 8)
        segment_list_relative = add_cell(b"\0" * 8)
        first_segment_relative = add_cell(b"A" * 16_344)
        tail = b"flag{registry_segmented_data}"
        second_segment_relative = add_cell(tail + b"B" * (3_656 - len(tail)))
        segmented_absolute = 4096 + segmented_value_relative + 4
        block_absolute = 4096 + data_block_relative + 4
        segment_list_absolute = 4096 + segment_list_relative + 4
        hive[segmented_absolute + 8:segmented_absolute + 12] = data_block_relative.to_bytes(4, "little")
        hive[block_absolute + 4:block_absolute + 8] = segment_list_relative.to_bytes(4, "little")
        hive[segment_list_absolute:segment_list_absolute + 4] = first_segment_relative.to_bytes(4, "little")
        hive[segment_list_absolute + 4:segment_list_absolute + 8] = second_segment_relative.to_bytes(4, "little")

    key_absolute = 4096 + key_relative + 4
    list_absolute = 4096 + value_list_relative + 4
    value_absolute = 4096 + value_relative + 4
    hive[key_absolute + record_prefix + 40:key_absolute + record_prefix + 44] = value_list_relative.to_bytes(4, "little")
    hive[list_absolute + record_prefix:list_absolute + record_prefix + 4] = value_relative.to_bytes(4, "little")
    if segmented_value_relative is not None:
        hive[list_absolute + record_prefix + 4:list_absolute + record_prefix + 8] = segmented_value_relative.to_bytes(4, "little")
    hive[value_absolute + record_prefix + 8:value_absolute + record_prefix + 12] = data_relative.to_bytes(4, "little")
    hive[36:40] = key_relative.to_bytes(4, "little")

    free_size = hbin_size - relative
    hive[4096 + relative:4100 + relative] = free_size.to_bytes(4, "little", signed=True)
    return bytes(hive)


def _mbox() -> bytes:
    return (
        b"From first@example.test Sat Jan 01 00:00:00 2022\n"
        b"From: first@example.test\nTo: player@example.test\nSubject: flag{mbox_subject}\n"
        b"Date: Sat, 01 Jan 2022 00:00:00 +0000\nMessage-ID: <one@example.test>\n"
        b"MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nflag{mbox_body}\n"
        b"From second@example.test Sun Jan 02 00:00:00 2022\n"
        b"From: second@example.test\nTo: player@example.test\nSubject: attachment\n"
        b"Date: Sun, 02 Jan 2022 00:00:00 +0000\nMessage-ID: <two@example.test>\n"
        b"MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=ctf-boundary\n\n"
        b"--ctf-boundary\nContent-Type: text/plain\n\nsecond message\n"
        b"--ctf-boundary\nContent-Type: application/octet-stream\n"
        b"Content-Disposition: attachment; filename=flag.bin\nContent-Transfer-Encoding: base64\n\n"
        b"ZmxhZ3ttYm94X2F0dGFjaG1lbnR9\n--ctf-boundary--\n"
    )


def _browser_sqlite() -> bytes:
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
        CREATE TABLE visits (url INTEGER, visit_time INTEGER, transition INTEGER);
        CREATE TABLE keyword_search_terms (url_id INTEGER, term TEXT);
        CREATE TABLE downloads (target_path TEXT, tab_url TEXT, referrer TEXT, start_time INTEGER, end_time INTEGER, total_bytes INTEGER, state INTEGER, danger_type INTEGER);
        CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
        CREATE TABLE moz_historyvisits (place_id INTEGER, visit_date INTEGER, visit_type INTEGER);
        CREATE TABLE moz_bookmarks (fk INTEGER, title TEXT, dateAdded INTEGER, lastModified INTEGER);
        CREATE TABLE moz_cookies (host TEXT, name TEXT, value TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER);
        CREATE TABLE moz_formhistory (fieldname TEXT, value TEXT, timesUsed INTEGER, firstUsed INTEGER, lastUsed INTEGER);
        CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);
        CREATE TABLE history_visits (history_item INTEGER, visit_time REAL);
        CREATE TABLE Activity (AppId TEXT, Payload TEXT, StartTime INTEGER, EndTime INTEGER, LastModifiedTime INTEGER, ClipboardPayload TEXT, ActivityType INTEGER, ActivityStatus INTEGER);
        CREATE TABLE LSQuarantineEvent (LSQuarantineTimeStamp REAL, LSQuarantineAgentName TEXT, LSQuarantineDataURLString TEXT, LSQuarantineOriginURLString TEXT, LSQuarantineSenderName TEXT);
        CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);
        CREATE TABLE message (text TEXT, date INTEGER, is_from_me INTEGER, service TEXT, handle_id INTEGER);
        CREATE TABLE sms (_id INTEGER, address TEXT, date INTEGER, type INTEGER, body TEXT, read INTEGER);
        INSERT INTO urls VALUES (1, 'https://flag{chromium_history}/', 'CTF', 3);
        INSERT INTO visits VALUES (1, 13300000000000000, 1);
        INSERT INTO keyword_search_terms VALUES (1, 'flag{chromium_search}');
        INSERT INTO downloads VALUES ('C:/flag{chromium_download}.zip', 'https://ctf.example/', '', 13300000000000000, 13300000010000000, 42, 1, 0);
        INSERT INTO moz_places VALUES (1, 'https://flag{firefox_places}/', 'Firefox CTF', 2);
        INSERT INTO moz_historyvisits VALUES (1, 1700000000000000, 1);
        INSERT INTO moz_bookmarks VALUES (1, 'flag{firefox_bookmark}', 1700000000000000, 1700000000000000);
        INSERT INTO moz_cookies VALUES ('ctf.example', 'challenge', 'flag{firefox_cookie}', '/', 1900000000, 1700000000000000, 1700000000000000, 1, 1);
        INSERT INTO moz_formhistory VALUES ('answer', 'flag{firefox_form}', 1, 1700000000000000, 1700000000000000);
        INSERT INTO history_items VALUES (1, 'https://flag{safari_history}/', 'Safari CTF', 1);
        INSERT INTO history_visits VALUES (1, 700000000.0);
        INSERT INTO Activity VALUES ('ctf.app', '{"description":"flag{windows_timeline}"}', 1700000000, 1700000010, 1700000011, 'flag{windows_clipboard}', 5, 1);
        INSERT INTO LSQuarantineEvent VALUES (700000000.0, 'Safari', 'file:///flag{macos_quarantine}', 'https://ctf.example/', 'CTF');
        INSERT INTO handle VALUES (1, '+3530000000');
        INSERT INTO message VALUES ('flag{ios_message}', 700000000000000000, 0, 'iMessage', 1);
        INSERT INTO sms VALUES (1, '+3530000001', 1700000000000, 1, 'flag{android_sms}', 1);
        """
    )
    connection.commit()
    data = connection.serialize()
    connection.close()
    return data


def _lnk_with_arguments(arguments: str) -> bytes:
    header = bytearray(76)
    header[:4] = b"L\0\0\0"
    header[4:20] = bytes.fromhex("0114020000000000c000000000000046")
    header[20:24] = ((1 << 5) | (1 << 7)).to_bytes(4, "little")
    encoded = arguments.encode("utf-16-le")
    return bytes(header) + (len(arguments)).to_bytes(2, "little") + encoded


def _prefetch() -> bytes:
    data = bytearray(1024)
    data[:4] = (26).to_bytes(4, "little")
    data[4:8] = b"SCCA"
    data[12:16] = len(data).to_bytes(4, "little")
    executable = "POWERSHELL.EXE".encode("utf-16-le")
    data[16:16 + len(executable)] = executable
    data[76:80] = bytes.fromhex("78563412")
    data[208:212] = (7).to_bytes(4, "little")
    path = r"C:\Users\ctf\flag{prefetch_path}.txt".encode("utf-16-le")
    data[300:300 + len(path)] = path
    return bytes(data)


def _mft() -> bytes:
    record = bytearray(1024)
    record[:4] = b"FILE"
    record[20:22] = (56).to_bytes(2, "little")
    record[22:24] = (1).to_bytes(2, "little")
    filename = "flag{mft_filename}.txt"
    name_bytes = filename.encode("utf-16-le")
    content = bytearray(66 + len(name_bytes))
    content[:6] = (5).to_bytes(6, "little")
    content[64] = len(filename)
    content[65] = 1
    content[66:] = name_bytes
    attribute_length = 24 + len(content)
    record[56:60] = (0x30).to_bytes(4, "little")
    record[60:64] = attribute_length.to_bytes(4, "little")
    record[72:76] = len(content).to_bytes(4, "little")
    record[76:78] = (24).to_bytes(2, "little")
    record[80:80 + len(content)] = content
    record[56 + attribute_length:60 + attribute_length] = (0xFFFFFFFF).to_bytes(4, "little")
    return bytes(record)


def _usn() -> bytes:
    filename = "flag{usn_filename}.txt".encode("utf-16-le")
    record_length = (60 + len(filename) + 7) & ~7
    record = bytearray(record_length)
    record[:4] = record_length.to_bytes(4, "little")
    record[4:6] = (2).to_bytes(2, "little")
    record[40:44] = (0x00000100).to_bytes(4, "little")
    record[56:58] = len(filename).to_bytes(2, "little")
    record[58:60] = (60).to_bytes(2, "little")
    record[60:60 + len(filename)] = filename
    return bytes(record)


def _recycle_bin_i() -> bytes:
    path = r"C:\Users\ctf\Desktop\flag{recycle_bin_path}.txt" + "\0"
    encoded = path.encode("utf-16-le")
    filetime = 133_801_632_000_000_000
    return struct.pack("<QQQI", 2, 1234, filetime, len(path)) + encoded


def _sqlite_wal() -> bytes:
    page = bytearray(512)
    page[80:80 + len(b"flag{sqlite_wal_record}")] = b"flag{sqlite_wal_record}"
    header = struct.pack(">IIIIIIII", 0x377F0682, 3_007_000, 512, 1, 0x11111111, 0x22222222, 0, 0)
    frame = struct.pack(">IIIIII", 3, 9, 0x11111111, 0x22222222, 0, 0) + bytes(page)
    return header + frame


def _sqlite_journal() -> bytes:
    header = b"\xd9\xd5\x05\xf9 \xa1c\xd7" + struct.pack(">IIIII", 1, 0x12345678, 10, 512, 512)
    header += b"\0" * (512 - len(header))
    page = bytearray(512)
    page[96:96 + len(b"flag{sqlite_journal_record}")] = b"flag{sqlite_journal_record}"
    return header + struct.pack(">I", 4) + bytes(page) + b"\0" * 4


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + chunk_type + payload + struct.pack(">I", zlib.crc32(chunk_type + payload) & 0xFFFFFFFF)


def _tiny_png() -> bytes:
    header = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", header) + _png_chunk(b"IDAT", zlib.compress(b"\0\xff\0\0\xff")) + _png_chunk(b"IEND", b"")


def _utmp() -> bytes:
    record = bytearray(384)
    record[0:2] = (7).to_bytes(2, "little")
    record[4:8] = (4242).to_bytes(4, "little", signed=True)
    record[8:12] = b"pts/"
    record[12:13] = b"1"
    record[40:44] = b"p1\0\0"
    user = b"flag{utmp_user}"
    host = b"ctf.example"
    record[44:44 + len(user)] = user
    record[76:76 + len(host)] = host
    record[340:344] = (1_700_000_000).to_bytes(4, "little", signed=True)
    record[348:352] = bytes((127, 0, 0, 1))
    return bytes(record)


def _mbdb_string(value: bytes | None) -> bytes:
    if value is None:
        return b"\xff\xff"
    return len(value).to_bytes(2, "big") + value


def _ios_mbdb() -> bytes:
    domain = b"HomeDomain"
    path = b"Library/flag{ios_mbdb_path}.txt"
    fields = b"".join((
        _mbdb_string(domain), _mbdb_string(path), _mbdb_string(None),
        _mbdb_string(b"\x11" * 20), _mbdb_string(None),
    ))
    fixed = struct.pack(">HQIIIIIQBB", 0x81A4, 42, 501, 501, 1_700_000_000, 1_700_000_001, 1_700_000_002, 123, 1, 1)
    properties = _mbdb_string(b"clue") + _mbdb_string(b"flag{ios_mbdb_property}")
    return b"mbdb\x05\x00" + fields + fixed + properties


def _lz4_literal_block(payload: bytes) -> bytes:
    initial = min(len(payload), 15)
    encoded = bytearray((initial << 4,))
    remaining = len(payload) - initial
    if initial == 15:
        while remaining >= 255:
            encoded.append(255)
            remaining -= 255
        encoded.append(remaining)
    encoded.extend(payload)
    return bytes(encoded)


def test_mobile_and_endpoint_artifact_solvers() -> None:
    android = _android_backup()
    plist = plistlib.dumps({"clue": "flag{binary_plist_fixture}"}, fmt=plistlib.FMT_BINARY)
    lnk = _lnk_with_arguments("--open flag{lnk_arguments}")
    prefetch = _prefetch()

    assert sniff_kind(android, "backup.ab") == "android_backup"
    assert analyze_format("android_backup", android)["extracted"][0]["kind"] == "tar"
    assert sniff_kind(plist, "settings.plist") == "plist"
    assert any("flag{binary_plist_fixture}" in record["text"] for record in analyze_format("plist", plist)["text_records"])
    assert sniff_kind(lnk, "recent.lnk") == "lnk"
    assert analyze_format("lnk", lnk)["metadata"]["command_line_arguments"] == "--open flag{lnk_arguments}"
    assert sniff_kind(prefetch, "POWERSHELL.EXE-12345678.pf") == "prefetch"
    assert any("flag{prefetch_path}" in record["text"] for record in analyze_format("prefetch", prefetch)["text_records"])


def test_ntfs_ese_and_virtual_disk_artifact_solvers() -> None:
    mft = _mft()
    usn = _usn()
    ese = b"\0\0\0\0\xef\xcd\xab\x89" + struct.pack("<II", 0x620, 0) + b"\0" * 256
    qcow = b"QFI\xfb" + struct.pack(">I", 3) + b"\0" * 12 + struct.pack(">I", 16) + struct.pack(">Q", 64 * 1024 * 1024) + b"\0" * 64

    assert sniff_kind(mft, "$MFT") == "mft"
    assert any("flag{mft_filename}" in record["text"] for record in analyze_format("mft", mft)["text_records"])
    assert sniff_kind(usn, "$J") == "usn"
    assert any("flag{usn_filename}" in record["text"] for record in analyze_format("usn", usn)["text_records"])
    assert sniff_kind(ese, "WebCacheV01.dat") == "ese"
    assert analyze_format("ese", ese)["properties"]["format_version"] == 0x620
    assert sniff_kind(qcow, "disk.qcow2") == "qcow"
    assert analyze_format("qcow", qcow)["properties"]["virtual_size"] == 64 * 1024 * 1024


def test_recycle_bin_and_sqlite_sidecar_solvers() -> None:
    recycle = _recycle_bin_i()
    wal = _sqlite_wal()
    journal = _sqlite_journal()

    assert sniff_kind(recycle, "$IABCDEF.txt") == "recycle_bin_i"
    assert "flag{recycle_bin_path}" in analyze_format("recycle_bin_i", recycle)["metadata"]["original_path"]
    assert sniff_kind(wal, "History.db-wal") == "sqlite_wal"
    assert any("flag{sqlite_wal_record}" in record["text"] for record in analyze_format("sqlite_wal", wal)["text_records"])
    assert sniff_kind(journal, "places.sqlite-journal") == "sqlite_journal"
    assert any("flag{sqlite_journal_record}" in record["text"] for record in analyze_format("sqlite_journal", journal)["text_records"])


def test_jump_list_recovers_embedded_lnk_and_paths() -> None:
    embedded_lnk = _lnk_with_arguments("--open flag{jumplist_argument}")
    path = r"C:\Users\ctf\Recent\flag{jumplist_path}.txt".encode("utf-16-le")
    jump_list = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 504 + path + b"\0\0" + embedded_lnk

    assert sniff_kind(jump_list, "1b4dd67f29cb1962.automaticDestinations-ms") == "jumplist"
    result = analyze_format("jumplist", jump_list)
    assert result["properties"]["embedded_shell_links"] == 1
    assert any("flag{jumplist_argument}" in record["text"] for record in result["text_records"])
    assert any("flag{jumplist_path}" in record["text"] for record in result["text_records"])


def test_thumbcache_linux_login_and_ios_manifest_solvers() -> None:
    png = _tiny_png()
    thumbcache = b"CMMM" + struct.pack("<II", 0x20, 4) + b"\0" * 128 + png + b"\0" * 32
    utmp = _utmp()
    mbdb = _ios_mbdb()

    assert sniff_kind(thumbcache, "thumbcache_256.db") == "thumbcache"
    thumb_report = analyze_format("thumbcache", thumbcache)
    assert thumb_report["properties"]["images_recovered"] == 1
    assert thumb_report["extracted"][0]["data"] == png

    assert sniff_kind(utmp, "wtmp") == "utmp"
    assert any("flag{utmp_user}" in record["text"] for record in analyze_format("utmp", utmp)["text_records"])

    assert sniff_kind(mbdb, "Manifest.mbdb") == "ios_mbdb"
    manifest_report = analyze_format("ios_mbdb", mbdb)
    recovered = "\n".join(record["text"] for record in manifest_report["text_records"])
    assert "flag{ios_mbdb_path}" in recovered
    assert "flag{ios_mbdb_property}" in recovered
    assert hashlib.sha1(b"HomeDomain-Library/flag{ios_mbdb_path}.txt").hexdigest() in recovered


def test_firefox_mozlz4_and_leveldb_browser_solvers() -> None:
    session = b'{"windows":[{"tabs":[{"url":"https://flag{firefox_session}/"}]}]}'
    mozlz4 = b"mozLz40\0" + len(session).to_bytes(4, "little") + _lz4_literal_block(session)
    level_payload = b"origin=https://ctf.example key=clue value=flag{leveldb_wal_record}"
    level_log = b"\0" * 4 + len(level_payload).to_bytes(2, "little") + b"\x01" + level_payload
    level_table = b"raw-key=flag{leveldb_table_record}" + b"\0" * 64 + b"\x57\xfb\x80\x8b\x24\x75\x47\xdb"

    assert sniff_kind(mozlz4, "recovery.jsonlz4") == "mozlz4"
    mozilla_report = analyze_format("mozlz4", mozlz4)
    assert any("flag{firefox_session}" in record["text"] for record in mozilla_report["text_records"])
    assert mozilla_report["extracted"][0]["kind"] == "text"

    assert sniff_kind(level_log, "000003.log") == "leveldb"
    assert any("flag{leveldb_wal_record}" in record["text"] for record in analyze_format("leveldb", level_log)["text_records"])
    assert sniff_kind(level_table, "000004.ldb") == "leveldb"
    assert any("flag{leveldb_table_record}" in record["text"] for record in analyze_format("leveldb", level_table)["text_records"])


def test_macos_finder_safari_cookie_and_browser_timeline_solvers() -> None:
    ds_store = _ds_store()
    binarycookies = _binarycookies()
    browser = _browser_sqlite()

    assert sniff_kind(ds_store, ".DS_Store") == "ds_store"
    finder_text = "\n".join(record["text"] for record in analyze_format("ds_store", ds_store)["text_records"])
    assert "flag{ds_store_deleted_name}" in finder_text
    assert "flag{ds_store_comment}" in finder_text

    assert sniff_kind(binarycookies, "Cookies.binarycookies") == "binarycookies"
    assert sniff_kind(b"cookie=chocolate\n", "notes.txt") == "text"
    cookie_report = analyze_format("binarycookies", binarycookies)
    assert cookie_report["properties"]["checksum_valid"] is True
    assert any("flag{binarycookies_value}" in record["text"] for record in cookie_report["text_records"])

    browser_report = analyze_format("sqlite", browser)
    browser_text = "\n".join(record["text"] for record in browser_report["text_records"])
    assert browser_report["properties"]["browser_families"] == ["chromium", "firefox", "safari"]
    for flag in (
        "flag{chromium_history}", "flag{chromium_search}", "flag{chromium_download}",
        "flag{firefox_places}", "flag{firefox_bookmark}", "flag{firefox_cookie}",
        "flag{firefox_form}", "flag{safari_history}",
        "flag{windows_timeline}", "flag{windows_clipboard}", "flag{macos_quarantine}",
        "flag{ios_message}", "flag{android_sms}",
    ):
        assert flag in browser_text
    assert browser_report["properties"]["structured_families"] == [
        "android", "chromium", "firefox", "ios", "macos", "safari", "windows",
    ]


def test_registry_systemd_journal_and_mbox_solvers() -> None:
    registry = _registry_hive()
    legacy_registry = _registry_hive(legacy_11=True)
    segmented_registry = _registry_hive(segmented=True)
    journal = _systemd_journal()
    mailbox = _mbox()

    assert sniff_kind(registry, "NTUSER.DAT") == "registry"
    registry_report = analyze_format("registry", registry)
    registry_text = "\n".join(record["text"] for record in registry_report["text_records"])
    assert r"C:\flag{registry_userassist}.exe" in registry_text
    assert "userassist_run_count=7" in registry_text
    assert registry_report["properties"]["userassist_records"] == 1
    legacy_report = analyze_format("registry", legacy_registry)
    assert legacy_report["properties"]["format_version"] == "1.1"
    assert any("flag{registry_userassist}" in record["text"] for record in legacy_report["text_records"])
    segmented_report = analyze_format("registry", segmented_registry)
    assert any("flag{registry_segmented_data}" in record["text"] for record in segmented_report["text_records"])

    assert sniff_kind(journal, "system.journal") == "systemd_journal"
    journal_report = analyze_format("systemd_journal", journal)
    journal_text = "\n".join(record["text"] for record in journal_report["text_records"])
    assert "flag{systemd_journal_message}" in journal_text
    assert "ctf.service" in journal_text
    assert "2023-11-14" in journal_text
    assert journal_report["properties"]["objects_scanned"] == 3

    assert sniff_kind(mailbox, "messages.mbox") == "mbox"
    mailbox_report = analyze_format("mbox", mailbox)
    mailbox_text = "\n".join(record["text"] for record in mailbox_report["text_records"])
    assert mailbox_report["properties"]["messages_parsed"] == 2
    assert "flag{mbox_subject}" in mailbox_text
    assert "flag{mbox_body}" in mailbox_text
    assert mailbox_report["extracted"][0]["data"] == b"flag{mbox_attachment}"
