# Forenscope

Forenscope is a local-first CTF file-forensics workbench. Give it an image, audio or video file, packet capture, document, archive, database, disk or memory image, executable, structured binary, or damaged file and it will build a bounded evidence report containing:

- content-based format identification and hashes;
- readable document text and media previews;
- ranked flag candidates and the transformations that produced them;
- metadata, structural findings, strings, decoded values, and carved files;
- image, audio, packet, hex, and repair workbenches;
- immutable, hashed child artifacts with parent/producer lineage;
- a Solve guide that recommends evidence-driven next steps; and
- an explicit coverage record showing which built-in and optional methods ran, were missing, were inapplicable, timed out, or failed.

Forenscope is designed for CTF challenges and files you are authorized to inspect. It is not a malware sandbox, antivirus product, password-cracking service, or replacement for evidence-handling procedures required by law or policy.

## Contents

- [Safety and operating model](#safety-and-operating-model)
- [Quick start](#quick-start)
- [Your first analysis](#your-first-analysis)
- [Scan profiles](#scan-profiles)
- [Understanding the interface](#understanding-the-interface)
- [Supported evidence and analysis](#supported-evidence-and-analysis)
- [Optional external tools](#optional-external-tools)
- [Configuration](#configuration)
- [HTTP API](#http-api)
- [Data storage and case lifecycle](#data-storage-and-case-lifecycle)
- [Architecture and report model](#architecture-and-report-model)
- [Known limits](#known-limits)
- [Troubleshooting](#troubleshooting)
- [Development and verification](#development-and-verification)

## Safety and operating model

The original upload is copied to a per-job directory, hashed with SHA-256, and never modified. Repairs, hex edits, conversions, decompressed content, extracted files, and recovered media are separate child artifacts. Reports record their parent, producer, transformation, size, hash, and detected type.

Analysis is local and does not intentionally access the network. Network access occurs only when you explicitly confirm installation of allowlisted optional tools. External analyzers receive fixed argument arrays, run without a shell, use bounded time/output/file quotas, and write to isolated temporary directories. Challenge bytes cannot supply a command, URL, plugin, YARA rule, Zeek script, Kaitai schema, output path, or package name.

The API has no login system. It is intentionally bound to loopback and accepts browser origins only from `localhost`, `127.0.0.1`, or `::1`. Do not expose port 8000 to an untrusted network or place the API behind a public reverse proxy.

Documents are never opened in Microsoft Office, LibreOffice, a browser renderer, or a PDF JavaScript environment. Text previews extract bounded plain text and display it in a `<pre>` element. Executables, macros, scripts, attachments, disk contents, and recovered files are not launched.

## Quick start

### Requirements

| Component | Requirement | Notes |
|---|---:|---|
| Python | 3.11 or newer | Python 3.12 is used by the Docker image and recommended locally. |
| Node.js | 22.13 or newer | Required by the `web` package. |
| npm | Included with Node.js | Keep the committed `package-lock.json`. |
| Browser | Current Chromium, Firefox, or Edge | The UI talks to a local API. |
| Docker | Optional | Docker Engine with Compose v2 can run the base stack. |
| Kali WSL | Optional on Windows | Enables the broadest automatic Linux-tool installation path. |

Built-in analysis works without any optional forensic command-line tools.

### Windows PowerShell

From the repository root, prepare and start the backend:

```powershell
Set-Location backend
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In a second PowerShell window:

```powershell
Set-Location web
Copy-Item .env.example .env.local -ErrorAction SilentlyContinue
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). The API health endpoint is [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health), and interactive OpenAPI documentation is at [http://127.0.0.1:8000/api/docs](http://127.0.0.1:8000/api/docs).

### Linux or macOS shell

```bash
cd backend
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In a second terminal:

```bash
cd web
cp -n .env.example .env.local
npm install
npm run dev
```

### Docker Compose

```powershell
docker compose up --build
```

The Compose stack publishes only `127.0.0.1:3000` and `127.0.0.1:8000`, drops Linux capabilities, uses `no-new-privileges`, limits CPU/memory/PIDs, mounts evidence storage in the `forenscope-data` volume, and runs the backend filesystem read-only apart from its data volume and temporary filesystem.

The backend image includes the image/steganography utilities declared in `backend/Dockerfile`. It does not contain every optional network, disk, mobile, memory, or program-analysis adapter. Because the Compose backend is non-root and read-only, **Install missing tools is not supported inside the hardened container**. Use a local/WSL installation for the full adapter catalog, or build a reviewed custom image.

Stop the stack with `docker compose down`. Add `--volumes` only when you intentionally want to delete the persisted Forenscope database and all cases in the Docker volume.

## Your first analysis

1. Choose **Image** for image-focused analysis, **Audio** for audio-focused analysis, or **Corrupted files** for documents, captures, archives, executables, databases, videos, forensic containers, unknown binaries, and damaged files. The Corrupted-files workflow accepts any file type and uses the general recovery pipeline.
2. Drop a file or select it from disk. The browser shows an initial signature/extension guess; the backend verifies the type from content.
3. Choose a profile. Start with **Balanced** for most CTF tasks.
4. Optionally enter a flag prefix such as `flag{`, `HTB{`, or `picoCTF{`. This improves ranking but is not required.
5. Optionally enter the exact passphrase supplied by the challenge. Passphrases are held only for the running analysis and are not stored in the job database or report.
6. Review scan settings. Missing external tools do not prevent built-in analysis.
7. Start the scan. Progress and method events stream into the UI.
8. Begin with **Overview**, **Solve guide**, and **Flag candidates**, then follow artifact lineage into the relevant lab.
9. Export JSON for machine processing, standalone HTML for review, or ZIP for a case bundle.

If a scan is active, request cancellation and wait for it to become `cancelled`, `failed`, or `completed` before deleting it.

## Scan profiles

Profiles select safe defaults; every job also records the final validated options and effective limits.

| Default | Quick | Balanced | Deep |
|---|---:|---:|---:|
| Best use | fast triage | normal CTF workflow | exhaustive local review |
| Source bytes inspected by built-ins | 32 MiB | 96 MiB | 192 MiB |
| String records | 5,000 | 15,000 | 40,000 |
| Default artifact count | 45 | 100 | 220 |
| Default recursive depth | 2 | 3 | 4 |
| Decoder depth / nodes | 2 / 30 | 3 / 100 | 4 / 300 |
| Per-tool timeout | 20 s | 60 s | 180 s |
| Captured output per tool | 512 KiB | 1 MiB | 2 MiB |
| External files retained | 16 | 32 | 64 |
| Audio duration analyzed | 60 s | 180 s | 300 s |
| Visual pixel ceiling | 24 MP | 40 MP | 64 MP |

The uploaded source remains complete on disk even when a profile inspects only a bounded prefix. Reports expose `inspection_truncated` and `source_read_complete`; do not interpret a bounded scan as proof that later bytes contain nothing.

Deep mode can be substantially slower and can create many derived files. Use it when Balanced exposes a promising archive, stream, overlay, disk partition, steganographic lane, or missing deep-only adapter.

## Understanding the interface

| View | What it answers |
|---|---|
| Overview | What is the file, how large is it, did its extension match, and what were the main findings? |
| Solve guide | Which artifact, finding, candidate, or missing method should I investigate next, and why? |
| Traffic lab | Which packets, protocols, streams, endpoints, conversations, objects, credentials, or anomalies are present? |
| Repair lab | Which deterministic copy-only repairs or recoverable hidden canvases were produced? |
| Audio lab | What do the waveform, spectrum, channels, decoded signals, SSTV results, and generated audio artifacts show? |
| Document text | What bounded plain text was safely extracted from the selected text, PDF, email, Office, ODF, or EPUB artifact? |
| Flag candidates | Which flag-like strings were found, with what confidence, offset, artifact, and transform chain? |
| Artifacts | What was extracted or generated, who produced it, what is its parent, and can it be previewed/downloaded? |
| Visual lab | What do channels, bit planes, palette indices, frames, remaps, differences, and OCR/barcode views reveal? |
| Metadata | Which format, EXIF, document, media, filesystem, packet, or tool fields were recovered? |
| Hex view | What are the exact bytes, matches, anomalies, structure verdicts, draft edits, and repair candidates? |
| Tool results | Which optional adapters ran and what bounded output/artifacts did they produce? |
| Coverage & logs | Which methods completed, were skipped, were missing, timed out, failed, or were limited? |

The Solve guide is a bounded provenance graph. It links artifacts, producing methods, findings, and candidates and ranks format-aware next actions. Recommendations can navigate inside the report, but cannot turn extracted text into commands, paths, URLs, or network requests.

## Supported evidence and analysis

Forenscope always begins with content signatures, SHA-256, bounded entropy/string inspection, embedded-signature searches, recursive decoding where applicable, and candidate extraction. Extension-only identification is used for formats without a reliable universal magic value, such as generic MessagePack or Protocol Buffers.

### Format overview

| Family | Recognized formats and artifacts | Main built-in work |
|---|---|---|
| Images | PNG/APNG, JPEG/MPO, GIF, BMP, WebP, SVG text, TIFF/BigTIFF, ICO/CUR, PSD/PSB, GIMP XCF, PBM/PGM/PPM/PAM, HEIF/HEIC/AVIF | structure, metadata, frames, channels, palette/index data, bit planes, OCR/barcodes, embedded content, repairs, bounded long-tail header triage |
| Audio | WAV/PCM, AIFF/AIFC, FLAC, Ogg/Opus, MP3, AAC/M4A, AU, WMA/ASF, AMR, CAF, MIDI | headers/metadata, PCM analysis, waveform/spectrogram, channels, LSB lanes, DTMF/Morse/SSTV, conversion handoffs |
| Video | MP4/MOV, Matroska/WebM, AVI | BMFF/EBML/RIFF structure, brands, text metadata, invalid sizes, trailers, optional metadata and contact-frame extraction |
| Text and documents | plain text, Markdown, JSON/JSONL, XML, YAML, CSV/TSV, config/log files, PDF, RTF, EML/MBOX, DOC/XLS/PPT, DOCX/XLSX/PPTX plus macro/template variants, ODT/ODS/ODP, EPUB, XPS/OXPS, OneNote | bounded plain-text preview, package text/metadata, attachments/objects, active-content indicators, whitespace and encoding analysis |
| Captures | PCAP, PCAPNG, PCAPNG secrets blocks, SocketCAN in captures | native flow/stream/object/covert-channel analysis plus optional TShark/Wireshark-grade queries |
| Archives, packages and compression | ZIP, TAR, gzip, bzip2, XZ, Zstandard, 7z, RAR, LZIP, LZ4, LZMA, LZOP, shar/uuencode, Unix ar, CAB, CPIO, RPM, XAR, APK, AAB, JAR/WAR, IPA, AppX/MSIX, NuGet/VSIX | bounded recursion, safe member extraction, package manifest text, extra-field carving, trailers, decompression, optional flat 7-Zip extraction |
| Databases and browser data | SQLite, WAL, rollback journal, LevelDB, ESE/EDB, Firefox MOZLZ4, HDF5, BSON, Access Jet/ACE | bounded schema/page/record/object strings, BSON key/value and binary-field recovery, and fixed read-only queries for common browser, activity, quarantine, and message stores |
| Windows artifacts | Registry hives, EVTX, LNK, Jump Lists, Prefetch, `$MFT`, `$UsnJrnl:$J`, `$Recycle.Bin` `$I`, thumbnail cache, PST/OST, memory/crash dumps | headers, records, paths, timestamps, stale cells, UserAssist, event strings, mail/store metadata, optional specialist tools |
| Linux/macOS/mobile | utmp/wtmp/btmp, systemd journals, plist, `.DS_Store`, Safari binary cookies, iOS MBDB, Android ADB backup | records, fields, timestamps, strings, filenames/comments/cookies, backup manifests and bounded child extraction |
| Disk and VM images | raw MBR/GPT/filesystem images, FAT/exFAT, NTFS, ext, HFS/HFS+, APFS, XFS, Btrfs, SquashFS/CramFS, LUKS/BitLocker indicators, ISO, E01/EWF, QCOW, VMDK, VHD/VHDX, VDI, DMG, AFF/AFF4 | container/partition metadata, embedded signatures, optional Sleuth Kit/libewf/QEMU recovery workflows |
| Programs, serialization and firmware | PE/PE32+, ELF32/ELF64, thin/fat Mach-O, WebAssembly, Android DEX, Java class/serialization, Python PYC/pickle, Intel HEX, Motorola S-record | bounded headers, sections/segments/load commands, strings/custom sections, checksum-validated firmware reconstruction, serialization disassembly without object loading, RWX warnings, overlays |
| Developer artifacts | Git pack and index files | bounded version/object metadata and path/string recovery without checking out or executing repository content |
| Structured binary | bencode/BitTorrent, self-described or extension-identified CBOR, MessagePack, Protocol Buffers wire data | bounded maps, arrays, fields, strings, byte payloads, trailers, recursive child inspection |

Unknown binary data still receives hashes, entropy, ASCII/UTF-16 strings, signature search, carving, common decoding/compression checks, crypto signals, and optional general-purpose tools.

### Images and steganography

Built-in image analysis includes:

- PNG chunks/CRC, JPEG markers, GIF blocks/frames/palettes, BMP headers/bitfields, WebP RIFF chunks, TIFF directories, ICO entries, and non-rendering SVG text/tspan extraction;
- metadata, embedded objects, trailing bytes, nested archives, and ZIP bytes hidden inside local-file-header extra fields;
- RGB/RGBA channels, channel differences, ordinary and value-filtered bit planes, MSB/LSB orders, pairwise channel-bit XOR, palette-index streams, animated frames, and transparency;
- baseline-JPEG DCT coefficient parity streams for JSteg-style challenges;
- bounded low-color black/white remapping for QR-like images, OCR variants, and barcode detection;
- Unicode whitespace bitstreams, NFKC/confusable normalization, Base encodings, compression, constant XOR/byte shifts, and flag-prefix-aware candidate ranking; and
- optional zsteg, Stegseek, Steghide, OutGuess, JPSeek, JSteg, OpenStego, Binwalk, Foremost, ExifTool, ImageMagick, and format-specific validators.

#### Image uncropping and repair

Forenscope creates a repair only when bytes and format invariants support it:

- PNG dimensions can expand when the complete decompressed IDAT scanline layout proves hidden rows or columns.
- BMP height can expand when `biSizeImage` and exact row stride prove complete hidden rows.
- GIF logical screens can expand to parsed frame extents.
- Balanced/Deep scans can recognize an aCropalypse-style overwrite-without-truncation layout, recover a bounded surviving DEFLATE tail, infer a plausible width from filter bytes, and mark pixels that could not be recovered.
- PNG CRCs, end markers, declared sizes, and some header/chunk boundaries can be repaired deterministically; BZip2 header changes are accepted only after successful bounded decompression.
- `pngfix`, OptiPNG, Gifsicle, `jpegtran`, qpdf, pcapfix, and Info-ZIP recovery can produce separate child artifacts when installed and applicable.

This cannot restore pixels that no longer exist. Ordinary editor crops, most JPEG/WebP crops, screenshots of cropped images, and re-encoded images discard the original pixels and are never AI-filled or presented as exact recovery.

### Documents and text preview

The Document text view supports readable text/config formats and `.pdf`, `.rtf`, `.eml`, `.mbox`, `.doc`, `.xls`, `.ppt`, OOXML and macro/template variants, `.odt`, `.ods`, `.odp`, `.epub`, `.xps`, `.oxps`, `.one`, and manifest-bearing APK/AAB/JAR/WAR/IPA/AppX/MSIX/NuGet packages. It reports encoding, character/line counts, source parts, and truncation.

Preview safety limits are independent:

- at most 2 MiB of a simple source is read;
- at most 500,000 characters are returned;
- at most 32 document-package members and 512 KiB per member are read;
- ZIP directories are limited to 1,000 entries and 4 MiB; and
- encrypted members, symlinks, suspicious expansion ratios, external links, and oversized entries are skipped or rejected.

OOXML/ODF/EPUB markup is stripped to plain text. PDF/RTF/email text comes from the bounded structural parser. Legacy Office preview uses recovered streams/UTF-16 strings. Preview is not layout-accurate and does not evaluate formulas, macros, scripts, remote resources, fonts, or embedded programs.

Document forensics additionally detects PDF active-content markers and embedded streams/attachments, MIME bodies and attachments, MBOX messages, OLE streams, RTF objects, and Office package content. Optional Poppler, qpdf, SNOW, and Oletools adapters provide deeper extraction without launching an office application.

### Audio and video

For WAV/PCM evidence, the built-in audio lab provides waveform and spectrogram views, channel/phase statistics, frequency peaks, silence/clipping findings, DTMF and tentative Morse decoding, PCM sample-bit extraction, channel/difference/reversed/normalized WAVs, and an Audacity-compatible label bundle.

The SSTV decoder reads VIS headers and scan tones and supports Robot 36/72, Martin M1/M2, Scottie S1/S2/DX, and PD120/180/240. Auto mode follows the VIS code; a manual mode can help when the header is damaged. Recovered images are hashed child artifacts.

Compressed audio can be normalized to PCM when FFmpeg is installed. FFprobe, FFmpeg, SoX, MediaInfo, Multimon-ng, Minimodem, and Steghide add metadata, contact frames, spectrograms, FSK/DTMF decoding, or extraction. FFmpeg receives a local-only protocol allowlist that excludes HTTP and HTTPS.

Video parsing is structural and bounded. Optional FFmpeg frame extraction keeps at most 24 frames, samples at one frame per five seconds, and scales frames to at most 1280 pixels wide.

### Packet captures and the Traffic lab

The native PCAP/PCAPNG pass handles multi-section PCAPNG, interface labels, timestamp resolution, EPB/SPB/PB records, comments, name-resolution blocks, and decryption-secrets blocks. It reconstructs bounded IPv4/IPv6 TCP, UDP, ICMP, ARP, DHCP, DNS, CoAP, cleartext HTTP/2 DATA, TFTP, SocketCAN/ISO-TP, MQTT, WebSocket, Modbus, BitTorrent DHT, RTP DTMF/G.711, FTP, Telnet, and common mail-authentication evidence.

CTF-oriented checks include:

- out-of-order TCP reassembly with retransmission/overlap clipping;
- HTTP, TFTP, FTP-DATA, SMB, IMF/email, DICOM, and HTTP/2 Content-Range object recovery;
- DNS TXT/CNAME/address data and concatenated encoded fragments;
- payload Base64/hex/Base32/URL/compression/XOR/shift transformations;
- source/destination address and port, TTL, IP ID, ICMP, TCP flag, and packet-bit covert channels;
- timing-delta clustering and millisecond/centisecond/microsecond timing bytes;
- repeated ICMP padding removal, TCP/IP flag bit planes, IMSI-derived repeating-XOR clues;
- USB HID keyboard decoding and relative mouse-motion SVG rendering with TShark; and
- cleartext Basic authorization decoding without copying the decoded secret into general metadata.

When TShark is installed, `POST /api/jobs/{job_id}/traffic/query` powers three read-only actions:

- `packets`: display filters, bounded packet rows, full decoded fields, and optional raw bytes;
- `follow`: numbered TCP, UDP, DCCP, TLS, DTLS, HTTP, HTTP/2, QUIC, MPEG-TS, or MPEG-PES streams in ASCII, hex, raw, or YAML form; and
- `statistics`: protocol hierarchy, I/O graph, packet lengths, flow graph, endpoints, conversations, DNS, HTTP, HTTP requests, HTTP/2, ICMP, SIP, RTP, SMB2, Expert Info, or credentials.

An NSS TLS key-log can be selected only from a text artifact already belonging to the same job. Secret values are validated but not rendered in the response. Forenscope does not start live capture, inject/replay traffic, resolve arbitrary paths, load capture-provided plugins, or expose every interactive Wireshark GUI feature.

### Endpoint, browser, mobile, disk, and memory artifacts

The built-in forensic layer performs bounded, read-only parsing rather than mounting or opening live application data. Highlights include:

- fixed SQLite queries for Chromium/Firefox/Safari history, searches, downloads, bookmarks, cookies/forms, Windows `ActivitiesCache.db`, macOS quarantine, and iOS/Android messages;
- SQLite WAL/rollback residual records without replaying the sidecar;
- Registry allocated/stale cells, typed values, key paths, segmented values, and UserAssist ROT13/count/focus/last-run fields;
- EVTX UTF-16 strings, Base64 fragments, and ordered flag-fragment reassembly;
- LNK/Jump List paths and arguments without following targets;
- Prefetch, MFT, USN, Recycle Bin `$I`, ESE, thumbnail-cache, systemd journal, utmp, plist, MBDB, `.DS_Store`, binary-cookie, MOZLZ4, and LevelDB structures;
- MBR/GPT/filesystem signatures and partition starts; and
- optional Sleuth Kit, libewf, Reglookup, python-evtx, libpst, libyal tools, QEMU, bulk_extractor, Plaso, iLEAPP/ALEAPP, and offline Volatility 3.

Encrypted Android ADB backups are identified but not decrypted. Volatility uses `--offline`, so missing symbols are reported instead of downloaded. Deep disk recovery writes to an isolated directory and applies the normal file-count, size, hashing, and lineage limits before importing anything into a case.

### Programs and structured binary data

PE, ELF, Mach-O, WebAssembly, DEX, and Java class parsers do not load or execute code. Optional YARA-X uses `yr dump` against supported executable modules rather than accepting challenge-provided rules. capa and FLOSS use bounded JSON output; FLOSS caching/workspace persistence is disabled. Bundled Kaitai schemas are limited to PE and WebAssembly headers.

Bencode, CBOR, MessagePack, and Protocol Buffers enforce nesting, node/field, and byte-string caps. Self-described CBOR can be recognized by magic; MessagePack and generic Protobuf normally require a filename extension. Protocol Buffers are schema-less: field numbers and wire values are shown, but semantic names/types require a trusted `.proto` outside this feature. Evidence-provided schemas are never compiled or loaded.

### Decoding and encrypted payloads

The bounded decoder explores common Base encodings, hexadecimal, URL encoding, Unicode representations, compression, and simple CTF transformations while tracking the transform chain. It is intentionally not an unbounded brute-force engine.

Ciphertext-like extracted payloads are reported. If you supply a passphrase, Forenscope can try bounded repeating-key XOR and OpenSSL `Salted__` AES-256-CBC recovery. It also supports the common capture challenge where one same-capture cleartext stream contains a literal OpenSSL decrypt command and another contains its payload; only that literal observed passphrase is considered. Legacy OpenSSL 3DES-CBC plus fixed MD5/SHA-256 EVP_BytesToKey variants are supported for this correlation. Plaintext is retained only after padding/content checks succeed.

Forenscope does not perform password spraying, wordlist attacks, hash cracking, online credential validation, or key retrieval.

## Optional external tools

All optional adapters are capability checks, not requirements. The Settings and Coverage views report each adapter as installed, missing, disabled, inapplicable, completed, limited, timed out, or failed. A missing tool never suppresses the built-in result.

### Tool groups

| Group | Examples | Purpose |
|---|---|---|
| Identity/metadata | `file`, GNU `strings`, ExifTool, Exiv2, ImageMagick, MediaInfo, FFprobe | independent type/metadata cross-checks |
| Image validation/repair | pngcheck/pngcrush/pngfix/OptiPNG, jpeginfo/jpegtran/djpeg, Gifsicle, WebP and TIFF tools | structure validation and copy-only recovery |
| Steganography/carving | zsteg, Stegseek, Steghide, OutGuess, JPSeek, JSteg, OpenStego, Binwalk, Foremost, 7-Zip | embedded payload and bit/coefficient techniques |
| Documents | Poppler, qpdf, SNOW, Oletools | text/images/attachments, whitespace steg, VBA/object indicators |
| Network | capinfos, TShark, Zeek, tcpflow, hcxpcapngtool, pcapfix | packet dissection, objects, flows, authentication artifacts, repair |
| Endpoint/database/disk | SQLite CLI, HDF5 `h5dump`, mdbtools, libyal tools, Sleuth Kit, libewf, Reglookup, python-evtx, libpst, QEMU, bulk_extractor | specialist read-only parsing and recovery |
| Audio/video | FFmpeg/FFprobe, SoX, MediaInfo, Multimon-ng, Minimodem | media normalization, metadata, frames, spectra, signal decoding |
| Program/mobile/timeline | YARA-X, capa, FLOSS, Kaitai, Plaso, iLEAPP, ALEAPP, Volatility 3 | capabilities/strings, headers, timelines, mobile reports, memory triage |

Primary upstream documentation includes [TShark](https://www.wireshark.org/docs/man-pages/tshark.html), [YARA-X](https://virustotal.github.io/yara-x/docs/cli/commands/), [capa](https://github.com/mandiant/capa/blob/master/doc/usage.md), [FLOSS](https://github.com/mandiant/flare-floss/blob/master/doc/usage.md), [Zeek](https://docs.zeek.org/en/stable/), [Plaso](https://plaso.readthedocs.io/en/latest/), [Kaitai Struct Visualizer](https://github.com/kaitai-io/kaitai_struct_visualizer), [iLEAPP](https://github.com/abrignoni/iLEAPP), [ALEAPP](https://github.com/abrignoni/ALEAPP), [Volatility 3](https://github.com/volatilityfoundation/volatility3), [Sleuth Kit](https://www.sleuthkit.org/), and [FFmpeg](https://ffmpeg.org/documentation.html).

### Discovery and installation

Forenscope searches the current process `PATH`, refreshed Windows user/system PATH entries, common application directories, `FORENSCOPE_TOOL_PATHS`, the managed `.tools` directory, and the default WSL distribution. A WSL tool transparently receives the evidence path as `/mnt/<drive>/...`.

In the GUI, use **Refresh availability** after installing tools. Availability is otherwise cached for five minutes. **Install all missing** requires explicit confirmation and can install only fixed entries declared in `backend/app/tool_installation.py`:

- Kali WSL packages through `apt`;
- fixed WinGet package identifiers for supported native Windows applications; and
- pinned/isolated managed WSL builds for zsteg, JSteg, JPSeek, Volatility 3, and python-evtx.

The browser never supplies package names, repositories, versions, URLs, scripts, or shell fragments. Some declared adapters—such as YARA-X, capa, FLOSS, Kaitai, iLEAPP, and ALEAPP—may need to be installed manually and placed on PATH because they do not currently have an automatic-install mapping.

To expose portable tools outside PATH before starting the backend:

```powershell
$env:FORENSCOPE_TOOL_PATHS = 'C:\ForensicTools\bin;D:\Portable\ffmpeg\bin'
```

To change the managed tool root:

```powershell
$env:FORENSCOPE_TOOLS_DIR = 'D:\ForenscopeTools'
```

Steghide makes one non-interactive empty-passphrase attempt when no passphrase is supplied; a supplied passphrase replaces it. `zsteg_mode=all` uses `-a`, while `zsteg_mode=lsb` limits the adapter to `--lsb` checks.

## Configuration

### Backend environment variables

All values are read when the backend process starts.

| Variable | Default | Meaning |
|---|---|---|
| `FORENSCOPE_DATA_DIR` | `backend/data` | SQLite database, jobs, artifacts, and temporary report workspace. |
| `FORENSCOPE_DB_PATH` | `<data-dir>/forenscope.sqlite3` | Override the job database path. |
| `FORENSCOPE_MAX_UPLOAD_BYTES` | `104857600` | Maximum uploaded file size: 100 MiB by default. |
| `FORENSCOPE_MAX_WORKERS` | `2` | Concurrent background analysis workers. |
| `FORENSCOPE_MAX_ARTIFACTS` | `500` | Server-wide maximum artifacts allowed for one job. |
| `FORENSCOPE_MAX_REPORT_BYTES` | `26214400` | Maximum serialized report size: 25 MiB by default. |
| `FORENSCOPE_EVENT_POLL_SECONDS` | `0.35` | Server-side event-stream database polling interval. |
| `FORENSCOPE_RATE_LIMIT` | `300` | Default requests per minute per client. |
| `FORENSCOPE_UPLOAD_RATE_LIMIT` | `12` | Upload requests per minute per client. |
| `FORENSCOPE_ALLOWED_ORIGINS` | local ports 3000 and 5173 | Comma-separated browser origins; validation permits loopback HTTP(S) origins only. |
| `FORENSCOPE_ALLOWED_HOSTS` | localhost/loopback/testserver | Trusted `Host` header values. |
| `FORENSCOPE_TOOL_PATHS` | empty | OS-path-separated additional directories used for tool discovery. |
| `FORENSCOPE_TOOLS_DIR` | repository `.tools` | Managed/portable tool directory. |

Example PowerShell session:

```powershell
$env:FORENSCOPE_DATA_DIR = 'D:\ForenscopeCases'
$env:FORENSCOPE_MAX_UPLOAD_BYTES = '536870912'
$env:FORENSCOPE_MAX_WORKERS = '1'
$env:FORENSCOPE_ALLOWED_ORIGINS = 'http://localhost:3000'
Set-Location backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Large upload limits do not automatically raise the built-in profile read limits or artifact quotas. They only permit the source to be stored.

### Frontend environment

`web/.env.example` contains:

```dotenv
NEXT_PUBLIC_API_URL=http://localhost:8000
```

Copy it to `web/.env.local` if you need a local override. The repository contains a Sites hosting manifest for frontend build/preview tooling, but the current product depends on the local FastAPI service and its local evidence store. Deploying the frontend alone does not deploy the backend, tools, cases, or artifacts; loopback-only API origins make local operation the supported configuration.

### Per-job analysis options

The UI writes these settings into the job. API clients send them as a JSON object in the multipart `options` field. Unknown keys and wrong JSON types are rejected.

#### Core toggles

| Option | Balanced default | Purpose |
|---|---:|---|
| `structure_analysis` | `true` | Run the detected format parser. |
| `visual_analysis` | `true` | Generate safe image views and visual findings. |
| `lsb_analysis` | `true` | Inspect image/palette/PCM bit lanes. |
| `ocr` / `barcodes` | `true` / `true` | Run built-in and available external text/code recognition. |
| `recursive_extraction` | `true` | Analyze bounded child files and decoded containers. |
| `decoders` | `true` | Explore common encodings/compression/CTF transforms. |
| `crypto_analysis` | `true` | Detect ciphertext and attempt only supported supplied-key workflows. |
| `repairs` | `true` | Generate deterministic child repair candidates. |
| `external_tools` | `true` | Permit selected installed adapters. |
| `external_extraction` | `true` | Import bounded files produced by extraction adapters. |
| `evidence_type` | `auto` | `auto`, `image`, `audio`, or `corrupted`. |
| `selected_external_tools` | `null` | `null` selects applicable tools; otherwise provide declared tool IDs only. |
| `ocr_language` | `eng` | Tesseract-style language expression, limited to letters, digits, `_`, `+`, and `-`. |
| `zsteg_mode` | `all` | `all` or `lsb`. |

#### Bounded numeric settings

| Option | Balanced default | Accepted range |
|---|---:|---:|
| `max_recursion_depth` | 3 | 1–12 |
| `max_artifacts` | 100 | 25–500 and no more than the server limit |
| `tool_timeout_seconds` | 60 | 5–180 |
| `external_output_kib` | 1024 | 64–2048 |
| `max_external_files` | 32 | 1–64 |
| `foremost_depth` | 2 | 1–4 |
| `color_remap_variants` | 8 | 0–8 |
| `audio_analysis_seconds` | 180 | 15–300 |
| `audio_spectrogram_fft` | 2048 | 256, 512, 1024, 2048, or 4096 |
| `audio_lsb_bits` | 2 | 1–8 |
| `audio_sstv_max_images` | 2 | 1–4 |

Audio toggles `audio_spectrogram`, `audio_signal_decoders`, `audio_sstv`, `audio_sstv_slant_correction`, `audio_channel_exports`, and `audio_audacity_bundle` default to `true`. `audio_channel_mode` is `mix`, `left`, `right`, or `difference`; `audio_sstv_mode` is `auto`, `robot36`, `robot72`, `martin1`, `martin2`, `scottie1`, `scottie2`, `scottiedx`, `pd120`, `pd180`, or `pd240`.

## HTTP API

The interactive schema at `/api/docs` is the most precise request/response reference. Common routes are:

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/api/health` | Database, uptime, and job/worker health. |
| `GET` | `/api/capabilities?refresh=false` | Profiles, limits, option defaults, and optional-tool availability. |
| `POST` | `/api/tools/install` | Explicitly install allowlisted tool IDs with `confirmed: true`. |
| `POST` | `/api/jobs` | Multipart upload and asynchronous job creation. |
| `GET` | `/api/jobs?limit=50&offset=0&status=completed&detail=full` | Paginated job list; use `detail=summary` to omit report JSON and artifact metadata for a lightweight history view. |
| `GET` | `/api/jobs/{job_id}` | Current status, result, artifacts, and export URLs. |
| `POST` | `/api/jobs/{job_id}/cancel` | Request cooperative cancellation. |
| `DELETE` | `/api/jobs/{job_id}` | Delete a terminal job and its case files. |
| `GET` | `/api/jobs/{job_id}/events?after=0` | Server-Sent Events progress/log stream; supports `Last-Event-ID`. |
| `GET` | `/api/jobs/{job_id}/artifacts` | List artifact metadata and lineage. |
| `GET` | `/api/jobs/{job_id}/artifacts/{artifact_id}/download` | Download bytes with SHA-256 response header. |
| `GET` | `/api/jobs/{job_id}/artifacts/{artifact_id}/preview` | Inline verified raster-image or browser-safe audio preview. |
| `GET` | `/api/jobs/{job_id}/artifacts/{artifact_id}/text-preview` | Bounded non-rendering document text. |
| `GET` | `/api/jobs/{job_id}/hex` | Bounded bytes, search matches, anomalies, and integrity checks. |
| `POST` | `/api/jobs/{job_id}/traffic/query` | Bounded TShark packets/follow/statistics action. |
| `POST` | `/api/jobs/{job_id}/hex/analyze` | Validate sparse edits in memory. |
| `POST` | `/api/jobs/{job_id}/hex/preview` | Render edited image/audio bytes without saving. |
| `POST` | `/api/jobs/{job_id}/hex/save` | Atomically create a new `hex-edit` child artifact. |
| `POST` | `/api/jobs/{job_id}/hex/repair` | Create one server-proposed deterministic repair artifact. |
| `GET` | `/api/jobs/{job_id}/report.json` | Machine-readable case export. |
| `GET` | `/api/jobs/{job_id}/report.html?download=false` | CSP-restricted standalone report. |
| `GET` | `/api/jobs/{job_id}/report.zip` | Report plus retained artifacts. |

The browser uses the lightweight `detail=summary` job list and loads a full report only when a case is opened. Live Server-Sent Events drive scan progress; interval polling starts only if that stream disconnects. Heavy result searches and derived collections are memoized so unrelated UI updates do not repeatedly stringify a complete report.

Analysis ingests each source in one pass for its bounded byte prefix, complete SHA-256, and size, then reuses extracted string and byte-frequency work instead of rescanning the same buffer. Independent external analyzers run with a strict two-process ceiling; executable resolution, child environment construction, and shared-binary version probes are reused within the job. Tool results remain in declared order, every adapter keeps its own temporary directory, argument arrays remain non-shell, and cancellation is checked before queued work and while child processes run.

### Create and monitor a job with PowerShell

```powershell
$options = '{"evidence_type":"auto","external_tools":true,"max_artifacts":100}'
$created = curl.exe --silent --show-error --request POST `
  --form "file=@C:\CTF\challenge.bin" `
  --form "profile=balanced" `
  --form "flag_prefix=flag{" `
  --form "options=$options" `
  http://127.0.0.1:8000/api/jobs | ConvertFrom-Json

$jobId = $created.id
do {
  Start-Sleep -Milliseconds 750
  $job = Invoke-RestMethod "http://127.0.0.1:8000/api/jobs/$jobId"
  "{0:P0} {1} {2}" -f $job.progress, $job.status, $job.current_stage
} while ($job.status -in @('queued', 'running', 'cancelling'))

Invoke-WebRequest "http://127.0.0.1:8000/api/jobs/$jobId/report.zip" `
  -OutFile ".\forenscope-$jobId.zip"
```

Use `curl.exe -N http://127.0.0.1:8000/api/jobs/$jobId/events` for the live event stream.

### Traffic query example

The job must be terminal, TShark must be available, and the selected artifact must be verified as PCAP/PCAPNG.

```powershell
$body = @{
  action = 'follow'
  follow_protocol = 'tcp'
  stream_index = 0
  follow_mode = 'ascii'
  display_filter = 'tcp'
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -ContentType 'application/json' `
  -Body $body `
  "http://127.0.0.1:8000/api/jobs/$jobId/traffic/query"
```

### Hex-edit concurrency contract

Hex analyze/preview/save requests include:

- `artifact_id` or omission for the original artifact;
- `base_sha256`, which must match the current stored artifact;
- a client `revision`; and
- 1–4096 sparse `{offset, value}` byte edits.

The server checks bounds and the base hash before operating. Analyze and preview do not persist bytes. Save creates a new artifact atomically. Repair requests use a server-issued `candidate_id`; clients cannot supply replacement content through that route.

### Error shape

Expected errors use a stable JSON detail object:

```json
{
  "detail": {
    "code": "capture_required",
    "message": "The Wireshark workbench only accepts verified PCAP or PCAPNG artifacts."
  }
}
```

Validation errors also contain an `errors` array with field, message, and type. Common status codes are `400` for invalid/confirmation-required requests, `404` for unknown jobs/artifacts, `409` for invalid lifecycle state, `413` for oversized uploads, `415` for unsupported previews/workbench inputs, `422` for schema/range errors, and `429` for rate limiting.

## Data storage and case lifecycle

The default runtime tree is:

```text
backend/data/
├── forenscope.sqlite3
├── forenscope.sqlite3-shm
├── forenscope.sqlite3-wal
├── jobs/
│   └── <job UUID>/
│       ├── input/source.upload
│       └── output/...
└── tmp/
```

SQLite stores job state, options, progress, events, report JSON, and artifact records. Evidence bytes stay in the job directory. SQLite uses WAL mode, foreign keys, short-lived connections, and transactional state updates.

At backend startup, jobs interrupted while queued/running/cancelling are marked failed rather than silently resumed. Deleting a terminal job removes its database records and its job directory. JSON/HTML exports are generated from the stored result; ZIP exports use a temporary archive that is removed after the response completes.

Back up the entire configured data directory while the service is stopped if you need a portable copy. Do not copy only the SQLite file while it may have live `-wal`/`-shm` companions. The repository ignores data, outputs, `.tools`, local environment files, build products, and SQLite databases.

## Architecture and report model

```text
ctf tool/
├── backend/
│   ├── app/
│   │   ├── main.py                # FastAPI routes and security middleware
│   │   ├── jobs.py                # bounded worker lifecycle and cancellation
│   │   ├── storage.py             # SQLite job/event/artifact persistence
│   │   ├── engine.py              # analysis orchestration and lineage
│   │   ├── analyzers/             # built-in format, media, crypto, and tool adapters
│   │   ├── text_preview.py        # non-rendering document preview
│   │   ├── hexview.py / hexedit.py
│   │   ├── solve_guidance.py      # provenance graph and next steps
│   │   ├── reporting.py           # JSON, HTML, and ZIP exports
│   │   └── tool_installation.py   # fixed allowlisted installers
│   ├── tests/
│   ├── pyproject.toml
│   └── Dockerfile
├── web/
│   ├── app/page.tsx               # client workbench
│   ├── app/globals.css            # responsive light/dark interface
│   ├── package.json
│   └── .openai/hosting.json       # frontend preview/build manifest
├── docker-compose.yml
└── README.md
```

The main analysis result uses schema version `1.0.0` and contains:

- `source`: immutable identity, hash, detected type, MIME, extension comparison, and inspected-byte state;
- `summary`: counts for candidates, findings, artifacts, views, bytes, and method statuses;
- `metadata`, `findings`, and `candidates`;
- `methods`: status, applicability, timing, tool resolution, bounded output, and details;
- `artifacts` and `visual_views` with provenance;
- `coverage`: options, effective limits, missing tools, read completeness, and `original_mutated: false`;
- `solve_guidance`: bounded graph and ranked recommendations;
- `logs` and `errors`.

Exports wrap the job, result, and public artifact records in schema version `1.0`. Treat method status and coverage as part of the forensic conclusion: a missing or truncated method is not a negative finding.

## Known limits

- No tool can recover bytes that were deleted or overwritten. “Uncrop” is evidence-backed container/residue recovery, not generative reconstruction.
- Built-in reads, recursion, parser nodes, packet rows, strings, visuals, artifacts, decompression, tools, output, and report sizes are intentionally capped.
- Large sources can be stored but only a profile-bounded prefix may be examined by generic passes.
- Long-tail containers such as PSD/XCF, HDF5/Access, CAB/RPM/XAR, OneNote, VHD, and application packages receive safe built-in identification, header/manifest, string, and child-artifact triage. Full semantic extraction can still require the listed optional specialist tools.
- Generic Protocol Buffers have no semantic field names without a trusted schema; evidence-provided schemas are not loaded.
- 7z/RAR extraction, compressed-media decoding, full disk recovery, memory plugins, and many specialist reports depend on optional local tools.
- Encrypted archives, encrypted Android backups, protected documents, and unknown cryptosystems are reported but not brute-forced.
- PDF/document preview is extracted text, not a faithful page renderer. Complex layout, formulas, tracked changes, charts, and unsupported encodings may be incomplete.
- Live Wireshark capture, packet injection/replay, Lua plugins, arbitrary profiles/scripts, and every Wireshark GUI dialog are outside the workbench.
- Volatility never downloads symbols automatically; offline analysis may be limited on an unfamiliar image.
- Forenscope is not hardened to execute malicious binaries. Do not manually open recovered executables on your host.
- The backend is local-only and unauthenticated. Public/multi-user deployment requires a separate authentication, isolation, authorization, retention, and abuse-control design.
- No license file is currently included in this repository. Do not assume permission to redistribute it until the project owner adds a license.

## Troubleshooting

### The frontend says the API is unavailable

Confirm both processes are running and check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/health
Get-Content web/.env.local -ErrorAction SilentlyContinue
```

`NEXT_PUBLIC_API_URL` should normally be `http://localhost:8000`. Restart the frontend after changing environment files. Keep the hostname/port in `FORENSCOPE_ALLOWED_ORIGINS` if you use another loopback frontend port.

### A tool is still marked missing

Call `/api/capabilities?refresh=true` or use Refresh availability. Confirm the executable works in the same account/environment that runs the backend. For portable Windows tools, set `FORENSCOPE_TOOL_PATHS` before backend startup. For WSL tools, confirm the default distribution starts and the command exists there.

The automatic installer does not cover every declared adapter and cannot mutate the hardened Docker container. Read the tool's upstream documentation, install it through a trusted channel, then restart or refresh detection.

### A preview returns HTTP 415

Binary preview accepts only verified raster images and browser-safe audio. Use the separate text-preview endpoint for supported documents. A text extension alone is not enough: bytes must pass conservative text/document checks. Encrypted, malformed, oversized, or unsafe package members may be rejected.

### A scan completed with no flag

Check Coverage & logs before concluding the flag is absent. Look for truncated source reads, missing tools, disabled options, artifact limits, parser warnings, encrypted content, and promising child artifacts. Try a flag prefix, then Deep mode selectively. Use Hex view and the Solve guide rather than repeatedly running every adapter without evidence.

### A job is stuck or the backend restarted

Refresh the job. Cancellation is cooperative and waits for a safe boundary or tool timeout. Jobs interrupted by process restart are marked failed on the next startup; create a new scan to rerun them.

### Upload rejected with 413

Raise `FORENSCOPE_MAX_UPLOAD_BYTES` before backend startup. For Docker Compose, set it in the shell or a root `.env` file. This permits storage only; profile inspection limits remain bounded.

### Build reports an unknown route classification

Vinext can emit an informational message that static analysis could not classify a route. If `npm run build` finishes successfully and the `/` route loads, this is not a build failure.

## Development and verification

Run backend tests from the repository root:

```powershell
.\backend\.venv\Scripts\python.exe -m pytest backend\tests -q
```

Run frontend checks:

```powershell
Push-Location web
npm run lint
npm run build
Pop-Location
```

An optional dependency audit requires registry/network access:

```powershell
Push-Location web
npm audit
Pop-Location
```

Useful focused tests include:

```powershell
.\backend\.venv\Scripts\python.exe -m pytest `
  backend\tests\test_text_preview.py `
  backend\tests\test_traffic_workbench.py `
  backend\tests\test_program_and_video_formats.py `
  backend\tests\test_structured_formats.py `
  backend\tests\test_solve_guidance.py -q
```

When adding a format or adapter:

1. Add conservative content detection and MIME/download mapping.
2. Keep parsers bounded by bytes, entries, nodes, depth, time, and output.
3. Never execute evidence or pass evidence-derived arguments to a shell.
4. Emit findings, text records, metadata, extracted bytes, and repairs with offsets/provenance.
5. Register built-in structure kinds and recursive handling.
6. Expose optional-tool applicability, profiles, source documentation, version checks, and fixed commands.
7. Add malformed/truncated/adversarial fixtures as well as a positive flag-bearing fixture.
8. Run the full backend suite, frontend lint/build, and `git diff --check`.

The backend OpenAPI schema, `/api/capabilities`, stored coverage object, and test suite are authoritative when this README and the implementation ever disagree.
