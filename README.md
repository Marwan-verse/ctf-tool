# Forenscope

Forenscope is a local-first CTF media and file-forensics workbench. Upload an image, audio file, capture, document, archive, database, disk image, memory image, or damaged candidate, choose a scan profile, and inspect ranked flag candidates, metadata, extracted artifacts, visual derivatives, signal analysis, and a complete method-coverage record.

The source file is copied into an isolated job directory, hashed, and never modified. Derived evidence is bounded, hashed, and linked to its parent. Scans make no network calls; network access is used only when you explicitly confirm automatic tool installation.

## Run locally

Backend (PowerShell):

```powershell
cd backend
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Frontend, in another terminal:

```powershell
cd web
npm install
npm run dev
```

Open `http://localhost:3000`. The API and its OpenAPI explorer are at `http://127.0.0.1:8000/api/docs`.

Alternatively, run `docker compose up --build`. Both published ports bind to loopback only.

## Image analysis coverage

Built-in analyzers cover hashing, magic signatures, entropy, ASCII/UTF-16 strings, bounded Unicode whitespace-bitstream recovery (including visually identical Unicode spaces and inverted bit order), Unicode NFKC/confusable normalization, bounded non-rendering SVG text/tspan recovery (including whitespace-obfuscated flags), PNG/JPEG/GIF/BMP/WebP/TIFF/ICO structure, BMP bitfield-mask inspection and interleaved 16-bit word-lane archive recovery, embedded objects and trailers, bounded carving, nested archives, ZIP local-file-header extra-field carving (including OOXML/DOCX hidden ZIPs), Base encodings, compression layers, visual channels, value-filtered and ordinary bit planes (including MSB), pairwise channel-bit XOR views, original palette-index bytes and planes, direct GIF local-palette frame index recovery, animation frames, transparency, bounded low-color QR black/white mapping search, baseline-JPEG DCT coefficient parity streams for JSteg-style challenges, LSB permutations, OCR, QR/barcodes, possible encrypted-payload detection, passphrase-based recovery, and non-destructive repair candidates.

The bounded CLI adapter library currently includes:

- `file`, `strings`, ExifTool, Exiv2, and ImageMagick `identify`
- `pngcheck`, `pngcrush`, `pngfix`, OptiPNG, `jpeginfo`, `jpegtran`, `djpeg`, `gifsicle`, `webpinfo`, `webpmux`, `tiffinfo`, and `tiffdump`
- `zsteg`, Stegseek, Steghide, and OutGuess
- JPSeek/JPHide, JSteg, OpenStego RandomLSB, Binwalk, Foremost, and 7-Zip signature/container inspection
- Tesseract and ZBar command-line cross-checks, Poppler PDF tools (`pdfinfo`, `pdftotext`, `pdfimages`, `pdfdetach`), qpdf validation, and the SNOW whitespace decoder
- Wireshark `capinfos`/TShark packet dissections, protocol hierarchy, endpoints, conversations, I/O statistics, Expert Info, cleartext credentials, RTP statistics, USB HID decoding, isolated HTTP/SMB/TFTP/IMF/DICOM object extraction, `tcpflow` stream carving, WPA/PMKID hash extraction with `hcxpcapngtool`, and `pcapfix` capture repair
- SQLite read-only safe dumps; Oletools `oleid`, `olevba`, `oleobj`, and `rtfobj`; Sleuth Kit `mmls`, `fsstat`, `fls`, and `tsk_recover`; libewf `ewfinfo`; Reglookup; python-evtx; libpst; and offline Volatility 3 triage

The corrupted-file workflow adds web-sourced, open-source recovery adapters for PNG (`pngfix` and OptiPNG), GIF (Gifsicle's tolerant rewrite), and ZIP (Info-ZIP `-F` and `-FF`). Built-in recovery also proves one-byte BZip2 header repairs by successful bounded decompression, derives unusable BMP heights from exact row strides, and parses PDF metadata, active-content markers, Flate streams, embedded images/attachments, and trailing archives without executing document code. Each adapter is pinned to a known executable/package mapping, runs with bounded time and output, and writes a separate derived artifact when a repaired file is produced. The settings panel links to each upstream project for provenance; those links are documentation only and never become executable download URLs.

Every adapter is optional. The GUI reports it as installed, missing, disabled, inapplicable, timed out, or completed; a missing tool never hides the rest of the scan. Steghide automatically makes one non-interactive empty-passphrase attempt when no passphrase is supplied, which recovers the common passwordless CTF format; a supplied passphrase replaces that attempt. A verified portable Windows build can live under `.tools/steghide/bin` or `.tools/steghide-0.5.1-win32/steghide` without changing the system PATH. The zsteg setting is explicit: `-a` checks all known channel/bit-depth combinations, while `--lsb` restricts the run to LSB checks. The Tool results tab exposes each redacted command, bounded stdout/stderr, exit state, and linked extracted artifacts.

## General forensic-file coverage

Built-in magic and bounded structure checks now recognize classic PCAP and PCAPNG captures, SQLite databases, OLE compound files and legacy Office documents, RTF, RFC 5322/MIME email, Outlook PST/OST stores, TAR/7z/RAR archives, raw MBR/GPT/filesystem images, E01/EWF segments, Windows registry hives and EVTX logs, memory/crash dumps, GNU shar/uuencode and Unix ar containers, and LZIP/LZ4/LZMA/LZOP compression. MIME bodies and attachments are decoded in memory; regular TAR members are read with `extractfile` and never materialized using archive-supplied paths. Nested gzip/bzip2/xz/LZIP/LZ4/LZMA/LZOP layers remain recursive, and 7-Zip can perform an opt-in flat extraction for formats the Python standard library does not support. The bounded EVTX pass decodes UTF-16 event strings, extracts Base64 values even when glued to neighboring fields, and reassembles ordered flag fragments.

Deep capture scans recover IPv4/IPv6/TCP/UDP/ICMP flows across classic PCAP and multi-section PCAPNG (including IDB timestamp resolution, EPB/SPB/PB blocks, comments, and decryption-secret blocks). A dedicated Traffic tab exposes a bounded packet list, display filters, packet layers and hex bytes, protocol hierarchy, endpoints, conversations, stream summaries, DNS/HTTP/TLS records, recovered objects, and expert-style events. The native pass reassembles out-of-order TCP spans with retransmission/overlap clipping, joins UDP and ICMP conversations, parses DNS questions/TXT/CNAME/A/AAAA data, reconstructs TFTP RRQ/WRQ/DATA objects, and tests timestamp-ordered per-packet Base64, hex/Base32, URL, compression, constant-XOR/byte-shift, source/destination-address, source-port, TTL/IP-ID/ICMP/TCP header covert channels. It also packs TCP/IP flag bit planes in both bit orders and directions, clusters inter-packet timing deltas, scans direct millisecond/centisecond/microsecond timing bytes, removes repeated ICMP padding, and reconstructs payloads selected by IPv4 reserved/DF or TCP PSH/RST/URG flags. Character-spaced payload flags are preserved as evidence and scanned again after inter-token whitespace normalization. Captures can concatenate Base64 fragments and try repeating XOR keys derived from decimal IMSI windows, which covers rogue-cell exfiltration patterns without requiring Wireshark. Printable hex packet payloads and non-IP Ethernet data are turned back into candidate text or files, ordinary eight-byte USB boot-keyboard reports are decoded (including shift and backspace), and bounded HTTP/SMB/TFTP/IMF/DICOM exported objects are retained for recursive flag scanning. Optional adapters use Wireshark's own dissectors for bounded JSON packet trees, statistics, Expert Info, credentials, RTP, and object exports; `tcpflow`, `hcxpcapngtool`, and `pcapfix` produce isolated child artifacts and never overwrite the source. Deep disk scans derive MBR/GPT sector starts, enumerate each bounded partition with Sleuth Kit, include deleted names, and recover allocated/unallocated files into isolated temporary output before applying the normal artifact limits. Office and RTF scans expose decoded VBA and embedded objects without launching Microsoft Office. Volatility runs with `--offline`, so symbol availability is reported honestly and an analysis never downloads data implicitly.

## Audio analysis coverage

Choose **Audio** in the sidebar to inspect WAV, MP3, FLAC, Ogg/Opus, M4A/AAC, AIFF, AU, WMA/ASF, AMR, CAF, MIDI, and damaged audio candidates. The built-in WAV analyzer creates an interactive audio handoff, waveform and spectrogram views, channel/phase statistics, frequency peaks, silence and clipping findings, DTMF and tentative Morse decoding, PCM sample-bit extraction, channel/difference WAVs, reversed/normalized WAVs, and an Audacity-compatible label track. Its RX-SSTV decoder reads the VIS header and 1200/1500–2300 Hz scan tones, locks each line to the leading edge of its sync pulse, and recovers Robot 36/72, Martin M1/M2, Scottie S1/S2/DX, and PD120/180/240 transmissions as PNG images. Auto mode follows the VIS code; a manual mode override can recover signals with damaged headers. All recovered files are linked to the source and can be previewed, played, enlarged to fill the viewport, or downloaded in the GUI.

Optional audio adapters add FFprobe metadata, FFmpeg PCM conversion and spectrograms, SoX statistics and spectrograms, MediaInfo metadata, Multimon-ng radio/DTMF decoding, Minimodem 1200-baud and Bell-103-compatible 300-baud decoding, and Steghide extraction for supported lossless audio. Forenscope performs SSTV image demodulation directly in the bounded analysis worker; compressed inputs are normalized to PCM by FFmpeg and passed back through the same decoder automatically. It also prepares compatible WAV/label files for further Audacity or desktop RX-SSTV review without launching an interactive GUI inside the server. The recovered images and handoff files appear in **Audio lab** and **Artifacts**.

## Corrupted-file recovery

Choose **Corrupted files** in the sidebar when the extension is missing, the container will not open, or you need recovery-first triage. It accepts any file type and starts with content signatures, file/extension mismatches, bounded string and entropy inspection, format-aware integrity checks, recursive archive expansion (including ZIP bytes hidden in local-file-header extra fields), carving, decoder passes, optional external tools, and encrypted-payload recovery. Corrupted-file scans remain on the generic recovery pipeline even when damaged bytes resemble audio, so they present structural diagnosis instead of a media playback workflow.

For supported image containers, deterministic fixes such as corrected PNG CRC fields, missing end markers, mismatched size fields, and CRC-proven multi-stage PNG header/chunk-boundary recovery are written as separate, hashed **repair candidates**. The Repair lab records the signal that prompted each copy, the exact transformation, provenance, and SHA-256, then provides a download without ever replacing the source. When enabled, the web-sourced adapters run alongside those built-in checks: `pngfix`/OptiPNG recover parser-readable PNG data, Gifsicle rewrites tolerant GIF parses, and Info-ZIP `-F`/`-FF` rebuilds damaged ZIP directories. These tools cannot reconstruct bytes that are absent, so their diagnostics remain visible when a repair is incomplete. If no safe automatic repair is possible, it directs the investigator to Hex view, recovered artifacts, and bounded tool output instead.

## Configurable scan settings

The settings panel controls structure parsing, visual analysis, LSB streams, OCR, barcodes, recursive extraction, decoders, encrypted-payload recovery, repair generation, external tools, and external payload extraction. Image settings include recursion depth (up to 12 bounded layers), Foremost carving depth (1–4 bounded passes), color-remap variants, OCR language, and zsteg mode. Audio settings include the maximum analyzed duration, spectrogram FFT size, channel mode, PCM bit-plane depth (1–8), raw payload-byte extraction, stereo channel splits, signal/SSTV analysis, channel exports, and Audacity handoff generation. Corrupted-file settings focus on validation, carving, decoders, copy-only repairs, and recovery adapters; media-only controls stay hidden. Shared limits cover artifacts, per-tool runtime, external output, and extracted files. Settings are server-validated and saved with the job; passphrases are never persisted. When a ciphertext-like extracted payload is detected, the engine reports the signal and, if a passphrase was supplied, tries only bounded repeating-key XOR and OpenSSL salted AES-256-CBC recovery. Successful plaintext is written as a hashed child artifact and scanned for flag candidates.

Foremost-carved PNG, JPEG, GIF, WebP, and BMP files appear as inline thumbnails in **Tool results**. Selecting a thumbnail opens the artifact inspector with a larger verified preview; other recovered formats remain available through the artifact download and lineage views.

The **Hex view** is a live, reversible byte editor for the original upload and every recovered artifact. It supports bounded text or hexadecimal searches across the full source, clickable match offsets, page navigation, per-byte edits with paste, undo/redo, discard, and a live image/audio preview. Hovering a byte highlights its matching ASCII character; right-clicking opens actions to undo that byte, restore it, clear one unit (byte), or clear the current fixed-size block to `00` without changing file length. The format-reference card documents common image/audio magic bytes, trailers, and container structure so an investigator can compare the live bytes with expected headers. `Scan corruption` re-runs format detection and integrity checks against the current bytes, identifies likely missing signatures, end markers, CRCs, and declared-size mismatches, and lists only deterministic copy-only repair candidates. Each candidate can be saved as a new hashed `repair` child artifact after a fresh source-SHA check; the original artifact is never overwritten. `POST /api/jobs/{job_id}/hex/analyze` rechecks edited bytes in memory; the format-aware panel reports confirmed structural errors separately from heuristic leads such as zero runs, embedded signatures, and high entropy. `POST /api/jobs/{job_id}/hex/preview` renders a safe temporary preview, while `POST /api/jobs/{job_id}/hex/save` creates a new hashed `hex-edit` child artifact.

Results can be searched across flag candidates, provenance, metadata paths and values, artifact names and hashes, method summaries, and bounded tool output. JSON, standalone HTML, and ZIP case exports preserve the same evidence record.

The settings panel also includes **Install all missing**. After an explicit confirmation, the local API installs only fixed, allowlisted packages: Linux-native forensic and audio tools come from Kali WSL's package manager, while supported native utilities use silent Windows Package Manager installs. This includes FFmpeg/FFprobe, SoX, MediaInfo, Multimon-ng, Minimodem, Poppler, qpdf, SNOW, Wireshark/TShark, SQLite, Oletools, Sleuth Kit, libewf, Reglookup, and libpst where available. ZSteg, JSteg, and JPSeek use fixed-version or pinned-source managed installs; Volatility 3 and python-evtx use fixed, isolated virtual environments under `/opt` with only their launchers linked into `/usr/local/bin`. No package name, URL, archive, or command comes from the browser, and no manual ZIP extraction is required. The app re-detects every requested command when installation finishes and shows a per-tool diagnostic for anything still unavailable.

Detection checks native Windows PATH values, standard install folders, Ruby command wrappers, and the default WSL distribution. A tool found in WSL runs transparently against the uploaded file through its `/mnt/<drive>/...` path. The automatic Linux installer requires a working WSL distribution with root package access; on this Windows setup, Kali WSL is supported directly. For an existing portable Windows directory elsewhere, set `FORENSCOPE_TOOL_PATHS` to a semicolon-separated list of folders before launching the API.

## Verification

```powershell
.\backend\.venv\Scripts\python.exe -m pytest backend\tests -q
cd web
npm run lint
npm run build
npm audit
```
