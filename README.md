# Forenscope

Forenscope is a local-first CTF media-forensics workbench. Upload an image, audio file, or damaged media candidate, choose a scan profile, and inspect ranked flag candidates, metadata, extracted artifacts, visual derivatives, signal analysis, and a complete method-coverage record.

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

Built-in analyzers cover hashing, magic signatures, entropy, ASCII/UTF-16 strings, PNG/JPEG/GIF/BMP/WebP/TIFF/ICO structure, embedded objects and trailers, bounded carving, nested archives, Base encodings, compression layers, visual channels, bit planes, animation frames, transparency, LSB permutations, OCR, QR/barcodes, possible encrypted-payload detection, passphrase-based recovery, and non-destructive repair candidates.

The bounded CLI adapter library currently includes:

- `file`, `strings`, ExifTool, Exiv2, and ImageMagick `identify`
- `pngcheck`, `pngcrush`, `jpeginfo`, `jpegtran`, `djpeg`, `gifsicle`, `webpinfo`, `webpmux`, `tiffinfo`, and `tiffdump`
- `zsteg`, Stegseek, Steghide, and OutGuess
- JPSeek/JPHide, JSteg, OpenStego RandomLSB, Binwalk, Foremost, and 7-Zip signature/container inspection
- Tesseract and ZBar command-line cross-checks

Every adapter is optional. The GUI reports it as installed, missing, disabled, inapplicable, timed out, or completed; a missing tool never hides the rest of the scan. The zsteg setting is explicit: `-a` checks all known channel/bit-depth combinations, while `--lsb` restricts the run to LSB checks. The Tool results tab exposes each redacted command, bounded stdout/stderr, exit state, and linked extracted artifacts.

## Audio analysis coverage

Choose **Audio** in the sidebar to inspect WAV, MP3, FLAC, Ogg/Opus, M4A/AAC, AIFF, AU, WMA/ASF, AMR, CAF, MIDI, and damaged audio candidates. The built-in WAV analyzer creates an interactive audio handoff, waveform and spectrogram views, channel/phase statistics, frequency peaks, silence and clipping findings, DTMF and tentative Morse decoding, PCM sample-bit extraction, channel/difference WAVs, reversed/normalized WAVs, and an Audacity-compatible label track. Its RX-SSTV decoder reads the VIS header and 1200/1500–2300 Hz scan tones, locks each line to the leading edge of its sync pulse, and recovers Robot 36/72, Martin M1/M2, Scottie S1/S2/DX, and PD120/180/240 transmissions as PNG images. Auto mode follows the VIS code; a manual mode override can recover signals with damaged headers. All recovered files are linked to the source and can be previewed, played, enlarged to fill the viewport, or downloaded in the GUI.

Optional audio adapters add FFprobe metadata, FFmpeg PCM conversion and spectrograms, SoX statistics and spectrograms, MediaInfo metadata, Multimon-ng radio/DTMF decoding, Minimodem decoding, and Steghide extraction for supported lossless audio. Forenscope performs SSTV image demodulation directly in the bounded analysis worker; compressed inputs are normalized to PCM by FFmpeg and passed back through the same decoder automatically. It also prepares compatible WAV/label files for further Audacity or desktop RX-SSTV review without launching an interactive GUI inside the server. The recovered images and handoff files appear in **Audio lab** and **Artifacts**.

## Corrupted-file recovery

Choose **Corrupted files** in the sidebar when the extension is missing, the container will not open, or you need recovery-first triage. It accepts any file type and starts with content signatures, file/extension mismatches, bounded string and entropy inspection, format-aware integrity checks, recursive archive expansion, carving, decoder passes, optional external tools, and encrypted-payload recovery. Corrupted-file scans remain on the generic recovery pipeline even when damaged bytes resemble audio, so they present structural diagnosis instead of a media playback workflow.

For supported image containers, deterministic fixes such as corrected PNG CRC fields, missing end markers, and mismatched size fields are written as separate, hashed **repair candidates**. The Repair lab records the signal that prompted each copy, the exact transformation, provenance, and SHA-256, then provides a download without ever replacing the source. If no safe automatic repair is possible, it directs the investigator to Hex view, recovered artifacts, and bounded tool output instead.

## Configurable scan settings

The settings panel controls structure parsing, visual analysis, LSB streams, OCR, barcodes, recursive extraction, decoders, encrypted-payload recovery, repair generation, external tools, and external payload extraction. Image settings include recursion depth, Foremost carving depth (1–4 bounded passes), color-remap variants, OCR language, and zsteg mode. Audio settings include the maximum analyzed duration, spectrogram FFT size, channel mode, PCM LSB depth, signal/SSTV analysis, channel exports, and Audacity handoff generation. Corrupted-file settings focus on validation, carving, decoders, copy-only repairs, and recovery adapters; media-only controls stay hidden. Shared limits cover artifacts, per-tool runtime, external output, and extracted files. Settings are server-validated and saved with the job; passphrases are never persisted. When a ciphertext-like extracted payload is detected, the engine reports the signal and, if a passphrase was supplied, tries only bounded repeating-key XOR and OpenSSL salted AES-256-CBC recovery. Successful plaintext is written as a hashed child artifact and scanned for flag candidates.

Foremost-carved PNG, JPEG, GIF, WebP, and BMP files appear as inline thumbnails in **Tool results**. Selecting a thumbnail opens the artifact inspector with a larger verified preview; other recovered formats remain available through the artifact download and lineage views.

The **Hex view** is a live, reversible byte editor for the original upload and every recovered artifact. It supports bounded text or hexadecimal searches across the full source, clickable match offsets, page navigation, per-byte edits with paste, undo/redo, discard, and a live image/audio preview. `POST /api/jobs/{job_id}/hex/analyze` rechecks the edited bytes in memory; the format-aware panel reports confirmed structural errors separately from heuristic leads such as zero runs, embedded signatures, and high entropy. `POST /api/jobs/{job_id}/hex/preview` renders a safe temporary preview, while `POST /api/jobs/{job_id}/hex/save` creates a new hashed `hex-edit` child artifact. The original artifact is never overwritten.

Results can be searched across flag candidates, provenance, metadata paths and values, artifact names and hashes, method summaries, and bounded tool output. JSON, standalone HTML, and ZIP case exports preserve the same evidence record.

The settings panel also includes **Install all missing**. After an explicit confirmation, the local API installs only fixed, allowlisted packages: Linux-native forensic and audio tools come from Kali WSL's package manager, while supported native utilities use silent Windows Package Manager installs. This includes FFmpeg/FFprobe, SoX, MediaInfo, Multimon-ng, and Minimodem for the Audio section where available. ZSteg, JSteg, and JPSeek use fixed-version or pinned-source managed installs. No package name, URL, archive, or command comes from the browser, and no manual ZIP extraction is required. The app re-detects every requested command when installation finishes and shows a per-tool diagnostic for anything still unavailable.

Detection checks native Windows PATH values, standard install folders, Ruby command wrappers, and the default WSL distribution. A tool found in WSL runs transparently against the uploaded file through its `/mnt/<drive>/...` path. The automatic Linux installer requires a working WSL distribution with root package access; on this Windows setup, Kali WSL is supported directly. For an existing portable Windows directory elsewhere, set `FORENSCOPE_TOOL_PATHS` to a semicolon-separated list of folders before launching the API.

## Verification

```powershell
.\backend\.venv\Scripts\python.exe -m pytest backend\tests -q
cd web
npm run lint
npm run build
npm audit
```
