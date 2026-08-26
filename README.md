# Forenscope

Forenscope is a local-first CTF image-forensics workbench. Upload an image or damaged image candidate, choose a scan profile, and inspect ranked flag candidates, metadata, extracted artifacts, visual derivatives, and a complete method-coverage record.

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

Audio-only spectrogram and document-only `pdfinfo`/PDFiD analyzers are represented as explicit out-of-scope coverage records in the image section; they are reserved for the planned Audio and corrupted-file sections.

## Configurable scan settings

The settings panel controls structure parsing, visual analysis, LSB streams, OCR, barcodes, recursive extraction, decoders, encrypted-payload recovery, repair generation, external tools, and external payload extraction. It also sets the recursion depth, Foremost carving depth (1–4 bounded passes), artifact ceiling, per-tool timeout, external output budget, extracted-file ceiling, color-remap variants, OCR language, zsteg mode, and the exact external adapters to run. Settings are server-validated and saved with the job; passphrases are never persisted. When a ciphertext-like payload is detected, the engine reports the signal and, if a passphrase was supplied, tries only bounded repeating-key XOR and OpenSSL salted AES-256-CBC recovery. Successful plaintext is written as a hashed child artifact and scanned for flag candidates.

Foremost-carved PNG, JPEG, GIF, WebP, and BMP files appear as inline thumbnails in **Tool results**. Selecting a thumbnail opens the artifact inspector with a larger verified preview; other recovered formats remain available through the artifact download and lineage views.

The **Hex view** is a read-only byte inspector for the original upload and every recovered artifact. It supports bounded text or hexadecimal searches across the full artifact, clickable match offsets, page navigation, and heuristic anomaly hints for long zero/repeated-byte runs, embedded file signatures, and high-entropy blocks. The displayed bytes are never edited, which preserves the evidentiary source.

Results can be searched across flag candidates, provenance, metadata paths and values, artifact names and hashes, method summaries, and bounded tool output. JSON, standalone HTML, and ZIP case exports preserve the same evidence record.

The settings panel also includes **Install all missing**. After an explicit confirmation, the local API installs only fixed, allowlisted packages: Linux-native forensic tools come from Kali WSL's package manager, while supported native utilities use silent Windows Package Manager installs. ZSteg, JSteg, and JPSeek use fixed-version or pinned-source managed installs. No package name, URL, archive, or command comes from the browser, and no manual ZIP extraction is required. The app re-detects every requested command when installation finishes and shows a per-tool diagnostic for anything still unavailable.

Detection checks native Windows PATH values, standard install folders, Ruby command wrappers, and the default WSL distribution. A tool found in WSL runs transparently against the uploaded file through its `/mnt/<drive>/...` path. The automatic Linux installer requires a working WSL distribution with root package access; on this Windows setup, Kali WSL is supported directly. For an existing portable Windows directory elsewhere, set `FORENSCOPE_TOOL_PATHS` to a semicolon-separated list of folders before launching the API.

## Verification

```powershell
.\backend\.venv\Scripts\python.exe -m pytest backend\tests -q
cd web
npm run lint
npm run build
npm audit
```
