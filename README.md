# Forenscope

Forenscope is a local-first CTF image-forensics workbench. Upload an image or damaged image candidate, choose a scan profile, and inspect ranked flag candidates, metadata, extracted artifacts, visual derivatives, and a complete method-coverage record.

The source file is copied into an isolated job directory, hashed, and never modified. Derived evidence is bounded, hashed, and linked to its parent. The application makes no analysis-time network calls.

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

Built-in analyzers cover hashing, magic signatures, entropy, ASCII/UTF-16 strings, PNG/JPEG/GIF/BMP/WebP/TIFF/ICO structure, embedded objects and trailers, bounded carving, nested archives, Base encodings, compression layers, visual channels, bit planes, animation frames, transparency, LSB permutations, OCR, QR/barcodes, and non-destructive repair candidates.

The bounded CLI adapter library currently includes:

- `file`, `strings`, ExifTool, Exiv2, and ImageMagick `identify`
- `pngcheck`, `pngcrush`, `jpeginfo`, `jpegtran`, `djpeg`, `gifsicle`, `webpinfo`, `webpmux`, `tiffinfo`, and `tiffdump`
- `zsteg`, Stegseek, Steghide, and OutGuess
- JPSeek/JPHide, JSteg, OpenStego RandomLSB, Binwalk, Foremost, and 7-Zip signature/container inspection
- Tesseract and ZBar command-line cross-checks

Every adapter is optional. The GUI reports it as installed, missing, disabled, inapplicable, timed out, or completed; a missing tool never hides the rest of the scan. The zsteg setting is explicit: `-a` checks all known channel/bit-depth combinations, while `--lsb` restricts the run to LSB checks. The Tool results tab exposes each redacted command, bounded stdout/stderr, exit state, and linked extracted artifacts.

Audio-only spectrogram and document-only `pdfinfo`/PDFiD analyzers are represented as explicit out-of-scope coverage records in the image section; they are reserved for the planned Audio and corrupted-file sections.

## Configurable scan settings

The settings panel controls structure parsing, visual analysis, LSB streams, OCR, barcodes, recursive extraction, decoders, repair generation, external tools, and external payload extraction. It also sets the recursion depth, artifact ceiling, per-tool timeout, external output budget, extracted-file ceiling, color-remap variants, OCR language, zsteg mode, and the exact external adapters to run. Settings are server-validated and saved with the job; passphrases are never persisted.

Results can be searched across flag candidates, provenance, metadata paths and values, artifact names and hashes, method summaries, and bounded tool output. JSON, standalone HTML, and ZIP case exports preserve the same evidence record.

The settings panel also includes **Download all missing**. It uses fixed, allowlisted Winget package IDs where available, downloads installer files into one ZIP bundle, and never executes them. Tools without a safe package mapping remain available through their project page link; after installing, restart the local API so availability is detected again.

## Verification

```powershell
.\backend\.venv\Scripts\python.exe -m pytest backend\tests -q
cd web
npm run lint
npm run build
npm audit
```
