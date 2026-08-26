#!/usr/bin/env python3
"""Print the optional forensic CLIs visible to the backend process."""

from __future__ import annotations

import shutil


TOOLS = (
    ("file", "type identification"),
    ("exiftool", "metadata"),
    ("pngcheck", "PNG structure"),
    ("identify", "ImageMagick inspection"),
    ("zsteg", "PNG/BMP bit-plane steganography"),
    ("steghide", "JPEG/BMP steganography"),
    ("stegseek", "steghide recovery (deep/manual)"),
    ("binwalk", "embedded signatures/carving (deep/manual)"),
    ("tesseract", "OCR"),
    ("zbarimg", "barcode/QR decoding"),
    ("7z", "archive inspection"),
)


def main() -> int:
    found = 0
    for executable, purpose in TOOLS:
        path = shutil.which(executable)
        state = path if path else "not installed"
        print(f"{executable:12} {state:32} {purpose}")
        found += path is not None
    print(f"\n{found}/{len(TOOLS)} optional tools available")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
