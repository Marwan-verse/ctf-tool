#!/usr/bin/env python3
"""Print the optional forensic CLIs visible to the backend process."""

from __future__ import annotations

import shutil


TOOLS = (
    ("file", "type identification"),
    ("exiftool", "metadata"),
    ("exiv2", "metadata cross-check"),
    ("strings", "raw strings cross-check"),
    ("pngcheck", "PNG structure"),
    ("pngcrush", "PNG validation"),
    ("jpeginfo", "JPEG structure"),
    ("jpegtran", "lossless JPEG normalization"),
    ("djpeg", "JPEG decode validation"),
    ("identify", "ImageMagick inspection"),
    ("zsteg", "PNG/BMP bit-plane steganography"),
    ("steghide", "JPEG/BMP steganography"),
    ("outguess", "JPEG steganography"),
    ("stegseek", "steghide recovery (deep/manual)"),
    ("jpseek", "JPHide/JPSeek payload extraction"),
    ("jsteg", "JPEG coefficient steganography"),
    ("openstego", "RandomLSB steganography"),
    ("binwalk", "embedded signatures/carving (deep/manual)"),
    ("foremost", "header/footer carving"),
    ("tesseract", "OCR"),
    ("zbarimg", "barcode/QR decoding"),
    ("7z", "archive inspection"),
    ("gifsicle", "GIF animation inspection"),
    ("webpinfo", "WebP structure"),
    ("webpmux", "WebP container inspection"),
    ("tiffinfo", "TIFF structure"),
    ("tiffdump", "TIFF directory dump"),
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
