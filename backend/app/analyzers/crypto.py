"""Bounded encrypted-payload detection and recovery helpers.

The image engine cannot prove that arbitrary high-entropy bytes are encrypted,
so this module reports signals as *possible ciphertext*. Recovery is strictly
bounded: it uses a user-supplied passphrase for repeating-key XOR and the
OpenSSL salted AES-256-CBC or legacy 3DES-CBC envelope, plus a small single-byte
XOR search that only accepts flag-shaped/plaintext-looking output. No
unbounded key guessing or general-purpose password cracking is performed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from typing import Any, Iterable

from .common import byte_entropy, display_text, sha256_bytes


_FLAG_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])[A-Za-z][A-Za-z0-9_-]{1,31}\{[A-Za-z0-9_@!#$%&*+.,:;?=/\\|~^'\"()\[\]<> -]{2,200}\}",
    re.IGNORECASE,
)
_BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/\s]*={0,2}$")
_HEX_PATTERN = re.compile(r"^[0-9A-Fa-f\s]+$")
_MEDIA_CONTAINER_KINDS = {
    "png", "jpeg", "gif", "bmp", "webp", "tiff", "ico",
    "audio", "wav", "aiff", "flac", "ogg", "mp3", "aac", "m4a", "au", "asf", "amr", "caf", "midi",
}
_MAX_INPUT_BYTES = 4 * 1024 * 1024
_MAX_INPUTS = 96
_MAX_ATTEMPTS = 192


def _text_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    sample = data[:8192]
    return sum(1 for byte in sample if byte in (9, 10, 13) or 32 <= byte <= 126) / len(sample)


def _flag_like(data: bytes) -> bool:
    try:
        text = data.decode("utf-8", "replace")
    except Exception:
        return False
    return bool(_FLAG_PATTERN.search(text))


def _looks_plaintext(data: bytes) -> bool:
    if not data or _text_ratio(data) < 0.82:
        return False
    if _flag_like(data):
        return True
    text = data[:8192].decode("utf-8", "replace")
    return any(character.isalpha() for character in text) and any(character in text for character in " \t\r\n{}:_-")


def _unwrap_candidates(data: bytes) -> list[tuple[str, bytes]]:
    """Return raw bytes and at most one validated hex/base64 interpretation."""

    candidates: list[tuple[str, bytes]] = [("raw", data)]
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        text = ""
    compact = re.sub(r"\s+", "", text)
    if len(compact) >= 24 and len(compact) % 4 in {0, 2, 3} and _BASE64_PATTERN.fullmatch(text):
        try:
            padded = compact + "=" * (-len(compact) % 4)
            decoded = base64.b64decode(padded, validate=True)
            if decoded and decoded != data:
                candidates.append(("base64", decoded))
        except (ValueError, binascii.Error):
            pass
    if len(compact) >= 32 and len(compact) % 2 == 0 and _HEX_PATTERN.fullmatch(text):
        try:
            decoded = bytes.fromhex(compact)
            if decoded and decoded != data:
                candidates.append(("hex", decoded))
        except ValueError:
            pass
    return candidates


def _passphrase_candidates(passphrase: str) -> list[bytes]:
    raw = passphrase.encode("utf-8")
    candidates = [raw]
    if passphrase.lower().startswith("hex:"):
        try:
            decoded = bytes.fromhex(passphrase[4:].strip())
            if decoded and decoded != raw:
                candidates.append(decoded)
        except ValueError:
            pass
    return [candidate for candidate in candidates if candidate]


def _recovery_passphrases(
    passphrase: str | None,
    passphrase_hints: Iterable[str],
) -> list[tuple[str, str]]:
    """Return a tiny, deduplicated list of explicitly observed credentials.

    Hints are not guesses: callers may supply only literal credentials that
    were already visible in the same evidence item (for example, an OpenSSL
    command in a CTF TCP stream).  Values are intentionally kept transient and
    never copied into reports or artifact metadata.
    """

    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(value: str | None, source: str) -> None:
        if not isinstance(value, str):
            return
        candidate = value.strip()
        if not candidate or len(candidate) > 256 or candidate in seen:
            return
        if any(ord(character) < 32 or ord(character) == 127 for character in candidate):
            return
        seen.add(candidate)
        candidates.append((candidate, source))

    add(passphrase, "user-supplied")
    for hint in passphrase_hints:
        add(hint, "observed-capture-command")
        if len(candidates) >= 8:
            break
    return candidates


def _xor_repeat(data: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def _single_byte_xor(data: bytes) -> tuple[int, bytes] | None:
    if len(data) > 128 * 1024:
        return None
    for key in range(1, 256):
        candidate = bytes(byte ^ key for byte in data)
        if _flag_like(candidate):
            return key, candidate
    return None


def _evp_bytes_to_key(
    password: bytes,
    salt: bytes,
    key_size: int = 32,
    iv_size: int = 16,
    digest_name: str = "md5",
) -> tuple[bytes, bytes]:
    digest_factory = getattr(hashlib, digest_name)
    blocks: list[bytes] = []
    previous = b""
    while sum(len(block) for block in blocks) < key_size + iv_size:
        previous = digest_factory(previous + password + salt).digest()
        blocks.append(previous)
    material = b"".join(blocks)
    return material[:key_size], material[key_size:key_size + iv_size]


def _openssl_aes_decrypt(data: bytes, passphrase: bytes) -> tuple[bytes | None, str | None]:
    if not data.startswith(b"Salted__") or len(data) <= 16:
        return None, "not_an_openssl_envelope"
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        return None, "cryptography_dependency_missing"
    salt = data[8:16]
    ciphertext = data[16:]
    if not ciphertext or len(ciphertext) % 16:
        return None, "invalid_block_length"
    last_reason = "invalid_padding"
    # OpenSSL versions in the wild use both legacy MD5 and newer SHA-256
    # EVP_BytesToKey defaults. Try the two fixed, non-guessing derivations.
    for digest_name in ("sha256", "md5"):
        key, iv = _evp_bytes_to_key(passphrase, salt, digest_name=digest_name)
        try:
            decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except Exception:
            last_reason = "cipher_error"
            continue
        if not plaintext:
            last_reason = "empty_plaintext"
            continue
        padding = plaintext[-1]
        if padding < 1 or padding > 16 or plaintext[-padding:] != bytes([padding]) * padding:
            continue
        return plaintext[:-padding], None
    return None, last_reason


def _openssl_des3_decrypt(data: bytes, passphrase: bytes) -> tuple[bytes | None, str | None]:
    """Try the legacy OpenSSL ``des-ede3-cbc`` salted envelope used by CTFs."""

    if not data.startswith(b"Salted__") or len(data) <= 16:
        return None, "not_an_openssl_envelope"
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:
            TripleDES = algorithms.TripleDES
    except ImportError:
        return None, "cryptography_dependency_missing"
    salt = data[8:16]
    ciphertext = data[16:]
    if not ciphertext or len(ciphertext) % 8:
        return None, "invalid_block_length"
    last_reason = "invalid_padding"
    for digest_name in ("sha256", "md5"):
        key, iv = _evp_bytes_to_key(passphrase, salt, key_size=24, iv_size=8, digest_name=digest_name)
        try:
            decryptor = Cipher(TripleDES(key), modes.CBC(iv)).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except Exception:
            last_reason = "cipher_error"
            continue
        if not plaintext:
            last_reason = "empty_plaintext"
            continue
        padding = plaintext[-1]
        if padding < 1 or padding > 8 or plaintext[-padding:] != bytes([padding]) * padding:
            continue
        return plaintext[:-padding], None
    return None, last_reason


def analyze_encrypted_payloads(
    inputs: Iterable[dict[str, Any]],
    *,
    passphrase: str | None,
    passphrase_hints: Iterable[str] = (),
    enabled: bool = True,
    max_inputs: int = _MAX_INPUTS,
    max_input_bytes: int = _MAX_INPUT_BYTES,
    max_attempts: int = _MAX_ATTEMPTS,
) -> dict[str, Any]:
    """Detect likely ciphertext and return only successful bounded decryptions."""

    if not enabled:
        return {
            "status": "skipped",
            "detections": [],
            "decryptions": [],
            "attempts": 0,
            "summary": "Encrypted-payload analysis was disabled in this job's settings.",
        }

    recovery_passphrases = _recovery_passphrases(passphrase, passphrase_hints)
    detections: list[dict[str, Any]] = []
    decryptions: list[dict[str, Any]] = []
    seen: set[str] = set()
    attempts = 0
    dependency_missing = False
    input_count = 0
    for item in inputs:
        if input_count >= max_inputs:
            break
        input_count += 1
        artifact_id = str(item.get("artifact_id") or "source")
        label = display_text(item.get("label") or "payload", 160)
        kind = str(item.get("kind") or "")
        raw = item.get("data")
        if not isinstance(raw, bytes):
            continue
        # Image containers and rendered derivatives are already covered by the
        # pixel/LSB stages; their compressed bytes are expected to be high
        # entropy and would create noisy ciphertext signals here.
        if kind in _MEDIA_CONTAINER_KINDS:
            continue
        data = raw[:max_input_bytes]
        for encoding, blob in _unwrap_candidates(data):
            if len(blob) < 16:
                continue
            digest = sha256_bytes(blob)
            if digest in seen:
                continue
            seen.add(digest)
            entropy = round(byte_entropy(blob), 4)
            is_salted = blob.startswith(b"Salted__")
            is_binary = _text_ratio(blob) < 0.72
            decoded_text = encoding != "raw"
            passphrase_guided = bool(recovery_passphrases) and is_binary and len(blob) <= 1 * 1024 * 1024
            strong_signal = is_salted or (is_binary and entropy >= 7.05) or (decoded_text and entropy >= 6.35)
            if not strong_signal and not passphrase_guided:
                continue
            signal = "OpenSSL salted envelope" if is_salted else (
                f"{encoding} payload with high entropy" if decoded_text else "high-entropy binary payload"
            )
            if passphrase_guided and not strong_signal:
                signal = "passphrase-guided ciphertext check"
            detection = {
                "artifact_id": artifact_id,
                "label": label,
                "encoding": encoding,
                "signal": signal,
                "size": len(blob),
                "entropy": entropy,
                "passphrase_supplied": bool(passphrase),
                "observed_passphrase_hint_available": any(source == "observed-capture-command" for _value, source in recovery_passphrases),
                "decryption_status": "not_attempted",
            }
            successful = False
            if attempts < max_attempts and recovery_passphrases:
                for passphrase_value, passphrase_source in recovery_passphrases:
                    for key in _passphrase_candidates(passphrase_value):
                        if attempts >= max_attempts:
                            break
                        if is_salted:
                            for algorithm_name, decryptor in (
                                ("openssl-aes-256-cbc", _openssl_aes_decrypt),
                                ("openssl-des-ede3-cbc", _openssl_des3_decrypt),
                            ):
                                if attempts >= max_attempts:
                                    break
                                attempts += 1
                                plaintext, reason = decryptor(blob, key)
                                if reason == "cryptography_dependency_missing":
                                    dependency_missing = True
                                if plaintext is not None and _looks_plaintext(plaintext):
                                    decryptions.append({
                                        "artifact_id": artifact_id,
                                        "label": label,
                                        "encoding": encoding,
                                        "algorithm": algorithm_name,
                                        "data": plaintext,
                                        "size": len(plaintext),
                                        "flag_like": _flag_like(plaintext),
                                        "passphrase_source": passphrase_source,
                                    })
                                    successful = True
                                    break
                            if successful:
                                break
                        else:
                            attempts += 1
                            plaintext = _xor_repeat(blob, key)
                            if _looks_plaintext(plaintext) and plaintext != blob:
                                decryptions.append({
                                    "artifact_id": artifact_id,
                                    "label": label,
                                    "encoding": encoding,
                                    "algorithm": "repeating-key-xor",
                                    "data": plaintext,
                                    "size": len(plaintext),
                                    "flag_like": _flag_like(plaintext),
                                    "passphrase_source": passphrase_source,
                                })
                                successful = True
                                break
                    if successful or attempts >= max_attempts:
                        break
            # A provided/observed passphrase can make an ordinary low-entropy
            # container eligible for a repeating-key check. Do not then run a
            # broad single-byte-XOR scan over that container: it is unrelated
            # to the observed OpenSSL envelope and can create false flags.
            if not successful and attempts < max_attempts and not is_salted and strong_signal:
                attempts += min(255, max_attempts - attempts)
                single = _single_byte_xor(blob)
                if single is not None:
                    key, plaintext = single
                    decryptions.append({
                        "artifact_id": artifact_id,
                        "label": label,
                        "encoding": encoding,
                        "algorithm": "single-byte-xor",
                        "data": plaintext,
                        "size": len(plaintext),
                        "flag_like": True,
                        "key_hex": f"{key:02x}",
                    })
                    successful = True
            if not strong_signal and not successful:
                # A passphrase-guided probe is kept quiet unless it actually
                # yields plausible plaintext; this avoids flagging every
                # ordinary binary artifact as encrypted.
                continue
            detection["decryption_status"] = "decrypted" if successful else ("key_required" if not recovery_passphrases else "no_plaintext")
            detections.append(detection)

    if detections:
        summary = f"Detected {len(detections)} possible encrypted payload(s); recovered {len(decryptions)} plaintext result(s)."
    else:
        summary = "No high-confidence ciphertext indicators were detected in extracted payloads."
    return {
        "status": "completed",
        "detections": detections[:200],
        "decryptions": decryptions[:64],
        "attempts": attempts,
        "dependency_missing": dependency_missing,
        "summary": summary,
    }
