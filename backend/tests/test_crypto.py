from __future__ import annotations

import base64
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from app.analyzers.crypto import _evp_bytes_to_key, analyze_encrypted_payloads
from app.engine import AnalysisEngine, _capture_openssl_passphrase_hints
from conftest import patterned_pixels, rgb_png


def openssl_salted_fixture(passphrase: bytes, plaintext: bytes, digest_name: str = "md5") -> bytes:
    salt = b"01234567"
    key, iv = _evp_bytes_to_key(passphrase, salt, digest_name=digest_name)
    padding = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([padding]) * padding
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return b"Salted__" + salt + encryptor.update(padded) + encryptor.finalize()


def openssl_des3_salted_fixture(passphrase: bytes, plaintext: bytes) -> bytes:
    salt = b"76543210"
    key, iv = _evp_bytes_to_key(passphrase, salt, key_size=24, iv_size=8, digest_name="md5")
    padding = 8 - (len(plaintext) % 8)
    padded = plaintext + bytes([padding]) * padding
    encryptor = Cipher(algorithms.TripleDES(key), modes.CBC(iv)).encryptor()
    return b"Salted__" + salt + encryptor.update(padded) + encryptor.finalize()


def test_detects_and_decrypts_base64_openssl_payload() -> None:
    passphrase = "correct horse battery staple"
    plaintext = b"flag{openssl_recovery_fixture} " + (b"encrypted payload context " * 20)
    payload = base64.b64encode(openssl_salted_fixture(passphrase.encode(), plaintext))

    report = analyze_encrypted_payloads(
        [{"artifact_id": "artifact-1", "label": "metadata:payload", "kind": "text", "data": payload}],
        passphrase=passphrase,
    )

    assert report["status"] == "completed"
    assert report["detections"][0]["signal"] == "OpenSSL salted envelope"
    assert report["detections"][0]["decryption_status"] == "decrypted"
    assert report["decryptions"][0]["algorithm"] == "openssl-aes-256-cbc"
    assert report["decryptions"][0]["data"] == plaintext


def test_passphrase_guided_repeating_xor_recovers_flag() -> None:
    passphrase = "xor-key"
    plaintext = b"flag{repeating_xor_fixture}"
    ciphertext = bytes(byte ^ passphrase.encode()[index % len(passphrase)] for index, byte in enumerate(plaintext))

    report = analyze_encrypted_payloads(
        [{"artifact_id": "artifact-2", "label": "extracted payload", "kind": "binary", "data": ciphertext}],
        passphrase=passphrase,
    )

    assert report["detections"][0]["signal"] == "passphrase-guided ciphertext check"
    assert report["decryptions"][0]["algorithm"] == "repeating-key-xor"
    assert report["decryptions"][0]["data"] == plaintext


def test_openssl_sha256_kdf_variant_is_supported() -> None:
    passphrase = "sha256-secret"
    plaintext = b"flag{openssl_sha256_fixture} " + (b"payload context " * 20)
    payload = base64.b64encode(openssl_salted_fixture(passphrase.encode(), plaintext, digest_name="sha256"))

    report = analyze_encrypted_payloads(
        [{"artifact_id": "artifact-3", "label": "encoded payload", "kind": "text", "data": payload}],
        passphrase=passphrase,
    )

    assert report["decryptions"][0]["algorithm"] == "openssl-aes-256-cbc"
    assert report["decryptions"][0]["data"] == plaintext


def test_openssl_des3_envelope_is_supported() -> None:
    passphrase = "des3-secret"
    plaintext = b"flag{openssl_des3_fixture}"
    report = analyze_encrypted_payloads(
        [{"artifact_id": "artifact-des3", "label": "des3", "kind": "binary", "data": openssl_des3_salted_fixture(passphrase.encode(), plaintext)}],
        passphrase=passphrase,
    )

    assert report["decryptions"][0]["algorithm"] == "openssl-des-ede3-cbc"
    assert report["decryptions"][0]["data"] == plaintext


def test_pcap_openssl_command_hint_decrypts_without_persisting_the_secret() -> None:
    passphrase = "captured-des3-secret"
    plaintext = b"flag{pcap_openssl_command_fixture}"
    hints = _capture_openssl_passphrase_hints([{
        "source": "pcap-tcp-stream",
        "text": f"openssl des3 -d -salt -in transfer.des3 -out flag.txt -k {passphrase}",
    }])
    ignored = _capture_openssl_passphrase_hints([{
        "source": "strings:ascii",
        "text": f"openssl des3 -d -k {passphrase}",
    }])

    report = analyze_encrypted_payloads(
        [{"artifact_id": "pcap-stream", "label": "TCP recovery", "kind": "binary", "data": openssl_des3_salted_fixture(passphrase.encode(), plaintext)}],
        passphrase=None,
        passphrase_hints=hints,
    )

    assert hints == [passphrase]
    assert ignored == []
    assert report["decryptions"][0]["algorithm"] == "openssl-des-ede3-cbc"
    assert report["decryptions"][0]["passphrase_source"] == "observed-capture-command"
    assert report["decryptions"][0]["data"] == plaintext
    assert passphrase not in str({key: value for key, value in report["decryptions"][0].items() if key != "data"})


def test_crypto_stage_can_be_disabled() -> None:
    report = analyze_encrypted_payloads(
        [{"artifact_id": "source", "label": "source", "kind": "binary", "data": b"A" * 128}],
        passphrase=None,
        enabled=False,
    )
    assert report["status"] == "skipped"
    assert report["detections"] == []


def test_engine_links_decrypted_flag_artifact(tmp_path: Path) -> None:
    passphrase = "image-secret"
    plaintext = b"flag{engine_crypto_fixture} " + (b"payload context " * 20)
    payload = base64.b64encode(openssl_salted_fixture(passphrase.encode(), plaintext)).decode()
    image = tmp_path / "encrypted-metadata.png"
    image.write_bytes(rgb_png(8, 8, patterned_pixels(8, 8), text_chunks=(("Comment", payload),)))

    report = AnalysisEngine().run(
        input_path=image,
        output_dir=tmp_path / "output",
        profile="quick",
        flag_prefix="flag",
        password=passphrase,
        progress_callback=None,
        is_cancelled=lambda: False,
        options={"external_tools": False, "visual_analysis": False, "ocr": False, "barcodes": False},
    )

    crypto_method = next(method for method in report["methods"] if method["id"] == "crypto-analysis")
    assert crypto_method["status"] == "completed"
    assert crypto_method["artifact_ids"]
    assert any(candidate["value"] == "flag{engine_crypto_fixture}" for candidate in report["candidates"])
