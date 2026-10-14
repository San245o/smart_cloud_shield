"""Envelope encryption: a random key per file (DEK) encrypts the data;
the DEK is wrapped by a master key (KEK) that lives outside the database.

This is an attribute-POLICY approximation of CP-ABE: the key is only
released after the access policy and risk check pass (see app.download).
It is NOT real CP-ABE: the server is trusted to enforce the policy.
"""
import base64
import hashlib
import json
import os
import time
from pathlib import Path

from cryptography.fernet import Fernet
from scs.config import Config

KEK_FILE = Config.INSTANCE_DIR / "kek.key"


def _load_kek() -> bytes:
    env = os.environ.get("SCS_KEK")  # preferred in production
    if env:
        return env.encode()
    if not KEK_FILE.exists():
        KEK_FILE.parent.mkdir(parents=True, exist_ok=True)
        KEK_FILE.write_bytes(Fernet.generate_key())
        try:
            os.chmod(KEK_FILE, 0o600)
        except OSError:
            pass  # Windows does not strictly implement POSIX 0o600 chmod
    return KEK_FILE.read_bytes()


def encrypt(data: bytes):
    """Return (ciphertext, wrapped_dek)."""
    dek = Fernet.generate_key()
    ciphertext = Fernet(dek).encrypt(data)
    wrapped = Fernet(_load_kek()).encrypt(dek)
    return ciphertext, wrapped


def decrypt(ciphertext: bytes, wrapped_dek: bytes) -> bytes:
    """Unwraps DEK using KEK and decrypts ciphertext with DEK."""
    dek = Fernet(_load_kek()).decrypt(wrapped_dek)
    return Fernet(dek).decrypt(ciphertext)  # raises InvalidToken if tampered


def encrypt_string(plaintext: str) -> str:
    """Envelope-encrypts an arbitrary UTF-8 string into a base64url JSON bundle."""
    data = plaintext.encode("utf-8")
    ct, wrapped_dek = encrypt(data)
    bundle = {
        "v": 1,
        "algo": "Fernet(AES-128-CBC+HMAC-SHA256)",
        "ct": base64.urlsafe_b64encode(ct).decode("ascii"),
        "dek": base64.urlsafe_b64encode(wrapped_dek).decode("ascii"),
        "ts": int(time.time()),
    }
    return base64.urlsafe_b64encode(json.dumps(bundle).encode("ascii")).decode("ascii")


def decrypt_string(token: str) -> str:
    """Decrypts a base64url JSON bundle created by encrypt_string."""
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        bundle = json.loads(raw)
        ct = base64.urlsafe_b64decode(bundle["ct"].encode("ascii"))
        wrapped_dek = base64.urlsafe_b64decode(bundle["dek"].encode("ascii"))
        plaintext_bytes = decrypt(ct, wrapped_dek)
        return plaintext_bytes.decode("utf-8")
    except Exception as exc:
        raise ValueError(f"Decryption failed or invalid token: {exc}") from exc


def get_crypto_info() -> dict:
    """Returns cryptographic suite architecture status."""
    kek = _load_kek()
    fingerprint = hashlib.sha256(kek).hexdigest()[:16].upper()
    return {
        "cipher": "AES-128-CBC",
        "mac": "HMAC-SHA256",
        "key_derivation": "CSPRNG 256-bit",
        "architecture": "Two-Tier Envelope Encryption (KEK/DEK)",
        "kek_source": "SCS_KEK env" if os.environ.get("SCS_KEK") else "instance/kek.key",
        "kek_fingerprint": f"SHA256:{fingerprint}...",
        "authenticated_encryption": True,
        "tamper_evident": True,
    }


def benchmark_crypto(payload_size_kb: int = 100) -> dict:
    """Live benchmark of envelope encryption & decryption performance."""
    size_bytes = max(1, payload_size_kb) * 1024
    sample_data = os.urandom(size_bytes)

    # 1. Benchmark Encryption
    t0 = time.perf_counter()
    ciphertext, wrapped_dek = encrypt(sample_data)
    enc_duration = time.perf_counter() - t0

    # 2. Benchmark Decryption
    t1 = time.perf_counter()
    decrypted = decrypt(ciphertext, wrapped_dek)
    dec_duration = time.perf_counter() - t1

    # 3. Verification & Tamper Resistance Check
    assert decrypted == sample_data, "Decrypted payload does not match original"

    tampered_ct = bytearray(ciphertext)
    tampered_ct[-1] ^= 0xFF
    tamper_blocked = False
    try:
        decrypt(bytes(tampered_ct), wrapped_dek)
    except Exception:
        tamper_blocked = True

    enc_speed_mb = (size_bytes / (1024 * 1024)) / (enc_duration or 1e-6)
    dec_speed_mb = (size_bytes / (1024 * 1024)) / (dec_duration or 1e-6)

    return {
        "payload_size_kb": payload_size_kb,
        "encryption_ms": round(enc_duration * 1000, 3),
        "decryption_ms": round(dec_duration * 1000, 3),
        "encryption_mb_s": round(enc_speed_mb, 2),
        "decryption_mb_s": round(dec_speed_mb, 2),
        "tamper_detected_and_blocked": tamper_blocked,
        "integrity_verified": True,
    }
