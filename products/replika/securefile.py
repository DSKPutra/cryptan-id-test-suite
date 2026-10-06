# REPLIKA SecureFile v1.0 (produk latihan UK-3) — dibuat dari spesifikasi prompt UK-3, BUKAN berkas asli materi.
# Hash berbeda dari slide. Format: MAGIC "SF01" (4) | salt (16) | nonce (12) | ciphertext + tag.
# PBKDF2-HMAC-SHA256 600.000 iterasi, salt acak 16 byte, AES-256-GCM, nonce acak 12 byte, AAD = MAGIC.
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC, ITER = b"SF01", 600_000


def _key(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, ITER, 32)


def encrypt(password: bytes, data: bytes) -> bytes:
    salt, nonce = os.urandom(16), os.urandom(12)
    return MAGIC + salt + nonce + AESGCM(_key(password, salt)).encrypt(nonce, data, MAGIC)


def decrypt(password: bytes, blob: bytes) -> bytes:
    if blob[:4] != MAGIC or len(blob) < 4 + 16 + 12 + 16:
        raise ValueError("format tidak valid")
    salt, nonce, ct = blob[4:20], blob[20:32], blob[32:]
    return AESGCM(_key(password, salt)).decrypt(nonce, ct, MAGIC)
