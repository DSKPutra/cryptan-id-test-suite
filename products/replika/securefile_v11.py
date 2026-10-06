# REPLIKA SecureFile v1.1 (produk latihan UK-3, SENGAJA cacat) — dibuat dari spesifikasi prompt UK-3, BUKAN berkas asli.
# Sama dengan v1.0 kecuali: salt tetap "SF-SALT-00000000" dan nonce = SHA-256(password)[:12].
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC, ITER = b"SF01", 600_000


def _key(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, ITER, 32)


def encrypt(password: bytes, data: bytes) -> bytes:
    salt = b"SF-SALT-00000000"                         # v1.1: salt tetap
    nonce = hashlib.sha256(password).digest()[:12]     # v1.1: nonce dari password
    return MAGIC + salt + nonce + AESGCM(_key(password, salt)).encrypt(nonce, data, MAGIC)


def decrypt(password: bytes, blob: bytes) -> bytes:
    if blob[:4] != MAGIC or len(blob) < 4 + 16 + 12 + 16:
        raise ValueError("format tidak valid")
    salt, nonce, ct = blob[4:20], blob[20:32], blob[32:]
    return AESGCM(_key(password, salt)).decrypt(nonce, ct, MAGIC)
