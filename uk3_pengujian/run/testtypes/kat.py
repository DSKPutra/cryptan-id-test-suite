"""KAT — keluaran dibandingkan byte demi byte dengan vektor resmi (expected dari skenario, bukan dari produk)."""
import hashlib
import hmac

from ...analysis import methods as A
from . import executor


def _res(actual_hex, tc):
    an = A.kat(actual_hex, tc["expected"]["nilai"])
    return {"actual": actual_hex, "passed": an["identik"], "metode": "KAT", "analisis": an,
            "data": {"actual": actual_hex, "expected": tc["expected"]["nilai"], "sumber": tc["expected"].get("sumber")}}


@executor("kat_pbkdf2")
def kat_pbkdf2(ctx, tc):
    # primitif KDF yang dipakai SecureFile (hashlib.pbkdf2_hmac)
    return _res(hashlib.pbkdf2_hmac("sha256", b"passwd", b"salt", 1, 64).hex(), tc)


@executor("kat_gcm13")
def kat_gcm13(ctx, tc):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return _res(AESGCM(bytes(32)).encrypt(bytes(12), b"", None).hex(), tc)


@executor("kat_aes")
def kat_aes(ctx, tc):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    e = Cipher(algorithms.AES(bytes.fromhex(tc["parameter"]["kunci"])), modes.ECB()).encryptor()
    return _res((e.update(bytes.fromhex("00112233445566778899aabbccddeeff")) + e.finalize()).hex(), tc)


@executor("kat_chacha20")
def kat_chacha20(ctx, tc):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    nonce = bytes.fromhex("000000090000004a00000000")
    ks = Cipher(algorithms.ChaCha20(bytes(range(32)), (1).to_bytes(4, "little") + nonce), None).encryptor().update(bytes(64))
    return _res(ks.hex(), tc)


@executor("kat_sha256")
def kat_sha256(ctx, tc):
    from cryptography.hazmat.primitives import hashes
    h = hashes.Hash(hashes.SHA256())
    h.update(b"abc")
    return _res(h.finalize().hex(), tc)


@executor("kat_hmac")
def kat_hmac(ctx, tc):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives import hmac as chmac
    h = chmac.HMAC(b"\x0b" * 20, hashes.SHA256())
    h.update(b"Hi There")
    return _res(h.finalize().hex(), tc)
