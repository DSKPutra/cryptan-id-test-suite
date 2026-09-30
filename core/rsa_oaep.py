"""RSA-OAEP (RFC 8017 / PKCS#1 v2.2, SP 800-56B, ISO/IEC 18033-2 RSAES) —
implementasi referensi pure Python.

- `seed` dapat disuntikkan agar enkripsi deterministik untuk Known Answer Test.
- Fungsi hash & MGF1 dapat diparameterkan (SHA-1 untuk vektor PKCS#1 resmi,
  SHA-256 sebagai konfigurasi produk).
"""
import hashlib
import math
import secrets
from dataclasses import dataclass

from .numtheory import bytes_to_int, gen_prime, int_to_bytes, lcm, modinv


class DecryptionError(Exception):
    """Satu jenis galat untuk SEMUA kegagalan dekripsi (mitigasi Manger 2001)."""


@dataclass
class PublicKey:
    n: int
    e: int

    @property
    def k(self) -> int:
        return (self.n.bit_length() + 7) // 8


@dataclass
class PrivateKey:
    n: int
    e: int
    d: int
    p: int = 0
    q: int = 0

    @property
    def k(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def public(self) -> PublicKey:
        return PublicKey(self.n, self.e)


def generate_keypair(bits: int = 2048, e: int = 65537, rng=None) -> PrivateKey:
    """Pembangkitan kunci ala FIPS 186-5 A.1.3 (prima probabilistik) dengan
    pemeriksaan |p-q| > 2^(nlen/2-100) dan d > 2^(nlen/2)."""
    half = bits // 2
    while True:
        p = gen_prime(half, e, rng)
        q = gen_prime(bits - half, e, rng)
        if abs(p - q) <= (1 << (half - 100)):
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        d = modinv(e, lcm(p - 1, q - 1))
        if d <= (1 << half):
            continue
        return PrivateKey(n, e, d, p, q)


def rsaep(pub: PublicKey, m: int) -> int:
    if not 0 <= m < pub.n:
        raise ValueError("message representative out of range")
    return pow(m, pub.e, pub.n)


def rsadp(priv: PrivateKey, c: int) -> int:
    if not 0 <= c < priv.n:
        raise ValueError("ciphertext representative out of range")
    return pow(c, priv.d, priv.n)


def mgf1(seed: bytes, length: int, hash_name: str = "sha256") -> bytes:
    out = bytearray()
    for counter in range(math.ceil(length / hashlib.new(hash_name).digest_size)):
        out += hashlib.new(hash_name, seed + counter.to_bytes(4, "big")).digest()
    return bytes(out[:length])


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt(pub: PublicKey, msg: bytes, label: bytes = b"", hash_name: str = "sha256",
            seed: bytes = None) -> bytes:
    """RSAES-OAEP-ENCRYPT (RFC 8017 §7.1.1)."""
    k = pub.k
    h_len = hashlib.new(hash_name).digest_size
    if len(msg) > k - 2 * h_len - 2:
        raise ValueError("message too long")
    l_hash = hashlib.new(hash_name, label).digest()
    ps = b"\x00" * (k - len(msg) - 2 * h_len - 2)
    db = l_hash + ps + b"\x01" + msg
    seed = seed if seed is not None else secrets.token_bytes(h_len)
    masked_db = _xor(db, mgf1(seed, k - h_len - 1, hash_name))
    masked_seed = _xor(seed, mgf1(masked_db, h_len, hash_name))
    em = b"\x00" + masked_seed + masked_db
    return int_to_bytes(rsaep(pub, bytes_to_int(em)), k)


def decrypt(priv: PrivateKey, ct: bytes, label: bytes = b"", hash_name: str = "sha256") -> bytes:
    """RSAES-OAEP-DECRYPT (RFC 8017 §7.1.2). Semua kegagalan menghasilkan
    DecryptionError yang identik (tidak membocorkan penyebab)."""
    k = priv.k
    h_len = hashlib.new(hash_name).digest_size
    if len(ct) != k or k < 2 * h_len + 2:
        raise DecryptionError("decryption error")
    c = bytes_to_int(ct)
    if c >= priv.n:
        raise DecryptionError("decryption error")
    em = int_to_bytes(rsadp(priv, c), k)
    l_hash = hashlib.new(hash_name, label).digest()
    y, masked_seed, masked_db = em[0], em[1:1 + h_len], em[1 + h_len:]
    seed = _xor(masked_seed, mgf1(masked_db, h_len, hash_name))
    db = _xor(masked_db, mgf1(seed, k - h_len - 1, hash_name))
    l_hash2, rest = db[:h_len], db[h_len:]
    # Evaluasi semua kondisi sebelum memutuskan (mengurangi kebocoran cabang).
    idx = rest.find(b"\x01")
    ps_ok = idx >= 0 and all(b == 0 for b in rest[:idx])
    bad = (y != 0) | (l_hash2 != l_hash) | (not ps_ok)
    if bad:
        raise DecryptionError("decryption error")
    return rest[idx + 1:]


def validate_public_key(pub: PublicKey, min_bits: int = 2048) -> dict:
    """Validasi parsial kunci publik RSA (SP 800-56B §6.4.2.2, FIPS 186-5 A.1.1)."""
    from .numtheory import miller_rabin, SMALL_PRIMES
    checks = {
        "modulus_bits": pub.n.bit_length(),
        "modulus_ge_min": pub.n.bit_length() >= min_bits,
        "modulus_odd": pub.n % 2 == 1,
        "modulus_composite": not miller_rabin(pub.n, rounds=10),
        "no_small_factor": all(pub.n % p for p in SMALL_PRIMES),
        "e_odd": pub.e % 2 == 1,
        "e_range_fips186_5": (1 << 16) < pub.e < (1 << 256),
    }
    checks["valid"] = all(v for k, v in checks.items() if k != "modulus_bits")
    return checks
