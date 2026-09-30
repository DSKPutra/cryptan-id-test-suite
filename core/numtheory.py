"""Utilitas teori bilangan (ISO/IEC 18032, FIPS 186-5 Lampiran B/C)."""
import math
import secrets

SMALL_PRIMES = [p for p in range(3, 2000) if all(p % q for q in range(2, int(p ** 0.5) + 1))]


def miller_rabin(n: int, rounds: int = 44, rng=None) -> bool:
    """Uji primalitas probabilistik Miller–Rabin (ISO/IEC 18032, FIPS 186-5 B.3.1).
    Peluang galat ≤ 4^-rounds untuk bilangan komposit sembarang."""
    if n < 2:
        return False
    for p in [2] + SMALL_PRIMES[:50]:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    rand = rng or secrets.SystemRandom()
    for _ in range(rounds):
        a = rand.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


is_probable_prime = miller_rabin


def gen_prime(bits: int, e: int = 65537, rng=None) -> int:
    """Bangkitkan prima `bits`-bit dengan dua bit teratas 1 dan gcd(p-1, e)=1
    (mengikuti batasan FIPS 186-5 A.1.3: p ≥ √2·2^(bits-1))."""
    rand = rng or secrets.SystemRandom()
    lower = math.isqrt(2 << (2 * bits - 2)) + 1   # ⌈√2 · 2^(bits-1)⌉
    while True:
        p = rand.getrandbits(bits) | (1 << (bits - 1)) | 1
        if p < lower:
            continue
        if math.gcd(p - 1, e) != 1:
            continue
        if miller_rabin(p, rng=rand):
            return p


def lcm(a: int, b: int) -> int:
    return a // math.gcd(a, b) * b


def modinv(a: int, m: int) -> int:
    return pow(a, -1, m)


def int_to_bytes(x: int, length: int) -> bytes:
    """I2OSP (PKCS#1 / RFC 8017 §4.1)."""
    if x >= 256 ** length:
        raise ValueError("integer too large")
    return x.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    """OS2IP (RFC 8017 §4.2)."""
    return int.from_bytes(b, "big")
