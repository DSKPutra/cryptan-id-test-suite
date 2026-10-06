"""Sumber barisan bit untuk Lab Keacakan: teks tempel, berkas (ASCII/biner), os.urandom, PRNG ber-seed,
generator bias P(1) = p, LFSR, dan pola berulang. Seed selalu dicatat agar dapat diulang."""
import os
import random

import numpy as np

from .lfsr import lfsr


def from_text(text: str) -> np.ndarray:
    return np.asarray([int(c) for c in text if c in "01"], dtype=np.int64)


def from_bytes(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8)).astype(np.int64)


def from_file(path_or_bytes, fmt="auto") -> np.ndarray:
    """fmt: 'ascii' (karakter 0/1), 'biner' (byte mentah), atau 'auto' (ASCII bila isinya hanya 0/1/spasi)."""
    data = path_or_bytes if isinstance(path_or_bytes, (bytes, bytearray)) else open(path_or_bytes, "rb").read()
    if fmt == "auto":
        fmt = "ascii" if set(data) <= set(b"01 \r\n\t") else "biner"
    return from_text(data.decode("ascii")) if fmt == "ascii" else from_bytes(bytes(data))


def urandom(n: int) -> np.ndarray:
    return from_bytes(os.urandom((n + 7) // 8))[:n]


def prng(n: int, seed: int) -> np.ndarray:
    """PRNG NumPy PCG64 ber-seed (bukan CSPRNG — hanya untuk studi kasus)."""
    return np.random.default_rng(seed).integers(0, 2, n, dtype=np.int64)


def python_randint(n: int, seed: int) -> np.ndarray:
    """random.Random(seed).randint(0, 1) — mereproduksi barisan 100 bit materi (seed 13)."""
    r = random.Random(seed)
    return np.asarray([r.randint(0, 1) for _ in range(n)], dtype=np.int64)


def biased(n: int, p: float, seed: int) -> np.ndarray:
    return (np.random.default_rng(seed).random(n) < p).astype(np.int64)


def lfsr_bits(n: int, taps, state: str, shift="right") -> np.ndarray:
    return np.asarray(lfsr(taps, state, n, shift), dtype=np.int64)


def pattern(n: int, pat: str = "1100") -> np.ndarray:
    return from_text((pat * (n // len(pat) + 1))[:n])


SOURCES = {"urandom": "os.urandom (CSPRNG OS)", "prng": "PRNG ber-seed (NumPy PCG64)", "python": "random.Random(seed).randint",
           "bias": "generator bias P(1) = p", "lfsr": "LFSR (tap & keadaan awal)", "pola": "pola berulang"}


def generate(kind: str, n: int, **kw) -> np.ndarray:
    if kind == "urandom":
        return urandom(n)
    if kind == "prng":
        return prng(n, kw.get("seed", 2026))
    if kind == "python":
        return python_randint(n, kw.get("seed", 13))
    if kind == "bias":
        return biased(n, kw.get("p", 0.51), kw.get("seed", 2026))
    if kind == "lfsr":
        return lfsr_bits(n, kw.get("taps", (3, 5)), kw.get("state", "01100"), kw.get("shift", "right"))
    if kind == "pola":
        return pattern(n, kw.get("pat", "1100"))
    raise ValueError(kind)
