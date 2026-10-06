"""LFSR Fibonacci dan Berlekamp–Massey (kompleksitas linear) — Lab Keacakan.

m-sequence lolos postulat Golomb, tetapi seluruh keadaannya dapat dipulihkan dari 2L bit keluaran:
lolos uji keacakan adalah syarat perlu, bukan syarat cukup."""
from typing import List, Sequence


def lfsr(taps: Sequence[int], state: str, nbits: int, shift: str = "right") -> List[int]:
    """LFSR Fibonacci.

    state: keadaan awal sebagai string bit, sel 1 di kiri (mis. "01100" untuk sel 1..5).
    taps : nomor sel (1-berbasis) yang di-XOR menjadi bit umpan balik.
    shift='right': keluaran dari sel paling kanan, umpan balik masuk ke sel 1 (kiri).
    shift='left' : keluaran dari sel paling kiri, umpan balik masuk ke sel terakhir.
    """
    s = [int(c) for c in state]
    out = []
    for _ in range(nbits):
        fb = 0
        for t in taps:
            fb ^= s[t - 1]
        if shift == "right":
            out.append(s[-1])
            s = [fb] + s[:-1]
        else:
            out.append(s[0])
            s = s[1:] + [fb]
    return out


def recurrence(coeffs: Sequence[int], init: Sequence[int], nbits: int) -> List[int]:
    """s_{t+L} = Σ c_i s_{t+i} (mod 2), coeffs = (c_0 … c_{L−1}). Mis. x⁴ + x + 1 → s_{t+4} = s_{t+1} ⊕ s_t → (1,1,0,0)."""
    s = list(init)
    L = len(coeffs)
    while len(s) < nbits:
        t = len(s) - L
        s.append(sum(c * s[t + i] for i, c in enumerate(coeffs)) % 2)
    return s[:nbits]


def period(bits: Sequence[int]) -> int:
    n = len(bits)
    for p in range(1, n + 1):
        if all(bits[i] == bits[i % p] for i in range(n)):
            return p
    return n


def berlekamp_massey(bits: Sequence[int]) -> dict:
    """Kompleksitas linear L dan polinomial koneksi C(x) = 1 + c1 x + … + cL x^L (GF(2))."""
    s = list(map(int, bits))
    n = len(s)
    C, B = [1] + [0] * n, [1] + [0] * n
    L, m = 0, -1
    for N in range(n):
        d = s[N]
        for i in range(1, L + 1):
            d ^= C[i] & s[N - i]
        if d:
            T = C[:]
            shift = N - m
            for i in range(0, n + 1 - shift):
                C[i + shift] ^= B[i]
            if 2 * L <= N:
                L, m, B = N + 1 - L, N, T
    poly = C[:L + 1]

    def show(cs):
        return " + ".join(("1" if i == 0 else "x" if i == 1 else f"x^{i}") for i, c in enumerate(cs) if c)
    char = list(reversed(poly))                      # polinomial karakteristik = resiprokal C(x)
    return {"L": L, "connection": poly, "polynomial": show(poly), "characteristic": " + ".join(reversed(show(char).split(" + "))),
            "bits_needed": 2 * L}


def predict(bits: Sequence[int], nbits: int) -> List[int]:
    """Pulihkan LFSR hanya dari bit yang diberikan (cukup 2L bit) lalu prediksi nbits keluaran."""
    bm = berlekamp_massey(bits)
    c, L = bm["connection"], bm["L"]
    s = list(bits[:L])
    while len(s) < nbits:
        N = len(s)
        v = 0
        for i in range(1, L + 1):
            v ^= c[i] & s[N - i]
        s.append(v)
    return s[:nbits]
