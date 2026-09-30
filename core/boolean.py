"""Analisis fungsi Boolean, S-box, lapisan difusi, dan barisan — dipakai
KUK 2.1 (telaah komponen berpotensi lemah). Semua nilai di sini adalah
HASIL UJI LANGSUNG (dihitung oleh kode).
"""
import itertools
import random
from typing import Callable, List, Sequence

from .aes import gf_inv, gf_mul


# ---------------------------------------------------------------- Walsh / ANF
def walsh_hadamard(f: Sequence[int]) -> List[int]:
    """Transformasi Walsh–Hadamard dari f: {0,1}^n → {0,1} (tabel kebenaran)."""
    w = [1 - 2 * b for b in f]
    h = 1
    while h < len(w):
        for i in range(0, len(w), 2 * h):
            for j in range(i, i + h):
                a, b = w[j], w[j + h]
                w[j], w[j + h] = a + b, a - b
        h *= 2
    return w


def anf(f: Sequence[int]) -> List[int]:
    """Algebraic Normal Form melalui transformasi Möbius."""
    a = list(f)
    h = 1
    while h < len(a):
        for i in range(0, len(a), 2 * h):
            for j in range(i, i + h):
                a[j + h] ^= a[j]
        h *= 2
    return a


def bool_degree(f: Sequence[int]) -> int:
    return max((bin(m).count("1") for m, c in enumerate(anf(f)) if c), default=0)


def bool_nonlinearity(f: Sequence[int]) -> int:
    return len(f) // 2 - max(abs(x) for x in walsh_hadamard(f)) // 2


def correlation_immunity(f: Sequence[int], n: int) -> int:
    """Orde imunitas korelasi terbesar t (W(w)=0 untuk 1 ≤ wt(w) ≤ t)."""
    W = walsh_hadamard(f)
    t = 0
    for order in range(1, n + 1):
        if all(W[w] == 0 for w in range(1, 1 << n) if bin(w).count("1") == order):
            t = order
        else:
            break
    return t


def boolean_profile(f: Sequence[int], n: int) -> dict:
    return {
        "n": n,
        "balanced": sum(f) == len(f) // 2,
        "nonlinearity": bool_nonlinearity(f),
        "algebraic_degree": bool_degree(f),
        "correlation_immunity": correlation_immunity(f, n),
    }


# ---------------------------------------------------------------- S-box
def _component(S, b, n):
    return [bin(S[x] & b).count("1") & 1 for x in range(1 << n)]


def sbox_nonlinearity(S: Sequence[int], n: int, m: int) -> int:
    return min(bool_nonlinearity(_component(S, b, n)) for b in range(1, 1 << m))


def ddt(S: Sequence[int], n: int, m: int) -> List[List[int]]:
    T = [[0] * (1 << m) for _ in range(1 << n)]
    for a in range(1 << n):
        for x in range(1 << n):
            T[a][S[x] ^ S[x ^ a]] += 1
    return T


def differential_uniformity(S, n, m) -> int:
    T = ddt(S, n, m)
    return max(max(row) for row in T[1:])


def lat_max_bias(S, n, m) -> dict:
    """Nilai |LAT| maksimum (LAT[a][b] = #{a·x = b·S(x)} − 2^(n−1)) dan korelasi."""
    mx = 0
    for b in range(1, 1 << m):
        W = walsh_hadamard(_component(S, b, n))
        mx = max(mx, max(abs(v) for v in W) // 2)
    return {"max_abs_lat": mx, "max_bias": mx / (1 << n), "max_correlation": 2 * mx / (1 << n)}


def sbox_degree(S, n, m) -> dict:
    coords = [bool_degree(_component(S, 1 << j, n)) for j in range(m)]
    comps = [bool_degree(_component(S, b, n)) for b in range(1, 1 << m)]
    return {"max_coordinate_degree": max(coords), "min_component_degree": min(comps)}


def sac_matrix(S, n, m) -> dict:
    """Strict Avalanche Criterion: P[bit j keluaran berubah | bit i masukan dibalik]."""
    mat = []
    for i in range(n):
        row = []
        for j in range(m):
            cnt = sum(((S[x] ^ S[x ^ (1 << i)]) >> j) & 1 for x in range(1 << n))
            row.append(cnt / (1 << n))
        mat.append(row)
    flat = [v for r in mat for v in r]
    return {"min": min(flat), "max": max(flat), "mean": sum(flat) / len(flat),
            "max_deviation": max(abs(v - 0.5) for v in flat)}


def fixed_points(S) -> dict:
    mask = max(S)
    mask = (1 << mask.bit_length()) - 1
    return {"fixed_points": sum(1 for x, y in enumerate(S) if x == y),
            "opposite_fixed_points": sum(1 for x, y in enumerate(S) if y == x ^ mask)}


def is_permutation(S) -> bool:
    return sorted(S) == list(range(len(S)))


def sbox_profile(S, n, m) -> dict:
    return {
        "n_in": n, "m_out": m,
        "bijective": is_permutation(S) if n == m else False,
        "nonlinearity": sbox_nonlinearity(S, n, m),
        "differential_uniformity": differential_uniformity(S, n, m),
        **lat_max_bias(S, n, m),
        **sbox_degree(S, n, m),
        "sac": sac_matrix(S, n, m),
        **fixed_points(S),
    }


# ---------------------------------------------------------------- Difusi (GF(2^8))
def _gf_det(M) -> int:
    M = [list(r) for r in M]
    n = len(M)
    det = 1
    for c in range(n):
        piv = next((r for r in range(c, n) if M[r][c]), None)
        if piv is None:
            return 0
        M[c], M[piv] = M[piv], M[c]
        det = gf_mul(det, M[c][c])
        inv = gf_inv(M[c][c])
        for r in range(c + 1, n):
            if M[r][c]:
                f = gf_mul(M[r][c], inv)
                M[r] = [a ^ gf_mul(f, b) for a, b in zip(M[r], M[c])]
    return det


def is_mds(M) -> bool:
    """MDS ⇔ setiap submatriks persegi non-singular di GF(2^8)."""
    n = len(M)
    for k in range(1, n + 1):
        for rows in itertools.combinations(range(n), k):
            for cols in itertools.combinations(range(n), k):
                if _gf_det([[M[r][c] for c in cols] for r in rows]) == 0:
                    return False
    return True


def _mat_vec(M, v):
    out = []
    for row in M:
        acc = 0
        for a, b in zip(row, v):
            acc ^= gf_mul(a, b)
        out.append(acc)
    return out


def branch_number(M, exhaustive_weight: int = 1) -> dict:
    """Branch number diferensial. MDS ⇒ B = n+1 (batas Singleton); pencarian
    empiris masukan berbobot ≤ exhaustive_weight sebagai pemeriksaan silang."""
    n = len(M)
    best = 2 * n
    for w in range(1, exhaustive_weight + 1):
        for pos in itertools.combinations(range(n), w):
            for vals in itertools.product(range(1, 256), repeat=w):
                v = [0] * n
                for p, x in zip(pos, vals):
                    v[p] = x
                out = _mat_vec(M, v)
                best = min(best, w + sum(1 for x in out if x))
    mds = is_mds(M)
    return {"mds": mds, "branch_number": n + 1 if mds else best,
            "empirical_upper_bound": best, "optimal": n + 1}


# ---------------------------------------------------------------- Barisan
def berlekamp_massey(bits: Sequence[int]) -> int:
    """Kompleksitas linear barisan biner (algoritma Berlekamp–Massey)."""
    n = len(bits)
    c, b = [0] * n, [0] * n
    c[0] = b[0] = 1
    L, m = 0, -1
    for N in range(n):
        d = bits[N]
        for i in range(1, L + 1):
            d ^= c[i] & bits[N - i]
        if d:
            t = c[:]
            for i in range(N - m, n):
                c[i] ^= b[i - (N - m)]
            if 2 * L <= N:
                L, m, b = N + 1 - L, N, t
    return L


def bytes_to_bits(data: bytes) -> List[int]:
    return [(byte >> (7 - i)) & 1 for byte in data for i in range(8)]


def avalanche(fn: Callable[[bytes], bytes], in_len: int, samples: int = 1000, seed: int = 1) -> dict:
    """Uji avalanche empiris: balik 1 bit acak masukan, ukur fraksi bit keluaran berubah."""
    rng = random.Random(seed)
    total, mn, mx, out_bits = 0.0, 1.0, 0.0, None
    for _ in range(samples):
        x = bytes(rng.getrandbits(8) for _ in range(in_len))
        bit = rng.randrange(in_len * 8)
        y = bytearray(x)
        y[bit // 8] ^= 1 << (bit % 8)
        a, b = fn(x), fn(bytes(y))
        out_bits = len(a) * 8
        frac = sum(bin(p ^ q).count("1") for p, q in zip(a, b)) / out_bits
        total += frac
        mn, mx = min(mn, frac), max(mx, frac)
    return {"samples": samples, "mean": total / samples, "min": mn, "max": mx,
            "output_bits": out_bits}
