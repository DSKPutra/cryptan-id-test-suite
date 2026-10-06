"""Five basic tests (Menezes, van Oorschot & Vanstone, HAC §5.4.4) pada α = 0,01 — Lab Keacakan (KUK 3.1).

Catatan tetap: five basic tests hanya untuk studi kasus; hasil resmi memakai NIST STS lengkap.
"""
import math

import numpy as np

from ..stats import chi2_critical, chi2_p, norm_critical, norm_p_two_sided
from .sp80022 import to_bits

ALPHA = 0.01
NOTE = "Five basic tests hanya untuk studi kasus; hasil resmi memakai NIST STS lengkap."


def _decision(stat, crit, two_sided=False):
    reject = abs(stat) > crit if two_sided else stat > crit
    return "Tolak H₀" if reject else "Terima H₀"


def frequency(bits):
    e = to_bits(bits)
    n = e.size
    n1 = int(e.sum())
    n0 = n - n1
    x1 = (n0 - n1) ** 2 / n
    crit = chi2_critical(1, ALPHA)
    return {"test": "frekuensi", "statistic_name": "X₁", "statistic": x1, "df": 1, "critical": crit, "p_value": chi2_p(x1, 1),
            "decision": _decision(x1, crit), "n0": n0, "n1": n1, "formula": "X₁ = (n₀ − n₁)²/n"}


def serial(bits):
    e = to_bits(bits)
    n = e.size
    n1 = int(e.sum())
    n0 = n - n1
    pairs = e[:-1] * 2 + e[1:]
    c = np.bincount(pairs, minlength=4).astype(np.int64)
    x2 = 4 / (n - 1) * int((c ** 2).sum()) - 2 / n * (n0 ** 2 + n1 ** 2) + 1
    crit = chi2_critical(2, ALPHA)
    return {"test": "serial", "statistic_name": "X₂", "statistic": x2, "df": 2, "critical": crit, "p_value": chi2_p(x2, 2),
            "decision": _decision(x2, crit), "n00": int(c[0]), "n01": int(c[1]), "n10": int(c[2]), "n11": int(c[3]),
            "formula": "X₂ = 4/(n−1)·Σnᵢⱼ² − 2/n·(n₀² + n₁²) + 1"}


def choose_poker_m(n):
    """m terbesar dengan ⌊n/m⌋ ≥ 5·2ᵐ."""
    m = 1
    while n // (m + 1) >= 5 * 2 ** (m + 1):
        m += 1
    return m


def poker(bits, m=None):
    e = to_bits(bits)
    n = e.size
    m = m or choose_poker_m(n)
    k = n // m
    if k < 5 * 2 ** m:
        return {"test": "poker", "statistic_name": "X₃", "m": m, "k": k, "statistic": None, "decision": "tidak dapat dijalankan",
                "reason": f"⌊n/m⌋ = {k} < 5·2^{m} = {5 * 2 ** m}"}
    blocks = e[:k * m].reshape(k, m)
    idx = (blocks * (1 << np.arange(m - 1, -1, -1))).sum(axis=1)
    c = np.bincount(idx, minlength=2 ** m).astype(np.int64)
    x3 = (2 ** m / k) * int((c ** 2).sum()) - k
    df = 2 ** m - 1
    crit = chi2_critical(df, ALPHA)
    return {"test": "poker", "statistic_name": "X₃", "statistic": x3, "df": df, "critical": crit, "p_value": chi2_p(x3, df),
            "decision": _decision(x3, crit), "m": m, "k": k, "counts": {format(i, f"0{m}b"): int(v) for i, v in enumerate(c)},
            "formula": "X₃ = (2ᵐ/k)·Σnᵢ² − k"}


def _runs_linear(e):
    B, G = {}, {}
    i, n = 0, e.size
    while i < n:
        j = i
        while j < n and e[j] == e[i]:
            j += 1
        L = j - i
        (B if e[i] == 1 else G)[L] = (B if e[i] == 1 else G).get(L, 0) + 1
        i = j
    return B, G


def runs(bits):
    e = to_bits(bits)
    n = e.size
    B, G = _runs_linear(e)
    k = 0
    while (n - (k + 1) + 3) / 2 ** (k + 3) >= 5:
        k += 1
    rows, x4 = [], 0.0
    for i in range(1, k + 1):
        ei = (n - i + 3) / 2 ** (i + 2)
        b, g = B.get(i, 0), G.get(i, 0)
        x4 += (b - ei) ** 2 / ei + (g - ei) ** 2 / ei
        rows.append({"i": i, "B": b, "G": g, "e": ei})
    df = 2 * k - 2
    if k < 2:
        return {"test": "runs", "statistic_name": "X₄", "k": k, "statistic": None, "decision": "tidak dapat dijalankan",
                "reason": "k < 2 (n terlalu kecil)"}
    crit = chi2_critical(df, ALPHA)
    return {"test": "runs", "statistic_name": "X₄", "statistic": x4, "df": df, "critical": crit, "p_value": chi2_p(x4, df),
            "decision": _decision(x4, crit), "k": k, "table": rows, "formula": "X₄ = Σ(Bᵢ − eᵢ)²/eᵢ + Σ(Gᵢ − eᵢ)²/eᵢ, eᵢ = (n − i + 3)/2^(i+2)"}


def autocorrelation(bits, d=8):
    e = to_bits(bits)
    n = e.size
    if not 1 <= d <= n // 2:
        return {"test": "autokorelasi", "statistic_name": "X₅", "d": d, "statistic": None, "decision": "tidak dapat dijalankan",
                "reason": "1 ≤ d ≤ ⌊n/2⌋"}
    A = int((e[:n - d] ^ e[d:]).sum())
    x5 = 2 * (A - (n - d) / 2) / math.sqrt(n - d)
    crit = norm_critical(ALPHA)
    return {"test": "autokorelasi", "statistic_name": "X₅", "statistic": x5, "critical": crit, "p_value": norm_p_two_sided(x5),
            "decision": _decision(x5, crit, two_sided=True), "d": d, "A": A, "formula": "X₅ = 2(A(d) − (n−d)/2)/√(n−d)"}


def run_all(bits, poker_m=None, d=8) -> dict:
    res = [frequency(bits), serial(bits), poker(bits, poker_m), runs(bits), autocorrelation(bits, d)]
    rejected = [r["test"] for r in res if r["decision"] == "Tolak H₀"]
    return {"alpha": ALPHA, "tests": res, "rejected": rejected,
            "summary": "Tidak ada bukti statistik untuk menolak keacakan barisan." if not rejected
            else f"H₀ ditolak oleh uji: {', '.join(rejected)}.", "note": NOTE}
