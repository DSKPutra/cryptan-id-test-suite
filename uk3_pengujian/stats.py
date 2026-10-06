"""Fungsi statistik dasar UK-3 (KUK 3.1). Rumus mengikuti materi UK-3 dan NIST SP 800-22 Rev.1a.

Catatan pengajar: jangan menjumlah bit bertipe uint8 (overflow) — semua penjumlahan di sini memakai int Python / int64.
"""
import math
from typing import Sequence

import numpy as np
from scipy import special, stats as sst


def erfc(x: float) -> float:
    return float(special.erfc(x))


def igamc(a: float, x: float) -> float:
    """Fungsi gamma tak lengkap atas teregularisasi Q(a, x) (igamc NIST)."""
    return float(special.gammaincc(a, x))


def chi2_critical(df: int, alpha: float = 0.01) -> float:
    return float(sst.chi2.ppf(1 - alpha, df))


def chi2_p(x: float, df: int) -> float:
    return float(sst.chi2.sf(x, df))


def norm_critical(alpha: float = 0.01) -> float:
    return float(sst.norm.ppf(1 - alpha / 2))


def norm_p_two_sided(z: float) -> float:
    return float(2 * sst.norm.sf(abs(z)))


# ------------------------------------------------------------------- proporsi & keseragaman (SP 800-22 §4.2)
def proportion_interval(m: int, alpha: float = 0.01) -> dict:
    """Rentang proporsi lulus p0 ± 3√(p0(1−p0)/m), p0 = 1 − α (KUK 3.1)."""
    p0 = 1 - alpha
    w = 3 * math.sqrt(p0 * (1 - p0) / m)
    return {"m": m, "p0": p0, "half_width": w, "low": p0 - w, "high": min(1.0, p0 + w)}


def proportion_decision(passed: int, m: int, alpha: float = 0.01) -> dict:
    iv = proportion_interval(m, alpha)
    prop = passed / m
    return {**iv, "passed": passed, "proportion": prop, "ok": prop >= iv["low"] - 1e-12}


def uniformity(pvalues=None, counts: Sequence[int] = None) -> dict:
    """χ² keseragaman p-value pada 10 interval; P-value_T = igamc(9/2, χ²/2); seragam bila ≥ 0,0001."""
    if counts is None:
        counts = np.histogram(np.asarray(pvalues, dtype=float), bins=10, range=(0, 1))[0].tolist()
    counts = [int(c) for c in counts]
    s = sum(counts)
    e = s / 10
    chi2 = sum((c - e) ** 2 / e for c in counts)
    pt = igamc(4.5, chi2 / 2)
    return {"counts": counts, "m": s, "chi2": chi2, "p_value_T": pt, "ok": pt >= 0.0001}


# ------------------------------------------------------------------- timing (TVLA) & kinerja
def welch_t(a=None, b=None, *, mean1=None, sd1=None, n1=None, mean2=None, sd2=None, n2=None) -> dict:
    """t = (μ1 − μ2)/√(s1²/n1 + s2²/n2); ambang TVLA |t| > 4,5 → indikasi kebocoran (KUK 3.1)."""
    if a is not None:
        a, b = np.asarray(a, float), np.asarray(b, float)
        mean1, sd1, n1 = a.mean(), a.std(ddof=1), a.size
        mean2, sd2, n2 = b.mean(), b.std(ddof=1), b.size
    v1, v2 = sd1 ** 2 / n1, sd2 ** 2 / n2
    t = (mean2 - mean1) / math.sqrt(v1 + v2) if (v1 + v2) > 0 else 0.0
    return {"t": float(t), "abs_t": abs(float(t)), "leak": abs(t) > 4.5, "mean1": float(mean1), "mean2": float(mean2),
            "var_n1": float(v1), "var_n2": float(v2), "n1": int(n1), "n2": int(n2), "threshold": 4.5}


def confidence_interval(data: Sequence[float], level: float = 0.95, warmup: int = 0) -> dict:
    """Rata-rata ± t(0,975; n−1)·s/√n setelah membuang putaran pemanasan; juga p95 (KUK 3.1)."""
    x = np.asarray(list(data)[warmup:], float)
    n = x.size
    mean, sd = float(x.mean()), float(x.std(ddof=1)) if n > 1 else 0.0
    tq = float(sst.t.ppf(1 - (1 - level) / 2, n - 1)) if n > 1 else float("nan")
    half = tq * sd / math.sqrt(n) if n > 1 else float("nan")
    return {"n": n, "warmup_dibuang": warmup, "mean": mean, "sd": sd, "t_quantile": tq, "half_width": half,
            "low": mean - half, "high": mean + half, "p95": float(np.percentile(x, 95)), "min": float(x.min()), "max": float(x.max())}


# ------------------------------------------------------------------- avalanche & entropi
def avalanche_z(mean_hd: float, n_bits: int, N: int) -> dict:
    """z = (rerata − n/2)/(√n/2/√N); |z| ≤ 3 → konsisten dengan perilaku ideal."""
    se = math.sqrt(n_bits) / 2 / math.sqrt(N)
    z = (mean_hd - n_bits / 2) / se
    return {"mean_hd": mean_hd, "expected": n_bits / 2, "sd_expected": math.sqrt(n_bits) / 2, "N": N, "z": z, "ok": abs(z) <= 3}


def min_entropy(p_max: float) -> float:
    """H_min = −log2(p_maks)."""
    return -math.log2(p_max)


def shannon_entropy(probs: Sequence[float]) -> float:
    return -sum(p * math.log2(p) for p in probs if p > 0)


def raw_bits_needed(target_bits: int, h_min_per_bit: float) -> int:
    """Bit mentah yang diperlukan untuk target entropi (mis. 256 / 0,737 ≈ 348)."""
    return math.ceil(target_bits / h_min_per_bit)


def min_entropy_mcv(bits) -> dict:
    """Estimasi min-entropi most-common-value sederhana per bit (SP 800-90B §6.3.1, batas atas 99%)."""
    b = np.asarray(bits, dtype=np.int64)
    n = b.size
    p_hat = max(int(b.sum()), n - int(b.sum())) / n
    p_u = min(1.0, p_hat + 2.576 * math.sqrt(p_hat * (1 - p_hat) / (n - 1)))
    return {"n": n, "p_hat": p_hat, "p_upper": p_u, "h_min": -math.log2(p_u)}
