"""Utilitas statistik (pra-uji keacakan SP 800-22, χ², Welch t-test / TVLA)."""
import math
from typing import Sequence


def igamc(a: float, x: float) -> float:
    """Fungsi gamma tak lengkap atas teregularisasi Q(a, x) (dipakai SP 800-22)."""
    if x <= 0:
        return 1.0
    if x < a + 1:   # deret untuk P lalu Q = 1 - P
        term = s = 1.0 / a
        n = a
        while True:
            n += 1
            term *= x / n
            s += term
            if abs(term) < abs(s) * 1e-15:
                break
        return max(0.0, 1.0 - s * math.exp(-x + a * math.log(x) - math.lgamma(a)))
    # pecahan berlanjut (Lentz)
    b = x + 1 - a
    c = 1 / 1e-300
    d = 1 / b
    h = d
    i = 1
    while True:
        an = -i * (i - a)
        b += 2
        d = an * d + b
        d = 1e-300 if abs(d) < 1e-300 else d
        c = b + an / c
        c = 1e-300 if abs(c) < 1e-300 else c
        d = 1 / d
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-15:
            break
        i += 1
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def monobit_test(bits: Sequence[int]) -> dict:
    """SP 800-22 §2.1 Frequency (Monobit)."""
    n = len(bits)
    s = sum(1 if b else -1 for b in bits)
    p = math.erfc(abs(s) / math.sqrt(2 * n))
    return {"test": "Frequency (Monobit)", "n": n, "p_value": p, "pass": p >= 0.01}


def runs_test(bits: Sequence[int]) -> dict:
    """SP 800-22 §2.3 Runs."""
    n = len(bits)
    pi = sum(bits) / n
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return {"test": "Runs", "n": n, "p_value": 0.0, "pass": False}
    v = 1 + sum(bits[i] != bits[i + 1] for i in range(n - 1))
    p = math.erfc(abs(v - 2 * n * pi * (1 - pi)) / (2 * math.sqrt(2 * n) * pi * (1 - pi)))
    return {"test": "Runs", "n": n, "p_value": p, "pass": p >= 0.01}


def chi_square_uniform(counts: Sequence[int]) -> dict:
    total = sum(counts)
    k = len(counts)
    exp = total / k
    chi2 = sum((c - exp) ** 2 / exp for c in counts)
    return {"chi2": chi2, "df": k - 1, "p_value": igamc((k - 1) / 2, chi2 / 2)}


def welch_t(a: Sequence[float], b: Sequence[float]) -> float:
    """Statistik t Welch (dipakai TVLA / dudect; ambang |t| > 4,5)."""
    na, nb = len(a), len(b)
    ma, mb = sum(a) / na, sum(b) / nb
    va = sum((x - ma) ** 2 for x in a) / (na - 1)
    vb = sum((x - mb) ** 2 for x in b) / (nb - 1)
    den = math.sqrt(va / na + vb / nb)
    return 0.0 if den == 0 else (ma - mb) / den


def sp80022_proportion_threshold(m: int, alpha: float = 0.01) -> float:
    """Ambang proporsi lulus SP 800-22 §4.2.1: p̂ − 3√(p̂(1−p̂)/m)."""
    p = 1 - alpha
    return p - 3 * math.sqrt(p * (1 - p) / m)
