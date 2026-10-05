"""Subset NIST SP 800-22 Rev.1a (vektorisasi numpy): Frequency (Monobit), Frequency within a Block,
Runs, Longest Run of Ones in a Block, Cumulative Sums (maju & mundur), Approximate Entropy.
Rumus mengikuti SP 800-22 §2.1–2.4, §2.12, §2.13. Fungsi gamma tak lengkap: core.stats.igamc."""
import math

import numpy as np

from core.stats import igamc

ALPHA = 0.01
TESTS = ["frequency", "block_frequency", "runs", "longest_run", "cusum_forward", "cusum_backward", "approximate_entropy"]


def bits_from_bytes(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8)).astype(np.int8)


def frequency(e):
    n = len(e)
    s = abs(int((2 * e.astype(np.int64) - 1).sum()))
    return math.erfc(s / math.sqrt(2 * n))


def block_frequency(e, M=128):
    n = len(e)
    N = n // M
    pi = e[:N * M].reshape(N, M).mean(axis=1)
    chi = 4 * M * float(((pi - 0.5) ** 2).sum())
    return igamc(N / 2, chi / 2)


def runs(e):
    n = len(e)
    pi = float(e.mean())
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return 0.0
    v = 1 + int((e[1:] != e[:-1]).sum())
    return math.erfc(abs(v - 2 * n * pi * (1 - pi)) / (2 * math.sqrt(2 * n) * pi * (1 - pi)))


_LR = {  # (M, K, v-kategori, pi) — SP 800-22 §2.4.4 / §3.4
    8: (3, [1, 2, 3, 4], [0.2148, 0.3672, 0.2305, 0.1875]),
    128: (5, [4, 5, 6, 7, 8, 9], [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]),
    10000: (6, [10, 11, 12, 13, 14, 15, 16], [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]),
}


def longest_run(e):
    n = len(e)
    M = 8 if n < 6272 else 128 if n < 750000 else 10000
    K, cats, pis = _LR[M]
    N = n // M
    blocks = e[:N * M].reshape(N, M)
    # panjang run 1 terpanjang per blok
    longest = np.zeros(N, dtype=np.int32)
    cur = np.zeros(N, dtype=np.int32)
    for j in range(M):
        col = blocks[:, j]
        cur = np.where(col == 1, cur + 1, 0)
        longest = np.maximum(longest, cur)
    v = np.zeros(K + 1)
    for L in longest:
        idx = 0 if L <= cats[0] else K if L >= cats[-1] else cats.index(int(L))
        v[idx] += 1
    chi = float(sum((v[i] - N * pis[i]) ** 2 / (N * pis[i]) for i in range(K + 1)))
    return igamc(K / 2, chi / 2)


def _cusum(e, forward=True):
    x = 2 * e.astype(np.int64) - 1
    if not forward:
        x = x[::-1]
    z = int(np.abs(np.cumsum(x)).max())
    n = len(e)
    if z == 0:
        return 0.0
    Phi = lambda t: 0.5 * math.erfc(-t / math.sqrt(2))
    s1 = sum(Phi((4 * k + 1) * z / math.sqrt(n)) - Phi((4 * k - 1) * z / math.sqrt(n))
             for k in range(int((-n / z + 1) / 4), int((n / z - 1) / 4) + 1))   # pemotongan seperti kode referensi NIST STS
    s2 = sum(Phi((4 * k + 3) * z / math.sqrt(n)) - Phi((4 * k + 1) * z / math.sqrt(n))
             for k in range(int((-n / z - 3) / 4), int((n / z - 1) / 4) + 1))
    return max(0.0, min(1.0, 1 - s1 + s2))


def approximate_entropy(e, m=None):
    n = len(e)
    m = m or max(2, min(10, int(math.log2(n)) - 6))

    def phi(mm):
        ext = np.concatenate([e, e[:mm - 1]]).astype(np.int64)
        w = np.zeros(n, dtype=np.int64)
        for j in range(mm):
            w = (w << 1) | ext[j:j + n]
        c = np.bincount(w, minlength=1 << mm) / n
        c = c[c > 0]
        return float((c * np.log(c)).sum())
    ap = phi(m) - phi(m + 1)
    chi = 2 * n * (math.log(2) - ap)
    return igamc(2 ** (m - 1), chi / 2)


def run_all(seqs: list) -> dict:
    """Jalankan subset uji pada s barisan; kembalikan p-value, proporsi, P-value_T per uji."""
    s = len(seqs)
    thr = (1 - ALPHA) - 3 * math.sqrt((1 - ALPHA) * ALPHA / s)
    out = {}
    fns = {"frequency": frequency, "block_frequency": block_frequency, "runs": runs, "longest_run": longest_run,
           "cusum_forward": lambda e: _cusum(e, True), "cusum_backward": lambda e: _cusum(e, False),
           "approximate_entropy": approximate_entropy}
    for name in TESTS:
        ps = [fns[name](e) for e in seqs]
        prop = sum(p >= ALPHA for p in ps) / s
        pT = None
        if s >= 55:                                   # SP 800-22 §4.2.2: uji keseragaman butuh ≥ 55 barisan
            hist = np.histogram(ps, bins=10, range=(0, 1))[0]
            chi = float(((hist - s / 10) ** 2 / (s / 10)).sum())
            pT = igamc(9 / 2, chi / 2)
        out[name] = {"proportion": round(prop, 4), "min_proportion": round(thr, 4), "p_value_T": pT,
                     "p_values_min": round(min(ps), 6), "pass_proportion": prop >= thr,
                     "pass_uniformity": (pT is None) or pT >= 0.0001}
    return {"sequences": s, "bits_per_sequence": len(seqs[0]), "alpha": ALPHA, "tests": out,
            "proportion_formula": "(1 − α) − 3·√((1 − α)·α/s)"}
