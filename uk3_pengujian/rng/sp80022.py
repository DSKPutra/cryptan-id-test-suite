"""Uji NIST SP 800-22 Rev.1a bawaan, dengan langkah perhitungan ditampilkan (Lab Keacakan, KUK 3.1).

Wajib: monobit (§2.1), block frequency (§2.2), runs (§2.3). Opsional: longest run (§2.4), serial (§2.11),
approximate entropy (§2.12), cumulative sums (§2.13). Setiap uji memeriksa n minimum; bila n kurang,
status "tidak dapat dijalankan" (kecuali enforce_min=False untuk mereproduksi contoh kecil di dokumen).
"""
import math

import numpy as np

from ..stats import erfc, igamc

ALPHA = 0.01
REQUIRED = ["monobit", "block_frequency", "runs"]
OPTIONAL = ["longest_run", "cusum", "serial", "approximate_entropy"]
NAMES = {"monobit": "Frequency (monobit) §2.1", "block_frequency": "Frequency within a block §2.2", "runs": "Runs §2.3",
         "longest_run": "Longest run of ones §2.4", "serial": "Serial §2.11", "approximate_entropy": "Approximate entropy §2.12",
         "cusum": "Cumulative sums §2.13"}


def to_bits(x) -> np.ndarray:
    """Barisan bit sebagai int64 (bukan uint8 → tidak overflow saat dijumlah)."""
    if isinstance(x, str):
        x = [int(c) for c in x if c in "01"]
    return np.asarray(x, dtype=np.int64)


def _fmt(v, d=4):
    return f"{v:.{d}f}".replace(".", ",")


def _result(test, n, n_min, statistic, p, steps, enforce_min, extra=None, p_values=None):
    runnable = n >= n_min or not enforce_min
    res = {"test": test, "name": NAMES[test], "n": int(n), "n_min": n_min, "runnable": bool(n >= n_min),
           "alpha": ALPHA, "statistic": statistic, "p_value": p, "p_values": p_values or ([p] if p is not None else []),
           "steps": steps, **(extra or {})}
    if not runnable:
        res.update({"status": "tidak dapat dijalankan", "passed": None, "p_value": None, "p_values": [],
                    "reason": f"n = {n} < n minimum {n_min}"})
    else:
        ok = all(pv >= ALPHA for pv in res["p_values"])
        res.update({"status": "LULUS" if ok else "GAGAL", "passed": ok})
        if n < n_min:
            res["note"] = f"n = {n} < n minimum {n_min}: hanya untuk mereproduksi contoh dokumen"
    return res


def monobit(bits, enforce_min=True):
    e = to_bits(bits)
    n = e.size
    S = int((2 * e - 1).sum())
    s = abs(S) / math.sqrt(n)
    p = erfc(s / math.sqrt(2))
    steps = [("Ubah bit 1→+1, 0→−1 lalu jumlahkan", f"{int(e.sum())} bit 1 dan {n - int(e.sum())} bit 0", f"S = {S}"),
             ("Statistik uji", f"s = |S|/√n = {abs(S)}/√{n}", _fmt(s, 3)),
             ("p-value", f"erfc({_fmt(s, 3)}/√2)", _fmt(p)),
             ("Keputusan", f"{_fmt(p)} {'≥' if p >= ALPHA else '<'} 0,01", "LULUS" if p >= ALPHA else "GAGAL")]
    return _result("monobit", n, 100, {"S": S, "s_obs": s}, p, steps, enforce_min)


def block_frequency(bits, M=128, enforce_min=True):
    e = to_bits(bits)
    n = e.size
    N = n // M
    blocks = e[:N * M].reshape(N, M) if N else np.zeros((0, M), dtype=np.int64)
    pis = blocks.sum(axis=1) / M
    chi2 = float(4 * M * ((pis - 0.5) ** 2).sum())
    p = igamc(N / 2, chi2 / 2) if N else 0.0
    shown = " · ".join("".join(map(str, b)) for b in blocks[:6]) + (" …" if N > 6 else "")
    steps = [("Bagi barisan menjadi N blok berukuran M", f"n = {n}, M = {M}", f"N = {N} blok; {n - N * M} bit sisa diabaikan"),
             ("Proporsi bit 1 per blok", shown, ", ".join(_fmt(x, 3) for x in pis[:6]) + (" …" if N > 6 else "")),
             ("χ² = 4M Σ(π_i − 0,5)²", f"4 × {M} × {_fmt(float(((pis - 0.5) ** 2).sum()))}", _fmt(chi2)),
             ("p-value", f"igamc({_fmt(N / 2, 1)} ; {_fmt(chi2 / 2)})", _fmt(p)),
             ("Keputusan", f"{_fmt(p)} {'≥' if p >= ALPHA else '<'} 0,01", "LULUS" if p >= ALPHA else "GAGAL")]
    nmin = 100
    res = _result("block_frequency", n, nmin, {"chi2": chi2, "N": N, "M": M}, p, steps, enforce_min)
    if enforce_min and n >= nmin and (M < 20 or M <= 0.01 * n or N >= 100):
        res["note"] = "SP 800-22 menyarankan M ≥ 20, M > 0,01n, N < 100"
    return res


def runs(bits, enforce_min=True):
    e = to_bits(bits)
    n = e.size
    pi = float(e.mean())
    tau = 2 / math.sqrt(n)
    V = 1 + int(np.count_nonzero(e[1:] != e[:-1]))
    pre = abs(pi - 0.5) < tau
    if pre:
        num = abs(V - 2 * n * pi * (1 - pi))
        p = erfc(num / (2 * math.sqrt(2 * n) * pi * (1 - pi)))
    else:
        p = 0.0
    seg, cur = [], str(e[0]) if n else ""
    head = e[:64]                                       # hanya untuk tampilan langkah
    for a, b in zip(head[:-1], head[1:]):
        if a == b:
            cur += str(b)
        else:
            seg.append(cur)
            cur = str(b)
    seg.append(cur)
    steps = [("Proporsi bit 1", f"π = {int(e.sum())}/{n}", _fmt(pi, 3)),
             ("Prasyarat |π − 0,5| < τ = 2/√n", f"|{_fmt(pi, 3)} − 0,5| = {_fmt(abs(pi - 0.5), 3)} vs τ = {_fmt(tau, 3)}",
              "terpenuhi" if pre else "tidak terpenuhi → uji gagal"),
             ("Jumlah run V = 1 + jumlah perubahan bit", " · ".join(seg[:12]) + (" …" if len(seg) > 12 or n > 64 else ""), f"V = {V}"),
             ("p-value", f"erfc(|{V} − {_fmt(2 * n * pi * (1 - pi), 1)}| / (2·√{2 * n}·{_fmt(pi * (1 - pi), 2)}))", _fmt(p)),
             ("Keputusan", f"{_fmt(p)} {'≥' if p >= ALPHA else '<'} 0,01", "LULUS" if p >= ALPHA else "GAGAL")]
    return _result("runs", n, 100, {"pi": pi, "tau": tau, "V": V, "prerequisite": pre}, p, steps, enforce_min)


_LR = {8: (3, [1, 2, 3, 4], [0.2148, 0.3672, 0.2305, 0.1875]),
       128: (5, [4, 5, 6, 7, 8, 9], [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]),
       10000: (6, [10, 11, 12, 13, 14, 15, 16], [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727])}


def longest_run(bits, enforce_min=True):
    e = to_bits(bits)
    n = e.size
    M = 8 if n < 6272 else 128 if n < 750000 else 10000
    K, cls, pi = _LR[M]
    N = n // M
    nu = [0] * (K + 1)
    for blk in e[:N * M].reshape(N, M) if N else []:
        best = cur = 0
        for b in blk:
            cur = cur + 1 if b else 0
            best = max(best, cur)
        idx = 0 if best <= cls[0] else K if best >= cls[-1] else cls.index(best)
        nu[idx] += 1
    chi2 = sum((nu[i] - N * pi[i]) ** 2 / (N * pi[i]) for i in range(K + 1)) if N else 0.0
    p = igamc(K / 2, chi2 / 2) if N else 0.0
    steps = [("Blok", f"M = {M}, N = {N}", f"K = {K}"), ("Frekuensi kelas ν", str(nu), ""),
             ("χ²", "Σ(ν_i − Nπ_i)²/(Nπ_i)", _fmt(chi2)), ("p-value", f"igamc({K}/2 ; χ²/2)", _fmt(p))]
    return _result("longest_run", n, 128, {"chi2": chi2, "nu": nu, "M": M}, p, steps, enforce_min)


def cusum(bits, enforce_min=True):
    e = to_bits(bits)
    n = e.size
    x = 2 * e - 1
    from scipy.stats import norm
    ps, zs = [], []
    for fwd in (True, False):
        s = np.cumsum(x if fwd else x[::-1])
        z = int(np.abs(s).max()) if n else 0
        zs.append(z)
        if z == 0:
            ps.append(0.0)
            continue
        sn = math.sqrt(n)
        k1 = np.arange(int((-n / z + 1) / 4), int((n / z - 1) / 4) + 1)
        k2 = np.arange(int((-n / z - 3) / 4), int((n / z - 1) / 4) + 1)
        t1 = (norm.cdf((4 * k1 + 1) * z / sn) - norm.cdf((4 * k1 - 1) * z / sn)).sum()
        t2 = (norm.cdf((4 * k2 + 3) * z / sn) - norm.cdf((4 * k2 + 1) * z / sn)).sum()
        ps.append(float(max(0.0, min(1.0, 1 - t1 + t2))))
    steps = [("z maju / mundur", f"maks |S_k| = {zs[0]} / {zs[1]}", ""), ("p-value maju / mundur", "", f"{_fmt(ps[0])} / {_fmt(ps[1])}")]
    return _result("cusum", n, 100, {"z_forward": zs[0], "z_backward": zs[1]}, min(ps), steps, enforce_min, p_values=ps)


def _psi2(e, m):
    if m <= 0:
        return 0.0
    n = e.size
    ext = np.concatenate([e, e[:m - 1]])
    idx = np.zeros(n, dtype=np.int64)
    for j in range(m):
        idx = (idx << 1) | ext[j:j + n]
    c = np.bincount(idx, minlength=2 ** m)
    return float((2 ** m / n) * (c.astype(float) ** 2).sum() - n)


def serial(bits, m=None, enforce_min=True):
    e = to_bits(bits)
    n = e.size
    m = m or max(2, min(16, int(math.log2(max(n, 2))) - 3))
    p0, p1, p2 = _psi2(e, m), _psi2(e, m - 1), _psi2(e, m - 2)
    d1, d2 = p0 - p1, p0 - 2 * p1 + p2
    pv1, pv2 = igamc(2 ** (m - 2), d1 / 2), igamc(2 ** (m - 3), d2 / 2)
    steps = [("ψ²_m, ψ²_m−1, ψ²_m−2", f"m = {m}", f"{_fmt(p0)}, {_fmt(p1)}, {_fmt(p2)}"),
             ("∇ψ², ∇²ψ²", "", f"{_fmt(d1)}, {_fmt(d2)}"), ("p-value 1 / 2", "", f"{_fmt(pv1)} / {_fmt(pv2)}")]
    nmin = 2 ** (m + 2)
    return _result("serial", n, nmin, {"m": m, "del1": d1, "del2": d2}, min(pv1, pv2), steps, enforce_min, p_values=[pv1, pv2])


def approximate_entropy(bits, m=None, enforce_min=True):
    e = to_bits(bits)
    n = e.size
    m = m or max(2, min(10, int(math.log2(max(n, 2))) - 6))

    def phi(mm):
        ext = np.concatenate([e, e[:mm - 1]]) if mm > 1 else e
        idx = np.zeros(n, dtype=np.int64)
        for j in range(mm):
            idx = (idx << 1) | ext[j:j + n]
        c = np.bincount(idx, minlength=2 ** mm).astype(float) / n
        c = c[c > 0]
        return float((c * np.log(c)).sum())
    apen = phi(m) - phi(m + 1)
    chi2 = 2 * n * (math.log(2) - apen)
    p = igamc(2 ** (m - 1), chi2 / 2)
    steps = [("φ(m) − φ(m+1)", f"m = {m}", f"ApEn = {_fmt(apen, 6)}"), ("χ² = 2n(ln 2 − ApEn)", "", _fmt(chi2)),
             ("p-value", f"igamc(2^{m - 1} ; χ²/2)", _fmt(p))]
    nmin = 2 ** (m + 5)
    return _result("approximate_entropy", n, nmin, {"m": m, "apen": apen, "chi2": chi2}, p, steps, enforce_min)


FUNCS = {"monobit": monobit, "block_frequency": block_frequency, "runs": runs, "longest_run": longest_run, "cusum": cusum,
         "serial": serial, "approximate_entropy": approximate_entropy}


def run_tests(bits, tests=None, block_m=128, enforce_min=True) -> list:
    out = []
    for t in tests or REQUIRED + OPTIONAL:
        f = FUNCS[t]
        out.append(f(bits, M=block_m, enforce_min=enforce_min) if t == "block_frequency" else f(bits, enforce_min=enforce_min))
    return out
