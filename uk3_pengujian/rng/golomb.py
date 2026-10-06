"""Postulat Golomb G1–G3 (Golomb 1967; HAC §5.4.3) untuk satu periode barisan (siklik) — Lab Keacakan."""
import numpy as np

from .sp80022 import to_bits


def cyclic_runs(e):
    """Run siklik (run awal & akhir bergabung). Mengembalikan daftar (bit, panjang)."""
    n = len(e)
    if n == 0 or all(b == e[0] for b in e):
        return [(int(e[0]), n)] if n else []
    start = next(i for i in range(n) if e[i] != e[i - 1])
    runs, i = [], 0
    while i < n:
        b = e[(start + i) % n]
        L = 0
        while i < n and e[(start + i) % n] == b:
            L += 1
            i += 1
        runs.append((int(b), L))
    return runs


def g1(e):
    n1 = int(np.sum(e))
    n0 = len(e) - n1
    return {"n0": n0, "n1": n1, "diff": abs(n1 - n0), "ok": abs(n1 - n0) <= 1}


def g2(e):
    rs = cyclic_runs(list(e))
    total = len(rs)
    maxL = max((L for _, L in rs), default=0)
    table = []
    ok = True
    for i in range(1, maxL + 1):
        blk = sum(1 for b, L in rs if b == 1 and L == i)
        gap = sum(1 for b, L in rs if b == 0 and L == i)
        ideal = total / 2 ** i
        table.append({"length": i, "observed": blk + gap, "blocks": blk, "gaps": gap, "ideal": ideal})
    # Golomb: untuk tiap panjang i dengan ideal ≥ 1, banyaknya run ≈ total/2^i dan blok = gap
    for row in table:
        if row["ideal"] >= 1:
            if abs(row["observed"] - row["ideal"]) > 0.5 or abs(row["blocks"] - row["gaps"]) > (1 if row["ideal"] < 2 else 0):
                ok = False
        elif row["observed"] > 1:
            ok = False
    blocks = sum(1 for b, _ in rs if b == 1)
    return {"runs": total, "blocks": blocks, "gaps": total - blocks, "table": table, "ok": ok}


def autocorr(e, tau):
    n = len(e)
    e = np.asarray(e, dtype=np.int64)
    A = int((e == np.roll(e, -tau)).sum())
    return (A - (n - A)) / n


def g3(e, taus=None):
    n = len(e)
    taus = taus or list(range(1, n))
    vals = {t: autocorr(e, t) for t in taus}
    distinct = {round(v, 9) for v in vals.values()}
    return {"C": vals, "ok": len(distinct) == 1, "min": min(vals.values()), "max": max(vals.values())}


def check(bits, max_tau=None) -> dict:
    e = list(map(int, to_bits(bits)))
    n = len(e)
    r3 = g3(e, list(range(1, (max_tau or n - 1) + 1)))
    res = {"n": n, "G1": g1(e), "G2": g2(e), "G3": r3}
    res["all_ok"] = res["G1"]["ok"] and res["G2"]["ok"] and (r3["ok"] if not max_tau or max_tau >= n - 1 else r3["ok"])
    res["conclusion"] = ("G1, G2, G3 terpenuhi (sifat barisan PN)" if res["all_ok"] else
                         "Postulat Golomb tidak terpenuhi secara ketat: bukan barisan PN")
    return res
