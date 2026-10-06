"""Analisis banyak barisan (SP 800-22 §4.2): proporsi lulus dan keseragaman p-value, histogram 10 interval (KUK 3.1)."""
import numpy as np

from ..stats import proportion_decision, uniformity
from . import sp80022
from .generators import biased, prng


def analyze(seqs, tests=("monobit", "block_frequency", "runs"), alpha=0.01, block_m=128) -> dict:
    m = len(seqs)
    out = {}
    for t in tests:
        pv = []
        for s in seqs:
            r = sp80022.FUNCS[t](s, M=block_m) if t == "block_frequency" else sp80022.FUNCS[t](s)
            if r["p_value"] is not None:
                pv.extend(r["p_values"][:1] if t not in ("cusum", "serial") else r["p_values"][:1])
        if not pv:
            out[t] = {"runnable": False, "reason": "n kurang dari n minimum"}
            continue
        passed = int(sum(p >= alpha for p in pv))
        prop = proportion_decision(passed, len(pv), alpha)
        uni = uniformity(pv)
        out[t] = {"runnable": True, "m": len(pv), "passed": passed, "proportion": prop["proportion"], "low": prop["low"],
                  "high": prop["high"], "prop_ok": prop["ok"], "chi2": uni["chi2"], "p_value_T": uni["p_value_T"],
                  "uniform_ok": uni["ok"] if len(pv) >= 55 else None, "histogram": uni["counts"], "p_values": pv,
                  "ok": prop["ok"] and (uni["ok"] if len(pv) >= 55 else True)}
    ok = all(v.get("ok") for v in out.values() if v.get("runnable"))
    return {"m": m, "n": int(len(seqs[0])) if m else 0, "alpha": alpha, "tests": out,
            "conclusion": "Tidak ditemukan bukti ketidakacakan" if ok else "Ditemukan indikasi ketidakacakan",
            "note": "Uji keseragaman hanya bermakna untuk m ≥ 55 (SP 800-22 §4.2.2)." if m < 55 else ""}


def length_experiment(ns=(10_000, 100_000, 1_000_000), m=100, p_bias=0.51, seed=2026) -> dict:
    """Eksperimen pengaruh panjang barisan: generator baik (PCG64 ber-seed) vs bias P(1) = 0,51 (materi slide 35)."""
    rows = []
    for n in ns:
        for name, gen in (("baik", lambda i: prng(n, seed + i)), (f"bias P(1) = {p_bias}", lambda i: biased(n, p_bias, seed + i))):
            seqs = [gen(i) for i in range(m)]
            a = analyze(seqs, ("monobit", "runs"))
            mono, runs = a["tests"]["monobit"], a["tests"]["runs"]
            det = [t for t, v in (("monobit", mono), ("runs", runs)) if not v["prop_ok"]]
            rows.append({"n": n, "generator": name, "monobit": mono["proportion"], "runs": runs["proportion"],
                         "batas": mono["low"], "kesimpulan": "LULUS" if not det else "Terdeteksi (" + ", ".join(det) + ")"})
    return {"m": m, "seed": seed, "rows": rows,
            "lesson": "Barisan pendek bisa meloloskan cacat kecil; tetapkan n dan m sebelum uji, jangan diubah setelah melihat hasil."}
