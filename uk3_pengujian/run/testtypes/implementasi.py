"""Kinerja & timing — butuh pengukuran berulang (tahap 6)."""
import time

from ...analysis import methods as A
from . import executor


@executor("sf_performance")
def sf_performance(ctx, tc):
    size, reps, warm = ctx.p(tc, "ukuran_byte", 1 << 20), ctx.p(tc, "ulangan", 10), ctx.p(tc, "pemanasan", 1)
    target = ctx.p(tc, "target_detik", 1.0)
    pt = ctx.rand(size, "kn")
    blob = ctx.mod.encrypt(b"kinerja", pt)
    times = []
    for _ in range(warm + reps):
        t0 = time.perf_counter()
        ctx.mod.decrypt(b"kinerja", blob)
        times.append(time.perf_counter() - t0)
    an = A.performance(times, warmup=warm, target=target)
    return {"actual": f"rata-rata {an['mean']:.3f} s ± {an['half_width']:.3f} (95%: {an['low']:.3f}–{an['high']:.3f} s), p95 {an['p95']:.3f} s",
            "passed": bool(an["ok"]), "metode": "Kinerja", "analisis": an, "batasan": tc.get("batasan_bila_lulus"),
            "data": {"times_s": times, "warmup": warm}}


@executor("timing_gcm")
def timing_gcm(ctx, tc):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    N, sessions = ctx.p(tc, "N", 3000), ctx.p(tc, "sesi", 2)
    g = AESGCM(ctx.rand(16, "wt-k"))
    nonce, fixed = ctx.rand(12, "wt-n"), ctx.rand(64, "wt-fixed")
    res = []
    for s in range(sessions):
        order = ctx.rand(N, f"ord{s}")
        tf, tr = [], []
        for _ in range(50):
            g.encrypt(nonce, fixed, None)
        for i in range(N):
            x = ctx.rand(64, f"r{s}-{i}")
            pair = ((fixed, tf), (x, tr)) if order[i] & 1 else ((x, tr), (fixed, tf))
            for data, bucket in pair:
                t0 = time.perf_counter_ns()
                g.encrypt(nonce, data, None)
                bucket.append(time.perf_counter_ns() - t0)
        res.append(A.timing(tf, tr))
    leaks = [r["leak"] for r in res]
    inconsistent = any(leaks) and not all(leaks)
    return {"actual": "; ".join(f"sesi {i + 1}: |t| = {r['abs_t']:.2f}" for i, r in enumerate(res)),
            "passed": not any(leaks), "metode": "Timing (Welch t)", "inconclusive": inconsistent,
            "analisis": {"sesi": [{k: v for k, v in r.items()} for r in res], "tidak_konsisten": inconsistent},
            "batasan": tc.get("batasan_bila_lulus"), "seed": ctx.seed}
