"""Uji statistik — hanya dapat menolak keacakan, tidak membuktikannya (H0 acak, α = 0,01)."""
import numpy as np

from ...analysis import methods as A
from . import executor


@executor("sf_uniqueness")
def sf_uniqueness(ctx, tc):
    N = ctx.p(tc, "N", 20)
    bs = [ctx.mod.encrypt(b"p", b"x") for _ in range(N)]
    s = A.uniqueness([b[4:20] for b in bs], "salt")
    n = A.uniqueness([b[20:32] for b in bs], "nonce")
    ctx.cache["blobs_same_pw"] = bs
    return {"actual": f"{s['teks']}, {n['teks']}; harapan {N}/{N}", "passed": s["ok"] and n["ok"], "metode": "Keunikan nonce/salt",
            "analisis": {"salt": s, "nonce": n}, "batasan": tc.get("batasan_bila_lulus"),
            "data": {"salts": [b[4:20].hex() for b in bs], "nonces": [b[20:32].hex() for b in bs]}}


@executor("stat_ctr_keystream")
def stat_ctr_keystream(ctx, tc):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    m, n = ctx.p(tc, "m", 100), ctx.p(tc, "n", 100_000)
    seqs = []
    for i in range(m):
        enc = Cipher(algorithms.AES(ctx.rand(16, f"ks{i}")), modes.CTR(ctx.rand(16, f"iv{i}"))).encryptor()
        ks = enc.update(bytes(n // 8))
        seqs.append(np.unpackbits(np.frombuffer(ks, np.uint8)).astype(np.int64))
    an = A.sp80022(seqs)
    me = A.min_entropy(np.concatenate(seqs[:10]))
    rows = {t: f"{v['passed']}/{v['m']} (batas {v['low']:.4f}), P-value_T = {v['p_value_T']:.4f}" for t, v in an["tests"].items()}
    lim = None if m >= 100 else f"m = {m} < 100: bukti statistik terbatas"
    return {"actual": "; ".join(f"{t}: {r}" for t, r in rows.items()), "passed": an["ok"], "metode": "NIST SP 800-22",
            "analisis": {**{k: v for k, v in an.items() if k != "tests"},
                         "tests": {t: {k: v for k, v in x.items() if k != "p_values"} for t, x in an["tests"].items()}, "min_entropy": me},
            "seed": ctx.seed, "batasan": lim, "data": {"p_values": {t: v["p_values"] for t, v in an["tests"].items()}, "m": m, "n": n}}


@executor("stat_avalanche_sha256")
def stat_avalanche_sha256(ctx, tc):
    import hashlib
    N = ctx.p(tc, "N", 10000)
    hds = []
    for i in range(N):
        msg = bytearray(ctx.rand(64, f"av{i}"))
        a = hashlib.sha256(msg).digest()
        bit = i % 512
        msg[bit // 8] ^= 1 << (bit % 8)
        b = hashlib.sha256(msg).digest()
        hds.append(int.from_bytes(a, "big") ^ int.from_bytes(b, "big"))
    hds = [bin(x).count("1") for x in hds]
    an = A.avalanche(hds, 256)
    return {"actual": f"rerata HD {an['mean_hd']:.2f} (sd {an['sd_teramati']:.2f}), harapan 128 (sd 8); z = {an['z']:.2f}",
            "passed": an["ok"], "metode": "Avalanche", "analisis": an, "seed": ctx.seed,
            "data": {"histogram": np.histogram(hds, bins=range(96, 162, 4))[0].tolist()}}
