"""Uji diferensial — produk vs implementasi independen pada banyak masukan (seed dicatat).

Berbeda dengan kriptanalisis diferensial (teknik serangan)."""
import hashlib

from ...analysis import methods as A
from . import executor, try_call


def _oracle_decrypt(password, blob):
    """Oracle independen SecureFile: hashlib PBKDF2 + pycryptodome AES-GCM (bukan pustaka produk)."""
    from Crypto.Cipher import AES
    salt, nonce, ct = blob[4:20], blob[20:32], blob[32:]
    key = hashlib.pbkdf2_hmac("sha256", password, salt, 600_000, 32)
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    c.update(blob[:4])
    return c.decrypt_and_verify(ct[:-16], ct[-16:])


@executor("sf_differential")
def sf_differential(ctx, tc):
    N = ctx.p(tc, "jumlah", 3)
    same, rows = 0, []
    for i in range(N):
        pw, pt = ctx.rand(12, f"df-pw{i}"), ctx.rand(10 + 37 * i, f"df-pt{i}")
        blob = ctx.mod.encrypt(pw, pt)
        out, e = try_call(_oracle_decrypt, pw, blob)
        ok = out == pt
        same += ok
        rows.append({"i": i, "panjang": len(pt), "identik": ok, "galat_oracle": type(e).__name__ if e else None})
    an = A.differential(same, N, ctx.seed)
    return {"actual": an["teks"] + " (oracle: hashlib + pycryptodome)", "passed": an["ok"], "metode": "Uji diferensial",
            "analisis": an, "seed": ctx.seed, "data": {"rows": rows}}


@executor("diff_gcm")
def diff_gcm(ctx, tc):
    from Crypto.Cipher import AES
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    N = ctx.p(tc, "jumlah", 1000)
    same, first_diff = 0, None
    for i in range(N):
        k = ctx.rand([16, 24, 32][i % 3], f"k{i}")
        n, aad, pt = ctx.rand(12, f"n{i}"), ctx.rand(i % 33, f"a{i}"), ctx.rand(i % 97, f"p{i}")
        a = AESGCM(k).encrypt(n, pt, aad)
        c = AES.new(k, AES.MODE_GCM, nonce=n)
        c.update(aad)
        ct, tag = c.encrypt_and_digest(pt)
        if a == ct + tag:
            same += 1
        elif first_diff is None:
            first_diff = i
    an = A.differential(same, N, ctx.seed)
    return {"actual": an["teks"] + " (pyca vs pycryptodome)", "passed": an["ok"], "metode": "Uji diferensial", "analisis": an,
            "seed": ctx.seed, "data": {"identik": same, "total": N, "beda_pertama": first_diff}}
