"""Uji positif — fitur bekerja untuk masukan sah (oracle: spesifikasi)."""
from . import executor, try_call


def blob(ctx):
    """Blob bersama TC-03..TC-09: encrypt(b"rahasia", b"dokumen uji")."""
    if "blob" not in ctx.cache:
        ctx.cache["blob"] = ctx.mod.encrypt(b"rahasia", b"dokumen uji")
    return ctx.cache["blob"]


@executor("sf_roundtrip")
def sf_roundtrip(ctx, tc):
    out, e = try_call(ctx.mod.decrypt, b"rahasia", blob(ctx))
    ok = out == b"dokumen uji"
    return {"actual": f"decrypt = {out!r}" if e is None else f"galat {type(e).__name__}: {e}", "passed": ok, "metode": "Uji positif",
            "data": {"blob_sha256": __import__("hashlib").sha256(blob(ctx)).hexdigest(), "blob_len": len(blob(ctx))}}


@executor("pk_oaep")
def pk_oaep(ctx, tc):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pad = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    m = b"data uji"
    c1, c2 = sk.public_key().encrypt(m, pad), sk.public_key().encrypt(m, pad)
    d1, d2 = sk.decrypt(c1, pad), sk.decrypt(c2, pad)
    ok = c1 != c2 and d1 == d2 == m
    return {"actual": f"c1 {'≠' if c1 != c2 else '='} c2; dekripsi {'= pesan' if d1 == d2 == m else 'salah'}", "passed": ok,
            "metode": "Uji positif"}
