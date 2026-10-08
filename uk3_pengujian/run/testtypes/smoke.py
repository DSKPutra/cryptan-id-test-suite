"""Smoke test — produk dapat dijalankan sama sekali (slide 14/16). Bila gagal, uji lain TERBLOKIR."""
from . import executor, try_call


@executor("sf_smoke")
def sf_smoke(ctx, tc):
    m = ctx.mod
    api = all(callable(getattr(m, f, None)) for f in ("encrypt", "decrypt"))
    if not api:
        return {"actual": "API encrypt/decrypt tidak ada", "passed": False, "metode": "Smoke"}
    blob, e = try_call(m.encrypt, b"smoke", b"halo")
    out, e2 = (None, e) if e else try_call(m.decrypt, b"smoke", blob)
    ok = out == b"halo"
    return {"actual": f"modul termuat; round-trip {'benar' if ok else 'gagal: ' + repr(e or e2)}", "passed": ok, "metode": "Smoke",
            "data": {"blob_len": len(blob) if blob else None}}


@executor("lib_smoke")
def lib_smoke(ctx, tc):
    import hashlib

    import cryptography
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    k, n = ctx.rand(16, "smoke-k"), ctx.rand(12, "smoke-n")
    rt = AESGCM(k).decrypt(n, AESGCM(k).encrypt(n, b"data uji", None), None) == b"data uji"
    h = hashlib.sha256(b"abc").hexdigest().startswith("ba7816bf")
    return {"actual": f"cryptography {cryptography.__version__} termuat; round-trip AES-GCM {'benar' if rt else 'salah'}; "
                      f"SHA-256(abc) {'sesuai' if h else 'tidak sesuai'}", "passed": rt and h, "metode": "Smoke"}
