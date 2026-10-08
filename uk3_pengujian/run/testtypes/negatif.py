"""Uji negatif — masukan salah harus ditolak dengan aman (minimal sepertiga dari seluruh TC)."""
from cryptography.exceptions import InvalidSignature, InvalidTag

from ...analysis import methods as A
from . import executor, try_call
from .positif import blob


def _case(name, fn, expected_exc, group="default", msg=None):
    out, e = try_call(fn)
    rejected = isinstance(e, expected_exc) and (msg is None or str(e) == msg)
    return {"case": name, "rejected": rejected, "error_class": type(e).__name__ if e else None, "message": str(e) if e else None,
            "plaintext_leaked": e is None and out is not None, "group": group}


def _res(cases, expected_text):
    an = A.negative(cases)
    c = cases[0]
    act = (f"{c['error_class']}: {c['message']}" if c["error_class"] else f"diterima (keluaran {('ada' if c['plaintext_leaked'] else 'tidak ada')})")
    return {"actual": f"{act} — {an['ditolak']}/{an['total']} ditolak", "passed": an["semua_ditolak"], "metode": "Uji negatif",
            "analisis": an, "data": {"cases": cases, "expected": expected_text}}


@executor("sf_wrong_password")
def sf_wrong_password(ctx, tc):
    return _res([_case("password salah", lambda: ctx.mod.decrypt(b"salah", blob(ctx)), InvalidTag, "autentikasi")], "InvalidTag")


@executor("sf_bitflip")
def sf_bitflip(ctx, tc):
    b = bytearray(blob(ctx))
    b[ctx.p(tc, "posisi_byte", 40)] ^= 1
    return _res([_case("1 bit ciphertext dibalik", lambda: ctx.mod.decrypt(b"rahasia", bytes(b)), InvalidTag, "autentikasi")], "InvalidTag")


@executor("sf_tagflip")
def sf_tagflip(ctx, tc):
    b = bytearray(blob(ctx))
    b[-1] ^= 1
    return _res([_case("1 bit tag diubah", lambda: ctx.mod.decrypt(b"rahasia", bytes(b)), InvalidTag, "autentikasi")], "InvalidTag")


@executor("sf_truncated")
def sf_truncated(ctx, tc):
    return _res([_case("berkas terpotong", lambda: ctx.mod.decrypt(b"rahasia", blob(ctx)[:40]), ValueError, "format",
                       "format tidak valid")], 'ValueError("format tidak valid")')


@executor("sf_bad_magic")
def sf_bad_magic(ctx, tc):
    return _res([_case("MAGIC diubah", lambda: ctx.mod.decrypt(b"rahasia", b"XF01" + blob(ctx)[4:]), ValueError, "format",
                       "format tidak valid")], 'ValueError("format tidak valid")')


def _gcm(ctx):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    k, n, aad = ctx.rand(16, "ae-k"), ctx.rand(12, "ae-n"), b"header"
    return AESGCM(k), n, aad, AESGCM(k).encrypt(n, b"data uji", aad)


@executor("neg_gcm_ct")
def neg_gcm_ct(ctx, tc):
    g, n, aad, c = _gcm(ctx)
    b = bytearray(c)
    b[0] ^= 1
    return _res([_case("1 bit ciphertext", lambda: g.decrypt(n, bytes(b), aad), InvalidTag)], "InvalidTag")


@executor("neg_gcm_aad")
def neg_gcm_aad(ctx, tc):
    g, n, aad, c = _gcm(ctx)
    bad = bytes([aad[0] ^ 1]) + aad[1:]
    return _res([_case("1 bit AAD", lambda: g.decrypt(n, c, bad), InvalidTag)], "InvalidTag")


@executor("neg_x25519_zero")
def neg_x25519_zero(ctx, tc):
    from cryptography.hazmat.primitives.asymmetric import x25519
    sk = x25519.X25519PrivateKey.generate()
    return _res([_case("kunci publik nol", lambda: sk.exchange(x25519.X25519PublicKey.from_public_bytes(bytes(32))), ValueError)],
                "ValueError")


@executor("neg_p256_offcurve")
def neg_p256_offcurve(ctx, tc):
    from cryptography.hazmat.primitives.asymmetric import ec
    gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    pt = b"\x04" + gx.to_bytes(32, "big") + (gy + 1).to_bytes(32, "big")
    return _res([_case("titik di luar kurva", lambda: ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pt), ValueError)],
                "ValueError")


def _ecdsa():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    sk = ec.generate_private_key(ec.SECP256R1())
    return sk, ec.ECDSA(hashes.SHA256())


@executor("neg_ecdsa_msg")
def neg_ecdsa_msg(ctx, tc):
    sk, alg = _ecdsa()
    m = b"pesan uji"
    sig = sk.sign(m, alg)
    bad = bytes([m[0] ^ 1]) + m[1:]
    return _res([_case("pesan diubah 1 byte", lambda: sk.public_key().verify(sig, bad, alg), InvalidSignature)], "InvalidSignature")


@executor("ecdsa_high_s")
def ecdsa_high_s(ctx, tc):
    """TC-DS-02: expected ditentukan kebijakan skenario (low_s_wajib), bukan asumsi penguji saat eksekusi."""
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    sk, alg = _ecdsa()
    m = b"pesan uji"
    r, s = decode_dss_signature(sk.sign(m, alg))
    sig2 = encode_dss_signature(r, n - s)
    _, e = try_call(sk.public_key().verify, sig2, m, alg)
    accepted = e is None
    low_s = bool((ctx.scenario.get("kebijakan") or {}).get("low_s_wajib"))
    ok = (not accepted) if low_s else accepted
    return {"actual": f"(r, n − s) {'diterima' if accepted else 'ditolak (' + type(e).__name__ + ')'}", "passed": ok,
            "metode": "Uji negatif", "data": {"diterima": accepted, "low_s_wajib": low_s},
            "batasan": None if low_s else "Malleability (r, n − s) diterima: sah hanya bila keunikan tanda tangan tidak diandalkan"}


def _ed_batch(ctx, tc, mode):
    from cryptography.hazmat.primitives.asymmetric import ed25519
    N = ctx.p(tc, "jumlah", 100)
    keys = [ed25519.Ed25519PrivateKey.from_private_bytes(ctx.rand(32, f"ed{i}")) for i in range(N + 1)]
    rej = 0
    cases = []
    for i in range(N):
        m = ctx.rand(32, f"m{i}")
        sig = keys[i].sign(m)
        pk = keys[i].public_key()
        if mode == "msg":
            bit = int.from_bytes(ctx.rand(2, f"b{i}"), "big") % (len(m) * 8)
            mm = bytearray(m)
            mm[bit // 8] ^= 1 << (bit % 8)
            fn = lambda: pk.verify(sig, bytes(mm))  # noqa: E731
        elif mode == "sig":
            bit = int.from_bytes(ctx.rand(2, f"b{i}"), "big") % (len(sig) * 8)
            ss = bytearray(sig)
            ss[bit // 8] ^= 1 << (bit % 8)
            fn = lambda: pk.verify(bytes(ss), m)  # noqa: E731
        else:
            other = keys[i + 1].public_key()
            fn = lambda: other.verify(sig, m)  # noqa: E731
        c = _case(f"{mode} #{i}", fn, InvalidSignature, "verifikasi")
        rej += c["rejected"]
        cases.append(c)
    an = A.negative(cases)
    rr = A.rejection_rate(rej, N)
    return {"actual": rr["teks"], "passed": rr["ok"] and an["galat_seragam"], "metode": "Uji negatif", "analisis": {**an, **rr},
            "seed": ctx.seed, "data": {"rejected": rej, "total": N}}


@executor("ed25519_mut_msg")
def ed25519_mut_msg(ctx, tc):
    return _ed_batch(ctx, tc, "msg")


@executor("ed25519_mut_sig")
def ed25519_mut_sig(ctx, tc):
    return _ed_batch(ctx, tc, "sig")


@executor("ed25519_other_key")
def ed25519_other_key(ctx, tc):
    return _ed_batch(ctx, tc, "key")
