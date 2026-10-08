"""Uji properti — invarian selalu berlaku (round-trip, panjang, hash bertahap = sekaligus, ECDH simetris).
Round-trip juga lulus pada implementasi salah yang konsisten → selalu dipadukan dengan KAT."""
import hashlib

from . import executor, try_call


@executor("sf_property")
def sf_property(ctx, tc):
    rows, ok = [], True
    for n in ctx.p(tc, "ukuran", [0, 1, 15, 16, 17]):
        pt = ctx.rand(n, f"pr{n}")
        b, e = try_call(ctx.mod.encrypt, b"properti", pt)
        out, e2 = (None, e) if e else try_call(ctx.mod.decrypt, b"properti", b)
        good_len = b is not None and len(b) == 4 + 16 + 12 + n + 16
        good = out == pt and good_len
        ok &= good
        rows.append({"ukuran": n, "round_trip": out == pt, "panjang_blob": len(b) if b else None, "panjang_sesuai": good_len})
    bad = [r["ukuran"] for r in rows if not (r["round_trip"] and r["panjang_sesuai"])]
    return {"actual": f"{len(rows) - len(bad)}/{len(rows)} ukuran memenuhi invarian" + (f"; gagal pada {bad}" if bad else ""),
            "passed": ok, "metode": "Uji properti", "data": {"rows": rows}}


@executor("prop_hash_incremental")
def prop_hash_incremental(ctx, tc):
    from cryptography.hazmat.primitives import hashes
    N = ctx.p(tc, "jumlah", 1000)
    same = 0
    for i in range(N):
        m = ctx.rand(int.from_bytes(ctx.rand(2, f"l{i}"), "big") % 301, f"m{i}")
        cut = int.from_bytes(ctx.rand(2, f"c{i}"), "big") % (len(m) + 1)
        h = hashes.Hash(hashes.SHA256())
        h.update(m[:cut])
        h.update(m[cut:])
        same += h.finalize() == hashlib.sha256(m).digest()
    return {"actual": f"{same}/{N} identik", "passed": same == N, "metode": "Uji properti", "seed": ctx.seed,
            "data": {"identik": same, "total": N}}


@executor("pk_x25519_agree")
def pk_x25519_agree(ctx, tc):
    from cryptography.hazmat.primitives.asymmetric import x25519
    a, b = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
    ok = a.exchange(b.public_key()) == b.exchange(a.public_key())
    return {"actual": "ECDH(A,B) = ECDH(B,A)" if ok else "ECDH(A,B) ≠ ECDH(B,A)", "passed": ok, "metode": "Uji properti"}
