"""Lapis K — Uji Kesesuaian: K-01 KAT/uji silang · K-02 round-trip · K-03 MCT/multi-blok/bertahap · K-04 negatif."""
from .. import kat
from . import GAGAL, INKON, LULUS, TDD, Plugin

SYM = ("cipher", "aead")


def _iv(a, ctx, tag):
    if getattr(a, "mode", None) == "XTS":
        return ctx.rand(16, tag)
    if a.kind == "aead":
        return ctx.rand(a.nonce_len, tag)
    if getattr(a, "needs_iv", False):
        return ctx.rand(a.block if a.block >= 8 else 16, tag)
    return None


def _key(ctx, tag):
    kb = ctx.row.get("key_bits") or 128
    fam = ctx.row["family"]
    if fam == "TDEA":
        return ctx.rand(24, tag)
    return ctx.rand(kb // 8, tag)


def _msg(a, ctx, tag, nblocks=4):
    if getattr(a, "mode", None) in ("KW", "KWP"):
        return ctx.rand(8 * (nblocks + 1), tag)
    if getattr(a, "full_blocks", False) or getattr(a, "mode", None) == "XTS":
        return ctx.rand(a.block * nblocks, tag)
    return ctx.rand(16 * nblocks + 5, tag)


_KP = {}


def _kp(a):
    """Pasangan kunci RSA/DSA per adapter (dari cache PEM) — menghindari pemuatan berulang."""
    key = (a.backend, a.row["id"])
    if key not in _KP:
        _KP[key] = a.keygen()
    return _KP[key]


def _ensure(ctx):
    if not ctx.backends:
        return False, "TDD:tidak ada backend (pyca/pycryptodome/hashlib/core/liboqs) untuk kombinasi ini"
    return True, ""


class K01(Plugin):
    id, name, layer = "K-01", "KAT vektor resmi (atau uji silang dua backend)", "K"
    criteria = "100% cocok"

    def applies(self, ctx):
        ok, why = _ensure(ctx)
        if not ok:
            return ok, why
        if kat.source_for(ctx.row) or len(ctx.backends) >= 2:
            return True, ""
        return False, "TDD:vektor resmi tidak tersedia dan hanya 1 backend — uji silang tidak mungkin"

    def run(self, ctx):
        res = {}
        for a in ctx.backends:
            r = kat.run(ctx.row, a, ctx.mode)
            if r:
                res[a.backend] = r
        if res:
            tot = sum(r["total"] for r in res.values())
            ok = sum(r["matched"] for r in res.values())
            st = LULUS if ok == tot else GAGAL
            return {"status": st, "label": "KAT", "parameters": {"sumber": sorted({r["source"] for r in res.values()}), "backend": sorted(res)},
                    "actual": f"{ok}/{tot} vektor cocok", "source": "HASIL UJI LANGSUNG vs vektor resmi",
                    "evidence": {"per_backend": res}}
        return _cross(ctx)


def _cross(ctx):
    """Uji silang dua backend independen (bila vektor resmi tidak tersedia)."""
    bs = ctx.backends
    n = 8 if ctx.light else 64
    k = bs[0].kind
    mism = []
    for i in range(n):
        tag = f"x{i}"
        try:
            if k in SYM:
                key = _key(ctx, tag)
                outs = {}
                for a in bs:
                    outs[a.backend] = a.encrypt(key, _iv(a, ctx, tag), _msg(a, ctx, tag, 1 + i % 4), ctx.rand(i % 20, "aad") if k == "aead" else b"")
            elif k == "mac":
                key = _key(ctx, tag)
                outs = {a.backend: a.mac(key, ctx.rand(i * 7, tag)) for a in bs}
            elif k in ("hash", "xof"):
                m = ctx.rand(i * 13, tag)
                outs = {a.backend: (a.digest(m, 32) if k == "xof" else a.digest(m)) for a in bs}
            elif k == "kdf":
                var = ctx.row["variant"]
                if var == "PBKDF2":
                    outs = {a.backend: a.derive(ctx.rand(12, tag), ctx.rand(16, "s" + tag), 2 + i, 32) for a in bs}
                elif var == "HKDF":
                    outs = {a.backend: a.derive(ctx.rand(22, tag), ctx.rand(13, "s" + tag), ctx.rand(10, "i" + tag), 42) for a in bs}
                else:
                    outs = {a.backend: a.derive(ctx.rand(32, tag), b"label", ctx.rand(8, "c" + tag), 48) for a in bs}
            elif k == "prime":
                import random
                rnd = random.Random(ctx.seed + i)
                x = rnd.getrandbits(256) | 1
                outs = {a.backend: a.is_prime(x) for a in bs}
            elif k == "rsa_pke":
                a, b = bs[0], bs[1]
                ska, pka = a.keygen()
                skb, _ = b.keygen()                      # PEM cache sama → kunci identik di kedua backend
                m = ctx.rand(32, tag)
                outs = {"A→B": b.decrypt(skb, a.encrypt(pka, m)) == m}
                outs["ref"] = True
            elif k == "sig":
                pairs = [(x, y) for x in bs for y in bs if x is not y and hasattr(x, "export_public") and hasattr(y, "import_public")]
                if not pairs:
                    return {"status": INKON, "label": "UJI SILANG", "actual": "backend tidak dapat bertukar kunci publik", "parameters": {}}
                x, y = pairs[0]
                sk, pk = x.keygen()
                m = ctx.rand(40, tag)
                outs = {"sign→verify": y.verify(y.import_public(x.export_public(pk)), m, x.sign(sk, m)), "ref": True}
            elif k == "kex":
                x, y = bs[0], bs[1]
                ska, pka = x.keygen()
                skb, pkb = y.keygen()
                s1 = x.agree(ska, x.import_public(y.export_public(pkb)))
                s2 = y.agree(skb, y.import_public(x.export_public(pka)))
                outs = {"A": s1, "B": s2}
            else:
                return {"status": TDD, "label": "UJI SILANG", "actual": None, "reason": f"uji silang belum didukung untuk jenis {k}", "parameters": {}}
        except Exception as e:
            mism.append({"i": i, "error": f"{type(e).__name__}: {e}"[:200]})
            continue
        if len(set(map(lambda v: bytes(v) if isinstance(v, (bytes, bytearray)) else v, outs.values()))) != 1:
            mism.append({"i": i, "outputs": {b: (v.hex()[:64] if isinstance(v, (bytes, bytearray)) else v) for b, v in outs.items()}})
    st = LULUS if not mism else GAGAL
    return {"status": st, "label": "UJI SILANG", "parameters": {"backend": [a.backend for a in bs], "sampel": n},
            "actual": f"{n - len(mism)}/{n} keluaran identik antar-backend",
            "reason": "vektor resmi tidak tersedia — uji silang dua backend independen (bukan KAT)",
            "evidence": {"mismatches": mism[:10]} if mism else None}


class K02(Plugin):
    id, name, layer = "K-02", "Round-trip D(E(x)) = x / Verify(Sign(m)) / Decaps(Encaps)", "K"
    criteria = "100% round-trip benar"

    def applies(self, ctx):
        ok, why = _ensure(ctx)
        if not ok:
            return ok, why
        if ctx.kind in SYM + ("rsa_pke", "kem", "kex", "sig"):
            return True, ""
        return False, "tidak berlaku untuk hash/MAC/KDF/prima"

    def run(self, ctx):
        n = 4 if ctx.light else 32
        if (ctx.row.get("key_bits") or 0) > 4096 and ctx.row["family"] == "RSA":
            n = 2 if ctx.light else 8
        bad, total = [], 0
        for a in ctx.backends:
            for i in range(n):
                total += 1
                tag = f"r{a.backend}{i}"
                try:
                    if a.kind in SYM:
                        key, iv, m = _key(ctx, tag), _iv(a, ctx, tag), _msg(a, ctx, tag, 1 + i)
                        aad = ctx.rand(7, "aad") if a.kind == "aead" else b""
                        ok = a.decrypt(key, iv, a.encrypt(key, iv, m, aad), aad) == m
                    elif a.kind == "rsa_pke":
                        sk, pk = _kp(a)
                        m = ctx.rand(min(32, a.max_msg), tag)
                        ok = a.decrypt(sk, a.encrypt(pk, m)) == m
                    elif a.kind == "kem":
                        sk, pk = a.keygen()
                        ct, ss = a.encaps(pk)
                        ok = a.decaps(sk, ct) == ss
                    elif a.kind == "kex":
                        s1, p1 = a.keygen()
                        s2, p2 = a.keygen()
                        ok = a.agree(s1, p2) == a.agree(s2, p1)
                    else:
                        sk, pk = _kp(a) if ctx.row["family"] in ("RSA", "DSA") else a.keygen()
                        m = ctx.rand(50 + i, tag)
                        ok = a.verify(pk, m, a.sign(sk, m))
                except Exception as e:
                    ok = False
                    bad.append({"backend": a.backend, "i": i, "error": f"{type(e).__name__}: {e}"[:200]})
                    continue
                if not ok:
                    bad.append({"backend": a.backend, "i": i})
        return {"status": LULUS if not bad else GAGAL, "parameters": {"backend": [a.backend for a in ctx.backends], "percobaan_per_backend": n},
                "actual": f"{total - len(bad)}/{total} round-trip benar", "evidence": {"failures": bad[:10]} if bad else None}


class K03(Plugin):
    id, name, layer = "K-03", "Monte Carlo / pesan multi-blok / one-shot vs bertahap", "K"
    criteria = "hasil identik"

    def applies(self, ctx):
        ok, why = _ensure(ctx)
        if not ok:
            return ok, why
        if ctx.kind in ("hash", "xof"):
            return True, ""
        if ctx.kind in SYM and ctx.row["primitive"] == "block_cipher":
            if getattr(ctx.backends[0], "mode", "") in ("KW", "KWP"):
                return False, "tidak berlaku untuk key wrap (MCT tidak didefinisikan)"
            if len(ctx.backends) >= 2 or getattr(ctx.backends[0], "mode", "") in ("ECB", "CBC", "CTR"):
                return True, ""
            return False, "TDD:MCT butuh ≥ 2 backend; pemecahan multi-blok tidak didefinisikan untuk mode ini"
        return False, "hanya untuk block cipher & hash"

    def run(self, ctx):
        if ctx.kind in ("hash", "xof"):
            bad, total = [], 0
            for a in ctx.backends:
                for i, L in enumerate([0, 1, 55, 64, 135, 136, 137, 1000, 4097]):
                    m = ctx.rand(L, f"h{i}")
                    cuts = sorted({(j * 7919) % (L + 1) for j in range(1, 6)}) if L else []
                    chunks, prev = [], 0
                    for c in cuts + [L]:
                        chunks.append(m[prev:c])
                        prev = c
                    total += 1
                    one = a.digest(m, 32) if ctx.kind == "xof" else a.digest(m)
                    inc = a.digest_chunks(chunks, 32) if ctx.kind == "xof" else a.digest_chunks(chunks)
                    if one != inc:
                        bad.append({"backend": a.backend, "len": L})
            return {"status": LULUS if not bad else GAGAL, "parameters": {"panjang_pesan": [0, 1, 55, 64, 135, 136, 137, 1000, 4097]},
                    "actual": f"{total - len(bad)}/{total} one-shot = bertahap", "evidence": {"failures": bad} if bad else None}
        it = 20 if ctx.light else 1000
        bs = ctx.backends
        if len(bs) >= 2:                                 # Monte Carlo berantai, dibandingkan antar-backend
            finals = {}
            for a in bs:
                key, iv, x = _key(ctx, "mct"), _iv(a, ctx, "mct"), _msg(a, ctx, "mct", 1)
                aad = b"" if a.kind != "aead" else b"mct"
                for _ in range(it):
                    y = a.encrypt(key, iv, x, aad)
                    x = y[:len(x)]
                finals[a.backend] = x.hex()
            ok = len(set(finals.values())) == 1
            return {"status": LULUS if ok else GAGAL, "label": "MCT uji silang", "parameters": {"iterasi": it, "backend": list(finals)},
                    "actual": "keluaran akhir identik" if ok else "keluaran akhir berbeda", "evidence": {"final": finals}}
        a = bs[0]                                         # MMT: pemecahan pesan (ECB/CBC/CTR)
        key, iv = _key(ctx, "mmt"), _iv(a, ctx, "mmt")
        m1, m2 = ctx.rand(32, "m1"), ctx.rand(48, "m2")
        whole = a.encrypt(key, iv, m1 + m2)
        if a.mode == "ECB":
            part = a.encrypt(key, None, m1) + a.encrypt(key, None, m2)
        elif a.mode == "CBC":
            c1 = a.encrypt(key, iv, m1)
            part = c1 + a.encrypt(key, c1[-16:], m2)
        else:
            c1 = a.encrypt(key, iv, m1)
            iv2 = ((int.from_bytes(iv, "big") + 2) % (1 << 128)).to_bytes(16, "big")
            part = c1 + a.encrypt(key, iv2, m2)
        ok = whole == part
        return {"status": LULUS if ok else GAGAL, "label": "MMT", "parameters": {"blok": [2, 3], "mode": a.mode},
                "actual": "E(m1∥m2) = E(m1) ∥ E(m2 | IV lanjutan)" if ok else "berbeda"}


class K04(Plugin):
    id, name, layer = "K-04", "Uji negatif: panjang kunci/IV salah, tag/tanda tangan diubah 1 bit", "K"
    criteria = "seluruh masukan negatif ditolak"

    def applies(self, ctx):
        ok, why = _ensure(ctx)
        if not ok:
            return ok, why
        return True, ""

    def run(self, ctx):
        cases = []

        def expect_reject(label, fn):
            try:
                out = fn()
                rejected = out is False or out is None
            except Exception:
                rejected = True
            cases.append({"case": label, "rejected": rejected})

        def expect_differs(label, a_, b_):
            cases.append({"case": label, "rejected": a_ != b_})
        for a in ctx.backends:
            k = a.kind
            p = f"[{a.backend}] "
            if k in SYM:
                key, iv = _key(ctx, "n"), _iv(a, ctx, "n")
                m = _msg(a, ctx, "n", 2)
                expect_reject(p + "kunci terlalu pendek (key − 1 byte)", lambda: a.encrypt(key[:-1], iv, m))
                expect_reject(p + "kunci 0 byte", lambda: a.encrypt(b"", iv, m))
                if k == "aead":
                    ct = bytearray(a.encrypt(key, iv, m, b"x"))
                    ct[-1] ^= 1
                    expect_reject(p + "tag diubah 1 bit", lambda: a.decrypt(key, iv, bytes(ct), b"x"))
                    expect_reject(p + "AAD diubah", lambda: a.decrypt(key, iv, a.encrypt(key, iv, m, b"x"), b"y"))
                elif getattr(a, "mode", "") in ("KW", "KWP"):
                    w = bytearray(a.encrypt(key, None, m))
                    w[0] ^= 1
                    expect_reject(p + "ciphertext wrap diubah 1 bit", lambda: a.decrypt(key, None, bytes(w)))
                elif getattr(a, "needs_iv", False):
                    expect_reject(p + "IV panjang salah (IV − 1 byte)", lambda: a.encrypt(key, iv[:-1], m))
                if getattr(a, "full_blocks", False):
                    expect_reject(p + "panjang data bukan kelipatan blok", lambda: a.encrypt(key, iv, m + b"\x01"))
            elif k == "mac":
                key = _key(ctx, "n")
                m = ctx.rand(33, "n")
                t = a.mac(key, m)
                mm = bytearray(m)
                mm[0] ^= 1
                expect_differs(p + "pesan diubah 1 bit → tag berbeda", t, a.mac(key, bytes(mm)))
                if ctx.row["family"] == "AES":
                    expect_reject(p + "kunci AES panjang salah", lambda: a.mac(key[:-1], m))
            elif k in ("hash", "xof"):
                expect_reject(p + "masukan bertipe str (bukan bytes)", lambda: a.digest("abc"))
                d1 = a.digest(b"abc", 32) if k == "xof" else a.digest(b"abc")
                d2 = a.digest(b"abd", 32) if k == "xof" else a.digest(b"abd")
                expect_differs(p + "pesan diubah 1 bit → digest berbeda", d1, d2)
                if k == "xof":
                    expect_reject(p + "panjang keluaran XOF negatif", lambda: a.digest(b"abc", -1))
            elif k == "rsa_pke":
                sk, pk = a.keygen()
                c = bytearray(a.encrypt(pk, b"cryptan"))
                c[-1] ^= 1
                expect_reject(p + "ciphertext diubah 1 bit", lambda: a.decrypt(sk, bytes(c)))
                expect_reject(p + "ciphertext terpotong", lambda: a.decrypt(sk, bytes(c[:-1])))
                expect_reject(p + "pesan melebihi kapasitas", lambda: a.encrypt(pk, b"\x00" * (a.max_msg + 1)))
            elif k == "kem":
                sk, pk = a.keygen()
                ct, ss = a.encaps(pk)
                bad = bytearray(ct)
                bad[0] ^= 1
                expect_differs(p + "ciphertext diubah 1 bit → shared secret berbeda (implicit rejection)", ss, a.decaps(sk, bytes(bad)))
                expect_reject(p + "ciphertext terpotong", lambda: a.decaps(sk, bytes(ct[:-1])))
            elif k == "kex":
                sk, pk = a.keygen()
                raw = a.export_public(pk)
                bad = bytearray(raw)
                bad[-1] ^= 1
                if ctx.row["family"] == "XECDH":
                    expect_reject(p + "kunci publik lawan nol (low-order) → shared secret nol ditolak",
                                  lambda: a.agree(sk, a.import_public(b"\x00" * len(raw))))
                else:
                    expect_reject(p + "titik kunci publik lawan di luar kurva (1 bit diubah)", lambda: a.agree(sk, a.import_public(bytes(bad))))
                expect_reject(p + "kunci publik panjang salah", lambda: a.agree(sk, a.import_public(raw[:-1])))
            elif k == "sig":
                sk, pk = a.keygen()
                m = ctx.rand(40, "n")
                s = bytearray(a.sign(sk, m))
                s2 = bytearray(s)
                s2[len(s2) // 2] ^= 1
                expect_reject(p + "tanda tangan diubah 1 bit", lambda: a.verify(pk, m, bytes(s2)))
                expect_reject(p + "pesan diubah", lambda: a.verify(pk, m + b"x", bytes(s)))
                expect_reject(p + "tanda tangan terpotong", lambda: a.verify(pk, m, bytes(s[:-1])))
            elif k == "kdf":
                var = ctx.row["variant"]
                if var == "HKDF":
                    expect_reject(p + "panjang keluaran > 255·HashLen", lambda: a.derive(b"k" * 16, b"", b"", 255 * 32 + 1))
                elif var == "PBKDF2":
                    expect_reject(p + "iterasi 0", lambda: a.derive(b"pw", b"salt", 0, 32))
                expect_reject(p + "panjang keluaran negatif", lambda: a.derive(*((b"k" * 16, b"", b"", -1) if var == "HKDF" else
                                                                               (b"pw", b"salt", 1, -1) if var == "PBKDF2" else (b"k" * 16, b"l", b"c", -1))))
            elif k == "prime":
                for n_ in (561, 41041, 3215031751, (2 ** 61 - 1) * (2 ** 31 - 1)):
                    expect_reject(p + f"bilangan komposit {n_}", lambda: a.is_prime(n_))
        if not cases:
            return {"status": TDD, "actual": None, "reason": "tidak ada kasus negatif untuk jenis ini", "parameters": {}}
        bad = [c for c in cases if not c["rejected"]]
        return {"status": LULUS if not bad else GAGAL, "parameters": {"kasus": len(cases)},
                "actual": f"{len(cases) - len(bad)}/{len(cases)} masukan negatif ditolak",
                "evidence": {"cases": cases}}
