"""Lapis I — Uji Implementasi: I-01 variasi waktu (indikatif) · I-02 kinerja (dicatat) · I-03 penanganan galat."""
import time

from core.stats import welch_t

from . import DICATAT, INKON, LULUS, GAGAL, Plugin
from .k import SYM, _iv, _key, _msg

SECRET_KINDS = SYM + ("mac", "rsa_pke", "sig", "kex", "kem")


class I01(Plugin):
    id, name, layer = "I-01", "Variasi waktu sederhana (fixed-vs-random, uji t Welch)", "I"
    criteria = "|t| < 4,5 (hanya indikatif)"
    label = "INDIKATIF"

    def applies(self, ctx):
        if not ctx.backends:
            return False, "TDD:tidak ada backend"
        if ctx.kind in SECRET_KINDS:
            if ctx.light and getattr(ctx.backends[0], "slow", False):
                return False, "TDD:hanya backend referensi pure-Python yang lambat — sampel waktu tidak muat di anggaran mode ringan; jalankan --mode full"
            return True, ""
        return False, "tidak ada operasi dengan kunci rahasia"

    def run(self, ctx):
        a = ctx.backends[0]
        N = 300 if ctx.light else 5000
        if a.kind in SYM:
            key, iv = _key(ctx, "t"), _iv(a, ctx, "t")
            fixed = _msg(a, ctx, "fixed", 2)
            op = lambda x: a.encrypt(key, iv, x)
            rnd = lambda i: _msg(a, ctx, f"r{i}", 2)
        elif a.kind == "mac":
            key = _key(ctx, "t")
            fixed = ctx.rand(64, "fixed")
            op = lambda x: a.mac(key, x)
            rnd = lambda i: ctx.rand(64, f"r{i}")
        elif a.kind == "rsa_pke":
            sk, pk = a.keygen()
            fixed = a.encrypt(pk, b"fixed")
            N = min(N, 120 if (ctx.row.get("key_bits") or 0) <= 4096 else 8)
            cts = [a.encrypt(pk, ctx.rand(16, f"r{i}")) for i in range(min(N, 60))]
            op = lambda c: a.decrypt(sk, c)
            rnd = lambda i: cts[i % len(cts)]
        elif a.kind == "sig":
            sk, pk = a.keygen()
            fixed = ctx.rand(32, "fixed")
            op = lambda m: a.sign(sk, m)
            rnd = lambda i: ctx.rand(32, f"r{i}")
            N = min(N, 150 if (ctx.row.get("key_bits") or 0) <= 3072 else 40)
        elif a.kind == "kex":
            sk, _ = a.keygen()
            fixed_pk = a.keygen()[1]
            peers = [a.keygen()[1] for _ in range(20)]
            fixed = fixed_pk
            op = lambda p: a.agree(sk, p)
            rnd = lambda i: peers[i % len(peers)]
            N = min(N, 150)
        else:                                             # kem
            sk, pk = a.keygen()
            fixed = a.encaps(pk)[0]
            cts = [a.encaps(pk)[0] for _ in range(20)]
            op = lambda c: a.decaps(sk, c)
            rnd = lambda i: cts[i % len(cts)]
            N = min(N, 150)
        tf, tr = [], []
        for _ in range(min(5, max(1, N // 8))):           # pemanasan
            op(fixed)
            op(rnd(0))
        order = ctx.rand(N, "order")                       # urutan kelas diacak per pengukuran (dudect)
        for i in range(N):
            x = rnd(i)
            first_fixed = order[i] & 1
            for which in ((0, 1) if first_fixed else (1, 0)):
                arg = fixed if which == 0 else x
                t0 = time.perf_counter_ns()
                op(arg)
                d = time.perf_counter_ns() - t0
                (tf if which == 0 else tr).append(d)
        t = welch_t(tf, tr)
        return {"status": LULUS if abs(t) < 4.5 else INKON, "label": "INDIKATIF",
                "parameters": {"pengukuran_per_kelas": N, "backend": a.backend, "timer": "perf_counter_ns (proses Python)"},
                "actual": f"|t| = {abs(t):.2f}",
                "reason": "" if abs(t) < 4.5 else "|t| ≥ 4,5 pada pengukuran kasar dari Python — indikatif; konfirmasi dengan dudect/lab (ISO/IEC 17825)",
                "evidence": {"t": t, "median_fixed_ns": sorted(tf)[len(tf) // 2], "median_random_ns": sorted(tr)[len(tr) // 2]}}


class I02(Plugin):
    id, name, layer = "I-02", "Kinerja: operasi/detik, MB/detik", "I"
    criteria = "dicatat, tanpa lulus/gagal"

    def applies(self, ctx):
        return (True, "") if ctx.backends else (False, "TDD:tidak ada backend")

    def run(self, ctx):
        budget = 0.05 if ctx.light else 0.5
        out = {}
        for a in ctx.backends:
            k = a.kind
            if k in SYM:
                key, iv = _key(ctx, "p"), _iv(a, ctx, "p")
                size = 4096 if getattr(a, "mode", "") not in ("KW", "KWP") else 64
                if a.backend == "core":
                    size = 16 if getattr(a, "mode", "") == "CFB1" else 256
                m = _msg(a, ctx, "p", size // 16)[:size] if not getattr(a, "full_blocks", False) else ctx.rand(size, "p")
                fn = lambda: a.encrypt(key, iv, m)
            elif k == "mac":
                key, m, size = _key(ctx, "p"), ctx.rand(4096, "p"), 4096
                fn = lambda: a.mac(key, m)
            elif k in ("hash", "xof"):
                m, size = ctx.rand(65536 if a.backend != "core" else 1024, "p"), 65536 if a.backend != "core" else 1024
                fn = (lambda: a.digest(m, 32)) if k == "xof" else (lambda: a.digest(m))
            elif k == "kdf":
                var, size = ctx.row["variant"], 0
                fn = (lambda: a.derive(b"pw", b"salt" * 4, 1000, 32)) if var == "PBKDF2" else \
                     (lambda: a.derive(b"k" * 32, b"s", b"i", 64)) if var == "HKDF" else (lambda: a.derive(b"k" * 32, b"l", b"c", 64))
            elif k == "rsa_pke":
                sk, pk = a.keygen()
                c, size = a.encrypt(pk, b"x" * 16), 0
                fn = lambda: a.decrypt(sk, c)
            elif k == "sig":
                sk, pk = a.keygen()
                size = 0
                fn = lambda: a.sign(sk, b"m" * 32)
            elif k == "kex":
                sk, _ = a.keygen()
                pk2, size = a.keygen()[1], 0
                fn = lambda: a.agree(sk, pk2)
            elif k == "kem":
                sk, pk = a.keygen()
                ct, size = a.encaps(pk)[0], 0
                fn = lambda: a.decaps(sk, ct)
            elif k == "prime":
                size = 0
                fn = lambda: a.is_prime((1 << 127) - 1)
            else:
                continue
            n, t0 = 0, time.perf_counter()
            while True:
                fn()
                n += 1
                el = time.perf_counter() - t0
                if el >= budget and n >= 3:
                    break
            ops = n / el
            out[a.backend] = {"ops_per_sec": round(ops, 1), "MB_per_sec": round(ops * size / 1e6, 2) if size else None,
                              "ukuran_masukan_byte": size or None}
        return {"status": DICATAT, "label": "dicatat", "parameters": {"anggaran_waktu_s": budget},
                "actual": "; ".join(f"{b}: {v['ops_per_sec']:,.0f} ops/s".replace(",", ".") + (f", {v['MB_per_sec']} MB/s" if v["MB_per_sec"] else "")
                                    for b, v in out.items()),
                "evidence": {"per_backend": out}}


class I03(Plugin):
    id, name, layer = "I-03", "Penanganan galat: input malformed tanpa crash, pesan galat seragam", "I"
    criteria = "tanpa crash"

    def applies(self, ctx):
        return (True, "") if ctx.backends else (False, "TDD:tidak ada backend")

    def run(self, ctx):
        crashes, cases, err_classes = [], 0, {}
        malformed = [b"", b"\x00", b"\xff" * 3, b"\x00" * 1000, bytes(range(256))]
        if ctx.light and any(getattr(a, "slow", False) for a in ctx.backends):
            malformed = malformed[:3] + [b"\x00" * 33]       # backend lambat: masukan panjang dipendekkan (mode ringan)

        def probe(label, fn, group=None):
            nonlocal cases
            cases += 1
            try:
                fn()
            except Exception as e:                        # galat terkendali = diterima (bukan crash)
                if group:
                    err_classes.setdefault(group, set()).add(type(e).__name__)
            except BaseException as e:                    # pragma: no cover — crash proses / keluar paksa
                crashes.append({"case": label, "error": type(e).__name__})
        for a in ctx.backends:
            k = a.kind
            kp = a.keygen() if k in ("rsa_pke", "sig", "kem") else (None, None)
            for j, junk in enumerate(malformed):
                if k in SYM:
                    key, iv = _key(ctx, "e"), _iv(a, ctx, "e")
                    probe(f"{a.backend} decrypt junk{j}", lambda: a.decrypt(key, iv, junk), group=f"{a.backend}:decrypt")
                    probe(f"{a.backend} key junk{j}", lambda: a.encrypt(junk, iv, b"\x00" * 16))
                elif k == "mac":
                    probe(f"{a.backend} mac junk{j}", lambda: a.mac(junk, junk))
                elif k in ("hash", "xof"):
                    probe(f"{a.backend} digest junk{j}", lambda: a.digest(junk * 50))
                elif k == "rsa_pke":
                    sk, pk = kp
                    probe(f"{a.backend} decrypt junk{j}", lambda: a.decrypt(sk, junk), group=f"{a.backend}:decrypt")
                elif k == "sig":
                    sk, pk = kp
                    probe(f"{a.backend} verify junk{j}", lambda: a.verify(pk, b"m", junk))
                    if hasattr(a, "import_public"):
                        probe(f"{a.backend} import pk junk{j}", lambda: a.import_public(junk))
                elif k in ("kex", "kem"):
                    if hasattr(a, "import_public"):
                        probe(f"{a.backend} import pk junk{j}", lambda: a.import_public(junk))
                    if k == "kem":
                        sk, pk = kp
                        probe(f"{a.backend} decaps junk{j}", lambda: a.decaps(sk, junk))
                elif k == "kdf":
                    probe(f"{a.backend} derive junk{j}", lambda: a.derive(junk, junk, junk, 32) if ctx.row["variant"] != "PBKDF2" else a.derive(junk, junk, 1, 32))
                elif k == "prime":
                    probe(f"{a.backend} is_prime junk{j}", lambda: a.is_prime(int.from_bytes(junk or b"\x01", "big")))
        uniform = {g: sorted(v) for g, v in err_classes.items()}
        nonuni = [g for g, v in uniform.items() if len(v) > 1]
        st = GAGAL if crashes else LULUS
        return {"status": st, "parameters": {"masukan_malformed": cases},
                "actual": f"{cases - len(crashes)}/{cases} tanpa crash" + (f"; kelas galat dekripsi tidak seragam: {nonuni}" if nonuni else "; galat dekripsi seragam per backend" if uniform else ""),
                "notes": [f"kelas galat {g}: {v}" for g, v in uniform.items()],
                "evidence": {"crashes": crashes, "error_classes": uniform}}
