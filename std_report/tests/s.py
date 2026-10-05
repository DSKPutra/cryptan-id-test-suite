"""Lapis S — Uji Keamanan: S-01 avalanche · S-02 subset SP 800-22 · S-03 sifat komponen · S-04 kecukupan parameter."""
import math
from functools import lru_cache

from .. import sp80022
from . import ACUAN, GAGAL, INKON, LULUS, Plugin
from .k import SYM, _iv, _key

STREAMLIKE = {"CTR", "OFB", "CFB1", "CFB8", "CFB128", "GCM", "CCM", "GCM-SIV"}
IR8547 = "NIST IR 8547 (ipd): algoritme rentan kuantum 112-bit deprecated setelah 2030, seluruhnya disallowed setelah 2035"


def _hw(b):
    return sum(bin(x).count("1") for x in b)


def _flip(b, bit):
    x = bytearray(b)
    x[bit // 8] ^= 1 << (bit % 8)
    return bytes(x)


class S01(Plugin):
    id, name, layer = "S-01", "Avalanche (plaintext, kunci, pesan)", "S"
    criteria = "rata-rata ≈ n/2; peluang flip per bit 0,49–0,51 (mode full)"

    def applies(self, ctx):
        if not ctx.backends:
            return False, "TDD:tidak ada backend"
        if ctx.row["primitive"] in ("block_cipher", "stream_cipher", "hash") and ctx.kind in SYM + ("hash", "xof"):
            if getattr(ctx.backends[0], "mode", "") in ("KW", "KWP"):
                return False, "tidak berlaku untuk key wrap"
            return True, ""
        return False, "hanya untuk block cipher, stream cipher, hash"

    def run(self, ctx):
        a = ctx.backends[0]
        N = 200 if ctx.light else 10000
        if ctx.light and getattr(a, "slow", False):
            N = 20
        fracs, per_bit, n_out = [], None, None
        kinds = []
        for i in range(N):
            tag = f"av{i}"
            if a.kind in ("hash", "xof"):
                m = ctx.rand(64, tag)
                f = (lambda x: a.digest(x, 32)) if a.kind == "xof" else a.digest
                o1, o2 = f(m), f(_flip(m, i % 512))
                kinds = ["pesan"]
            else:
                key, iv = _key(ctx, tag), _iv(a, ctx, tag)
                blk = 16 if a.kind == "aead" else a.block
                m = ctx.rand(blk * 2 if getattr(a, "mode", "") == "XTS" else blk, tag)
                if i % 2 == 0 or getattr(a, "mode", "") in STREAMLIKE or a.kind == "aead":
                    nb = len(key) * 8
                    bit = i % nb
                    if ctx.row["family"] == "TDEA":            # lewati bit paritas DES (LSB tiap byte, diabaikan algoritme)
                        bit = (bit // 7) * 8 + 1 + bit % 7
                        bit = bit % nb
                    k2 = _flip(key, bit)
                    o1, o2 = a.encrypt(key, iv, m), a.encrypt(k2, iv, m)
                    kinds = sorted(set(kinds) | {"kunci"})
                    o1, o2 = o1[:len(m)], o2[:len(m)]
                else:
                    bit = i % (len(m) * 8)
                    o1, o2 = a.encrypt(key, iv, m), a.encrypt(key, iv, _flip(m, bit))
                    kinds = sorted(set(kinds) | {"plaintext"})
                    j = (bit // 8 // blk) * blk if getattr(a, "mode", "") == "XTS" else 0
                    o1, o2 = o1[j:j + blk], o2[j:j + blk]           # XTS: blok lain independen (per-blok tweak) — ukur blok yang diubah
                if getattr(a, "mode", "") == "XTS":
                    o1, o2 = o1[:blk], o2[:blk]
            d = bytes(x ^ y for x, y in zip(o1, o2))
            n_out = len(d) * 8
            fracs.append(_hw(d) / n_out)
            if per_bit is None:
                per_bit = [0] * n_out
            for j in range(n_out):
                per_bit[j] += (d[j // 8] >> (j % 8)) & 1
        mean = sum(fracs) / N
        band = 3 * 0.5 / math.sqrt(n_out * N)
        pb = [c / N for c in per_bit]
        mean_ok = abs(mean - 0.5) <= band
        bit_ok = all(0.49 <= x <= 0.51 for x in pb) if not ctx.light else None
        hist = [0] * 21
        for f in fracs:
            hist[min(20, int(f * 20))] += 1
        if ctx.light:
            st = LULUS if mean_ok else INKON
        else:
            st = LULUS if mean_ok and bit_ok else GAGAL
        return {"status": st, "label": "INDIKATIF (mode ringan)" if ctx.light else "mode full",
                "parameters": {"sampel": N, "bit_keluaran_n": n_out, "variasi": kinds, "backend": a.backend},
                "actual": f"rerata {mean:.4f} (n/2 = {n_out / 2:.0f} bit; σ ≈ √n/2 = {math.sqrt(n_out) / 2:.2f}); "
                          f"flip per bit {min(pb):.3f}–{max(pb):.3f}",
                "criteria": f"|rerata − 0,5| ≤ {band:.4f} (3σ)" + ("" if ctx.light else "; setiap bit 0,49–0,51"),
                "evidence": {"histogram_fraction_0_1_bins20": hist, "mean": mean, "per_bit_min": min(pb), "per_bit_max": max(pb)}}


class S02(Plugin):
    id, name, layer = "S-02", "Keacakan keluaran — subset SP 800-22 (6 uji)", "S"
    criteria = "α = 0,01; proporsi ≥ 0,99 − 3√(0,99·0,01/s); P-value_T ≥ 0,0001"

    def applies(self, ctx):
        if not ctx.backends:
            return False, "TDD:tidak ada backend"
        if ctx.row["primitive"] in ("block_cipher", "stream_cipher", "hash", "drbg") and ctx.kind in SYM + ("hash", "xof"):
            if getattr(ctx.backends[0], "mode", "") in ("KW", "KWP"):
                return False, "tidak berlaku untuk key wrap"
            if ctx.light and getattr(ctx.backends[0], "slow", False):
                return False, "TDD:hanya backend referensi pure-Python (~1,6 kbit/s) — 10⁶ bit tidak muat di anggaran mode ringan; jalankan --mode full"
            return True, ""
        return False, "hanya untuk block (keystream), stream, hash, DRBG"

    def _seq(self, ctx, a, idx, nbits):
        nbytes = nbits // 8
        if a.kind in ("hash", "xof"):
            if a.kind == "xof":
                return a.digest(ctx.rand(32, f"s{idx}"), nbytes)
            out, h, i = bytearray(), ctx.rand(32, f"s{idx}"), 0
            while len(out) < nbytes:
                h = a.digest(h + i.to_bytes(4, "big"))
                out += h
                i += 1
            return bytes(out[:nbytes])
        key, iv = _key(ctx, f"s{idx}"), _iv(a, ctx, f"s{idx}")
        blk = 16 if a.kind == "aead" else a.block
        if getattr(a, "mode", "") == "ECB":
            pt = b"".join(i.to_bytes(blk, "big") for i in range(nbytes // blk + 1))
        else:
            pt = bytes(nbytes + blk)
        return a.encrypt(key, iv, pt[:((nbytes + blk - 1) // blk) * blk] if getattr(a, "full_blocks", False) or getattr(a, "mode", "") == "XTS" else pt[:nbytes])[:nbytes]

    def run(self, ctx):
        a = ctx.backends[0]
        s, n = (10, 100_000) if ctx.light else (100, 1_000_000)
        seqs = [sp80022.bits_from_bytes(self._seq(ctx, a, i, n)) for i in range(s)]
        r = sp80022.run_all(seqs)
        prop_ok = all(t["pass_proportion"] for t in r["tests"].values())
        uni_ok = all(t["pass_uniformity"] for t in r["tests"].values())
        lo = min(t["proportion"] for t in r["tests"].values())
        if ctx.light:
            st = LULUS if prop_ok else INKON
        else:
            st = LULUS if prop_ok and uni_ok else GAGAL
        pT = [t["p_value_T"] for t in r["tests"].values() if t["p_value_T"] is not None]
        return {"status": st, "label": "INDIKATIF (mode ringan)" if ctx.light else "mode full",
                "parameters": {"barisan_s": s, "bit_per_barisan": n, "uji": sp80022.TESTS, "backend": a.backend,
                               "sumber_bit": "digest berantai" if a.kind == "hash" else "keluaran XOF" if a.kind == "xof" else "keystream/ciphertext"},
                "actual": f"proporsi terendah {lo:.2f} (min {r['tests']['frequency']['min_proportion']:.4f})"
                          + (f"; P-value_T terendah {min(pT):.4f}" if pT else "; P-value_T n/a (s < 55)"),
                "evidence": r}


@lru_cache(maxsize=None)
def _aes_props():
    from core import aes, boolean as B
    sp = B.sbox_profile(aes.SBOX, 8, 8)
    return {"NL": sp["nonlinearity"], "DU": sp["differential_uniformity"], "derajat": sp["max_coordinate_degree"],
            "branch_number": B.branch_number(aes.MIX_MATRIX)["branch_number"]}


@lru_cache(maxsize=None)
def _chi_props():
    from core import boolean as B, keccak
    sp = B.sbox_profile(keccak.CHI_SBOX, 5, 5)
    return {"DU": sp["differential_uniformity"], "derajat": sp["max_coordinate_degree"]}


AES_REF = {"NL": 112, "DU": 4, "derajat": 7, "branch_number": 5}
CHI_REF = {"DU": 8, "derajat": 2}


class S03(Plugin):
    id, name, layer = "S-03", "Sifat komponen (NL, keseragaman diferensial, derajat aljabar, branch number)", "S"
    criteria = "sesuai nilai acuan materi (AES: NL 112, DU 4, derajat 7, BN 5; χ Keccak: DU 8, derajat 2)"

    def applies(self, ctx):
        fam, var = ctx.row["family"], ctx.row["variant"]
        if fam == "AES" or (fam == "DRBG" and "AES" in ctx.row["id"]):
            return True, ""
        if fam == "SHA-3" or fam in ("KMAC",) or var.startswith("SHA3"):
            return True, ""
        return False, "komponen algoritme ini tidak tersedia di core/"

    def run(self, ctx):
        fam, var = ctx.row["family"], ctx.row["variant"]
        if fam == "AES" or "AES" in ctx.row["id"]:
            got, ref, comp = _aes_props(), AES_REF, "S-box & MixColumns AES (core/aes.py)"
        else:
            got, ref, comp = _chi_props(), CHI_REF, "χ Keccak-f[1600] (core/keccak.py)"
        ok = all(got[k] == v for k, v in ref.items())
        return {"status": LULUS if ok else GAGAL, "parameters": {"komponen": comp},
                "actual": ", ".join(f"{k} = {v}" for k, v in got.items()),
                "criteria": "acuan: " + ", ".join(f"{k} = {v}" for k, v in ref.items()),
                "source": "HASIL UJI LANGSUNG (core/boolean.py) vs " + ACUAN, "evidence": {"computed": got, "reference": ref}}


class S04(Plugin):
    id, name, layer = "S-04", "Kecukupan parameter (SP 800-57, SP 800-131A, NIST IR 8547)", "S"
    criteria = "≥ 112 bit dan status acceptable"

    def applies(self, ctx):
        return True, ""

    def run(self, ctx):
        r = ctx.row
        s, st, q = r["security_strength_bits"], r["status_nist"], r.get("quantum_vulnerable")
        nist = "FIPS" in r.get("source_body", []) or "NIST-SP" in r.get("source_body", [])
        if isinstance(s, str) and s.startswith("<"):
            s_ok, s_txt = False, f"{s} bit"
        elif isinstance(s, (int, float)):
            s_ok, s_txt = s >= 112, f"{s} bit"
        else:
            s_ok, s_txt = None, str(s)
        notes = []
        if st in ("disallowed", "deprecated", "legacy_use"):
            st_ok = False
        elif st == "acceptable":
            st_ok = True
        elif st == "not_nist":
            st_ok = None if nist else True
            notes.append("algoritme ISO/IEC (bukan NIST) — kriteria status SP 800-131A tidak berlaku")
        else:
            st_ok = None
        if q:
            notes.append(IR8547)
        if s_ok is False or st_ok is False:
            res = GAGAL
        elif s_ok is None or st_ok is None:
            res = INKON
        else:
            res = LULUS
        return {"status": res, "source": ACUAN + " (SP 800-57 Pt.1 Tabel 2, SP 800-131A Rev.2, FIPS 203–205, IR 8547)",
                "parameters": {"security_strength": s_txt, "status_nist": st, "rentan_kuantum": bool(q)},
                "actual": f"strength {s_txt}; status {st}" + (" ; rentan kuantum" if q else ""),
                "notes": notes, "reason": "; ".join(notes) if notes else ""}
