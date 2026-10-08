"""Lab Keacakan (Bagian 3): satu pintu untuk GUI & CLI — Golomb, five basic tests, SP 800-22 bawaan,
kompleksitas linear. Hasil disimpan beserta SHA-256 masukan."""
import datetime as dt
import hashlib
import json
from pathlib import Path

import numpy as np

from .. import OUT
from . import basic5, golomb, lfsr, sp80022

NOTES = ["Five basic tests hanya untuk studi kasus; hasil resmi memakai NIST STS lengkap.",
         "Lolos uji keacakan adalah syarat perlu, bukan syarat cukup (m-sequence lolos Golomb tetapi dapat dipulihkan dari 2L bit).",
         "Uji statistik hanya dapat menolak keacakan, tidak membuktikannya."]
ALL = ("golomb", "basic5", "sp80022", "linear")


def run_lab(bits, tests=ALL, poker_m=None, d=8, block_m=None, max_tau=10, enforce_min=True, sp_tests=None) -> dict:
    e = sp80022.to_bits(bits)
    n = int(e.size)
    res = {"n": n, "n0": int(n - e.sum()), "n1": int(e.sum()), "sha256_masukan": hashlib.sha256("".join(map(str, e)).encode()).hexdigest(),
           "catatan": NOTES}
    if "golomb" in tests:
        res["golomb"] = golomb.check(e, max_tau=min(max_tau, n - 1) if max_tau else None)
    if "basic5" in tests:
        res["basic5"] = basic5.run_all(e, poker_m, d)
    if "sp80022" in tests:
        bm = block_m or (128 if n >= 12800 else max(20, n // 10) if n >= 200 else 10)
        res["sp80022"] = sp80022.run_tests(e, sp_tests, block_m=bm, enforce_min=enforce_min)
    if "linear" in tests:
        res["linear"] = lfsr.berlekamp_massey(e[:5000].tolist())
        res["linear"]["n_dianalisis"] = min(n, 5000)
        res["linear"]["harapan_acak"] = min(n, 5000) / 2
    return res


def save(res, label="lab", out_root=None) -> Path:
    d = (Path(out_root) if out_root else OUT) / "lab_keacakan"
    d.mkdir(parents=True, exist_ok=True)
    f = d / f"{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}_{label}.json"
    f.write_text(json.dumps(res, indent=1, ensure_ascii=False, default=lambda o: o.tolist() if isinstance(o, np.ndarray) else str(o)),
                 encoding="utf-8")
    return f


def text_report(res) -> str:
    out = [f"n = {res['n']} (n₀ = {res['n0']}, n₁ = {res['n1']}), SHA-256 masukan {res['sha256_masukan'][:16]}…"]
    if "golomb" in res:
        g = res["golomb"]
        out.append(f"Golomb: G1 {'✓' if g['G1']['ok'] else '✗'} (|n₁−n₀| = {g['G1']['diff']}), G2 {'✓' if g['G2']['ok'] else '✗'} "
                   f"({g['G2']['runs']} run siklik), G3 {'✓' if g['G3']['ok'] else '✗'} → {g['conclusion']}")
    if "basic5" in res:
        out.append("Five basic tests (α = 0,01):")
        for t in res["basic5"]["tests"]:
            if t.get("statistic") is None:
                out.append(f"  {t['test']:<13} tidak dapat dijalankan ({t.get('reason')})")
            else:
                out.append(f"  {t['test']:<13} {t['statistic_name']} = {t['statistic']:.4f}  kritis {t['critical']:.4f}  "
                           f"p = {t['p_value']:.4f}  {t['decision']}")
        out.append("  " + res["basic5"]["summary"])
    if "sp80022" in res:
        out.append("SP 800-22 bawaan:")
        for t in res["sp80022"]:
            out.append(f"  {t['name']:<32} " + (f"p = {t['p_value']:.6f}  {t['status']}" if t["p_value"] is not None
                                                else f"{t['status']} ({t.get('reason')})"))
    if "linear" in res:
        out.append(f"Kompleksitas linear (Berlekamp–Massey, {res['linear']['n_dianalisis']} bit): L = {res['linear']['L']} "
                   f"(harapan acak ≈ {res['linear']['harapan_acak']:.0f})")
    out += [f"Catatan: {x}" for x in res["catatan"]]
    return "\n".join(out)
