"""Cryptan.ID Test Suite — Modul UK-2 (Menyusun Skenario Pengujian).

  python -m uk2_skenario --profile config/product_profile.yaml --uk1 outputs/uk1/uk1_penetapan_metode.json
  python -m uk2_skenario --profile config/product_profile.yaml --uk1 outputs/uk1            # folder: 5 algoritma
  python -m uk2_skenario --samples                                                          # 3 profil sampel materi
"""
import argparse
import sys
import time
from pathlib import Path

from core import APP_NAME

from . import pipeline
from .context import ContextError

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ["ecdsa_p256_token", "tls13_gateway", "hsm_x_sl3"]


def _report(name, res, dt):
    R, f = res["result"], res["files"]
    tcs = R["test_cases"]
    print(f"\n■ {name} — {dt:.1f} s · model {R['profile']['testing_model']} tingkat · {len(R['profile']['objects'])} objek uji")
    for n in R["inputs"]["notes"]:
        print(f"  ! {n}")
    s = R["method_review"]["summary"]
    print(f"  KUK 1.1 metode UK-1   : {s['methods']} ditelaah, {s['relevant']} relevan, {s['cells_empty']} sel kosong → templat")
    pw = [(c, v["pairwise"]["full_combinations"], v["pairwise"]["pairwise_combinations"]) for c, v in R["param_space"]["categories"].items()]
    print("  KUK 1.2 pairwise      : " + ", ".join(f"{c} {a:,}→{b}".replace(",", ".") for c, a, b in pw))
    print(f"  KUK 2.1 skenario      : {len(R['scenarios'])} sel · {R['design']['summary']['recipes']} resep · {R['design']['summary']['excluded']} tidak berlaku")
    print(f"  KUK 2.2 verifikasi    : {R['verification']['status']} ({R['verification']['total_findings']} temuan) — "
          + " ".join(f"({r['rule']}){r['status'][0]}" for r in R["verification"]["rules"]))
    print(f"  KUK 2.3 test case     : {len(tcs)} (K {sum(t['layer'] == 'K' for t in tcs)} · S {sum(t['layer'] == 'S' for t in tcs)} · I {sum(t['layer'] == 'I' for t in tcs)})")
    e = R["expected"]["summary"]
    print(f"  KUK 2.4 expected      : {e['COCOK_VEKTOR_RESMI']} cocok vektor resmi · {e['KRITERIA']} kriteria · {e['PERLU_VERIFIKASI']} PERLU_VERIFIKASI")
    print(f"  KUK 2.5 kompilasi     : {len(R['traceability'])} baris keterlacakan · {len(R['outcome_map'])} pemetaan hasil · skema "
          + ("VALID" if not R["schema_errors"] else f"{len(R['schema_errors'])} galat"))
    for k, p in f.items():
        print(f"  → {p}")
    return 0 if not R["schema_errors"] else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m uk2_skenario", description=f"{APP_NAME} — UK-2 Menyusun Skenario Pengujian")
    ap.add_argument("--profile", default="config/product_profile.yaml")
    ap.add_argument("--uk1", default="outputs/uk1", help="uk1_penetapan_metode.json, folder outputs/uk1, atau stub STUB_UK1")
    ap.add_argument("--out", default="outputs/uk2")
    ap.add_argument("--samples", action="store_true", help="jalankan 3 profil sampel materi (samples/uk2/*)")
    ap.add_argument("--no-docx", action="store_true")
    a = ap.parse_args(argv)
    print(f"{APP_NAME} · UK-2 Menyusun Skenario Pengujian")
    rc = 0
    jobs = ([(f"sampel {s}", ROOT / "samples" / "uk2" / s / "product_profile.yaml", ROOT / "samples" / "uk2" / s / "uk1_stub.json",
              ROOT / "samples" / "uk2" / s / "output") for s in SAMPLES] if a.samples else [("produk", a.profile, a.uk1, Path(a.out))])
    for name, prof, uk1, out in jobs:
        uk1p = Path(uk1)
        if uk1p.is_dir() is False and uk1p.name == "uk1_penetapan_metode.json" and not uk1p.exists() and (uk1p.parent / "index.json").exists():
            uk1 = uk1p.parent                                     # UK-1 kita: satu JSON per algoritma (folder)
        t0 = time.time()
        try:
            res = pipeline.run(str(prof), str(uk1) if uk1 else None, Path(out), docx=not a.no_docx)
        except ContextError as e:
            print(f"[GALAT] {e}", file=sys.stderr)
            return 2
        rc |= _report(name, res, time.time() - t0)
    return rc


if __name__ == "__main__":
    sys.exit(main())
