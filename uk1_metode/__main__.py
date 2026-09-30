"""Cryptan.ID Test Suite — Modul UK-1 (Menentukan Metode Pengujian).

  python -m uk1_metode --profile config/product_profile.yaml          # semua algoritma
  python -m uk1_metode --profile config/profiles/aes128.yaml          # satu algoritma
  python -m uk1_metode --profile config/product_profile.yaml --quick  # cepat (sampel kecil)
"""
import argparse
import json
import sys
import time
from pathlib import Path

from core import APP_NAME

from . import pipeline, report
from .profile import ProfileError, load_profiles


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m uk1_metode", description=f"{APP_NAME} — UK-1 Penetapan Metode & Parameter Pengujian")
    ap.add_argument("--profile", default="config/product_profile.yaml", help="profil produk (YAML)")
    ap.add_argument("--out", default="outputs/uk1", help="direktori keluaran")
    ap.add_argument("--quick", action="store_true", help="sampel kecil (untuk demo/CI)")
    ap.add_argument("--no-docx", action="store_true", help="lewati pembuatan DOCX")
    a = ap.parse_args(argv)

    try:
        profiles = load_profiles(a.profile)
    except (ProfileError, FileNotFoundError) as e:
        print(f"[GALAT] {e}", file=sys.stderr)
        return 2

    out_root = Path(a.out)
    index = {"app": APP_NAME, "module": "UK-1", "profile": a.profile, "algorithms": []}
    print(f"{APP_NAME} · UK-1 · {len(profiles)} profil")
    rc = 0
    for p in profiles:
        t0 = time.time()
        alg = p["algorithm"]["id"]
        r = pipeline.run(p, quick=a.quick)
        d = out_root / pipeline.slug(alg)
        files = report.write_all(r, d, docx=not a.no_docx)
        sel = r["selection"]
        print(f"\n■ {alg} ({r['profile']['algorithm']['primitive_label']}) — {time.time() - t0:.1f} s")
        print(f"  KAT core/          : [{r['kat']['status']}] {r['kat']['passed']}/{r['kat']['total']}")
        print(f"  Berpotensi lemah   : {', '.join(r['component_summary']['berpotensi_lemah']) or '—'}")
        print(f"  Perlu perhatian    : {', '.join(r['component_summary']['perhatian']) or '—'}")
        print(f"  Metode terpilih    : {len(sel['selected'])} → {', '.join(s['method_id'] + ('*' if s['variant'] == 'tereduksi' else '') for s in sel['selected'])}")
        print(f"  Metode ditolak     : {len(sel['rejected'])} → {', '.join(s['method_id'] for s in sel['rejected'])}")
        print(f"  Keterlacakan       : {len(r['traceability'])} baris · upaya {sel['effort_hours_total']}/{sel['person_hours_available']} jam-orang")
        for k, f in files.items():
            print(f"  → {f}")
        rc |= r["kat"]["status"] != "LULUS"
        index["algorithms"].append({
            "id": alg, "slug": pipeline.slug(alg), "primitive": r["profile"]["algorithm"]["primitive"],
            "primitive_label": r["profile"]["algorithm"]["primitive_label"], "name": r["profile"]["algorithm"]["name"],
            "kat": f"{r['kat']['passed']}/{r['kat']['total']} {r['kat']['status']}",
            "weak": r["component_summary"]["berpotensi_lemah"], "attention": r["component_summary"]["perhatian"],
            "selected": [s["method_id"] for s in sel["selected"]], "rejected": [s["method_id"] for s in sel["rejected"]],
            "files": {k: str(Path(v).relative_to(out_root)) for k, v in files.items()},
            "generated_at": r["generated_at"],
        })
    out_root.mkdir(parents=True, exist_ok=True)
    (out_root / "index.json").write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nIndeks: {out_root / 'index.json'}  (* = varian tereduksi)")
    return rc


if __name__ == "__main__":
    sys.exit(main())
