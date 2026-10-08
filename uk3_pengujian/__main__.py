"""Cryptan.ID Test Suite — UK-3 Melakukan Pengujian Terhadap Produk Kriptografi (J.61KRP00.014.1).

  python -m uk3_pengujian prep     --product securefile [--set izin_jadwal=Tidak]
  python -m uk3_pengujian plan     --product securefile
  python -m uk3_pengujian run      --product securefile --tc all [--version 1.0] [--alasan "…"] [--param TC-06:N=40]
  python -m uk3_pengujian analyze  --product securefile --run <run_id>
  python -m uk3_pengujian conclude --product securefile --run <run_id> [--kesimpulan "teks penguji"]
  python -m uk3_pengujian report   --product securefile --run <run_id> --pdf --docx
  python -m uk3_pengujian rng      --input bits.txt --tests golomb,basic5,sp80022,linear
  python -m uk3_pengujian cvss     AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
  python -m uk3_pengujian verify-evidence --product securefile --run <run_id>
  streamlit run uk3_pengujian/app.py

--product menerima path berkas produk (mis. products/latihan/securefile.py) atau ID registri.
"""
import argparse
import json
import sys
from pathlib import Path

from . import products as P


def _pid(x):
    if x in P.REGISTRY:
        return x
    stem = Path(x).stem
    for pid, p in P.REGISTRY.items():
        if any(v.get("modul") == stem for v in p["versi"].values()):
            return pid
    sys.exit(f"Produk tidak dikenal: {x} (pilihan: {', '.join(P.REGISTRY)})")


def _run_id(a):
    from .run.runner import runs_index
    if a.run and a.run != "latest":
        return a.run
    idx = runs_index(a.product)
    if not idx:
        sys.exit("Belum ada run untuk produk ini")
    return idx[-1]["run_id"]


def cmd_prep(a):
    from .prep.documents import prepare
    ov = {}
    for s in a.set or []:
        k, v = s.split("=", 1)
        ov[k] = (v.lower() in ("ya", "yes", "true", "1"), f"ditandai '{v}' oleh penguji")
    r = prepare(a.product, ov or None)
    print(r["inventaris"]["catatan_lingkungan"])
    for d in r["dokumen"]:
        print(f"  [{'ada' if d['ada'] else 'TIDAK ADA':>9}] {d['jenis']}: {d['berkas']} {('SHA-256 ' + d['sha256'][:16]) if d['sha256'] else ''}")
    for i in r["checklist"]["items"]:
        print(f"  {i['status']:<5} {i['uraian']}" + (f" — {i['kekurangan']} (PJ {i['penanggung_jawab']}, ulang {i['tanggal_ulang']})"
                                                    if i["status"] == "Tidak" else ""))
    print(r["checklist"]["keputusan"])
    return 0 if r["checklist"]["siap"] else 2


def cmd_plan(a):
    from .run.planner import plan
    p = plan(a.product, a.tc)
    for s in p["tahapan"]:
        print(f"Tahap {s['tahap']} {s['nama']:<28} {', '.join(s['tc']) or '—'}")
    print(f"{p['jumlah']} TC, {p['negatif']} uji negatif")
    for w in p["peringatan"]:
        print("PERINGATAN:", w)
    return 0


def cmd_run(a):
    from .run import runner
    params = {}
    for s in a.param or []:
        tid, kv = s.split(":", 1)
        k, v = kv.split("=", 1)
        params.setdefault(tid, {})[k] = json.loads(v) if v[:1].isdigit() or v[:1] in "[{" else v
    try:
        r = runner.run(a.product, a.version and [a.version], a.tc, a.alasan, params or None,
                       progress=lambda i, n, t: print(f"\r[{i}/{n}] {t:<40}", end="" if i < n else "\n", file=sys.stderr))
    except (runner.NotReady, runner.RerunWithoutReason, PermissionError) as e:
        print("DITOLAK:", e, file=sys.stderr)
        return 2
    print(f"run_id {r['run_id']} ({r['durasi_s']} s)")
    for v, x in r["versi"].items():
        print(f"  v{v}: " + ", ".join(f"{t['id']}={t['status']}" for t in x["tc"]))
    return 0


def cmd_analyze(a):
    from .analysis.analyze import analyze
    r = analyze(a.product, _run_id(a))
    for m in r["metode"]:
        print(f"{m['metode']} — {m['aturan']}")
        for b in m["baris"]:
            print(f"  v{b['versi']} {b['tc']}: {b['olah']}")
    print("Keputusan konsisten dengan olah data:", r["konsisten"])
    return 0


def cmd_conclude(a):
    from .conclude.decide import conclude
    r = conclude(a.product, _run_id(a), pernyataan=a.kesimpulan)
    for v, x in r["per_versi"].items():
        print(f"v{v}: {x['keseluruhan']}")
        for s, o in sorted(x["sasaran"].items()):
            print(f"  {s} {o['kategori']:<24} {o['alasan']}")
    for f in r["temuan"]:
        print(f"{f['id']} {f['judul']} (v{f['versi']}) — {f['keparahan']}")
    for c in r["pemeriksaan_rumusan"]:
        print(("✓ " if c["diterima"] else "✗ DITOLAK: ") + c["teks"])
        for m in c["masalah"]:
            print(f"    '{m['kutipan']}': {m['alasan']}")
    return 0


def cmd_report(a):
    from .report.build import report
    out = report(a.product, _run_id(a), pdf=a.pdf or not a.docx, docx=a.docx, penguji=a.penguji)
    for k, v in out.items():
        print(f"{k}: {v}")
    return 0


def cmd_rng(a):
    from .rng import generators, lab
    if a.input:
        bits = generators.from_file(a.input)
    else:
        bits = generators.generate(a.gen, a.n, seed=a.seed, p=a.p)
    tests = tuple(t.strip() for t in a.tests.split(","))
    r = lab.run_lab(bits, tests, d=a.d)
    print(lab.text_report(r))
    print("tersimpan:", lab.save(r, Path(a.input).stem if a.input else a.gen))
    return 0


def cmd_cvss(a):
    from .conclude.cvss import score
    r = score(a.vector)
    for s in r["langkah"]:
        print(f"{s[0]:<16} {s[1]:<60} {s[2]}")
    return 0


def cmd_verify(a):
    from .evidence import verify
    from .run.runner import run_dir
    r = verify(run_dir(a.product, _run_id(a)))
    print(r["kesimpulan"], f"({r['diperiksa']} berkas)")
    for c in r["berubah"]:
        print("  BERUBAH:", c["path"])
    for c in r["hilang"]:
        print("  HILANG:", c)
    return 0 if r["ok"] else 1


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m uk3_pengujian", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def prod(sp, run=False):
        sp.add_argument("--product", required=True, type=_pid)
        if run:
            sp.add_argument("--run", default="latest")
    sp = sub.add_parser("prep"); prod(sp); sp.add_argument("--set", action="append", help="butir=Ya|Tidak"); sp.set_defaults(fn=cmd_prep)
    sp = sub.add_parser("plan"); prod(sp); sp.add_argument("--tc", default="all"); sp.set_defaults(fn=cmd_plan)
    sp = sub.add_parser("run"); prod(sp); sp.add_argument("--tc", default="all"); sp.add_argument("--version")
    sp.add_argument("--alasan"); sp.add_argument("--param", action="append", help="TC-ID:param=nilai (dicatat sebagai deviasi)")
    sp.set_defaults(fn=cmd_run)
    sp = sub.add_parser("analyze"); prod(sp, True); sp.set_defaults(fn=cmd_analyze)
    sp = sub.add_parser("conclude"); prod(sp, True); sp.add_argument("--kesimpulan"); sp.set_defaults(fn=cmd_conclude)
    sp = sub.add_parser("report"); prod(sp, True); sp.add_argument("--pdf", action="store_true"); sp.add_argument("--docx", action="store_true")
    sp.add_argument("--penguji"); sp.set_defaults(fn=cmd_report)
    sp = sub.add_parser("rng"); sp.add_argument("--input"); sp.add_argument("--gen", default="prng", choices=["urandom", "prng", "python", "bias", "lfsr", "pola"])
    sp.add_argument("--n", type=int, default=100_000); sp.add_argument("--seed", type=int, default=2026); sp.add_argument("--p", type=float, default=0.51)
    sp.add_argument("--d", type=int, default=8); sp.add_argument("--tests", default="golomb,basic5,sp80022,linear"); sp.set_defaults(fn=cmd_rng)
    sp = sub.add_parser("cvss"); sp.add_argument("vector"); sp.set_defaults(fn=cmd_cvss)
    sp = sub.add_parser("verify-evidence"); prod(sp, True); sp.set_defaults(fn=cmd_verify)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
