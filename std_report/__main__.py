"""Cryptan.ID Test Suite — std_report (Daftar Algoritme Standar + Hasil Semua Uji + Export PDF).

  python -m std_report list   [--source fips,nist-sp,iso-iec] [--primitive hash,kdf]
  python -m std_report run    [--mode ringan|full] [--only AES,SHA3] [--source …] [--primitive …]
  python -m std_report report --pdf [--html] [--xlsx] [--ringkas] [--only-tested] [--penyusun "Nama"]
  python -m std_report all    --pdf [--penyusun "Nama"]
"""
import argparse
import sys
import time

from .report.model import norm_list, norm_sources


def _progress(i, n, rid):
    if sys.stderr.isatty() or i == n or i % 25 == 0:
        print(f"\r[{i:>3}/{n}] {rid:<32}", end="" if i < n else "\n", file=sys.stderr, flush=True)


def cmd_list(a):
    from . import catalog
    cat = catalog.build(norm_sources(a.source), norm_list(a.primitive))
    print(f"{'ID kanonik':<30} {'Primitif':<14} {'Varian':<20} {'Kunci':>6} {'Strength':>9}  {'Status NIST':<12} Sumber")
    for r in cat["rows"]:
        print(f"{r['id']:<30} {r['primitive']:<14} {str(r['variant'])[:20]:<20} {str(r['key_bits'] or '—'):>6} "
              f"{str(r['security_strength_bits']):>9}  {str(r['status_nist']):<12} {', '.join(r['source_doc'])}")
    c = cat["counts"]
    print(f"\n{len(cat['rows'])} kombinasi — " + ", ".join(f"{cat['bodies'][b]}: {n}" for b, n in c.items()))
    return 0


def cmd_run(a):
    from . import runner
    t0 = time.time()
    res = runner.run(a.mode, norm_list(a.only), norm_sources(a.source), norm_list(a.primitive), progress=_progress)
    k = res["summary"]["kpi"]
    print(f"results.json ditulis ({time.time() - t0:.0f} s): {k['terdaftar']} terdaftar, {k['diuji']} diuji, "
          f"{k['lulus_semua']} lulus semua, {k['punya_temuan']} punya temuan, {k['tidak_dapat_diuji']} tidak dapat diuji")
    if res["schema_errors"]:
        print("PERINGATAN skema:", res["schema_errors"][:5], file=sys.stderr)
        return 1
    return 0


def cmd_report(a):
    from .report.builder import build_pdf
    from .report.export import build_html, build_xlsx
    from .report.model import load
    res = load()
    kw = dict(sources=a.source, primitives=a.primitive, only_tested=a.only_tested, penyusun=a.penyusun)
    if not (a.pdf or a.html or a.xlsx):
        a.pdf = True
    if a.pdf:
        print("PDF :", build_pdf(res, ringkas=a.ringkas, **kw))
    if a.html:
        print("HTML:", build_html(res, ringkas=a.ringkas, **kw))
    if a.xlsx:
        print("XLSX:", build_xlsx(res, **kw))
    return 0


def cmd_all(a):
    a.only = None
    cmd_list(a) if a.verbose else None
    rc = cmd_run(a)
    return rc or cmd_report(a)


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m std_report", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def filters(sp):
        sp.add_argument("--source", help="fips,nist-sp,iso-iec")
        sp.add_argument("--primitive", help="block_cipher,stream_cipher,hash,mac,pkc_kem,signature,drbg,kdf")

    def report_opts(sp):
        sp.add_argument("--pdf", action="store_true")
        sp.add_argument("--html", action="store_true")
        sp.add_argument("--xlsx", action="store_true")
        sp.add_argument("--ringkas", action="store_true", help="tanpa Bab 5 (hasil rinci)")
        sp.add_argument("--only-tested", action="store_true", help="hanya algoritme yang dapat diuji")
        sp.add_argument("--penyusun", help="nama penyusun / pengunduh dokumen (tampil di sampul & footer)")

    sp = sub.add_parser("list", help="tampilkan daftar algoritme standar")
    filters(sp)
    sp.set_defaults(fn=cmd_list)
    sp = sub.add_parser("run", help="jalankan semua uji → outputs/std_report/results.json")
    filters(sp)
    sp.add_argument("--mode", choices=["ringan", "full"], default="ringan")
    sp.add_argument("--only", help="mis. AES,SHA3")
    sp.set_defaults(fn=cmd_run)
    sp = sub.add_parser("report", help="buat laporan dari results.json")
    filters(sp)
    report_opts(sp)
    sp.set_defaults(fn=cmd_report)
    sp = sub.add_parser("all", help="list + run + report")
    filters(sp)
    report_opts(sp)
    sp.add_argument("--mode", choices=["ringan", "full"], default="ringan")
    sp.add_argument("--verbose", action="store_true", help="cetak daftar algoritme lebih dulu")
    sp.set_defaults(fn=cmd_all)
    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
