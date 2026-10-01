"""Cryptan.ID Test Suite — modul algo_catalog (Daftar Algoritma yang Diuji, UK-1 KUK 1.1).

  python -m algo_catalog list [--primitive hash] [--tree]
  python -m algo_catalog scrape --refresh [--include-optional]
  python -m algo_catalog select --url <URL> --file <path> --pick "AES:GCM:128,256" "ECDSA:P-384"
                                [--urls-file samples/links.txt] [--yes | --interactive] [--min-confidence 0.6]
  python -m algo_catalog export-web [--out site/data/catalog.json]
"""
import argparse
import sys
from pathlib import Path

from core import APP_NAME

from . import catalog, extract, link, output, picker
from .normalize import Matcher, best
from .schema import PRIMITIVES
from .selection import Selection


def cmd_list(a):
    E = catalog.load(use_cache=not a.no_cache)
    if a.tree:
        for p, fams in catalog.tree(E).items():
            if a.primitive and p != a.primitive:
                continue
            print(f"{PRIMITIVES[p]}")
            for fam, vs in fams.items():
                print(f"  {fam}")
                for v in vs:
                    print(f"    {v['variant']:<22} kunci={v['keys'] or '—'}  → {', '.join(v['combos'])}")
        return 0
    n = 0
    print(f"{'ID kanonik':<28} {'Primitif':<14} {'Varian':<22} {'Kunci':>6} {'Strength':>10}  Status")
    for e in E:
        if a.primitive and e.primitive != a.primitive:
            continue
        for k in e.keys():
            n += 1
            print(f"{e.combo(k):<28} {e.primitive:<14} {e.variant[:22]:<22} {str(k or '—'):>6} {str(e.strength(k)):>10}  {e.status(k)}")
    c = catalog.count_combinations(E)
    print(f"\n{n} kombinasi ditampilkan · katalog total {c['total']} kombinasi dari {len(E)} entri")
    return 0


def cmd_scrape(a):
    from . import scraper
    print(f"{APP_NAME} · scraping katalog ({'refresh' if a.refresh else 'cache'})")
    scraper.scrape(refresh=a.refresh, include_optional=a.include_optional)
    return 0


def _ask(prompt):
    try:
        return input(prompt).strip().lower()
    except EOFError:
        return ""


def cmd_select(a):
    E = catalog.load(use_cache=not a.no_cache)
    M = Matcher(E)
    sel = Selection(E)
    auto = a.min_confidence if a.yes else None
    urls = list(a.url or [])
    if a.urls_file:
        urls += [l.strip() for l in Path(a.urls_file).read_text().splitlines() if l.strip() and not l.startswith("#")]
    for u in urls:
        try:
            page = link.fetch(u, delay=a.delay)
            dets = best(M.find(page["text"], source={"type": "link", "url": u}))
            sel.add_detections(dets, "link", u, auto)
            print(f"[link] {u}: {len(dets)} deteksi ({page['kind']}, {page['bytes']} B)")
        except link.FetchError as e:
            print(f"[link] GAGAL {e}", file=sys.stderr)
    for f in a.file or []:
        try:
            text = extract.file_to_text(f)
        except (extract.ExtractError, OSError) as e:
            print(f"[file] GAGAL {f}: {e}", file=sys.stderr)
            continue
        dets = best(M.find(text, key_bits=a.key_bits, source={"type": "file", "path": f}))
        sel.add_detections(dets, "file", Path(f).name, auto)
        print(f"[file] {f}: {len(dets)} deteksi")
    for spec in a.pick or []:
        try:
            ids = sel.add_pick(picker.parse_pick(spec, E), spec)
            print(f"[dropdown] {spec}: {', '.join(ids)}")
        except picker.PickError as e:
            print(f"[dropdown] GAGAL {e}", file=sys.stderr)
            return 2

    # konfirmasi pengguna atas hasil deteksi otomatis
    pend = sel.pending()
    if pend and a.interactive:
        print("\nKonfirmasi hasil deteksi (y = terima, n = tolak, a = terima semua sisa, q = tolak semua sisa):")
        accept_rest = None
        for it in pend:
            if accept_rest is None:
                ev = it["inputs"][0]
                ans = _ask(f"  {it['id']:<26} keyakinan {it['confidence']:.2f} · {ev.get('match')} · [{ev['ref']}] ? ")
                if ans == "a":
                    accept_rest = True
                elif ans == "q":
                    accept_rest = False
                sel.confirm([it["id"]], ans in ("y", "ya", "a"))
            else:
                sel.confirm([it["id"]], accept_rest)
    elif pend:
        low = [p for p in pend if p["confidence"] < a.min_confidence]
        print(f"\n{len(pend)} kandidat belum dikonfirmasi"
              + (f" ({len(low)} di bawah ambang {a.min_confidence})" if low else "")
              + " — jalankan dengan --interactive untuk konfirmasi, atau --yes untuk menerima yang ≥ ambang.")
    rows = sel.final()
    res = output.write_all(rows, Path(a.out), a.product, sel.pending(), link=not a.no_link_profile)
    doc = res["doc"]
    print(f"\nDaftar akhir: {doc['summary']['total_combinations']} kombinasi · "
          + ", ".join(f"{PRIMITIVES[p]} {n}" for p, n in doc["summary"]["by_primitive"].items()))
    hi = [w for w in doc["warnings"] if w["level"] == "TINGGI"]
    print(f"Peringatan: {len(hi)} tinggi · {sum(w['level'] == 'SEDANG' for w in doc['warnings'])} sedang (rentan kuantum)")
    for w in hi[:10]:
        print(f"  ⚠ {w['message']}")
    for k, f in res["files"].items():
        if f:
            print(f"  → {f}" + ("  (ditautkan: algorithms_under_test)" if k == "profile_linked" else ""))
    return 0


def cmd_export_web(a):
    E = catalog.load()
    catalog.export_json(E, Path(a.out))
    print(f"katalog web → {a.out} ({len(E)} entri)")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m algo_catalog", description=f"{APP_NAME} — Daftar Algoritma yang Diuji")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("list", help="tampilkan katalog")
    p.add_argument("--primitive", choices=list(PRIMITIVES))
    p.add_argument("--tree", action="store_true", help="hierarki Primitif → Algoritma → Varian → Kunci")
    p.add_argument("--no-cache", action="store_true", help="hanya seed")
    p.set_defaults(fn=cmd_list)
    p = sub.add_parser("scrape", help="perbarui katalog dari sumber NIST/ISO")
    p.add_argument("--refresh", action="store_true")
    p.add_argument("--include-optional", action="store_true")
    p.set_defaults(fn=cmd_scrape)
    p = sub.add_parser("select", help="susun daftar algoritma uji (link/file/dropdown)")
    p.add_argument("--url", nargs="*", help="URL halaman/PDF")
    p.add_argument("--urls-file", help="berkas berisi daftar URL (satu per baris)")
    p.add_argument("--file", nargs="*", help="berkas spesifikasi/source code")
    p.add_argument("--pick", nargs="*", help='pilihan katalog, mis. "AES:GCM:128,256" "ECDSA:P-384" "AES-256-GCM"')
    p.add_argument("--key-bits", type=int, help="panjang kunci default untuk alias tanpa kunci (mis. AES/GCM/NoPadding)")
    p.add_argument("--min-confidence", type=float, default=0.6)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--yes", action="store_true", help="terima otomatis deteksi ≥ ambang (konfirmasi non-interaktif)")
    g.add_argument("--interactive", action="store_true", help="konfirmasi tiap deteksi")
    p.add_argument("--out", default="outputs/algo_catalog")
    p.add_argument("--product", default="Cryptan.ID SecureLib")
    p.add_argument("--delay", type=float, default=link.DELAY_S)
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("--no-link-profile", action="store_true", help="jangan ubah config/product_profile.yaml")
    p.set_defaults(fn=cmd_select)
    p = sub.add_parser("export-web", help="ekspor katalog JSON untuk dashboard")
    p.add_argument("--out", default="web/data/catalog.json")
    p.set_defaults(fn=cmd_export_web)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
