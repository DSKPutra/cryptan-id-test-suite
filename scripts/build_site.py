"""Bangun situs statis (dashboard) ke site/: salin web/* + outputs/uk1 → site/data/uk1.

  python scripts/build_site.py [--repo URL]
"""
import argparse
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="https://github.com/DSKPutra/cryptan-id-test-suite")
    a = ap.parse_args()
    site = ROOT / "site"
    shutil.rmtree(site, ignore_errors=True)
    shutil.copytree(ROOT / "web", site)
    src = ROOT / "outputs" / "uk1"
    if not (src / "index.json").exists():
        raise SystemExit("outputs/uk1/index.json belum ada — jalankan `make run` dulu")
    shutil.copytree(src, site / "data" / "uk1")
    # modul algo_catalog: katalog (web/data/catalog.json, dibuat `make catalog-web`), daftar produk, kode Python untuk Pyodide
    aut = ROOT / "outputs" / "algo_catalog"
    if aut.exists():
        shutil.copytree(aut, site / "data" / "algo_catalog")
    # UK-2: produk + 3 sampel materi
    uk2 = ROOT / "outputs" / "uk2"
    if uk2.exists():
        shutil.copytree(uk2, site / "data" / "uk2" / "produk")
        for sdir in sorted((ROOT / "samples" / "uk2").glob("*/output")):
            shutil.copytree(sdir, site / "data" / "uk2" / sdir.parent.name)
    pydir = site / "py" / "algo_catalog"
    pydir.mkdir(parents=True, exist_ok=True)
    for f in ("schema.py", "normalize.py"):
        shutil.copy(ROOT / "algo_catalog" / f, pydir / f)
    if not (site / "data" / "catalog.json").exists():
        raise SystemExit("web/data/catalog.json belum ada — jalankan `python -m algo_catalog export-web`")
    idx = json.loads((site / "data" / "uk1" / "index.json").read_text())
    idx["repo"] = a.repo
    (site / "data" / "uk1" / "index.json").write_text(json.dumps(idx, indent=2, ensure_ascii=False))
    print(f"situs → {site} ({sum(1 for _ in site.rglob('*') if _.is_file())} file)")
