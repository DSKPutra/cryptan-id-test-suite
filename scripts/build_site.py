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
    idx = json.loads((site / "data" / "uk1" / "index.json").read_text())
    idx["repo"] = a.repo
    (site / "data" / "uk1" / "index.json").write_text(json.dumps(idx, indent=2, ensure_ascii=False))
    print(f"situs → {site} ({sum(1 for _ in site.rglob('*') if _.is_file())} file)")
