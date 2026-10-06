"""Registri & pemuat produk uji (KUK 1.1–1.2): versi, berkas, sidik jari SHA-256, label ASLI/REPLIKA, ruang lingkup."""
import hashlib
import importlib.util
from pathlib import Path

import yaml

from . import PKG, ROOT, rel

REGISTRY = yaml.safe_load((PKG / "data" / "products.yaml").read_text(encoding="utf-8"))
SCOPE_FILE = ROOT / "products" / "ruang_lingkup.yaml"
LATIHAN, REPLIKA = ROOT / "products" / "latihan", ROOT / "products" / "replika"


def sha256_file(p) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def scope() -> dict:
    return yaml.safe_load(SCOPE_FILE.read_text(encoding="utf-8"))


def in_scope(product_id: str) -> bool:
    return product_id in (scope().get("produk_dalam_lingkup") or [])


def versions(product_id: str) -> dict:
    """Versi produk beserta berkas, hash, label (ASLI/REPLIKA) dan ketersediaannya."""
    p = REGISTRY[product_id]
    out = {}
    for ver, v in p["versi"].items():
        if "modul" in v:
            f = LATIHAN / f"{v['modul']}.py"
            label = "ASLI (materi)"
            if not f.exists():
                f, label = REPLIKA / f"{v['modul']}.py", "REPLIKA"
            out[ver] = {"versi": ver, "modul": v["modul"], "berkas": rel(f), "sha256": sha256_file(f), "label": label,
                        "tersedia": f.exists(), "catatan": v.get("catatan", "")}
        elif "pustaka" in v:
            mod = importlib.import_module(v["pustaka"])
            f = Path(mod.__file__)
            ver_s = getattr(mod, "__version__", "?")
            out[ver_s] = {"versi": ver_s, "modul": v["pustaka"], "berkas": f"{v['pustaka']} {ver_s} (paket terpasang)",
                          "sha256": sha256_file(f), "label": "PUSTAKA TERPASANG", "tersedia": True, "catatan": ""}
        else:
            out[ver] = {"versi": ver, "modul": None, "berkas": None, "sha256": None, "label": "TIDAK TERSEDIA",
                        "tersedia": bool(v.get("tersedia")), "catatan": v.get("alasan", "")}
    return out


def load(product_id: str, version: str):
    """Muat modul produk dari berkasnya (tidak lewat sys.path) agar yang diuji tepat berkas yang di-hash."""
    v = versions(product_id)[version]
    if not v["tersedia"]:
        raise LookupError(v["catatan"] or "produk tidak tersedia")
    if v["label"] == "PUSTAKA TERPASANG":
        return importlib.import_module(v["modul"])
    path = ROOT / v["berkas"]
    spec = importlib.util.spec_from_file_location(f"uk3_produk_{v['modul']}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def fingerprint(product_id: str, version: str) -> str:
    v = versions(product_id)[version]
    return f"{v['modul']} {v['sha256'][:16]}" if v["sha256"] else "—"
