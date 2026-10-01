"""KUK 1.1 — Mengidentifikasi informasi desain & teknik implementasi produk.

Membaca product_profile.yaml (dengan dukungan `extends` untuk profil per
algoritma), memvalidasi kelengkapan, dan menyusun Profil Produk.
"""
import copy
from pathlib import Path

import yaml

PRIMITIVES = {
    "block_cipher": "Block cipher",
    "stream_cipher": "Stream cipher",
    "hash": "Fungsi hash",
    "pkc": "Kriptografi kunci publik (PKC)",
    "dss": "Tanda tangan digital (DSS)",
}
ROOT = Path(__file__).resolve().parents[1]
ACCESS_LEVELS = {"black_box": 0, "grey_box": 1, "white_box": 2}
ACCESS_SHORT = {"black": 0, "grey": 1, "white": 2}

REQUIRED = {
    "product": ["name", "version", "description"],
    "algorithm": ["id", "name", "primitive", "structure", "parameters"],
    "implementation": ["platform", "language", "interfaces", "rng"],
    "tester": ["access", "scope"],
    "resources": ["personnel", "schedule_days", "hours_per_day", "method_budget_hours",
                  "compute", "tools_available"],
}


class ProfileError(ValueError):
    pass


def _deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _read(path: Path) -> dict:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if data.get("algorithms_under_test"):        # tautan algo_catalog, relatif terhadap berkas ini
        data["algorithms_under_test"] = str((path.parent / data["algorithms_under_test"]).resolve())
    if "extends" in data:
        parent = _read((path.parent / data.pop("extends")).resolve())
        parent.pop("algorithms", None)
        data = _deep_merge(parent, data)
    return data


def validate(p: dict) -> list:
    """KUK 1.1 — cek kelengkapan informasi. Mengembalikan daftar kekurangan."""
    missing = []
    for sec, keys in REQUIRED.items():
        if sec not in p:
            missing.append(sec)
            continue
        missing += [f"{sec}.{k}" for k in keys if p[sec].get(k) in (None, "", [])]
    alg = p.get("algorithm", {})
    if alg.get("primitive") and alg["primitive"] not in PRIMITIVES:
        missing.append(f"algorithm.primitive (tidak dikenal: {alg['primitive']})")
    if p.get("tester", {}).get("access") not in ACCESS_LEVELS:
        missing.append("tester.access (white_box|grey_box|black_box)")
    return missing


def load_profiles(path) -> list:
    """Muat profil. Bila file memuat `algorithms:`, kembalikan satu profil per
    algoritma (mode "All"); jika tidak, satu profil."""
    path = Path(path).resolve()
    raw = _read(path)
    if "algorithms" in raw and "algorithm" not in raw:
        return [load_profiles(path.parent / rel)[0] for rel in raw["algorithms"]]
    missing = validate(raw)
    if missing:
        raise ProfileError(f"Profil {path.name} tidak lengkap: {', '.join(missing)}")
    raw["_source"] = str(path)
    return [raw]


def rel(path) -> str:
    """Path relatif terhadap root repo (hindari membocorkan path lokal pada keluaran)."""
    try:
        return Path(path).resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return Path(path).name


def access_level(p: dict) -> int:
    return ACCESS_LEVELS[p["tester"]["access"]]


def algorithms_under_test(p: dict) -> dict:
    """KUK 1.1 — ringkasan Daftar Algoritma yang Diuji (keluaran modul algo_catalog)."""
    path = p.get("algorithms_under_test")
    if not path or not Path(path).exists():
        return {"linked": False, "note": "Jalankan `python -m algo_catalog select …` untuk menyusun daftar algoritma uji"}
    d = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    cid = (p.get("algorithm") or {}).get("catalog_id", "")
    item = next((i for i in d.get("items", []) if i["id"].upper() == cid.upper()), None)
    return {"linked": True, "file": rel(path), "generated_at": d.get("generated_at"),
            "total_combinations": d.get("summary", {}).get("total_combinations", 0),
            "by_primitive": d.get("summary", {}).get("by_primitive", {}),
            "warnings_high": sum(1 for w in d.get("warnings", []) if w.get("level") == "TINGGI"),
            "catalog_id": cid, "in_list": item is not None,
            "item": {k: item[k] for k in ("security_strength_bits", "status_nist", "standards")} if item else None}


def summarize(p: dict) -> dict:
    """Profil Produk terstruktur untuk dokumen & JSON (bab 1)."""
    alg, impl, t = p["algorithm"], p["implementation"], p["tester"]
    return {
        "product": p["product"],
        "algorithm": {
            "id": alg["id"], "name": alg["name"], "primitive": alg["primitive"],
            "primitive_label": PRIMITIVES[alg["primitive"]], "structure": alg["structure"],
            "mode": alg.get("mode"), "parameters": alg["parameters"],
            "reference_values": alg.get("reference_values", {}),
            "implementation_notes": alg.get("implementation_notes", {}),
        },
        "implementation": impl,
        "tester": {"access": t["access"], "access_desc": t.get("access_desc", "").strip(),
                   "scope": t["scope"], "out_of_scope": t.get("out_of_scope", [])},
        "resources": p["resources"],
        "completeness": {"status": "LENGKAP", "missing": []},
        "algorithms_under_test": algorithms_under_test(p),
        "source_file": rel(p["_source"]) if p.get("_source") else None,
    }
