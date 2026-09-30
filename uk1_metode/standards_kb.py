"""KUK 1.3 — Mengidentifikasi best practice metode pengujian (standar
ISO/IEC & NIST) sesuai kelas primitif. Keluaran: Daftar Referensi.
"""
from pathlib import Path

import yaml

DATA = Path(__file__).parent / "data" / "standards.yaml"
ROLE_LABEL = {
    "spesifikasi": "Spesifikasi algoritma/skema",
    "pengujian_kesesuaian": "Pengujian kesesuaian",
    "kekuatan": "Pengujian kekuatan / kriteria keamanan",
    "implementasi": "Pengujian implementasi & modul",
    "manajemen_kunci": "Ukuran kunci & manajemen kunci",
    "rbg": "Pembangkitan bilangan acak",
    "evaluasi": "Evaluasi keamanan / migrasi",
    "proses_uji": "Proses & dokumentasi pengujian",
}


def load() -> dict:
    return yaml.safe_load(DATA.read_text(encoding="utf-8"))


def references_for(primitive: str) -> list:
    """Daftar referensi (unik) untuk kelas primitif, diurutkan per peran."""
    kb = load()
    rows, seen = [], set()
    for item in kb["by_primitive"].get(primitive, []) + kb["common"]:
        if item["id"] in seen:
            continue
        seen.add(item["id"])
        meta = kb["catalog"][item["id"]]
        rows.append({
            "id": item["id"], "org": meta["org"], "title": meta["title"], "year": meta.get("year"),
            "role": item["role"], "role_label": ROLE_LABEL[item["role"]],
            "note": meta.get("note", ""), "verify": meta.get("verify", ""),
        })
    order = list(ROLE_LABEL)
    return sorted(rows, key=lambda r: (order.index(r["role"]), r["id"]))


def catalog() -> dict:
    return load()["catalog"]


def label(std_id: str) -> str:
    meta = catalog().get(std_id)
    return f"{std_id.replace('-', ' ', 1)}" if meta else f"{std_id} (PERLU_VERIFIKASI)"
