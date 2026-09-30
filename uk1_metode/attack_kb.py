"""KUK 1.2 — Mengidentifikasi tren serangan terhadap algoritma & platform.

Memuat data/attacks.yaml (HASIL LITERATUR) dan memfilter otomatis sesuai
profil: kelas primitif, struktur, algoritma, mode, platform, bahasa.
"""
from pathlib import Path

import yaml

DATA = Path(__file__).parent / "data" / "attacks.yaml"
CATEGORIES = {
    "desain": "Serangan terhadap desain algoritma",
    "protokol": "Kelemahan implementasi protokol / pemakaian",
    "bahasa": "Kesalahan bahasa pemrograman",
    "platform": "Serangan terhadap platform (side-channel / fault)",
}


def load_all() -> list:
    return yaml.safe_load(DATA.read_text(encoding="utf-8"))["attacks"]


def _match(value, allowed) -> bool:
    return allowed is None or allowed == "all" or value in allowed


def applies(a: dict, profile: dict) -> bool:
    alg, impl = profile["algorithm"], profile["implementation"]
    langs = [impl["language"]] + list(impl.get("bindings", []))
    return (_match(alg["primitive"], a.get("primitives"))
            and _match(alg["id"], a.get("algorithms"))
            and _match(alg["structure"], a.get("structures"))
            and _match(alg.get("mode"), a.get("modes"))
            and _match(impl["platform"], a.get("platforms"))
            and (a.get("languages") in (None, "all") or any(l in a["languages"] for l in langs)))


def filter_for(profile: dict) -> list:
    """Daftar serangan relevan, diurutkan per kategori lalu status praktis."""
    order = list(CATEGORIES)
    out = []
    for a in load_all():
        if applies(a, profile):
            e = dict(a)
            e["source"] = "HASIL LITERATUR"
            e["verify"] = a.get("verify", "TERVERIFIKASI_REFERENSI")
            out.append(e)
    return sorted(out, key=lambda a: (order.index(a["category"]), not str(a["status"]).startswith("praktis")))


def summary(attacks: list) -> dict:
    by_cat = {c: [a["id"] for a in attacks if a["category"] == c] for c in CATEGORIES}
    return {
        "total": len(attacks),
        "by_category": by_cat,
        "practical": [a["id"] for a in attacks if str(a["status"]).startswith("praktis")],
        "needs_verification": [a["id"] for a in attacks if a["verify"] == "PERLU_VERIFIKASI"],
    }


def weakness_tags(attacks: list) -> set:
    return {t for a in attacks for t in a.get("targets", [])}
