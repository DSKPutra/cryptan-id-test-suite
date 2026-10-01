"""KUK 1.1 — Metode ditelaah sesuai kebutuhan pengujian.

Setiap metode terpilih UK-1 ditelaah terhadap 4 kebutuhan pengujian SKKNI:
  N1 jenis algoritma · N2 desain & teknik implementasi · N3 tren serangan · N4 best practice
lalu ditempatkan pada sel matriks lapis × tingkat. Sel kosong & metode tidak relevan dilaporkan.
"""
from .context import LAYERS, UK1_LAYER, category_of

# kategori materi → kelas primitif katalog metode UK-1 (methods.yaml)
CAT_TO_UK1 = {"block": "block_cipher", "stream": "stream_cipher", "hash": "hash", "pke": "pkc",
              "signature": "dss", "protocol": None}
UK1_TO_CAT = {"block_cipher": "block", "stream_cipher": "stream", "hash": "hash", "pkc": "pke", "dss": "signature",
              "protocol": "protocol", "module": None}
# metode yang memerlukan fitur/akses tertentu pada produk (dipakai N2 untuk stub & produk non-library)
METHOD_FEATURES = {
    "M-TVLA": ["side_channel_lab"], "M-FAULT": ["power_glitch"], "M-CODEREVIEW": ["source_code"],
    "M-CACHE": ["timing_measurement"], "M-TIMING": ["timing_measurement", "side_channel_lab"],
    "M-FUZZ": ["fuzzing_harness"], "M-ZEROIZE": ["debug_build", "key_import_export", "key_non_exportable", "audit_log"],
    "M-SELFTEST": ["self_tests"], "M-RNG": ["rng_internal", "entropy_source"],
}


def _needs(ctx, m_sel: dict, cats: set) -> dict:
    mid = m_sel["method_id"]
    cat = ctx.methods_catalog.get(mid, {})
    uk1_prims = set(cat.get("primitives", []))
    obj_prims = {CAT_TO_UK1.get(c) for c in cats} - {None}
    # N1 — jenis algoritma: metode berlaku untuk kelas primitif objek uji (protokol/modul: metode generik)
    generic = len(uk1_prims) >= 5
    n1 = bool(uk1_prims & obj_prims) or (generic and bool(cats)) or (not obj_prims and bool(cat))
    # N2 — desain & teknik implementasi: menargetkan komponen hasil telaah UK-1 / fitur produk
    targets = []
    for r in ctx.uk1:
        for row in r.get("matrix", []):
            if row.get("method_id") == mid:
                targets.append(row["component_id"])
    feats = METHOD_FEATURES.get(mid)
    feat_ok = feats is None or bool(set(feats) & ctx.features)
    n2 = (bool(targets) or m_sel.get("stub", False) or not ctx.uk1[0].get("matrix")) and feat_ok
    # N3 — tren serangan: ada serangan (literatur UK-1) yang menyasar tag kelemahan yang ditangani metode
    tags = set(cat.get("addresses", []))
    atk = sorted({a["id"] for a in ctx.attacks if tags & set(a.get("targets", []))
                  and (a.get("primitives") == "all" or set(a.get("primitives", [])) & (obj_prims | {"pkc", "dss"} if not obj_prims else obj_prims))})
    n3 = bool(atk) or "conformance" in tags
    # N4 — best practice: dirujuk standar ISO/IEC atau NIST
    stds = cat.get("standards", [])
    n4 = bool(stds)
    return {"N1_jenis_algoritma": n1, "N2_desain_implementasi": n2, "N3_tren_serangan": n3, "N4_best_practice": n4,
            "evidence": {"primitives": sorted(uk1_prims), "uk1_targets": sorted(set(targets))[:12],
                         "required_features": feats or [], "attacks": atk[:12], "standards": stds}}


def review(ctx) -> dict:
    """KUK 1.1 — telaah metode, penempatan sel, sel kosong, metode tidak relevan."""
    cats = set(ctx.categories())
    rows, seen = [], {}
    for s in ctx.uk1_selected():
        key = s["method_id"]
        layer = UK1_LAYER.get(s.get("layer"), "I")
        tier = ctx.tier_for_uk1_level(s.get("level", "Sistem"))
        src_cat = UK1_TO_CAT.get(s.get("uk1_primitive"))
        if key in seen:                                   # metode sama dari algoritma lain → gabung
            seen[key]["uk1_algorithms"].append(s.get("uk1_algorithm"))
            if src_cat and src_cat not in seen[key]["categories"]:
                seen[key]["categories"].append(src_cat)
            continue
        n = _needs(ctx, s, cats)
        met = sum(n[k] for k in ("N1_jenis_algoritma", "N2_desain_implementasi", "N3_tren_serangan", "N4_best_practice"))
        relevant = met >= 3 and n["N1_jenis_algoritma"] and n["N2_desain_implementasi"]
        row = {"method_id": key, "name": s.get("name") or ctx.methods_catalog.get(key, {}).get("name", key),
               "layer": layer, "layer_label": LAYERS[layer], "tier": tier, "variant": s.get("variant", "penuh"),
               "uk1_algorithms": [s.get("uk1_algorithm")], "categories": [src_cat] if src_cat else sorted(cats),
               "needs": {k: v for k, v in n.items() if k != "evidence"}, "needs_met": met, "evidence": n["evidence"],
               "relevant": relevant, "stub": s.get("stub", False),
               "verdict": "RELEVAN" if relevant else "TIDAK RELEVAN — " + ", ".join(
                   k.split("_", 1)[1].replace("_", " ") for k in ("N1_jenis_algoritma", "N2_desain_implementasi",
                                                                  "N3_tren_serangan", "N4_best_practice") if not n[k])}
        seen[key] = row
        rows.append(row)
    # sel matriks per kategori
    cells = {}
    for c in sorted(cats):
        cells[c] = {}
        for t in ctx.tiers:
            for L in "KSI":
                ms = [r["method_id"] for r in rows if r["relevant"] and r["tier"] == t and r["layer"] == L
                      and (c in r["categories"] or c == "protocol")]
                cells[c][f"{t}|{L}"] = ms
    empty = [{"category": c, "tier": k.split("|")[0], "layer": k.split("|")[1],
              "action": "diisi dari templat kategori materi (designer, KUK 2.1)"}
             for c, cs in cells.items() for k, v in cs.items() if not v]
    return {"methods": rows, "cells": cells, "empty_cells": empty,
            "irrelevant": [r for r in rows if not r["relevant"]],
            "summary": {"methods": len(rows), "relevant": sum(r["relevant"] for r in rows),
                        "cells_total": sum(len(v) for v in cells.values()), "cells_empty": len(empty)}}
