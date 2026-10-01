"""Orkestrasi UK-1: EK 1 → EK 2 → EK 3 → keluaran terstruktur (masukan UK-2)."""
import datetime as dt
import math

from core import APP_NAME, __version__

from . import attack_kb, component_analysis, decompose, mapping, parameters, profile as prof
from . import resources, selector, standards_kb, traceability

UNIT = {"code": "J.61KRP00.012.1", "title": "Menentukan Metode Pengujian yang akan Dilakukan",
        "module": "UK-1", "skkni": "SKKNI 2023-004 (Cryptographic Analyst)"}

KUK_MAP = [
    {"kuk": "1.1", "desc": "Informasi desain & teknik implementasi", "section": "Bab 1", "files": ["uk1_metode/profile.py", "config/product_profile.yaml", "algo_catalog/ (Daftar Algoritma yang Diuji)"], "tests": ["tests/test_uk1_ek1.py::test_kuk_1_1_*", "tests/test_algo_catalog.py"]},
    {"kuk": "1.2", "desc": "Tren serangan terhadap platform", "section": "Bab 2.2", "files": ["uk1_metode/attack_kb.py", "uk1_metode/data/attacks.yaml"], "tests": ["tests/test_uk1_ek1.py::test_kuk_1_2_*"]},
    {"kuk": "1.3", "desc": "Best practice metode pengujian", "section": "Bab 2.1", "files": ["uk1_metode/standards_kb.py", "uk1_metode/data/standards.yaml"], "tests": ["tests/test_uk1_ek1.py::test_kuk_1_3_*"]},
    {"kuk": "2.1", "desc": "Komponen berpotensi lemah", "section": "Bab 3", "files": ["uk1_metode/decompose.py", "uk1_metode/component_analysis.py", "core/boolean.py"], "tests": ["tests/test_core_components.py", "tests/test_uk1_ek2.py::test_kuk_2_1_*"]},
    {"kuk": "2.2", "desc": "Analisis best practice vs potensi kelemahan", "section": "Bab 4", "files": ["uk1_metode/mapping.py", "uk1_metode/data/methods.yaml"], "tests": ["tests/test_uk1_ek2.py::test_kuk_2_2_*"]},
    {"kuk": "2.3", "desc": "Kesesuaian sumber daya internal", "section": "Bab 5", "files": ["uk1_metode/resources.py"], "tests": ["tests/test_uk1_ek2.py::test_kuk_2_3_*"]},
    {"kuk": "3.1", "desc": "Penetapan metode", "section": "Bab 6.1", "files": ["uk1_metode/selector.py"], "tests": ["tests/test_uk1_ek3.py::test_kuk_3_1_*"]},
    {"kuk": "3.2", "desc": "Penetapan parameter", "section": "Bab 6.2", "files": ["uk1_metode/parameters.py"], "tests": ["tests/test_uk1_ek3.py::test_kuk_3_2_*"]},
    {"kuk": "—", "desc": "Matriks keterlacakan", "section": "Bab 7", "files": ["uk1_metode/traceability.py"], "tests": ["tests/test_uk1_ek3.py::test_traceability_*"]},
]


def slug(alg_id: str) -> str:
    return alg_id.lower().replace("-", "_")


def _clean(o):
    """Buat hasil aman-JSON (inf → null)."""
    if isinstance(o, float):
        return None if math.isinf(o) or math.isnan(o) else o
    if isinstance(o, dict):
        return {str(k): _clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [_clean(v) for v in o]
    return o


def run(p: dict, quick: bool = False) -> dict:
    alg = p["algorithm"]
    # EK 1
    summary = prof.summarize(p)                              # KUK 1.1
    attacks = attack_kb.filter_for(p)                        # KUK 1.2
    refs = standards_kb.references_for(alg["primitive"])     # KUK 1.3
    # EK 2
    comps = decompose.decompose(p)                           # KUK 2.1
    analysis = component_analysis.analyze(p, comps, quick)   # KUK 2.1
    rows = mapping.build_matrix(p, analysis, attacks)        # KUK 2.2
    methods = mapping.methods_for(p)
    bench = resources.benchmark(p, quick)                    # KUK 2.3
    ests = {m["id"]: resources.estimate(m, p, bench) for m in methods}
    cap = resources.capacity(p)
    # EK 3
    sel = selector.select(methods, rows, ests, lambda m: mapping.access_ok(m, p), attacks)   # KUK 3.1
    effort = sum(ests[s["method_id"]]["effort_h"] for s in sel["selected"])
    sel["effort_hours_total"] = effort
    sel["person_hours_available"] = cap["person_hours"]
    sel["effort_fit"] = "SESUAI" if effort <= cap["person_hours"] else "MELEBIHI KAPASITAS"
    params = {s["method_id"]: parameters.build(s["method_id"], p, analysis, ests[s["method_id"]])
              for s in sel["selected"]}                      # KUK 3.2
    by_id = {m["id"]: m for m in methods}
    trace = traceability.build(sel["selected"], by_id, analysis)

    result = {
        "schema": "cryptan.uk1.penetapan_metode.v1",
        "app": {"name": APP_NAME, "version": __version__},
        "unit": UNIT,
        "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "mode": "quick" if quick else "full",
        "profile": summary,
        "references": refs,
        "attacks": {"items": attacks, "summary": attack_kb.summary(attacks)},
        "kat": analysis["kat"],
        "components": list(analysis["components"].values()),
        "component_summary": {
            "total": len(analysis["components"]),
            "berpotensi_lemah": [c for c, v in analysis["components"].items() if v["status"] == "BERPOTENSI_LEMAH"],
            "perhatian": [c for c, v in analysis["components"].items() if v["status"] == "PERHATIAN"],
        },
        "matrix": rows,
        "layer_summary": mapping.layer_summary(rows),
        "resources": {"benchmark": bench, "capacity": cap, "estimates": list(ests.values())},
        "selection": sel,
        "parameters": params,
        "traceability": trace,
        "kuk_map": KUK_MAP,
        "handoff_uk2": {
            "note": "Masukan untuk UK-2 (Menyusun Skenario Pengujian)",
            "algorithm": alg["id"], "primitive": alg["primitive"], "access": p["tester"]["access"],
            "methods": [{"method_id": s["method_id"], "name": s["name"], "layer": s["layer"], "level": s["level"],
                         "variant": s["variant"], "targets": s["weak_targets"] or s["targets"],
                         "parameters": params[s["method_id"]],
                         "requirements": [t["id"] for t in trace if t["method_id"] == s["method_id"]]}
                        for s in sel["selected"]],
        },
    }
    return _clean(result)
