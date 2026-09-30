"""Matriks Keterlacakan (format slide 29): ID (K-xx kebutuhan keamanan,
I-xx kebutuhan implementasi), persyaratan, objek, metode uji, rujukan,
kriteria lulus. Dihasilkan dari metode terpilih (KUK 3.1) & komponen (KUK 2.1).
"""
from .standards_kb import label


def build(selected: list, methods_by_id: dict, analysis: dict) -> list:
    rows, k, i = [], 0, 0
    comps = analysis["components"]
    for s in sorted(selected, key=lambda e: (methods_by_id[e["method_id"]]["requirement"]["type"] != "K", e["method_id"])):
        m = methods_by_id[s["method_id"]]
        req = m["requirement"]
        if req["type"] == "K":
            k += 1
            rid = f"K-{k:02d}"
        else:
            i += 1
            rid = f"I-{i:02d}"
        objs = s["weak_targets"] or s["targets"]
        rows.append({
            "id": rid, "type": "Kebutuhan keamanan" if req["type"] == "K" else "Kebutuhan implementasi",
            "requirement": req["text"],
            "object": "; ".join(f"{c} {comps[c]['name']}" for c in objs if c in comps),
            "method_id": m["id"], "method": m["name"], "variant": s["variant"],
            "reference": ", ".join(label(x) for x in m["standards"]),
            "pass_criteria": req["pass"],
        })
    return rows
