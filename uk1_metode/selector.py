"""KUK 3.1 — Penetapan metode pengujian.

Skor = relevansi × kelayakan sumber daya × kesesuaian tingkat akses, dengan
relevansi = keparahan komponen target (1–3) + bobot tren serangan (KUK 1.2):
+1 bila ada serangan praktis, +0,5 bila hanya teoretis (maks 3).
Metode wajib (mandatory) dipilih bila layak & akses memadai. Metode yang
ditolak disertai alasan.
"""
from .resources import LAYAK, REDUKSI, TIDAK

SEVERITY = {"BERPOTENSI_LEMAH": 3, "PERHATIAN": 2, "OK": 1}
FEAS = {LAYAK: 1.0, REDUKSI: 0.6, TIDAK: 0.0}
THRESHOLD = 1.0


def _attack_bonus(mine: list, attack_status: dict) -> float:
    ids = {a for r in mine for a in r["attacks"]}
    if any(str(attack_status.get(a, "")).startswith("praktis") for a in ids):
        return 1.0
    return 0.5 if ids else 0.0


def score(method: dict, rows: list, est: dict, access_ok: bool, attack_status: dict = None) -> dict:
    mine = [r for r in rows if r["method_id"] == method["id"]]
    base = max((SEVERITY[r["component_status"]] for r in mine), default=0)
    bonus = _attack_bonus(mine, attack_status or {}) if base else 0.0
    relevance = min(3.0, base + bonus)
    targets = sorted({r["component_id"] for r in mine})
    weak_targets = sorted({r["component_id"] for r in mine if r["component_status"] != "OK"})
    feas = FEAS[est["status"]]
    acc = 1.0 if access_ok else 0.0
    return {"relevance": relevance, "severity": base, "attack_bonus": bonus, "feasibility": feas, "access": acc,
            "score": round(relevance * feas * acc, 2), "targets": targets, "weak_targets": weak_targets}


def select(methods: list, rows: list, estimates: dict, access_fn, attacks: list = ()) -> dict:
    attack_status = {a["id"]: a["status"] for a in attacks}
    chosen, rejected = [], []
    for m in methods:
        est = estimates[m["id"]]
        ok = access_fn(m)
        s = score(m, rows, est, ok, attack_status)
        entry = {"method_id": m["id"], "name": m["name"], "layer": m["layer"], "level": m["level"],
                 "standards": m["standards"], "feasibility": est["status"], **s,
                 "variant": "tereduksi" if est["status"] == REDUKSI else "penuh"}
        if not ok:
            entry["reason"] = f"Ditolak: memerlukan akses {m['access']}-box (di luar akses penguji)"
            rejected.append(entry)
        elif est["status"] == TIDAK:
            entry["reason"] = f"Ditolak: {est['reason']}"
            rejected.append(entry)
        elif m.get("mandatory"):
            entry["reason"] = "Wajib (kesesuaian standar / baseline keamanan). " + est["reason"]
            chosen.append(entry)
        elif s["relevance"] == 0:
            entry["reason"] = "Ditolak: tidak ada komponen yang ditargetkan"
            rejected.append(entry)
        elif s["score"] >= THRESHOLD:
            w = ", ".join(s["weak_targets"]) or "komponen OK (verifikasi)"
            entry["reason"] = (f"Skor {s['score']} ≥ {THRESHOLD}: relevan terhadap {w}. {est['reason']}")
            chosen.append(entry)
        else:
            entry["reason"] = f"Ditolak: skor {s['score']} < {THRESHOLD}"
            rejected.append(entry)
    chosen.sort(key=lambda e: (-e["score"], e["method_id"]))
    return {"selected": chosen, "rejected": rejected, "threshold": THRESHOLD,
            "formula": "skor = relevansi[keparahan 1–3 + tren serangan (+1 praktis | +0,5 teoretis), maks 3] × kelayakan(1 | 0,6 | 0) × akses(1 | 0)"}
