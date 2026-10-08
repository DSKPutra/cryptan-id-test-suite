"""KUK 3.1 — Olah data satu run: tabel per metode (KAT, uji negatif, keunikan, SP 800-22, timing, kinerja,
avalanche, min-entropy) disusun dari bukti mentah run, memakai fungsi yang sama dengan eksekutor."""
import json
from pathlib import Path

from .. import GAGAL, LULUS
from ..evidence import append
from ..run.runner import load_run, run_dir
from . import methods as A

METHOD_ORDER = ["Smoke", "KAT", "Uji positif", "Uji negatif", "Uji diferensial", "Uji properti", "Keunikan nonce/salt",
                "NIST SP 800-22", "Avalanche", "Kinerja", "Timing (Welch t)"]
RULES = {
    "KAT": "Identik byte demi byte → LULUS",
    "Uji negatif": "Semua masukan rusak ditolak dengan galat seragam → LULUS",
    "Keunikan nonce/salt": "0 duplikat → LULUS",
    "NIST SP 800-22": "Proporsi ≥ 0,99 − 3√(0,0099/m); P-value_T ≥ 0,0001",
    "Timing (Welch t)": "|t| ≤ 4,5 → tidak ada indikasi bocor",
    "Kinerja": "Batas atas selang 95% ≤ target",
    "Avalanche": "|z| ≤ 3 → konsisten dengan perilaku ideal",
    "Uji diferensial": "Semua keluaran identik dengan implementasi independen",
    "Uji properti": "Invarian berlaku untuk semua masukan",
    "Uji positif": "Hasil sesuai spesifikasi",
    "Smoke": "Produk termuat dan round-trip dasar berhasil",
}


def _ev(d: Path, row):
    if not row.get("bukti"):
        return {}
    return json.loads((d / row["bukti"]).read_text(encoding="utf-8"))


def analyze(product_id, run_id, out_root=None) -> dict:
    rec = load_run(product_id, run_id, out_root)
    d = run_dir(product_id, run_id, out_root)
    per_method, checks = {}, []
    for ver, vr in rec["versi"].items():
        neg_cases = []
        for row in vr["tc"]:
            m = row.get("metode")
            if not m:
                continue
            ev = _ev(d, row)
            data = ev.get("data") or {}
            entry = {"versi": ver, "tc": row["id"], "status": row["status"], "ringkas": row["actual"]}
            recomputed = None
            if m == "KAT" and data:
                recomputed = A.kat(data["actual"], data["expected"])
                entry["olah"] = f"{recomputed['panjang_aktual']} byte; " + (
                    "identik" if recomputed["identik"] else f"beda mulai byte ke-{recomputed['byte_beda_pertama']}")
                ok = recomputed["identik"]
            elif m == "Uji negatif" and data.get("cases"):
                neg_cases += [{**c, "tc": row["id"]} for c in data["cases"]]
                recomputed = A.negative(data["cases"])
                entry["olah"] = f"{recomputed['ditolak']}/{recomputed['total']} ditolak; kelas galat {recomputed['kelas_galat']}"
                ok = recomputed["semua_ditolak"]
                if "low_s_wajib" in data:
                    ok = None
            elif m == "Keunikan nonce/salt" and data.get("salts"):
                s, n = A.uniqueness(data["salts"], "salt"), A.uniqueness(data["nonces"], "nonce")
                entry["olah"] = f"{s['teks']} ({s['duplikat']} duplikat); {n['teks']} ({n['duplikat']} duplikat)"
                ok = s["ok"] and n["ok"]
                recomputed = {"salt": s, "nonce": n}
            elif m == "NIST SP 800-22" and data.get("p_values"):
                from ..stats import proportion_decision, uniformity
                rows = {}
                ok = True
                for t, pv in data["p_values"].items():
                    pd_ = proportion_decision(sum(p >= 0.01 for p in pv), len(pv))
                    un = uniformity(pv)
                    rows[t] = {"proporsi": pd_["proportion"], "batas_bawah": pd_["low"], "P_value_T": un["p_value_T"],
                               "histogram": un["counts"], "ok": pd_["ok"] and (un["ok"] if len(pv) >= 55 else True)}
                    ok &= rows[t]["ok"]
                recomputed = rows
                entry["olah"] = "; ".join(f"{t}: proporsi {r['proporsi']:.2f} (≥ {r['batas_bawah']:.4f}), P-value_T {r['P_value_T']:.4f}"
                                          for t, r in rows.items())
                entry["min_entropy"] = (row.get("analisis") or {}).get("min_entropy")
            elif m == "Kinerja" and data.get("times_s"):
                recomputed = A.performance(data["times_s"], data.get("warmup", 0), (row.get("analisis") or {}).get("target"))
                entry["olah"] = (f"n = {recomputed['n']} (pemanasan {recomputed['warmup_dibuang']} dibuang), rata-rata {recomputed['mean']:.4f} s, "
                                 f"s = {recomputed['sd']:.4f}, 95%: {recomputed['low']:.4f}–{recomputed['high']:.4f} s, p95 {recomputed['p95']:.4f} s")
                ok = recomputed["ok"]
            else:
                an = row.get("analisis") or {}
                entry["olah"] = row["actual"]
                ok = None
                recomputed = an or None
            entry["analisis"] = recomputed
            if ok is not None and row["status"] in (LULUS, GAGAL):
                consistent = (row["status"] == LULUS) == bool(ok)
                checks.append({"versi": ver, "tc": row["id"], "konsisten": consistent})
            per_method.setdefault(m, []).append(entry)
        if neg_cases:
            groups = {}
            for c in neg_cases:
                if c.get("rejected"):
                    groups.setdefault(c.get("group", "default"), set()).add(c.get("error_class"))
            per_method.setdefault("_galat_seragam", []).append({"versi": ver, "kelompok": {g: sorted(v) for g, v in groups.items()},
                                                                 "seragam": all(len(v) == 1 for v in groups.values())})
    uniform = per_method.pop("_galat_seragam", [])
    res = {"schema": "cryptan.uk3.analysis.v1", "run_id": run_id, "produk": product_id,
           "metode": [{"metode": m, "aturan": RULES.get(m, ""), "baris": per_method[m]} for m in METHOD_ORDER if m in per_method],
           "galat_seragam": uniform, "konsistensi_keputusan": checks,
           "konsisten": all(c["konsisten"] for c in checks)}
    out = d / "analisis.json"
    out.write_text(json.dumps(res, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    append(d, [out])
    return res
