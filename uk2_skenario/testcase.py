"""KUK 2.3 — Identifikasi test case dari skenario yang sudah terverifikasi.

Format ID mengikuti materi: <KAT>-<K/S/I>-<nn> (mis. DS-K-01, PR-S-03, BC-I-02) atau
<U/I/S/A>-<K/S/I>-<nn> untuk model 4 tingkat (modul ISO/IEC 19790). Setiap test case memuat:
ID, tingkat, lapis, area 19790 (opsional), parameter & nilai uji, prasyarat, langkah bernomor,
kriteria lulus, metode asal (UK-1), rujukan standar, prioritas, pelaksana, expected value,
dan objek `runner` yang dapat dieksekusi langsung oleh UK-3 (Melakukan Pengujian).
"""
from uk1_metode.standards_kb import catalog as std_catalog

from .context import LAYERS

RUNNER_ACTIONS = {
    "kat_vectors": "Eksekusi vektor expected & bandingkan byte-per-byte",
    "sigver_vectors": "Verifikasi vektor tanda tangan; bandingkan keputusan terima/tolak",
    "mct": "Monte Carlo Test berantai; bandingkan checkpoint",
    "roundtrip": "Properti D(E(x)) = x / konsistensi bertahap",
    "api_negative": "Panggil API dengan masukan negatif; harapkan galat",
    "interop": "Uji silang dua arah dengan implementasi referensi",
    "component_props": "Hitung properti komponen (NL, DDT, LAT, derajat, difusi)",
    "statistical_suite": "Uji statistik (avalanche, SP 800-22, SP 800-90B, χ²)",
    "nonce_stats": "Kumpulkan nonce/r; uji duplikasi & bias",
    "reduced_round_analysis": "Analisis ronde tereduksi & margin keamanan",
    "config_audit": "Audit konfigurasi/klaim terhadap SP 800-57/131A",
    "timing_tvla": "Pengukuran waktu fixed-vs-random; Welch t (TVLA)",
    "oracle_uniformity": "Kelas galat dekripsi: keseragaman pesan & waktu",
    "fuzz": "Fuzzing di bawah sanitizer",
    "keygen_validate": "Bangkitkan kunci & validasi syarat standar",
    "weak_key_battery": "Batch-GCD/Fermat/Pollard p−1/Wiener",
    "performance": "Uji beban/throughput/ketersediaan",
    "protocol_harness": "Harness protokol (handshake/negosiasi/replay)",
    "formal_model": "Analisis formal (Tamarin/ProVerif)",
    "chain_e2e": "Alur end-to-end lintas-algoritma",
    "manual": "Prosedur manual/lab — checklist bukti",
}
OUTCOMES = ["Memenuhi", "Memenuhi dengan Catatan", "Tidak Memenuhi", "Inkonklusif"]


def _std_labels(ids):
    cat = std_catalog()
    return [f"{i.replace('-', ' ', 1)}" + ("" if i in cat else " (PERLU_VERIFIKASI)") for i in ids]


def _narrative(tc) -> str:
    tg = ", ".join(tc["targets"][:6]) + (f" dan {len(tc['targets']) - 6} objek lain" if len(tc["targets"]) > 6 else "")
    nvals = len(tc["parameters"])
    neg = " Seluruh masukan pada uji ini bersifat negatif, sehingga hasil yang benar adalah PENOLAKAN." if tc["negative"] else ""
    return (f"Penguji melakukan {tc['title'][0].lower() + tc['title'][1:]} pada {tg}"
            + (f" dengan {nvals} nilai parameter uji" if nvals else "") + ". "
            + f"Uji dinyatakan Memenuhi bila: {tc['pass']}.{neg}")


def build(ctx, design: dict, verification: dict, exp: dict, pspace: dict) -> list:
    if verification["status"] != "LULUS":
        verified = set(verification["verified_recipes"])     # tetap diturunkan, ditandai status verifikasi
    gov = ctx.iso.get("governance", {})
    gov_by_tier = dict(zip(["Unit", "Integrasi", "Sistem", "UAT"], gov.values()))
    tcs = []
    for r in design["recipes"]:
        kind = r.get("expected", {}).get("kind")
        refs = [{"target": t, **exp["refs"][(r["id"], t)]} for t in r["targets"] if (r["id"], t) in exp["refs"]]
        prereq = [f"Objek uji tersedia & terkonfigurasi: {', '.join(r['targets'][:8])}" + (" …" if len(r["targets"]) > 8 else ""),
                  "Kunci & data uji ilustratif (bukan material produksi)"]
        if r.get("requires"):
            prereq.append("Fitur/akses tersedia: " + ", ".join(r["requires"]))
        if refs:
            prereq.append("Expected value terverifikasi integritasnya (SHA-256 berkas expected/*.json)")
        if ctx.model == 4 and r["level"] in gov_by_tier:
            prereq.append("Kriteria masuk tingkat: " + gov_by_tier[r["level"]].get("entry", ""))
        steps = list(r.get("steps", []))
        steps.append("Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, "
                     "lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif)")
        executor = gov_by_tier.get(r["level"], {}).get("executor") if ctx.model == 4 else r.get("executor")
        combos = []
        if r["id"] == "PR-K-04":
            combos = pspace["categories"].get("protocol", {}).get("pairwise", {}).get("tests", [])
        tc = {
            "id": r["id"], "title": r["title"], "category": r["category"], "tier": r["level"],
            "tier_note": r.get("level_note"), "layer": r["layer"], "layer_label": LAYERS[r["layer"]],
            "area": r.get("area"), "targets": r["targets"],
            "parameters": r.get("param_values", []), "pairwise_combinations": combos,
            "material_reference": r.get("material"),
            "prerequisites": prereq, "steps": [f"{i}. {s}" for i, s in enumerate(steps, 1)],
            "pass": r["pass"], "methods": r.get("methods", []),
            "method_names": [ctx.methods_catalog.get(m, {}).get("name", m) for m in r.get("methods", [])],
            "standards": r.get("standards", []), "standard_labels": _std_labels(r.get("standards", [])),
            "claims": r.get("claims", []), "requires": r.get("requires", []),
            "priority": r.get("priority", "Sedang"), "executor": executor or "Penguji lab",
            "negative": kind == "negative", "expected_kind": kind, "expected": refs,
            "expected_status": sorted({x["status"] for x in refs}) or ["KRITERIA"],
            "runner": {"action": r.get("runner", "manual"), "description": RUNNER_ACTIONS.get(r.get("runner", "manual"), ""),
                       "targets": r["targets"], "expected_files": [x["file"] for x in refs],
                       "inputs": {"parameters": [{"param": p["param"], "value": p["value"], "expect": p["expect"]} for p in r.get("param_values", [])],
                                  "pairwise": combos},
                       "decision": {"kind": kind, "outcomes": OUTCOMES}},
            "verification": "TERVERIFIKASI" if verification["status"] == "LULUS" or r["id"] in verified else "BELUM",
        }
        tc["narrative"] = _narrative(tc)
        tcs.append(tc)
    order = {"K": 0, "S": 1, "I": 2}
    return sorted(tcs, key=lambda t: (t["category"] == "cross", order[t["layer"]], t["id"]))
