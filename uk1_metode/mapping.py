"""KUK 2.2 — Analisis best practice vs potensi kelemahan.

Menyusun Matriks Komponen → Kelemahan → Metode Uji → Standar mengikuti tiga
lapis pengujian (Kesesuaian / Kekuatan algoritma / Implementasi & sistem) dan
level uji (Unit / Integrasi / Sistem), disesuaikan dengan tingkat akses penguji.
"""
from pathlib import Path

import yaml

from .profile import ACCESS_SHORT, access_level

METHODS = Path(__file__).parent / "data" / "methods.yaml"
LAYERS = ["Kesesuaian", "Kekuatan algoritma", "Implementasi & sistem"]
LEVELS = ["Unit", "Integrasi", "Sistem"]

WEAKNESS = {
    "sbox": "Nonlinearitas/keseragaman diferensial S-box tidak memadai",
    "chi": "Derajat aljabar rendah pemetaan χ",
    "diffusion": "Difusi tidak lengkap / branch number rendah",
    "round_count": "Margin ronde tidak memadai terhadap serangan ronde tereduksi",
    "key_schedule": "Key schedule lemah (related-key / biclique)",
    "key_size": "Ruang kunci / tingkat keamanan tidak memadai",
    "mode_nonce": "Penyalahgunaan mode (counter/IV berulang, padding oracle)",
    "keystream_stat": "Keluaran terbedakan dari acak",
    "nonce_reuse": "Nonce/IV dipakai ulang",
    "counter_wrap": "Counter wrap-around → keystream berulang",
    "table_lookup": "Lookup tabel bergantung data rahasia (cache-timing)",
    "constant_time": "Eksekusi tidak constant-time",
    "arx_nonlinear": "Nonlinearitas ARX rendah pada ronde awal",
    "boolean_function": "Fungsi Boolean dengan NL/CI/derajat rendah",
    "padding": "Padding salah pada batas blok",
    "sponge_capacity": "Kapasitas sponge tidak memadai",
    "generic_bound": "Batas generik collision/preimage di bawah target",
    "prime_gen": "Prima lemah (berdekatan, p−1 smooth, faktor bersama)",
    "private_exponent": "Eksponen privat kecil",
    "small_e": "Eksponen publik kecil tanpa padding",
    "oaep_oracle": "Oracle galat/timing dekripsi OAEP",
    "hash_strength": "Kekuatan hash di bawah tingkat keamanan skema",
    "bigint_timing": "Timing/cache pada aritmetika bilangan besar",
    "rng": "RBG lemah / entropi rendah",
    "curve_params": "Parameter domain kurva tidak valid",
    "pubkey_validation": "Kunci publik/titik tidak divalidasi",
    "nonce_bias": "Nonce tanda tangan berulang/bias",
    "sig_malleability": "Tanda tangan non-kanonik/malleable diterima",
    "scalar_mult_timing": "Timing/cache pada perkalian skalar",
    "memory_safety": "Buffer overflow / masukan malformed",
    "key_zeroization": "Material kunci tidak dihapus dari memori",
    "self_test": "Self-test / error state tidak berfungsi",
    "speculative": "Kebocoran eksekusi spekulatif",
    "power_em": "Kebocoran daya/EM",
    "fault": "Kerentanan injeksi kesalahan",
    "conformance": "Keluaran implementasi tidak sesuai standar",
}


def load_methods() -> list:
    return yaml.safe_load(METHODS.read_text(encoding="utf-8"))["methods"]


def methods_for(profile: dict) -> list:
    prim = profile["algorithm"]["primitive"]
    return [m for m in load_methods() if prim in m["primitives"]]


def access_ok(method: dict, profile: dict) -> bool:
    return access_level(profile) >= ACCESS_SHORT[method["access"]]


def build_matrix(profile: dict, analysis: dict, attacks: list) -> list:
    """Satu baris per (komponen, kelemahan, metode)."""
    methods = methods_for(profile)
    rows = []
    for cid, c in analysis["components"].items():
        for tag in c["tags"]:
            atk = [a["id"] for a in attacks if tag in a.get("targets", [])]
            for m in methods:
                if tag not in m["addresses"]:
                    continue
                ok = access_ok(m, profile)
                rows.append({
                    "component_id": cid, "component": c["name"], "component_status": c["status"],
                    "weakness_tag": tag, "weakness": WEAKNESS.get(tag, tag), "attacks": atk,
                    "method_id": m["id"], "method": m["name"], "layer": m["layer"], "level": m["level"],
                    "standards": m["standards"], "access_required": m["access"], "access_ok": ok,
                    "access_note": "" if ok else f"butuh akses {m['access']}-box; penguji {profile['tester']['access']}",
                })
    order = {l: i for i, l in enumerate(LAYERS)}
    lv = {l: i for i, l in enumerate(LEVELS)}
    return sorted(rows, key=lambda r: (order[r["layer"]], lv[r["level"]], r["component_id"], r["method_id"]))


def layer_summary(rows: list) -> dict:
    out = {}
    for l in LAYERS:
        out[l] = {lv: sorted({r["method_id"] for r in rows if r["layer"] == l and r["level"] == lv}) for lv in LEVELS}
    return out
