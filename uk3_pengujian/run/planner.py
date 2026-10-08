"""KUK 2.1 — Tahapan pengujian diidentifikasi berdasarkan test case.

Test case dibaca dari skenario produk (gaya UK-2) atau dari outputs/uk2/uk2_skenario.json, diurutkan ke enam tahapan,
dan dibangun graf ketergantungan: bila smoke test atau KAT gagal, TC yang bergantung padanya TERBLOKIR."""
from ..prep.documents import load_scenario

STAGES = {1: "Smoke test", 2: "Kesesuaian algoritma (KAT)", 3: "Fungsional", 4: "Negatif & penanganan galat",
          5: "Sifat keamanan & statistik", 6: "Kinerja & implementasi"}
STAGE_REASON = {1: "Produk dapat dijalankan sama sekali", 2: "Primitif benar sebelum fitur di atasnya diuji",
                3: "Alur normal berjalan", 4: "Masukan salah ditolak dengan aman", 5: "Butuh data banyak atau waktu lama",
                6: "Butuh pengukuran berulang"}

NINE_STEPS = [
    (1, "Tetapkan spesifikasi", "Primitif, mode, parameter, format masukan/keluaran", "Uji belum boleh dimulai"),
    (2, "Siapkan oracle", "Test vector resmi atau implementasi acuan independen", "Uji belum boleh dimulai"),
    (3, "KAT dan uji positif", "FIPS 197 C.1, RFC 8439 §2.3.2, RFC 4231", "Langkah 4–8 TERBLOKIR"),
    (4, "Uji negatif", "Tag/tanda tangan diubah, masukan terpotong, parameter salah", "Catat GAGAL, lanjutkan"),
    (5, "Uji diferensial", "Implementasi A vs implementasi B pada banyak masukan", "Kembali ke spesifikasi"),
    (6, "Uji properti", "decrypt(encrypt(m)) = m; hash bertahap = hash sekaligus", "Catat GAGAL, lanjutkan"),
    (7, "Uji statistik (bila relevan)", "Keystream, keluaran DRBG, nonce", "Analisis proporsi"),
    (8, "Kinerja & side channel", "Throughput, distribusi waktu (Welch t)", "Analisis lanjutan"),
    (9, "Dokumentasi", "Versi, parameter, data, seed, lingkungan", "–"),
]

# pemetaan aksi runner UK-2 → (tahap, jenis uji)
UK2_ACTION = {"kat_vectors": (2, "kat"), "sigver_vectors": (2, "kat"), "mct": (2, "kat"), "component_props": (2, "properti"),
              "roundtrip": (3, "properti"), "interop": (3, "diferensial"), "chain_e2e": (3, "positif"), "config_audit": (3, "positif"),
              "manual": (3, "positif"), "api_negative": (4, "negatif"), "fuzz": (4, "negatif"), "weak_key_battery": (4, "negatif"),
              "keygen_validate": (4, "negatif"), "statistical_suite": (5, "statistik"), "nonce_stats": (5, "statistik"),
              "oracle_uniformity": (5, "statistik"), "reduced_round_analysis": (5, "properti"), "performance": (6, "kinerja"),
              "timing_tvla": (6, "timing")}


def _from_uk2(sc) -> list:
    tcs = [{"id": "SL-SMOKE", "skenario": "—", "judul": "Smoke test produk SecureLib (ditambahkan UK-3)", "tahap": 1, "jenis": "smoke",
            "executor": None, "sasaran": "SL", "wajib": True, "depends_on": [], "negatif": False,
            "expected": {"kriteria": "modul termuat, self-test lulus"}}]
    kat_by_cat = {}
    for t in sc.get("test_cases", []):
        tahap, jenis = UK2_ACTION.get(t["runner"]["action"], (3, "positif"))
        if t.get("negative"):
            tahap, jenis = 4, "negatif"
        if tahap == 2:
            kat_by_cat.setdefault(t["category"], []).append(t["id"])
        tcs.append({"id": t["id"], "skenario": t.get("scenario") or t.get("scenario_id") or t["category"], "judul": t["title"],
                    "tahap": tahap, "jenis": jenis, "executor": None, "sasaran": t["category"], "wajib": t.get("priority") != "Rendah",
                    "depends_on": ["SL-SMOKE"], "negatif": jenis == "negatif", "aksi_uk2": t["runner"]["action"],
                    "expected": {"kriteria": t.get("pass"), "sumber": ", ".join(t.get("standard_labels") or [])}})
    for t in tcs:
        if t["tahap"] >= 3:
            t["depends_on"] = t["depends_on"] + kat_by_cat.get(t["sasaran"], [])
    return tcs


def test_cases(product_id) -> list:
    sc = load_scenario(product_id)
    if "handoff_uk3" in sc or sc.get("schema", "").startswith("cryptan.uk2"):
        return _from_uk2(sc)
    out = []
    for t in sc.get("test_cases", []):
        out.append({**t, "negatif": t.get("jenis") == "negatif"})
    return out


def plan(product_id, select="all") -> dict:
    tcs = test_cases(product_id)
    ids = {t["id"] for t in tcs}
    if select not in (None, "all"):
        want = set(select.split(",") if isinstance(select, str) else select)
        chosen = [t for t in tcs if t["id"] in want]
    else:
        chosen = tcs
    order = {t["id"]: i for i, t in enumerate(tcs)}
    chosen = sorted(chosen, key=lambda t: (t["tahap"], order[t["id"]]))
    edges = [(d, t["id"]) for t in chosen for d in t.get("depends_on", []) if d in ids]
    neg = sum(1 for t in chosen if t["negatif"])
    warn = []
    if chosen and neg < len(chosen) / 3:
        warn.append(f"Uji negatif {neg} dari {len(chosen)} TC (< sepertiga). Materi: uji negatif harus banyak, minimal sepertiga.")
    missing_dep = sorted({d for t in chosen for d in t.get("depends_on", []) if d not in ids})
    if missing_dep:
        warn.append(f"Ketergantungan tidak dikenal: {', '.join(missing_dep)}")
    stages = []
    for s, name in STAGES.items():
        stages.append({"tahap": s, "nama": name, "alasan": STAGE_REASON[s], "tc": [t["id"] for t in chosen if t["tahap"] == s]})
    return {"produk": product_id, "tc": chosen, "tidak_dipilih": [t["id"] for t in tcs if t not in chosen], "tahapan": stages,
            "graf": edges, "jumlah": len(chosen), "negatif": neg, "peringatan": warn, "sembilan_langkah": NINE_STEPS,
            "jenis_uji": sorted({t["jenis"] for t in chosen})}


def blocked_by(tc, status: dict) -> list:
    """Daftar ketergantungan yang GAGAL/TERBLOKIR/TIDAK DAPAT DIUJI → TC ini TERBLOKIR."""
    return [f"{d} ({status[d]})" for d in tc.get("depends_on", []) if status.get(d) in ("GAGAL", "TERBLOKIR", "TIDAK DAPAT DIUJI")]
