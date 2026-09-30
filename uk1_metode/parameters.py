"""KUK 3.2 — Penetapan parameter pengujian terukur per metode terpilih."""
import math

from core import stats

ALPHA = 0.01
SP80022_M = 100
SP80022_N = 1_000_000


def sp80022_params() -> dict:
    thr = stats.sp80022_proportion_threshold(SP80022_M, ALPHA)
    return {
        "sequences_m": SP80022_M, "bits_per_sequence_n": SP80022_N, "total_bits": SP80022_M * SP80022_N,
        "alpha": ALPHA,
        "proportion_threshold": round(thr, 5),
        "proportion_threshold_formula": "(1−α) − 3·√((1−α)·α/m) = 0,99 − 3·√(0,99·0,01/100)",
        "min_pass_sequences": math.ceil(thr * SP80022_M),
        "min_pass_note": "ambang 0,96015 × 100 = 96,015 → ketat 97/100; laporan NIST STS menyebut ≈ 96/100",
        "uniformity_p_value_T_min": 0.0001, "uniformity_bins": 10,
        "tests": {
            "Frequency (Monobit)": {}, "Frequency within a Block": {"M": 128},
            "Runs": {}, "Longest Run of Ones in a Block": {"M": 10000},
            "Binary Matrix Rank": {"M": 32, "Q": 32}, "Discrete Fourier Transform (Spectral)": {},
            "Non-overlapping Template Matching": {"m": 9, "N_blocks": 8},
            "Overlapping Template Matching": {"m": 9, "M": 1032},
            "Maurer's Universal Statistical": {"L": 7, "Q": 1280},
            "Linear Complexity": {"M": 500}, "Serial": {"m": 16}, "Approximate Entropy": {"m": 10},
            "Cumulative Sums": {"mode": "forward & backward"}, "Random Excursions": {"states": "±1..±4"},
            "Random Excursions Variant": {"states": "±1..±9"},
        },
        "source": "SP 800-22 Rev.1a §2 & §4.2 (parameter default yang direkomendasikan)",
    }


def _kat_params(p, a):
    k = a["kat"]
    return {"vector_sources": sorted({c["source"] for c in k["cases"]}), "vector_count": k["total"],
            "additional_sources": "NIST CAVP/ACVP response files untuk implementasi produk",
            "pass_criterion": "100% vektor cocok (0 selisih bit)",
            "reference_result": f"{k['passed']}/{k['total']} ({k['status']}) pada core/"}


def build(method_id: str, profile: dict, analysis: dict, est: dict) -> dict:
    alg = profile["algorithm"]
    par = alg["parameters"]
    prim = alg["primitive"]
    comps = analysis["components"]
    rounds = par.get("rounds")
    P = {}
    if method_id == "M-KAT":
        P = _kat_params(profile, analysis)
    elif method_id == "M-MCT":
        P = {"mct_outer_iterations": 100, "mct_inner_iterations": 1000,
             "mmt_messages": 10 if prim == "block_cipher" else "panjang 1..10 × rate",
             "checkpoints": "setiap iterasi luar (100 checkpoint)",
             "pass_criterion": "100% checkpoint = implementasi referensi core/"}
    elif method_id == "M-SBOX":
        ref = alg.get("reference_values", {})
        P = {"properties": ["NL", "DDT/DU", "LAT/bias", "derajat aljabar", "SAC", "titik tetap", "bijektivitas"],
             "domain": "exhaustive seluruh 2^n masukan",
             "reference_values": ref, "pass_criterion": "nilai terukur = nilai acuan desain"}
    elif method_id == "M-DIFFUSION":
        P = {"rounds_tested": list(range(1, min(6, rounds or 6) + 1)), "samples_per_round": 10000,
             "metric": "fraksi bit keluaran berubah (1 bit masukan dibalik)",
             "full_diffusion_criterion": "|mean − 0,5| ≤ 0,01 dan min > 0,3",
             "branch_number_target": alg.get("reference_values", {}).get("branch_number", "n/a")}
    elif method_id == "M-AVAL":
        P = {"samples": 10000, "flip": ["1 bit plaintext/pesan", "1 bit kunci"] if prim != "hash" else ["1 bit pesan"],
             "target_mean": 0.5, "tolerance_mean": 0.01, "per_bit_tolerance": 0.05,
             "sac_matrix": "n_in × n_out probabilitas perubahan"}
    elif method_id == "M-SP80022":
        P = sp80022_params()
        P["generation"] = {"block_cipher": "keystream CTR (kunci acak, counter berurutan)",
                           "stream_cipher": "keystream (kunci & nonce acak per barisan)",
                           "hash": "digest berantai H_i = H(H_{i-1} ∥ i)"}[prim]
    elif method_id in ("M-DIFF", "M-LIN", "M-INT", "M-ARX-PNB"):
        red = est.get("reduced") or {}
        rr = {"M-DIFF": [2, 3], "M-LIN": [2, 3], "M-INT": [3, 4], "M-ARX-PNB": [3, 4]}[method_id]
        P = {"variant": "ronde tereduksi" if est["status"].endswith("TEREDUKSI") else "penuh",
             "reduced_rounds": rr, "full_rounds": rounds,
             "samples_log2": red.get("ops_log2"), "reduced_desc": red.get("desc"),
             "pass_criterion": "serangan ronde tereduksi berhasil sesuai prediksi & tidak dapat diperluas ≥ 70% ronde"}
        if method_id == "M-INT":
            P["chosen_plaintexts_per_lambda_set"] = 256
        if method_id == "M-DIFF" and prim == "block_cipher":
            P["active_sbox_bound_4r"] = comps.get("C-ROUND", {}).get("metrics", {}).get("min_active_sboxes_4r")
    elif method_id == "M-LC":
        P = {"sample_bits_N": 10000, "blocks": "10 barisan × 10^4 bit (+ SP 800-22 Linear Complexity M = 500)",
             "pass_criterion": "|L − N/2| ≤ 3"}
    elif method_id == "M-BOOL":
        P = {"functions": ["carry (mayoritas 3-bit)", "penjumlahan mod 2^n (n = 8, 16)"],
             "properties": ["NL", "derajat", "CI", "balancedness", "P[add = xor]"]}
    elif method_id == "M-BRUTE":
        red = est.get("reduced") or {}
        P = {"key_bits": par.get("key_bits"), "full_search_log2": par.get("key_bits"),
             "reduced_unknown_key_bits": 24, "reduced_ops_log2": red.get("ops_log2"),
             "pass_criterion": "harness menemukan kunci tereduksi; ekstrapolasi penuh > 10^20 tahun"}
    elif method_id == "M-KEYSIZE":
        sec = None
        for cid in ("C-KEY", "C-MOD", "C-CURVE"):
            if cid in comps:
                sec = comps[cid]["metrics"].get("security_bits") or sec
        P = {"key_parameters": {k: v for k, v in par.items() if "bits" in k or k in ("curve", "public_exponent")},
             "security_bits": sec or (128 if prim == "dss" else par.get("output_bits", 256) // 2),
             "min_security_bits": 112, "horizon": "2030 (≥128 bit untuk perlindungan setelah 2030)",
             "reference": "SP 800-57 Part 1 Rev.5 Tabel 2 & 4; SP 800-131A Rev.2"}
    elif method_id == "M-GENERIC":
        P = {"truncated_output_bits": [16, 24, 32], "trials_per_length": 20,
             "expected_collision_work": "≈ √(π/2 · 2^t)", "full_collision_bits": par.get("output_bits", 256) // 2,
             "pass_criterion": "rerata kerja empiris dalam ±20% dari √(π/2·2^t)"}
    elif method_id == "M-PAD":
        r = par.get("rate_bits", 1088) // 8
        P = {"rate_bytes": r, "lengths_bytes": [0, 1, r - 2, r - 1, r, r + 1, 2 * r - 1, 2 * r, 3 * r + 7],
             "domain_separation": "0x06 (SHA-3)", "pass_criterion": "digest = referensi untuk setiap panjang"}
    elif method_id == "M-PRIME":
        n = par.get("modulus_bits", 2048)
        P = {"sample_keys": 20, "miller_rabin_rounds": 64 if n >= 2048 else 44,
             "checks": ["p,q prima", f"|p−q| > 2^{n // 2 - 100}", f"d > 2^{n // 2}", "e ∈ (2^16, 2^256) ganjil",
                        "gcd(e, λ(n)) = 1", "p,q ≥ √2·2^(n/2−1)"],
             "reference": "FIPS 186-5 A.1.1/A.1.3, B.3; ISO/IEC 18032"}
    elif method_id == "M-PKV":
        P = {"positive_cases": 10, "negative_cases": {"pkc": ["modulus genap", "modulus prima", "e = 1/3/genap", "n < 2048 bit"],
                                                       "dss": ["titik di luar kurva", "koordinat ≥ p", "titik tak hingga", "orde ≠ n"]}[prim],
             "pass_criterion": "100% negatif ditolak, 100% positif diterima"}
    elif method_id == "M-RSAWEAK":
        P = {"sample_keys": 100, "tests": {"Fermat": "2^20 iterasi", "Pollard p−1": "B1 = 10^6", "batch-GCD": "seluruh sampel",
                                           "Wiener": "pecahan berlanjut e/n", "ROCA fingerprint": "uji diskrit log mod primorial"},
             "pass_criterion": "0 kunci terfaktorkan"}
    elif method_id == "M-FACT":
        red = est.get("reduced") or {}
        P = {"full": f"GNFS {par.get('modulus_bits')}-bit ≈ 2^112 (literatur)", "reduced_modulus_bits": [64, 80, 96],
             "reduced_ops_log2": red.get("ops_log2"), "method": "Pollard rho / ECM (validasi skala)"}
    elif method_id == "M-ORACLE":
        P = {"error_classes": ["y ≠ 0", "lHash salah", "tanpa pemisah 0x01", "panjang ciphertext salah", "c ≥ n"],
             "measurements_per_class": 100000, "statistic": "Welch t-test (fixed-vs-fixed antar kelas)",
             "threshold_abs_t": 4.5, "pass_criterion": "satu pesan/kode galat & |t| < 4,5"}
    elif method_id == "M-ECDLP":
        red = est.get("reduced") or {}
        P = {"full_log2": comps.get("C-CURVE", {}).get("metrics", {}).get("rho_log2", 127.8),
             "reduced_curve_bits": [32, 36, 40], "reduced_ops_log2": red.get("ops_log2"),
             "pass_criterion": "iterasi empiris ≈ √(πn/4) ± 25%"}
    elif method_id == "M-CURVE":
        P = {"checks": ["p, n prima", "4a³+27b² ≠ 0", "G ∈ E", "n·G = O", "h = 1", "n ≠ p", "MOV k ≤ 20"],
             "reference": "SP 800-186 §3.2.1 (P-256)"}
    elif method_id == "M-NONCE":
        P = {"signatures": 4096 if prim == "dss" else None, "messages": 2 ** 16 if prim != "dss" else None,
             "checks": ["duplikasi nonce/r = 0", "χ² 8 bit teratas k (df = 255)", "HNP lattice: bias ≥ 2 bit → 100 sampel"]
             if prim == "dss" else ["duplikasi nonce/IV = 0", "counter tidak wrap (tolak > 2^32 blok)"],
             "alpha": ALPHA}
    elif method_id == "M-SIGMAL":
        P = {"cases": ["r = 0", "s = 0", "r = n", "s = n", "(0,0)", "(r, n−s)", "encoding DER non-minimal"],
             "pass_criterion": "semua kasus di luar rentang ditolak; kebijakan low-S terdokumentasi"}
    elif method_id == "M-TIMING":
        P = {"method": "dudect fixed-vs-random (Welch t)", "measurements": 1_000_000, "threshold_abs_t": 4.5,
             "classes": {"block_cipher": "kunci tetap, plaintext tetap vs acak", "stream_cipher": "kunci tetap vs acak",
                         "hash": "pesan tetap vs acak", "pkc": "ciphertext tetap vs acak (RSADP)",
                         "dss": "nonce/kunci HW rendah vs acak"}[prim],
             "timer": "rdtsc / perf_counter_ns, core diisolasi (taskset), turbo dimatikan"}
    elif method_id == "M-CACHE":
        P = {"technique": "Flush+Reload pada tabel/fungsi library", "traces": 100000, "co-location": "core fisik sama"}
    elif method_id == "M-TVLA":
        P = {"traces": 100000, "test": "TVLA non-specific fixed-vs-random", "threshold_abs_t": 4.5, "orders": [1, 2],
             "reference": "ISO/IEC 17825"}
    elif method_id == "M-FAULT":
        P = {"injection": ["clock glitch", "voltage glitch"], "attempts": 10000}
    elif method_id == "M-CODEREVIEW":
        P = {"checklist": ["branch/lookup bergantung rahasia", "bounds check", "zeroization", "error handling seragam"]}
    elif method_id == "M-FUZZ":
        P = {"engine": "fuzzing berbasis properti (Hypothesis/AFL++ via harness C)", "executions": 1_000_000,
             "inputs": ["panjang 0", "panjang maks+1", "buffer tidak selaras", "NULL pointer", "kunci/nonce panjang salah"],
             "pass_criterion": "0 crash, 0 sanitizer error, galat terdefinisi"}
    elif method_id == "M-ZEROIZE":
        P = {"procedure": "core dump / gdb setelah free & pemanggilan API destroy", "search": "pola kunci uji (known key)",
             "pass_criterion": "0 kemunculan"}
    elif method_id == "M-SELFTEST":
        P = {"tests": ["POST KAT tiap algoritma", "pairwise consistency (pkc/dss)", "continuous RNG test", "error state injection"]}
    elif method_id == "M-RNG":
        P = {"entropy_samples_bits": 1_000_000, "sp800_90b": "IID & non-IID track, restart test 1000×1000",
             "sp800_22": "subset sesuai M-SP80022", "drbg": "CAVP DRBG KAT (HMAC_DRBG)"}
    P.setdefault("variant", "tereduksi" if est["status"].endswith("TEREDUKSI") else "penuh")
    P["estimated_time"] = est["time_human"] if est["status"] != "LAYAK VERSI TEREDUKSI" else (est.get("reduced") or {}).get("time_human")
    return P
