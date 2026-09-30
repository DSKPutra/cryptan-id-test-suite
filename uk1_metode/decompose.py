"""KUK 2.1 (bagian 1) — Dekomposisi algoritma & implementasi menjadi komponen.

Setiap komponen diberi tag kelemahan (`tags`) yang menautkannya ke basis
serangan (attacks.yaml) dan katalog metode (methods.yaml).
"""

_ALG = {
    "block_cipher": [
        ("C-SBOX", "S-box (SubBytes)", "Satu-satunya komponen nonlinear; menentukan ketahanan diferensial/linear/aljabar.", ["sbox"]),
        ("C-DIFF", "Lapisan difusi (ShiftRows + MixColumns)", "Menyebarkan perubahan antar-byte; diukur dengan branch number (MDS).", ["diffusion"]),
        ("C-ROUND", "Fungsi ronde & jumlah ronde", "Margin keamanan terhadap serangan ronde tereduksi.", ["round_count"]),
        ("C-KS", "Key schedule", "Penurunan round key; relevan untuk related-key / biclique.", ["key_schedule"]),
        ("C-KEY", "Ukuran kunci", "Ruang kunci terhadap brute force & tingkat keamanan.", ["key_size"]),
        ("C-MODE", "Mode operasi & pengelolaan counter/nonce", "Keunikan counter block & keacakan keluaran mode.", ["mode_nonce", "keystream_stat", "nonce_reuse"]),
        ("C-IMPL-TBL", "Implementasi berbasis tabel (lookup)", "Akses memori bergantung data rahasia pada platform ber-cache.", ["table_lookup", "constant_time"]),
    ],
    "stream_cipher": [
        ("C-ARX", "Quarter-round ARX (penjumlahan mod 2^32)", "Sumber nonlinearitas: bit carry penjumlahan modular (fungsi mayoritas).", ["arx_nonlinear", "boolean_function"]),
        ("C-DIFF", "Difusi antar ronde (column/diagonal round)", "Jumlah ronde hingga difusi penuh.", ["diffusion"]),
        ("C-ROUND", "Jumlah ronde (20)", "Margin keamanan terhadap PNB / differential-linear.", ["round_count"]),
        ("C-STATE", "Inisialisasi state: konstanta, kunci, counter, nonce", "Keunikan nonce & batas counter 32-bit.", ["nonce_reuse", "counter_wrap"]),
        ("C-KS-OUT", "Keluaran keystream", "Sifat statistik & kompleksitas linear keystream.", ["keystream_stat"]),
        ("C-KEY", "Ukuran kunci", "Ruang kunci 2^256.", ["key_size"]),
    ],
    "hash": [
        ("C-CHI", "Pemetaan χ (S-box 5-bit)", "Satu-satunya komponen nonlinear, derajat 2.", ["chi", "sbox"]),
        ("C-DIFF", "Lapisan linear θ, ρ, π", "Difusi antar-lane / kolom.", ["diffusion"]),
        ("C-ROUND", "ι & jumlah ronde (24)", "Margin terhadap serangan ronde tereduksi.", ["round_count"]),
        ("C-PAD", "Padding pad10*1 + domain separation", "Kebenaran padding pada batas blok (rate).", ["padding"]),
        ("C-SPONGE", "Konstruksi sponge (rate/capacity)", "Batas generik min(2^(n/2), 2^(c/2)).", ["sponge_capacity", "generic_bound"]),
    ],
    "pkc": [
        ("C-MOD", "Modulus n & ukuran kunci", "Ketahanan terhadap faktorisasi (GNFS) & status SP 800-131A.", ["key_size"]),
        ("C-PRIME", "Pembangkitan prima p, q", "Kualitas prima: primalitas, jarak |p−q|, kehalusan p−1.", ["prime_gen", "rng"]),
        ("C-EXP-E", "Eksponen publik e", "Rentang e sesuai FIPS 186-5.", ["small_e"]),
        ("C-EXP-D", "Eksponen privat d", "Ukuran d terhadap Wiener / Boneh–Durfee.", ["private_exponent"]),
        ("C-OAEP", "Encoding/decoding OAEP", "Keseragaman galat dekripsi (Manger).", ["oaep_oracle"]),
        ("C-HASH", "Hash & MGF1", "Kekuatan hash dalam OAEP.", ["hash_strength"]),
        ("C-MODEXP", "Eksponensiasi modular (RSADP/CRT)", "Kebocoran timing/cache operasi kunci privat.", ["bigint_timing", "constant_time", "fault"]),
        ("C-PKV", "Validasi kunci publik", "Penolakan modulus/eksponen tidak valid.", ["pubkey_validation"]),
    ],
    "dss": [
        ("C-CURVE", "Parameter domain kurva P-256", "Validitas p, n, a, b, G; MOV/anomalous.", ["curve_params", "key_size"]),
        ("C-PKV", "Validasi kunci publik Q", "Titik di kurva, dalam rentang, orde n.", ["pubkey_validation"]),
        ("C-NONCE", "Nonce k", "Keunikan & ketidakbiasan k (RFC 6979 / RBG).", ["nonce_bias", "rng"]),
        ("C-SMUL", "Perkalian skalar", "Kebocoran timing/cache double-and-add.", ["scalar_mult_timing", "constant_time"]),
        ("C-SIG", "Encoding & verifikasi (r, s)", "Rentang r,s & malleability (r, n−s).", ["sig_malleability"]),
        ("C-HASH", "Fungsi hash pesan", "Kekuatan hash vs tingkat keamanan kurva.", ["hash_strength"]),
    ],
}

_IMPL = [
    ("C-API", "Antarmuka API & validasi masukan", "Penanganan masukan malformed / panjang ekstrem.", ["memory_safety", "pubkey_validation"]),
    ("C-MEM", "Pengelolaan material kunci di memori", "Zeroization CSP setelah dipakai.", ["key_zeroization"]),
    ("C-SELFTEST", "Self-test & error state modul", "Power-on KAT, conditional test.", ["self_test", "conformance"]),
    ("C-RNG", "Sumber acak (RBG)", "RBG untuk kunci/nonce/seed.", ["rng"]),
    ("C-PLAT", "Platform eksekusi (CPU x86-64 bercache, speculative execution)", "Side-channel mikroarsitektur.", ["speculative", "constant_time"]),
    ("C-CONF", "Kesesuaian implementasi keseluruhan", "Keluaran identik dengan standar.", ["conformance"]),
]


def decompose(profile: dict) -> list:
    prim = profile["algorithm"]["primitive"]
    comps = [{"id": cid, "name": n, "role": d, "tags": t, "layer": "algoritma"} for cid, n, d, t in _ALG[prim]]
    impl = []
    for cid, n, d, t in _IMPL:
        if cid == "C-RNG" and prim == "hash":
            continue
        if cid == "C-PLAT" and profile["implementation"]["platform"] != "linux-x86_64-library":
            n, t = "Platform eksekusi (embedded/HSM)", ["power_em", "fault"]
        impl.append({"id": cid, "name": n, "role": d, "tags": t, "layer": "implementasi"})
    return comps + impl
