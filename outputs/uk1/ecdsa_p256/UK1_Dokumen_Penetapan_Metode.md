# Dokumen Penetapan Metode & Parameter Pengujian — ECDSA-P256

**Cryptan.ID Test Suite** v1.0.0 · Modul **UK-1** · Unit J.61KRP00.012.1 — *Menentukan Metode Pengujian yang akan Dilakukan* · SKKNI 2023-004 (Cryptographic Analyst)

Dibangkitkan: 2026-09-30T23:04:35+07:00 · mode: full · objek: **Cryptan.ID SecureLib** (1.0.0 (hipotetis))

> Seluruh data produk bersifat ILUSTRATIF. Nilai bertanda HASIL UJI LANGSUNG dihitung oleh kode; HASIL LITERATUR dikutip dari rujukan; PERLU_VERIFIKASI wajib dicek ke sumber primer.

## Ringkasan

- Kelas primitif: **Tanda tangan digital (DSS)**, struktur Elliptic curve discrete log (ECC)
- Tingkat akses penguji: **grey_box**
- KAT implementasi referensi: **4/4 LULUS**
- Komponen berpotensi lemah: **—**; perlu perhatian: C-SMUL, C-SIG, C-API, C-MEM, C-PLAT
- Metode terpilih: **12** · ditolak: 4 · upaya 49 / 240 jam-orang (SESUAI)

## 1. Profil Produk & Ruang Lingkup (KUK 1.1)

| Atribut | Nilai |
|---|---|
| Produk | Cryptan.ID SecureLib 1.0.0 (hipotetis) |
| Deskripsi | Library kriptografi perangkat lunak (shared object) untuk Linux x86-64 |
| Algoritma | ECDSA P-256 + SHA-256 (FIPS 186-5, SP 800-186) |
| Kelas primitif | Tanda tangan digital (DSS) |
| Struktur | Elliptic curve discrete log (ECC) |
| Mode | — |
| Parameter | curve=P-256; field_bits=256; order_bits=256; hash=sha256; nonce=RFC 6979 deterministik |
| Platform | Shared library (.so) di Linux x86-64; CPU multi-core dengan cache L3 bersama |
| Bahasa / binding | C / Python |
| Antarmuka | C API (libsecure.so), Python binding (ctypes) |
| RBG | getrandom(2) → HMAC_DRBG (SP 800-90A) |
| Catatan implementasi | nonce_generation=rfc6979; low_s_enforced=False |
| Tingkat akses | grey_box — Penguji memperoleh spesifikasi algoritma & dokumen desain tingkat tinggi, biner library + header API, dan lingkungan uji dengan kunci uji. Kode sumber TIDAK tersedia. |
| Kelengkapan profil | LENGKAP |

**Ruang lingkup:**

- Kesesuaian implementasi algoritma terhadap standar (KAT/MCT)
- Kekuatan algoritma (komponen, ronde tereduksi, keacakan keluaran)
- Implementasi pada platform: timing/cache, validasi masukan, RNG, self-test

**Di luar ruang lingkup:**

- Serangan invasif fisik (decapsulation, probing)
- Keamanan sistem operasi host di luar library

## 2. Daftar Referensi Standar & Tren Serangan

### 2.1 Daftar Referensi Standar (KUK 1.3)

| ID | Organisasi | Judul | Tahun | Peran |
|---|---|---|---|---|
| FIPS-180-4 | NIST | Secure Hash Standard (SHS) | 2015 | Spesifikasi algoritma/skema |
| FIPS-186-5 | NIST | Digital Signature Standard (DSS) | 2023 | Spesifikasi algoritma/skema |
| ISO-14888-3 | ISO/IEC | Digital signatures with appendix — Part 3: Discrete logarithm based mechanisms (EC-DSA) | 2018 | Spesifikasi algoritma/skema |
| RFC-6979 | IETF | Deterministic Usage of DSA and ECDSA *(Di luar daftar materi; nonce deterministik & test vector)* | 2013 | Spesifikasi algoritma/skema |
| SP-800-186 | NIST | Recommendations for Discrete Logarithm-based Cryptography: Elliptic Curve Domain Parameters | 2023 | Spesifikasi algoritma/skema |
| ISO-18367 | ISO/IEC | Cryptographic algorithms and security mechanisms conformance testing | 2016 | Pengujian kesesuaian |
| SP-800-107 | NIST | Recommendation for Applications Using Approved Hash Algorithms (Rev. 1) | 2012 | Pengujian kekuatan / kriteria keamanan |
| ISO-17825 | ISO/IEC | Testing methods for the mitigation of non-invasive attack classes against cryptographic modules `PERLU_VERIFIKASI` | 2024 | Pengujian implementasi & modul |
| ISO-19790 | ISO/IEC | Security requirements for cryptographic modules | 2012 | Pengujian implementasi & modul |
| ISO-20085 | ISO/IEC | Test tool requirements and test tool calibration methods for use in testing non-invasive attack mitigation techniques | 2019 | Pengujian implementasi & modul |
| ISO-24759 | ISO/IEC | Test requirements for cryptographic modules | 2017 | Pengujian implementasi & modul |
| SP-800-131A | NIST | Transitioning the Use of Cryptographic Algorithms and Key Lengths (Rev. 2) | 2019 | Ukuran kunci & manajemen kunci |
| SP-800-57 | NIST | Recommendation for Key Management, Part 1: General (Rev. 5) | 2020 | Ukuran kunci & manajemen kunci |
| ISO-18031 | ISO/IEC | Random bit generation | 2011 | Pembangkitan bilangan acak |
| SP-800-90A | NIST | Recommendation for Random Number Generation Using Deterministic RBGs (Rev. 1) | 2015 | Pembangkitan bilangan acak |
| FIPS-204 | NIST | Module-Lattice-Based Digital Signature Standard (ML-DSA) | 2024 | Evaluasi keamanan / migrasi |
| FIPS-205 | NIST | Stateless Hash-Based Digital Signature Standard (SLH-DSA) | 2024 | Evaluasi keamanan / migrasi |
| ISO-15408 | ISO/IEC | Evaluation criteria for IT security (Common Criteria) | 2022 | Evaluasi keamanan / migrasi |
| ISO-18045 | ISO/IEC | Methodology for IT security evaluation (CEM) | 2022 | Evaluasi keamanan / migrasi |
| ISO-29119 | ISO/IEC/IEEE | Software and systems engineering — Software testing | 2022 | Proses & dokumentasi pengujian |

### 2.2 Tren Serangan Relevan (KUK 1.2) — HASIL LITERATUR

13 serangan relevan setelah filter profil; praktis: 11; perlu verifikasi: 2.

| ID | Kategori | Serangan | Model | Kompleksitas (log2 T/D/M) | Ronde | Status | Rujukan |
|---|---|---|---|---|---|---|---|
| A-P-02 | desain | Algoritma Shor (komputer kuantum) | n/a | —/—/— | n/a | teoretis (ancaman masa depan / harvest-now-decrypt-later) | Shor, FOCS 1994; FIPS 203/204/205 (migrasi PQC) |
| A-D-01 | desain | Pollard rho (ECDLP) | n/a | 128/0/0 | n/a | teoretis | Pollard, Math. Comp. 1978; SP 800-57 Part 1 Rev.5 Tabel 2 (P-256 ≈ 128-bit) |
| A-D-02 | protokol | Nonce reuse → pemulihan kunci privat | KMA (known message) | 0/1/0 | n/a | praktis | fail0verflow — Console Hacking 2010 (PS3 ECDSA), 27C3 |
| A-D-04 | protokol | Invalid-curve / kunci publik tidak tervalidasi | CCA | —/—/— | n/a | praktis (terutama ECDH) | Biehl, Meyer, Müller — Differential Fault Attacks on Elliptic Curve Cryptosystems, CRYPTO 2000; Jager, Schwenk, Somorovsky — Practical Invalid Curve Attacks on TLS-ECDH, ESORICS 2015 |
| A-D-05 | protokol | Malleability tanda tangan (r, n−s) | n/a | 0/0/0 | n/a | praktis (dampak pada protokol yang memakai sig sebagai ID) | Bitcoin BIP-62 / BIP-146 (low-S) |
| A-L-01 | bahasa | Perbandingan tidak constant-time (memcmp pada tag/MAC/padding) | side-channel | —/—/— | n/a | praktis `PERLU_VERIFIKASI` | Lawson — Timing attack in Google Keyczar, 2009; ISO/IEC 17825 |
| A-L-02 | bahasa | Buffer over-read/overflow (memory safety) | n/a | 0/0/0 | n/a | praktis | NVD CVE-2014-0160 (Heartbleed, OpenSSL) |
| A-L-03 | bahasa | Material kunci tidak di-zeroize (sisa di memori / cold boot) | n/a | —/—/— | n/a | praktis | Halderman et al. — Lest We Remember: Cold Boot Attacks, USENIX Security 2008; ISO/IEC 19790 §7.9 (zeroisation) |
| A-P-11 | platform | RNG lemah saat pembangkitan kunci | n/a | 15/0/— | n/a | praktis | CVE-2008-0166 (Debian OpenSSL, ruang kunci 2^15); Heninger et al., USENIX Security 2012 |
| A-D-03 | platform | Bias nonce parsial → lattice (Hidden Number Problem) | KMA + side-channel | 30/10/— | n/a | praktis `PERLU_VERIFIKASI` | Howgrave-Graham & Smart, DCC 2001; Jancar et al. — Minerva, TCHES 2020; Moghimi et al. — TPM-FAIL, USENIX Security 2020 |
| A-D-07 | platform | Timing/cache pada perkalian skalar | side-channel | —/—/— | n/a | praktis | Brumley & Tuveri — Remote Timing Attacks are Still Practical, ESORICS 2011; Yarom & Benger — Recovering OpenSSL ECDSA Nonces Using the FLUSH+RELOAD Cache Side-channel Attack, 2014 |
| A-X-01 | platform | Transient execution (Spectre) | side-channel | —/—/— | n/a | praktis | Kocher et al. — Spectre Attacks, IEEE S&P 2019 |
| A-X-02 | platform | Frequency-scaling side-channel (Hertzbleed) | side-channel | —/—/— | n/a | praktis (remote timing dari variasi daya) | Wang et al. — Hertzbleed, USENIX Security 2022 |

## 3. Hasil Telaah Komponen (KUK 2.1)

| ID | Komponen | Lapis | Status | Tag kelemahan |
|---|---|---|---|---|
| C-CURVE | Parameter domain kurva P-256 | algoritma | OK | curve_params, key_size |
| C-PKV | Validasi kunci publik Q | algoritma | OK | pubkey_validation |
| C-NONCE | Nonce k | algoritma | OK | nonce_bias, rng |
| C-SMUL | Perkalian skalar | algoritma | PERHATIAN | scalar_mult_timing, constant_time |
| C-SIG | Encoding & verifikasi (r, s) | algoritma | PERHATIAN | sig_malleability |
| C-HASH | Fungsi hash pesan | algoritma | OK | hash_strength |
| C-API | Antarmuka API & validasi masukan | implementasi | PERHATIAN | memory_safety, pubkey_validation |
| C-MEM | Pengelolaan material kunci di memori | implementasi | PERHATIAN | key_zeroization |
| C-SELFTEST | Self-test & error state modul | implementasi | OK | self_test, conformance |
| C-RNG | Sumber acak (RBG) | implementasi | OK | rng |
| C-PLAT | Platform eksekusi (CPU x86-64 bercache, speculative execution) | implementasi | PERHATIAN | speculative, constant_time |
| C-CONF | Kesesuaian implementasi keseluruhan | implementasi | OK | conformance |

### C-CURVE — Parameter domain kurva P-256 [OK]

Validitas p, n, a, b, G; MOV/anomalous.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| p prima & n prima | True | True | OK | HASIL UJI LANGSUNG |  |
| Diskriminan 4a³+27b² ≠ 0 | True | True | OK | HASIL UJI LANGSUNG |  |
| G di kurva & n·G = O | True | True | OK | HASIL UJI LANGSUNG |  |
| Kofaktor h | 1 | 1 | OK | HASIL UJI LANGSUNG |  |
| Bukan kurva anomalous (n ≠ p) & MOV: p^k ≠ 1 mod n (k ≤ 20) | True | True | OK | HASIL UJI LANGSUNG |  |
| Biaya Pollard rho √(πn/4) | 2^127.8 | ≥ 2^127 | OK | HASIL UJI LANGSUNG |  |

### C-PKV — Validasi kunci publik Q [OK]

Titik di kurva, dalam rentang, orde n.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Kunci publik valid diterima | True | True | OK | HASIL UJI LANGSUNG |  |
| Kunci publik tidak valid ditolak (3 kasus) | 3/3 | 3/3 | OK | HASIL UJI LANGSUNG |  |

### C-NONCE — Nonce k [OK]

Keunikan & ketidakbiasan k (RFC 6979 / RBG).

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Keunikan nonce (r unik) | 512/512 | 512/512 | OK | HASIL UJI LANGSUNG |  |
| Bias 4 bit teratas k (χ², df=15) | p = 0.013 | p ≥ 0,01 | OK | HASIL UJI LANGSUNG |  |

### C-SMUL — Perkalian skalar [PERHATIAN]

Kebocoran timing/cache double-and-add.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Timing perkalian skalar referensi (HW rendah vs tinggi) | 354 | \|t\| < 4,5 | PERHATIAN | HASIL UJI LANGSUNG | Double-and-add referensi tidak constant-time; produk wajib diuji M-TIMING (A-D-07) |

### C-SIG — Encoding & verifikasi (r, s) [PERHATIAN]

Rentang r,s & malleability (r, n−s).

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| (r,s) di luar [1, n−1] ditolak (5 kasus) | 5/5 | 5/5 | OK | HASIL UJI LANGSUNG |  |
| Malleability (r, n−s) diterima | True | ditolak bila protokol butuh low-S | PERHATIAN | HASIL UJI LANGSUNG | A-D-05; klaim profil low_s_enforced=False |

### C-HASH — Fungsi hash pesan [OK]

Kekuatan hash vs tingkat keamanan kurva.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Kekuatan hash vs kurva (SP 800-57) | 128 bit | ≥ 128 bit | OK | HASIL UJI LANGSUNG |  |

### C-API — Antarmuka API & validasi masukan [PERHATIAN]

Penanganan masukan malformed / panjang ekstrem.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Bahasa implementasi tanpa memory safety | C | memory-safe atau fuzzing ekstensif | PERHATIAN | KLAIM PROFIL | A-L-02 / A-H-07 |

### C-MEM — Pengelolaan material kunci di memori [PERHATIAN]

Zeroization CSP setelah dipakai.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Zeroization material kunci | tidak dapat diverifikasi (grey box) | CSP dihapus pasca-pakai (ISO/IEC 19790) | PERHATIAN | KLAIM PROFIL | A-L-03 |

### C-SELFTEST — Self-test & error state modul [OK]

Power-on KAT, conditional test.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Self-test tersedia | True | True (POST KAT + conditional) | OK | KLAIM PROFIL | Diverifikasi di M-SELFTEST |

### C-RNG — Sumber acak (RBG) [OK]

RBG untuk kunci/nonce/seed.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| RBG yang dipakai | getrandom(2) → HMAC_DRBG (SP 800-90A) | DRBG SP 800-90A + sumber entropi SP 800-90B | OK | KLAIM PROFIL | Diverifikasi di M-RNG |

### C-PLAT — Platform eksekusi (CPU x86-64 bercache, speculative execution) [PERHATIAN]

Side-channel mikroarsitektur.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Platform ber-cache bersama & speculative execution | Shared library (.so) di Linux x86-64; CPU multi-core dengan cache L3 bersama | operasi rahasia constant-time | PERHATIAN | HASIL LITERATUR | A-X-01 / A-X-02 |

### C-CONF — Kesesuaian implementasi keseluruhan [OK]

Keluaran identik dengan standar.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| KAT implementasi referensi (core/) | 4/4 LULUS | 100% cocok | OK | HASIL UJI LANGSUNG | Vektor: RFC 6979 Appendix A.2.5 |

## 4. Matriks Komponen–Kelemahan–Metode (KUK 2.2)

Tiga lapis pengujian × level uji (metode yang dipetakan):

| Lapis \ Level | Unit | Integrasi | Sistem |
|---|---|---|---|
| Kesesuaian | M-CURVE, M-KAT, M-PKV, M-SIGMAL | — | — |
| Kekuatan algoritma | — | — | M-ECDLP, M-KEYSIZE |
| Implementasi & sistem | M-CODEREVIEW | M-FUZZ, M-NONCE, M-RNG, M-TIMING | M-CACHE, M-SELFTEST, M-ZEROIZE |

| Komponen | Status | Kelemahan | Serangan | Metode | Lapis | Level | Standar | Akses |
|---|---|---|---|---|---|---|---|---|
| C-API Antarmuka API & validasi masukan | PERHATIAN | Kunci publik/titik tidak divalidasi | A-D-04 | M-PKV Validasi kunci publik (positif & negatif) | Kesesuaian | Unit | SP-800-56B, SP-800-186, ISO-18033-2 | ✔ black |
| C-CONF Kesesuaian implementasi keseluruhan | OK | Keluaran implementasi tidak sesuai standar | — | M-KAT Known Answer Test (KAT) terhadap vektor resmi | Kesesuaian | Unit | ISO-18367, ISO-24759 | ✔ black |
| C-CURVE Parameter domain kurva P-256 | OK | Parameter domain kurva tidak valid | A-D-01, A-D-04 | M-CURVE Validasi parameter domain kurva (prima, orde, diskriminan, MOV/anomalous) | Kesesuaian | Unit | SP-800-186, FIPS-186-5 | ✔ black |
| C-CURVE Parameter domain kurva P-256 | OK | Parameter domain kurva tidak valid | A-D-01, A-D-04 | M-PKV Validasi kunci publik (positif & negatif) | Kesesuaian | Unit | SP-800-56B, SP-800-186, ISO-18033-2 | ✔ black |
| C-PKV Validasi kunci publik Q | OK | Kunci publik/titik tidak divalidasi | A-D-04 | M-PKV Validasi kunci publik (positif & negatif) | Kesesuaian | Unit | SP-800-56B, SP-800-186, ISO-18033-2 | ✔ black |
| C-SELFTEST Self-test & error state modul | OK | Keluaran implementasi tidak sesuai standar | — | M-KAT Known Answer Test (KAT) terhadap vektor resmi | Kesesuaian | Unit | ISO-18367, ISO-24759 | ✔ black |
| C-SIG Encoding & verifikasi (r, s) | PERHATIAN | Tanda tangan non-kanonik/malleable diterima | A-D-05 | M-SIGMAL Uji penolakan (r,s) non-kanonik & malleability | Kesesuaian | Unit | FIPS-186-5, ISO-14888-3 | ✔ black |
| C-CURVE Parameter domain kurva P-256 | OK | Parameter domain kurva tidak valid | A-D-01, A-D-04 | M-ECDLP Estimasi & uji Pollard rho ECDLP | Kekuatan algoritma | Sistem | SP-800-186, SP-800-57 | ✔ black |
| C-CURVE Parameter domain kurva P-256 | OK | Ruang kunci / tingkat keamanan tidak memadai | A-P-02, A-D-01 | M-ECDLP Estimasi & uji Pollard rho ECDLP | Kekuatan algoritma | Sistem | SP-800-186, SP-800-57 | ✔ black |
| C-CURVE Parameter domain kurva P-256 | OK | Ruang kunci / tingkat keamanan tidak memadai | A-P-02, A-D-01 | M-KEYSIZE Evaluasi ukuran kunci & tingkat keamanan (SP 800-57 / 131A) | Kekuatan algoritma | Sistem | SP-800-57, SP-800-131A | ✔ black |
| C-HASH Fungsi hash pesan | OK | Kekuatan hash di bawah tingkat keamanan skema | — | M-KEYSIZE Evaluasi ukuran kunci & tingkat keamanan (SP 800-57 / 131A) | Kekuatan algoritma | Sistem | SP-800-57, SP-800-131A | ✔ black |
| C-API Antarmuka API & validasi masukan | PERHATIAN | Buffer overflow / masukan malformed | A-L-02 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-MEM Pengelolaan material kunci di memori | PERHATIAN | Material kunci tidak dihapus dari memori | A-L-03 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | PERHATIAN | Eksekusi tidak constant-time | A-L-01, A-D-07, A-X-01, A-X-02 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-SMUL Perkalian skalar | PERHATIAN | Timing/cache pada perkalian skalar | A-D-03, A-D-07 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-SMUL Perkalian skalar | PERHATIAN | Eksekusi tidak constant-time | A-L-01, A-D-07, A-X-01, A-X-02 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-API Antarmuka API & validasi masukan | PERHATIAN | Buffer overflow / masukan malformed | A-L-02 | M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | ISO-29119, ISO-18045 | ✔ black |
| C-API Antarmuka API & validasi masukan | PERHATIAN | Kunci publik/titik tidak divalidasi | A-D-04 | M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | ISO-29119, ISO-18045 | ✔ black |
| C-NONCE Nonce k | OK | Nonce tanda tangan berulang/bias | A-D-02, A-D-03 | M-NONCE Uji keunikan & bias nonce (statistik + kelayakan lattice HNP) | Implementasi & sistem | Integrasi | FIPS-186-5, RFC-6979, SP-800-90A, SP-800-38A, RFC-8439 | ✔ grey |
| C-NONCE Nonce k | OK | RBG lemah / entropi rendah | A-D-02, A-P-11 | M-NONCE Uji keunikan & bias nonce (statistik + kelayakan lattice HNP) | Implementasi & sistem | Integrasi | FIPS-186-5, RFC-6979, SP-800-90A, SP-800-38A, RFC-8439 | ✔ grey |
| C-NONCE Nonce k | OK | RBG lemah / entropi rendah | A-D-02, A-P-11 | M-RNG Asesmen RBG / sumber entropi (SP 800-90A/B, ISO/IEC 18031) | Implementasi & sistem | Integrasi | SP-800-90A, SP-800-90B, ISO-18031, SP-800-22 | ✔ grey |
| C-PKV Validasi kunci publik Q | OK | Kunci publik/titik tidak divalidasi | A-D-04 | M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | ISO-29119, ISO-18045 | ✔ black |
| C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | PERHATIAN | Eksekusi tidak constant-time | A-L-01, A-D-07, A-X-01, A-X-02 | M-TIMING Analisis timing leakage (dudect / Welch t-test, fixed-vs-random) | Implementasi & sistem | Integrasi | ISO-17825, ISO-20085 | ✔ grey |
| C-RNG Sumber acak (RBG) | OK | RBG lemah / entropi rendah | A-D-02, A-P-11 | M-NONCE Uji keunikan & bias nonce (statistik + kelayakan lattice HNP) | Implementasi & sistem | Integrasi | FIPS-186-5, RFC-6979, SP-800-90A, SP-800-38A, RFC-8439 | ✔ grey |
| C-RNG Sumber acak (RBG) | OK | RBG lemah / entropi rendah | A-D-02, A-P-11 | M-RNG Asesmen RBG / sumber entropi (SP 800-90A/B, ISO/IEC 18031) | Implementasi & sistem | Integrasi | SP-800-90A, SP-800-90B, ISO-18031, SP-800-22 | ✔ grey |
| C-SMUL Perkalian skalar | PERHATIAN | Timing/cache pada perkalian skalar | A-D-03, A-D-07 | M-TIMING Analisis timing leakage (dudect / Welch t-test, fixed-vs-random) | Implementasi & sistem | Integrasi | ISO-17825, ISO-20085 | ✔ grey |
| C-SMUL Perkalian skalar | PERHATIAN | Eksekusi tidak constant-time | A-L-01, A-D-07, A-X-01, A-X-02 | M-TIMING Analisis timing leakage (dudect / Welch t-test, fixed-vs-random) | Implementasi & sistem | Integrasi | ISO-17825, ISO-20085 | ✔ grey |
| C-CONF Kesesuaian implementasi keseluruhan | OK | Keluaran implementasi tidak sesuai standar | — | M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ black |
| C-MEM Pengelolaan material kunci di memori | PERHATIAN | Material kunci tidak dihapus dari memori | A-L-03 | M-ZEROIZE Uji zeroization material kunci (memory dump pasca-operasi) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ grey |
| C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | PERHATIAN | Kebocoran eksekusi spekulatif | A-X-01 | M-CACHE Analisis cache side-channel (Flush+Reload / Prime+Probe) | Implementasi & sistem | Sistem | ISO-17825 | ✔ grey |
| C-SELFTEST Self-test & error state modul | OK | Self-test / error state tidak berfungsi | — | M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ black |
| C-SELFTEST Self-test & error state modul | OK | Keluaran implementasi tidak sesuai standar | — | M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ black |
| C-SMUL Perkalian skalar | PERHATIAN | Timing/cache pada perkalian skalar | A-D-03, A-D-07 | M-CACHE Analisis cache side-channel (Flush+Reload / Prime+Probe) | Implementasi & sistem | Sistem | ISO-17825 | ✔ grey |

## 5. Estimasi Sumber Daya & Kelayakan (KUK 2.3)

### 5.1 Benchmark mesin lab — HASIL UJI LANGSUNG

| Operasi | ops/detik |
|---|---|
| sign | 581.3 |
| verify | 292.8 |
| point_add | 59,833.9 |
| primary | 581.3 |

Mesin: Darwin arm64, arm, 8 CPU logis, Python 3.11.1. Implementasi: referensi pure Python (core/) — batas bawah konservatif.

### 5.2 Sumber daya internal

| Sumber daya | Nilai |
|---|---|
| SDM | 2× Cryptographic Analyst (kriptanalisis, statistik, Python); 1× Test engineer (otomasi uji, fuzzing, Linux) |
| Jadwal | 10 hari × 8 jam = 240 jam-orang |
| Komputasi | 1 mesin × 8 core, 16 GB RAM |
| Anggaran komputasi per metode | 24 jam |
| Faktor speedup | 1 |
| Tools tersedia | python, pytest, gdb |

### 5.3 Estimasi waktu per metode

Waktu = 2^k ÷ (ops/detik × core × speedup).

| Metode | Operasi | k (log2) | Estimasi penuh | Data | Memori | Varian tereduksi | Status | Alasan |
|---|---|---|---|---|---|---|---|---|
| M-KAT | primary | 7 | 0.03 detik | 2^7.0 operasi/sampel | ≤ 2^10 B | — | LAYAK | Estimasi 0.03 detik ≤ anggaran 24 jam |
| M-KEYSIZE | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-PKV | verify | 8 | 0.11 detik | 2^8.0 operasi/sampel | ≤ 2^10 B | — | LAYAK | Estimasi 0.11 detik ≤ anggaran 24 jam |
| M-ECDLP | point_add | 128 | 2^84.2 tahun | 2^128.0 operasi/sampel | ≤ 2^40 B | Pollard rho pada subgrup/kurva mainan 32–40 bit — validasi √(πn/4) — 4.38 detik | LAYAK VERSI TEREDUKSI | Versi penuh 2^84.2 tahun > anggaran; versi tereduksi 4.38 detik |
| M-CURVE | point_add | 10 | 0.00 detik | 2^10.0 operasi/sampel | ≤ 2^11 B | — | LAYAK | Estimasi 0.00 detik ≤ anggaran 24 jam |
| M-NONCE | sign | 12 | 0.88 detik | 2^12.0 operasi/sampel | ≤ 2^12 B | — | LAYAK | Estimasi 0.88 detik ≤ anggaran 24 jam |
| M-SIGMAL | verify | 6 | 0.03 detik | 2^6.0 operasi/sampel | ≤ 2^10 B | — | LAYAK | Estimasi 0.03 detik ≤ anggaran 24 jam |
| M-TIMING | primary | 20 | 3.8 menit | 2^20.0 operasi/sampel | ≤ 2^16 B | — | LAYAK | Estimasi 3.8 menit ≤ anggaran 24 jam |
| M-CACHE | primary | 22 | 15.0 menit | 2^22.0 operasi/sampel | ≤ 2^17 B | — | TIDAK LAYAK | Alat tidak tersedia: mastik |
| M-TVLA | primary | 17 | 28.19 detik | 2^17.0 operasi/sampel | ≤ 2^14 B | — | TIDAK LAYAK | Alat tidak tersedia: oscilloscope, chipwhisperer |
| M-FAULT | primary | 16 | 14.09 detik | 2^16.0 operasi/sampel | ≤ 2^14 B | — | TIDAK LAYAK | Alat tidak tersedia: glitcher |
| M-CODEREVIEW | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-FUZZ | primary | 20 | 3.8 menit | 2^20.0 operasi/sampel | ≤ 2^16 B | — | LAYAK | Estimasi 3.8 menit ≤ anggaran 24 jam |
| M-ZEROIZE | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-SELFTEST | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-RNG | primary | 11.93 | 0.84 detik | 2^11.9 operasi/sampel | ≈ 0.1 MB | — | LAYAK | Estimasi 0.84 detik ≤ anggaran 24 jam |

## 6. Metode Terpilih & Parameter Pengujian (KUK 3.1, 3.2)

### 6.1 Penetapan metode

Rumus: skor = relevansi[keparahan 1–3 + tren serangan (+1 praktis | +0,5 teoretis), maks 3] × kelayakan(1 | 0,6 | 0) × akses(1 | 0); ambang ≥ 1.0.

| Metode | Lapis | Level | Varian | Skor | Target | Alasan |
|---|---|---|---|---|---|---|
| M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | penuh | 3 | C-API | Skor 3.0 ≥ 1.0: relevan terhadap C-API. Estimasi 3.8 menit ≤ anggaran 24 jam |
| M-PKV Validasi kunci publik (positif & negatif) | Kesesuaian | Unit | penuh | 3 | C-API | Skor 3.0 ≥ 1.0: relevan terhadap C-API. Estimasi 0.11 detik ≤ anggaran 24 jam |
| M-SIGMAL Uji penolakan (r,s) non-kanonik & malleability | Kesesuaian | Unit | penuh | 3 | C-SIG | Skor 3.0 ≥ 1.0: relevan terhadap C-SIG. Estimasi 0.03 detik ≤ anggaran 24 jam |
| M-TIMING Analisis timing leakage (dudect / Welch t-test, fixed-vs-random) | Implementasi & sistem | Integrasi | penuh | 3 | C-PLAT, C-SMUL | Skor 3.0 ≥ 1.0: relevan terhadap C-PLAT, C-SMUL. Estimasi 3.8 menit ≤ anggaran 24 jam |
| M-ZEROIZE Uji zeroization material kunci (memory dump pasca-operasi) | Implementasi & sistem | Sistem | penuh | 3 | C-MEM | Skor 3.0 ≥ 1.0: relevan terhadap C-MEM. Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-CURVE Validasi parameter domain kurva (prima, orde, diskriminan, MOV/anomalous) | Kesesuaian | Unit | penuh | 2 | C-CURVE | Skor 2.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 0.00 detik ≤ anggaran 24 jam |
| M-NONCE Uji keunikan & bias nonce (statistik + kelayakan lattice HNP) | Implementasi & sistem | Integrasi | penuh | 2 | C-NONCE, C-RNG | Skor 2.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 0.88 detik ≤ anggaran 24 jam |
| M-RNG Asesmen RBG / sumber entropi (SP 800-90A/B, ISO/IEC 18031) | Implementasi & sistem | Integrasi | penuh | 2 | C-NONCE, C-RNG | Skor 2.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 0.84 detik ≤ anggaran 24 jam |
| M-KEYSIZE Evaluasi ukuran kunci & tingkat keamanan (SP 800-57 / 131A) | Kekuatan algoritma | Sistem | penuh | 1.5 | C-CURVE, C-HASH | Wajib (kesesuaian standar / baseline keamanan). Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-ECDLP Estimasi & uji Pollard rho ECDLP | Kekuatan algoritma | Sistem | tereduksi | 1.2 | C-CURVE | Skor 1.2 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Versi penuh 2^84.2 tahun > anggaran; versi tereduksi 4.38 detik |
| M-KAT Known Answer Test (KAT) terhadap vektor resmi | Kesesuaian | Unit | penuh | 1 | C-CONF, C-SELFTEST | Wajib (kesesuaian standar / baseline keamanan). Estimasi 0.03 detik ≤ anggaran 24 jam |
| M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | penuh | 1 | C-CONF, C-SELFTEST | Skor 1.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 0 detik (analitis) ≤ anggaran 24 jam |

**Metode yang ditolak:**

| Metode | Kelayakan | Skor | Alasan |
|---|---|---|---|
| M-CACHE Analisis cache side-channel (Flush+Reload / Prime+Probe) | 0 | 0 | Ditolak: Alat tidak tersedia: mastik |
| M-TVLA Uji kebocoran daya/EM (TVLA, ISO/IEC 17825) | 0 | 0 | Ditolak: Alat tidak tersedia: oscilloscope, chipwhisperer |
| M-FAULT Uji injeksi kesalahan (clock/voltage glitch, laser) | 0 | 0 | Ditolak: memerlukan akses white-box (di luar akses penguji) |
| M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | 1 | 0 | Ditolak: memerlukan akses white-box (di luar akses penguji) |

### 6.2 Parameter pengujian

**M-FUZZ**

| Parameter | Nilai |
|---|---|
| engine | fuzzing berbasis properti (Hypothesis/AFL++ via harness C) |
| executions | 1000000 |
| inputs | panjang 0, panjang maks+1, buffer tidak selaras, NULL pointer, kunci/nonce panjang salah |
| pass_criterion | 0 crash, 0 sanitizer error, galat terdefinisi |
| variant | penuh |
| estimated_time | 3.8 menit |

**M-PKV**

| Parameter | Nilai |
|---|---|
| positive_cases | 10 |
| negative_cases | titik di luar kurva, koordinat ≥ p, titik tak hingga, orde ≠ n |
| pass_criterion | 100% negatif ditolak, 100% positif diterima |
| variant | penuh |
| estimated_time | 0.11 detik |

**M-SIGMAL**

| Parameter | Nilai |
|---|---|
| cases | r = 0, s = 0, r = n, s = n, (0,0), (r, n−s), encoding DER non-minimal |
| pass_criterion | semua kasus di luar rentang ditolak; kebijakan low-S terdokumentasi |
| variant | penuh |
| estimated_time | 0.03 detik |

**M-TIMING**

| Parameter | Nilai |
|---|---|
| method | dudect fixed-vs-random (Welch t) |
| measurements | 1000000 |
| threshold_abs_t | 4.5 |
| classes | nonce/kunci HW rendah vs acak |
| timer | rdtsc / perf_counter_ns, core diisolasi (taskset), turbo dimatikan |
| variant | penuh |
| estimated_time | 3.8 menit |

**M-ZEROIZE**

| Parameter | Nilai |
|---|---|
| procedure | core dump / gdb setelah free & pemanggilan API destroy |
| search | pola kunci uji (known key) |
| pass_criterion | 0 kemunculan |
| variant | penuh |
| estimated_time | 0 detik (analitis) |

**M-CURVE**

| Parameter | Nilai |
|---|---|
| checks | p, n prima, 4a³+27b² ≠ 0, G ∈ E, n·G = O, h = 1, n ≠ p, MOV k ≤ 20 |
| reference | SP 800-186 §3.2.1 (P-256) |
| variant | penuh |
| estimated_time | 0.00 detik |

**M-NONCE**

| Parameter | Nilai |
|---|---|
| signatures | 4096 |
| messages |  |
| checks | duplikasi nonce/r = 0, χ² 8 bit teratas k (df = 255), HNP lattice: bias ≥ 2 bit → 100 sampel |
| alpha | 0.01 |
| variant | penuh |
| estimated_time | 0.88 detik |

**M-RNG**

| Parameter | Nilai |
|---|---|
| entropy_samples_bits | 1000000 |
| sp800_90b | IID & non-IID track, restart test 1000×1000 |
| sp800_22 | subset sesuai M-SP80022 |
| drbg | CAVP DRBG KAT (HMAC_DRBG) |
| variant | penuh |
| estimated_time | 0.84 detik |

**M-KEYSIZE**

| Parameter | Nilai |
|---|---|
| key_parameters | curve=P-256; field_bits=256; order_bits=256 |
| security_bits | 128 |
| min_security_bits | 112 |
| horizon | 2030 (≥128 bit untuk perlindungan setelah 2030) |
| reference | SP 800-57 Part 1 Rev.5 Tabel 2 & 4; SP 800-131A Rev.2 |
| variant | penuh |
| estimated_time | 0 detik (analitis) |

**M-ECDLP**

| Parameter | Nilai |
|---|---|
| full_log2 | 127.8 |
| reduced_curve_bits | 32, 36, 40 |
| reduced_ops_log2 | 21 |
| pass_criterion | iterasi empiris ≈ √(πn/4) ± 25% |
| variant | tereduksi |
| estimated_time | 4.38 detik |

**M-KAT**

| Parameter | Nilai |
|---|---|
| vector_sources | RFC 6979 Appendix A.2.5 (ECDSA, 256 bits, prime field) |
| vector_count | 4 |
| additional_sources | NIST CAVP/ACVP response files untuk implementasi produk |
| pass_criterion | 100% vektor cocok (0 selisih bit) |
| reference_result | 4/4 (LULUS) pada core/ |
| variant | penuh |
| estimated_time | 0.03 detik |

**M-SELFTEST**

| Parameter | Nilai |
|---|---|
| tests | POST KAT tiap algoritma, pairwise consistency (pkc/dss), continuous RNG test, error state injection |
| variant | penuh |
| estimated_time | 0 detik (analitis) |

## 7. Matriks Keterlacakan

| ID | Persyaratan | Objek | Metode uji | Rujukan | Kriteria lulus |
|---|---|---|---|---|---|
| K-01 | ECDLP tidak terpecahkan (≥ 2^128 operasi) | C-CURVE Parameter domain kurva P-256 | M-ECDLP (tereduksi) | SP 800-186, SP 800-57 | √(πn/4) ≥ 2^127 |
| K-02 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | C-CURVE Parameter domain kurva P-256; C-HASH Fungsi hash pesan | M-KEYSIZE (penuh) | SP 800-57, SP 800-131A | security_bits ≥ 112 |
| K-03 | Nonce tidak pernah berulang dan tidak bias | C-NONCE Nonce k; C-RNG Sumber acak (RBG) | M-NONCE (penuh) | FIPS 186-5, RFC 6979, SP 800-90A, SP 800-38A, RFC 8439 | 0 duplikasi; χ² MSB p-value ≥ 0,01 (≥ 4096 sampel) |
| K-04 | RBG yang dipakai disetujui (SP 800-90A) dengan entropi memadai | C-NONCE Nonce k; C-RNG Sumber acak (RBG) | M-RNG (penuh) | SP 800-90A, SP 800-90B, ISO 18031, SP 800-22 | min-entropy ≥ nilai klaim (SP 800-90B); SP 800-22 lulus |
| I-01 | Parameter domain identik dengan SP 800-186 & lolos uji validitas | C-CURVE Parameter domain kurva P-256 | M-CURVE (penuh) | SP 800-186, FIPS 186-5 | semua pemeriksaan LULUS |
| I-02 | API menolak masukan tidak valid tanpa crash/kebocoran | C-API Antarmuka API & validasi masukan | M-FUZZ (penuh) | ISO 29119, ISO 18045 | 0 crash; 100% masukan invalid ditolak dengan galat terdefinisi |
| I-03 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | C-CONF Kesesuaian implementasi keseluruhan; C-SELFTEST Self-test & error state modul | M-KAT (penuh) | ISO 18367, ISO 24759 | 100% vektor cocok |
| I-04 | Produk menolak kunci publik/titik tidak valid | C-API Antarmuka API & validasi masukan | M-PKV (penuh) | SP 800-56B, SP 800-186, ISO 18033-2 | 100% kasus negatif ditolak, 100% kasus positif diterima |
| I-05 | Power-on self-test (KAT) & conditional test (pairwise) berjalan; error state memblokir layanan | C-CONF Kesesuaian implementasi keseluruhan; C-SELFTEST Self-test & error state modul | M-SELFTEST (penuh) | ISO 19790, ISO 24759 | semua self-test terpicu & error state tervalidasi |
| I-06 | Verifikasi menolak r,s ∉ [1, n−1]; kebijakan low-S terdokumentasi | C-SIG Encoding & verifikasi (r, s) | M-SIGMAL (penuh) | FIPS 186-5, ISO 14888-3 | 100% kasus di luar rentang ditolak |
| I-07 | Waktu eksekusi tidak bergantung pada data rahasia | C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution); C-SMUL Perkalian skalar | M-TIMING (penuh) | ISO 17825, ISO 20085 | \|t\| < 4,5 pada ≥ 10^6 pengukuran |
| I-08 | Kunci/CSP dihapus dari memori setelah dipakai | C-MEM Pengelolaan material kunci di memori | M-ZEROIZE (penuh) | ISO 19790, ISO 24759 | 0 salinan kunci pada dump memori |

## 8. Lampiran: Peta KUK → Bagian Dokumen → File Kode

| KUK | Deskripsi | Bagian | File kode | Unit test |
|---|---|---|---|---|
| 1.1 | Informasi desain & teknik implementasi | Bab 1 | uk1_metode/profile.py, config/product_profile.yaml | tests/test_uk1_ek1.py::test_kuk_1_1_* |
| 1.2 | Tren serangan terhadap platform | Bab 2.2 | uk1_metode/attack_kb.py, uk1_metode/data/attacks.yaml | tests/test_uk1_ek1.py::test_kuk_1_2_* |
| 1.3 | Best practice metode pengujian | Bab 2.1 | uk1_metode/standards_kb.py, uk1_metode/data/standards.yaml | tests/test_uk1_ek1.py::test_kuk_1_3_* |
| 2.1 | Komponen berpotensi lemah | Bab 3 | uk1_metode/decompose.py, uk1_metode/component_analysis.py, core/boolean.py | tests/test_core_components.py, tests/test_uk1_ek2.py::test_kuk_2_1_* |
| 2.2 | Analisis best practice vs potensi kelemahan | Bab 4 | uk1_metode/mapping.py, uk1_metode/data/methods.yaml | tests/test_uk1_ek2.py::test_kuk_2_2_* |
| 2.3 | Kesesuaian sumber daya internal | Bab 5 | uk1_metode/resources.py | tests/test_uk1_ek2.py::test_kuk_2_3_* |
| 3.1 | Penetapan metode | Bab 6.1 | uk1_metode/selector.py | tests/test_uk1_ek3.py::test_kuk_3_1_* |
| 3.2 | Penetapan parameter | Bab 6.2 | uk1_metode/parameters.py | tests/test_uk1_ek3.py::test_kuk_3_2_* |
| — | Matriks keterlacakan | Bab 7 | uk1_metode/traceability.py | tests/test_uk1_ek3.py::test_traceability_* |

KAT rinci (ECDSA-P256):

| Vektor | Sumber | Hasil |
|---|---|---|
| RFC6979-A.2.5-pubkey | RFC 6979 Appendix A.2.5 (ECDSA, 256 bits, prime field) | LULUS |
| RFC6979-A.2.5-sample-SHA256 | RFC 6979 Appendix A.2.5 (ECDSA, 256 bits, prime field) | LULUS |
| RFC6979-A.2.5-test-SHA256 | RFC 6979 Appendix A.2.5 (ECDSA, 256 bits, prime field) | LULUS |
| RFC6979-A.2.5-sample-SHA1 | RFC 6979 Appendix A.2.5 (ECDSA, 256 bits, prime field) | LULUS |
