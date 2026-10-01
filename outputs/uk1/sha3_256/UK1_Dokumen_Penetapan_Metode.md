# Dokumen Penetapan Metode & Parameter Pengujian — SHA3-256

**Cryptan.ID Test Suite** v1.0.0 · Modul **UK-1** · Unit J.61KRP00.012.1 — *Menentukan Metode Pengujian yang akan Dilakukan* · SKKNI 2023-004 (Cryptographic Analyst)

Dibangkitkan: 2026-10-01T09:16:57+07:00 · mode: full · objek: **Cryptan.ID SecureLib** (1.0.0 (hipotetis))

> Seluruh data produk bersifat ILUSTRATIF. Nilai bertanda HASIL UJI LANGSUNG dihitung oleh kode; HASIL LITERATUR dikutip dari rujukan; PERLU_VERIFIKASI wajib dicek ke sumber primer.

## Ringkasan

- Kelas primitif: **Fungsi hash**, struktur Sponge
- Tingkat akses penguji: **grey_box**
- KAT implementasi referensi: **3/3 LULUS**
- Komponen berpotensi lemah: **—**; perlu perhatian: C-CHI, C-API, C-MEM, C-PLAT
- Metode terpilih: **13** · ditolak: 3 · upaya 64 / 240 jam-orang (SESUAI)

## 1. Profil Produk & Ruang Lingkup (KUK 1.1)

| Atribut | Nilai |
|---|---|
| Produk | Cryptan.ID SecureLib 1.0.0 (hipotetis) |
| Deskripsi | Library kriptografi perangkat lunak (shared object) untuk Linux x86-64 |
| Algoritma | SHA3-256 (FIPS 202) |
| Kelas primitif | Fungsi hash |
| Struktur | Sponge |
| Mode | — |
| Parameter | state_bits=1600; rate_bits=1088; capacity_bits=512; output_bits=256; rounds=24; output_bits_per_op=256 |
| Platform | Shared library (.so) di Linux x86-64; CPU multi-core dengan cache L3 bersama |
| Bahasa / binding | C / Python |
| Antarmuka | C API (libsecure.so), Python binding (ctypes) |
| RBG | getrandom(2) → HMAC_DRBG (SP 800-90A) |
| Catatan implementasi | streaming_api=True |
| Tingkat akses | grey_box — Penguji memperoleh spesifikasi algoritma & dokumen desain tingkat tinggi, biner library + header API, dan lingkungan uji dengan kunci uji. Kode sumber TIDAK tersedia. |
| Kelengkapan profil | LENGKAP |
| Daftar algoritma diuji (algo_catalog) | 33 kombinasi (block_cipher=6; stream_cipher=2; hash=7; mac=4; pkc_kem=7; signature=6; drbg=1); 6 peringatan tinggi; SHA3-256 termasuk daftar (strength 128, status acceptable) — `algorithms_under_test.yaml` |

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
| FIPS-202 | NIST | SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions | 2015 | Spesifikasi algoritma/skema |
| ISO-10118-3 | ISO/IEC | Hash-functions — Part 3: Dedicated hash-functions (termasuk SHA-3) | 2018 | Spesifikasi algoritma/skema |
| ISO-18367 | ISO/IEC | Cryptographic algorithms and security mechanisms conformance testing | 2016 | Pengujian kesesuaian |
| SP-800-107 | NIST | Recommendation for Applications Using Approved Hash Algorithms (Rev. 1) | 2012 | Pengujian kekuatan / kriteria keamanan |
| SP-800-22 | NIST | A Statistical Test Suite for Random and Pseudorandom Number Generators (Rev. 1a) | 2010 | Pengujian kekuatan / kriteria keamanan |
| ISO-17825 | ISO/IEC | Testing methods for the mitigation of non-invasive attack classes against cryptographic modules `PERLU_VERIFIKASI` | 2024 | Pengujian implementasi & modul |
| ISO-19790 | ISO/IEC | Security requirements for cryptographic modules | 2012 | Pengujian implementasi & modul |
| ISO-20085 | ISO/IEC | Test tool requirements and test tool calibration methods for use in testing non-invasive attack mitigation techniques | 2019 | Pengujian implementasi & modul |
| ISO-24759 | ISO/IEC | Test requirements for cryptographic modules | 2017 | Pengujian implementasi & modul |
| SP-800-131A | NIST | Transitioning the Use of Cryptographic Algorithms and Key Lengths (Rev. 2) | 2019 | Ukuran kunci & manajemen kunci |
| SP-800-57 | NIST | Recommendation for Key Management, Part 1: General (Rev. 5) | 2020 | Ukuran kunci & manajemen kunci |
| ISO-15408 | ISO/IEC | Evaluation criteria for IT security (Common Criteria) | 2022 | Evaluasi keamanan / migrasi |
| ISO-18045 | ISO/IEC | Methodology for IT security evaluation (CEM) | 2022 | Evaluasi keamanan / migrasi |
| ISO-29119 | ISO/IEC/IEEE | Software and systems engineering — Software testing | 2022 | Proses & dokumentasi pengujian |

### 2.2 Tren Serangan Relevan (KUK 1.2) — HASIL LITERATUR

12 serangan relevan setelah filter profil; praktis: 7; perlu verifikasi: 3.

| ID | Kategori | Serangan | Model | Kompleksitas (log2 T/D/M) | Ronde | Status | Rujukan |
|---|---|---|---|---|---|---|---|
| A-H-03 | desain | Practical collision — Keccak/SHA3 ronde tereduksi | n/a | —/—/— | 5/24 (tabrakan aktual) | praktis (ronde tereduksi) | Guo, Liao, Liu, Liu, Qiao, Song — Practical Collision Attacks against Round-Reduced SHA-3, J. Cryptology 2020 |
| A-BC-03 | desain | Differential cryptanalysis (batas wide-trail) | CPA | —/—/— | karakteristik 4 ronde ≥ 25 S-box aktif ⇒ p ≤ 2^-150 | teoretis | Biham & Shamir, CRYPTO 1990 / J. Cryptology 1991; Daemen & Rijmen — The Design of Rijndael, Springer 2002 (wide trail strategy) |
| A-H-01 | desain | Generic collision (birthday) | n/a | 128/—/128 | full | teoretis | FIPS 202 Tabel 4; SP 800-107 Rev.1 §4 (kekuatan collision = n/2) |
| A-H-02 | desain | Generic (second-)preimage | n/a | 256/—/0 | full | teoretis | FIPS 202 Tabel 4 (min(n, c/2)) |
| A-H-04 | desain | Preimage dengan linear structures (Keccak ronde tereduksi) | n/a | —/—/— | ≤ 4/24 | teoretis `PERLU_VERIFIKASI` | Guo, Liu, Song — Linear Structures: Applications to Cryptanalysis of Round-Reduced Keccak, ASIACRYPT 2016 |
| A-H-05 | desain | Zero-sum distinguisher Keccak-f[1600] (24 ronde) | n/a | 1575/—/— | 24/24 (permutasi, bukan serangan hash) | teoretis `PERLU_VERIFIKASI` | Boura, Canteaut, De Cannière — Higher-order differential properties of Keccak and Luffa, FSE 2011 |
| A-H-07 | bahasa | Buffer overflow pada implementasi Keccak (CVE-2022-37454, XKCP) | n/a | 0/32/32 | n/a | praktis | NVD CVE-2022-37454 (integer overflow & buffer overflow di XKCP sponge; ditemukan N. Mouha) |
| A-L-01 | bahasa | Perbandingan tidak constant-time (memcmp pada tag/MAC/padding) | side-channel | —/—/— | n/a | praktis `PERLU_VERIFIKASI` | Lawson — Timing attack in Google Keyczar, 2009; ISO/IEC 17825 |
| A-L-02 | bahasa | Buffer over-read/overflow (memory safety) | n/a | 0/0/0 | n/a | praktis | NVD CVE-2014-0160 (Heartbleed, OpenSSL) |
| A-L-03 | bahasa | Material kunci tidak di-zeroize (sisa di memori / cold boot) | n/a | —/—/— | n/a | praktis | Halderman et al. — Lest We Remember: Cold Boot Attacks, USENIX Security 2008; ISO/IEC 19790 §7.9 (zeroisation) |
| A-X-01 | platform | Transient execution (Spectre) | side-channel | —/—/— | n/a | praktis | Kocher et al. — Spectre Attacks, IEEE S&P 2019 |
| A-X-02 | platform | Frequency-scaling side-channel (Hertzbleed) | side-channel | —/—/— | n/a | praktis (remote timing dari variasi daya) | Wang et al. — Hertzbleed, USENIX Security 2022 |

## 3. Hasil Telaah Komponen (KUK 2.1)

| ID | Komponen | Lapis | Status | Tag kelemahan |
|---|---|---|---|---|
| C-CHI | Pemetaan χ (S-box 5-bit) | algoritma | PERHATIAN | chi, sbox |
| C-DIFF | Lapisan linear θ, ρ, π | algoritma | OK | diffusion |
| C-ROUND | ι & jumlah ronde (24) | algoritma | OK | round_count |
| C-PAD | Padding pad10*1 + domain separation | algoritma | OK | padding |
| C-SPONGE | Konstruksi sponge (rate/capacity) | algoritma | OK | sponge_capacity, generic_bound |
| C-API | Antarmuka API & validasi masukan | implementasi | PERHATIAN | memory_safety, pubkey_validation |
| C-MEM | Pengelolaan material kunci di memori | implementasi | PERHATIAN | key_zeroization |
| C-SELFTEST | Self-test & error state modul | implementasi | OK | self_test, conformance |
| C-PLAT | Platform eksekusi (CPU x86-64 bercache, speculative execution) | implementasi | PERHATIAN | speculative, constant_time |
| C-CONF | Kesesuaian implementasi keseluruhan | implementasi | OK | conformance |

### C-CHI — Pemetaan χ (S-box 5-bit) [PERHATIAN]

Satu-satunya komponen nonlinear, derajat 2.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Keseragaman diferensial χ | 8 | = 8 | OK | HASIL UJI LANGSUNG |  |
| Derajat aljabar χ | 2 | = 2 (by design) | PERHATIAN | HASIL UJI LANGSUNG | Derajat rendah dikompensasi 24 ronde; relevan untuk serangan aljabar/kubus ronde tereduksi (A-H-03/04) |
| Nonlinearitas χ | 8 | = 8 | OK | HASIL UJI LANGSUNG |  |
| Bijektif | True | True | OK | HASIL UJI LANGSUNG |  |

### C-DIFF — Lapisan linear θ, ρ, π [OK]

Difusi antar-lane / kolom.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Ronde menuju difusi penuh Keccak-f[1600] | 3 | ≤ 6 | OK | HASIL UJI LANGSUNG |  |

### C-ROUND — ι & jumlah ronde (24) [OK]

Margin terhadap serangan ronde tereduksi.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Margin keamanan ronde (collision praktis 5/24) | 79% | ≥ 20% | OK | HASIL LITERATUR | A-H-03 |

### C-PAD — Padding pad10*1 + domain separation [OK]

Kebenaran padding pada batas blok (rate).

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Digest pada panjang batas rate (r−2, r−1, r, r+1, …) = hashlib | 8/8 | 100% | OK | HASIL UJI LANGSUNG |  |
| Padding satu byte (panjang ≡ r−1) | 0x86 | 0x86 (01 ∥ 10*1) | OK | HASIL UJI LANGSUNG |  |

### C-SPONGE — Konstruksi sponge (rate/capacity) [OK]

Batas generik min(2^(n/2), 2^(c/2)).

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Kekuatan collision min(n/2, c/2) | 128 bit | ≥ 128 | OK | HASIL UJI LANGSUNG |  |
| Kekuatan preimage min(n, c/2) | 256 bit | ≥ 256 | OK | HASIL UJI LANGSUNG |  |
| Avalanche digest penuh | 0.5029 | 0,5 ± 0,02 | OK | HASIL UJI LANGSUNG |  |

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

### C-PLAT — Platform eksekusi (CPU x86-64 bercache, speculative execution) [PERHATIAN]

Side-channel mikroarsitektur.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Platform ber-cache bersama & speculative execution | Shared library (.so) di Linux x86-64; CPU multi-core dengan cache L3 bersama | operasi rahasia constant-time | PERHATIAN | HASIL LITERATUR | A-X-01 / A-X-02 |

### C-CONF — Kesesuaian implementasi keseluruhan [OK]

Keluaran identik dengan standar.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| KAT implementasi referensi (core/) | 3/3 LULUS | 100% cocok | OK | HASIL UJI LANGSUNG | Vektor: NIST CSRC SHA3-256 example |

## 4. Matriks Komponen–Kelemahan–Metode (KUK 2.2)

Tiga lapis pengujian × level uji (metode yang dipetakan):

| Lapis \ Level | Unit | Integrasi | Sistem |
|---|---|---|---|
| Kesesuaian | M-KAT, M-MCT, M-PAD | — | — |
| Kekuatan algoritma | M-AVAL, M-DIFF, M-DIFFUSION, M-GENERIC, M-SBOX, M-SP80022 | — | M-KEYSIZE |
| Implementasi & sistem | M-CODEREVIEW | M-FUZZ, M-TIMING | M-SELFTEST, M-ZEROIZE |

| Komponen | Status | Kelemahan | Serangan | Metode | Lapis | Level | Standar | Akses |
|---|---|---|---|---|---|---|---|---|
| C-CONF Kesesuaian implementasi keseluruhan | OK | Keluaran implementasi tidak sesuai standar | — | M-KAT Known Answer Test (KAT) terhadap vektor resmi | Kesesuaian | Unit | ISO-18367, ISO-24759 | ✔ black |
| C-CONF Kesesuaian implementasi keseluruhan | OK | Keluaran implementasi tidak sesuai standar | — | M-MCT Monte Carlo Test (MCT) & Multi-block Message Test (MMT) gaya CAVP | Kesesuaian | Unit | ISO-18367, ISO-24759 | ✔ black |
| C-PAD Padding pad10*1 + domain separation | OK | Padding salah pada batas blok | A-H-07 | M-PAD Uji kesesuaian padding (pad10*1 / MD-strengthening) pada batas blok | Kesesuaian | Unit | FIPS-202, ISO-10118-3 | ✔ black |
| C-SELFTEST Self-test & error state modul | OK | Keluaran implementasi tidak sesuai standar | — | M-KAT Known Answer Test (KAT) terhadap vektor resmi | Kesesuaian | Unit | ISO-18367, ISO-24759 | ✔ black |
| C-SELFTEST Self-test & error state modul | OK | Keluaran implementasi tidak sesuai standar | — | M-MCT Monte Carlo Test (MCT) & Multi-block Message Test (MMT) gaya CAVP | Kesesuaian | Unit | ISO-18367, ISO-24759 | ✔ black |
| C-CHI Pemetaan χ (S-box 5-bit) | PERHATIAN | Derajat aljabar rendah pemetaan χ | A-H-03, A-H-04, A-H-05 | M-AVAL Uji avalanche & Strict Avalanche Criterion (fungsi penuh) | Kekuatan algoritma | Unit | ISO-18367 | ✔ black |
| C-CHI Pemetaan χ (S-box 5-bit) | PERHATIAN | Derajat aljabar rendah pemetaan χ | A-H-03, A-H-04, A-H-05 | M-DIFF Kriptanalisis diferensial (pencarian trail / batas S-box aktif) | Kekuatan algoritma | Unit | ISO-18033-3, ISO-15408 | ✔ grey |
| C-CHI Pemetaan χ (S-box 5-bit) | PERHATIAN | Nonlinearitas/keseragaman diferensial S-box tidak memadai | A-BC-03 | M-DIFF Kriptanalisis diferensial (pencarian trail / batas S-box aktif) | Kekuatan algoritma | Unit | ISO-18033-3, ISO-15408 | ✔ grey |
| C-CHI Pemetaan χ (S-box 5-bit) | PERHATIAN | Derajat aljabar rendah pemetaan χ | A-H-03, A-H-04, A-H-05 | M-SBOX Analisis sifat S-box / fungsi nonlinear (NL, DDT, LAT, derajat, SAC) | Kekuatan algoritma | Unit | ISO-18033-3, FIPS-197, FIPS-202 | ✔ grey |
| C-CHI Pemetaan χ (S-box 5-bit) | PERHATIAN | Nonlinearitas/keseragaman diferensial S-box tidak memadai | A-BC-03 | M-SBOX Analisis sifat S-box / fungsi nonlinear (NL, DDT, LAT, derajat, SAC) | Kekuatan algoritma | Unit | ISO-18033-3, FIPS-197, FIPS-202 | ✔ grey |
| C-DIFF Lapisan linear θ, ρ, π | OK | Difusi tidak lengkap / branch number rendah | A-H-03, A-BC-03 | M-AVAL Uji avalanche & Strict Avalanche Criterion (fungsi penuh) | Kekuatan algoritma | Unit | ISO-18367 | ✔ black |
| C-DIFF Lapisan linear θ, ρ, π | OK | Difusi tidak lengkap / branch number rendah | A-H-03, A-BC-03 | M-DIFF Kriptanalisis diferensial (pencarian trail / batas S-box aktif) | Kekuatan algoritma | Unit | ISO-18033-3, ISO-15408 | ✔ grey |
| C-DIFF Lapisan linear θ, ρ, π | OK | Difusi tidak lengkap / branch number rendah | A-H-03, A-BC-03 | M-DIFFUSION Analisis difusi (branch number/MDS, ronde menuju difusi penuh, avalanche per ronde) | Kekuatan algoritma | Unit | ISO-18033-3, ISO-18033-4, FIPS-202 | ✔ grey |
| C-DIFF Lapisan linear θ, ρ, π | OK | Difusi tidak lengkap / branch number rendah | A-H-03, A-BC-03 | M-SP80022 Uji keacakan statistik NIST SP 800-22 (15 uji) | Kekuatan algoritma | Unit | SP-800-22 | ✔ black |
| C-ROUND ι & jumlah ronde (24) | OK | Margin ronde tidak memadai terhadap serangan ronde tereduksi | A-H-03, A-BC-03, A-H-04 | M-DIFF Kriptanalisis diferensial (pencarian trail / batas S-box aktif) | Kekuatan algoritma | Unit | ISO-18033-3, ISO-15408 | ✔ grey |
| C-SPONGE Konstruksi sponge (rate/capacity) | OK | Kapasitas sponge tidak memadai | A-H-01, A-H-02 | M-GENERIC Uji batas generik hash (collision/preimage pada keluaran terpotong) | Kekuatan algoritma | Unit | FIPS-202, SP-800-107 | ✔ black |
| C-SPONGE Konstruksi sponge (rate/capacity) | OK | Batas generik collision/preimage di bawah target | A-H-01, A-H-02 | M-GENERIC Uji batas generik hash (collision/preimage pada keluaran terpotong) | Kekuatan algoritma | Unit | FIPS-202, SP-800-107 | ✔ black |
| C-SPONGE Konstruksi sponge (rate/capacity) | OK | Batas generik collision/preimage di bawah target | A-H-01, A-H-02 | M-KEYSIZE Evaluasi ukuran kunci & tingkat keamanan (SP 800-57 / 131A) | Kekuatan algoritma | Sistem | SP-800-57, SP-800-131A | ✔ black |
| C-API Antarmuka API & validasi masukan | PERHATIAN | Buffer overflow / masukan malformed | A-H-07, A-L-02 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-MEM Pengelolaan material kunci di memori | PERHATIAN | Material kunci tidak dihapus dari memori | A-L-03 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | PERHATIAN | Eksekusi tidak constant-time | A-L-01, A-X-01, A-X-02 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-API Antarmuka API & validasi masukan | PERHATIAN | Buffer overflow / masukan malformed | A-H-07, A-L-02 | M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | ISO-29119, ISO-18045 | ✔ black |
| C-API Antarmuka API & validasi masukan | PERHATIAN | Kunci publik/titik tidak divalidasi | — | M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | ISO-29119, ISO-18045 | ✔ black |
| C-PAD Padding pad10*1 + domain separation | OK | Padding salah pada batas blok | A-H-07 | M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | ISO-29119, ISO-18045 | ✔ black |
| C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | PERHATIAN | Eksekusi tidak constant-time | A-L-01, A-X-01, A-X-02 | M-TIMING Analisis timing leakage (dudect / Welch t-test, fixed-vs-random) | Implementasi & sistem | Integrasi | ISO-17825, ISO-20085 | ✔ grey |
| C-CONF Kesesuaian implementasi keseluruhan | OK | Keluaran implementasi tidak sesuai standar | — | M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ black |
| C-MEM Pengelolaan material kunci di memori | PERHATIAN | Material kunci tidak dihapus dari memori | A-L-03 | M-ZEROIZE Uji zeroization material kunci (memory dump pasca-operasi) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ grey |
| C-SELFTEST Self-test & error state modul | OK | Self-test / error state tidak berfungsi | — | M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ black |
| C-SELFTEST Self-test & error state modul | OK | Keluaran implementasi tidak sesuai standar | — | M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ black |

## 5. Estimasi Sumber Daya & Kelayakan (KUK 2.3)

### 5.1 Benchmark mesin lab — HASIL UJI LANGSUNG

| Operasi | ops/detik |
|---|---|
| hash | 2,617.8 |
| primary | 2,617.8 |

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
| M-KAT | primary | 7 | 0.01 detik | 2^7.0 operasi/sampel | ≤ 2^10 B | — | LAYAK | Estimasi 0.01 detik ≤ anggaran 24 jam |
| M-MCT | primary | 16.61 | 4.78 detik | 2^16.6 operasi/sampel | ≤ 2^14 B | — | LAYAK | Estimasi 4.78 detik ≤ anggaran 24 jam |
| M-SBOX | analysis | 20 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-DIFFUSION | primary | 17 | 6.26 detik | 2^17.0 operasi/sampel | ≤ 2^14 B | — | LAYAK | Estimasi 6.26 detik ≤ anggaran 24 jam |
| M-AVAL | primary | 14.29 | 0.96 detik | 2^14.3 operasi/sampel | ≤ 2^13 B | — | LAYAK | Estimasi 0.96 detik ≤ anggaran 24 jam |
| M-SP80022 | primary | 18.58 | 18.65 detik | 2^18.6 operasi/sampel | ≈ 12.5 MB | — | LAYAK | Estimasi 18.65 detik ≤ anggaran 24 jam |
| M-DIFF | primary | 150 | 2^110.7 tahun | 2^150.0 operasi/sampel | ≤ 2^40 B | Trail/distinguisher diferensial pada 2–3 ronde tereduksi — 12.52 detik | LAYAK VERSI TEREDUKSI | Versi penuh 2^110.7 tahun > anggaran; versi tereduksi 12.52 detik |
| M-KEYSIZE | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-GENERIC | hash | 128 | 2^88.7 tahun | 2^128.0 operasi/sampel | ≤ 2^40 B | Birthday collision pada digest terpotong 32 bit (≈ 2^16 hash) — validasi rumus 2^(n/2) — 6.26 detik | LAYAK VERSI TEREDUKSI | Versi penuh 2^88.7 tahun > anggaran; versi tereduksi 6.26 detik |
| M-PAD | hash | 10 | 0.05 detik | 2^10.0 operasi/sampel | ≤ 2^11 B | — | LAYAK | Estimasi 0.05 detik ≤ anggaran 24 jam |
| M-TIMING | primary | 20 | 50.07 detik | 2^20.0 operasi/sampel | ≤ 2^16 B | — | LAYAK | Estimasi 50.07 detik ≤ anggaran 24 jam |
| M-TVLA | primary | 17 | 6.26 detik | 2^17.0 operasi/sampel | ≤ 2^14 B | — | TIDAK LAYAK | Alat tidak tersedia: oscilloscope, chipwhisperer |
| M-CODEREVIEW | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-FUZZ | primary | 20 | 50.07 detik | 2^20.0 operasi/sampel | ≤ 2^16 B | — | LAYAK | Estimasi 50.07 detik ≤ anggaran 24 jam |
| M-ZEROIZE | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-SELFTEST | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |

## 6. Metode Terpilih & Parameter Pengujian (KUK 3.1, 3.2)

### 6.1 Penetapan metode

Rumus: skor = relevansi[keparahan 1–3 + tren serangan (+1 praktis | +0,5 teoretis), maks 3] × kelayakan(1 | 0,6 | 0) × akses(1 | 0); ambang ≥ 1.0.

| Metode | Lapis | Level | Varian | Skor | Target | Alasan |
|---|---|---|---|---|---|---|
| M-AVAL Uji avalanche & Strict Avalanche Criterion (fungsi penuh) | Kekuatan algoritma | Unit | penuh | 3 | C-CHI | Skor 3.0 ≥ 1.0: relevan terhadap C-CHI. Estimasi 0.96 detik ≤ anggaran 24 jam |
| M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | penuh | 3 | C-API | Skor 3.0 ≥ 1.0: relevan terhadap C-API. Estimasi 50.07 detik ≤ anggaran 24 jam |
| M-SBOX Analisis sifat S-box / fungsi nonlinear (NL, DDT, LAT, derajat, SAC) | Kekuatan algoritma | Unit | penuh | 3 | C-CHI | Skor 3.0 ≥ 1.0: relevan terhadap C-CHI. Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-TIMING Analisis timing leakage (dudect / Welch t-test, fixed-vs-random) | Implementasi & sistem | Integrasi | penuh | 3 | C-PLAT | Skor 3.0 ≥ 1.0: relevan terhadap C-PLAT. Estimasi 50.07 detik ≤ anggaran 24 jam |
| M-ZEROIZE Uji zeroization material kunci (memory dump pasca-operasi) | Implementasi & sistem | Sistem | penuh | 3 | C-MEM | Skor 3.0 ≥ 1.0: relevan terhadap C-MEM. Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-DIFFUSION Analisis difusi (branch number/MDS, ronde menuju difusi penuh, avalanche per ronde) | Kekuatan algoritma | Unit | penuh | 2 | C-DIFF | Skor 2.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 6.26 detik ≤ anggaran 24 jam |
| M-PAD Uji kesesuaian padding (pad10*1 / MD-strengthening) pada batas blok | Kesesuaian | Unit | penuh | 2 | C-PAD | Skor 2.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 0.05 detik ≤ anggaran 24 jam |
| M-SP80022 Uji keacakan statistik NIST SP 800-22 (15 uji) | Kekuatan algoritma | Unit | penuh | 2 | C-DIFF | Skor 2.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 18.65 detik ≤ anggaran 24 jam |
| M-DIFF Kriptanalisis diferensial (pencarian trail / batas S-box aktif) | Kekuatan algoritma | Unit | tereduksi | 1.8 | C-CHI | Skor 1.8 ≥ 1.0: relevan terhadap C-CHI. Versi penuh 2^110.7 tahun > anggaran; versi tereduksi 12.52 detik |
| M-KEYSIZE Evaluasi ukuran kunci & tingkat keamanan (SP 800-57 / 131A) | Kekuatan algoritma | Sistem | penuh | 1.5 | C-SPONGE | Wajib (kesesuaian standar / baseline keamanan). Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-KAT Known Answer Test (KAT) terhadap vektor resmi | Kesesuaian | Unit | penuh | 1 | C-CONF, C-SELFTEST | Wajib (kesesuaian standar / baseline keamanan). Estimasi 0.01 detik ≤ anggaran 24 jam |
| M-MCT Monte Carlo Test (MCT) & Multi-block Message Test (MMT) gaya CAVP | Kesesuaian | Unit | penuh | 1 | C-CONF, C-SELFTEST | Wajib (kesesuaian standar / baseline keamanan). Estimasi 4.78 detik ≤ anggaran 24 jam |
| M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | penuh | 1 | C-CONF, C-SELFTEST | Skor 1.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 0 detik (analitis) ≤ anggaran 24 jam |

**Metode yang ditolak:**

| Metode | Kelayakan | Skor | Alasan |
|---|---|---|---|
| M-GENERIC Uji batas generik hash (collision/preimage pada keluaran terpotong) | 0.6 | 0.9 | Ditolak: skor 0.9 < 1.0 |
| M-TVLA Uji kebocoran daya/EM (TVLA, ISO/IEC 17825) | 0 | 0 | Ditolak: Alat tidak tersedia: oscilloscope, chipwhisperer |
| M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | 1 | 0 | Ditolak: memerlukan akses white-box (di luar akses penguji) |

### 6.2 Parameter pengujian

**M-AVAL**

| Parameter | Nilai |
|---|---|
| samples | 10000 |
| flip | 1 bit pesan |
| target_mean | 0.5 |
| tolerance_mean | 0.01 |
| per_bit_tolerance | 0.05 |
| sac_matrix | n_in × n_out probabilitas perubahan |
| variant | penuh |
| estimated_time | 0.96 detik |

**M-FUZZ**

| Parameter | Nilai |
|---|---|
| engine | fuzzing berbasis properti (Hypothesis/AFL++ via harness C) |
| executions | 1000000 |
| inputs | panjang 0, panjang maks+1, buffer tidak selaras, NULL pointer, kunci/nonce panjang salah |
| pass_criterion | 0 crash, 0 sanitizer error, galat terdefinisi |
| variant | penuh |
| estimated_time | 50.07 detik |

**M-SBOX**

| Parameter | Nilai |
|---|---|
| properties | NL, DDT/DU, LAT/bias, derajat aljabar, SAC, titik tetap, bijektivitas |
| domain | exhaustive seluruh 2^n masukan |
| reference_values | chi_differential_uniformity=8; chi_algebraic_degree=2; collision_bits=128; preimage_bits=256 |
| pass_criterion | nilai terukur = nilai acuan desain |
| variant | penuh |
| estimated_time | 0 detik (analitis) |

**M-TIMING**

| Parameter | Nilai |
|---|---|
| method | dudect fixed-vs-random (Welch t) |
| measurements | 1000000 |
| threshold_abs_t | 4.5 |
| classes | pesan tetap vs acak |
| timer | rdtsc / perf_counter_ns, core diisolasi (taskset), turbo dimatikan |
| variant | penuh |
| estimated_time | 50.07 detik |

**M-ZEROIZE**

| Parameter | Nilai |
|---|---|
| procedure | core dump / gdb setelah free & pemanggilan API destroy |
| search | pola kunci uji (known key) |
| pass_criterion | 0 kemunculan |
| variant | penuh |
| estimated_time | 0 detik (analitis) |

**M-DIFFUSION**

| Parameter | Nilai |
|---|---|
| rounds_tested | 1, 2, 3, 4, 5, 6 |
| samples_per_round | 10000 |
| metric | fraksi bit keluaran berubah (1 bit masukan dibalik) |
| full_diffusion_criterion | \|mean − 0,5\| ≤ 0,01 dan min > 0,3 |
| branch_number_target | n/a |
| variant | penuh |
| estimated_time | 6.26 detik |

**M-PAD**

| Parameter | Nilai |
|---|---|
| rate_bytes | 136 |
| lengths_bytes | 0, 1, 134, 135, 136, 137, 271, 272, 415 |
| domain_separation | 0x06 (SHA-3) |
| pass_criterion | digest = referensi untuk setiap panjang |
| variant | penuh |
| estimated_time | 0.05 detik |

**M-SP80022**

| Parameter | Nilai |
|---|---|
| sequences_m | 100 |
| bits_per_sequence_n | 1000000 |
| total_bits | 100000000 |
| alpha | 0.01 |
| proportion_threshold | 0.9601 |
| proportion_threshold_formula | (1−α) − 3·√((1−α)·α/m) = 0,99 − 3·√(0,99·0,01/100) |
| min_pass_sequences | 97 |
| min_pass_note | ambang 0,96015 × 100 = 96,015 → ketat 97/100; laporan NIST STS menyebut ≈ 96/100 |
| uniformity_p_value_T_min | 0.0001 |
| uniformity_bins | 10 |
| tests | Frequency (Monobit); Frequency within a Block M=128; Runs; Longest Run of Ones in a Block M=10000; Binary Matrix Rank M=32; Q=32; Discrete Fourier Transform (Spectral); Non-overlapping Template Matching m=9; N_blocks=8; Overlapping Template Matching m=9; M=1032; Maurer's Universal Statistical L=7; Q=1280; Linear Complexity M=500; Serial m=16; Approximate Entropy m=10; Cumulative Sums mode=forward & backward; Random Excursions states=±1..±4; Random Excursions Variant states=±1..±9 |
| source | SP 800-22 Rev.1a §2 & §4.2 (parameter default yang direkomendasikan) |
| generation | digest berantai H_i = H(H_{i-1} ∥ i) |
| variant | penuh |
| estimated_time | 18.65 detik |

**M-DIFF**

| Parameter | Nilai |
|---|---|
| variant | ronde tereduksi |
| reduced_rounds | 2, 3 |
| full_rounds | 24 |
| samples_log2 | 18 |
| reduced_desc | Trail/distinguisher diferensial pada 2–3 ronde tereduksi |
| pass_criterion | serangan ronde tereduksi berhasil sesuai prediksi & tidak dapat diperluas ≥ 70% ronde |
| estimated_time | 12.52 detik |

**M-KEYSIZE**

| Parameter | Nilai |
|---|---|
| key_parameters | state_bits=1600; rate_bits=1088; capacity_bits=512; output_bits=256; output_bits_per_op=256 |
| security_bits | 128 |
| min_security_bits | 112 |
| horizon | 2030 (≥128 bit untuk perlindungan setelah 2030) |
| reference | SP 800-57 Part 1 Rev.5 Tabel 2 & 4; SP 800-131A Rev.2 |
| variant | penuh |
| estimated_time | 0 detik (analitis) |

**M-KAT**

| Parameter | Nilai |
|---|---|
| vector_sources | NIST CSRC SHA3-256 example ('abc'), NIST CSRC SHA3-256 example (200 byte 0xA3), NIST CSRC SHA3-256 example (pesan kosong) |
| vector_count | 3 |
| additional_sources | NIST CAVP/ACVP response files untuk implementasi produk |
| pass_criterion | 100% vektor cocok (0 selisih bit) |
| reference_result | 3/3 (LULUS) pada core/ |
| variant | penuh |
| estimated_time | 0.01 detik |

**M-MCT**

| Parameter | Nilai |
|---|---|
| mct_outer_iterations | 100 |
| mct_inner_iterations | 1000 |
| mmt_messages | panjang 1..10 × rate |
| checkpoints | setiap iterasi luar (100 checkpoint) |
| pass_criterion | 100% checkpoint = implementasi referensi core/ |
| variant | penuh |
| estimated_time | 4.78 detik |

**M-SELFTEST**

| Parameter | Nilai |
|---|---|
| tests | POST KAT tiap algoritma, pairwise consistency (pkc/dss), continuous RNG test, error state injection |
| variant | penuh |
| estimated_time | 0 detik (analitis) |

## 7. Matriks Keterlacakan

| ID | Persyaratan | Objek | Metode uji | Rujukan | Kriteria lulus |
|---|---|---|---|---|---|
| K-01 | Perubahan 1 bit masukan/kunci mengubah ≈ 50% bit keluaran | C-CHI Pemetaan χ (S-box 5-bit) | M-AVAL (penuh) | ISO 18367 | rerata 0,5 ± 0,01; tiap bit 0,5 ± 0,05 |
| K-02 | Tidak ada karakteristik diferensial ronde penuh dengan probabilitas > 2^-k | C-CHI Pemetaan χ (S-box 5-bit) | M-DIFF (tereduksi) | ISO 18033-3, ISO 15408 | batas bawah S-box aktif × DP_max ≤ 2^-128 (≥ 4 ronde) |
| K-03 | Lapisan difusi mencapai difusi penuh dengan margin ronde memadai | C-DIFF Lapisan linear θ, ρ, π | M-DIFFUSION (penuh) | ISO 18033-3, ISO 18033-4, FIPS 202 | branch number optimal; avalanche ≈ 0,5 sebelum ≤ 1/2 jumlah ronde |
| K-04 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | C-SPONGE Konstruksi sponge (rate/capacity) | M-KEYSIZE (penuh) | SP 800-57, SP 800-131A | security_bits ≥ 112 |
| K-05 | Komponen nonlinear memenuhi batas acuan NL/DU/derajat | C-CHI Pemetaan χ (S-box 5-bit) | M-SBOX (penuh) | ISO 18033-3, FIPS 197, FIPS 202 | NL, DU, derajat = nilai acuan desain |
| K-06 | Keluaran (keystream/CTR/digest berantai) tak terbedakan dari acak | C-DIFF Lapisan linear θ, ρ, π | M-SP80022 (penuh) | SP 800-22 | proporsi lulus ≥ ambang SP 800-22 & P-value_T ≥ 0,0001 tiap uji |
| I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | C-API Antarmuka API & validasi masukan | M-FUZZ (penuh) | ISO 29119, ISO 18045 | 0 crash; 100% masukan invalid ditolak dengan galat terdefinisi |
| I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | C-CONF Kesesuaian implementasi keseluruhan; C-SELFTEST Self-test & error state modul | M-KAT (penuh) | ISO 18367, ISO 24759 | 100% vektor cocok |
| I-03 | Implementasi konsisten pada iterasi berantai & pesan multi-blok | C-CONF Kesesuaian implementasi keseluruhan; C-SELFTEST Self-test & error state modul | M-MCT (penuh) | ISO 18367, ISO 24759 | 100% checkpoint cocok dengan implementasi referensi |
| I-04 | Padding benar untuk panjang r−2, r−1, r, r+1 byte | C-PAD Padding pad10*1 + domain separation | M-PAD (penuh) | FIPS 202, ISO 10118-3 | digest = referensi untuk semua panjang batas |
| I-05 | Power-on self-test (KAT) & conditional test (pairwise) berjalan; error state memblokir layanan | C-CONF Kesesuaian implementasi keseluruhan; C-SELFTEST Self-test & error state modul | M-SELFTEST (penuh) | ISO 19790, ISO 24759 | semua self-test terpicu & error state tervalidasi |
| I-06 | Waktu eksekusi tidak bergantung pada data rahasia | C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | M-TIMING (penuh) | ISO 17825, ISO 20085 | \|t\| < 4,5 pada ≥ 10^6 pengukuran |
| I-07 | Kunci/CSP dihapus dari memori setelah dipakai | C-MEM Pengelolaan material kunci di memori | M-ZEROIZE (penuh) | ISO 19790, ISO 24759 | 0 salinan kunci pada dump memori |

## 8. Lampiran: Peta KUK → Bagian Dokumen → File Kode

| KUK | Deskripsi | Bagian | File kode | Unit test |
|---|---|---|---|---|
| 1.1 | Informasi desain & teknik implementasi | Bab 1 | uk1_metode/profile.py, config/product_profile.yaml, algo_catalog/ (Daftar Algoritma yang Diuji) | tests/test_uk1_ek1.py::test_kuk_1_1_*, tests/test_algo_catalog.py |
| 1.2 | Tren serangan terhadap platform | Bab 2.2 | uk1_metode/attack_kb.py, uk1_metode/data/attacks.yaml | tests/test_uk1_ek1.py::test_kuk_1_2_* |
| 1.3 | Best practice metode pengujian | Bab 2.1 | uk1_metode/standards_kb.py, uk1_metode/data/standards.yaml | tests/test_uk1_ek1.py::test_kuk_1_3_* |
| 2.1 | Komponen berpotensi lemah | Bab 3 | uk1_metode/decompose.py, uk1_metode/component_analysis.py, core/boolean.py | tests/test_core_components.py, tests/test_uk1_ek2.py::test_kuk_2_1_* |
| 2.2 | Analisis best practice vs potensi kelemahan | Bab 4 | uk1_metode/mapping.py, uk1_metode/data/methods.yaml | tests/test_uk1_ek2.py::test_kuk_2_2_* |
| 2.3 | Kesesuaian sumber daya internal | Bab 5 | uk1_metode/resources.py | tests/test_uk1_ek2.py::test_kuk_2_3_* |
| 3.1 | Penetapan metode | Bab 6.1 | uk1_metode/selector.py | tests/test_uk1_ek3.py::test_kuk_3_1_* |
| 3.2 | Penetapan parameter | Bab 6.2 | uk1_metode/parameters.py | tests/test_uk1_ek3.py::test_kuk_3_2_* |
| — | Matriks keterlacakan | Bab 7 | uk1_metode/traceability.py | tests/test_uk1_ek3.py::test_traceability_* |

KAT rinci (SHA3-256):

| Vektor | Sumber | Hasil |
|---|---|---|
| FIPS202-empty | NIST CSRC SHA3-256 example (pesan kosong) | LULUS |
| FIPS202-abc | NIST CSRC SHA3-256 example ('abc') | LULUS |
| FIPS202-1600bit | NIST CSRC SHA3-256 example (200 byte 0xA3) | LULUS |
