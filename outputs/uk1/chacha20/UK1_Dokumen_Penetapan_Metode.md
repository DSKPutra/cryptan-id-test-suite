# Dokumen Penetapan Metode & Parameter Pengujian — ChaCha20

**Cryptan.ID Test Suite** v1.0.0 · Modul **UK-1** · Unit J.61KRP00.012.1 — *Menentukan Metode Pengujian yang akan Dilakukan* · SKKNI 2023-004 (Cryptographic Analyst)

Dibangkitkan: 2026-10-01T09:16:56+07:00 · mode: full · objek: **Cryptan.ID SecureLib** (1.0.0 (hipotetis))

> Seluruh data produk bersifat ILUSTRATIF. Nilai bertanda HASIL UJI LANGSUNG dihitung oleh kode; HASIL LITERATUR dikutip dari rujukan; PERLU_VERIFIKASI wajib dicek ke sumber primer.

## Ringkasan

- Kelas primitif: **Stream cipher**, struktur ARX
- Tingkat akses penguji: **grey_box**
- KAT implementasi referensi: **3/3 LULUS**
- Komponen berpotensi lemah: **—**; perlu perhatian: C-STATE, C-API, C-MEM, C-PLAT
- Metode terpilih: **13** · ditolak: 4 · upaya 57 / 240 jam-orang (SESUAI)

## 1. Profil Produk & Ruang Lingkup (KUK 1.1)

| Atribut | Nilai |
|---|---|
| Produk | Cryptan.ID SecureLib 1.0.0 (hipotetis) |
| Deskripsi | Library kriptografi perangkat lunak (shared object) untuk Linux x86-64 |
| Algoritma | ChaCha20 (RFC 8439) |
| Kelas primitif | Stream cipher |
| Struktur | ARX |
| Mode | — |
| Parameter | key_bits=256; nonce_bits=96; counter_bits=32; rounds=20; state_words=16; output_bits_per_op=512 |
| Platform | Shared library (.so) di Linux x86-64; CPU multi-core dengan cache L3 bersama |
| Bahasa / binding | C / Python |
| Antarmuka | C API (libsecure.so), Python binding (ctypes) |
| RBG | getrandom(2) → HMAC_DRBG (SP 800-90A) |
| Catatan implementasi | nonce_generation=acak 96-bit per pesan; max_message_bytes=274877906944 |
| Tingkat akses | grey_box — Penguji memperoleh spesifikasi algoritma & dokumen desain tingkat tinggi, biner library + header API, dan lingkungan uji dengan kunci uji. Kode sumber TIDAK tersedia. |
| Kelengkapan profil | LENGKAP |
| Daftar algoritma diuji (algo_catalog) | 33 kombinasi (block_cipher=6; stream_cipher=2; hash=7; mac=4; pkc_kem=7; signature=6; drbg=1); 6 peringatan tinggi; CHACHA20-256 termasuk daftar (strength 256, status not_nist) — `algorithms_under_test.yaml` |

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
| ISO-18033-4 | ISO/IEC | Encryption algorithms — Part 4: Stream ciphers | 2011 | Spesifikasi algoritma/skema |
| RFC-8439 | IETF | ChaCha20 and Poly1305 for IETF Protocols *(Di luar daftar materi; spesifikasi algoritma ChaCha20)* | 2018 | Spesifikasi algoritma/skema |
| ISO-18367 | ISO/IEC | Cryptographic algorithms and security mechanisms conformance testing | 2016 | Pengujian kesesuaian |
| SP-800-22 | NIST | A Statistical Test Suite for Random and Pseudorandom Number Generators (Rev. 1a) | 2010 | Pengujian kekuatan / kriteria keamanan |
| ISO-17825 | ISO/IEC | Testing methods for the mitigation of non-invasive attack classes against cryptographic modules `PERLU_VERIFIKASI` | 2024 | Pengujian implementasi & modul |
| ISO-19790 | ISO/IEC | Security requirements for cryptographic modules | 2012 | Pengujian implementasi & modul |
| ISO-20085 | ISO/IEC | Test tool requirements and test tool calibration methods for use in testing non-invasive attack mitigation techniques | 2019 | Pengujian implementasi & modul |
| ISO-24759 | ISO/IEC | Test requirements for cryptographic modules | 2017 | Pengujian implementasi & modul |
| SP-800-131A | NIST | Transitioning the Use of Cryptographic Algorithms and Key Lengths (Rev. 2) | 2019 | Ukuran kunci & manajemen kunci |
| SP-800-57 | NIST | Recommendation for Key Management, Part 1: General (Rev. 5) | 2020 | Ukuran kunci & manajemen kunci |
| SP-800-90A | NIST | Recommendation for Random Number Generation Using Deterministic RBGs (Rev. 1) | 2015 | Pembangkitan bilangan acak |
| ISO-15408 | ISO/IEC | Evaluation criteria for IT security (Common Criteria) | 2022 | Evaluasi keamanan / migrasi |
| ISO-18045 | ISO/IEC | Methodology for IT security evaluation (CEM) | 2022 | Evaluasi keamanan / migrasi |
| ISO-29119 | ISO/IEC/IEEE | Software and systems engineering — Software testing | 2022 | Proses & dokumentasi pengujian |

### 2.2 Tren Serangan Relevan (KUK 1.2) — HASIL LITERATUR

11 serangan relevan setelah filter profil; praktis: 8; perlu verifikasi: 3.

| ID | Kategori | Serangan | Model | Kompleksitas (log2 T/D/M) | Ronde | Status | Rujukan |
|---|---|---|---|---|---|---|---|
| A-SC-01 | desain | Exhaustive key search (256-bit) | KPA | 256/0/0 | full | teoretis | Batas generik \|K\| = 2^256 |
| A-SC-02 | desain | Probabilistic Neutral Bits (PNB) / differential — ChaCha ronde tereduksi | CPA (chosen IV) | 248/27/— | 7/20 (ChaCha6: waktu 2^139) | teoretis `PERLU_VERIFIKASI` | Aumasson, Fischer, Khazaei, Meier, Rechberger — New Features of Latin Dances, FSE 2008 |
| A-SC-03 | desain | Differential-linear distinguisher (ChaCha ronde tereduksi) | CPA (chosen IV) | —/—/— | ≤ 7/20 | teoretis `PERLU_VERIFIKASI` | Beierle, Leander, Todo — Improved Differential-Linear Attacks with Applications to ARX Ciphers, CRYPTO 2020 |
| A-SC-06 | protokol | Nonce reuse (two-time pad) | KPA / COA | 0/1/0 | n/a | praktis | RFC 8439 §4 (nonce MUST NOT repeat for the same key) |
| A-SC-07 | bahasa | Counter overflow / wrap-around (keystream berulang) | KPA | 0/38/0 | n/a | praktis (bila > 256 GiB per nonce pada ChaCha20 RFC 8439) | RFC 8439 §2.4 (counter 32-bit ⇒ maks 2^32 blok × 64 byte) |
| A-L-01 | bahasa | Perbandingan tidak constant-time (memcmp pada tag/MAC/padding) | side-channel | —/—/— | n/a | praktis `PERLU_VERIFIKASI` | Lawson — Timing attack in Google Keyczar, 2009; ISO/IEC 17825 |
| A-L-02 | bahasa | Buffer over-read/overflow (memory safety) | n/a | 0/0/0 | n/a | praktis | NVD CVE-2014-0160 (Heartbleed, OpenSSL) |
| A-L-03 | bahasa | Material kunci tidak di-zeroize (sisa di memori / cold boot) | n/a | —/—/— | n/a | praktis | Halderman et al. — Lest We Remember: Cold Boot Attacks, USENIX Security 2008; ISO/IEC 19790 §7.9 (zeroisation) |
| A-P-11 | platform | RNG lemah saat pembangkitan kunci | n/a | 15/0/— | n/a | praktis | CVE-2008-0166 (Debian OpenSSL, ruang kunci 2^15); Heninger et al., USENIX Security 2012 |
| A-X-01 | platform | Transient execution (Spectre) | side-channel | —/—/— | n/a | praktis | Kocher et al. — Spectre Attacks, IEEE S&P 2019 |
| A-X-02 | platform | Frequency-scaling side-channel (Hertzbleed) | side-channel | —/—/— | n/a | praktis (remote timing dari variasi daya) | Wang et al. — Hertzbleed, USENIX Security 2022 |

## 3. Hasil Telaah Komponen (KUK 2.1)

| ID | Komponen | Lapis | Status | Tag kelemahan |
|---|---|---|---|---|
| C-ARX | Quarter-round ARX (penjumlahan mod 2^32) | algoritma | OK | arx_nonlinear, boolean_function |
| C-DIFF | Difusi antar ronde (column/diagonal round) | algoritma | OK | diffusion |
| C-ROUND | Jumlah ronde (20) | algoritma | OK | round_count |
| C-STATE | Inisialisasi state: konstanta, kunci, counter, nonce | algoritma | PERHATIAN | nonce_reuse, counter_wrap |
| C-KS-OUT | Keluaran keystream | algoritma | OK | keystream_stat |
| C-KEY | Ukuran kunci | algoritma | OK | key_size |
| C-API | Antarmuka API & validasi masukan | implementasi | PERHATIAN | memory_safety, pubkey_validation |
| C-MEM | Pengelolaan material kunci di memori | implementasi | PERHATIAN | key_zeroization |
| C-SELFTEST | Self-test & error state modul | implementasi | OK | self_test, conformance |
| C-RNG | Sumber acak (RBG) | implementasi | OK | rng |
| C-PLAT | Platform eksekusi (CPU x86-64 bercache, speculative execution) | implementasi | PERHATIAN | speculative, constant_time |
| C-CONF | Kesesuaian implementasi keseluruhan | implementasi | OK | conformance |

### C-ARX — Quarter-round ARX (penjumlahan mod 2^32) [OK]

Sumber nonlinearitas: bit carry penjumlahan modular (fungsi mayoritas).

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Derajat aljabar fungsi carry (mayoritas) | 2 | = 2 | OK | HASIL UJI LANGSUNG |  |
| Nonlinearitas fungsi carry (n=3) | 2 | = 2 (maks untuk n=3) | OK | HASIL UJI LANGSUNG |  |
| Imunitas korelasi carry | 0 | 0 (sifat mayoritas) | OK | HASIL UJI LANGSUNG | Tidak relevan untuk ARX tanpa LFSR; dicatat untuk analisis korelasi |
| P[(a+b) mod 2^8 = a⊕b] | 0.1335 | ≈ (3/4)^7 ≈ 0,1335 | OK | HASIL UJI LANGSUNG |  |

### C-DIFF — Difusi antar ronde (column/diagonal round) [OK]

Jumlah ronde hingga difusi penuh.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Ronde menuju difusi penuh (permutasi, tanpa feed-forward) | 3 | ≤ 4 | OK | HASIL UJI LANGSUNG |  |

### C-ROUND — Jumlah ronde (20) [OK]

Margin keamanan terhadap PNB / differential-linear.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Margin keamanan ronde (serangan terbaik 7/20) | 65% | ≥ 20% | OK | HASIL LITERATUR | A-SC-02 / A-SC-03 |

### C-STATE — Inisialisasi state: konstanta, kunci, counter, nonce [PERHATIAN]

Keunikan nonce & batas counter 32-bit.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Batas tabrakan nonce acak 96-bit | 2^48 pesan | rekey ≤ 2^32 pesan (p tabrakan ≤ 2^-32) | PERHATIAN | KLAIM PROFIL | Klaim profil: acak 96-bit per pesan |
| Batas panjang pesan per nonce (counter 32-bit) | 274877906944 byte (2^38) | produk menolak > batas (klaim 274877906944) | PERHATIAN | HASIL UJI LANGSUNG | Counter implementasi referensi wrap-around |

### C-KS-OUT — Keluaran keystream [OK]

Sifat statistik & kompleksitas linear keystream.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Kompleksitas linear (Berlekamp–Massey) | 999 | ≈ N/2 = 1000 (±3) | OK | HASIL UJI LANGSUNG |  |
| Pra-uji keacakan keystream (Monobit, Runs) | Frequency (Monobit) p=0.435, Runs p=0.762 | p ≥ 0,01 | OK | HASIL UJI LANGSUNG |  |

### C-KEY — Ukuran kunci [OK]

Ruang kunci 2^256.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Tingkat keamanan (SP 800-57) | 256 bit | ≥ 128 bit | OK | HASIL UJI LANGSUNG |  |

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
| KAT implementasi referensi (core/) | 3/3 LULUS | 100% cocok | OK | HASIL UJI LANGSUNG | Vektor: RFC 8439 Appendix A.1 Test Vector #1; RFC 8439 §2.3.2; RFC 8439 §2.4.2 |

## 4. Matriks Komponen–Kelemahan–Metode (KUK 2.2)

Tiga lapis pengujian × level uji (metode yang dipetakan):

| Lapis \ Level | Unit | Integrasi | Sistem |
|---|---|---|---|
| Kesesuaian | M-KAT | — | — |
| Kekuatan algoritma | M-ARX-PNB, M-AVAL, M-BOOL, M-DIFFUSION, M-LC, M-SP80022 | — | M-BRUTE, M-KEYSIZE |
| Implementasi & sistem | M-CODEREVIEW | M-FUZZ, M-NONCE, M-RNG, M-TIMING | M-SELFTEST, M-ZEROIZE |

| Komponen | Status | Kelemahan | Serangan | Metode | Lapis | Level | Standar | Akses |
|---|---|---|---|---|---|---|---|---|
| C-CONF Kesesuaian implementasi keseluruhan | OK | Keluaran implementasi tidak sesuai standar | — | M-KAT Known Answer Test (KAT) terhadap vektor resmi | Kesesuaian | Unit | ISO-18367, ISO-24759 | ✔ black |
| C-SELFTEST Self-test & error state modul | OK | Keluaran implementasi tidak sesuai standar | — | M-KAT Known Answer Test (KAT) terhadap vektor resmi | Kesesuaian | Unit | ISO-18367, ISO-24759 | ✔ black |
| C-ARX Quarter-round ARX (penjumlahan mod 2^32) | OK | Nonlinearitas ARX rendah pada ronde awal | A-SC-02, A-SC-03 | M-ARX-PNB Analisis diferensial/PNB & differential-linear ARX (ronde tereduksi) | Kekuatan algoritma | Unit | ISO-18033-4, ISO-15408 | ✔ grey |
| C-ARX Quarter-round ARX (penjumlahan mod 2^32) | OK | Nonlinearitas ARX rendah pada ronde awal | A-SC-02, A-SC-03 | M-AVAL Uji avalanche & Strict Avalanche Criterion (fungsi penuh) | Kekuatan algoritma | Unit | ISO-18367 | ✔ black |
| C-ARX Quarter-round ARX (penjumlahan mod 2^32) | OK | Nonlinearitas ARX rendah pada ronde awal | A-SC-02, A-SC-03 | M-BOOL Analisis fungsi Boolean komponen nonlinear (NL, CI, derajat) | Kekuatan algoritma | Unit | ISO-18033-4 | ✔ grey |
| C-ARX Quarter-round ARX (penjumlahan mod 2^32) | OK | Fungsi Boolean dengan NL/CI/derajat rendah | — | M-BOOL Analisis fungsi Boolean komponen nonlinear (NL, CI, derajat) | Kekuatan algoritma | Unit | ISO-18033-4 | ✔ grey |
| C-ARX Quarter-round ARX (penjumlahan mod 2^32) | OK | Nonlinearitas ARX rendah pada ronde awal | A-SC-02, A-SC-03 | M-DIFFUSION Analisis difusi (branch number/MDS, ronde menuju difusi penuh, avalanche per ronde) | Kekuatan algoritma | Unit | ISO-18033-3, ISO-18033-4, FIPS-202 | ✔ grey |
| C-ARX Quarter-round ARX (penjumlahan mod 2^32) | OK | Fungsi Boolean dengan NL/CI/derajat rendah | — | M-LC Kompleksitas linear (Berlekamp–Massey) & periode keystream | Kekuatan algoritma | Unit | ISO-18033-4, SP-800-22 | ✔ black |
| C-DIFF Difusi antar ronde (column/diagonal round) | OK | Difusi tidak lengkap / branch number rendah | A-SC-02, A-SC-03 | M-ARX-PNB Analisis diferensial/PNB & differential-linear ARX (ronde tereduksi) | Kekuatan algoritma | Unit | ISO-18033-4, ISO-15408 | ✔ grey |
| C-DIFF Difusi antar ronde (column/diagonal round) | OK | Difusi tidak lengkap / branch number rendah | A-SC-02, A-SC-03 | M-AVAL Uji avalanche & Strict Avalanche Criterion (fungsi penuh) | Kekuatan algoritma | Unit | ISO-18367 | ✔ black |
| C-DIFF Difusi antar ronde (column/diagonal round) | OK | Difusi tidak lengkap / branch number rendah | A-SC-02, A-SC-03 | M-DIFFUSION Analisis difusi (branch number/MDS, ronde menuju difusi penuh, avalanche per ronde) | Kekuatan algoritma | Unit | ISO-18033-3, ISO-18033-4, FIPS-202 | ✔ grey |
| C-DIFF Difusi antar ronde (column/diagonal round) | OK | Difusi tidak lengkap / branch number rendah | A-SC-02, A-SC-03 | M-SP80022 Uji keacakan statistik NIST SP 800-22 (15 uji) | Kekuatan algoritma | Unit | SP-800-22 | ✔ black |
| C-KS-OUT Keluaran keystream | OK | Keluaran terbedakan dari acak | — | M-LC Kompleksitas linear (Berlekamp–Massey) & periode keystream | Kekuatan algoritma | Unit | ISO-18033-4, SP-800-22 | ✔ black |
| C-KS-OUT Keluaran keystream | OK | Keluaran terbedakan dari acak | — | M-SP80022 Uji keacakan statistik NIST SP 800-22 (15 uji) | Kekuatan algoritma | Unit | SP-800-22 | ✔ black |
| C-ROUND Jumlah ronde (20) | OK | Margin ronde tidak memadai terhadap serangan ronde tereduksi | A-SC-02, A-SC-03 | M-ARX-PNB Analisis diferensial/PNB & differential-linear ARX (ronde tereduksi) | Kekuatan algoritma | Unit | ISO-18033-4, ISO-15408 | ✔ grey |
| C-KEY Ukuran kunci | OK | Ruang kunci / tingkat keamanan tidak memadai | A-SC-01 | M-BRUTE Pencarian kunci menyeluruh (exhaustive key search) | Kekuatan algoritma | Sistem | SP-800-57, SP-800-131A | ✔ black |
| C-KEY Ukuran kunci | OK | Ruang kunci / tingkat keamanan tidak memadai | A-SC-01 | M-KEYSIZE Evaluasi ukuran kunci & tingkat keamanan (SP 800-57 / 131A) | Kekuatan algoritma | Sistem | SP-800-57, SP-800-131A | ✔ black |
| C-API Antarmuka API & validasi masukan | PERHATIAN | Buffer overflow / masukan malformed | A-L-02 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-MEM Pengelolaan material kunci di memori | PERHATIAN | Material kunci tidak dihapus dari memori | A-L-03 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | PERHATIAN | Eksekusi tidak constant-time | A-L-01, A-X-01, A-X-02 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-API Antarmuka API & validasi masukan | PERHATIAN | Buffer overflow / masukan malformed | A-L-02 | M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | ISO-29119, ISO-18045 | ✔ black |
| C-API Antarmuka API & validasi masukan | PERHATIAN | Kunci publik/titik tidak divalidasi | — | M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | ISO-29119, ISO-18045 | ✔ black |
| C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | PERHATIAN | Eksekusi tidak constant-time | A-L-01, A-X-01, A-X-02 | M-TIMING Analisis timing leakage (dudect / Welch t-test, fixed-vs-random) | Implementasi & sistem | Integrasi | ISO-17825, ISO-20085 | ✔ grey |
| C-RNG Sumber acak (RBG) | OK | RBG lemah / entropi rendah | A-P-11 | M-NONCE Uji keunikan & bias nonce (statistik + kelayakan lattice HNP) | Implementasi & sistem | Integrasi | FIPS-186-5, RFC-6979, SP-800-90A, SP-800-38A, RFC-8439 | ✔ grey |
| C-RNG Sumber acak (RBG) | OK | RBG lemah / entropi rendah | A-P-11 | M-RNG Asesmen RBG / sumber entropi (SP 800-90A/B, ISO/IEC 18031) | Implementasi & sistem | Integrasi | SP-800-90A, SP-800-90B, ISO-18031, SP-800-22 | ✔ grey |
| C-STATE Inisialisasi state: konstanta, kunci, counter, nonce | PERHATIAN | Counter wrap-around → keystream berulang | A-SC-07 | M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | ISO-29119, ISO-18045 | ✔ black |
| C-STATE Inisialisasi state: konstanta, kunci, counter, nonce | PERHATIAN | Nonce/IV dipakai ulang | A-SC-06 | M-NONCE Uji keunikan & bias nonce (statistik + kelayakan lattice HNP) | Implementasi & sistem | Integrasi | FIPS-186-5, RFC-6979, SP-800-90A, SP-800-38A, RFC-8439 | ✔ grey |
| C-STATE Inisialisasi state: konstanta, kunci, counter, nonce | PERHATIAN | Counter wrap-around → keystream berulang | A-SC-07 | M-NONCE Uji keunikan & bias nonce (statistik + kelayakan lattice HNP) | Implementasi & sistem | Integrasi | FIPS-186-5, RFC-6979, SP-800-90A, SP-800-38A, RFC-8439 | ✔ grey |
| C-CONF Kesesuaian implementasi keseluruhan | OK | Keluaran implementasi tidak sesuai standar | — | M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ black |
| C-MEM Pengelolaan material kunci di memori | PERHATIAN | Material kunci tidak dihapus dari memori | A-L-03 | M-ZEROIZE Uji zeroization material kunci (memory dump pasca-operasi) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ grey |
| C-SELFTEST Self-test & error state modul | OK | Self-test / error state tidak berfungsi | — | M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ black |
| C-SELFTEST Self-test & error state modul | OK | Keluaran implementasi tidak sesuai standar | — | M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ black |

## 5. Estimasi Sumber Daya & Kelayakan (KUK 2.3)

### 5.1 Benchmark mesin lab — HASIL UJI LANGSUNG

| Operasi | ops/detik |
|---|---|
| encrypt | 14,064.8 |
| primary | 14,064.8 |

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
| M-KAT | primary | 7 | 0.00 detik | 2^7.0 operasi/sampel | ≤ 2^10 B | — | LAYAK | Estimasi 0.00 detik ≤ anggaran 24 jam |
| M-DIFFUSION | primary | 17 | 1.16 detik | 2^17.0 operasi/sampel | ≤ 2^14 B | — | LAYAK | Estimasi 1.16 detik ≤ anggaran 24 jam |
| M-AVAL | primary | 14.29 | 0.18 detik | 2^14.3 operasi/sampel | ≤ 2^13 B | — | LAYAK | Estimasi 0.18 detik ≤ anggaran 24 jam |
| M-SP80022 | primary | 17.58 | 1.74 detik | 2^17.6 operasi/sampel | ≈ 12.5 MB | — | LAYAK | Estimasi 1.74 detik ≤ anggaran 24 jam |
| M-ARX-PNB | primary | 248 | 2^206.3 tahun | 2^248.0 operasi/sampel | ≤ 2^40 B | Bias diferensial 3–4 ronde (distinguisher empiris 2^20 sampel) — 18.64 detik | LAYAK VERSI TEREDUKSI | Versi penuh 2^206.3 tahun > anggaran; versi tereduksi 18.64 detik |
| M-LC | primary | 12 | 0.04 detik | 2^12.0 operasi/sampel | ≤ 2^12 B | — | LAYAK | Estimasi 0.04 detik ≤ anggaran 24 jam |
| M-BOOL | analysis | 10 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-BRUTE | primary | 128 | 2^86.3 tahun | 2^128.0 operasi/sampel | ≤ 2^40 B | Pencarian kunci tereduksi (24 bit kunci tak diketahui) — validasi harness — 2.5 menit | LAYAK VERSI TEREDUKSI | Versi penuh 2^86.3 tahun > anggaran; versi tereduksi 2.5 menit |
| M-KEYSIZE | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-NONCE | primary | 12 | 0.04 detik | 2^12.0 operasi/sampel | ≤ 2^12 B | — | LAYAK | Estimasi 0.04 detik ≤ anggaran 24 jam |
| M-TIMING | primary | 20 | 9.32 detik | 2^20.0 operasi/sampel | ≤ 2^16 B | — | LAYAK | Estimasi 9.32 detik ≤ anggaran 24 jam |
| M-TVLA | primary | 17 | 1.16 detik | 2^17.0 operasi/sampel | ≤ 2^14 B | — | TIDAK LAYAK | Alat tidak tersedia: oscilloscope, chipwhisperer |
| M-CODEREVIEW | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-FUZZ | primary | 20 | 9.32 detik | 2^20.0 operasi/sampel | ≤ 2^16 B | — | LAYAK | Estimasi 9.32 detik ≤ anggaran 24 jam |
| M-ZEROIZE | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-SELFTEST | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-RNG | primary | 10.93 | 0.02 detik | 2^10.9 operasi/sampel | ≈ 0.1 MB | — | LAYAK | Estimasi 0.02 detik ≤ anggaran 24 jam |

## 6. Metode Terpilih & Parameter Pengujian (KUK 3.1, 3.2)

### 6.1 Penetapan metode

Rumus: skor = relevansi[keparahan 1–3 + tren serangan (+1 praktis | +0,5 teoretis), maks 3] × kelayakan(1 | 0,6 | 0) × akses(1 | 0); ambang ≥ 1.0.

| Metode | Lapis | Level | Varian | Skor | Target | Alasan |
|---|---|---|---|---|---|---|
| M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | penuh | 3 | C-API, C-STATE | Skor 3.0 ≥ 1.0: relevan terhadap C-API, C-STATE. Estimasi 9.32 detik ≤ anggaran 24 jam |
| M-NONCE Uji keunikan & bias nonce (statistik + kelayakan lattice HNP) | Implementasi & sistem | Integrasi | penuh | 3 | C-STATE | Skor 3.0 ≥ 1.0: relevan terhadap C-STATE. Estimasi 0.04 detik ≤ anggaran 24 jam |
| M-TIMING Analisis timing leakage (dudect / Welch t-test, fixed-vs-random) | Implementasi & sistem | Integrasi | penuh | 3 | C-PLAT | Skor 3.0 ≥ 1.0: relevan terhadap C-PLAT. Estimasi 9.32 detik ≤ anggaran 24 jam |
| M-ZEROIZE Uji zeroization material kunci (memory dump pasca-operasi) | Implementasi & sistem | Sistem | penuh | 3 | C-MEM | Skor 3.0 ≥ 1.0: relevan terhadap C-MEM. Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-RNG Asesmen RBG / sumber entropi (SP 800-90A/B, ISO/IEC 18031) | Implementasi & sistem | Integrasi | penuh | 2 | C-RNG | Skor 2.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 0.02 detik ≤ anggaran 24 jam |
| M-AVAL Uji avalanche & Strict Avalanche Criterion (fungsi penuh) | Kekuatan algoritma | Unit | penuh | 1.5 | C-ARX, C-DIFF | Skor 1.5 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 0.18 detik ≤ anggaran 24 jam |
| M-BOOL Analisis fungsi Boolean komponen nonlinear (NL, CI, derajat) | Kekuatan algoritma | Unit | penuh | 1.5 | C-ARX | Skor 1.5 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-DIFFUSION Analisis difusi (branch number/MDS, ronde menuju difusi penuh, avalanche per ronde) | Kekuatan algoritma | Unit | penuh | 1.5 | C-ARX, C-DIFF | Skor 1.5 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 1.16 detik ≤ anggaran 24 jam |
| M-KEYSIZE Evaluasi ukuran kunci & tingkat keamanan (SP 800-57 / 131A) | Kekuatan algoritma | Sistem | penuh | 1.5 | C-KEY | Wajib (kesesuaian standar / baseline keamanan). Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-SP80022 Uji keacakan statistik NIST SP 800-22 (15 uji) | Kekuatan algoritma | Unit | penuh | 1.5 | C-DIFF, C-KS-OUT | Skor 1.5 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 1.74 detik ≤ anggaran 24 jam |
| M-KAT Known Answer Test (KAT) terhadap vektor resmi | Kesesuaian | Unit | penuh | 1 | C-CONF, C-SELFTEST | Wajib (kesesuaian standar / baseline keamanan). Estimasi 0.00 detik ≤ anggaran 24 jam |
| M-LC Kompleksitas linear (Berlekamp–Massey) & periode keystream | Kekuatan algoritma | Unit | penuh | 1 | C-ARX, C-KS-OUT | Skor 1.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 0.04 detik ≤ anggaran 24 jam |
| M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | penuh | 1 | C-CONF, C-SELFTEST | Skor 1.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 0 detik (analitis) ≤ anggaran 24 jam |

**Metode yang ditolak:**

| Metode | Kelayakan | Skor | Alasan |
|---|---|---|---|
| M-ARX-PNB Analisis diferensial/PNB & differential-linear ARX (ronde tereduksi) | 0.6 | 0.9 | Ditolak: skor 0.9 < 1.0 |
| M-BRUTE Pencarian kunci menyeluruh (exhaustive key search) | 0.6 | 0.9 | Ditolak: skor 0.9 < 1.0 |
| M-TVLA Uji kebocoran daya/EM (TVLA, ISO/IEC 17825) | 0 | 0 | Ditolak: Alat tidak tersedia: oscilloscope, chipwhisperer |
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
| estimated_time | 9.32 detik |

**M-NONCE**

| Parameter | Nilai |
|---|---|
| signatures |  |
| messages | 65536 |
| checks | duplikasi nonce/IV = 0, counter tidak wrap (tolak > 2^32 blok) |
| alpha | 0.01 |
| variant | penuh |
| estimated_time | 0.04 detik |

**M-TIMING**

| Parameter | Nilai |
|---|---|
| method | dudect fixed-vs-random (Welch t) |
| measurements | 1000000 |
| threshold_abs_t | 4.5 |
| classes | kunci tetap vs acak |
| timer | rdtsc / perf_counter_ns, core diisolasi (taskset), turbo dimatikan |
| variant | penuh |
| estimated_time | 9.32 detik |

**M-ZEROIZE**

| Parameter | Nilai |
|---|---|
| procedure | core dump / gdb setelah free & pemanggilan API destroy |
| search | pola kunci uji (known key) |
| pass_criterion | 0 kemunculan |
| variant | penuh |
| estimated_time | 0 detik (analitis) |

**M-RNG**

| Parameter | Nilai |
|---|---|
| entropy_samples_bits | 1000000 |
| sp800_90b | IID & non-IID track, restart test 1000×1000 |
| sp800_22 | subset sesuai M-SP80022 |
| drbg | CAVP DRBG KAT (HMAC_DRBG) |
| variant | penuh |
| estimated_time | 0.02 detik |

**M-AVAL**

| Parameter | Nilai |
|---|---|
| samples | 10000 |
| flip | 1 bit plaintext/pesan, 1 bit kunci |
| target_mean | 0.5 |
| tolerance_mean | 0.01 |
| per_bit_tolerance | 0.05 |
| sac_matrix | n_in × n_out probabilitas perubahan |
| variant | penuh |
| estimated_time | 0.18 detik |

**M-BOOL**

| Parameter | Nilai |
|---|---|
| functions | carry (mayoritas 3-bit), penjumlahan mod 2^n (n = 8, 16) |
| properties | NL, derajat, CI, balancedness, P[add = xor] |
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
| estimated_time | 1.16 detik |

**M-KEYSIZE**

| Parameter | Nilai |
|---|---|
| key_parameters | key_bits=256; nonce_bits=96; counter_bits=32; output_bits_per_op=512 |
| security_bits | 256 |
| min_security_bits | 112 |
| horizon | 2030 (≥128 bit untuk perlindungan setelah 2030) |
| reference | SP 800-57 Part 1 Rev.5 Tabel 2 & 4; SP 800-131A Rev.2 |
| variant | penuh |
| estimated_time | 0 detik (analitis) |

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
| generation | keystream (kunci & nonce acak per barisan) |
| variant | penuh |
| estimated_time | 1.74 detik |

**M-KAT**

| Parameter | Nilai |
|---|---|
| vector_sources | RFC 8439 Appendix A.1 Test Vector #1, RFC 8439 §2.3.2 (block function), RFC 8439 §2.4.2 (encryption, 'sunscreen') |
| vector_count | 3 |
| additional_sources | NIST CAVP/ACVP response files untuk implementasi produk |
| pass_criterion | 100% vektor cocok (0 selisih bit) |
| reference_result | 3/3 (LULUS) pada core/ |
| variant | penuh |
| estimated_time | 0.00 detik |

**M-LC**

| Parameter | Nilai |
|---|---|
| sample_bits_N | 10000 |
| blocks | 10 barisan × 10^4 bit (+ SP 800-22 Linear Complexity M = 500) |
| pass_criterion | \|L − N/2\| ≤ 3 |
| variant | penuh |
| estimated_time | 0.04 detik |

**M-SELFTEST**

| Parameter | Nilai |
|---|---|
| tests | POST KAT tiap algoritma, pairwise consistency (pkc/dss), continuous RNG test, error state injection |
| variant | penuh |
| estimated_time | 0 detik (analitis) |

## 7. Matriks Keterlacakan

| ID | Persyaratan | Objek | Metode uji | Rujukan | Kriteria lulus |
|---|---|---|---|---|---|
| K-01 | Perubahan 1 bit masukan/kunci mengubah ≈ 50% bit keluaran | C-ARX Quarter-round ARX (penjumlahan mod 2^32); C-DIFF Difusi antar ronde (column/diagonal round) | M-AVAL (penuh) | ISO 18367 | rerata 0,5 ± 0,01; tiap bit 0,5 ± 0,05 |
| K-02 | Fungsi nonlinear memiliki NL & derajat sesuai desain | C-ARX Quarter-round ARX (penjumlahan mod 2^32) | M-BOOL (penuh) | ISO 18033-4 | nilai = acuan desain |
| K-03 | Lapisan difusi mencapai difusi penuh dengan margin ronde memadai | C-ARX Quarter-round ARX (penjumlahan mod 2^32); C-DIFF Difusi antar ronde (column/diagonal round) | M-DIFFUSION (penuh) | ISO 18033-3, ISO 18033-4, FIPS 202 | branch number optimal; avalanche ≈ 0,5 sebelum ≤ 1/2 jumlah ronde |
| K-04 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | C-KEY Ukuran kunci | M-KEYSIZE (penuh) | SP 800-57, SP 800-131A | security_bits ≥ 112 |
| K-05 | Kompleksitas linear keystream mendekati N/2 | C-ARX Quarter-round ARX (penjumlahan mod 2^32); C-KS-OUT Keluaran keystream | M-LC (penuh) | ISO 18033-4, SP 800-22 | \|L − N/2\| ≤ 3 untuk N sampel |
| K-06 | Nonce tidak pernah berulang dan tidak bias | C-STATE Inisialisasi state: konstanta, kunci, counter, nonce | M-NONCE (penuh) | FIPS 186-5, RFC 6979, SP 800-90A, SP 800-38A, RFC 8439 | 0 duplikasi; χ² MSB p-value ≥ 0,01 (≥ 4096 sampel) |
| K-07 | RBG yang dipakai disetujui (SP 800-90A) dengan entropi memadai | C-RNG Sumber acak (RBG) | M-RNG (penuh) | SP 800-90A, SP 800-90B, ISO 18031, SP 800-22 | min-entropy ≥ nilai klaim (SP 800-90B); SP 800-22 lulus |
| K-08 | Keluaran (keystream/CTR/digest berantai) tak terbedakan dari acak | C-DIFF Difusi antar ronde (column/diagonal round); C-KS-OUT Keluaran keystream | M-SP80022 (penuh) | SP 800-22 | proporsi lulus ≥ ambang SP 800-22 & P-value_T ≥ 0,0001 tiap uji |
| I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | C-API Antarmuka API & validasi masukan; C-STATE Inisialisasi state: konstanta, kunci, counter, nonce | M-FUZZ (penuh) | ISO 29119, ISO 18045 | 0 crash; 100% masukan invalid ditolak dengan galat terdefinisi |
| I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | C-CONF Kesesuaian implementasi keseluruhan; C-SELFTEST Self-test & error state modul | M-KAT (penuh) | ISO 18367, ISO 24759 | 100% vektor cocok |
| I-03 | Power-on self-test (KAT) & conditional test (pairwise) berjalan; error state memblokir layanan | C-CONF Kesesuaian implementasi keseluruhan; C-SELFTEST Self-test & error state modul | M-SELFTEST (penuh) | ISO 19790, ISO 24759 | semua self-test terpicu & error state tervalidasi |
| I-04 | Waktu eksekusi tidak bergantung pada data rahasia | C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | M-TIMING (penuh) | ISO 17825, ISO 20085 | \|t\| < 4,5 pada ≥ 10^6 pengukuran |
| I-05 | Kunci/CSP dihapus dari memori setelah dipakai | C-MEM Pengelolaan material kunci di memori | M-ZEROIZE (penuh) | ISO 19790, ISO 24759 | 0 salinan kunci pada dump memori |

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

KAT rinci (ChaCha20):

| Vektor | Sumber | Hasil |
|---|---|---|
| RFC8439-2.3.2 | RFC 8439 §2.3.2 (block function) | LULUS |
| RFC8439-2.4.2 | RFC 8439 §2.4.2 (encryption, 'sunscreen') | LULUS |
| RFC8439-A.1-1 | RFC 8439 Appendix A.1 Test Vector #1 | LULUS |
