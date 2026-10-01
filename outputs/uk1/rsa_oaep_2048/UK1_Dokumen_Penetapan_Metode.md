# Dokumen Penetapan Metode & Parameter Pengujian — RSA-OAEP-2048

**Cryptan.ID Test Suite** v1.0.0 · Modul **UK-1** · Unit J.61KRP00.012.1 — *Menentukan Metode Pengujian yang akan Dilakukan* · SKKNI 2023-004 (Cryptographic Analyst)

Dibangkitkan: 2026-10-01T09:17:08+07:00 · mode: full · objek: **Cryptan.ID SecureLib** (1.0.0 (hipotetis))

> Seluruh data produk bersifat ILUSTRATIF. Nilai bertanda HASIL UJI LANGSUNG dihitung oleh kode; HASIL LITERATUR dikutip dari rujukan; PERLU_VERIFIKASI wajib dicek ke sumber primer.

## Ringkasan

- Kelas primitif: **Kriptografi kunci publik (PKC)**, struktur Integer factorization (IFC)
- Tingkat akses penguji: **grey_box**
- KAT implementasi referensi: **12/12 LULUS**
- Komponen berpotensi lemah: **—**; perlu perhatian: C-MOD, C-MODEXP, C-API, C-MEM, C-PLAT
- Metode terpilih: **12** · ditolak: 4 · upaya 59 / 240 jam-orang (SESUAI)

## 1. Profil Produk & Ruang Lingkup (KUK 1.1)

| Atribut | Nilai |
|---|---|
| Produk | Cryptan.ID SecureLib 1.0.0 (hipotetis) |
| Deskripsi | Library kriptografi perangkat lunak (shared object) untuk Linux x86-64 |
| Algoritma | RSA-OAEP 2048-bit, SHA-256/MGF1-SHA-256 (RFC 8017, SP 800-56B) |
| Kelas primitif | Kriptografi kunci publik (PKC) |
| Struktur | Integer factorization (IFC) |
| Mode | — |
| Parameter | modulus_bits=2048; public_exponent=65537; hash=sha256; mgf=MGF1-SHA256; crt=True |
| Platform | Shared library (.so) di Linux x86-64; CPU multi-core dengan cache L3 bersama |
| Bahasa / binding | C / Python |
| Antarmuka | C API (libsecure.so), Python binding (ctypes) |
| RBG | getrandom(2) → HMAC_DRBG (SP 800-90A) |
| Catatan implementasi | keygen=prima probabilistik (FIPS 186-5 A.1.3), Miller–Rabin; sample_keys=3 |
| Tingkat akses | grey_box — Penguji memperoleh spesifikasi algoritma & dokumen desain tingkat tinggi, biner library + header API, dan lingkungan uji dengan kunci uji. Kode sumber TIDAK tersedia. |
| Kelengkapan profil | LENGKAP |
| Daftar algoritma diuji (algo_catalog) | 33 kombinasi (block_cipher=6; stream_cipher=2; hash=7; mac=4; pkc_kem=7; signature=6; drbg=1); 6 peringatan tinggi; RSA-OAEP-2048 termasuk daftar (strength 112, status acceptable) — `algorithms_under_test.yaml` |

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
| FIPS-186-5 | NIST | Digital Signature Standard (DSS) | 2023 | Spesifikasi algoritma/skema |
| ISO-18033-2 | ISO/IEC | Encryption algorithms — Part 2: Asymmetric ciphers (RSAES/OAEP) | 2006 | Spesifikasi algoritma/skema |
| RFC-8017 | IETF | PKCS #1: RSA Cryptography Specifications Version 2.2 *(Di luar daftar materi; spesifikasi OAEP)* | 2016 | Spesifikasi algoritma/skema |
| SP-800-56B | NIST | Pair-Wise Key-Establishment Using Integer Factorization Cryptography (Rev. 2) | 2019 | Spesifikasi algoritma/skema |
| ISO-18367 | ISO/IEC | Cryptographic algorithms and security mechanisms conformance testing | 2016 | Pengujian kesesuaian |
| ISO-18032 | ISO/IEC | Prime number generation | 2020 | Pengujian kekuatan / kriteria keamanan |
| ISO-17825 | ISO/IEC | Testing methods for the mitigation of non-invasive attack classes against cryptographic modules `PERLU_VERIFIKASI` | 2024 | Pengujian implementasi & modul |
| ISO-19790 | ISO/IEC | Security requirements for cryptographic modules | 2012 | Pengujian implementasi & modul |
| ISO-20085 | ISO/IEC | Test tool requirements and test tool calibration methods for use in testing non-invasive attack mitigation techniques | 2019 | Pengujian implementasi & modul |
| ISO-24759 | ISO/IEC | Test requirements for cryptographic modules | 2017 | Pengujian implementasi & modul |
| SP-800-131A | NIST | Transitioning the Use of Cryptographic Algorithms and Key Lengths (Rev. 2) | 2019 | Ukuran kunci & manajemen kunci |
| SP-800-57 | NIST | Recommendation for Key Management, Part 1: General (Rev. 5) | 2020 | Ukuran kunci & manajemen kunci |
| ISO-18031 | ISO/IEC | Random bit generation | 2011 | Pembangkitan bilangan acak |
| SP-800-90A | NIST | Recommendation for Random Number Generation Using Deterministic RBGs (Rev. 1) | 2015 | Pembangkitan bilangan acak |
| SP-800-90B | NIST | Recommendation for the Entropy Sources Used for Random Bit Generation | 2018 | Pembangkitan bilangan acak |
| FIPS-203 | NIST | Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) | 2024 | Evaluasi keamanan / migrasi |
| ISO-15408 | ISO/IEC | Evaluation criteria for IT security (Common Criteria) | 2022 | Evaluasi keamanan / migrasi |
| ISO-18045 | ISO/IEC | Methodology for IT security evaluation (CEM) | 2022 | Evaluasi keamanan / migrasi |
| ISO-29119 | ISO/IEC/IEEE | Software and systems engineering — Software testing | 2022 | Proses & dokumentasi pengujian |

### 2.2 Tren Serangan Relevan (KUK 1.2) — HASIL LITERATUR

16 serangan relevan setelah filter profil; praktis: 14; perlu verifikasi: 3.

| ID | Kategori | Serangan | Model | Kompleksitas (log2 T/D/M) | Ronde | Status | Rujukan |
|---|---|---|---|---|---|---|---|
| A-P-03 | desain | Kunci lemah — prima berdekatan (Fermat), p−1 smooth (Pollard), faktor bersama (batch-GCD), ROCA | n/a | 20/0/— | n/a | praktis (bila keygen cacat) | Heninger, Durumeric, Wustrow, Halderman — Mining Your Ps and Qs, USENIX Security 2012; Nemec et al. — The Return of Coppersmith's Attack (ROCA), CCS 2017 |
| A-P-04 | desain | Eksponen privat kecil (Wiener / Boneh–Durfee) | n/a | 20/0/— | d < N^0.25/3 (Wiener); d < N^0.292 (Boneh–Durfee) | praktis (bila kondisi terpenuhi) | Wiener — Cryptanalysis of Short RSA Secret Exponents, IEEE TIT 1990; Boneh & Durfee, EUROCRYPT 1999 |
| A-P-01 | desain | Faktorisasi GNFS | n/a | 112/0/— | n/a | teoretis (2048-bit); rekor RSA-250 (829-bit) 2020 | SP 800-57 Part 1 Rev.5 Tabel 2 (RSA-2048 ≈ 112-bit); Boudot et al. — Comparing the difficulty of factorization and discrete logarithm: a 240-digit experiment, CRYPTO 2020 |
| A-P-02 | desain | Algoritma Shor (komputer kuantum) | n/a | —/—/— | n/a | teoretis (ancaman masa depan / harvest-now-decrypt-later) | Shor, FOCS 1994; FIPS 203/204/205 (migrasi PQC) |
| A-P-05 | protokol | Eksponen publik kecil tanpa padding (Håstad / Coppersmith) | CPA | 10/2/— | n/a | praktis pada textbook RSA; dimitigasi OAEP | Håstad, SIAM J. Comput. 1988; Coppersmith, J. Cryptology 1997 |
| A-P-06 | protokol | Manger's attack (oracle galat dekripsi OAEP) | CCA | 11/11/0 | ≈ log2(n) query | praktis (bila galat/timing dapat dibedakan) `PERLU_VERIFIKASI` | Manger — A Chosen Ciphertext Attack on RSA OAEP as Standardized in PKCS #1 v2.0, CRYPTO 2001 |
| A-P-07 | protokol | Bleichenbacher / ROBOT (fallback PKCS#1 v1.5) | CCA | 20/20/0 | n/a | praktis (bila masih mendukung v1.5) `PERLU_VERIFIKASI` | Bleichenbacher, CRYPTO 1998; Böck, Somorovsky, Young — ROBOT, USENIX Security 2018 |
| A-D-04 | protokol | Invalid-curve / kunci publik tidak tervalidasi | CCA | —/—/— | n/a | praktis (terutama ECDH) | Biehl, Meyer, Müller — Differential Fault Attacks on Elliptic Curve Cryptosystems, CRYPTO 2000; Jager, Schwenk, Somorovsky — Practical Invalid Curve Attacks on TLS-ECDH, ESORICS 2015 |
| A-L-01 | bahasa | Perbandingan tidak constant-time (memcmp pada tag/MAC/padding) | side-channel | —/—/— | n/a | praktis `PERLU_VERIFIKASI` | Lawson — Timing attack in Google Keyczar, 2009; ISO/IEC 17825 |
| A-L-02 | bahasa | Buffer over-read/overflow (memory safety) | n/a | 0/0/0 | n/a | praktis | NVD CVE-2014-0160 (Heartbleed, OpenSSL) |
| A-L-03 | bahasa | Material kunci tidak di-zeroize (sisa di memori / cold boot) | n/a | —/—/— | n/a | praktis | Halderman et al. — Lest We Remember: Cold Boot Attacks, USENIX Security 2008; ISO/IEC 19790 §7.9 (zeroisation) |
| A-P-08 | platform | Timing attack pada modular exponentiation | side-channel | —/—/— | n/a | praktis | Kocher, CRYPTO 1996; Brumley & Boneh — Remote Timing Attacks are Practical, USENIX Security 2003 |
| A-P-09 | platform | Cache side-channel (Flush+Reload) pada RSA | side-channel | —/—/— | n/a | praktis | Yarom & Falkner — FLUSH+RELOAD, USENIX Security 2014 |
| A-P-11 | platform | RNG lemah saat pembangkitan kunci | n/a | 15/0/— | n/a | praktis | CVE-2008-0166 (Debian OpenSSL, ruang kunci 2^15); Heninger et al., USENIX Security 2012 |
| A-X-01 | platform | Transient execution (Spectre) | side-channel | —/—/— | n/a | praktis | Kocher et al. — Spectre Attacks, IEEE S&P 2019 |
| A-X-02 | platform | Frequency-scaling side-channel (Hertzbleed) | side-channel | —/—/— | n/a | praktis (remote timing dari variasi daya) | Wang et al. — Hertzbleed, USENIX Security 2022 |

## 3. Hasil Telaah Komponen (KUK 2.1)

| ID | Komponen | Lapis | Status | Tag kelemahan |
|---|---|---|---|---|
| C-MOD | Modulus n & ukuran kunci | algoritma | PERHATIAN | key_size |
| C-PRIME | Pembangkitan prima p, q | algoritma | OK | prime_gen, rng |
| C-EXP-E | Eksponen publik e | algoritma | OK | small_e |
| C-EXP-D | Eksponen privat d | algoritma | OK | private_exponent |
| C-OAEP | Encoding/decoding OAEP | algoritma | OK | oaep_oracle |
| C-HASH | Hash & MGF1 | algoritma | OK | hash_strength |
| C-MODEXP | Eksponensiasi modular (RSADP/CRT) | algoritma | PERHATIAN | bigint_timing, constant_time, fault |
| C-PKV | Validasi kunci publik | algoritma | OK | pubkey_validation |
| C-API | Antarmuka API & validasi masukan | implementasi | PERHATIAN | memory_safety, pubkey_validation |
| C-MEM | Pengelolaan material kunci di memori | implementasi | PERHATIAN | key_zeroization |
| C-SELFTEST | Self-test & error state modul | implementasi | OK | self_test, conformance |
| C-RNG | Sumber acak (RBG) | implementasi | OK | rng |
| C-PLAT | Platform eksekusi (CPU x86-64 bercache, speculative execution) | implementasi | PERHATIAN | speculative, constant_time |
| C-CONF | Kesesuaian implementasi keseluruhan | implementasi | OK | conformance |

### C-MOD — Modulus n & ukuran kunci [PERHATIAN]

Ketahanan terhadap faktorisasi (GNFS) & status SP 800-131A.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Tingkat keamanan IFC (SP 800-57 Tabel 2) | 112 bit | ≥ 112 bit | OK | HASIL UJI LANGSUNG |  |
| Status transisi SP 800-131A | acceptable | ≥ 128 bit untuk perlindungan melampaui 2030 | PERHATIAN | HASIL LITERATUR | 112-bit hanya disetujui hingga 2030 (SP 800-57 Tabel 4) |

### C-PRIME — Pembangkitan prima p, q [OK]

Kualitas prima: primalitas, jarak |p−q|, kehalusan p−1.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| p, q prima (Miller–Rabin 64 iterasi) | True | True | OK | HASIL UJI LANGSUNG |  |
| \|p − q\| > 2^(nlen/2 − 100) | min 2^1012.5682 | > 2^924 | OK | HASIL UJI LANGSUNG | Mitigasi faktorisasi Fermat |
| p, q ≥ √2·2^(nlen/2−1) | True | True | OK | HASIL UJI LANGSUNG |  |
| Bagian kasar p−1 setelah pembagian prima < 2^14 | min 1004 bit | ≥ 160 bit | OK | HASIL UJI LANGSUNG | Mitigasi Pollard p−1 |

### C-EXP-E — Eksponen publik e [OK]

Rentang e sesuai FIPS 186-5.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Eksponen publik e ∈ (2^16, 2^256), ganjil | 65537 | 65537 disarankan | OK | HASIL UJI LANGSUNG |  |

### C-EXP-D — Eksponen privat d [OK]

Ukuran d terhadap Wiener / Boneh–Durfee.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| d > 2^(nlen/2) (FIPS 186-5) | 2042 bit | > 1024 bit | OK | HASIL UJI LANGSUNG |  |
| d di atas batas Boneh–Durfee N^0,292 | 2042 bit | > 598 bit | OK | HASIL UJI LANGSUNG |  |

### C-OAEP — Encoding/decoding OAEP [OK]

Keseragaman galat dekripsi (Manger).

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Keseragaman pesan galat antar kelas kegagalan | seragam | satu jenis galat | OK | HASIL UJI LANGSUNG | Mitigasi Manger (A-P-06) — implementasi referensi |
| Beda waktu antar kelas galat (Welch \|t\| maks) | 1.31 | < 4,5 (indikatif, n kecil) | OK | HASIL UJI LANGSUNG | Pengukuran pada implementasi referensi; produk diuji di M-ORACLE |

### C-HASH — Hash & MGF1 [OK]

Kekuatan hash dalam OAEP.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Kekuatan hash OAEP (sha256) | 128 bit | ≥ 112 bit | OK | HASIL UJI LANGSUNG |  |

### C-MODEXP — Eksponensiasi modular (RSADP/CRT) [PERHATIAN]

Kebocoran timing/cache operasi kunci privat.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Eksponensiasi modular constant-time pada produk | tidak diketahui (grey box) | constant-time + blinding | PERHATIAN | KLAIM PROFIL | A-P-08/A-P-09; CRT → juga relevan fault (A-P-10) bila platform embedded |

### C-PKV — Validasi kunci publik [OK]

Penolakan modulus/eksponen tidak valid.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Kunci valid diterima | True | True | OK | HASIL UJI LANGSUNG |  |
| Kunci tidak valid ditolak (4 kasus) | 4/4 | 4/4 | OK | HASIL UJI LANGSUNG |  |

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
| KAT implementasi referensi (core/) | 12/12 LULUS | 100% cocok | OK | HASIL UJI LANGSUNG | Vektor: PKCS #1 v2.1 oaep-vect.txt |

## 4. Matriks Komponen–Kelemahan–Metode (KUK 2.2)

Tiga lapis pengujian × level uji (metode yang dipetakan):

| Lapis \ Level | Unit | Integrasi | Sistem |
|---|---|---|---|
| Kesesuaian | M-KAT, M-PKV, M-PRIME | — | — |
| Kekuatan algoritma | M-RSAWEAK | — | M-FACT, M-KEYSIZE |
| Implementasi & sistem | M-CODEREVIEW | M-FUZZ, M-ORACLE, M-RNG, M-TIMING | M-CACHE, M-FAULT, M-SELFTEST, M-ZEROIZE |

| Komponen | Status | Kelemahan | Serangan | Metode | Lapis | Level | Standar | Akses |
|---|---|---|---|---|---|---|---|---|
| C-API Antarmuka API & validasi masukan | PERHATIAN | Kunci publik/titik tidak divalidasi | A-D-04 | M-PKV Validasi kunci publik (positif & negatif) | Kesesuaian | Unit | SP-800-56B, SP-800-186, ISO-18033-2 | ✔ black |
| C-CONF Kesesuaian implementasi keseluruhan | OK | Keluaran implementasi tidak sesuai standar | — | M-KAT Known Answer Test (KAT) terhadap vektor resmi | Kesesuaian | Unit | ISO-18367, ISO-24759 | ✔ black |
| C-EXP-D Eksponen privat d | OK | Eksponen privat kecil | A-P-04 | M-PRIME Uji primalitas & validasi pembangkitan kunci (ISO/IEC 18032, FIPS 186-5 App. A/B) | Kesesuaian | Unit | ISO-18032, FIPS-186-5 | ✔ grey |
| C-EXP-E Eksponen publik e | OK | Eksponen publik kecil tanpa padding | A-P-05 | M-PRIME Uji primalitas & validasi pembangkitan kunci (ISO/IEC 18032, FIPS 186-5 App. A/B) | Kesesuaian | Unit | ISO-18032, FIPS-186-5 | ✔ grey |
| C-PKV Validasi kunci publik | OK | Kunci publik/titik tidak divalidasi | A-D-04 | M-PKV Validasi kunci publik (positif & negatif) | Kesesuaian | Unit | SP-800-56B, SP-800-186, ISO-18033-2 | ✔ black |
| C-PRIME Pembangkitan prima p, q | OK | Prima lemah (berdekatan, p−1 smooth, faktor bersama) | A-P-03 | M-PRIME Uji primalitas & validasi pembangkitan kunci (ISO/IEC 18032, FIPS 186-5 App. A/B) | Kesesuaian | Unit | ISO-18032, FIPS-186-5 | ✔ grey |
| C-SELFTEST Self-test & error state modul | OK | Keluaran implementasi tidak sesuai standar | — | M-KAT Known Answer Test (KAT) terhadap vektor resmi | Kesesuaian | Unit | ISO-18367, ISO-24759 | ✔ black |
| C-EXP-D Eksponen privat d | OK | Eksponen privat kecil | A-P-04 | M-RSAWEAK Baterai kunci lemah RSA (Fermat, Pollard p−1, batch-GCD, Wiener) | Kekuatan algoritma | Unit | ISO-18032, FIPS-186-5 | ✔ black |
| C-PRIME Pembangkitan prima p, q | OK | Prima lemah (berdekatan, p−1 smooth, faktor bersama) | A-P-03 | M-RSAWEAK Baterai kunci lemah RSA (Fermat, Pollard p−1, batch-GCD, Wiener) | Kekuatan algoritma | Unit | ISO-18032, FIPS-186-5 | ✔ black |
| C-PRIME Pembangkitan prima p, q | OK | RBG lemah / entropi rendah | A-P-03, A-P-11 | M-RSAWEAK Baterai kunci lemah RSA (Fermat, Pollard p−1, batch-GCD, Wiener) | Kekuatan algoritma | Unit | ISO-18032, FIPS-186-5 | ✔ black |
| C-RNG Sumber acak (RBG) | OK | RBG lemah / entropi rendah | A-P-03, A-P-11 | M-RSAWEAK Baterai kunci lemah RSA (Fermat, Pollard p−1, batch-GCD, Wiener) | Kekuatan algoritma | Unit | ISO-18032, FIPS-186-5 | ✔ black |
| C-HASH Hash & MGF1 | OK | Kekuatan hash di bawah tingkat keamanan skema | — | M-KEYSIZE Evaluasi ukuran kunci & tingkat keamanan (SP 800-57 / 131A) | Kekuatan algoritma | Sistem | SP-800-57, SP-800-131A | ✔ black |
| C-MOD Modulus n & ukuran kunci | PERHATIAN | Ruang kunci / tingkat keamanan tidak memadai | A-P-01, A-P-02 | M-FACT Percobaan faktorisasi modulus (GNFS) | Kekuatan algoritma | Sistem | SP-800-57 | ✔ black |
| C-MOD Modulus n & ukuran kunci | PERHATIAN | Ruang kunci / tingkat keamanan tidak memadai | A-P-01, A-P-02 | M-KEYSIZE Evaluasi ukuran kunci & tingkat keamanan (SP 800-57 / 131A) | Kekuatan algoritma | Sistem | SP-800-57, SP-800-131A | ✔ black |
| C-API Antarmuka API & validasi masukan | PERHATIAN | Buffer overflow / masukan malformed | A-L-02 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-MEM Pengelolaan material kunci di memori | PERHATIAN | Material kunci tidak dihapus dari memori | A-L-03 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-MODEXP Eksponensiasi modular (RSADP/CRT) | PERHATIAN | Timing/cache pada aritmetika bilangan besar | A-P-08, A-P-09 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-MODEXP Eksponensiasi modular (RSADP/CRT) | PERHATIAN | Eksekusi tidak constant-time | A-L-01, A-P-08, A-P-09, A-X-01, A-X-02 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | PERHATIAN | Eksekusi tidak constant-time | A-L-01, A-P-08, A-P-09, A-X-01, A-X-02 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-API Antarmuka API & validasi masukan | PERHATIAN | Buffer overflow / masukan malformed | A-L-02 | M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | ISO-29119, ISO-18045 | ✔ black |
| C-API Antarmuka API & validasi masukan | PERHATIAN | Kunci publik/titik tidak divalidasi | A-D-04 | M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | ISO-29119, ISO-18045 | ✔ black |
| C-MODEXP Eksponensiasi modular (RSADP/CRT) | PERHATIAN | Eksekusi tidak constant-time | A-L-01, A-P-08, A-P-09, A-X-01, A-X-02 | M-ORACLE Uji oracle galat dekripsi OAEP (Manger) — keseragaman galat & timing | Implementasi & sistem | Integrasi | SP-800-56B, RFC-8017, ISO-17825 | ✔ grey |
| C-MODEXP Eksponensiasi modular (RSADP/CRT) | PERHATIAN | Timing/cache pada aritmetika bilangan besar | A-P-08, A-P-09 | M-TIMING Analisis timing leakage (dudect / Welch t-test, fixed-vs-random) | Implementasi & sistem | Integrasi | ISO-17825, ISO-20085 | ✔ grey |
| C-MODEXP Eksponensiasi modular (RSADP/CRT) | PERHATIAN | Eksekusi tidak constant-time | A-L-01, A-P-08, A-P-09, A-X-01, A-X-02 | M-TIMING Analisis timing leakage (dudect / Welch t-test, fixed-vs-random) | Implementasi & sistem | Integrasi | ISO-17825, ISO-20085 | ✔ grey |
| C-OAEP Encoding/decoding OAEP | OK | Oracle galat/timing dekripsi OAEP | A-P-06, A-P-07 | M-ORACLE Uji oracle galat dekripsi OAEP (Manger) — keseragaman galat & timing | Implementasi & sistem | Integrasi | SP-800-56B, RFC-8017, ISO-17825 | ✔ grey |
| C-PKV Validasi kunci publik | OK | Kunci publik/titik tidak divalidasi | A-D-04 | M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | ISO-29119, ISO-18045 | ✔ black |
| C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | PERHATIAN | Eksekusi tidak constant-time | A-L-01, A-P-08, A-P-09, A-X-01, A-X-02 | M-ORACLE Uji oracle galat dekripsi OAEP (Manger) — keseragaman galat & timing | Implementasi & sistem | Integrasi | SP-800-56B, RFC-8017, ISO-17825 | ✔ grey |
| C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | PERHATIAN | Eksekusi tidak constant-time | A-L-01, A-P-08, A-P-09, A-X-01, A-X-02 | M-TIMING Analisis timing leakage (dudect / Welch t-test, fixed-vs-random) | Implementasi & sistem | Integrasi | ISO-17825, ISO-20085 | ✔ grey |
| C-PRIME Pembangkitan prima p, q | OK | RBG lemah / entropi rendah | A-P-03, A-P-11 | M-RNG Asesmen RBG / sumber entropi (SP 800-90A/B, ISO/IEC 18031) | Implementasi & sistem | Integrasi | SP-800-90A, SP-800-90B, ISO-18031, SP-800-22 | ✔ grey |
| C-RNG Sumber acak (RBG) | OK | RBG lemah / entropi rendah | A-P-03, A-P-11 | M-RNG Asesmen RBG / sumber entropi (SP 800-90A/B, ISO/IEC 18031) | Implementasi & sistem | Integrasi | SP-800-90A, SP-800-90B, ISO-18031, SP-800-22 | ✔ grey |
| C-CONF Kesesuaian implementasi keseluruhan | OK | Keluaran implementasi tidak sesuai standar | — | M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ black |
| C-MEM Pengelolaan material kunci di memori | PERHATIAN | Material kunci tidak dihapus dari memori | A-L-03 | M-ZEROIZE Uji zeroization material kunci (memory dump pasca-operasi) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ grey |
| C-MODEXP Eksponensiasi modular (RSADP/CRT) | PERHATIAN | Timing/cache pada aritmetika bilangan besar | A-P-08, A-P-09 | M-CACHE Analisis cache side-channel (Flush+Reload / Prime+Probe) | Implementasi & sistem | Sistem | ISO-17825 | ✔ grey |
| C-MODEXP Eksponensiasi modular (RSADP/CRT) | PERHATIAN | Kerentanan injeksi kesalahan | — | M-FAULT Uji injeksi kesalahan (clock/voltage glitch, laser) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✘ white |
| C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | PERHATIAN | Kebocoran eksekusi spekulatif | A-X-01 | M-CACHE Analisis cache side-channel (Flush+Reload / Prime+Probe) | Implementasi & sistem | Sistem | ISO-17825 | ✔ grey |
| C-SELFTEST Self-test & error state modul | OK | Self-test / error state tidak berfungsi | — | M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ black |
| C-SELFTEST Self-test & error state modul | OK | Keluaran implementasi tidak sesuai standar | — | M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ black |

## 5. Estimasi Sumber Daya & Kelayakan (KUK 2.3)

### 5.1 Benchmark mesin lab — HASIL UJI LANGSUNG

| Operasi | ops/detik |
|---|---|
| public_op | 4,102.1 |
| private_op | 30.9 |
| primary | 4,102.1 |

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
| M-KEYSIZE | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-PRIME | private_op | 8 | 1.04 detik | 2^8.0 operasi/sampel | ≤ 2^10 B | — | LAYAK | Estimasi 1.04 detik ≤ anggaran 24 jam |
| M-PKV | primary | 8 | 0.01 detik | 2^8.0 operasi/sampel | ≤ 2^10 B | — | LAYAK | Estimasi 0.01 detik ≤ anggaran 24 jam |
| M-RSAWEAK | public_op | 22 | 2.1 menit | 2^22.0 operasi/sampel | ≤ 2^17 B | — | LAYAK | Estimasi 2.1 menit ≤ anggaran 24 jam |
| M-FACT | public_op | 112 | 2^72.1 tahun | 2^112.0 operasi/sampel | ≤ 2^40 B | Faktorisasi modulus mainan 64–96 bit (Pollard rho/ECM) — validasi estimasi — 34.1 menit | LAYAK VERSI TEREDUKSI | Alat versi penuh tidak tersedia (cado-nfs); versi tereduksi 34.1 menit |
| M-ORACLE | private_op | 13 | 33.16 detik | 2^13.0 operasi/sampel | ≤ 2^12 B | — | LAYAK | Estimasi 33.16 detik ≤ anggaran 24 jam |
| M-TIMING | primary | 20 | 31.95 detik | 2^20.0 operasi/sampel | ≤ 2^16 B | — | LAYAK | Estimasi 31.95 detik ≤ anggaran 24 jam |
| M-CACHE | primary | 22 | 2.1 menit | 2^22.0 operasi/sampel | ≤ 2^17 B | — | TIDAK LAYAK | Alat tidak tersedia: mastik |
| M-TVLA | primary | 17 | 3.99 detik | 2^17.0 operasi/sampel | ≤ 2^14 B | — | TIDAK LAYAK | Alat tidak tersedia: oscilloscope, chipwhisperer |
| M-FAULT | primary | 16 | 2.00 detik | 2^16.0 operasi/sampel | ≤ 2^14 B | — | TIDAK LAYAK | Alat tidak tersedia: glitcher |
| M-CODEREVIEW | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-FUZZ | primary | 20 | 31.95 detik | 2^20.0 operasi/sampel | ≤ 2^16 B | — | LAYAK | Estimasi 31.95 detik ≤ anggaran 24 jam |
| M-ZEROIZE | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-SELFTEST | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-RNG | primary | 11.93 | 0.12 detik | 2^11.9 operasi/sampel | ≈ 0.1 MB | — | LAYAK | Estimasi 0.12 detik ≤ anggaran 24 jam |

## 6. Metode Terpilih & Parameter Pengujian (KUK 3.1, 3.2)

### 6.1 Penetapan metode

Rumus: skor = relevansi[keparahan 1–3 + tren serangan (+1 praktis | +0,5 teoretis), maks 3] × kelayakan(1 | 0,6 | 0) × akses(1 | 0); ambang ≥ 1.0.

| Metode | Lapis | Level | Varian | Skor | Target | Alasan |
|---|---|---|---|---|---|---|
| M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | penuh | 3 | C-API | Skor 3.0 ≥ 1.0: relevan terhadap C-API. Estimasi 31.95 detik ≤ anggaran 24 jam |
| M-ORACLE Uji oracle galat dekripsi OAEP (Manger) — keseragaman galat & timing | Implementasi & sistem | Integrasi | penuh | 3 | C-MODEXP, C-PLAT | Skor 3.0 ≥ 1.0: relevan terhadap C-MODEXP, C-PLAT. Estimasi 33.16 detik ≤ anggaran 24 jam |
| M-PKV Validasi kunci publik (positif & negatif) | Kesesuaian | Unit | penuh | 3 | C-API | Skor 3.0 ≥ 1.0: relevan terhadap C-API. Estimasi 0.01 detik ≤ anggaran 24 jam |
| M-TIMING Analisis timing leakage (dudect / Welch t-test, fixed-vs-random) | Implementasi & sistem | Integrasi | penuh | 3 | C-MODEXP, C-PLAT | Skor 3.0 ≥ 1.0: relevan terhadap C-MODEXP, C-PLAT. Estimasi 31.95 detik ≤ anggaran 24 jam |
| M-ZEROIZE Uji zeroization material kunci (memory dump pasca-operasi) | Implementasi & sistem | Sistem | penuh | 3 | C-MEM | Skor 3.0 ≥ 1.0: relevan terhadap C-MEM. Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-KEYSIZE Evaluasi ukuran kunci & tingkat keamanan (SP 800-57 / 131A) | Kekuatan algoritma | Sistem | penuh | 2.5 | C-MOD | Wajib (kesesuaian standar / baseline keamanan). Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-PRIME Uji primalitas & validasi pembangkitan kunci (ISO/IEC 18032, FIPS 186-5 App. A/B) | Kesesuaian | Unit | penuh | 2 | C-EXP-D, C-EXP-E, C-PRIME | Skor 2.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 1.04 detik ≤ anggaran 24 jam |
| M-RNG Asesmen RBG / sumber entropi (SP 800-90A/B, ISO/IEC 18031) | Implementasi & sistem | Integrasi | penuh | 2 | C-PRIME, C-RNG | Skor 2.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 0.12 detik ≤ anggaran 24 jam |
| M-RSAWEAK Baterai kunci lemah RSA (Fermat, Pollard p−1, batch-GCD, Wiener) | Kekuatan algoritma | Unit | penuh | 2 | C-EXP-D, C-PRIME, C-RNG | Skor 2.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 2.1 menit ≤ anggaran 24 jam |
| M-FACT Percobaan faktorisasi modulus (GNFS) | Kekuatan algoritma | Sistem | tereduksi | 1.5 | C-MOD | Skor 1.5 ≥ 1.0: relevan terhadap C-MOD. Alat versi penuh tidak tersedia (cado-nfs); versi tereduksi 34.1 menit |
| M-KAT Known Answer Test (KAT) terhadap vektor resmi | Kesesuaian | Unit | penuh | 1 | C-CONF, C-SELFTEST | Wajib (kesesuaian standar / baseline keamanan). Estimasi 0.00 detik ≤ anggaran 24 jam |
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
| estimated_time | 31.95 detik |

**M-ORACLE**

| Parameter | Nilai |
|---|---|
| error_classes | y ≠ 0, lHash salah, tanpa pemisah 0x01, panjang ciphertext salah, c ≥ n |
| measurements_per_class | 100000 |
| statistic | Welch t-test (fixed-vs-fixed antar kelas) |
| threshold_abs_t | 4.5 |
| pass_criterion | satu pesan/kode galat & \|t\| < 4,5 |
| variant | penuh |
| estimated_time | 33.16 detik |

**M-PKV**

| Parameter | Nilai |
|---|---|
| positive_cases | 10 |
| negative_cases | modulus genap, modulus prima, e = 1/3/genap, n < 2048 bit |
| pass_criterion | 100% negatif ditolak, 100% positif diterima |
| variant | penuh |
| estimated_time | 0.01 detik |

**M-TIMING**

| Parameter | Nilai |
|---|---|
| method | dudect fixed-vs-random (Welch t) |
| measurements | 1000000 |
| threshold_abs_t | 4.5 |
| classes | ciphertext tetap vs acak (RSADP) |
| timer | rdtsc / perf_counter_ns, core diisolasi (taskset), turbo dimatikan |
| variant | penuh |
| estimated_time | 31.95 detik |

**M-ZEROIZE**

| Parameter | Nilai |
|---|---|
| procedure | core dump / gdb setelah free & pemanggilan API destroy |
| search | pola kunci uji (known key) |
| pass_criterion | 0 kemunculan |
| variant | penuh |
| estimated_time | 0 detik (analitis) |

**M-KEYSIZE**

| Parameter | Nilai |
|---|---|
| key_parameters | modulus_bits=2048; public_exponent=65537 |
| security_bits | 112 |
| min_security_bits | 112 |
| horizon | 2030 (≥128 bit untuk perlindungan setelah 2030) |
| reference | SP 800-57 Part 1 Rev.5 Tabel 2 & 4; SP 800-131A Rev.2 |
| variant | penuh |
| estimated_time | 0 detik (analitis) |

**M-PRIME**

| Parameter | Nilai |
|---|---|
| sample_keys | 20 |
| miller_rabin_rounds | 64 |
| checks | p,q prima, \|p−q\| > 2^924, d > 2^1024, e ∈ (2^16, 2^256) ganjil, gcd(e, λ(n)) = 1, p,q ≥ √2·2^(n/2−1) |
| reference | FIPS 186-5 A.1.1/A.1.3, B.3; ISO/IEC 18032 |
| variant | penuh |
| estimated_time | 1.04 detik |

**M-RNG**

| Parameter | Nilai |
|---|---|
| entropy_samples_bits | 1000000 |
| sp800_90b | IID & non-IID track, restart test 1000×1000 |
| sp800_22 | subset sesuai M-SP80022 |
| drbg | CAVP DRBG KAT (HMAC_DRBG) |
| variant | penuh |
| estimated_time | 0.12 detik |

**M-RSAWEAK**

| Parameter | Nilai |
|---|---|
| sample_keys | 100 |
| tests | Fermat 2^20 iterasi; Pollard p−1 B1 = 10^6; batch-GCD seluruh sampel; Wiener pecahan berlanjut e/n; ROCA fingerprint uji diskrit log mod primorial |
| pass_criterion | 0 kunci terfaktorkan |
| variant | penuh |
| estimated_time | 2.1 menit |

**M-FACT**

| Parameter | Nilai |
|---|---|
| full | GNFS 2048-bit ≈ 2^112 (literatur) |
| reduced_modulus_bits | 64, 80, 96 |
| reduced_ops_log2 | 26 |
| method | Pollard rho / ECM (validasi skala) |
| variant | tereduksi |
| estimated_time | 34.1 menit |

**M-KAT**

| Parameter | Nilai |
|---|---|
| vector_sources | PKCS #1 v2.1 oaep-vect.txt (RSA Laboratories), via github.com/pyca/cryptography/vectors/.../pkcs-1v2-1d2-vec/oaep-vect.txt (kunci 1024-bit), PKCS #1 v2.1 oaep-vect.txt (RSA Laboratories), via github.com/pyca/cryptography/vectors/.../pkcs-1v2-1d2-vec/oaep-vect.txt (kunci 2048-bit) |
| vector_count | 12 |
| additional_sources | NIST CAVP/ACVP response files untuk implementasi produk |
| pass_criterion | 100% vektor cocok (0 selisih bit) |
| reference_result | 12/12 (LULUS) pada core/ |
| variant | penuh |
| estimated_time | 0.00 detik |

**M-SELFTEST**

| Parameter | Nilai |
|---|---|
| tests | POST KAT tiap algoritma, pairwise consistency (pkc/dss), continuous RNG test, error state injection |
| variant | penuh |
| estimated_time | 0 detik (analitis) |

## 7. Matriks Keterlacakan

| ID | Persyaratan | Objek | Metode uji | Rujukan | Kriteria lulus |
|---|---|---|---|---|---|
| K-01 | Modulus tidak terfaktorkan dengan sumber daya realistis | C-MOD Modulus n & ukuran kunci | M-FACT (tereduksi) | SP 800-57 | estimasi GNFS ≥ 2^112 |
| K-02 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | C-MOD Modulus n & ukuran kunci | M-KEYSIZE (penuh) | SP 800-57, SP 800-131A | security_bits ≥ 112 |
| K-03 | p, q prima kuat; \|p−q\| > 2^(nlen/2−100); d > 2^(nlen/2); e ∈ (2^16, 2^256) | C-EXP-D Eksponen privat d; C-EXP-E Eksponen publik e; C-PRIME Pembangkitan prima p, q | M-PRIME (penuh) | ISO 18032, FIPS 186-5 | semua kondisi FIPS 186-5 A.1.1/A.1.3 terpenuhi pada ≥ 20 sampel kunci |
| K-04 | RBG yang dipakai disetujui (SP 800-90A) dengan entropi memadai | C-PRIME Pembangkitan prima p, q; C-RNG Sumber acak (RBG) | M-RNG (penuh) | SP 800-90A, SP 800-90B, ISO 18031, SP 800-22 | min-entropy ≥ nilai klaim (SP 800-90B); SP 800-22 lulus |
| K-05 | Kunci produk tidak rentan terhadap serangan kunci lemah | C-EXP-D Eksponen privat d; C-PRIME Pembangkitan prima p, q; C-RNG Sumber acak (RBG) | M-RSAWEAK (penuh) | ISO 18032, FIPS 186-5 | 0 kunci terfaktorkan dari sampel ≥ 100 kunci |
| I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | C-API Antarmuka API & validasi masukan | M-FUZZ (penuh) | ISO 29119, ISO 18045 | 0 crash; 100% masukan invalid ditolak dengan galat terdefinisi |
| I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | C-CONF Kesesuaian implementasi keseluruhan; C-SELFTEST Self-test & error state modul | M-KAT (penuh) | ISO 18367, ISO 24759 | 100% vektor cocok |
| I-03 | Semua kegagalan dekripsi menghasilkan galat & waktu yang tak terbedakan | C-MODEXP Eksponensiasi modular (RSADP/CRT); C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | M-ORACLE (penuh) | SP 800-56B, RFC 8017, ISO 17825 | satu jenis galat; \|t\| Welch < 4,5 antar kelas galat |
| I-04 | Produk menolak kunci publik/titik tidak valid | C-API Antarmuka API & validasi masukan | M-PKV (penuh) | SP 800-56B, SP 800-186, ISO 18033-2 | 100% kasus negatif ditolak, 100% kasus positif diterima |
| I-05 | Power-on self-test (KAT) & conditional test (pairwise) berjalan; error state memblokir layanan | C-CONF Kesesuaian implementasi keseluruhan; C-SELFTEST Self-test & error state modul | M-SELFTEST (penuh) | ISO 19790, ISO 24759 | semua self-test terpicu & error state tervalidasi |
| I-06 | Waktu eksekusi tidak bergantung pada data rahasia | C-MODEXP Eksponensiasi modular (RSADP/CRT); C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | M-TIMING (penuh) | ISO 17825, ISO 20085 | \|t\| < 4,5 pada ≥ 10^6 pengukuran |
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

KAT rinci (RSA-OAEP-2048):

| Vektor | Sumber | Hasil |
|---|---|---|
| PKCS1-OAEP-1.1 | PKCS #1 v2.1 oaep-vect.txt (RSA Laboratories), via github.com/pyca/cryptography/vectors/.../pkcs-1v2-1d2-vec/oaep-vect.txt (kunci 1024-bit) | LULUS |
| PKCS1-OAEP-1.2 | PKCS #1 v2.1 oaep-vect.txt (RSA Laboratories), via github.com/pyca/cryptography/vectors/.../pkcs-1v2-1d2-vec/oaep-vect.txt (kunci 1024-bit) | LULUS |
| PKCS1-OAEP-1.3 | PKCS #1 v2.1 oaep-vect.txt (RSA Laboratories), via github.com/pyca/cryptography/vectors/.../pkcs-1v2-1d2-vec/oaep-vect.txt (kunci 1024-bit) | LULUS |
| PKCS1-OAEP-1.4 | PKCS #1 v2.1 oaep-vect.txt (RSA Laboratories), via github.com/pyca/cryptography/vectors/.../pkcs-1v2-1d2-vec/oaep-vect.txt (kunci 1024-bit) | LULUS |
| PKCS1-OAEP-1.5 | PKCS #1 v2.1 oaep-vect.txt (RSA Laboratories), via github.com/pyca/cryptography/vectors/.../pkcs-1v2-1d2-vec/oaep-vect.txt (kunci 1024-bit) | LULUS |
| PKCS1-OAEP-1.6 | PKCS #1 v2.1 oaep-vect.txt (RSA Laboratories), via github.com/pyca/cryptography/vectors/.../pkcs-1v2-1d2-vec/oaep-vect.txt (kunci 1024-bit) | LULUS |
| PKCS1-OAEP-10.1 | PKCS #1 v2.1 oaep-vect.txt (RSA Laboratories), via github.com/pyca/cryptography/vectors/.../pkcs-1v2-1d2-vec/oaep-vect.txt (kunci 2048-bit) | LULUS |
| PKCS1-OAEP-10.2 | PKCS #1 v2.1 oaep-vect.txt (RSA Laboratories), via github.com/pyca/cryptography/vectors/.../pkcs-1v2-1d2-vec/oaep-vect.txt (kunci 2048-bit) | LULUS |
| PKCS1-OAEP-10.3 | PKCS #1 v2.1 oaep-vect.txt (RSA Laboratories), via github.com/pyca/cryptography/vectors/.../pkcs-1v2-1d2-vec/oaep-vect.txt (kunci 2048-bit) | LULUS |
| PKCS1-OAEP-10.4 | PKCS #1 v2.1 oaep-vect.txt (RSA Laboratories), via github.com/pyca/cryptography/vectors/.../pkcs-1v2-1d2-vec/oaep-vect.txt (kunci 2048-bit) | LULUS |
| PKCS1-OAEP-10.5 | PKCS #1 v2.1 oaep-vect.txt (RSA Laboratories), via github.com/pyca/cryptography/vectors/.../pkcs-1v2-1d2-vec/oaep-vect.txt (kunci 2048-bit) | LULUS |
| PKCS1-OAEP-10.6 | PKCS #1 v2.1 oaep-vect.txt (RSA Laboratories), via github.com/pyca/cryptography/vectors/.../pkcs-1v2-1d2-vec/oaep-vect.txt (kunci 2048-bit) | LULUS |
