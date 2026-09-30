# Dokumen Penetapan Metode & Parameter Pengujian — AES-128

**Cryptan.ID Test Suite** v1.0.0 · Modul **UK-1** · Unit J.61KRP00.012.1 — *Menentukan Metode Pengujian yang akan Dilakukan* · SKKNI 2023-004 (Cryptographic Analyst)

Dibangkitkan: 2026-09-30T23:04:20+07:00 · mode: full · objek: **Cryptan.ID SecureLib** (1.0.0 (hipotetis))

> Seluruh data produk bersifat ILUSTRATIF. Nilai bertanda HASIL UJI LANGSUNG dihitung oleh kode; HASIL LITERATUR dikutip dari rujukan; PERLU_VERIFIKASI wajib dicek ke sumber primer.

## Ringkasan

- Kelas primitif: **Block cipher**, struktur SPN
- Tingkat akses penguji: **grey_box**
- KAT implementasi referensi: **6/6 LULUS**
- Komponen berpotensi lemah: **C-IMPL-TBL**; perlu perhatian: C-MODE, C-API, C-MEM, C-PLAT
- Metode terpilih: **16** · ditolak: 5 · upaya 99 / 240 jam-orang (SESUAI)

## 1. Profil Produk & Ruang Lingkup (KUK 1.1)

| Atribut | Nilai |
|---|---|
| Produk | Cryptan.ID SecureLib 1.0.0 (hipotetis) |
| Deskripsi | Library kriptografi perangkat lunak (shared object) untuk Linux x86-64 |
| Algoritma | AES-128 (FIPS 197) mode CTR |
| Kelas primitif | Block cipher |
| Struktur | SPN |
| Mode | CTR |
| Parameter | block_bits=128; key_bits=128; rounds=10; sbox_bits=8; output_bits_per_op=128 |
| Platform | Shared library (.so) di Linux x86-64; CPU multi-core dengan cache L3 bersama |
| Bahasa / binding | C / Python |
| Antarmuka | C API (libsecure.so), Python binding (ctypes) |
| RBG | getrandom(2) → HMAC_DRBG (SP 800-90A) |
| Catatan implementasi | table_based=True; nonce_generation=counter 64-bit + nonce acak 64-bit |
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
| FIPS-197 | NIST | Advanced Encryption Standard (AES) | 2001 | Spesifikasi algoritma/skema |
| ISO-18033-3 | ISO/IEC | Encryption algorithms — Part 3: Block ciphers (AES) | 2010 | Spesifikasi algoritma/skema |
| SP-800-38A | NIST | Recommendation for Block Cipher Modes of Operation: Methods and Techniques | 2001 | Spesifikasi algoritma/skema |
| SP-800-38D | NIST | Recommendation for Block Cipher Modes of Operation: GCM and GMAC | 2007 | Spesifikasi algoritma/skema |
| ISO-18367 | ISO/IEC | Cryptographic algorithms and security mechanisms conformance testing | 2016 | Pengujian kesesuaian |
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

15 serangan relevan setelah filter profil; praktis: 10; perlu verifikasi: 3.

| ID | Kategori | Serangan | Model | Kompleksitas (log2 T/D/M) | Ronde | Status | Rujukan |
|---|---|---|---|---|---|---|---|
| A-BC-05 | desain | Integral / Square attack (ronde tereduksi) | CPA | 9/9/4 | 4/10 (6/10 dengan partial sums: data ≈ 6·2^32, waktu ≈ 2^44) | praktis (ronde tereduksi) `PERLU_VERIFIKASI` | Daemen, Knudsen, Rijmen — The Block Cipher Square, FSE 1997; Ferguson et al. — Improved Cryptanalysis of Rijndael, FSE 2000 |
| A-BC-01 | desain | Exhaustive key search (brute force) | KPA | 128/0/0 | full | teoretis | Batas generik \|K\| = 2^128; SP 800-57 Part 1 Rev.5 Tabel 2 |
| A-BC-02 | desain | Biclique cryptanalysis (full AES-128) | CPA | 126.1/88/8 | 10/10 | teoretis | Bogdanov, Khovratovich, Rechberger — Biclique Cryptanalysis of the Full AES, ASIACRYPT 2011 |
| A-BC-03 | desain | Differential cryptanalysis (batas wide-trail) | CPA | —/—/— | karakteristik 4 ronde ≥ 25 S-box aktif ⇒ p ≤ 2^-150 | teoretis | Biham & Shamir, CRYPTO 1990 / J. Cryptology 1991; Daemen & Rijmen — The Design of Rijndael, Springer 2002 (wide trail strategy) |
| A-BC-04 | desain | Linear cryptanalysis (batas wide-trail) | KPA | —/—/— | korelasi trail 4 ronde ≤ 2^-75 | teoretis | Matsui, EUROCRYPT 1993; Daemen & Rijmen — The Design of Rijndael, 2002 |
| A-BC-06 | desain | Impossible differential / meet-in-the-middle (7 ronde AES-128) | CPA | —/—/— | 7/10 | teoretis `PERLU_VERIFIKASI` | Lu, Dunkelman, Keller, Kim — New impossible differential attacks on AES, INDOCRYPT 2008; Derbez, Fouque, Jean — MITM attacks on AES, EUROCRYPT 2013 |
| A-BC-07 | protokol | Nonce/counter reuse pada mode CTR/GCM | KPA | 0/1/0 | n/a | praktis | SP 800-38A App. B (keunikan counter block); Joux — Authentication failures in NIST version of GCM (forbidden attack), 2006 |
| A-SC-07 | bahasa | Counter overflow / wrap-around (keystream berulang) | KPA | 0/38/0 | n/a | praktis (bila > 256 GiB per nonce pada ChaCha20 RFC 8439) | RFC 8439 §2.4 (counter 32-bit ⇒ maks 2^32 blok × 64 byte) |
| A-L-01 | bahasa | Perbandingan tidak constant-time (memcmp pada tag/MAC/padding) | side-channel | —/—/— | n/a | praktis `PERLU_VERIFIKASI` | Lawson — Timing attack in Google Keyczar, 2009; ISO/IEC 17825 |
| A-L-02 | bahasa | Buffer over-read/overflow (memory safety) | n/a | 0/0/0 | n/a | praktis | NVD CVE-2014-0160 (Heartbleed, OpenSSL) |
| A-L-03 | bahasa | Material kunci tidak di-zeroize (sisa di memori / cold boot) | n/a | —/—/— | n/a | praktis | Halderman et al. — Lest We Remember: Cold Boot Attacks, USENIX Security 2008; ISO/IEC 19790 §7.9 (zeroisation) |
| A-BC-09 | platform | Cache-timing pada implementasi berbasis tabel (T-table / S-box lookup) | side-channel | —/—/— | n/a | praktis | Bernstein — Cache-timing attacks on AES, 2005; Osvik, Shamir, Tromer — Cache Attacks and Countermeasures: the Case of AES, CT-RSA 2006 |
| A-P-11 | platform | RNG lemah saat pembangkitan kunci | n/a | 15/0/— | n/a | praktis | CVE-2008-0166 (Debian OpenSSL, ruang kunci 2^15); Heninger et al., USENIX Security 2012 |
| A-X-01 | platform | Transient execution (Spectre) | side-channel | —/—/— | n/a | praktis | Kocher et al. — Spectre Attacks, IEEE S&P 2019 |
| A-X-02 | platform | Frequency-scaling side-channel (Hertzbleed) | side-channel | —/—/— | n/a | praktis (remote timing dari variasi daya) | Wang et al. — Hertzbleed, USENIX Security 2022 |

## 3. Hasil Telaah Komponen (KUK 2.1)

| ID | Komponen | Lapis | Status | Tag kelemahan |
|---|---|---|---|---|
| C-SBOX | S-box (SubBytes) | algoritma | OK | sbox |
| C-DIFF | Lapisan difusi (ShiftRows + MixColumns) | algoritma | OK | diffusion |
| C-ROUND | Fungsi ronde & jumlah ronde | algoritma | OK | round_count |
| C-KS | Key schedule | algoritma | OK | key_schedule |
| C-KEY | Ukuran kunci | algoritma | OK | key_size |
| C-MODE | Mode operasi & pengelolaan counter/nonce | algoritma | PERHATIAN | mode_nonce, keystream_stat, nonce_reuse |
| C-IMPL-TBL | Implementasi berbasis tabel (lookup) | algoritma | BERPOTENSI_LEMAH | table_lookup, constant_time |
| C-API | Antarmuka API & validasi masukan | implementasi | PERHATIAN | memory_safety, pubkey_validation |
| C-MEM | Pengelolaan material kunci di memori | implementasi | PERHATIAN | key_zeroization |
| C-SELFTEST | Self-test & error state modul | implementasi | OK | self_test, conformance |
| C-RNG | Sumber acak (RBG) | implementasi | OK | rng |
| C-PLAT | Platform eksekusi (CPU x86-64 bercache, speculative execution) | implementasi | PERHATIAN | speculative, constant_time |
| C-CONF | Kesesuaian implementasi keseluruhan | implementasi | OK | conformance |

### C-SBOX — S-box (SubBytes) [OK]

Satu-satunya komponen nonlinear; menentukan ketahanan diferensial/linear/aljabar.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Nonlinearitas (NL) | 112 | ≥ 112 | OK | HASIL UJI LANGSUNG |  |
| Keseragaman diferensial (DU, DDT maks) | 4 | ≤ 4 | OK | HASIL UJI LANGSUNG | DP maks = 4/256 = 2^-6 |
| \|LAT\| maks / korelasi linear maks | 16 / 0.125 | ≤ 16 / 2^-3 | OK | HASIL UJI LANGSUNG |  |
| Derajat aljabar | 7 | ≥ 7 | OK | HASIL UJI LANGSUNG |  |
| SAC (deviasi maks dari 0,5) | 0.0625 | ≤ 0,125 | OK | HASIL UJI LANGSUNG |  |
| Titik tetap / titik tetap berlawanan | 0 / 0 | 0 / 0 | OK | HASIL UJI LANGSUNG |  |
| Bijektif | True | True | OK | HASIL UJI LANGSUNG |  |

### C-DIFF — Lapisan difusi (ShiftRows + MixColumns) [OK]

Menyebarkan perubahan antar-byte; diukur dengan branch number (MDS).

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Branch number MixColumns | 5 | = 5 (optimal, MDS) | OK | HASIL UJI LANGSUNG |  |
| MDS (semua submatriks non-singular) | True | True | OK | HASIL UJI LANGSUNG |  |
| Ronde menuju difusi penuh (avalanche ≈ 0,5) | 3 | ≤ 5 | OK | HASIL UJI LANGSUNG |  |

### C-ROUND — Fungsi ronde & jumlah ronde [OK]

Margin keamanan terhadap serangan ronde tereduksi.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Batas probabilitas trail diferensial 4 ronde | 2^-150 | ≤ 2^-128 | OK | HASIL UJI LANGSUNG | 25 S-box aktif × DP maks (dihitung dari DU & branch number) |
| Batas korelasi trail linear 4 ronde | 2^-75 | ≤ 2^-64 | OK | HASIL UJI LANGSUNG |  |
| Margin keamanan ronde (serangan non-biclique terbaik 7/10) | 30% | ≥ 20% | OK | HASIL LITERATUR | Lihat A-BC-06 |

### C-KS — Key schedule [OK]

Penurunan round key; relevan untuk related-key / biclique.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Avalanche kunci → ciphertext | 0.502 | 0,5 ± 0,02 | OK | HASIL UJI LANGSUNG |  |
| Difusi key schedule (beda bit round key terakhir, 1 bit kunci) | 0.3125 | ≥ 0,3 | OK | HASIL UJI LANGSUNG |  |
| Biclique ronde penuh | 2^126.1 | ≥ 2^112 | OK | HASIL LITERATUR | Keunggulan 1,9 bit atas brute force (A-BC-02) |

### C-KEY — Ukuran kunci [OK]

Ruang kunci terhadap brute force & tingkat keamanan.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Tingkat keamanan (SP 800-57) | 128 bit | ≥ 128 bit | OK | HASIL UJI LANGSUNG |  |

### C-MODE — Mode operasi & pengelolaan counter/nonce [PERHATIAN]

Keunikan counter block & keacakan keluaran mode.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Pra-uji keacakan keystream CTR (Monobit, Runs; α = 0,01) | Frequency (Monobit) p=0.365, Runs p=0.344 | p ≥ 0,01 | OK | HASIL UJI LANGSUNG | 32768 bit; uji penuh SP 800-22 pada metode M-SP80022 |
| Batas tabrakan nonce acak | 2^32 pesan | rekey sebelum 2^32 pesan | PERHATIAN | KLAIM PROFIL | Nonce acak 64-bit (klaim profil: counter 64-bit + nonce acak 64-bit) |

### C-IMPL-TBL — Implementasi berbasis tabel (lookup) [BERPOTENSI_LEMAH]

Akses memori bergantung data rahasia pada platform ber-cache.

| Pemeriksaan | Nilai | Acuan | Status | Sumber | Catatan |
|---|---|---|---|---|---|
| Implementasi berbasis tabel pada CPU ber-cache | Ya | tanpa lookup bergantung-rahasia (bitsliced/AES-NI) | BERPOTENSI_LEMAH | KLAIM PROFIL | Rentan cache-timing (A-BC-09); wajib M-TIMING/M-CACHE |

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
| KAT implementasi referensi (core/) | 6/6 LULUS | 100% cocok | OK | HASIL UJI LANGSUNG | Vektor: FIPS 197 Appendix B; FIPS 197 Appendix C.1; SP 800-38A F.1.1 ECB-AES128 blok 1; SP 800-38A F.1.1 ECB-AES128 blok 2; SP 800-38A F.1.1 ECB-AES128 blok 3; SP 800-38A F.1.1 ECB-AES128 blok 4 |

## 4. Matriks Komponen–Kelemahan–Metode (KUK 2.2)

Tiga lapis pengujian × level uji (metode yang dipetakan):

| Lapis \ Level | Unit | Integrasi | Sistem |
|---|---|---|---|
| Kesesuaian | M-KAT, M-MCT | — | — |
| Kekuatan algoritma | M-AVAL, M-DIFF, M-DIFFUSION, M-INT, M-LIN, M-SBOX, M-SP80022 | — | M-BRUTE, M-KEYSIZE |
| Implementasi & sistem | M-CODEREVIEW | M-FUZZ, M-NONCE, M-RNG, M-TIMING | M-CACHE, M-SELFTEST, M-ZEROIZE |

| Komponen | Status | Kelemahan | Serangan | Metode | Lapis | Level | Standar | Akses |
|---|---|---|---|---|---|---|---|---|
| C-CONF Kesesuaian implementasi keseluruhan | OK | Keluaran implementasi tidak sesuai standar | — | M-KAT Known Answer Test (KAT) terhadap vektor resmi | Kesesuaian | Unit | ISO-18367, ISO-24759 | ✔ black |
| C-CONF Kesesuaian implementasi keseluruhan | OK | Keluaran implementasi tidak sesuai standar | — | M-MCT Monte Carlo Test (MCT) & Multi-block Message Test (MMT) gaya CAVP | Kesesuaian | Unit | ISO-18367, ISO-24759 | ✔ black |
| C-SELFTEST Self-test & error state modul | OK | Keluaran implementasi tidak sesuai standar | — | M-KAT Known Answer Test (KAT) terhadap vektor resmi | Kesesuaian | Unit | ISO-18367, ISO-24759 | ✔ black |
| C-SELFTEST Self-test & error state modul | OK | Keluaran implementasi tidak sesuai standar | — | M-MCT Monte Carlo Test (MCT) & Multi-block Message Test (MMT) gaya CAVP | Kesesuaian | Unit | ISO-18367, ISO-24759 | ✔ black |
| C-DIFF Lapisan difusi (ShiftRows + MixColumns) | OK | Difusi tidak lengkap / branch number rendah | A-BC-05, A-BC-03, A-BC-04 | M-AVAL Uji avalanche & Strict Avalanche Criterion (fungsi penuh) | Kekuatan algoritma | Unit | ISO-18367 | ✔ black |
| C-DIFF Lapisan difusi (ShiftRows + MixColumns) | OK | Difusi tidak lengkap / branch number rendah | A-BC-05, A-BC-03, A-BC-04 | M-DIFF Kriptanalisis diferensial (pencarian trail / batas S-box aktif) | Kekuatan algoritma | Unit | ISO-18033-3, ISO-15408 | ✔ grey |
| C-DIFF Lapisan difusi (ShiftRows + MixColumns) | OK | Difusi tidak lengkap / branch number rendah | A-BC-05, A-BC-03, A-BC-04 | M-DIFFUSION Analisis difusi (branch number/MDS, ronde menuju difusi penuh, avalanche per ronde) | Kekuatan algoritma | Unit | ISO-18033-3, ISO-18033-4, FIPS-202 | ✔ grey |
| C-DIFF Lapisan difusi (ShiftRows + MixColumns) | OK | Difusi tidak lengkap / branch number rendah | A-BC-05, A-BC-03, A-BC-04 | M-INT Serangan integral / Square pada ronde tereduksi | Kekuatan algoritma | Unit | ISO-15408 | ✔ grey |
| C-DIFF Lapisan difusi (ShiftRows + MixColumns) | OK | Difusi tidak lengkap / branch number rendah | A-BC-05, A-BC-03, A-BC-04 | M-LIN Kriptanalisis linear (LAT, batas korelasi trail) | Kekuatan algoritma | Unit | ISO-18033-3, ISO-15408 | ✔ grey |
| C-DIFF Lapisan difusi (ShiftRows + MixColumns) | OK | Difusi tidak lengkap / branch number rendah | A-BC-05, A-BC-03, A-BC-04 | M-SP80022 Uji keacakan statistik NIST SP 800-22 (15 uji) | Kekuatan algoritma | Unit | SP-800-22 | ✔ black |
| C-KS Key schedule | OK | Key schedule lemah (related-key / biclique) | A-BC-02, A-BC-06 | M-AVAL Uji avalanche & Strict Avalanche Criterion (fungsi penuh) | Kekuatan algoritma | Unit | ISO-18367 | ✔ black |
| C-MODE Mode operasi & pengelolaan counter/nonce | PERHATIAN | Keluaran terbedakan dari acak | — | M-SP80022 Uji keacakan statistik NIST SP 800-22 (15 uji) | Kekuatan algoritma | Unit | SP-800-22 | ✔ black |
| C-ROUND Fungsi ronde & jumlah ronde | OK | Margin ronde tidak memadai terhadap serangan ronde tereduksi | A-BC-05, A-BC-02, A-BC-03, A-BC-04, A-BC-06 | M-DIFF Kriptanalisis diferensial (pencarian trail / batas S-box aktif) | Kekuatan algoritma | Unit | ISO-18033-3, ISO-15408 | ✔ grey |
| C-ROUND Fungsi ronde & jumlah ronde | OK | Margin ronde tidak memadai terhadap serangan ronde tereduksi | A-BC-05, A-BC-02, A-BC-03, A-BC-04, A-BC-06 | M-INT Serangan integral / Square pada ronde tereduksi | Kekuatan algoritma | Unit | ISO-15408 | ✔ grey |
| C-ROUND Fungsi ronde & jumlah ronde | OK | Margin ronde tidak memadai terhadap serangan ronde tereduksi | A-BC-05, A-BC-02, A-BC-03, A-BC-04, A-BC-06 | M-LIN Kriptanalisis linear (LAT, batas korelasi trail) | Kekuatan algoritma | Unit | ISO-18033-3, ISO-15408 | ✔ grey |
| C-SBOX S-box (SubBytes) | OK | Nonlinearitas/keseragaman diferensial S-box tidak memadai | A-BC-05, A-BC-03, A-BC-04 | M-DIFF Kriptanalisis diferensial (pencarian trail / batas S-box aktif) | Kekuatan algoritma | Unit | ISO-18033-3, ISO-15408 | ✔ grey |
| C-SBOX S-box (SubBytes) | OK | Nonlinearitas/keseragaman diferensial S-box tidak memadai | A-BC-05, A-BC-03, A-BC-04 | M-LIN Kriptanalisis linear (LAT, batas korelasi trail) | Kekuatan algoritma | Unit | ISO-18033-3, ISO-15408 | ✔ grey |
| C-SBOX S-box (SubBytes) | OK | Nonlinearitas/keseragaman diferensial S-box tidak memadai | A-BC-05, A-BC-03, A-BC-04 | M-SBOX Analisis sifat S-box / fungsi nonlinear (NL, DDT, LAT, derajat, SAC) | Kekuatan algoritma | Unit | ISO-18033-3, FIPS-197, FIPS-202 | ✔ grey |
| C-KEY Ukuran kunci | OK | Ruang kunci / tingkat keamanan tidak memadai | A-BC-01, A-BC-02 | M-BRUTE Pencarian kunci menyeluruh (exhaustive key search) | Kekuatan algoritma | Sistem | SP-800-57, SP-800-131A | ✔ black |
| C-KEY Ukuran kunci | OK | Ruang kunci / tingkat keamanan tidak memadai | A-BC-01, A-BC-02 | M-KEYSIZE Evaluasi ukuran kunci & tingkat keamanan (SP 800-57 / 131A) | Kekuatan algoritma | Sistem | SP-800-57, SP-800-131A | ✔ black |
| C-API Antarmuka API & validasi masukan | PERHATIAN | Buffer overflow / masukan malformed | A-L-02 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-IMPL-TBL Implementasi berbasis tabel (lookup) | BERPOTENSI_LEMAH | Lookup tabel bergantung data rahasia (cache-timing) | A-BC-09 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-IMPL-TBL Implementasi berbasis tabel (lookup) | BERPOTENSI_LEMAH | Eksekusi tidak constant-time | A-L-01, A-BC-09, A-X-01, A-X-02 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-MEM Pengelolaan material kunci di memori | PERHATIAN | Material kunci tidak dihapus dari memori | A-L-03 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | PERHATIAN | Eksekusi tidak constant-time | A-L-01, A-BC-09, A-X-01, A-X-02 | M-CODEREVIEW Tinjauan kode sumber (constant-time, memory safety, zeroization) | Implementasi & sistem | Unit | ISO-18045, ISO-15408 | ✘ white |
| C-API Antarmuka API & validasi masukan | PERHATIAN | Buffer overflow / masukan malformed | A-L-02 | M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | ISO-29119, ISO-18045 | ✔ black |
| C-API Antarmuka API & validasi masukan | PERHATIAN | Kunci publik/titik tidak divalidasi | — | M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | ISO-29119, ISO-18045 | ✔ black |
| C-IMPL-TBL Implementasi berbasis tabel (lookup) | BERPOTENSI_LEMAH | Lookup tabel bergantung data rahasia (cache-timing) | A-BC-09 | M-TIMING Analisis timing leakage (dudect / Welch t-test, fixed-vs-random) | Implementasi & sistem | Integrasi | ISO-17825, ISO-20085 | ✔ grey |
| C-IMPL-TBL Implementasi berbasis tabel (lookup) | BERPOTENSI_LEMAH | Eksekusi tidak constant-time | A-L-01, A-BC-09, A-X-01, A-X-02 | M-TIMING Analisis timing leakage (dudect / Welch t-test, fixed-vs-random) | Implementasi & sistem | Integrasi | ISO-17825, ISO-20085 | ✔ grey |
| C-MODE Mode operasi & pengelolaan counter/nonce | PERHATIAN | Penyalahgunaan mode (counter/IV berulang, padding oracle) | A-BC-07 | M-NONCE Uji keunikan & bias nonce (statistik + kelayakan lattice HNP) | Implementasi & sistem | Integrasi | FIPS-186-5, RFC-6979, SP-800-90A, SP-800-38A, RFC-8439 | ✔ grey |
| C-MODE Mode operasi & pengelolaan counter/nonce | PERHATIAN | Nonce/IV dipakai ulang | A-BC-07 | M-NONCE Uji keunikan & bias nonce (statistik + kelayakan lattice HNP) | Implementasi & sistem | Integrasi | FIPS-186-5, RFC-6979, SP-800-90A, SP-800-38A, RFC-8439 | ✔ grey |
| C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | PERHATIAN | Eksekusi tidak constant-time | A-L-01, A-BC-09, A-X-01, A-X-02 | M-TIMING Analisis timing leakage (dudect / Welch t-test, fixed-vs-random) | Implementasi & sistem | Integrasi | ISO-17825, ISO-20085 | ✔ grey |
| C-RNG Sumber acak (RBG) | OK | RBG lemah / entropi rendah | A-P-11 | M-NONCE Uji keunikan & bias nonce (statistik + kelayakan lattice HNP) | Implementasi & sistem | Integrasi | FIPS-186-5, RFC-6979, SP-800-90A, SP-800-38A, RFC-8439 | ✔ grey |
| C-RNG Sumber acak (RBG) | OK | RBG lemah / entropi rendah | A-P-11 | M-RNG Asesmen RBG / sumber entropi (SP 800-90A/B, ISO/IEC 18031) | Implementasi & sistem | Integrasi | SP-800-90A, SP-800-90B, ISO-18031, SP-800-22 | ✔ grey |
| C-CONF Kesesuaian implementasi keseluruhan | OK | Keluaran implementasi tidak sesuai standar | — | M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ black |
| C-IMPL-TBL Implementasi berbasis tabel (lookup) | BERPOTENSI_LEMAH | Lookup tabel bergantung data rahasia (cache-timing) | A-BC-09 | M-CACHE Analisis cache side-channel (Flush+Reload / Prime+Probe) | Implementasi & sistem | Sistem | ISO-17825 | ✔ grey |
| C-MEM Pengelolaan material kunci di memori | PERHATIAN | Material kunci tidak dihapus dari memori | A-L-03 | M-ZEROIZE Uji zeroization material kunci (memory dump pasca-operasi) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ grey |
| C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | PERHATIAN | Kebocoran eksekusi spekulatif | A-X-01 | M-CACHE Analisis cache side-channel (Flush+Reload / Prime+Probe) | Implementasi & sistem | Sistem | ISO-17825 | ✔ grey |
| C-SELFTEST Self-test & error state modul | OK | Self-test / error state tidak berfungsi | — | M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ black |
| C-SELFTEST Self-test & error state modul | OK | Keluaran implementasi tidak sesuai standar | — | M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | ISO-19790, ISO-24759 | ✔ black |

## 5. Estimasi Sumber Daya & Kelayakan (KUK 2.3)

### 5.1 Benchmark mesin lab — HASIL UJI LANGSUNG

| Operasi | ops/detik |
|---|---|
| encrypt | 2,670.7 |
| primary | 2,670.7 |

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
| M-MCT | primary | 16.61 | 4.68 detik | 2^16.6 operasi/sampel | ≤ 2^14 B | — | LAYAK | Estimasi 4.68 detik ≤ anggaran 24 jam |
| M-SBOX | analysis | 20 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-DIFFUSION | primary | 17 | 6.13 detik | 2^17.0 operasi/sampel | ≤ 2^14 B | — | LAYAK | Estimasi 6.13 detik ≤ anggaran 24 jam |
| M-AVAL | primary | 14.29 | 0.94 detik | 2^14.3 operasi/sampel | ≤ 2^13 B | — | LAYAK | Estimasi 0.94 detik ≤ anggaran 24 jam |
| M-SP80022 | primary | 19.58 | 36.57 detik | 2^19.6 operasi/sampel | ≈ 12.5 MB | — | LAYAK | Estimasi 36.57 detik ≤ anggaran 24 jam |
| M-DIFF | primary | 150 | 2^110.7 tahun | 2^150.0 operasi/sampel | ≤ 2^40 B | Trail/distinguisher diferensial pada 2–3 ronde tereduksi — 12.27 detik | LAYAK VERSI TEREDUKSI | Versi penuh 2^110.7 tahun > anggaran; versi tereduksi 12.27 detik |
| M-LIN | primary | 150 | 2^110.7 tahun | 2^150.0 operasi/sampel | ≤ 2^40 B | Aproksimasi linear 2–3 ronde tereduksi, verifikasi bias empiris — 49.08 detik | LAYAK VERSI TEREDUKSI | Versi penuh 2^110.7 tahun > anggaran; versi tereduksi 49.08 detik |
| M-INT | primary | 128 | 2^88.7 tahun | 2^128.0 operasi/sampel | ≤ 2^40 B | Integral 3–4 ronde (2^8 CP per Λ-set) + margin keamanan — 3.07 detik | LAYAK VERSI TEREDUKSI | Versi penuh 2^88.7 tahun > anggaran; versi tereduksi 3.07 detik |
| M-BRUTE | primary | 128 | 2^88.7 tahun | 2^128.0 operasi/sampel | ≤ 2^40 B | Pencarian kunci tereduksi (24 bit kunci tak diketahui) — validasi harness — 13.1 menit | LAYAK VERSI TEREDUKSI | Versi penuh 2^88.7 tahun > anggaran; versi tereduksi 13.1 menit |
| M-KEYSIZE | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-NONCE | primary | 12 | 0.19 detik | 2^12.0 operasi/sampel | ≤ 2^12 B | — | LAYAK | Estimasi 0.19 detik ≤ anggaran 24 jam |
| M-TIMING | primary | 20 | 49.08 detik | 2^20.0 operasi/sampel | ≤ 2^16 B | — | LAYAK | Estimasi 49.08 detik ≤ anggaran 24 jam |
| M-CACHE | primary | 22 | 3.3 menit | 2^22.0 operasi/sampel | ≤ 2^17 B | — | TIDAK LAYAK | Alat tidak tersedia: mastik |
| M-TVLA | primary | 17 | 6.13 detik | 2^17.0 operasi/sampel | ≤ 2^14 B | — | TIDAK LAYAK | Alat tidak tersedia: oscilloscope, chipwhisperer |
| M-FAULT | primary | 16 | 3.07 detik | 2^16.0 operasi/sampel | ≤ 2^14 B | — | TIDAK LAYAK | Alat tidak tersedia: glitcher |
| M-CODEREVIEW | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-FUZZ | primary | 20 | 49.08 detik | 2^20.0 operasi/sampel | ≤ 2^16 B | — | LAYAK | Estimasi 49.08 detik ≤ anggaran 24 jam |
| M-ZEROIZE | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-SELFTEST | analysis | 0 | 0 detik (analitis) | — | — | — | LAYAK | Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-RNG | primary | 12.93 | 0.37 detik | 2^12.9 operasi/sampel | ≈ 0.1 MB | — | LAYAK | Estimasi 0.37 detik ≤ anggaran 24 jam |

## 6. Metode Terpilih & Parameter Pengujian (KUK 3.1, 3.2)

### 6.1 Penetapan metode

Rumus: skor = relevansi[keparahan 1–3 + tren serangan (+1 praktis | +0,5 teoretis), maks 3] × kelayakan(1 | 0,6 | 0) × akses(1 | 0); ambang ≥ 1.0.

| Metode | Lapis | Level | Varian | Skor | Target | Alasan |
|---|---|---|---|---|---|---|
| M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Implementasi & sistem | Integrasi | penuh | 3 | C-API | Skor 3.0 ≥ 1.0: relevan terhadap C-API. Estimasi 49.08 detik ≤ anggaran 24 jam |
| M-NONCE Uji keunikan & bias nonce (statistik + kelayakan lattice HNP) | Implementasi & sistem | Integrasi | penuh | 3 | C-MODE | Skor 3.0 ≥ 1.0: relevan terhadap C-MODE. Estimasi 0.19 detik ≤ anggaran 24 jam |
| M-SP80022 Uji keacakan statistik NIST SP 800-22 (15 uji) | Kekuatan algoritma | Unit | penuh | 3 | C-MODE | Skor 3.0 ≥ 1.0: relevan terhadap C-MODE. Estimasi 36.57 detik ≤ anggaran 24 jam |
| M-TIMING Analisis timing leakage (dudect / Welch t-test, fixed-vs-random) | Implementasi & sistem | Integrasi | penuh | 3 | C-IMPL-TBL, C-PLAT | Skor 3.0 ≥ 1.0: relevan terhadap C-IMPL-TBL, C-PLAT. Estimasi 49.08 detik ≤ anggaran 24 jam |
| M-ZEROIZE Uji zeroization material kunci (memory dump pasca-operasi) | Implementasi & sistem | Sistem | penuh | 3 | C-MEM | Skor 3.0 ≥ 1.0: relevan terhadap C-MEM. Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-AVAL Uji avalanche & Strict Avalanche Criterion (fungsi penuh) | Kekuatan algoritma | Unit | penuh | 2 | C-DIFF, C-KS | Skor 2.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 0.94 detik ≤ anggaran 24 jam |
| M-DIFFUSION Analisis difusi (branch number/MDS, ronde menuju difusi penuh, avalanche per ronde) | Kekuatan algoritma | Unit | penuh | 2 | C-DIFF | Skor 2.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 6.13 detik ≤ anggaran 24 jam |
| M-RNG Asesmen RBG / sumber entropi (SP 800-90A/B, ISO/IEC 18031) | Implementasi & sistem | Integrasi | penuh | 2 | C-RNG | Skor 2.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 0.37 detik ≤ anggaran 24 jam |
| M-SBOX Analisis sifat S-box / fungsi nonlinear (NL, DDT, LAT, derajat, SAC) | Kekuatan algoritma | Unit | penuh | 2 | C-SBOX | Skor 2.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-KEYSIZE Evaluasi ukuran kunci & tingkat keamanan (SP 800-57 / 131A) | Kekuatan algoritma | Sistem | penuh | 1.5 | C-KEY | Wajib (kesesuaian standar / baseline keamanan). Estimasi 0 detik (analitis) ≤ anggaran 24 jam |
| M-DIFF Kriptanalisis diferensial (pencarian trail / batas S-box aktif) | Kekuatan algoritma | Unit | tereduksi | 1.2 | C-DIFF, C-ROUND, C-SBOX | Skor 1.2 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Versi penuh 2^110.7 tahun > anggaran; versi tereduksi 12.27 detik |
| M-INT Serangan integral / Square pada ronde tereduksi | Kekuatan algoritma | Unit | tereduksi | 1.2 | C-DIFF, C-ROUND | Skor 1.2 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Versi penuh 2^88.7 tahun > anggaran; versi tereduksi 3.07 detik |
| M-LIN Kriptanalisis linear (LAT, batas korelasi trail) | Kekuatan algoritma | Unit | tereduksi | 1.2 | C-DIFF, C-ROUND, C-SBOX | Skor 1.2 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Versi penuh 2^110.7 tahun > anggaran; versi tereduksi 49.08 detik |
| M-KAT Known Answer Test (KAT) terhadap vektor resmi | Kesesuaian | Unit | penuh | 1 | C-CONF, C-SELFTEST | Wajib (kesesuaian standar / baseline keamanan). Estimasi 0.01 detik ≤ anggaran 24 jam |
| M-MCT Monte Carlo Test (MCT) & Multi-block Message Test (MMT) gaya CAVP | Kesesuaian | Unit | penuh | 1 | C-CONF, C-SELFTEST | Wajib (kesesuaian standar / baseline keamanan). Estimasi 4.68 detik ≤ anggaran 24 jam |
| M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Implementasi & sistem | Sistem | penuh | 1 | C-CONF, C-SELFTEST | Skor 1.0 ≥ 1.0: relevan terhadap komponen OK (verifikasi). Estimasi 0 detik (analitis) ≤ anggaran 24 jam |

**Metode yang ditolak:**

| Metode | Kelayakan | Skor | Alasan |
|---|---|---|---|
| M-BRUTE Pencarian kunci menyeluruh (exhaustive key search) | 0.6 | 0.9 | Ditolak: skor 0.9 < 1.0 |
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
| estimated_time | 49.08 detik |

**M-NONCE**

| Parameter | Nilai |
|---|---|
| signatures |  |
| messages | 65536 |
| checks | duplikasi nonce/IV = 0, counter tidak wrap (tolak > 2^32 blok) |
| alpha | 0.01 |
| variant | penuh |
| estimated_time | 0.19 detik |

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
| generation | keystream CTR (kunci acak, counter berurutan) |
| variant | penuh |
| estimated_time | 36.57 detik |

**M-TIMING**

| Parameter | Nilai |
|---|---|
| method | dudect fixed-vs-random (Welch t) |
| measurements | 1000000 |
| threshold_abs_t | 4.5 |
| classes | kunci tetap, plaintext tetap vs acak |
| timer | rdtsc / perf_counter_ns, core diisolasi (taskset), turbo dimatikan |
| variant | penuh |
| estimated_time | 49.08 detik |

**M-ZEROIZE**

| Parameter | Nilai |
|---|---|
| procedure | core dump / gdb setelah free & pemanggilan API destroy |
| search | pola kunci uji (known key) |
| pass_criterion | 0 kemunculan |
| variant | penuh |
| estimated_time | 0 detik (analitis) |

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
| estimated_time | 0.94 detik |

**M-DIFFUSION**

| Parameter | Nilai |
|---|---|
| rounds_tested | 1, 2, 3, 4, 5, 6 |
| samples_per_round | 10000 |
| metric | fraksi bit keluaran berubah (1 bit masukan dibalik) |
| full_diffusion_criterion | \|mean − 0,5\| ≤ 0,01 dan min > 0,3 |
| branch_number_target | 5 |
| variant | penuh |
| estimated_time | 6.13 detik |

**M-RNG**

| Parameter | Nilai |
|---|---|
| entropy_samples_bits | 1000000 |
| sp800_90b | IID & non-IID track, restart test 1000×1000 |
| sp800_22 | subset sesuai M-SP80022 |
| drbg | CAVP DRBG KAT (HMAC_DRBG) |
| variant | penuh |
| estimated_time | 0.37 detik |

**M-SBOX**

| Parameter | Nilai |
|---|---|
| properties | NL, DDT/DU, LAT/bias, derajat aljabar, SAC, titik tetap, bijektivitas |
| domain | exhaustive seluruh 2^n masukan |
| reference_values | nonlinearity=112; differential_uniformity=4; algebraic_degree=7; branch_number=5 |
| pass_criterion | nilai terukur = nilai acuan desain |
| variant | penuh |
| estimated_time | 0 detik (analitis) |

**M-KEYSIZE**

| Parameter | Nilai |
|---|---|
| key_parameters | block_bits=128; key_bits=128; sbox_bits=8; output_bits_per_op=128 |
| security_bits | 128 |
| min_security_bits | 112 |
| horizon | 2030 (≥128 bit untuk perlindungan setelah 2030) |
| reference | SP 800-57 Part 1 Rev.5 Tabel 2 & 4; SP 800-131A Rev.2 |
| variant | penuh |
| estimated_time | 0 detik (analitis) |

**M-DIFF**

| Parameter | Nilai |
|---|---|
| variant | ronde tereduksi |
| reduced_rounds | 2, 3 |
| full_rounds | 10 |
| samples_log2 | 18 |
| reduced_desc | Trail/distinguisher diferensial pada 2–3 ronde tereduksi |
| pass_criterion | serangan ronde tereduksi berhasil sesuai prediksi & tidak dapat diperluas ≥ 70% ronde |
| active_sbox_bound_4r | 25 |
| estimated_time | 12.27 detik |

**M-INT**

| Parameter | Nilai |
|---|---|
| variant | ronde tereduksi |
| reduced_rounds | 3, 4 |
| full_rounds | 10 |
| samples_log2 | 16 |
| reduced_desc | Integral 3–4 ronde (2^8 CP per Λ-set) + margin keamanan |
| pass_criterion | serangan ronde tereduksi berhasil sesuai prediksi & tidak dapat diperluas ≥ 70% ronde |
| chosen_plaintexts_per_lambda_set | 256 |
| estimated_time | 3.07 detik |

**M-LIN**

| Parameter | Nilai |
|---|---|
| variant | ronde tereduksi |
| reduced_rounds | 2, 3 |
| full_rounds | 10 |
| samples_log2 | 20 |
| reduced_desc | Aproksimasi linear 2–3 ronde tereduksi, verifikasi bias empiris |
| pass_criterion | serangan ronde tereduksi berhasil sesuai prediksi & tidak dapat diperluas ≥ 70% ronde |
| estimated_time | 49.08 detik |

**M-KAT**

| Parameter | Nilai |
|---|---|
| vector_sources | FIPS 197 Appendix B (Cipher Example), FIPS 197 Appendix C.1 (AES-128), SP 800-38A F.1.1 ECB-AES128 blok 1, SP 800-38A F.1.1 ECB-AES128 blok 2, SP 800-38A F.1.1 ECB-AES128 blok 3, SP 800-38A F.1.1 ECB-AES128 blok 4 |
| vector_count | 6 |
| additional_sources | NIST CAVP/ACVP response files untuk implementasi produk |
| pass_criterion | 100% vektor cocok (0 selisih bit) |
| reference_result | 6/6 (LULUS) pada core/ |
| variant | penuh |
| estimated_time | 0.01 detik |

**M-MCT**

| Parameter | Nilai |
|---|---|
| mct_outer_iterations | 100 |
| mct_inner_iterations | 1000 |
| mmt_messages | 10 |
| checkpoints | setiap iterasi luar (100 checkpoint) |
| pass_criterion | 100% checkpoint = implementasi referensi core/ |
| variant | penuh |
| estimated_time | 4.68 detik |

**M-SELFTEST**

| Parameter | Nilai |
|---|---|
| tests | POST KAT tiap algoritma, pairwise consistency (pkc/dss), continuous RNG test, error state injection |
| variant | penuh |
| estimated_time | 0 detik (analitis) |

## 7. Matriks Keterlacakan

| ID | Persyaratan | Objek | Metode uji | Rujukan | Kriteria lulus |
|---|---|---|---|---|---|
| K-01 | Perubahan 1 bit masukan/kunci mengubah ≈ 50% bit keluaran | C-DIFF Lapisan difusi (ShiftRows + MixColumns); C-KS Key schedule | M-AVAL (penuh) | ISO 18367 | rerata 0,5 ± 0,01; tiap bit 0,5 ± 0,05 |
| K-02 | Tidak ada karakteristik diferensial ronde penuh dengan probabilitas > 2^-k | C-DIFF Lapisan difusi (ShiftRows + MixColumns); C-ROUND Fungsi ronde & jumlah ronde; C-SBOX S-box (SubBytes) | M-DIFF (tereduksi) | ISO 18033-3, ISO 15408 | batas bawah S-box aktif × DP_max ≤ 2^-128 (≥ 4 ronde) |
| K-03 | Lapisan difusi mencapai difusi penuh dengan margin ronde memadai | C-DIFF Lapisan difusi (ShiftRows + MixColumns) | M-DIFFUSION (penuh) | ISO 18033-3, ISO 18033-4, FIPS 202 | branch number optimal; avalanche ≈ 0,5 sebelum ≤ 1/2 jumlah ronde |
| K-04 | Margin keamanan ronde memadai terhadap serangan struktural | C-DIFF Lapisan difusi (ShiftRows + MixColumns); C-ROUND Fungsi ronde & jumlah ronde | M-INT (tereduksi) | ISO 15408 | serangan hanya berhasil pada ≤ 70% ronde |
| K-05 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | C-KEY Ukuran kunci | M-KEYSIZE (penuh) | SP 800-57, SP 800-131A | security_bits ≥ 112 |
| K-06 | Tidak ada aproksimasi linear ronde penuh dengan korelasi > 2^-64 | C-DIFF Lapisan difusi (ShiftRows + MixColumns); C-ROUND Fungsi ronde & jumlah ronde; C-SBOX S-box (SubBytes) | M-LIN (tereduksi) | ISO 18033-3, ISO 15408 | korelasi trail ≤ 2^-64 (≥ 4 ronde) |
| K-07 | Nonce tidak pernah berulang dan tidak bias | C-MODE Mode operasi & pengelolaan counter/nonce | M-NONCE (penuh) | FIPS 186-5, RFC 6979, SP 800-90A, SP 800-38A, RFC 8439 | 0 duplikasi; χ² MSB p-value ≥ 0,01 (≥ 4096 sampel) |
| K-08 | RBG yang dipakai disetujui (SP 800-90A) dengan entropi memadai | C-RNG Sumber acak (RBG) | M-RNG (penuh) | SP 800-90A, SP 800-90B, ISO 18031, SP 800-22 | min-entropy ≥ nilai klaim (SP 800-90B); SP 800-22 lulus |
| K-09 | Komponen nonlinear memenuhi batas acuan NL/DU/derajat | C-SBOX S-box (SubBytes) | M-SBOX (penuh) | ISO 18033-3, FIPS 197, FIPS 202 | NL, DU, derajat = nilai acuan desain |
| K-10 | Keluaran (keystream/CTR/digest berantai) tak terbedakan dari acak | C-MODE Mode operasi & pengelolaan counter/nonce | M-SP80022 (penuh) | SP 800-22 | proporsi lulus ≥ ambang SP 800-22 & P-value_T ≥ 0,0001 tiap uji |
| I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | C-API Antarmuka API & validasi masukan | M-FUZZ (penuh) | ISO 29119, ISO 18045 | 0 crash; 100% masukan invalid ditolak dengan galat terdefinisi |
| I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | C-CONF Kesesuaian implementasi keseluruhan; C-SELFTEST Self-test & error state modul | M-KAT (penuh) | ISO 18367, ISO 24759 | 100% vektor cocok |
| I-03 | Implementasi konsisten pada iterasi berantai & pesan multi-blok | C-CONF Kesesuaian implementasi keseluruhan; C-SELFTEST Self-test & error state modul | M-MCT (penuh) | ISO 18367, ISO 24759 | 100% checkpoint cocok dengan implementasi referensi |
| I-04 | Power-on self-test (KAT) & conditional test (pairwise) berjalan; error state memblokir layanan | C-CONF Kesesuaian implementasi keseluruhan; C-SELFTEST Self-test & error state modul | M-SELFTEST (penuh) | ISO 19790, ISO 24759 | semua self-test terpicu & error state tervalidasi |
| I-05 | Waktu eksekusi tidak bergantung pada data rahasia | C-IMPL-TBL Implementasi berbasis tabel (lookup); C-PLAT Platform eksekusi (CPU x86-64 bercache, speculative execution) | M-TIMING (penuh) | ISO 17825, ISO 20085 | \|t\| < 4,5 pada ≥ 10^6 pengukuran |
| I-06 | Kunci/CSP dihapus dari memori setelah dipakai | C-MEM Pengelolaan material kunci di memori | M-ZEROIZE (penuh) | ISO 19790, ISO 24759 | 0 salinan kunci pada dump memori |

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

KAT rinci (AES-128):

| Vektor | Sumber | Hasil |
|---|---|---|
| FIPS197-B | FIPS 197 Appendix B (Cipher Example) | LULUS |
| FIPS197-C.1 | FIPS 197 Appendix C.1 (AES-128) | LULUS |
| SP800-38A-F.1.1-b1 | SP 800-38A F.1.1 ECB-AES128 blok 1 | LULUS |
| SP800-38A-F.1.1-b2 | SP 800-38A F.1.1 ECB-AES128 blok 2 | LULUS |
| SP800-38A-F.1.1-b3 | SP 800-38A F.1.1 ECB-AES128 blok 3 | LULUS |
| SP800-38A-F.1.1-b4 | SP 800-38A F.1.1 ECB-AES128 blok 4 | LULUS |
