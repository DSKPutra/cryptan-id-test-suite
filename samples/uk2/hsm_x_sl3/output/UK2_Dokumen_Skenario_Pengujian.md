# Dokumen Skenario Pengujian — HSM-X

**Cryptan.ID Test Suite** · Modul **UK-2** · Unit J.61KRP00.013.1 — *Menyusun Skenario Pengujian* · SKKNI 2023-004 (Cryptographic Analyst)

Dibangkitkan 2026-10-01T13:47:19+07:00 · model 4 tingkat · masukan UK-1: `samples/uk2/hsm_x_sl3/uk1_stub.json`

> Objek uji & data produk ILUSTRATIF. HASIL UJI LANGSUNG = dihitung kode; LITERATUR/ACUAN = dikutip dengan rujukan; PERLU_VERIFIKASI = belum dapat dihitung/dicocokkan, tidak dikarang.

## Ringkasan

- Objek uji: **8** kombinasi · kategori: block, hash, pke, signature
- Metode UK-1 ditelaah: 9 (relevan 9) · sel kosong diisi templat: 32
- Skenario: **16** · test case: **53** (K 17 · S 19 · I 17)
- Verifikasi terhadap spesifikasi desain: **LULUS** (0 temuan)
- Expected value: 1 cocok vektor resmi · 145 kriteria · 10 PERLU_VERIFIKASI

## 1. Profil Objek Uji & Ruang Parameter

| Atribut | Nilai |
|---|---|
| Produk | HSM-X 1.0 (ilustratif) |
| Deskripsi | Modul perangkat keras multi-chip standalone (HSM jaringan) |
| Jenis produk | hsm |
| Model tingkat | 4 (Unit → Integrasi → Sistem → UAT) |
| SL ISO/IEC 19790 | 3 |
| Fitur | aead, api, audit_log, backup_restore, cluster_failover, debug_build, dual_control, entropy_source, environmental_failure_protection, error_codes, firmware_update, fuzzing_harness, kem, key_wrap, keygen, kmip, load_testing, physical_access, pkcs11, power_glitch, pqc_hybrid, reproducible_build, rng_internal, roles_identity_auth, self_tests, side_channel_lab, signature, source_code, split_knowledge, tamper_response |

**Klaim keamanan:**

| ID | Klaim | Tag |
|---|---|---|
| C-SL3 | ISO/IEC 19790 Tingkat Keamanan 3 | iso19790_sl3 |
| C-SSP | CSP hanya keluar terenkripsi dengan kunci approved; split knowledge untuk entri manual | ssp_protection |
| C-TAMPER | Tamper evidence & response dengan zeroisation | tamper |
| C-AUTH | Autentikasi berbasis identitas; dual control operasi kritis | identity_auth, dual_control |
| C-FW | Hanya firmware bertanda tangan sah dengan versi ≥ saat ini yang dimuat | firmware_integrity |

**Objek uji (algorithms_under_test):**

| ID | Kategori | Varian | Kunci | Strength | Status NIST |
|---|---|---|---|---|---|
| AES-256-GCM | block | GCM | 256 | 256 | acceptable |
| AES-256-KW | block | KW | 256 | 256 | acceptable |
| SHA-384 | hash | SHA-384 | — | 192 | acceptable |
| HMAC-SHA-384-K384 | hash | SHA-384 | 384 | 384 | acceptable |
| ECDSA-P384 | signature | P-384 | 384 | 192 | acceptable |
| ML-KEM-768 | pke | ML-KEM-768 | — | 192 | acceptable |
| ML-DSA-65 | signature | ML-DSA-65 | — | 192 | acceptable |
| CTR-DRBG-AES-256 | rng | CTR_DRBG | 256 | 256 | acceptable |

### 1.1 Ruang parameter — block

| ID | Parameter | Kelas | Status | Nilai uji (teknik) |
|---|---|---|---|---|
| BC-KEY-LEN | Panjang kunci | Parameter publik/domain | Tetap | 0 [BVA, NEG]; 248 [BVA, NEG]; 256 [EP]; 264 [BVA, NEG] |
| BC-KEY-VAL | Nilai kunci | Material rahasia | Variabel | acak (DRBG) [EP]; nol-semua (0x00…) [DEG]; satu-semua (0xFF…) [DEG]; low-density (HW = 1) [DEG]; high-density (HW = n−1) [DEG]; related-key (beda 1 bit) [BIT]; kunci lemah/semi-lemah (bila ada) [DEG] |
| BC-PT | Blok plaintext | Data masukan | Variabel | acak [EP]; nol-semua (0x00…) [DEG]; satu-semua (0xFF…) [DEG]; low-density (HW = 1) [DEG]; high-density (HW = n−1) [DEG]; periodik (0x55/0xAA) [DEG]; 1-bit flip pada tiap posisi (n = 128) [BIT] |
| BC-MODE | Mode operasi | Konfigurasi | Variabel | CBC [EP, NEG]; CTR [EP, NEG]; ECB [EP, NEG]; GCM [EP]; KW [EP]; XTS [EP, NEG] |
| BC-IV | IV/nonce | Material rahasia | Variabel | acak 96 bit [EP]; counter berurutan [EP]; nol [DEG, NEG]; berulang (reuse) [NEG, NEG]; dapat diprediksi (CBC) [NEG, NEG]; panjang non-96 bit (GCM) [BVA] |
| BC-LEN | Panjang pesan & padding | Data masukan | Variabel | 0 [BVA]; 1 [BVA]; 15 [BVA]; 16 [BVA]; 17 [BVA]; 1048576 [EP] |
| BC-ROUNDS | Jumlah ronde | Konfigurasi | Variabel | penuh (10/12/14) [EP]; tereduksi 2–4 ronde (analisis) [BVA] |
| ENV | Kondisi operasional | Kondisi lingkungan | Tetap | normal [EP] |

Reduksi pairwise (t = 2. IPOG) atas 4 parameter Variabel: **168** kombinasi penuh → **42** kombinasi pairwise (75.0% berkurang; semua pasangan tercakup: True).

### 1.2 Ruang parameter — hash

| ID | Parameter | Kelas | Status | Nilai uji (teknik) |
|---|---|---|---|---|
| HF-LEN-SHA-384 | Panjang pesan SHA-384 (b = 128 B) | Data masukan | Variabel | 0 [BVA]; 1 [BVA]; 111 [BVA]; 112 [BVA]; 127 [BVA]; 128 [BVA]; 129 [BVA]; 1048576 [EP]; 104857600 [EP] |
| HF-PAT | Pola pesan | Data masukan | Variabel | acak [EP]; nol-semua (0x00…) [DEG]; satu-semua (0xFF…) [DEG]; low-density (HW = 1) [DEG]; high-density (HW = n−1) [DEG]; periodik (0x55/0xAA) [DEG]; beda 1 bit [BIT] |
| HF-DIG | Panjang digest | Konfigurasi | Variabel | penuh [EP]; terpotong t = 128 bit [EP]; XOF 256/512 bit [EP]; terpotong t = 32 bit (analisis birthday) [BVA] |
| HF-CHUNK | Pemecahan input | Konfigurasi | Variabel | one-shot [EP]; update bertahap acak (1…b+7 byte) [EP] |
| HF-ROUNDS | Jumlah ronde | Konfigurasi | Variabel | penuh [EP]; tereduksi (analisis) [BVA] |
| HF-KEY | Kunci/salt (HMAC, KDF) | Material rahasia | Variabel | kunci < blok [BVA]; kunci = blok [BVA]; kunci > blok (di-hash dulu) [BVA]; kunci 0 byte [NEG, NEG] |
| ENV | Kondisi operasional | Kondisi lingkungan | Tetap | normal [EP] |

Reduksi pairwise (t = 2. IPOG) atas 5 parameter Variabel: **1.008** kombinasi penuh → **63** kombinasi pairwise (93.8% berkurang; semua pasangan tercakup: True).

### 1.3 Ruang parameter — pke

| ID | Parameter | Kelas | Status | Nilai uji (teknik) |
|---|---|---|---|---|
| PK-DOM | Ukuran kunci & domain | Parameter publik/domain | Tetap | ML-KEM-768 [EP] |
| PK-KEYGEN | Kualitas pembangkitan kunci | Material rahasia | Tetap | DRBG produk (normal) [EP]; entropi rendah (simulasi, batch-GCD) [NEG, NEG] |
| PK-PAD | Skema padding | Konfigurasi | Tetap | OAEP (SHA-256/MGF1) [EP, NEG]; PKCS#1 v1.5 [NEG, NEG]; FO transform (KEM) [EP] |
| PK-CT | Ciphertext masukan | Data masukan | Tetap | valid [EP]; termodifikasi 1 bit [BIT, NEG]; malformed (panjang ±1) [NEG, NEG]; di luar rentang (c ≥ n) [BVA, NEG] |
| PK-PEER | Kunci publik lawan | Data masukan | Tetap | valid [EP]; titik tidak di kurva [NEG, NEG]; subgrup kecil / low-order [NEG, NEG]; titik tak hingga [BVA, NEG] |
| ENV | Kondisi operasional | Kondisi lingkungan | Tetap | normal [EP] |

Reduksi pairwise (t = 2. IPOG) atas 0 parameter Variabel: **0** kombinasi penuh → **0** kombinasi pairwise (0.0% berkurang; semua pasangan tercakup: True).

### 1.4 Ruang parameter — signature

| ID | Parameter | Kelas | Status | Nilai uji (teknik) |
|---|---|---|---|---|
| DS-ALG | Kurva & hash / parameter set | Parameter publik/domain | Variabel | ECDSA-P384 [EP]; ML-DSA-65 [EP] |
| DS-NONCE | Mode nonce | Konfigurasi | Tetap | rfc6979 [EP]; bias beberapa bit (simulasi) [NEG, NEG]; berulang (simulasi) [NEG, NEG] |
| DS-MSG | Panjang pesan | Data masukan | Variabel | 0 [BVA]; 1 [BVA]; 55 [BVA]; 56 [BVA]; 63 [BVA]; 64 [BVA]; 65 [BVA]; 1048576 [EP]; 104857600 [EP] |
| DS-D | Kunci privat d | Material rahasia | Variabel | acak [EP]; Hamming weight rendah [DEG]; Hamming weight tinggi [DEG]; d = 1 [BVA]; d = n − 1 [BVA]; d = 0 [BVA, NEG]; d = n [BVA, NEG] |
| DS-ENC | Encoding (r, s) | Data masukan | Variabel | DER kanonik [EP]; DER non-kanonik [NEG, NEG]; r atau s = 0 [BVA, NEG]; r atau s ≥ n [BVA, NEG]; s ↔ n − s [NEG] |
| DS-Q | Kunci publik Q | Data masukan | Tetap | valid [EP]; titik tak hingga O [BVA, NEG]; di luar kurva [NEG, NEG]; koordinat ≥ p [BVA, NEG] |
| DS-N | Ukuran sampel | Konfigurasi | Variabel | N = 1.000.000 tanda tangan (uji nonce) [EP]; 100.000 trace/pengukuran (side-channel) [EP] |
| DS-PQC | Parameter PQC & state | Parameter publik/domain | Tetap | ML-DSA-65 [EP]; indeks OTS dipakai ulang (stateful) [NEG, NEG] |
| ENV | Kondisi operasional | Kondisi lingkungan | Tetap | normal [EP] |

Reduksi pairwise (t = 2. IPOG) atas 4 parameter Variabel: **72** kombinasi penuh → **18** kombinasi pairwise (75.0% berkurang; semua pasangan tercakup: True).

### 1.5 Ruang parameter — module

| ID | Parameter | Kelas | Status | Nilai uji (teknik) |
|---|---|---|---|---|
| M-SL | Tingkat keamanan target | Parameter publik/domain | Tetap | SL 1 [EP, NEG]; SL 2 [EP, NEG]; SL 3 [EP]; SL 4 [EP, NEG] |
| M-ALG | Parameter algoritma | Parameter publik/domain | Variabel | AES-256-GCM [EP]; AES-256-KW [EP]; SHA-384 [EP]; HMAC-SHA-384-K384 [EP]; ECDSA-P384 [EP]; ML-KEM-768 [EP]; ML-DSA-65 [EP]; CTR-DRBG-AES-256 [EP]; IV GCM non-96 bit [BVA]; tag 96 bit [BVA]; parameter non-approved [NEG, NEG] |
| M-ENT | Kondisi sumber entropi | Kondisi lingkungan | Variabel | normal [EP]; suhu batas operasi [BVA]; sumber dirusak/macet [NEG, NEG] |
| M-ROLE | Peran & kredensial | Material rahasia | Variabel | Crypto Officer [EP]; User [EP]; tanpa autentikasi [EP]; kredensial salah [NEG, NEG]; kedaluwarsa [NEG, NEG]; berulang (brute force) [NEG, NEG] |
| M-STATE | Status modul | Konfigurasi | Variabel | power-up [EP]; operasional [EP]; galat [EP]; degraded [EP]; update firmware [EP] |
| M-SSP | Metode entri/output SSP | Konfigurasi | Variabel | plaintext [EP, NEG]; terbungkus AES-KW [EP]; split knowledge N-dari-M [EP] |
| M-PHYS | Kondisi fisik & lingkungan | Kondisi lingkungan | Tetap | normal [EP]; tutup dibuka [NEG, NEG]; pengeboran [NEG, NEG]; probing [NEG, NEG]; suhu/tegangan di luar rentang [BVA, NEG] |
| M-TRACE | Kuantitas trace side-channel | Konfigurasi | Variabel | 10000 [EP]; 100000 [EP]; 1000000 [EP] |

Reduksi pairwise (t = 2. IPOG) atas 6 parameter Variabel: **1.800** kombinasi penuh → **50** kombinasi pairwise (97.2% berkurang; semua pasangan tercakup: True).

## 2. Telaah Metode & Parameter (KUK 1.1, 1.2)

Empat kebutuhan pengujian SKKNI: N1 jenis algoritma · N2 desain & teknik implementasi · N3 tren serangan · N4 best practice.

| Metode | Sel (tingkat × lapis) | N1 | N2 | N3 | N4 | Asal UK-1 | Putusan |
|---|---|---|---|---|---|---|---|
| M-KAT Known Answer Test | Unit × K | ✔ | ✔ | ✔ | ✔ | HSM-X (STUB_UK1) | RELEVAN |
| M-SELFTEST Self-test & error state | Sistem × I | ✔ | ✔ | ✔ | ✔ | HSM-X (STUB_UK1) | RELEVAN |
| M-RNG Asesmen sumber entropi | Integrasi × I | ✔ | ✔ | ✔ | ✔ | HSM-X (STUB_UK1) | RELEVAN |
| M-ZEROIZE Zeroisation | Sistem × I | ✔ | ✔ | ✔ | ✔ | HSM-X (STUB_UK1) | RELEVAN |
| M-TVLA TVLA | Sistem × I | ✔ | ✔ | ✔ | ✔ | HSM-X (STUB_UK1) | RELEVAN |
| M-FAULT Fault injection | Sistem × I | ✔ | ✔ | ✔ | ✔ | HSM-X (STUB_UK1) | RELEVAN |
| M-CODEREVIEW Static analysis / review kode | Unit × I | ✔ | ✔ | ✔ | ✔ | HSM-X (STUB_UK1) | RELEVAN |
| M-FUZZ Fuzzing | Integrasi × I | ✔ | ✔ | ✔ | ✔ | HSM-X (STUB_UK1) | RELEVAN |
| M-TIMING Constant-time | Integrasi × I | ✔ | ✔ | ✔ | ✔ | HSM-X (STUB_UK1) | RELEVAN |

Sel kosong (32) diisi dari templat kategori materi: block:Unit×S, block:Integrasi×K, block:Integrasi×S, block:Sistem×K, block:Sistem×S, block:UAT×K, block:UAT×S, block:UAT×I, hash:Unit×S, hash:Integrasi×K, hash:Integrasi×S, hash:Sistem×K, hash:Sistem×S, hash:UAT×K, hash:UAT×S, hash:UAT×I, pke:Unit×S, pke:Integrasi×K, pke:Integrasi×S, pke:Sistem×K, pke:Sistem×S, pke:UAT×K, pke:UAT×S, pke:UAT×I, signature:Unit×S, signature:Integrasi×K, signature:Integrasi×S, signature:Sistem×K, signature:Sistem×S, signature:UAT×K…

Teknik penetapan nilai uji: EP = Partisi ekuivalensi; BVA = Analisis nilai batas; DEG = Input degeneratif/berpola; BIT = Variasi 1-bit (diferensial); TWAY = Kombinatorial t-way (pairwise); NEG = Negative testing

## 3. Matriks Skenario Lapis × Tingkat (KUK 2.1)

**module**

| Tingkat | Uji Kesesuaian | Uji Keamanan | Uji Implementasi |
|---|---|---|---|
| Unit | SCN-M-UNI-K: U-K-01, U-K-02, U-K-03, U-K-04 | SCN-M-UNI-S: U-S-01, U-S-02, U-S-03, U-S-04 | SCN-M-UNI-I: U-I-01, U-I-02, U-I-03, U-I-04 |
| Integrasi | SCN-M-INT-K: I-K-01, I-K-02, I-K-03, I-K-04 | SCN-M-INT-S: I-S-01, I-S-02, I-S-03, I-S-04 | SCN-M-INT-I: I-I-01, I-I-02, I-I-03, I-I-04 |
| Sistem | SCN-M-SIS-K: S-K-01, S-K-02, S-K-03, S-K-04 | SCN-M-SIS-S: S-S-01, S-S-02, S-S-03, S-S-04 | SCN-M-SIS-I: S-I-01, S-I-02, S-I-03, S-I-04 |
| UAT | SCN-M-UAT-K: A-K-01, A-K-02, A-K-03, A-K-04 | SCN-M-UAT-S: A-S-01, A-S-02, A-S-03, A-S-04 | SCN-M-UAT-I: A-I-01, A-I-02, A-I-03, A-I-04 |

**cross**

| Tingkat | Uji Kesesuaian | Uji Keamanan | Uji Implementasi |
|---|---|---|---|
| Integrasi | SCN-XA-INT-K: XA-K-01 | SCN-XA-INT-S: XA-S-01 | — |
| Sistem | — | SCN-XA-SIS-S: XA-S-02, XA-S-03 | SCN-XA-SIS-I: XA-I-01 |

**Lintas-algoritma:** RNG / Sumber Entropi → Pembangkitan Kunci → KDF → Cipher / MAC / Signature → Protokol → Produk · skenario: XA-K-01, XA-S-01, XA-S-02, XA-I-01, XA-S-03 · PQC relevan: True

**Resep tidak berlaku (fitur/objek tidak dimiliki produk — aturan f):**

| Resep | Alasan |
|---|---|
| XA-S-04 | fitur produk tidak ada: timing_measurement |

**Pemetaan area ISO/IEC 19790:**

| Area | Unit | Integrasi | Sistem | UAT |
|---|---|---|---|---|
| 7.2 | U-K-01, U-K-02, U-S-02 | I-K-02 | S-K-01 | A-K-03, A-S-04 |
| 7.3 | U-I-03 | I-I-04, I-S-01 | S-K-02 | A-K-02, A-K-04 |
| 7.4 | U-S-04 | I-K-01, I-S-03 | — | A-S-01 |
| 7.5 | U-I-02 | I-S-04 | — | A-I-03 |
| 7.6 | — | — | S-I-02 | — |
| 7.7 | — | — | S-S-01, S-S-02 | A-S-02 |
| 7.8 | U-I-01 | I-I-02 | S-I-01 | — |
| 7.9 | U-K-03, U-S-01, U-S-03 | I-K-03, I-S-02 | S-S-03 | A-K-01, A-S-03 |
| 7.10 | U-K-04 | I-K-04 | S-K-04 | — |
| 7.11 | — | I-I-01 | S-I-04, S-K-03 | A-I-04 |
| 7.12 | U-I-04 | I-I-03 | S-S-04 | — |

## 4. Laporan Verifikasi terhadap Spesifikasi Desain (KUK 2.2 — aspek kritis)

Status keseluruhan: **LULUS** · 0 temuan

| Aturan | Deskripsi | Diperiksa | Status | Temuan |
|---|---|---|---|---|
| (a) | Cakupan algoritma, varian, panjang kunci, mode & parameter set profil | 8 | LULUS | — |
| (b) | Nilai di luar spesifikasi hanya sebagai negative test (harapan ditolak) | 4 | LULUS | — |
| (c) | Setiap klaim keamanan punya ≥ 1 skenario Uji Keamanan | 5 | LULUS | — |
| (d) | Setiap metode UK-1 punya ≥ 1 skenario | 9 | LULUS | — |
| (e) | Modul: 11 area ISO/IEC 19790 (7.2–7.12) tercakup / dijustifikasi | 11 | LULUS | — |
| (f) | Tidak ada skenario untuk fitur/objek yang tidak dimiliki produk | 53 | LULUS | — |

## 5. Katalog Test Case (KUK 2.3)

### 5.1 Uji Kesesuaian

| ID | Tingkat | Area | Parameter & nilai uji | Prosedur | Kriteria lulus | Metode UK-1 | Prioritas | Pelaksana |
|---|---|---|---|---|---|---|---|---|
| A-K-01 | UAT | 7.9 | Key ceremony root CA: pembangkitan dan backup kunci | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Pelaksanaan seremoni oleh pengguna sesuai SOP (area 7.9) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Sesuai SOP dan security policy | M-ZEROIZE | Sedang | Pengguna / pemilik proses bisnis bersama penguji |
| A-K-02 | UAT | 7.3 | Aplikasi pengguna melalui PKCS#11/KMIP | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Uji dengan aplikasi bisnis nyata (area 7.3) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruh fungsi yang dibutuhkan tersedia | M-KAT | Sedang | Pengguna / pemilik proses bisnis bersama penguji |
| A-K-03 | UAT | 7.2 | Konfigurasi algoritma terhadap kebijakan organisasi dan regulasi nasional | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Audit konfigurasi produksi (area 7.2) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Hanya algoritma yang diizinkan aktif | M-KEYSIZE | Sedang | Pengguna / pemilik proses bisnis bersama penguji |
| A-K-04 | UAT | 7.3 | Status output dan log audit | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Operator menafsirkan status dan log (area 7.3) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Status dan log dapat dipahami dan lengkap | M-SELFTEST | Sedang | Pengguna / pemilik proses bisnis bersama penguji |
| I-K-01 | Integrasi | 7.4 | Setiap layanan × peran (CO, User, tanpa autentikasi) | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Panggil seluruh layanan; bandingkan dengan tabel layanan pada security policy (area 7.4) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Akses sesuai matriks peran–layanan | M-SELFTEST | Sedang | Tim verifikasi internal |
| I-K-02 | Integrasi | 7.2 | Layanan approved vs non-approved | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Periksa indikator mode approved pada tiap layanan (area 7.2) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Indikator benar untuk setiap layanan | M-KEYSIZE | Sedang | Tim verifikasi internal |
| I-K-03 | Integrasi | 7.9 | Siklus SSP: generate → store → use → wrap/export → zeroise | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Uji alur lintas unit manajer kunci, key store, dan engine (area 7.9) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Setiap transisi sesuai security policy | M-ZEROIZE | Sedang | Tim verifikasi internal |
| I-K-04 | Integrasi | 7.10 | Urutan self-test pra-operasional; PCT saat KeyGen; uji pemuatan firmware | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Amati status output dan log saat boot dan KeyGen (area 7.10) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada output data sebelum self-test lulus | M-SELFTEST | Sedang | Tim verifikasi internal |
| S-K-01 | Sistem | 7.2 | Batas kriptografis dan komponen yang dikecualikan | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Inspeksi fisik dan dokumen terhadap security policy (area 7.2) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Sesuai deklarasi | M-SELFTEST | Sedang | Laboratorium uji terakreditasi (ISO/IEC 17025) |
| S-K-02 | Sistem | 7.3 | Seluruh antarmuka fisik dan logis; trusted channel | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Uji pemisahan dan pemetaan antarmuka (area 7.3) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada jalur tak terdokumentasi | M-SELFTEST | Sedang | Laboratorium uji terakreditasi (ISO/IEC 17025) |
| S-K-03 | Sistem | 7.11 | Panduan instalasi dan inisialisasi | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Instal dan inisialisasi hanya dengan panduan (area 7.11) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Modul mencapai mode approved | M-SELFTEST | Sedang | Laboratorium uji terakreditasi (ISO/IEC 17025) |
| S-K-04 | Sistem | 7.10 | Self-test periodik dan on-demand saat beban tinggi | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Jalankan self-test selama operasi berbeban (area 7.10) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Test berjalan; layanan tertahan sesuai kebijakan | M-SELFTEST | Sedang | Laboratorium uji terakreditasi (ISO/IEC 17025) |
| U-K-01 | Unit | 7.2 | Engine AES-256-GCM: KAT; IV 96 & non-96 bit; AAD 0/1/16/65 byte; tag 128 bit | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Eksekusi vektor uji pada unit engine terisolasi (ISO/IEC 18367) (area 7.2) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Hasil identik 100% | M-KAT | Tinggi | Pengembang / tim verifikasi internal |
| U-K-02 | Unit | 7.2 | ECDSA P-384 dan ML-DSA-65: vektor KeyGen/SigGen/SigVer valid dan invalid | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Eksekusi vektor pada unit tanda tangan (area 7.2) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Valid diterima; seluruh invalid ditolak | M-KAT | Tinggi | Pengembang / tim verifikasi internal |
| U-K-03 | Unit | 7.9 | CTR_DRBG AES-256: instantiate, reseed, generate; additional input 0/256 bit | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Bandingkan keluaran dengan vektor acuan DRBG (area 7.9) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Keluaran identik 100% | M-KAT, M-RNG | Sedang | Pengembang / tim verifikasi internal |
| U-K-04 | Unit | 7.10 | Rutin CAST dan uji integritas firmware; nilai acuan benar vs dirusak 1 bit | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Jalankan rutin self-test dengan kedua kondisi (area 7.10) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Kondisi rusak selalu menghasilkan status galat | M-SELFTEST | Sedang | Pengembang / tim verifikasi internal |
| XA-K-01 | Integrasi | — | AES-256-GCM, AES-256-KW, SHA-384, HMAC-SHA-384-K384 | 1. Jalankan alur end-to-end dengan data uji tetap 2. Periksa endianness, encoding (DER/raw), panjang parameter & kode galat antar-komponen 3. Bandingkan keluaran tiap tahap dengan referensi 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Format & kode galat konsisten di seluruh rantai | M-KAT | Sedang | Tim verifikasi internal |

### 5.2 Uji Keamanan

| ID | Tingkat | Area | Parameter & nilai uji | Prosedur | Kriteria lulus | Metode UK-1 | Prioritas | Pelaksana |
|---|---|---|---|---|---|---|---|---|
| A-S-01 | UAT | 7.4 | Pemisahan tugas dan dual control pada operasi kritis | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Latihan operasional dengan peran nyata (area 7.4) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada satu orang yang dapat bertindak sendiri | M-SELFTEST | Sedang | Pengguna / pemilik proses bisnis bersama penguji |
| A-S-02 | UAT | 7.7 | Insiden: tamper, kehilangan kartu kustodian, kompromi kredensial | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Tabletop exercise dan simulasi (area 7.7) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Prosedur respons berjalan; kunci dapat dicabut/dipulihkan | M-ZEROIZE | Sedang | Pengguna / pemilik proses bisnis bersama penguji |
| A-S-03 | UAT | 7.9 | Backup dan restore kunci terbungkus ke HSM cadangan | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Uji pemulihan bencana (area 7.9) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Pulih tanpa CSP plaintext keluar | M-ZEROIZE | Sedang | Pengguna / pemilik proses bisnis bersama penguji |
| A-S-04 | UAT | 7.2 | Rollout ML-DSA/ML-KEM dan mode hybrid pada aplikasi | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Uji pilot transisi PQC (area 7.2) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Aplikasi berjalan; interoperabilitas terjaga | M-KEYSIZE | Sedang | Pengguna / pemilik proses bisnis bersama penguji |
| I-S-01 | Integrasi | 7.3 | Status galat dipicu (self-test gagal, sensor aktif) | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Minta layanan kriptografi saat status galat (area 7.3) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Data output interface terhambat | M-SELFTEST | Tinggi | Tim verifikasi internal |
| I-S-02 | Integrasi | 7.9 | Ekspor kunci: plaintext, terbungkus AES-KW, kunci pembungkus lemah | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Coba ekspor melalui API (area 7.9) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | CSP hanya keluar terenkripsi dengan kunci approved | M-ZEROIZE | Tinggi | Tim verifikasi internal |
| I-S-03 | Integrasi | 7.4 | Brute-force kredensial, sesi paralel, percobaan eskalasi peran | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Serangan logis terhadap alur autentikasi (area 7.4) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Lockout/penundaan aktif; tanpa eskalasi peran | M-FUZZ | Sedang | Tim verifikasi internal |
| I-S-04 | Integrasi | 7.5 | Image firmware: tanda tangan valid, invalid, versi lama (rollback) | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Muat image melalui mekanisme update (area 7.5) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Hanya image sah dengan versi ≥ saat ini diterima | M-SELFTEST | Tinggi | Tim verifikasi internal |
| S-S-01 | Sistem | 7.7 | Pembukaan tutup, pengeboran, probing enclosure | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Serangan fisik terhadap tamper evidence dan response (area 7.7) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Terdeteksi; SSP ter-zeroise seketika | M-FAULT | Tinggi | Laboratorium uji terakreditasi (ISO/IEC 17025) |
| S-S-02 | Sistem | 7.7 | Suhu dan tegangan di luar rentang operasi | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Uji EFP/EFT sesuai tingkat keamanan target (area 7.7) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Shutdown/zeroise tanpa kompromi SSP | M-FAULT | Sedang | Laboratorium uji terakreditasi (ISO/IEC 17025) |
| S-S-03 | Sistem | 7.9 | Entri SSP manual split knowledge; kustodian kurang dari kuorum | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Impor kunci dengan jumlah kustodian bervariasi (area 7.9) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Kunci hanya terbentuk bila kuorum terpenuhi | M-ZEROIZE | Tinggi | Laboratorium uji terakreditasi (ISO/IEC 17025) |
| S-S-04 | Sistem | 7.12 | Serangan lain yang diklaim dimitigasi | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Evaluasi terhadap klaim pada security policy (area 7.12) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Mitigasi efektif sesuai klaim | M-FAULT | Sedang | Laboratorium uji terakreditasi (ISO/IEC 17025) |
| U-S-01 | Unit | 7.9 | Sumber entropi fisik: 10^6 sampel mentah; suhu normal dan batas operasi | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Estimasi min-entropi; uji kesehatan (repetition count, adaptive proportion) (area 7.9) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Min-entropi ≥ klaim; kegagalan injeksi terdeteksi | M-RNG | Sedang | Pengembang / tim verifikasi internal |
| U-S-02 | Unit | 7.2 | Panjang kunci, kurva, dan parameter set di luar daftar approved | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Panggil fungsi dengan parameter non-approved (area 7.2) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Ditolak atau ditandai non-approved | M-KEYSIZE | Sedang | Pengembang / tim verifikasi internal |
| U-S-03 | Unit | 7.9 | Fungsi zeroise untuk SSP 16 byte–4 KB di RAM dan flash | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Panggil zeroise lalu periksa memori (build debug) (area 7.9) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada sisa SSP | M-ZEROIZE | Sedang | Pengembang / tim verifikasi internal |
| U-S-04 | Unit | 7.4 | Verifikasi kredensial: panjang min/maks, karakter, percobaan berulang | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Uji unit fungsi autentikasi dan penghitung percobaan (area 7.4) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Kekuatan autentikasi sesuai batas yang ditetapkan | M-FUZZ | Sedang | Pengembang / tim verifikasi internal |
| XA-S-01 | Integrasi | — | AES-256-GCM, AES-256-KW, SHA-384, HMAC-SHA-384-K384 | 1. Kumpulkan keluaran DRBG produk 2. Estimasi min-entropi (SP 800-90B) & SP 800-22 3. Gagalkan sumber entropi (simulasi) dan pastikan keygen berhenti 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Min-entropi ≥ klaim; uji statistik lolos; kegagalan hulu terdeteksi | M-RNG | Tinggi | Tim verifikasi internal |
| XA-S-02 | Sistem | — | AES-256-GCM, AES-256-KW, SHA-384, HMAC-SHA-384-K384 | 1. Jalankan siklus lengkap untuk satu kunci tiap kelas primitif 2. Verifikasi kebijakan rotasi & batas penggunaan 3. Pastikan pemusnahan (zeroize) di akhir 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Setiap transisi sesuai kebijakan; kunci termusnahkan | M-ZEROIZE, M-KEYSIZE | Sedang | Laboratorium uji terakreditasi (ISO/IEC 17025) |
| XA-S-03 | Sistem | — | AES-256-GCM, AES-256-KW, SHA-384, HMAC-SHA-384-K384 | 1. Ganti algoritma rentan kuantum ke padanan PQC (ML-KEM/ML-DSA) melalui konfigurasi 2. Uji mode hybrid 3. Pastikan arsitektur & format tidak berubah 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Penggantian berhasil tanpa perubahan arsitektur; sesuai rencana IR 8547 | M-KEYSIZE | Sedang | Laboratorium uji terakreditasi (ISO/IEC 17025) |

### 5.3 Uji Implementasi

| ID | Tingkat | Area | Parameter & nilai uji | Prosedur | Kriteria lulus | Metode UK-1 | Prioritas | Pelaksana |
|---|---|---|---|---|---|---|---|---|
| A-I-01 | UAT | Pengguna | Beban puncak produksi | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Uji beban di lingkungan operasional (area Pengguna) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Memenuhi SLA | M-SELFTEST | Sedang | Pengguna / pemilik proses bisnis bersama penguji |
| A-I-02 | UAT | Pengguna | Failover, pemutusan daya, restart | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Uji ketersediaan operasional (area Pengguna) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | RTO/RPO tercapai | M-SELFTEST | Sedang | Pengguna / pemilik proses bisnis bersama penguji |
| A-I-03 | UAT | 7.5 | Update firmware di lapangan dan prosedur rollback | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Pelaksanaan prosedur pemeliharaan (area 7.5) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Berhasil tanpa kehilangan kunci | M-SELFTEST | Sedang | Pengguna / pemilik proses bisnis bersama penguji |
| A-I-04 | UAT | 7.11 | Kesalahan umum operator | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Observasi penggunaan oleh operator (area 7.11) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Kesalahan tidak menurunkan keamanan | M-SELFTEST | Sedang | Pengguna / pemilik proses bisnis bersama penguji |
| I-I-01 | Integrasi | 7.11 | Build dari repositori terkendali | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Bandingkan hash hasil build ulang dengan image rilis (area 7.11) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Hash identik (reproducible build) | M-CODEREVIEW | Sedang | Tim verifikasi internal |
| I-I-02 | Integrasi | 7.8 | Layanan signing ECDSA melalui API; 10^5 trace | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. TVLA pada layanan utuh (area 7.8) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | \|t\| < 4,5 | M-TVLA | Sedang | Tim verifikasi internal |
| I-I-03 | Integrasi | 7.12 | Glitch tegangan/clock saat verifikasi tanda tangan firmware | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Fault injection pada boot chain (area 7.12) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada bypass verifikasi | M-FAULT | Sedang | Tim verifikasi internal |
| I-I-04 | Integrasi | 7.3 | 10^6 urutan pemanggilan API menyimpang | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Fuzzing API stateful (area 7.3) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tanpa crash; state modul konsisten | M-FUZZ | Sedang | Tim verifikasi internal |
| S-I-01 | Sistem | 7.8 | Modul tertutup; SPA/DPA/EM; 10^6 trace | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Pengukuran eksternal sesuai ISO/IEC 17825 (area 7.8) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Di bawah metrik yang ditetapkan | M-TVLA | Sedang | Laboratorium uji terakreditasi (ISO/IEC 17025) |
| S-I-02 | Sistem | 7.6 | Lingkungan operasi terbatas; upaya memuat kode tak sah | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Uji kemampuan eksekusi kode di luar image sah (area 7.6) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Kode tak sah tidak dapat dijalankan | M-CODEREVIEW | Sedang | Laboratorium uji terakreditasi (ISO/IEC 17025) |
| S-I-03 | Sistem | Pengguna | Beban 1–10.000 operasi/detik; failover klaster | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Uji kinerja dan ketersediaan (area Pengguna) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Sesuai klaim kinerja | M-SELFTEST | Sedang | Laboratorium uji terakreditasi (ISO/IEC 17025) |
| S-I-04 | Sistem | 7.11 | Pengiriman: segel, kemasan, verifikasi integritas awal | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Simulasi penerimaan barang dengan kemasan dimanipulasi (area 7.11) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Manipulasi terdeteksi | M-SELFTEST | Sedang | Laboratorium uji terakreditasi (ISO/IEC 17025) |
| U-I-01 | Unit | 7.8 | Fungsi AES dan perkalian skalar P-384; fixed-vs-random; 10^5 trace | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. TVLA per fungsi pada board pengembangan (ISO/IEC 17825) (area 7.8) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | \|t\| < 4,5 | M-TVLA | Sedang | Pengembang / tim verifikasi internal |
| U-I-02 | Unit | 7.5 | Kode sumber firmware; aturan CERT C/MISRA C | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Static analysis dan pengukuran cakupan uji (area 7.5) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tanpa temuan tinggi; cakupan cabang ≥ target (mis. 90%) | M-CODEREVIEW | Sedang | Pengembang / tim verifikasi internal |
| U-I-03 | Unit | 7.3 | Parser perintah PKCS#11: 10^6 input malformed | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Fuzzing unit parser (area 7.3) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tanpa crash/hang; galat terdefinisi | M-FUZZ | Sedang | Pengembang / tim verifikasi internal |
| U-I-04 | Unit | 7.12 | Pembandingan PIN dan MAC; input benar vs salah pada posisi berbeda | 1. Siapkan modul pada status awal yang ditetapkan prasyarat 2. Uji waktu konstan (mis. dudect) (area 7.12) 3. Catat bukti (log, status output, hasil pengukuran) 4. Bandingkan dengan kriteria lulus 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada perbedaan waktu signifikan | M-TIMING | Sedang | Pengembang / tim verifikasi internal |
| XA-I-01 | Sistem | — | 4 nilai (Kondisi operasional) | 1. Hentikan proses saat operasi kunci 2. Restart & jalankan ulang self-test 3. Uji di bawah beban tinggi 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Sifat keamanan tidak menurun; tidak ada keluaran parsial | M-SELFTEST | Sedang | Laboratorium uji terakreditasi (ISO/IEC 17025) |

**Narasi empiris (contoh):**

- **A-K-01** — Penguji melakukan pelaksanaan seremoni oleh pengguna sesuai SOP pada AES-256-GCM, AES-256-KW, SHA-384, HMAC-SHA-384-K384, ECDSA-P384, ML-KEM-768 dan 2 objek lain. Uji dinyatakan Memenuhi bila: Sesuai SOP dan security policy.
- **A-K-02** — Penguji melakukan uji dengan aplikasi bisnis nyata pada AES-256-GCM, AES-256-KW, SHA-384, HMAC-SHA-384-K384, ECDSA-P384, ML-KEM-768 dan 2 objek lain. Uji dinyatakan Memenuhi bila: Seluruh fungsi yang dibutuhkan tersedia.
- **A-K-03** — Penguji melakukan audit konfigurasi produksi pada AES-256-GCM, AES-256-KW, SHA-384, HMAC-SHA-384-K384, ECDSA-P384, ML-KEM-768 dan 2 objek lain. Uji dinyatakan Memenuhi bila: Hanya algoritma yang diizinkan aktif.
- **A-K-04** — Penguji melakukan operator menafsirkan status dan log pada AES-256-GCM, AES-256-KW, SHA-384, HMAC-SHA-384-K384, ECDSA-P384, ML-KEM-768 dan 2 objek lain. Uji dinyatakan Memenuhi bila: Status dan log dapat dipahami dan lengkap.
- **I-K-01** — Penguji melakukan panggil seluruh layanan; bandingkan dengan tabel layanan pada security policy pada AES-256-GCM, AES-256-KW, SHA-384, HMAC-SHA-384-K384, ECDSA-P384, ML-KEM-768 dan 2 objek lain. Uji dinyatakan Memenuhi bila: Akses sesuai matriks peran–layanan.
- **I-K-02** — Penguji melakukan periksa indikator mode approved pada tiap layanan pada AES-256-GCM, AES-256-KW, SHA-384, HMAC-SHA-384-K384, ECDSA-P384, ML-KEM-768 dan 2 objek lain. Uji dinyatakan Memenuhi bila: Indikator benar untuk setiap layanan.
- **I-K-03** — Penguji melakukan uji alur lintas unit manajer kunci, key store, dan engine pada AES-256-GCM, AES-256-KW, SHA-384, HMAC-SHA-384-K384, ECDSA-P384, ML-KEM-768 dan 2 objek lain. Uji dinyatakan Memenuhi bila: Setiap transisi sesuai security policy.
- **I-K-04** — Penguji melakukan amati status output dan log saat boot dan KeyGen pada AES-256-GCM, AES-256-KW, SHA-384, HMAC-SHA-384-K384, ECDSA-P384, ML-KEM-768 dan 2 objek lain. Uji dinyatakan Memenuhi bila: Tidak ada output data sebelum self-test lulus. Seluruh masukan pada uji ini bersifat negatif, sehingga hasil yang benar adalah PENOLAKAN.

## 6. Expected Value & Kriteria Keputusan (KUK 2.4)

Kriteria keputusan materi: **Deterministik**: KAT/MCT cocok 100%; vektor invalid seluruhnya ditolak.; **Statistik**: α = 0,01; proporsi lolos dalam interval kepercayaan; p-value terdistribusi seragam.; **Kriptanalitik**: Kompleksitas serangan terbaik ≥ klaim tingkat keamanan (bit security).; **Implementasi**: Tidak ada kebocoran terukur (mis. TVLA |t| < 4,5) dan galat seragam.

| Berkas expected | Target | Jenis | Status | Cocok/total | SHA-256 |
|---|---|---|---|---|---|
| kat_gcm256__AES-256-GCM | AES-256-GCM | deterministic | COCOK_VEKTOR_RESMI | 66/66 | 6386c99995932291… |
| approved_indicator__AES-256-GCM | AES-256-GCM | deterministic | KRITERIA | — | bec0ae62016d636a… |
| approved_indicator__AES-256-KW | AES-256-KW | deterministic | KRITERIA | — | 8e7363dbdb474112… |
| approved_indicator__CTR-DRBG-AES-256 | CTR-DRBG-AES-256 | deterministic | KRITERIA | — | 4a4bed4d46158563… |
| approved_indicator__ECDSA-P384 | ECDSA-P384 | deterministic | KRITERIA | — | 04e55137fda86318… |
| approved_indicator__HMAC-SHA-384-K384 | HMAC-SHA-384-K384 | deterministic | KRITERIA | — | 1fe3287c04e0d8b9… |
| approved_indicator__ML-DSA-65 | ML-DSA-65 | deterministic | KRITERIA | — | 4ad3b928a4f75043… |
| approved_indicator__ML-KEM-768 | ML-KEM-768 | deterministic | KRITERIA | — | ed0d53480ff06909… |
| approved_indicator__SHA-384 | SHA-384 | deterministic | KRITERIA | — | d7521e5d195a7d00… |
| drbg__CTR-DRBG-AES-256 | CTR-DRBG-AES-256 | deterministic | KRITERIA | — | 0dae6d4857a2a140… |
| inspection__AES-256-GCM | AES-256-GCM | deterministic | KRITERIA | — | 8394d8f2d104018a… |
| inspection__AES-256-KW | AES-256-KW | deterministic | KRITERIA | — | 340caa8af523080b… |
| inspection__CTR-DRBG-AES-256 | CTR-DRBG-AES-256 | deterministic | KRITERIA | — | aa3e3627bbb7fd2e… |
| inspection__ECDSA-P384 | ECDSA-P384 | deterministic | KRITERIA | — | 482fcdbd3edf031f… |
| inspection__HMAC-SHA-384-K384 | HMAC-SHA-384-K384 | deterministic | KRITERIA | — | 961a5200ad11a52d… |
| inspection__ML-DSA-65 | ML-DSA-65 | deterministic | KRITERIA | — | 3d75be899d642788… |
| inspection__ML-KEM-768 | ML-KEM-768 | deterministic | KRITERIA | — | 5b087592a8ac911b… |
| inspection__SHA-384 | SHA-384 | deterministic | KRITERIA | — | bc339275312e7d46… |
| interop__AES-256-GCM | AES-256-GCM | deterministic | KRITERIA | — | fb8bba722a1825f2… |
| interop__AES-256-KW | AES-256-KW | deterministic | KRITERIA | — | 1d3647fd27d4fd01… |
| interop__CTR-DRBG-AES-256 | CTR-DRBG-AES-256 | deterministic | KRITERIA | — | f5a8f22ed74c8e2f… |
| interop__ECDSA-P384 | ECDSA-P384 | deterministic | KRITERIA | — | 420ef28e0d6d4b59… |
| interop__HMAC-SHA-384-K384 | HMAC-SHA-384-K384 | deterministic | KRITERIA | — | 14b6094a4f38082d… |
| interop__ML-DSA-65 | ML-DSA-65 | deterministic | KRITERIA | — | ae4bc245abfd341a… |
| interop__ML-KEM-768 | ML-KEM-768 | deterministic | KRITERIA | — | a2a3389c6e6d03a7… |
| interop__SHA-384 | SHA-384 | deterministic | KRITERIA | — | b55befdab2a13cea… |
| kat__ECDSA-P384 | ECDSA-P384 | deterministic | PERLU_VERIFIKASI | — | c7387b7e375ee6ac… |
| kat__ML-DSA-65 | ML-DSA-65 | deterministic | PERLU_VERIFIKASI | — | 6e23bbd13f57f036… |
| performance__AES-256-GCM | AES-256-GCM | implementation | PERLU_VERIFIKASI | — | 55750a8d82079998… |
| performance__AES-256-KW | AES-256-KW | implementation | PERLU_VERIFIKASI | — | 77dba65ad27af89d… |
| performance__CTR-DRBG-AES-256 | CTR-DRBG-AES-256 | implementation | PERLU_VERIFIKASI | — | a226f149e066aad0… |
| performance__ECDSA-P384 | ECDSA-P384 | implementation | PERLU_VERIFIKASI | — | 3d2a3f6a7e773ade… |
| performance__HMAC-SHA-384-K384 | HMAC-SHA-384-K384 | implementation | PERLU_VERIFIKASI | — | a8ce4e2db3b75840… |
| performance__ML-DSA-65 | ML-DSA-65 | implementation | PERLU_VERIFIKASI | — | 1850630a4422f253… |
| performance__ML-KEM-768 | ML-KEM-768 | implementation | PERLU_VERIFIKASI | — | b8a90ca8ab88c2d7… |
| performance__SHA-384 | SHA-384 | implementation | PERLU_VERIFIKASI | — | 611388767cc80827… |
| reject_params__AES-256-GCM | AES-256-GCM | negative | KRITERIA | — | e11f9cdef8fc022d… |
| reject_params__AES-256-KW | AES-256-KW | negative | KRITERIA | — | f615f012567f7b3d… |
| reject_params__CTR-DRBG-AES-256 | CTR-DRBG-AES-256 | negative | KRITERIA | — | 8ef52e567fb871ae… |
| reject_params__ECDSA-P384 | ECDSA-P384 | negative | KRITERIA | — | 68e04544e0b4b89a… |
| reject_params__HMAC-SHA-384-K384 | HMAC-SHA-384-K384 | negative | KRITERIA | — | 67b28b871d9d0d01… |
| reject_params__ML-DSA-65 | ML-DSA-65 | negative | KRITERIA | — | 0a7aad8ea9751e17… |
| reject_params__ML-KEM-768 | ML-KEM-768 | negative | KRITERIA | — | bfc3d1f9405df7c7… |
| reject_params__SHA-384 | SHA-384 | negative | KRITERIA | — | 6e1149cef2ec3446… |
| reproducible_build__AES-256-GCM | AES-256-GCM | deterministic | KRITERIA | — | a007bb20b8448176… |
| reproducible_build__AES-256-KW | AES-256-KW | deterministic | KRITERIA | — | d8b67d9b9856fef0… |
| reproducible_build__CTR-DRBG-AES-256 | CTR-DRBG-AES-256 | deterministic | KRITERIA | — | 7679b10d463522d5… |
| reproducible_build__ECDSA-P384 | ECDSA-P384 | deterministic | KRITERIA | — | 78294dc835330560… |
| reproducible_build__HMAC-SHA-384-K384 | HMAC-SHA-384-K384 | deterministic | KRITERIA | — | 71989c32b8e76ed0… |
| reproducible_build__ML-DSA-65 | ML-DSA-65 | deterministic | KRITERIA | — | 68289093174f5fa0… |
| reproducible_build__ML-KEM-768 | ML-KEM-768 | deterministic | KRITERIA | — | f049f55e8b41a1cd… |
| reproducible_build__SHA-384 | SHA-384 | deterministic | KRITERIA | — | 1b2955677e4fe6e8… |
| role_matrix__AES-256-GCM | AES-256-GCM | deterministic | KRITERIA | — | eb5ce748b3d20908… |
| role_matrix__AES-256-KW | AES-256-KW | deterministic | KRITERIA | — | 7ad3f79e2923baed… |
| role_matrix__CTR-DRBG-AES-256 | CTR-DRBG-AES-256 | deterministic | KRITERIA | — | 1949d75404b9d9df… |
| role_matrix__ECDSA-P384 | ECDSA-P384 | deterministic | KRITERIA | — | c82fd741b7270edf… |
| role_matrix__HMAC-SHA-384-K384 | HMAC-SHA-384-K384 | deterministic | KRITERIA | — | fd9d984bb945b352… |
| role_matrix__ML-DSA-65 | ML-DSA-65 | deterministic | KRITERIA | — | b28484e96957e16f… |
| role_matrix__ML-KEM-768 | ML-KEM-768 | deterministic | KRITERIA | — | d1637ad0e40679fa… |
| role_matrix__SHA-384 | SHA-384 | deterministic | KRITERIA | — | be82c895e99c7b76… |
| selftest__AES-256-GCM | AES-256-GCM | negative | KRITERIA | — | 5c4cf63c5ee793b3… |
| selftest__AES-256-KW | AES-256-KW | negative | KRITERIA | — | 56af128fce3f475d… |
| selftest__CTR-DRBG-AES-256 | CTR-DRBG-AES-256 | negative | KRITERIA | — | f8b6baa71564c6cc… |
| selftest__ECDSA-P384 | ECDSA-P384 | negative | KRITERIA | — | 82ecf85a5c345412… |
| selftest__HMAC-SHA-384-K384 | HMAC-SHA-384-K384 | negative | KRITERIA | — | ac0c035cdb09ee23… |
| selftest__ML-DSA-65 | ML-DSA-65 | negative | KRITERIA | — | df78067a34db467d… |
| selftest__ML-KEM-768 | ML-KEM-768 | negative | KRITERIA | — | 69604f0bb8895704… |
| selftest__SHA-384 | SHA-384 | negative | KRITERIA | — | 00f8002dc6be8c7e… |
| ssp_lifecycle__AES-256-GCM | AES-256-GCM | deterministic | KRITERIA | — | 23e852cbc92da641… |
| ssp_lifecycle__AES-256-KW | AES-256-KW | deterministic | KRITERIA | — | dbb3a1146a010624… |
| ssp_lifecycle__CTR-DRBG-AES-256 | CTR-DRBG-AES-256 | deterministic | KRITERIA | — | 69a0feab42c7ecc7… |
| ssp_lifecycle__ECDSA-P384 | ECDSA-P384 | deterministic | KRITERIA | — | f91f8218284ca8bf… |
| ssp_lifecycle__HMAC-SHA-384-K384 | HMAC-SHA-384-K384 | deterministic | KRITERIA | — | 471348c24c7939f7… |
| ssp_lifecycle__ML-DSA-65 | ML-DSA-65 | deterministic | KRITERIA | — | e8e8910ec1cd310a… |
| ssp_lifecycle__ML-KEM-768 | ML-KEM-768 | deterministic | KRITERIA | — | e201a3f55e5c37fd… |
| ssp_lifecycle__SHA-384 | SHA-384 | deterministic | KRITERIA | — | b5cced1ddc5e3287… |
| tamper__AES-256-GCM | AES-256-GCM | negative | KRITERIA | — | 670eb11972bb1fe0… |
| tamper__AES-256-KW | AES-256-KW | negative | KRITERIA | — | a0971e14f1866dbc… |
| tamper__CTR-DRBG-AES-256 | CTR-DRBG-AES-256 | negative | KRITERIA | — | 06fd4a12da35a0bf… |
| tamper__ECDSA-P384 | ECDSA-P384 | negative | KRITERIA | — | f0e18c37ca7f9065… |
| tamper__HMAC-SHA-384-K384 | HMAC-SHA-384-K384 | negative | KRITERIA | — | 1ca38f5b98853ddc… |
| tamper__ML-DSA-65 | ML-DSA-65 | negative | KRITERIA | — | f928643c5bbef37e… |
| tamper__ML-KEM-768 | ML-KEM-768 | negative | KRITERIA | — | a7c44d74c9d8e668… |
| tamper__SHA-384 | SHA-384 | negative | KRITERIA | — | 4e75d1db47f13024… |

## 7. Pemetaan Parameter → Kemungkinan Hasil Uji (KUK 2.5)

Kategori hasil: **Memenuhi** — Seluruh kriteria terpenuhi pada semua variasi parameter yang ditetapkan.; **Memenuhi dengan Catatan** — Lulus, tetapi terdapat batasan penggunaan (mis. batas data per kunci, parameter minimum).; **Tidak Memenuhi** — Minimal satu kriteria gagal; parameter pemicu kegagalan diidentifikasi.; **Inkonklusif** — Bukti statistik belum cukup; diperlukan sampel lebih besar atau uji lanjutan.

| Kondisi temuan | Parameter pemicu | Kemungkinan hasil | Tindak lanjut | Sumber |
|---|---|---|---|---|
| Output data keluar saat self-test gagal | Status modul | Tidak Memenuhi | Temuan kritis area 7.3/7.10; perbaiki state machine, ulangi I-K-04 dan I-S-01 | materi (hsm_x_sl3) |
| Min-entropi di bawah klaim pada suhu batas operasi | Kondisi entropi | Memenuhi dengan Catatan | Diterima bila rentang suhu operasi dipersempit dalam security policy; jika tidak, tidak memenuhi | materi (hsm_x_sl3) |
| TVLA \|t\| ≥ 4,5 pada signing ECDSA melalui API | Kuantitas trace | Tidak Memenuhi | Konfirmasi eksploitabilitas dengan CPA; terapkan countermeasure | materi (hsm_x_sl3) |
| Hasil TVLA tidak konsisten antarsesi pengukuran | Kuantitas trace | Inkonklusif | Perbesar jumlah trace dan kendalikan derau pengukuran | materi (hsm_x_sl3) |
| Firmware versi lama diterima (rollback) | Image firmware | Tidak Memenuhi | Terapkan penghitung versi anti-rollback | materi (hsm_x_sl3) |
| Kunci dapat diimpor tanpa kuorum kustodian | Metode entri SSP | Tidak Memenuhi | Wajibkan split knowledge pada seluruh jalur impor | materi (hsm_x_sl3) |
| Seluruh uji sistem lulus, kinerja di bawah SLA | Beban produksi | Memenuhi dengan Catatan | Penerimaan bersyarat: tambah kapasitas atau revisi SLA | materi (hsm_x_sl3) |
| Keluaran berbeda dari expected value pada ≥ 1 vektor | target, vektor (kunci/nonce/pesan) | Tidak Memenuhi | Telusuri vektor pertama yang gagal; perbaiki implementasi; ulangi KAT/MCT | aturan umum (kriteria keputusan materi) |
| Vektor 'invalid' (Wycheproof) diterima produk | encoding/parameter invalid | Tidak Memenuhi | Temuan kritis: perketat validasi masukan; ulangi seluruh vektor invalid | aturan umum (kriteria keputusan materi) |
| Expected value bertanda PERLU_VERIFIKASI (vektor resmi belum tersedia) | ketersediaan vektor | Inkonklusif | Muat vektor ACVP/CAVP resmi, regenerasi expected, ulangi uji | aturan umum (kriteria keputusan materi) |
| Proporsi lolos < ambang SP 800-22 atau P-value_T < 0,0001 | pola masukan, ukuran sampel | Tidak Memenuhi | Identifikasi dataset pemicu (low/high-density, avalanche); analisis difusi | aturan umum (kriteria keputusan materi) |
| Proporsi lolos tepat di tepi interval kepercayaan | ukuran sampel | Inkonklusif | Perbesar sampel (mis. 10×) lalu ulangi | aturan umum (kriteria keputusan materi) |
| Security strength 112 ≤ s < 128 bit | ukuran kunci/domain | Memenuhi dengan Catatan | Batasi penggunaan hingga 2030 (SP 800-131A / IR 8547); rencanakan migrasi | aturan umum (kriteria keputusan materi) |
| Serangan terbaik < klaim bit security / strength < 112 bit | ukuran kunci, jumlah ronde | Tidak Memenuhi | Nonaktifkan untuk layanan approved; ganti algoritma/parameter | aturan umum (kriteria keputusan materi) |
| TVLA \|t\| ≥ 4,5 | kunci/nonce rahasia, jumlah pengukuran | Tidak Memenuhi | Konfirmasi eksploitabilitas (CPA/analisis timing); perbaiki ke constant-time | aturan umum (kriteria keputusan materi) |
| Hasil TVLA tidak konsisten antarsesi | jumlah trace/pengukuran, derau | Inkonklusif | Perbesar jumlah pengukuran; kendalikan derau (isolasi core, turbo off) | aturan umum (kriteria keputusan materi) |
| Crash/hang pada fuzzing | masukan malformed | Tidak Memenuhi | Reproduksi dengan sanitizer; perbaiki parser; ulangi fuzzing | aturan umum (kriteria keputusan materi) |
| Masukan negatif diterima | nilai di luar spesifikasi | Tidak Memenuhi | Tambahkan validasi; ulangi uji negatif | aturan umum (kriteria keputusan materi) |
| Masukan ditolak tetapi kode galat berbeda antar-kelas | jenis kegagalan | Memenuhi dengan Catatan | Seragamkan kode galat (mitigasi oracle) bila menyangkut data rahasia | aturan umum (kriteria keputusan materi) |

## 8. Matriks Keterlacakan

| Kebutuhan | Uraian | Metode UK-1 | Skenario | Test case | Area | Standar |
|---|---|---|---|---|---|---|
| C-AUTH | Autentikasi berbasis identitas; dual control operasi kritis | M-ZEROIZE | SCN-M-UAT-K | A-K-01 | 7.9 | ISO-19790 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-KAT | SCN-M-UAT-K | A-K-02 | 7.3 | ISO-29119 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-KEYSIZE | SCN-M-UAT-K | A-K-03 | 7.2 | SP-800-131A |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-SELFTEST | SCN-M-UAT-K | A-K-04 | 7.3 | ISO-19790 |
| C-AUTH | Autentikasi berbasis identitas; dual control operasi kritis | M-SELFTEST | SCN-M-INT-K | I-K-01 | 7.4 | ISO-24759 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-KEYSIZE | SCN-M-INT-K | I-K-02 | 7.2 | ISO-24759 |
| C-SSP | CSP hanya keluar terenkripsi dengan kunci approved; split knowledge untuk entri manual | M-ZEROIZE | SCN-M-INT-K | I-K-03 | 7.9 | ISO-19790 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-SELFTEST | SCN-M-INT-K | I-K-04 | 7.10 | ISO-19790 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-SELFTEST | SCN-M-SIS-K | S-K-01 | 7.2 | ISO-24759 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-SELFTEST | SCN-M-SIS-K | S-K-02 | 7.3 | ISO-24759 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-SELFTEST | SCN-M-SIS-K | S-K-03 | 7.11 | ISO-24759 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-SELFTEST | SCN-M-SIS-K | S-K-04 | 7.10 | ISO-19790 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-KAT | SCN-M-UNI-K | U-K-01 | 7.2 | ISO-18367, SP-800-38D |
| OBJ:ECDSA-P384 | Kesesuaian ECDSA-P384, ML-DSA-65 terhadap standar | M-KAT | SCN-M-UNI-K | U-K-02 | 7.2 | FIPS-186-5, FIPS-204 |
| OBJ:CTR-DRBG-AES-256 | Kesesuaian CTR-DRBG-AES-256 terhadap standar | M-KAT | SCN-M-UNI-K | U-K-03 | 7.9 | SP-800-90A |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-SELFTEST | SCN-M-UNI-K | U-K-04 | 7.10 | ISO-19790, ISO-24759 |
| C-AUTH | Autentikasi berbasis identitas; dual control operasi kritis | M-SELFTEST | SCN-M-UAT-S | A-S-01 | 7.4 | ISO-19790 |
| C-TAMPER | Tamper evidence & response dengan zeroisation | M-ZEROIZE | SCN-M-UAT-S | A-S-02 | 7.7 | ISO-19790 |
| C-SSP | CSP hanya keluar terenkripsi dengan kunci approved; split knowledge untuk entri manual | M-ZEROIZE | SCN-M-UAT-S | A-S-03 | 7.9 | ISO-19790 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-KEYSIZE | SCN-M-UAT-S | A-S-04 | 7.2 | FIPS-203, FIPS-204 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-SELFTEST | SCN-M-INT-S | I-S-01 | 7.3 | ISO-19790 |
| C-SSP | CSP hanya keluar terenkripsi dengan kunci approved; split knowledge untuk entri manual | M-ZEROIZE | SCN-M-INT-S | I-S-02 | 7.9 | ISO-19790, SP-800-38F |
| C-AUTH | Autentikasi berbasis identitas; dual control operasi kritis | M-FUZZ | SCN-M-INT-S | I-S-03 | 7.4 | ISO-19790 |
| C-SL3 | ISO/IEC 19790 Tingkat Keamanan 3 | M-FUZZ | SCN-M-INT-S | I-S-03 | 7.4 | ISO-19790 |
| C-FW | Hanya firmware bertanda tangan sah dengan versi ≥ saat ini yang dimuat | M-SELFTEST | SCN-M-INT-S | I-S-04 | 7.5 | ISO-19790 |
| C-TAMPER | Tamper evidence & response dengan zeroisation | M-FAULT | SCN-M-SIS-S | S-S-01 | 7.7 | ISO-19790 |
| C-SL3 | ISO/IEC 19790 Tingkat Keamanan 3 | M-FAULT | SCN-M-SIS-S | S-S-01 | 7.7 | ISO-19790 |
| C-TAMPER | Tamper evidence & response dengan zeroisation | M-FAULT | SCN-M-SIS-S | S-S-02 | 7.7 | ISO-19790 |
| C-SL3 | ISO/IEC 19790 Tingkat Keamanan 3 | M-FAULT | SCN-M-SIS-S | S-S-02 | 7.7 | ISO-19790 |
| C-SSP | CSP hanya keluar terenkripsi dengan kunci approved; split knowledge untuk entri manual | M-ZEROIZE | SCN-M-SIS-S | S-S-03 | 7.9 | ISO-19790 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-FAULT | SCN-M-SIS-S | S-S-04 | 7.12 | ISO-19790 |
| C-SSP | CSP hanya keluar terenkripsi dengan kunci approved; split knowledge untuk entri manual | M-RNG | SCN-M-UNI-S | U-S-01 | 7.9 | SP-800-90B |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-KEYSIZE | SCN-M-UNI-S | U-S-02 | 7.2 | SP-800-131A |
| C-SSP | CSP hanya keluar terenkripsi dengan kunci approved; split knowledge untuk entri manual | M-ZEROIZE | SCN-M-UNI-S | U-S-03 | 7.9 | ISO-19790 |
| C-AUTH | Autentikasi berbasis identitas; dual control operasi kritis | M-FUZZ | SCN-M-UNI-S | U-S-04 | 7.4 | ISO-19790 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-SELFTEST | SCN-M-UAT-I | A-I-01 | Pengguna | ISO-29119 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-SELFTEST | SCN-M-UAT-I | A-I-02 | Pengguna | ISO-29119 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-SELFTEST | SCN-M-UAT-I | A-I-03 | 7.5 | ISO-19790 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-SELFTEST | SCN-M-UAT-I | A-I-04 | 7.11 | ISO-19790 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-CODEREVIEW | SCN-M-INT-I | I-I-01 | 7.11 | ISO-19790 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-TVLA | SCN-M-INT-I | I-I-02 | 7.8 | ISO-17825 |
| C-FW | Hanya firmware bertanda tangan sah dengan versi ≥ saat ini yang dimuat | M-FAULT | SCN-M-INT-I | I-I-03 | 7.12 | ISO-19790 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-FUZZ | SCN-M-INT-I | I-I-04 | 7.3 | ISO-29119 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-TVLA | SCN-M-SIS-I | S-I-01 | 7.8 | ISO-17825, ISO-20085 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-CODEREVIEW | SCN-M-SIS-I | S-I-02 | 7.6 | ISO-19790 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-SELFTEST | SCN-M-SIS-I | S-I-03 | Pengguna | ISO-29119 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-SELFTEST | SCN-M-SIS-I | S-I-04 | 7.11 | ISO-19790 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-TVLA | SCN-M-UNI-I | U-I-01 | 7.8 | ISO-17825 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-CODEREVIEW | SCN-M-UNI-I | U-I-02 | 7.5 | ISO-18045 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-FUZZ | SCN-M-UNI-I | U-I-03 | 7.3 | ISO-29119 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-TIMING | SCN-M-UNI-I | U-I-04 | 7.12 | ISO-17825 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-KAT | SCN-XA-INT-K | XA-K-01 | — | ISO-18367 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-RNG | SCN-XA-INT-S | XA-S-01 | — | SP-800-90A, SP-800-90B, SP-800-22 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-ZEROIZE | SCN-XA-SIS-S | XA-S-02 | — | SP-800-57, ISO-19790 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-KEYSIZE | SCN-XA-SIS-S | XA-S-03 | — | FIPS-203, FIPS-204, SP-800-131A |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, AES-256-KW, SHA-384 terhadap standar | M-SELFTEST | SCN-XA-SIS-I | XA-I-01 | — | ISO-19790 |

## Tata Kelola Pengujian (model 4 tingkat)

| Tingkat | Pelaksana | Kriteria masuk | Kriteria keluar |
|---|---|---|---|
| Unit Testing | Pengembang / tim verifikasi internal | Desain & kode unit dibekukan; vektor uji tersedia | Seluruh uji unit lulus; cakupan cabang ≥ target; tanpa temuan SAST tingkat tinggi |
| Integration Testing | Tim verifikasi internal | Uji unit lulus; antarmuka antar-unit terdokumentasi | Alur layanan, peran, dan SSP sesuai rancangan security policy |
| System Testing | Laboratorium uji terakreditasi (ISO/IEC 17025) | Security policy final; bukti vendor sesuai ISO/IEC 24759 | Seluruh asersi uji terpenuhi pada tingkat keamanan yang ditargetkan |
| UAT | Pengguna / pemilik proses bisnis bersama penguji | Laporan uji sistem tersedia; lingkungan operasional siap | Kriteria penerimaan pengguna terpenuhi; berita acara penerimaan |

## 9. Lampiran: Peta KUK → Bab → File Kode

| KUK | Deskripsi | Bab | File | Test |
|---|---|---|---|---|
| 1.1 | Metode ditelaah sesuai kebutuhan pengujian | Bab 2 | uk2_skenario/method_review.py | tests/test_uk2.py::test_kuk_1_1_* |
| 1.2 | Parameter ditelaah sesuai metode | Bab 1, 2 | uk2_skenario/param_space.py | tests/test_uk2.py::test_kuk_1_2_* |
| 2.1 | Skenario didesain dari hasil telaah | Bab 3 | uk2_skenario/designer.py, uk2_skenario/data/recipes.yaml, uk2_skenario/data/templates.yaml | tests/test_uk2.py::test_kuk_2_1_* |
| 2.2 | Skenario diverifikasi terhadap spesifikasi desain (aspek kritis) | Bab 4 | uk2_skenario/verifier.py | tests/test_uk2.py::test_kuk_2_2_* |
| 2.3 | Identifikasi test case | Bab 5 | uk2_skenario/testcase.py, uk2_skenario/schema/uk2_skenario.schema.json | tests/test_uk2.py::test_kuk_2_3_* |
| 2.4 | Expected value | Bab 6 | uk2_skenario/expected.py, uk2_skenario/data/vectors/ | tests/test_uk2.py::test_kuk_2_4_* |
| 2.5 | Kompilasi skenario | Bab 7, 8 | uk2_skenario/compiler.py | tests/test_uk2.py::test_kuk_2_5_* |
