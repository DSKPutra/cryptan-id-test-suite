# Dokumen Skenario Pengujian — SignDoc Token

**Cryptan.ID Test Suite** · Modul **UK-2** · Unit J.61KRP00.013.1 — *Menyusun Skenario Pengujian* · SKKNI 2023-004 (Cryptographic Analyst)

Dibangkitkan 2026-10-01T10:33:13+07:00 · model 3 tingkat · masukan UK-1: `/Users/deasakakurniaputra/Cryptography Analyst_Dea Saka Kurnia Putra/cryptan-id-test-suite/samples/uk2/ecdsa_p256_token/uk1_stub.json`

> Objek uji & data produk ILUSTRATIF. HASIL UJI LANGSUNG = dihitung kode; LITERATUR/ACUAN = dikutip dengan rujukan; PERLU_VERIFIKASI = belum dapat dihitung/dicocokkan, tidak dikarang.

## Ringkasan

- Objek uji: **3** kombinasi · kategori: hash, signature
- Metode UK-1 ditelaah: 11 (relevan 11) · sel kosong diisi templat: 15
- Skenario: **22** · test case: **38** (K 12 · S 16 · I 10)
- Verifikasi terhadap spesifikasi desain: **LULUS** (0 temuan)
- Expected value: 5 cocok vektor resmi · 30 kriteria · 1 PERLU_VERIFIKASI

## 1. Profil Objek Uji & Ruang Parameter

| Atribut | Nilai |
|---|---|
| Produk | SignDoc Token 1.0 (ilustratif) |
| Deskripsi | Modul tanda tangan elektronik dokumen (aplikasi + token kriptografi/secure element) |
| Jenis produk | token |
| Model tingkat | 3 (Komponen → Integrasi → Sistem) |
| SL ISO/IEC 19790 | tidak berlaku |
| Fitur | api, audit_log, certificates, error_codes, fuzzing_harness, key_non_exportable, keygen, multi_doc_signing, pdf_signing, physical_access, power_glitch, revocation, rng_internal, secure_element, side_channel_lab, signature, timestamp, timing_measurement, token |

**Klaim keamanan:**

| ID | Klaim | Tag |
|---|---|---|
| C-STRENGTH | 128 bit | bit_security |
| C-EUF | EUF-CMA | euf_cma, nonce_bias |
| C-NOEXP | Kunci privat tidak dapat diekspor | key_non_exportable |

**Objek uji (algorithms_under_test):**

| ID | Kategori | Varian | Kunci | Strength | Status NIST |
|---|---|---|---|---|---|
| ECDSA-P256 | signature | P-256 | 256 | 128 | acceptable |
| SHA-256 | hash | SHA-256 | — | 128 | acceptable |
| HMAC-DRBG-S128 | rng | HMAC_DRBG | 128 | 128 | acceptable |

### 1.1 Ruang parameter — hash

| ID | Parameter | Kelas | Status | Nilai uji (teknik) |
|---|---|---|---|---|
| HF-LEN-SHA-256 | Panjang pesan SHA-256 (b = 64 B) | Data masukan | Variabel | 0 [BVA]; 1 [BVA]; 55 [BVA]; 56 [BVA]; 63 [BVA]; 64 [BVA]; 65 [BVA]; 1048576 [EP]; 104857600 [EP] |
| HF-PAT | Pola pesan | Data masukan | Variabel | acak [EP]; nol-semua (0x00…) [DEG]; satu-semua (0xFF…) [DEG]; low-density (HW = 1) [DEG]; high-density (HW = n−1) [DEG]; periodik (0x55/0xAA) [DEG]; beda 1 bit [BIT] |
| HF-DIG | Panjang digest | Konfigurasi | Variabel | penuh [EP]; terpotong t = 128 bit [EP]; XOF 256/512 bit [EP]; terpotong t = 32 bit (analisis birthday) [BVA] |
| HF-CHUNK | Pemecahan input | Konfigurasi | Variabel | one-shot [EP]; update bertahap acak (1…b+7 byte) [EP] |
| HF-ROUNDS | Jumlah ronde | Konfigurasi | Variabel | penuh [EP]; tereduksi (analisis) [BVA] |
| ENV | Kondisi operasional | Kondisi lingkungan | Variabel | normal [EP]; gangguan daya saat signing [EP]; glitch tegangan/clock [EP] |

Reduksi pairwise (t = 2. IPOG) atas 6 parameter Variabel: **3.024** kombinasi penuh → **63** kombinasi pairwise (97.9% berkurang; semua pasangan tercakup: True).

### 1.2 Ruang parameter — signature

| ID | Parameter | Kelas | Status | Nilai uji (teknik) |
|---|---|---|---|---|
| DS-ALG | Kurva & hash / parameter set | Parameter publik/domain | Tetap | ECDSA-P256 [EP] |
| DS-NONCE | Mode nonce | Konfigurasi | Variabel | rfc6979 [EP]; drbg [EP]; bias beberapa bit (simulasi) [NEG, NEG]; berulang (simulasi) [NEG, NEG] |
| DS-MSG | Panjang pesan | Data masukan | Variabel | 0 [BVA]; 1 [BVA]; 55 [BVA]; 56 [BVA]; 63 [BVA]; 64 [BVA]; 65 [BVA]; 1048576 [EP]; 104857600 [EP] |
| DS-D | Kunci privat d | Material rahasia | Variabel | acak [EP]; Hamming weight rendah [DEG]; Hamming weight tinggi [DEG]; d = 1 [BVA]; d = n − 1 [BVA]; d = 0 [BVA, NEG]; d = n [BVA, NEG] |
| DS-ENC | Encoding (r, s) | Data masukan | Variabel | DER kanonik [EP]; DER non-kanonik [NEG, NEG]; r atau s = 0 [BVA, NEG]; r atau s ≥ n [BVA, NEG]; s ↔ n − s [NEG] |
| DS-Q | Kunci publik Q | Data masukan | Tetap | valid [EP]; titik tak hingga O [BVA, NEG]; di luar kurva [NEG, NEG]; koordinat ≥ p [BVA, NEG] |
| DS-N | Ukuran sampel | Konfigurasi | Variabel | N = 1.000.000 tanda tangan (uji nonce) [EP]; 100.000 trace/pengukuran (side-channel) [EP] |
| ENV | Kondisi operasional | Kondisi lingkungan | Variabel | normal [EP]; gangguan daya saat signing [EP]; glitch tegangan/clock [EP] |

Reduksi pairwise (t = 2. IPOG) atas 5 parameter Variabel: **216** kombinasi penuh → **28** kombinasi pairwise (87.0% berkurang; semua pasangan tercakup: True).

## 2. Telaah Metode & Parameter (KUK 1.1, 1.2)

Empat kebutuhan pengujian SKKNI: N1 jenis algoritma · N2 desain & teknik implementasi · N3 tren serangan · N4 best practice.

| Metode | Sel (tingkat × lapis) | N1 | N2 | N3 | N4 | Asal UK-1 | Putusan |
|---|---|---|---|---|---|---|---|
| M-KAT Known Answer Test | Komponen × K | ✔ | ✔ | ✔ | ✔ | ECDSA-P256 (STUB_UK1) | RELEVAN |
| M-PKV Validasi kunci publik | Komponen × K | ✔ | ✔ | ✔ | ✔ | ECDSA-P256 (STUB_UK1) | RELEVAN |
| M-SIGMAL Penolakan (r,s) non-kanonik | Komponen × K | ✔ | ✔ | ✔ | ✔ | ECDSA-P256 (STUB_UK1) | RELEVAN |
| M-CURVE Validasi parameter domain | Komponen × K | ✔ | ✔ | ✔ | ✔ | ECDSA-P256 (STUB_UK1) | RELEVAN |
| M-NONCE Keunikan & bias nonce | Integrasi × I | ✔ | ✔ | ✔ | ✔ | ECDSA-P256 (STUB_UK1) | RELEVAN |
| M-RNG Asesmen RBG | Integrasi × I | ✔ | ✔ | ✔ | ✔ | ECDSA-P256 (STUB_UK1) | RELEVAN |
| M-TIMING Timing leakage | Integrasi × I | ✔ | ✔ | ✔ | ✔ | ECDSA-P256 (STUB_UK1) | RELEVAN |
| M-TVLA TVLA daya/EM | Sistem × I | ✔ | ✔ | ✔ | ✔ | ECDSA-P256 (STUB_UK1) | RELEVAN |
| M-FAULT Fault injection | Sistem × I | ✔ | ✔ | ✘ | ✔ | ECDSA-P256 (STUB_UK1) | RELEVAN |
| M-FUZZ Fuzzing | Integrasi × I | ✔ | ✔ | ✔ | ✔ | ECDSA-P256 (STUB_UK1) | RELEVAN |
| M-ZEROIZE Zeroization | Sistem × I | ✔ | ✔ | ✔ | ✔ | ECDSA-P256 (STUB_UK1) | RELEVAN |

Sel kosong (15) diisi dari templat kategori materi: hash:Komponen×K, hash:Komponen×S, hash:Komponen×I, hash:Integrasi×K, hash:Integrasi×S, hash:Integrasi×I, hash:Sistem×K, hash:Sistem×S, hash:Sistem×I, signature:Komponen×S, signature:Komponen×I, signature:Integrasi×K, signature:Integrasi×S, signature:Sistem×K, signature:Sistem×S

Teknik penetapan nilai uji: EP = Partisi ekuivalensi; BVA = Analisis nilai batas; DEG = Input degeneratif/berpola; BIT = Variasi 1-bit (diferensial); TWAY = Kombinatorial t-way (pairwise); NEG = Negative testing

## 3. Matriks Skenario Lapis × Tingkat (KUK 2.1)

**hash**

| Tingkat | Uji Kesesuaian | Uji Keamanan | Uji Implementasi |
|---|---|---|---|
| Komponen | SCN-HF-KOM-K: HF-K-01 | SCN-HF-KOM-S: TIDAK BERLAKU — tidak ada resep yang memenuhi fitur produk | SCN-HF-KOM-I: TIDAK BERLAKU — tidak ada resep yang memenuhi fitur produk |
| Integrasi | SCN-HF-INT-K: HF-K-02, HF-K-03 | SCN-HF-INT-S: HF-S-02, HF-S-03, HF-S-04 | SCN-HF-INT-I: HF-I-02, HF-I-03 |
| Sistem | SCN-HF-SIS-K: HF-K-06 | SCN-HF-SIS-S: HF-S-06 | SCN-HF-SIS-I: HF-I-05 |

**signature**

| Tingkat | Uji Kesesuaian | Uji Keamanan | Uji Implementasi |
|---|---|---|---|
| Komponen | SCN-DS-KOM-K: DS-K-01, DS-K-02 | SCN-DS-KOM-S: DS-S-01 | SCN-DS-KOM-I: DS-I-01, DS-I-02 |
| Integrasi | SCN-DS-INT-K: DS-K-03, DS-K-04, DS-K-05 | SCN-DS-INT-S: DS-S-02, DS-S-03, DS-S-04, DS-S-05, DS-S-08 | SCN-DS-INT-I: DS-I-03, DS-I-04 |
| Sistem | SCN-DS-SIS-K: DS-K-06, DS-K-07 | SCN-DS-SIS-S: DS-S-06, DS-S-07, DS-S-09 | SCN-DS-SIS-I: DS-I-05, DS-I-06 |

**cross**

| Tingkat | Uji Kesesuaian | Uji Keamanan | Uji Implementasi |
|---|---|---|---|
| Integrasi | SCN-XA-INT-K: XA-K-01 | SCN-XA-INT-S: XA-S-01 | — |
| Sistem | — | SCN-XA-SIS-S: XA-S-02, XA-S-04 | SCN-XA-SIS-I: XA-I-01 |

**Lintas-algoritma:** RNG / Sumber Entropi → Pembangkitan Kunci → KDF → Cipher / MAC / Signature → Protokol → Produk · skenario: XA-K-01, XA-S-01, XA-S-02, XA-S-04, XA-I-01 · PQC relevan: True

**Resep tidak berlaku (fitur/objek tidak dimiliki produk — aturan f):**

| Resep | Alasan |
|---|---|
| HF-K-04 | fitur produk tidak ada: streaming_api |
| HF-K-05 | tidak ada objek uji yang sesuai (applies) |
| HF-S-01 | tidak ada objek uji yang sesuai (applies) |
| HF-S-05 | tidak ada objek uji yang sesuai (applies) |
| HF-I-01 | fitur produk tidak ada: streaming_api |
| HF-I-04 | fitur produk tidak ada: multi_thread |
| HF-I-06 | fitur produk tidak ada: key_import_export |
| DS-K-08 | tidak ada objek uji yang sesuai (applies) |
| XA-S-03 | fitur produk tidak ada: kem |

## 4. Laporan Verifikasi terhadap Spesifikasi Desain (KUK 2.2 — aspek kritis)

Status keseluruhan: **LULUS** · 0 temuan

| Aturan | Deskripsi | Diperiksa | Status | Temuan |
|---|---|---|---|---|
| (a) | Cakupan algoritma, varian, panjang kunci, mode & parameter set profil | 3 | LULUS | — |
| (b) | Nilai di luar spesifikasi hanya sebagai negative test (harapan ditolak) | 59 | LULUS | — |
| (c) | Setiap klaim keamanan punya ≥ 1 skenario Uji Keamanan | 3 | LULUS | — |
| (d) | Setiap metode UK-1 punya ≥ 1 skenario | 11 | LULUS | — |
| (e) | Modul: 11 area ISO/IEC 19790 (7.2–7.12) tercakup / dijustifikasi | 0 | TIDAK BERLAKU | — |
| (f) | Tidak ada skenario untuk fitur/objek yang tidak dimiliki produk | 38 | LULUS | — |

## 5. Katalog Test Case (KUK 2.3)

### 5.1 Uji Kesesuaian

| ID | Tingkat | Area | Parameter & nilai uji | Prosedur | Kriteria lulus | Metode UK-1 | Prioritas | Pelaksana |
|---|---|---|---|---|---|---|---|---|
| DS-K-01 | Komponen | — | Titik khusus: O, P + (−P), P + P, n·G | 1. Hitung O, P + (−P), P + P, n·G dengan produk 2. Hitung yang sama dengan implementasi referensi core/ 3. Bandingkan seluruh hasil 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Hasil identik 100%; n·G = O | M-CURVE, M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| DS-K-02 | Komponen | — | Pesan 0, 55, 56, 64, 65 byte dan 1 MB · 9 nilai (Panjang pesan) | 1. Hash pesan pada nilai batas panjang (b = 64: 0, 55, 56, 64, 65 byte) dan 1 MB 2. Jalankan MCT SHA-256 3. Bandingkan digest 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Digest identik 100% | M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| DS-K-03 | Integrasi | — | 100 pasangan kunci hasil KeyGen | 1. Bangkitkan 100 pasangan kunci 2. Periksa 1 ≤ d ≤ n − 1 3. Periksa Q = d·G valid di kurva (validasi penuh) 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | 100% pasangan kunci valid | M-PKV | Sedang | Penguji lab (Cryptographic Analyst) |
| DS-K-04 | Integrasi | — | Vektor uji RFC 6979 (P-256, SHA-256) | 1. Gunakan d & pesan dari vektor RFC 6979 A.2.5 2. Bangkitkan (r, s) dengan produk 3. Bandingkan dengan vektor acuan 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | (r, s) identik dengan vektor acuan | M-KAT | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-K-05 | Integrasi | — | ≥ 500 vektor SigVer: valid dan seluruh variasi encoding invalid · 2 nilai (Encoding (r, s)) | 1. Muat vektor SigVer (Wycheproof + mutasi encoding) 2. Verifikasi tiap vektor dengan produk 3. Catat terima/tolak per vektor 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Valid diterima; seluruh invalid ditolak | M-KAT, M-SIGMAL | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-K-06 | Sistem | — | Dokumen PDF bertanda tangan, 3 ukuran berkas | 1. Tanda tangani dokumen 3 ukuran 2. Verifikasi dengan ≥ 2 verifier referensi 3. Ulangi dua arah 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Status verifikasi konsisten | M-KAT | Sedang | Penguji lab + test engineer |
| DS-K-07 | Sistem | — | ECDSA-P256 | 1. Tanda tangani pesan dengan produk; verifikasi dengan OpenSSL/pyca 2. Arah sebaliknya 3. Untuk EdDSA/ML-DSA gunakan vektor resmi 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Status verifikasi konsisten dua arah | M-KAT | Sedang | Penguji lab + test engineer |
| HF-K-01 | Komponen | — | SHA-256 | 1. Bandingkan konstanta ronde & offset rotasi dengan standar 2. Jalankan permutasi pada state uji (core/) 3. Periksa padding pad10*1 / MD-strengthening pada batas b 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Identik 100% | M-KAT, M-PAD | Tinggi | Penguji lab (Cryptographic Analyst) |
| HF-K-02 | Integrasi | — | 16 nilai (Panjang pesan SHA-256 (b = 64 B), Pola pesan) | 1. Hash pesan pada setiap nilai batas (0, 1, b−L−1, b−L, b−1, b, b+1, 1 MiB) 2. Bandingkan dengan expected value (dua implementasi independen + vektor resmi) 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Digest identik 100% | M-KAT, M-PAD | Tinggi | Penguji lab (Cryptographic Analyst) |
| HF-K-03 | Integrasi | — | SHA-256 | 1. MCT 100 × 1000 iterasi (gaya CAVP) 2. Bandingkan checkpoint 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | 100% checkpoint identik | M-MCT | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-K-06 | Sistem | — | SHA-256 | 1. Verifikasi silang digest berkas dengan sha3sum/OpenSSL 2. Periksa label domain separation 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Konsisten | M-KAT | Sedang | Penguji lab + test engineer |
| XA-K-01 | Integrasi | — | ECDSA-P256, SHA-256, HMAC-DRBG-S128 | 1. Jalankan alur end-to-end dengan data uji tetap 2. Periksa endianness, encoding (DER/raw), panjang parameter & kode galat antar-komponen 3. Bandingkan keluaran tiap tahap dengan referensi 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Format & kode galat konsisten di seluruh rantai | M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |

### 5.2 Uji Keamanan

| ID | Tingkat | Area | Parameter & nilai uji | Prosedur | Kriteria lulus | Metode UK-1 | Prioritas | Pelaksana |
|---|---|---|---|---|---|---|---|---|
| DS-S-01 | Komponen | — | Parameter domain P-256 di dalam produk | 1. Ekstrak p, a, b, G, n, h dari produk 2. Cocokkan dengan SP 800-186 3. Uji primalitas n; h = 1 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Identik; n prima, h = 1 | M-CURVE | Sedang | Penguji lab (Cryptographic Analyst) |
| DS-S-02 | Integrasi | — | N = 10^6 tanda tangan, pesan acak, d uji diketahui · 4 nilai (Mode nonce, Ukuran sampel) | 1. Bangkitkan N tanda tangan, pesan acak, d uji diketahui 2. Hitung k = s⁻¹(e + r·d) mod n 3. Uji bias MSB/LSB (χ²) & keacakan bit k 4. Simulasikan serangan lattice/HNP 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada bias signifikan (α = 0,01); serangan HNP simulasi gagal | M-NONCE | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-S-03 | Integrasi | — | N tanda tangan dari DS-S-02, kedua mode nonce · 2 nilai (Mode nonce) | 1. Gunakan N tanda tangan dari DS-S-02 untuk kedua mode nonce 2. Cari r berulang untuk pesan berbeda 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada r berulang | M-NONCE | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-S-04 | Integrasi | — | Q = O, Q di luar kurva, koordinat ≥ p · 4 nilai (Kunci publik Q) | 1. Masukkan Q = O, Q di luar kurva, koordinat ≥ p ke verifier 2. Masukkan ke proses impor sertifikat 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruhnya ditolak | M-PKV | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-S-05 | Integrasi | — | Keluaran DRBG pembangkit d dan k (mode acak) | 1. Kumpulkan keluaran DRBG (mode acak) 2. Estimasi min-entropi SP 800-90B 3. Jalankan SP 800-22 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Min-entropi ≥ klaim; lolos uji statistik | M-RNG | Sedang | Penguji lab (Cryptographic Analyst) |
| DS-S-06 | Sistem | — | Dokumen diubah, sertifikat disubstitusi/dicabut/kedaluwarsa, timestamp dimanipulasi | 1. Ubah dokumen; substitusi/cabut/kedaluwarsakan sertifikat; manipulasi timestamp 2. Verifikasi melalui aplikasi 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Verifikasi gagal dengan status yang benar | M-SIGMAL | Sedang | Penguji lab + test engineer |
| DS-S-07 | Sistem | — | ECDSA-P256 | 1. Hitung strength tiap skema (SP 800-57/FIPS 204) 2. Tandai skema rentan kuantum (IR 8547) 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Strength ≥ 112 bit; rencana migrasi PQC | M-KEYSIZE, M-ECDLP | Sedang | Penguji lab + test engineer |
| DS-S-08 | Integrasi | — | 5 nilai (Encoding (r, s)) | 1. Kirim (r, n−s), r/s = 0, ≥ n, DER non-kanonik 2. Catat terima/tolak 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Di luar rentang ditolak; kebijakan low-s didokumentasikan | M-SIGMAL | Sedang | Penguji lab (Cryptographic Analyst) |
| DS-S-09 | Sistem | — | ECDSA-P256 | 1. Inventarisasi seluruh perintah/atribut yang dapat mengeluarkan kunci (mis. CKA_EXTRACTABLE, CKA_SENSITIVE) 2. Coba ekspor d melalui API, perintah vendor & backup 3. Periksa audit log setiap upaya 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Kunci privat tidak pernah keluar dalam bentuk plaintext; seluruh upaya tercatat | M-ZEROIZE | Tinggi | Penguji lab + test engineer |
| HF-S-02 | Integrasi | — | 7 nilai (Pola pesan) | 1. 10 000 pasangan pesan beda 1 bit 2. Uji χ² byte keluaran 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Avalanche n/2 (σ ≈ √n/2); χ² p ≥ 0,01 | M-AVAL, M-SP80022 | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-S-03 | Integrasi | — | 4 nilai (Panjang digest) | 1. Cari collision pada digest terpotong t = 16/24/32 bit 2. Bandingkan kerja empiris dengan √(π/2·2^t) 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Kerja empiris ±20% dari prediksi; klaim penuh = min(n/2, c/2) | M-GENERIC, M-KEYSIZE | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-S-04 | Integrasi | — | SHA-256 | 1. Untuk SHA-2: tunjukkan length-extension pada H(k ∥ m) 2. Pastikan produk memakai HMAC untuk autentikasi 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada konstruksi H(k ∥ m) pada produk | M-PAD | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-S-06 | Sistem | — | SHA-256 | 1. Hitung strength klasik & kuantum (Grover: preimage 2^(n/2)) 2. Bandingkan dengan umur data produk 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Strength ≥ 112 bit (klasik) untuk umur data | M-KEYSIZE | Sedang | Penguji lab + test engineer |
| XA-S-01 | Integrasi | — | ECDSA-P256, SHA-256, HMAC-DRBG-S128 | 1. Kumpulkan keluaran DRBG produk 2. Estimasi min-entropi (SP 800-90B) & SP 800-22 3. Gagalkan sumber entropi (simulasi) dan pastikan keygen berhenti 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Min-entropi ≥ klaim; uji statistik lolos; kegagalan hulu terdeteksi | M-RNG | Tinggi | Penguji lab (Cryptographic Analyst) |
| XA-S-02 | Sistem | — | ECDSA-P256, SHA-256, HMAC-DRBG-S128 | 1. Jalankan siklus lengkap untuk satu kunci tiap kelas primitif 2. Verifikasi kebijakan rotasi & batas penggunaan 3. Pastikan pemusnahan (zeroize) di akhir 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Setiap transisi sesuai kebijakan; kunci termusnahkan | M-ZEROIZE, M-KEYSIZE | Sedang | Penguji lab + test engineer |
| XA-S-04 | Sistem | — | ECDSA-P256, SHA-256, HMAC-DRBG-S128 | 1. Pilih operasi dengan data rahasia (dekripsi RSA-OAEP, signing ECDSA, verifikasi tag AEAD) 2. Kumpulkan ≥ 10^6 pengukuran waktu dari sisi pemanggil API (remote-timing) 3. Coba pulihkan bit kunci/nonce dengan analisis statistik (gaya Brumley–Boneh) 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada informasi kunci yang dapat dipulihkan; \|t\| < 4,5 pada seluruh operasi | M-TIMING, M-CACHE | Tinggi | Penguji lab + test engineer |

### 5.3 Uji Implementasi

| ID | Tingkat | Area | Parameter & nilai uji | Prosedur | Kriteria lulus | Metode UK-1 | Prioritas | Pelaksana |
|---|---|---|---|---|---|---|---|---|
| DS-I-01 | Komponen | — | Fixed-vs-random d dan k; 10^5 pengukuran waktu | 1. Fixed-vs-random d dan k 2. 10^5 pengukuran waktu perkalian skalar 3. Uji TVLA (Welch t) 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | \|t\| < 4,5 | M-TIMING | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-I-02 | Komponen | — | 10^5 trace daya/EM pada token | 1. Akuisisi 10^5 trace daya/EM 2. TVLA; lanjut CPA bila \|t\| ≥ 4,5 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada kebocoran terukur | M-TVLA | Sedang | Penguji lab (Cryptographic Analyst) |
| DS-I-03 | Integrasi | — | Glitch tegangan/clock pada ronde perkalian skalar | 1. Glitch tegangan/clock pada ronde perkalian skalar 2. Kumpulkan tanda tangan keluaran 3. Verifikasi seluruh tanda tangan 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tanda tangan salah tidak pernah dikeluarkan | M-FAULT | Sedang | Penguji lab (Cryptographic Analyst) |
| DS-I-04 | Integrasi | — | 10^6 input DER/ASN.1 malformed | 1. Bangkitkan 10^6 input DER/ASN.1 malformed 2. Fuzzing parser 3. Catat crash/hang & galat 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tanpa crash/hang; galat seragam | M-FUZZ | Sedang | Penguji lab (Cryptographic Analyst) |
| DS-I-05 | Sistem | — | Perintah ekspor kunci, pemutusan daya, reset token | 1. Coba ekspor d melalui API 2. Putus daya/reset token saat operasi 3. Periksa zeroization & audit log 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | d tidak terekspor; log lengkap | M-ZEROIZE | Sedang | Penguji lab + test engineer |
| DS-I-06 | Sistem | — | Beban 1, 10, 100 dokumen paralel | 1. Beban 1, 10, 100 dokumen paralel 2. Ukur throughput & latensi 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Sesuai klaim kinerja produk | M-TIMING | Sedang | Penguji lab + test engineer |
| HF-I-02 | Integrasi | — | SHA-256 | 1. Tag benar vs salah per posisi byte (10^5) 2. Welch t 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | \|t\| < 4,5 | M-TIMING | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-I-03 | Integrasi | — | SHA-256 | 1. Urutan update/final menyimpang 10^6 kali 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tanpa crash; galat terdefinisi | M-FUZZ | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-I-05 | Sistem | — | SHA-256 | 1. Rusak 1 byte berkas; verifikasi 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Kerusakan terdeteksi | M-KAT | Sedang | Penguji lab + test engineer |
| XA-I-01 | Sistem | — | 6 nilai (Kondisi operasional) | 1. Hentikan proses saat operasi kunci 2. Restart & jalankan ulang self-test 3. Uji di bawah beban tinggi 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Sifat keamanan tidak menurun; tidak ada keluaran parsial | M-SELFTEST | Sedang | Penguji lab + test engineer |

**Narasi empiris (contoh):**

- **DS-K-01** — Penguji melakukan aritmetika kurva pada titik khusus pada ECDSA-P256. Uji dinyatakan Memenuhi bila: Hasil identik 100%; n·G = O.
- **DS-K-02** — Penguji melakukan sHA-256: Short/Long Message & Monte Carlo Test pada SHA-256 dengan 9 nilai parameter uji. Uji dinyatakan Memenuhi bila: Digest identik 100%.
- **DS-K-03** — Penguji melakukan validitas pasangan kunci hasil KeyGen pada ECDSA-P256. Uji dinyatakan Memenuhi bila: 100% pasangan kunci valid.
- **DS-K-04** — Penguji melakukan tanda tangan deterministik RFC 6979 pada ECDSA-P256. Uji dinyatakan Memenuhi bila: (r, s) identik dengan vektor acuan.
- **DS-K-05** — Penguji melakukan sigVer ≥ 500 vektor valid & invalid (gaya Wycheproof) pada ECDSA-P256 dengan 2 nilai parameter uji. Uji dinyatakan Memenuhi bila: Valid diterima; seluruh invalid ditolak.
- **DS-K-06** — Penguji melakukan verifikasi silang dokumen bertanda tangan pada ECDSA-P256. Uji dinyatakan Memenuhi bila: Status verifikasi konsisten.
- **DS-K-07** — Penguji melakukan interoperabilitas tanda tangan dengan pustaka referensi pada ECDSA-P256. Uji dinyatakan Memenuhi bila: Status verifikasi konsisten dua arah.
- **HF-K-01** — Penguji melakukan verifikasi permutasi/fungsi kompresi, konstanta & padding pada SHA-256. Uji dinyatakan Memenuhi bila: Identik 100%.

## 6. Expected Value & Kriteria Keputusan (KUK 2.4)

Kriteria keputusan materi: **Deterministik**: KAT/MCT cocok 100%; vektor invalid seluruhnya ditolak.; **Statistik**: α = 0,01; proporsi lolos dalam interval kepercayaan; p-value terdistribusi seragam.; **Kriptanalitik**: Kompleksitas serangan terbaik ≥ klaim tingkat keamanan (bit security).; **Implementasi**: Tidak ada kebocoran terukur (mis. TVLA |t| < 4,5) dan galat seragam.

| Berkas expected | Target | Jenis | Status | Cocok/total | SHA-256 |
|---|---|---|---|---|---|
| curve_points__ECDSA-P256 | ECDSA-P256 | deterministic | COCOK_VEKTOR_RESMI | 4/4 | c630bf4399771847… |
| domain_params__ECDSA-P256 | ECDSA-P256 | deterministic | COCOK_VEKTOR_RESMI | 2/2 | e303e371ae4d4950… |
| hash_boundaries__SHA-256 | SHA-256 | deterministic | COCOK_VEKTOR_RESMI | 9/9 | 0d9fbf5706c154ea… |
| rfc6979__ECDSA-P256 | ECDSA-P256 | deterministic | COCOK_VEKTOR_RESMI | 4/4 | 1b343225ff5109f2… |
| sigver__ECDSA-P256 | ECDSA-P256 | deterministic | COCOK_VEKTOR_RESMI | 516/516 | c331a7418794f46d… |
| interop__ECDSA-P256 | ECDSA-P256 | deterministic | KRITERIA | — | b9371962a2cb9408… |
| interop__HMAC-DRBG-S128 | HMAC-DRBG-S128 | deterministic | KRITERIA | — | 6344cbbaf8b156d5… |
| interop__SHA-256 | SHA-256 | deterministic | KRITERIA | — | 7201df6e641b2a4f… |
| keygen_validate__ECDSA-P256 | ECDSA-P256 | deterministic | KRITERIA | — | a58409404cdbd688… |
| mct__SHA-256 | SHA-256 | deterministic | KRITERIA | — | 6bd284dc3043d86a… |
| performance__ECDSA-P256 | ECDSA-P256 | implementation | PERLU_VERIFIKASI | — | 147b2d588fbaa78e… |
| pubkey_negative__ECDSA-P256 | ECDSA-P256 | negative | KRITERIA | — | 83e3bb96cd5af261… |
| reject_params__ECDSA-P256 | ECDSA-P256 | negative | KRITERIA | — | a813a3950a7ed469… |
| reject_params__SHA-256 | SHA-256 | negative | KRITERIA | — | e155a7bf882c987c… |
| ssp_lifecycle__ECDSA-P256 | ECDSA-P256 | deterministic | KRITERIA | — | dcf88fa6148ab5b5… |
| ssp_lifecycle__HMAC-DRBG-S128 | HMAC-DRBG-S128 | deterministic | KRITERIA | — | 3a2e16fbf77c5b06… |
| ssp_lifecycle__SHA-256 | SHA-256 | deterministic | KRITERIA | — | 4fcb496648c42850… |

## 7. Pemetaan Parameter → Kemungkinan Hasil Uji (KUK 2.5)

Kategori hasil: **Memenuhi** — Seluruh kriteria terpenuhi pada semua variasi parameter yang ditetapkan.; **Memenuhi dengan Catatan** — Lulus, tetapi terdapat batasan penggunaan (mis. batas data per kunci, parameter minimum).; **Tidak Memenuhi** — Minimal satu kriteria gagal; parameter pemicu kegagalan diidentifikasi.; **Inkonklusif** — Bukti statistik belum cukup; diperlukan sampel lebih besar atau uji lanjutan.

| Kondisi temuan | Parameter pemicu | Kemungkinan hasil | Tindak lanjut | Sumber |
|---|---|---|---|---|
| Nilai r berulang ditemukan pada pesan berbeda | Mode nonce | Tidak Memenuhi | Temuan kritis: kunci privat dapat dipulihkan; perbaiki pembangkitan nonce | materi (ecdsa_p256_token) |
| Bias ≥ 1 bit pada MSB/LSB nonce k | Mode nonce, ukuran sampel | Tidak Memenuhi | Rawan serangan lattice/HNP; uji ulang setelah perbaikan | materi (ecdsa_p256_token) |
| Proporsi lolos di tepi interval kepercayaan | Ukuran sampel | Inkonklusif | Perbesar N (mis. 10^7) lalu ulangi uji statistik | materi (ecdsa_p256_token) |
| Tanda tangan s ↔ n − s diterima | Encoding (r, s) | Memenuhi dengan Catatan | Dapat diterima bila keunikan tanda tangan tidak diandalkan; terapkan low-s | materi (ecdsa_p256_token) |
| TVLA \|t\| ≥ 4,5 pada perkalian skalar | Kunci privat d | Tidak Memenuhi | Konfirmasi eksploitabilitas dengan CPA; perbaiki ke constant-time | materi (ecdsa_p256_token) |
| Gagal diverifikasi oleh satu verifier referensi | Encoding, format dokumen | Memenuhi dengan Catatan | Perbaiki encoding; ulangi DS-K-06 | materi (ecdsa_p256_token) |
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
| OBJ:ECDSA-P256 | Kesesuaian ECDSA-P256 terhadap standar | M-CURVE | SCN-DS-KOM-K | DS-K-01 | — | FIPS-186-5, SP-800-186 |
| OBJ:SHA-256 | Kesesuaian SHA-256 terhadap standar | M-KAT | SCN-DS-KOM-K | DS-K-02 | — | FIPS-180-4 |
| OBJ:ECDSA-P256 | Kesesuaian ECDSA-P256 terhadap standar | M-PKV | SCN-DS-INT-K | DS-K-03 | — | FIPS-186-5, SP-800-186 |
| OBJ:ECDSA-P256 | Kesesuaian ECDSA-P256 terhadap standar | M-KAT | SCN-DS-INT-K | DS-K-04 | — | RFC-6979, FIPS-186-5 |
| OBJ:ECDSA-P256 | Kesesuaian ECDSA-P256 terhadap standar | M-KAT | SCN-DS-INT-K | DS-K-05 | — | FIPS-186-5, ISO-14888-3 |
| OBJ:ECDSA-P256 | Kesesuaian ECDSA-P256 terhadap standar | M-KAT | SCN-DS-SIS-K | DS-K-06 | — | ISO-18367 |
| OBJ:ECDSA-P256 | Kesesuaian ECDSA-P256 terhadap standar | M-KAT | SCN-DS-SIS-K | DS-K-07 | — | ISO-18367 |
| OBJ:SHA-256 | Kesesuaian SHA-256 terhadap standar | M-KAT | SCN-HF-KOM-K | HF-K-01 | — | FIPS-202, FIPS-180-4, ISO-10118-3 |
| OBJ:SHA-256 | Kesesuaian SHA-256 terhadap standar | M-KAT | SCN-HF-INT-K | HF-K-02 | — | FIPS-202, FIPS-180-4 |
| OBJ:SHA-256 | Kesesuaian SHA-256 terhadap standar | M-MCT | SCN-HF-INT-K | HF-K-03 | — | ISO-18367 |
| OBJ:SHA-256 | Kesesuaian SHA-256 terhadap standar | M-KAT | SCN-HF-SIS-K | HF-K-06 | — | ISO-18367 |
| C-STRENGTH | 128 bit | M-CURVE | SCN-DS-KOM-S | DS-S-01 | — | SP-800-186, FIPS-186-5 |
| C-EUF | EUF-CMA | M-NONCE | SCN-DS-INT-S | DS-S-02 | — | FIPS-186-5, RFC-6979 |
| C-EUF | EUF-CMA | M-NONCE | SCN-DS-INT-S | DS-S-02 | — | FIPS-186-5, RFC-6979 |
| C-EUF | EUF-CMA | M-NONCE | SCN-DS-INT-S | DS-S-03 | — | FIPS-186-5 |
| C-EUF | EUF-CMA | M-NONCE | SCN-DS-INT-S | DS-S-03 | — | FIPS-186-5 |
| C-EUF | EUF-CMA | M-PKV | SCN-DS-INT-S | DS-S-04 | — | SP-800-186 |
| C-EUF | EUF-CMA | M-RNG | SCN-DS-INT-S | DS-S-05 | — | SP-800-90B, SP-800-22 |
| C-EUF | EUF-CMA | M-SIGMAL | SCN-DS-SIS-S | DS-S-06 | — | ISO-14888-3 |
| C-STRENGTH | 128 bit | M-KEYSIZE | SCN-DS-SIS-S | DS-S-07 | — | SP-800-57, FIPS-204, SP-800-186 |
| C-EUF | EUF-CMA | M-KEYSIZE | SCN-DS-SIS-S | DS-S-07 | — | SP-800-57, FIPS-204, SP-800-186 |
| C-EUF | EUF-CMA | M-SIGMAL | SCN-DS-INT-S | DS-S-08 | — | FIPS-186-5 |
| C-NOEXP | Kunci privat tidak dapat diekspor | M-ZEROIZE | SCN-DS-SIS-S | DS-S-09 | — | ISO-19790 |
| OBJ:SHA-256 | Kesesuaian SHA-256 terhadap standar | M-AVAL | SCN-HF-INT-S | HF-S-02 | — | SP-800-22 |
| C-STRENGTH | 128 bit | M-GENERIC | SCN-HF-INT-S | HF-S-03 | — | SP-800-107, FIPS-202 |
| OBJ:SHA-256 | Kesesuaian SHA-256 terhadap standar | M-PAD | SCN-HF-INT-S | HF-S-04 | — | SP-800-107 |
| C-STRENGTH | 128 bit | M-KEYSIZE | SCN-HF-SIS-S | HF-S-06 | — | SP-800-57, SP-800-107 |
| OBJ:ECDSA-P256 | Kesesuaian ECDSA-P256 terhadap standar | M-TIMING | SCN-DS-KOM-I | DS-I-01 | — | ISO-17825 |
| OBJ:ECDSA-P256 | Kesesuaian ECDSA-P256 terhadap standar | M-TVLA | SCN-DS-KOM-I | DS-I-02 | — | ISO-17825, ISO-20085 |
| OBJ:ECDSA-P256 | Kesesuaian ECDSA-P256 terhadap standar | M-FAULT | SCN-DS-INT-I | DS-I-03 | — | ISO-19790 |
| OBJ:ECDSA-P256 | Kesesuaian ECDSA-P256 terhadap standar | M-FUZZ | SCN-DS-INT-I | DS-I-04 | — | ISO-29119 |
| C-NOEXP | Kunci privat tidak dapat diekspor | M-ZEROIZE | SCN-DS-SIS-I | DS-I-05 | — | ISO-19790 |
| OBJ:ECDSA-P256 | Kesesuaian ECDSA-P256 terhadap standar | M-TIMING | SCN-DS-SIS-I | DS-I-06 | — | ISO-29119 |
| OBJ:SHA-256 | Kesesuaian SHA-256 terhadap standar | M-TIMING | SCN-HF-INT-I | HF-I-02 | — | ISO-17825 |
| OBJ:SHA-256 | Kesesuaian SHA-256 terhadap standar | M-FUZZ | SCN-HF-INT-I | HF-I-03 | — | ISO-29119 |
| OBJ:SHA-256 | Kesesuaian SHA-256 terhadap standar | M-KAT | SCN-HF-SIS-I | HF-I-05 | — | ISO-29119 |
| OBJ:ECDSA-P256 | Kesesuaian ECDSA-P256, SHA-256, HMAC-DRBG-S128 terhadap standar | M-KAT | SCN-XA-INT-K | XA-K-01 | — | ISO-18367 |
| OBJ:ECDSA-P256 | Kesesuaian ECDSA-P256, SHA-256, HMAC-DRBG-S128 terhadap standar | M-RNG | SCN-XA-INT-S | XA-S-01 | — | SP-800-90A, SP-800-90B, SP-800-22 |
| C-STRENGTH | 128 bit | M-ZEROIZE | SCN-XA-SIS-S | XA-S-02 | — | SP-800-57, ISO-19790 |
| OBJ:ECDSA-P256 | Kesesuaian ECDSA-P256, SHA-256, HMAC-DRBG-S128 terhadap standar | M-TIMING | SCN-XA-SIS-S | XA-S-04 | — | ISO-17825, ISO-20085 |
| OBJ:ECDSA-P256 | Kesesuaian ECDSA-P256, SHA-256, HMAC-DRBG-S128 terhadap standar | M-SELFTEST | SCN-XA-SIS-I | XA-I-01 | — | ISO-19790 |

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
