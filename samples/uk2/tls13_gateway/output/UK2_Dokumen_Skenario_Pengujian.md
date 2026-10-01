# Dokumen Skenario Pengujian — Gateway-TLS13

**Cryptan.ID Test Suite** · Modul **UK-2** · Unit J.61KRP00.013.1 — *Menyusun Skenario Pengujian* · SKKNI 2023-004 (Cryptographic Analyst)

Dibangkitkan 2026-10-01T13:47:18+07:00 · model 3 tingkat · masukan UK-1: `samples/uk2/tls13_gateway/uk1_stub.json`

> Objek uji & data produk ILUSTRATIF. HASIL UJI LANGSUNG = dihitung kode; LITERATUR/ACUAN = dikutip dengan rujukan; PERLU_VERIFIKASI = belum dapat dihitung/dicocokkan, tidak dikarang.

## Ringkasan

- Objek uji: **7** kombinasi · kategori: block, hash, pke, signature, protocol
- Metode UK-1 ditelaah: 6 (relevan 6) · sel kosong diisi templat: 42
- Skenario: **48** · test case: **74** (K 26 · S 29 · I 19)
- Verifikasi terhadap spesifikasi desain: **LULUS** (0 temuan)
- Expected value: 8 cocok vektor resmi · 77 kriteria · 9 PERLU_VERIFIKASI

## 1. Profil Objek Uji & Ruang Parameter

| Atribut | Nilai |
|---|---|
| Produk | Gateway-TLS13 1.0 (ilustratif) |
| Deskripsi | Modul TLS 1.3 pada gateway layanan dengan autentikasi mutual |
| Jenis produk | gateway |
| Model tingkat | 3 (Komponen → Integrasi → Sistem) |
| SL ISO/IEC 19790 | tidak berlaku |
| Fitur | aead, api, certificates, error_codes, formal_model, fuzzing_harness, hybrid_kem, kdf, kem, load_testing, mutual_auth, network, protocol_tls13, revocation, session_resumption, session_tickets, signature, timing_measurement, zero_rtt |

**Klaim keamanan:**

| ID | Klaim | Tag |
|---|---|---|
| C-CONF | Kerahasiaan kunci sesi | secrecy |
| C-MAUTH | Autentikasi mutual | mutual_auth |
| C-FS | Forward secrecy | forward_secrecy |
| C-DOWN | Ketahanan downgrade | downgrade |
| C-REPLAY | Ketahanan replay | replay |

**Objek uji (algorithms_under_test):**

| ID | Kategori | Varian | Kunci | Strength | Status NIST |
|---|---|---|---|---|---|
| AES-256-GCM | block | GCM | 256 | 256 | acceptable |
| SHA-384 | hash | SHA-384 | — | 192 | acceptable |
| HKDF | hash | HKDF | — | PERLU_VERIFIKASI | acceptable |
| ECDH-P384 | pke | P-384 | 384 | 192 | acceptable |
| X25519 | pke | X25519 | 255 | 128 | PERLU_VERIFIKASI |
| ML-KEM-768 | pke | ML-KEM-768 | — | 192 | acceptable |
| ECDSA-P384 | signature | P-384 | 384 | 192 | acceptable |

### 1.1 Ruang parameter — block

| ID | Parameter | Kelas | Status | Nilai uji (teknik) |
|---|---|---|---|---|
| BC-KEY-LEN | Panjang kunci | Parameter publik/domain | Tetap | 0 [BVA, NEG]; 248 [BVA, NEG]; 256 [EP]; 264 [BVA, NEG] |
| BC-KEY-VAL | Nilai kunci | Material rahasia | Variabel | acak (DRBG) [EP]; nol-semua (0x00…) [DEG]; satu-semua (0xFF…) [DEG]; low-density (HW = 1) [DEG]; high-density (HW = n−1) [DEG]; related-key (beda 1 bit) [BIT]; kunci lemah/semi-lemah (bila ada) [DEG] |
| BC-PT | Blok plaintext | Data masukan | Variabel | acak [EP]; nol-semua (0x00…) [DEG]; satu-semua (0xFF…) [DEG]; low-density (HW = 1) [DEG]; high-density (HW = n−1) [DEG]; periodik (0x55/0xAA) [DEG]; 1-bit flip pada tiap posisi (n = 128) [BIT] |
| BC-MODE | Mode operasi | Konfigurasi | Tetap | CBC [EP, NEG]; CTR [EP, NEG]; ECB [EP, NEG]; GCM [EP]; XTS [EP, NEG] |
| BC-IV | IV/nonce | Material rahasia | Variabel | acak 96 bit [EP]; counter berurutan [EP]; nol [DEG, NEG]; berulang (reuse) [NEG, NEG]; dapat diprediksi (CBC) [NEG, NEG]; panjang non-96 bit (GCM) [BVA] |
| BC-LEN | Panjang pesan & padding | Data masukan | Variabel | 0 [BVA]; 1 [BVA]; 15 [BVA]; 16 [BVA]; 17 [BVA]; 1048576 [EP] |
| BC-ROUNDS | Jumlah ronde | Konfigurasi | Variabel | penuh (10/12/14) [EP]; tereduksi 2–4 ronde (analisis) [BVA] |
| ENV | Kondisi operasional | Kondisi lingkungan | Tetap | normal [EP] |

Reduksi pairwise (t = 2. IPOG) atas 3 parameter Variabel: **84** kombinasi penuh → **42** kombinasi pairwise (50.0% berkurang; semua pasangan tercakup: True).

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
| PK-DOM | Ukuran kunci & domain | Parameter publik/domain | Variabel | ECDH-P384 [EP]; ML-KEM-768 [EP]; X25519 [EP] |
| PK-KEYGEN | Kualitas pembangkitan kunci | Material rahasia | Tetap | DRBG produk (normal) [EP]; entropi rendah (simulasi, batch-GCD) [NEG, NEG] |
| PK-PAD | Skema padding | Konfigurasi | Tetap | OAEP (SHA-256/MGF1) [EP, NEG]; PKCS#1 v1.5 [NEG, NEG]; FO transform (KEM) [EP] |
| PK-CT | Ciphertext masukan | Data masukan | Tetap | valid [EP]; termodifikasi 1 bit [BIT, NEG]; malformed (panjang ±1) [NEG, NEG]; di luar rentang (c ≥ n) [BVA, NEG] |
| PK-PEER | Kunci publik lawan | Data masukan | Tetap | valid [EP]; titik tidak di kurva [NEG, NEG]; subgrup kecil / low-order [NEG, NEG]; titik tak hingga [BVA, NEG] |
| ENV | Kondisi operasional | Kondisi lingkungan | Tetap | normal [EP] |

Reduksi pairwise (t = 2. IPOG) atas 1 parameter Variabel: **3** kombinasi penuh → **3** kombinasi pairwise (0.0% berkurang; semua pasangan tercakup: True).

### 1.4 Ruang parameter — signature

| ID | Parameter | Kelas | Status | Nilai uji (teknik) |
|---|---|---|---|---|
| DS-ALG | Kurva & hash / parameter set | Parameter publik/domain | Tetap | ECDSA-P384 [EP] |
| DS-NONCE | Mode nonce | Konfigurasi | Tetap | rfc6979 [EP]; bias beberapa bit (simulasi) [NEG, NEG]; berulang (simulasi) [NEG, NEG] |
| DS-MSG | Panjang pesan | Data masukan | Variabel | 0 [BVA]; 1 [BVA]; 55 [BVA]; 56 [BVA]; 63 [BVA]; 64 [BVA]; 65 [BVA]; 1048576 [EP]; 104857600 [EP] |
| DS-D | Kunci privat d | Material rahasia | Variabel | acak [EP]; Hamming weight rendah [DEG]; Hamming weight tinggi [DEG]; d = 1 [BVA]; d = n − 1 [BVA]; d = 0 [BVA, NEG]; d = n [BVA, NEG] |
| DS-ENC | Encoding (r, s) | Data masukan | Variabel | DER kanonik [EP]; DER non-kanonik [NEG, NEG]; r atau s = 0 [BVA, NEG]; r atau s ≥ n [BVA, NEG]; s ↔ n − s [NEG] |
| DS-Q | Kunci publik Q | Data masukan | Tetap | valid [EP]; titik tak hingga O [BVA, NEG]; di luar kurva [NEG, NEG]; koordinat ≥ p [BVA, NEG] |
| DS-N | Ukuran sampel | Konfigurasi | Variabel | N = 1.000.000 tanda tangan (uji nonce) [EP]; 100.000 trace/pengukuran (side-channel) [EP] |
| ENV | Kondisi operasional | Kondisi lingkungan | Tetap | normal [EP] |

Reduksi pairwise (t = 2. IPOG) atas 3 parameter Variabel: **36** kombinasi penuh → **18** kombinasi pairwise (50.0% berkurang; semua pasangan tercakup: True).

### 1.5 Ruang parameter — protocol

| ID | Parameter | Kelas | Status | Nilai uji (teknik) |
|---|---|---|---|---|
| PR-VER | Versi protokol | Konfigurasi | Tetap | TLS 1.3 [EP]; TLS 1.2 [NEG, NEG]; TLS 1.1 [NEG, NEG]; TLS 1.0 [NEG, NEG]; SSL 3.0 [NEG, NEG] |
| PR-SUITE | Cipher suite | Konfigurasi | Tetap | TLS_AES_256_GCM_SHA384 [EP]; CBC (TLS 1.2) [NEG, NEG]; RC4 [NEG, NEG]; 3DES [NEG, NEG]; NULL [NEG, NEG] |
| PR-GROUP | Grup pertukaran kunci | Parameter publik/domain | Variabel | secp384r1 [EP]; x25519 [EP]; X25519MLKEM768 [EP]; grup tidak didukung (memicu HRR) [BVA] |
| PR-KS | Nilai publik key share | Data masukan | Tetap | valid [EP]; di luar kurva [NEG, NEG]; titik tak hingga [BVA, NEG]; low-order X25519 [NEG, NEG]; panjang salah [BVA, NEG] |
| PR-CERT | Sertifikat klien | Material rahasia | Tetap | valid [EP]; kedaluwarsa [NEG, NEG]; dicabut [NEG, NEG]; self-signed [NEG, NEG]; CA asing [NEG, NEG]; nama tidak cocok [NEG, NEG] |
| PR-ORDER | Urutan pesan | Data masukan | Tetap | normal [EP]; dilewati [NEG, NEG]; diulang [NEG, NEG]; disisipkan [NEG, NEG] |
| PR-0RTT | Replay & 0-RTT | Konfigurasi | Variabel | nonaktif [EP]; aktif [EP]; replay ClientHello & early data [NEG, NEG] |
| PR-NET | Kondisi jaringan | Kondisi lingkungan | Variabel | normal [EP]; latensi 500 ms [BVA]; loss 5% [BVA]; putus di tengah handshake [BVA]; OCSP tak terjangkau [BVA] |
| ENV | Kondisi operasional | Kondisi lingkungan | Tetap | normal [EP] |

Reduksi pairwise (t = 2. IPOG) atas 3 parameter Variabel: **40** kombinasi penuh → **20** kombinasi pairwise (50.0% berkurang; semua pasangan tercakup: True).

## 2. Telaah Metode & Parameter (KUK 1.1, 1.2)

Empat kebutuhan pengujian SKKNI: N1 jenis algoritma · N2 desain & teknik implementasi · N3 tren serangan · N4 best practice.

| Metode | Sel (tingkat × lapis) | N1 | N2 | N3 | N4 | Asal UK-1 | Putusan |
|---|---|---|---|---|---|---|---|
| M-KAT Known Answer Test | Komponen × K | ✔ | ✔ | ✔ | ✔ | TLS13 (STUB_UK1) | RELEVAN |
| M-PKV Validasi kunci publik / key share | Komponen × K | ✔ | ✔ | ✔ | ✔ | TLS13 (STUB_UK1) | RELEVAN |
| M-FUZZ Fuzzing state machine & parser | Integrasi × I | ✔ | ✔ | ✔ | ✔ | TLS13 (STUB_UK1) | RELEVAN |
| M-TIMING Timing leakage | Integrasi × I | ✔ | ✔ | ✔ | ✔ | TLS13 (STUB_UK1) | RELEVAN |
| M-NONCE Replay / nonce | Integrasi × I | ✔ | ✔ | ✔ | ✔ | TLS13 (STUB_UK1) | RELEVAN |
| M-KEYSIZE Ukuran kunci & grup | Sistem × S | ✔ | ✔ | ✔ | ✔ | TLS13 (STUB_UK1) | RELEVAN |

Sel kosong (42) diisi dari templat kategori materi: block:Komponen×K, block:Komponen×S, block:Komponen×I, block:Integrasi×K, block:Integrasi×S, block:Integrasi×I, block:Sistem×K, block:Sistem×S, block:Sistem×I, hash:Komponen×K, hash:Komponen×S, hash:Komponen×I, hash:Integrasi×K, hash:Integrasi×S, hash:Integrasi×I, hash:Sistem×K, hash:Sistem×S, hash:Sistem×I, pke:Komponen×K, pke:Komponen×S, pke:Komponen×I, pke:Integrasi×K, pke:Integrasi×S, pke:Integrasi×I, pke:Sistem×K, pke:Sistem×S, pke:Sistem×I, protocol:Komponen×S, protocol:Komponen×I, protocol:Integrasi×K…

Teknik penetapan nilai uji: EP = Partisi ekuivalensi; BVA = Analisis nilai batas; DEG = Input degeneratif/berpola; BIT = Variasi 1-bit (diferensial); TWAY = Kombinatorial t-way (pairwise); NEG = Negative testing

## 3. Matriks Skenario Lapis × Tingkat (KUK 2.1)

**block**

| Tingkat | Uji Kesesuaian | Uji Keamanan | Uji Implementasi |
|---|---|---|---|
| Komponen | SCN-BC-KOM-K: BC-K-01 | SCN-BC-KOM-S: BC-S-01 | SCN-BC-KOM-I: BC-I-01 |
| Integrasi | SCN-BC-INT-K: BC-K-02, BC-K-03, BC-K-04, BC-K-05 | SCN-BC-INT-S: BC-S-02, BC-S-03, BC-S-04 | SCN-BC-INT-I: BC-I-02, BC-I-03 |
| Sistem | SCN-BC-SIS-K: BC-K-06 | SCN-BC-SIS-S: BC-S-05, BC-S-06 | SCN-BC-SIS-I: BC-I-06 |

**hash**

| Tingkat | Uji Kesesuaian | Uji Keamanan | Uji Implementasi |
|---|---|---|---|
| Komponen | SCN-HF-KOM-K: HF-K-01 | SCN-HF-KOM-S: TIDAK BERLAKU — tidak ada resep yang memenuhi fitur produk | SCN-HF-KOM-I: TIDAK BERLAKU — tidak ada resep yang memenuhi fitur produk |
| Integrasi | SCN-HF-INT-K: HF-K-02, HF-K-03, HF-K-05 | SCN-HF-INT-S: HF-S-02, HF-S-03, HF-S-04 | SCN-HF-INT-I: HF-I-02, HF-I-03 |
| Sistem | SCN-HF-SIS-K: HF-K-06 | SCN-HF-SIS-S: HF-S-06 | SCN-HF-SIS-I: HF-I-05 |

**pke**

| Tingkat | Uji Kesesuaian | Uji Keamanan | Uji Implementasi |
|---|---|---|---|
| Komponen | SCN-PK-KOM-K: PK-K-01 | SCN-PK-KOM-S: PK-S-01 | SCN-PK-KOM-I: PK-I-01 |
| Integrasi | SCN-PK-INT-K: PK-K-02, PK-K-05 | SCN-PK-INT-S: PK-S-03, PK-S-05 | SCN-PK-INT-I: PK-I-02, PK-I-03 |
| Sistem | SCN-PK-SIS-K: TIDAK BERLAKU — tidak ada resep yang memenuhi fitur produk | SCN-PK-SIS-S: PK-S-06 | SCN-PK-SIS-I: TIDAK BERLAKU — tidak ada resep yang memenuhi fitur produk |

**signature**

| Tingkat | Uji Kesesuaian | Uji Keamanan | Uji Implementasi |
|---|---|---|---|
| Komponen | SCN-DS-KOM-K: DS-K-01, DS-K-02 | SCN-DS-KOM-S: DS-S-01 | SCN-DS-KOM-I: DS-I-01 |
| Integrasi | SCN-DS-INT-K: DS-K-04, DS-K-05 | SCN-DS-INT-S: DS-S-02, DS-S-03, DS-S-04, DS-S-08 | SCN-DS-INT-I: DS-I-04 |
| Sistem | SCN-DS-SIS-K: DS-K-07 | SCN-DS-SIS-S: DS-S-07 | SCN-DS-SIS-I: TIDAK BERLAKU — tidak ada resep yang memenuhi fitur produk |

**protocol**

| Tingkat | Uji Kesesuaian | Uji Keamanan | Uji Implementasi |
|---|---|---|---|
| Komponen | SCN-PR-KOM-K: PR-K-01, PR-K-02 | SCN-PR-KOM-S: PR-S-01 | SCN-PR-KOM-I: TIDAK BERLAKU — tidak ada resep yang memenuhi fitur produk |
| Integrasi | SCN-PR-INT-K: PR-K-03, PR-K-04, PR-K-05 | SCN-PR-INT-S: PR-S-02, PR-S-03, PR-S-04 | SCN-PR-INT-I: PR-I-01, PR-I-02, PR-I-03 |
| Sistem | SCN-PR-SIS-K: PR-K-06 | SCN-PR-SIS-S: PR-S-05, PR-S-06 | SCN-PR-SIS-I: PR-I-04, PR-I-05, PR-I-06 |

**cross**

| Tingkat | Uji Kesesuaian | Uji Keamanan | Uji Implementasi |
|---|---|---|---|
| Integrasi | SCN-XA-INT-K: XA-K-01 | — | — |
| Sistem | — | SCN-XA-SIS-S: XA-S-02, XA-S-04, XA-S-03 | SCN-XA-SIS-I: XA-I-01 |

**Lintas-algoritma:** RNG / Sumber Entropi → Pembangkitan Kunci → KDF → Cipher / MAC / Signature → Protokol → Produk · skenario: XA-K-01, XA-S-02, XA-S-04, XA-I-01, XA-S-03 · PQC relevan: True

**Resep tidak berlaku (fitur/objek tidak dimiliki produk — aturan f):**

| Resep | Alasan |
|---|---|
| BC-I-04 | fitur produk tidak ada: power_glitch |
| BC-I-05 | fitur produk tidak ada: multi_thread |
| HF-K-04 | fitur produk tidak ada: streaming_api |
| HF-S-01 | tidak ada objek uji yang sesuai (applies) |
| HF-S-05 | tidak ada objek uji yang sesuai (applies) |
| HF-I-01 | fitur produk tidak ada: streaming_api |
| HF-I-04 | fitur produk tidak ada: multi_thread |
| HF-I-06 | fitur produk tidak ada: key_import_export |
| PK-K-03 | tidak ada objek uji yang sesuai (applies) |
| PK-K-04 | fitur produk tidak ada: keygen |
| PK-K-06 | fitur produk tidak ada: key_import_export |
| PK-S-02 | tidak ada objek uji yang sesuai (applies) |
| PK-S-04 | fitur produk tidak ada: keygen |
| PK-I-04 | fitur produk tidak ada: key_import_export |
| PK-I-05 | fitur produk tidak ada: multi_thread |
| PK-I-06 | fitur produk tidak ada: power_glitch |
| DS-K-03 | fitur produk tidak ada: keygen |
| DS-K-06 | fitur produk tidak ada: pdf_signing |
| DS-S-05 | fitur produk tidak ada: rng_internal |
| DS-S-06 | fitur produk tidak ada: pdf_signing |
| DS-I-02 | fitur produk tidak ada: side_channel_lab, token |
| DS-I-03 | fitur produk tidak ada: power_glitch |
| DS-I-05 | fitur produk tidak ada: key_non_exportable |
| DS-I-06 | fitur produk tidak ada: multi_doc_signing |
| DS-K-08 | tidak ada objek uji yang sesuai (applies) |
| DS-S-09 | fitur produk tidak ada: key_non_exportable |
| XA-S-01 | fitur produk tidak ada: rng_internal |

## 4. Laporan Verifikasi terhadap Spesifikasi Desain (KUK 2.2 — aspek kritis)

Status keseluruhan: **LULUS** · 0 temuan

| Aturan | Deskripsi | Diperiksa | Status | Temuan |
|---|---|---|---|---|
| (a) | Cakupan algoritma, varian, panjang kunci, mode & parameter set profil | 7 | LULUS | — |
| (b) | Nilai di luar spesifikasi hanya sebagai negative test (harapan ditolak) | 192 | LULUS | — |
| (c) | Setiap klaim keamanan punya ≥ 1 skenario Uji Keamanan | 5 | LULUS | — |
| (d) | Setiap metode UK-1 punya ≥ 1 skenario | 6 | LULUS | — |
| (e) | Modul: 11 area ISO/IEC 19790 (7.2–7.12) tercakup / dijustifikasi | 0 | TIDAK BERLAKU | — |
| (f) | Tidak ada skenario untuk fitur/objek yang tidak dimiliki produk | 74 | LULUS | — |

## 5. Katalog Test Case (KUK 2.3)

### 5.1 Uji Kesesuaian

| ID | Tingkat | Area | Parameter & nilai uji | Prosedur | Kriteria lulus | Metode UK-1 | Prioritas | Pelaksana |
|---|---|---|---|---|---|---|---|---|
| BC-K-01 | Komponen | — | 1 nilai (Panjang kunci) | 1. Ambil vektor contoh per ronde (FIPS 197 App. B/C) untuk kunci yang didukung 2. Jalankan unit enkripsi produk dengan trace nilai antara (build analisis) 3. Bandingkan state awal/akhir tiap ronde & round key dengan implementasi referensi core/ 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruh nilai antara & round key identik 100% | M-KAT, M-SBOX | Tinggi | Penguji lab (Cryptographic Analyst) |
| BC-K-02 | Integrasi | — | 2 nilai (Mode operasi, Panjang kunci) | 1. Muat berkas expected value untuk target 2. Eksekusi enkripsi/dekripsi produk pada setiap vektor 3. Catat keluaran & bandingkan byte-per-byte 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Ciphertext/tag/plaintext identik 100% dengan vektor resmi; vektor invalid ditolak | M-KAT | Tinggi | Penguji lab (Cryptographic Analyst) |
| BC-K-03 | Integrasi | — | 7 nilai (Mode operasi, Panjang pesan & padding) | 1. Jalankan MCT 100 × 1000 iterasi berantai (gaya CAVP) 2. Jalankan MMT 1–10 blok per mode 3. Bandingkan 100 checkpoint dengan core/ atau pustaka tepercaya 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | 100% checkpoint identik | M-MCT | Sedang | Penguji lab (Cryptographic Analyst) |
| BC-K-04 | Integrasi | — | 13 nilai (Blok plaintext, Panjang pesan & padding) | 1. Bangkitkan pesan pada setiap nilai batas panjang (0, 1, b−1, b, b+1, 1 MiB) 2. Enkripsi lalu dekripsi dengan kunci & nonce yang sama 3. Bandingkan dengan pesan asli 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | D(E(x)) = x untuk 100% kasus | M-KAT, M-FUZZ | Sedang | Penguji lab (Cryptographic Analyst) |
| BC-K-05 | Integrasi | — | 9 nilai (Mode operasi, Panjang kunci) | 1. Panggil API dengan panjang kunci & mode yang tidak didukung (nilai NEG ruang parameter) 2. Catat kode galat 3. Pastikan tidak ada keluaran kriptografis 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruh parameter di luar spesifikasi ditolak dengan galat terdefinisi | M-FUZZ | Tinggi | Penguji lab (Cryptographic Analyst) |
| BC-K-06 | Sistem | — | 1 nilai (Mode operasi) | 1. Enkripsi data dengan produk, dekripsi dengan pustaka referensi (OpenSSL/pyca) 2. Lakukan arah sebaliknya 3. Periksa format (IV ∥ CT ∥ tag) sesuai dokumentasi 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Interoperabel dua arah 100% | M-KAT | Sedang | Penguji lab + test engineer |
| DS-K-01 | Komponen | — | Titik khusus: O, P + (−P), P + P, n·G | 1. Hitung O, P + (−P), P + P, n·G dengan produk 2. Hitung yang sama dengan implementasi referensi core/ 3. Bandingkan seluruh hasil 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Hasil identik 100%; n·G = O | M-CURVE, M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| DS-K-02 | Komponen | — | Pesan 0, 55, 56, 64, 65 byte dan 1 MB · 9 nilai (Panjang pesan) | 1. Hash pesan pada nilai batas panjang (b = 64: 0, 55, 56, 64, 65 byte) dan 1 MB 2. Jalankan MCT SHA-256 3. Bandingkan digest 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Digest identik 100% | M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| DS-K-04 | Integrasi | — | Vektor uji RFC 6979 (P-256, SHA-256) | 1. Gunakan d & pesan dari vektor RFC 6979 A.2.5 2. Bangkitkan (r, s) dengan produk 3. Bandingkan dengan vektor acuan 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | (r, s) identik dengan vektor acuan | M-KAT | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-K-05 | Integrasi | — | ≥ 500 vektor SigVer: valid dan seluruh variasi encoding invalid · 2 nilai (Encoding (r, s)) | 1. Muat vektor SigVer (Wycheproof + mutasi encoding) 2. Verifikasi tiap vektor dengan produk 3. Catat terima/tolak per vektor 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Valid diterima; seluruh invalid ditolak | M-KAT, M-SIGMAL | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-K-07 | Sistem | — | ECDSA-P384 | 1. Tanda tangani pesan dengan produk; verifikasi dengan OpenSSL/pyca 2. Arah sebaliknya 3. Untuk EdDSA/ML-DSA gunakan vektor resmi 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Status verifikasi konsisten dua arah | M-KAT | Sedang | Penguji lab + test engineer |
| HF-K-01 | Komponen | — | SHA-384 | 1. Bandingkan konstanta ronde & offset rotasi dengan standar 2. Jalankan permutasi pada state uji (core/) 3. Periksa padding pad10*1 / MD-strengthening pada batas b 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Identik 100% | M-KAT, M-PAD | Tinggi | Penguji lab (Cryptographic Analyst) |
| HF-K-02 | Integrasi | — | 16 nilai (Panjang pesan SHA-384 (b = 128 B), Pola pesan) | 1. Hash pesan pada setiap nilai batas (0, 1, b−L−1, b−L, b−1, b, b+1, 1 MiB) 2. Bandingkan dengan expected value (dua implementasi independen + vektor resmi) 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Digest identik 100% | M-KAT, M-PAD | Tinggi | Penguji lab (Cryptographic Analyst) |
| HF-K-03 | Integrasi | — | SHA-384 | 1. MCT 100 × 1000 iterasi (gaya CAVP) 2. Bandingkan checkpoint 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | 100% checkpoint identik | M-MCT | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-K-05 | Integrasi | — | 3 nilai (Kunci/salt (HMAC, KDF)) | 1. Muat vektor HMAC (Wycheproof/RFC 4231) & KDF 2. Eksekusi; bandingkan tag 3. Vektor invalid harus ditolak 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Identik 100% | M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-K-06 | Sistem | — | SHA-384, HKDF | 1. Verifikasi silang digest berkas dengan sha3sum/OpenSSL 2. Periksa label domain separation 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Konsisten | M-KAT | Sedang | Penguji lab + test engineer |
| PK-K-01 | Komponen | — | ECDH-P384, X25519, ML-KEM-768 | 1. Uji primalitas p, q kunci sampel (Miller–Rabin 64) 2. Periksa parameter domain kurva/grup 3. Bandingkan aritmetika dengan core/ 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruh pemeriksaan LULUS | M-PRIME, M-CURVE, M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| PK-K-02 | Integrasi | — | 3 nilai (Ukuran kunci & domain) | 1. Muat expected value target (PKCS#1 / Wycheproof / RFC 7748) 2. Eksekusi pada tiap vektor 3. Bandingkan keluaran; invalid ditolak 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Identik 100%; invalid ditolak | M-KAT | Tinggi | Penguji lab (Cryptographic Analyst) |
| PK-K-05 | Integrasi | — | 3 nilai (Ukuran kunci & domain) | 1. Impor RSA-1024, modulus 2047 bit, kurva tak didukung 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruhnya ditolak | M-PKV | Sedang | Penguji lab (Cryptographic Analyst) |
| PR-K-01 | Komponen | — | Vektor jejak RFC 8448 | 1. Ambil nilai jejak RFC 8448 (ECDHE shared secret, transcript hash) 2. Hitung HKDF-Extract/Expand-Label seluruh secret 3. Bandingkan dengan acuan 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Secret turunan identik dengan acuan | M-KAT | Tinggi | Penguji lab (Cryptographic Analyst) |
| PR-K-02 | Komponen | — | KAT AES-256-GCM; tag dimodifikasi 1 bit | 1. Muat vektor AES-256-GCM (Wycheproof) 2. Enkripsi/dekripsi 3. Ubah 1 bit tag, pastikan ditolak 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Identik 100%; tag salah ditolak | M-KAT | Tinggi | Penguji lab (Cryptographic Analyst) |
| PR-K-03 | Integrasi | — | Full handshake, HelloRetryRequest, resumption PSK | 1. Jalankan full handshake, HelloRetryRequest, resumption PSK 2. Rekam transcript & transisi state 3. Bandingkan dengan RFC 8446 §4 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Urutan pesan & state sesuai RFC 8446 | M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| PR-K-04 | Integrasi | — | Kombinasi versi × suite × grup (pairwise) · 6 nilai (Cipher suite, Grup pertukaran kunci, Versi protokol) | 1. Ambil kombinasi pairwise dari ruang parameter (KUK 1.2) 2. Klien menawarkan tiap kombinasi 3. Catat pilihan server 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Pilihan server sesuai kebijakan preferensi | M-KEYSIZE | Sedang | Penguji lab (Cryptographic Analyst) |
| PR-K-05 | Integrasi | — | Grup hybrid X25519MLKEM768 | 1. Handshake dengan klien pendukung hybrid 2. Bandingkan shared secret dengan spesifikasi hybrid 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Shared secret sesuai spesifikasi hybrid | M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| PR-K-06 | Sistem | — | ≥ 3 implementasi klien referensi | 1. Uji dengan OpenSSL, BoringSSL, NSS (dua arah) 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruh handshake berhasil | M-KAT | Sedang | Penguji lab + test engineer |
| XA-K-01 | Integrasi | — | AES-256-GCM, SHA-384, HKDF, ECDH-P384 | 1. Jalankan alur end-to-end dengan data uji tetap 2. Periksa endianness, encoding (DER/raw), panjang parameter & kode galat antar-komponen 3. Bandingkan keluaran tiap tahap dengan referensi 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Format & kode galat konsisten di seluruh rantai | M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |

### 5.2 Uji Keamanan

| ID | Tingkat | Area | Parameter & nilai uji | Prosedur | Kriteria lulus | Metode UK-1 | Prioritas | Pelaksana |
|---|---|---|---|---|---|---|---|---|
| BC-S-01 | Komponen | — | 2 nilai (Jumlah ronde) | 1. Ekstrak S-box dari produk (white/grey box) atau gunakan S-box standar 2. Hitung NL, DDT, LAT, derajat, SAC secara exhaustive 3. Bandingkan dengan nilai acuan desain 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | NL = 112, DU = 4, derajat = 7 (AES) | M-SBOX | Sedang | Penguji lab (Cryptographic Analyst) |
| BC-S-02 | Integrasi | — | 14 nilai (Blok plaintext, Nilai kunci) | 1. Bangkitkan dataset key-avalanche, plaintext-avalanche, low/high-density, korelasi P–C 2. Ukur fraksi bit berubah (N = 10 000 sampel) 3. Jalankan SP 800-22 pada keystream/keluaran (100 × 10^6 bit) 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Avalanche rerata n/2 (σ ≈ √n/2); proporsi lolos ≥ ambang SP 800-22; P-value_T ≥ 0,0001 | M-AVAL, M-SP80022 | Sedang | Penguji lab (Cryptographic Analyst) |
| BC-S-03 | Integrasi | — | 6 nilai (IV/nonce) | 1. Kirim dua pesan dengan kunci & nonce sama ke API 2. Periksa apakah produk mendeteksi/menolak reuse 3. Bila tidak, tunjukkan XOR plaintext bocor dari XOR ciphertext 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Reuse ditolak/terdeteksi; nonce yang dibangkitkan produk tidak pernah berulang (≥ 2^16 pesan) | M-NONCE | Tinggi | Penguji lab (Cryptographic Analyst) |
| BC-S-04 | Integrasi | — | 2 nilai (Jumlah ronde) | 1. Bangun varian ronde tereduksi (2–4 ronde) dengan core/ 2. Jalankan distinguisher diferensial/linear/integral (Λ-set 2^8) 3. Bandingkan margin dengan serangan literatur (UK-1) 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Serangan hanya berhasil pada ronde tereduksi; kompleksitas ronde penuh ≥ klaim bit security | M-DIFF, M-LIN, M-INT | Sedang | Penguji lab (Cryptographic Analyst) |
| BC-S-05 | Sistem | — | 6 nilai (Panjang pesan & padding) | 1. Baca batas data per kunci dari dokumentasi/profil 2. Hitung 2^(n/2) blok untuk tiap target 3. Uji API melewati batas (maks + 1) 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Batas ≤ 2^(n/2) blok dan ditegakkan produk (pesan berlebih ditolak/rekey) | M-KEYSIZE | Sedang | Penguji lab + test engineer |
| BC-S-06 | Sistem | — | AES-256-GCM | 1. Bandingkan security strength tiap target dengan SP 800-57 & status SP 800-131A 2. Tandai algoritma legacy/disallowed (mis. TDEA, PRESENT-80) 3. Periksa bahwa legacy hanya untuk dekripsi 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Strength ≥ 112 bit untuk layanan approved; legacy hanya legacy use | M-KEYSIZE | Tinggi | Penguji lab + test engineer |
| DS-S-01 | Komponen | — | Parameter domain P-256 di dalam produk | 1. Ekstrak p, a, b, G, n, h dari produk 2. Cocokkan dengan SP 800-186 3. Uji primalitas n; h = 1 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Identik; n prima, h = 1 | M-CURVE | Sedang | Penguji lab (Cryptographic Analyst) |
| DS-S-02 | Integrasi | — | N = 10^6 tanda tangan, pesan acak, d uji diketahui · 3 nilai (Mode nonce, Ukuran sampel) | 1. Bangkitkan N tanda tangan, pesan acak, d uji diketahui 2. Hitung k = s⁻¹(e + r·d) mod n 3. Uji bias MSB/LSB (χ²) & keacakan bit k 4. Simulasikan serangan lattice/HNP 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada bias signifikan (α = 0,01); serangan HNP simulasi gagal | M-NONCE | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-S-03 | Integrasi | — | N tanda tangan dari DS-S-02, kedua mode nonce · 1 nilai (Mode nonce) | 1. Gunakan N tanda tangan dari DS-S-02 untuk kedua mode nonce 2. Cari r berulang untuk pesan berbeda 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada r berulang | M-NONCE | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-S-04 | Integrasi | — | Q = O, Q di luar kurva, koordinat ≥ p · 4 nilai (Kunci publik Q) | 1. Masukkan Q = O, Q di luar kurva, koordinat ≥ p ke verifier 2. Masukkan ke proses impor sertifikat 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruhnya ditolak | M-PKV | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-S-07 | Sistem | — | ECDSA-P384 | 1. Hitung strength tiap skema (SP 800-57/FIPS 204) 2. Tandai skema rentan kuantum (IR 8547) 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Strength ≥ 112 bit; rencana migrasi PQC | M-KEYSIZE, M-ECDLP | Sedang | Penguji lab + test engineer |
| DS-S-08 | Integrasi | — | 5 nilai (Encoding (r, s)) | 1. Kirim (r, n−s), r/s = 0, ≥ n, DER non-kanonik 2. Catat terima/tolak 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Di luar rentang ditolak; kebijakan low-s didokumentasikan | M-SIGMAL | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-S-02 | Integrasi | — | 7 nilai (Pola pesan) | 1. 10 000 pasangan pesan beda 1 bit 2. Uji χ² byte keluaran 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Avalanche n/2 (σ ≈ √n/2); χ² p ≥ 0,01 | M-AVAL, M-SP80022 | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-S-03 | Integrasi | — | 4 nilai (Panjang digest) | 1. Cari collision pada digest terpotong t = 16/24/32 bit 2. Bandingkan kerja empiris dengan √(π/2·2^t) 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Kerja empiris ±20% dari prediksi; klaim penuh = min(n/2, c/2) | M-GENERIC, M-KEYSIZE | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-S-04 | Integrasi | — | SHA-384, HKDF | 1. Untuk SHA-2: tunjukkan length-extension pada H(k ∥ m) 2. Pastikan produk memakai HMAC untuk autentikasi 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada konstruksi H(k ∥ m) pada produk | M-PAD | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-S-06 | Sistem | — | SHA-384, HKDF | 1. Hitung strength klasik & kuantum (Grover: preimage 2^(n/2)) 2. Bandingkan dengan umur data produk 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Strength ≥ 112 bit (klasik) untuk umur data | M-KEYSIZE | Sedang | Penguji lab + test engineer |
| PK-S-01 | Komponen | — | ECDH-P384, X25519, ML-KEM-768 | 1. Hitung strength (SP 800-57) per target 2. Periksa \|p−q\|, d, kehalusan p−1 (UK-1) 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Strength ≥ 112 bit; prima kuat | M-KEYSIZE, M-PRIME, M-FACT | Sedang | Penguji lab (Cryptographic Analyst) |
| PK-S-03 | Integrasi | — | 4 nilai (Kunci publik lawan) | 1. Kirim titik di luar kurva, low-order, titik tak hingga 2. Periksa penolakan & shared secret nol 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruhnya ditolak | M-PKV | Tinggi | Penguji lab (Cryptographic Analyst) |
| PK-S-05 | Integrasi | — | ML-KEM-768 | 1. 10^6 encaps/decaps 2. Ciphertext dimodifikasi → harus menghasilkan kunci pseudoacak (implicit rejection) 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Laju kegagalan ≤ klaim (2^-139 ML-KEM-512…); implicit rejection benar | M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| PK-S-06 | Sistem | — | ECDH-P384, X25519, ML-KEM-768 | 1. Inventarisasi target rentan kuantum 2. Uji penggantian ke ML-KEM / hybrid tanpa ubah arsitektur 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Rencana migrasi sesuai IR 8547; mode hybrid berfungsi | M-KEYSIZE | Sedang | Penguji lab + test engineer |
| PR-S-01 | Komponen (Model formal (materi)) | — | Model formal handshake + resumption | 1. Modelkan handshake + resumption 2. Buktikan lemma secrecy, autentikasi mutual, FS, KCI 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruh lemma terbukti | M-KEYSIZE | Sedang | Penguji lab (Cryptographic Analyst) |
| PR-S-02 | Integrasi | — | Penawaran TLS ≤ 1.2, suite lemah; MitM mengubah ClientHello · 10 nilai (Cipher suite, Versi protokol) | 1. Tawarkan versi/suite lemah 2. MitM mengubah ClientHello 3. Periksa sentinel anti-downgrade & Finished 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Ditolak; modifikasi menggagalkan Finished | M-FUZZ | Tinggi | Penguji lab (Cryptographic Analyst) |
| PR-S-03 | Integrasi | — | Key share di luar kurva, titik tak hingga, low-order X25519 · 5 nilai (Nilai publik key share) | 1. Kirim key share di luar kurva, titik tak hingga, low-order X25519 2. Periksa alert 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruhnya ditolak dengan alert yang tepat | M-PKV | Tinggi | Penguji lab (Cryptographic Analyst) |
| PR-S-04 | Integrasi | — | Replay ClientHello/Finished dan early data; sequence number diubah · 7 nilai (Replay & 0-RTT, Urutan pesan) | 1. Kirim ulang/ubah urutan record 2. Amati efek & alert 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Replay tidak menghasilkan efek; record ditolak | M-NONCE | Sedang | Penguji lab (Cryptographic Analyst) |
| PR-S-05 | Sistem | — | Seluruh variasi sertifikat klien · 6 nilai (Sertifikat klien) | 1. Handshake dengan seluruh variasi sertifikat 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Hanya sertifikat valid yang diterima | M-PKV | Sedang | Penguji lab + test engineer |
| PR-S-06 | Sistem | — | Kunci privat jangka panjang dibocorkan pasca-sesi | 1. Rekam trafik 2. Bocorkan kunci privat jangka panjang 3. Coba dekripsi trafik lampau 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Trafik lampau tidak dapat didekripsi | M-KEYSIZE | Sedang | Penguji lab + test engineer |
| XA-S-02 | Sistem | — | AES-256-GCM, SHA-384, HKDF, ECDH-P384 | 1. Jalankan siklus lengkap untuk satu kunci tiap kelas primitif 2. Verifikasi kebijakan rotasi & batas penggunaan 3. Pastikan pemusnahan (zeroize) di akhir 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Setiap transisi sesuai kebijakan; kunci termusnahkan | M-ZEROIZE, M-KEYSIZE | Sedang | Penguji lab + test engineer |
| XA-S-03 | Sistem | — | AES-256-GCM, SHA-384, HKDF, ECDH-P384 | 1. Ganti algoritma rentan kuantum ke padanan PQC (ML-KEM/ML-DSA) melalui konfigurasi 2. Uji mode hybrid 3. Pastikan arsitektur & format tidak berubah 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Penggantian berhasil tanpa perubahan arsitektur; sesuai rencana IR 8547 | M-KEYSIZE | Sedang | Penguji lab + test engineer |
| XA-S-04 | Sistem | — | AES-256-GCM, SHA-384, HKDF, ECDH-P384 | 1. Pilih operasi dengan data rahasia (dekripsi RSA-OAEP, signing ECDSA, verifikasi tag AEAD) 2. Kumpulkan ≥ 10^6 pengukuran waktu dari sisi pemanggil API (remote-timing) 3. Coba pulihkan bit kunci/nonce dengan analisis statistik (gaya Brumley–Boneh) 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada informasi kunci yang dapat dipulihkan; \|t\| < 4,5 pada seluruh operasi | M-TIMING, M-CACHE | Tinggi | Penguji lab + test engineer |

### 5.3 Uji Implementasi

| ID | Tingkat | Area | Parameter & nilai uji | Prosedur | Kriteria lulus | Metode UK-1 | Prioritas | Pelaksana |
|---|---|---|---|---|---|---|---|---|
| BC-I-01 | Komponen | — | 7 nilai (Nilai kunci) | 1. Ukur waktu enkripsi fixed-vs-random key (10^6 pengukuran, dudect) 2. Lakukan Flush+Reload pada tabel bila tersedia 3. Dump memori setelah free konteks 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | \|t\| < 4,5; tidak ada sisa round key di memori | M-TIMING, M-ZEROIZE | Tinggi | Penguji lab (Cryptographic Analyst) |
| BC-I-02 | Integrasi | — | 6 nilai (Panjang pesan & padding) | 1. Kirim ciphertext dengan padding/tag rusak pada posisi berbeda 2. Ukur waktu respons & kode galat (10^5 sampel per kelas) 3. Uji Welch t antar kelas 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Galat seragam; \|t\| < 4,5 | M-TIMING | Sedang | Penguji lab (Cryptographic Analyst) |
| BC-I-03 | Integrasi | — | 6 nilai (Panjang pesan & padding) | 1. Bangkitkan 10^6 masukan malformed (panjang 0, maks+1, NULL, unaligned) 2. Jalankan di bawah ASan/UBSan 3. Catat crash/hang & kode galat 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tanpa crash/hang/sanitizer error; galat terdefinisi | M-FUZZ | Sedang | Penguji lab (Cryptographic Analyst) |
| BC-I-06 | Sistem | — | AES-256-GCM | 1. Picu galat (tag salah, kunci salah, self-test gagal) 2. Periksa pesan galat & log 3. Pastikan tidak ada material kunci/plaintext di log 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Galat terdefinisi; log tanpa data rahasia | M-SELFTEST, M-ZEROIZE | Sedang | Penguji lab + test engineer |
| DS-I-01 | Komponen | — | Fixed-vs-random d dan k; 10^5 pengukuran waktu | 1. Fixed-vs-random d dan k 2. 10^5 pengukuran waktu perkalian skalar 3. Uji TVLA (Welch t) 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | \|t\| < 4,5 | M-TIMING | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-I-04 | Integrasi | — | 10^6 input DER/ASN.1 malformed | 1. Bangkitkan 10^6 input DER/ASN.1 malformed 2. Fuzzing parser 3. Catat crash/hang & galat 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tanpa crash/hang; galat seragam | M-FUZZ | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-I-02 | Integrasi | — | SHA-384, HKDF | 1. Tag benar vs salah per posisi byte (10^5) 2. Welch t 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | \|t\| < 4,5 | M-TIMING | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-I-03 | Integrasi | — | SHA-384, HKDF | 1. Urutan update/final menyimpang 10^6 kali 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tanpa crash; galat terdefinisi | M-FUZZ | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-I-05 | Sistem | — | SHA-384, HKDF | 1. Rusak 1 byte berkas; verifikasi 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Kerusakan terdeteksi | M-KAT | Sedang | Penguji lab + test engineer |
| PK-I-01 | Komponen | — | ECDH-P384, X25519, ML-KEM-768 | 1. dudect fixed-vs-random kunci privat (10^6) 2. Periksa verifikasi hasil CRT sebelum keluaran 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | \|t\| < 4,5; hasil CRT diverifikasi | M-TIMING | Tinggi | Penguji lab (Cryptographic Analyst) |
| PK-I-02 | Integrasi | — | 1 nilai (Ciphertext masukan) | 1. 10^6 ciphertext/DER kunci malformed di bawah sanitizer 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tanpa crash; galat seragam | M-FUZZ | Sedang | Penguji lab (Cryptographic Analyst) |
| PK-I-03 | Integrasi | — | ECDH-P384, X25519, ML-KEM-768 | 1. Kelas galat berbeda, 10^5 sampel 2. Welch t 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | \|t\| < 4,5 | M-ORACLE, M-TIMING | Sedang | Penguji lab (Cryptographic Analyst) |
| PR-I-01 | Integrasi | — | ≥ 10^5 urutan pesan menyimpang · 1 nilai (Urutan pesan) | 1. ≥ 10^5 urutan pesan menyimpang (gaya TLS-Attacker) 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada transisi ilegal atau crash | M-FUZZ | Sedang | Penguji lab (Cryptographic Analyst) |
| PR-I-02 | Integrasi | — | Panjang record/extension salah, extension duplikat | 1. Panjang salah, extension duplikat 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Alert benar; tanpa crash/kebocoran memori | M-FUZZ | Sedang | Penguji lab (Cryptographic Analyst) |
| PR-I-03 | Integrasi | — | Record dengan tag valid vs invalid; 10^5 sampel | 1. Tag valid vs invalid, 10^5 sampel 2. TVLA 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | TVLA \|t\| < 4,5 | M-TIMING | Sedang | Penguji lab (Cryptographic Analyst) |
| PR-I-04 | Sistem | — | Banjir ClientHello, amplifikasi HRR, KeyUpdate berulang | 1. Banjir ClientHello, amplifikasi HRR, KeyUpdate berulang 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Layanan tersedia sesuai SLA | M-FUZZ | Sedang | Penguji lab + test engineer |
| PR-I-05 | Sistem | — | Rotasi kunci session ticket; umur tiket | 1. Periksa kebijakan rotasi, umur ≤ 7 hari, zeroization 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Sesuai kebijakan manajemen kunci | M-ZEROIZE | Sedang | Penguji lab + test engineer |
| PR-I-06 | Sistem | — | Latensi 500 ms, loss 5%, putus di tengah handshake · 5 nilai (Kondisi jaringan) | 1. Latensi 500 ms, loss 5%, putus di tengah handshake (emulator jaringan) 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Sesi setengah jadi dibersihkan; tanpa kebocoran state | M-FUZZ | Sedang | Penguji lab + test engineer |
| XA-I-01 | Sistem | — | 5 nilai (Kondisi operasional) | 1. Hentikan proses saat operasi kunci 2. Restart & jalankan ulang self-test 3. Uji di bawah beban tinggi 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Sifat keamanan tidak menurun; tidak ada keluaran parsial | M-SELFTEST | Sedang | Penguji lab + test engineer |

**Narasi empiris (contoh):**

- **BC-K-01** — Penguji melakukan verifikasi S-box, permutasi, key schedule & nilai antara per ronde pada AES-256-GCM dengan 1 nilai parameter uji. Uji dinyatakan Memenuhi bila: Seluruh nilai antara & round key identik 100%.
- **BC-K-02** — Penguji melakukan kAT per algoritma × mode × panjang kunci pada AES-256-GCM dengan 2 nilai parameter uji. Uji dinyatakan Memenuhi bila: Ciphertext/tag/plaintext identik 100% dengan vektor resmi; vektor invalid ditolak.
- **BC-K-03** — Penguji melakukan monte Carlo Test & Multi-block Message Test pada AES-256-GCM dengan 7 nilai parameter uji. Uji dinyatakan Memenuhi bila: 100% checkpoint identik.
- **BC-K-04** — Penguji melakukan round-trip D(E(x)) = x pada nilai batas panjang pesan pada AES-256-GCM dengan 13 nilai parameter uji. Uji dinyatakan Memenuhi bila: D(E(x)) = x untuk 100% kasus.
- **BC-K-05** — Penguji melakukan penolakan parameter di luar spesifikasi (negative test) pada AES-256-GCM dengan 9 nilai parameter uji. Uji dinyatakan Memenuhi bila: Seluruh parameter di luar spesifikasi ditolak dengan galat terdefinisi. Seluruh masukan pada uji ini bersifat negatif, sehingga hasil yang benar adalah PENOLAKAN.
- **BC-K-06** — Penguji melakukan interoperabilitas format ciphertext dengan implementasi referensi pada AES-256-GCM dengan 1 nilai parameter uji. Uji dinyatakan Memenuhi bila: Interoperabel dua arah 100%.
- **DS-K-01** — Penguji melakukan aritmetika kurva pada titik khusus pada ECDSA-P384. Uji dinyatakan Memenuhi bila: Hasil identik 100%; n·G = O.
- **DS-K-02** — Penguji melakukan sHA-256: Short/Long Message & Monte Carlo Test pada SHA-384 dengan 9 nilai parameter uji. Uji dinyatakan Memenuhi bila: Digest identik 100%.

## 6. Expected Value & Kriteria Keputusan (KUK 2.4)

Kriteria keputusan materi: **Deterministik**: KAT/MCT cocok 100%; vektor invalid seluruhnya ditolak.; **Statistik**: α = 0,01; proporsi lolos dalam interval kepercayaan; p-value terdistribusi seragam.; **Kriptanalitik**: Kompleksitas serangan terbaik ≥ klaim tingkat keamanan (bit security).; **Implementasi**: Tidak ada kebocoran terukur (mis. TVLA |t| < 4,5) dan galat seragam.

| Berkas expected | Target | Jenis | Status | Cocok/total | SHA-256 |
|---|---|---|---|---|---|
| hash_boundaries__SHA-384 | SHA-384 | deterministic | COCOK_VEKTOR_RESMI | 14/14 | f1c022d02827c04b… |
| kat__AES-256-GCM | AES-256-GCM | deterministic | COCOK_VEKTOR_RESMI | 66/66 | 0f59a33f04b0a9e0… |
| kat__ECDH-P384 | ECDH-P384 | deterministic | COCOK_VEKTOR_RESMI | 1047/1047 | 3bfdb1e13c460060… |
| kat__HKDF | HKDF | deterministic | COCOK_VEKTOR_RESMI | 22/22 | 8d9fb7e799a2cae6… |
| kat__X25519 | X25519 | deterministic | COCOK_VEKTOR_RESMI | 518/518 | b2e8dc378d852a7d… |
| kat_gcm256__AES-256-GCM | AES-256-GCM | deterministic | COCOK_VEKTOR_RESMI | 66/66 | 6386c99995932291… |
| rfc6979__ECDSA-P384 | ECDSA-P384 | deterministic | COCOK_VEKTOR_RESMI | 4/4 | 7fdb67c736ef8c90… |
| rfc8448__HKDF | HKDF | deterministic | COCOK_VEKTOR_RESMI | 22/22 | 363c66fb18131b9a… |
| attack_margin__HKDF | HKDF | cryptanalytic | PERLU_VERIFIKASI | — | 1df1bdd1787c0ce6… |
| curve_points__ECDSA-P384 | ECDSA-P384 | deterministic | PERLU_VERIFIKASI | — | 83c50eef835c9c1c… |
| domain_params__ECDSA-P384 | ECDSA-P384 | deterministic | PERLU_VERIFIKASI | — | f375ffa0b05ed27c… |
| formal__TLS_1.3 | TLS 1.3 | cryptanalytic | PERLU_VERIFIKASI | — | 11cb42d7a67f05d3… |
| generic_bound__HKDF | HKDF | cryptanalytic | PERLU_VERIFIKASI | — | 83d0792ebefcc0fc… |
| hybrid__TLS_1.3 | TLS 1.3 | deterministic | KRITERIA | — | 25876e44c2b16e43… |
| interop__AES-256-GCM | AES-256-GCM | deterministic | KRITERIA | — | c3fd2e9032182df7… |
| interop__ECDH-P384 | ECDH-P384 | deterministic | KRITERIA | — | 248e411ba8ab7962… |
| interop__ECDSA-P384 | ECDSA-P384 | deterministic | KRITERIA | — | b69dd3a4b9d29cf3… |
| interop__HKDF | HKDF | deterministic | KRITERIA | — | b2f772593e22e8d8… |
| interop__ML-KEM-768 | ML-KEM-768 | deterministic | KRITERIA | — | 492f4154623a6fa5… |
| interop__SHA-384 | SHA-384 | deterministic | KRITERIA | — | 65563f7481293e7a… |
| interop__TLS_1.3 | TLS 1.3 | deterministic | KRITERIA | — | 03f4d7be8ca9ebb0… |
| interop__X25519 | X25519 | deterministic | KRITERIA | — | d92849305bb376f2… |
| kat__ML-KEM-768 | ML-KEM-768 | deterministic | PERLU_VERIFIKASI | — | e9164ebaad954160… |
| keygen_validate__ECDH-P384 | ECDH-P384 | deterministic | KRITERIA | — | 592ce0b4c7c6918b… |
| keygen_validate__ML-KEM-768 | ML-KEM-768 | deterministic | KRITERIA | — | f31246f1be140cf4… |
| keygen_validate__X25519 | X25519 | deterministic | KRITERIA | — | 20cf29f9f9a1eee2… |
| mct__AES-256-GCM | AES-256-GCM | deterministic | KRITERIA | — | 5909577e4030f3b3… |
| mct__SHA-384 | SHA-384 | deterministic | KRITERIA | — | 5646a3d56f444350… |
| negotiation__TLS_1.3 | TLS 1.3 | deterministic | KRITERIA | — | 88250a29b8e52c40… |
| nonce_reuse__AES-256-GCM | AES-256-GCM | negative | KRITERIA | — | aacf7248f558d335… |
| performance__TLS_1.3 | TLS 1.3 | implementation | PERLU_VERIFIKASI | — | f4b6655548f280e3… |
| pubkey_negative__ECDSA-P384 | ECDSA-P384 | negative | KRITERIA | — | c68a3daff1590839… |
| pubkey_negative__TLS_1.3 | TLS 1.3 | negative | KRITERIA | — | b454b08520e460ad… |
| reject_params__AES-256-GCM | AES-256-GCM | negative | KRITERIA | — | ec4c98e125c8b59e… |
| reject_params__ECDH-P384 | ECDH-P384 | negative | KRITERIA | — | db4cf9cbac2fd5a7… |
| reject_params__HKDF | HKDF | negative | KRITERIA | — | 7fe38d435ce1a35c… |
| reject_params__ML-KEM-768 | ML-KEM-768 | negative | KRITERIA | — | bfc3d1f9405df7c7… |
| reject_params__SHA-384 | SHA-384 | negative | KRITERIA | — | 6e1149cef2ec3446… |
| reject_params__TLS_1.3 | TLS 1.3 | negative | KRITERIA | — | 0440c21e04961f99… |
| reject_params__X25519 | X25519 | negative | KRITERIA | — | 24b47247451ce8bf… |
| roundtrip__AES-256-GCM | AES-256-GCM | deterministic | KRITERIA | — | d6ce4974999db6ad… |
| sigver__ECDSA-P384 | ECDSA-P384 | deterministic | PERLU_VERIFIKASI | — | 0653bee4a771bded… |
| ssp_lifecycle__AES-256-GCM | AES-256-GCM | deterministic | KRITERIA | — | a25389c85d5a189f… |
| ssp_lifecycle__ECDH-P384 | ECDH-P384 | deterministic | KRITERIA | — | 3b205c8cc8c17dcd… |
| ssp_lifecycle__ECDSA-P384 | ECDSA-P384 | deterministic | KRITERIA | — | 830f0a59d70ed9d2… |
| ssp_lifecycle__HKDF | HKDF | deterministic | KRITERIA | — | 148d2dac4f1b5b61… |
| ssp_lifecycle__ML-KEM-768 | ML-KEM-768 | deterministic | KRITERIA | — | 56c68b798966cbab… |
| ssp_lifecycle__SHA-384 | SHA-384 | deterministic | KRITERIA | — | ff1489f6b2dee405… |
| ssp_lifecycle__X25519 | X25519 | deterministic | KRITERIA | — | 4ee5d419c2195fe8… |
| state_machine__TLS_1.3 | TLS 1.3 | deterministic | KRITERIA | — | da19aa7f92bd4d48… |
| strength__HKDF | HKDF | cryptanalytic | PERLU_VERIFIKASI | — | 4ef1c3dc6d7f8427… |

## 7. Pemetaan Parameter → Kemungkinan Hasil Uji (KUK 2.5)

Kategori hasil: **Memenuhi** — Seluruh kriteria terpenuhi pada semua variasi parameter yang ditetapkan.; **Memenuhi dengan Catatan** — Lulus, tetapi terdapat batasan penggunaan (mis. batas data per kunci, parameter minimum).; **Tidak Memenuhi** — Minimal satu kriteria gagal; parameter pemicu kegagalan diidentifikasi.; **Inkonklusif** — Bukti statistik belum cukup; diperlukan sampel lebih besar atau uji lanjutan.

| Kondisi temuan | Parameter pemicu | Kemungkinan hasil | Tindak lanjut | Sumber |
|---|---|---|---|---|
| Titik low-order X25519 diterima (shared secret nol) | Nilai publik key share | Tidak Memenuhi | Temuan kritis; wajibkan pemeriksaan shared secret nol | materi (tls13_gateway) |
| Server menerima TLS 1.2 dengan suite non-AEAD | Versi, cipher suite | Tidak Memenuhi | Batasi ke TLS 1.3 atau TLS 1.2 ECDHE-AEAD sesuai profil | materi (tls13_gateway) |
| 0-RTT aktif tanpa mekanisme anti-replay | Replay & 0-RTT | Memenuhi dengan Catatan | Diterima hanya untuk permintaan idempoten; selain itu nonaktifkan | materi (tls13_gateway) |
| Sertifikat dicabut diterima saat OCSP tak terjangkau | Sertifikat, kondisi jaringan | Memenuhi dengan Catatan | Terapkan hard-fail atau OCSP stapling wajib | materi (tls13_gateway) |
| Analisis Tamarin tidak berhenti (non-termination) | Model formal | Inkonklusif | Sederhanakan model atau tambahkan lemma bantu | materi (tls13_gateway) |
| Crash pada fuzzing state machine | Urutan pesan | Tidak Memenuhi | Perbaiki state machine; ulangi PR-I-01 dan PR-K-03 | materi (tls13_gateway) |
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
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-KAT | SCN-BC-KOM-K | BC-K-01 | — | FIPS-197, ISO-18367 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-KAT | SCN-BC-INT-K | BC-K-02 | — | FIPS-197, SP-800-38A, SP-800-38D, ISO-18367 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-MCT | SCN-BC-INT-K | BC-K-03 | — | ISO-18367 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-KAT | SCN-BC-INT-K | BC-K-04 | — | SP-800-38A, ISO-29119 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-FUZZ | SCN-BC-INT-K | BC-K-05 | — | ISO-29119, ISO-19790 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-KAT | SCN-BC-SIS-K | BC-K-06 | — | ISO-18367 |
| OBJ:ECDSA-P384 | Kesesuaian ECDSA-P384 terhadap standar | M-CURVE | SCN-DS-KOM-K | DS-K-01 | — | FIPS-186-5, SP-800-186 |
| OBJ:SHA-384 | Kesesuaian SHA-384 terhadap standar | M-KAT | SCN-DS-KOM-K | DS-K-02 | — | FIPS-180-4 |
| OBJ:ECDSA-P384 | Kesesuaian ECDSA-P384 terhadap standar | M-KAT | SCN-DS-INT-K | DS-K-04 | — | RFC-6979, FIPS-186-5 |
| OBJ:ECDSA-P384 | Kesesuaian ECDSA-P384 terhadap standar | M-KAT | SCN-DS-INT-K | DS-K-05 | — | FIPS-186-5, ISO-14888-3 |
| OBJ:ECDSA-P384 | Kesesuaian ECDSA-P384 terhadap standar | M-KAT | SCN-DS-SIS-K | DS-K-07 | — | ISO-18367 |
| OBJ:SHA-384 | Kesesuaian SHA-384 terhadap standar | M-KAT | SCN-HF-KOM-K | HF-K-01 | — | FIPS-202, FIPS-180-4, ISO-10118-3 |
| OBJ:SHA-384 | Kesesuaian SHA-384 terhadap standar | M-KAT | SCN-HF-INT-K | HF-K-02 | — | FIPS-202, FIPS-180-4 |
| OBJ:SHA-384 | Kesesuaian SHA-384 terhadap standar | M-MCT | SCN-HF-INT-K | HF-K-03 | — | ISO-18367 |
| OBJ:HKDF | Kesesuaian HKDF terhadap standar | M-KAT | SCN-HF-INT-K | HF-K-05 | — | SP-800-107, FIPS-202 |
| OBJ:SHA-384 | Kesesuaian SHA-384, HKDF terhadap standar | M-KAT | SCN-HF-SIS-K | HF-K-06 | — | ISO-18367 |
| OBJ:ECDH-P384 | Kesesuaian ECDH-P384, X25519, ML-KEM-768 terhadap standar | M-PRIME | SCN-PK-KOM-K | PK-K-01 | — | ISO-18032, FIPS-186-5 |
| OBJ:ECDH-P384 | Kesesuaian ECDH-P384, X25519, ML-KEM-768 terhadap standar | M-KAT | SCN-PK-INT-K | PK-K-02 | — | RFC-8017, ISO-18033-2, SP-800-56B |
| OBJ:ECDH-P384 | Kesesuaian ECDH-P384, X25519, ML-KEM-768 terhadap standar | M-PKV | SCN-PK-INT-K | PK-K-05 | — | SP-800-56B, SP-800-131A |
| OBJ:HKDF | Kesesuaian HKDF terhadap standar | M-KAT | SCN-PR-KOM-K | PR-K-01 | — | RFC-8446 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-KAT | SCN-PR-KOM-K | PR-K-02 | — | SP-800-38D |
| OBJ:TLS 1.3 | Kesesuaian TLS 1.3 terhadap standar | M-KAT | SCN-PR-INT-K | PR-K-03 | — | RFC-8446 |
| OBJ:TLS 1.3 | Kesesuaian TLS 1.3 terhadap standar | M-KEYSIZE | SCN-PR-INT-K | PR-K-04 | — | RFC-8446 |
| OBJ:TLS 1.3 | Kesesuaian TLS 1.3 terhadap standar | M-KAT | SCN-PR-INT-K | PR-K-05 | — | FIPS-203 |
| OBJ:TLS 1.3 | Kesesuaian TLS 1.3 terhadap standar | M-KAT | SCN-PR-SIS-K | PR-K-06 | — | RFC-8446 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-SBOX | SCN-BC-KOM-S | BC-S-01 | — | FIPS-197, ISO-18033-3 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-AVAL | SCN-BC-INT-S | BC-S-02 | — | SP-800-22 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-NONCE | SCN-BC-INT-S | BC-S-03 | — | SP-800-38A, SP-800-38D |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-DIFF | SCN-BC-INT-S | BC-S-04 | — | ISO-15408 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-KEYSIZE | SCN-BC-SIS-S | BC-S-05 | — | SP-800-38D, SP-800-57 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-KEYSIZE | SCN-BC-SIS-S | BC-S-06 | — | SP-800-57, SP-800-131A |
| OBJ:ECDSA-P384 | Kesesuaian ECDSA-P384 terhadap standar | M-CURVE | SCN-DS-KOM-S | DS-S-01 | — | SP-800-186, FIPS-186-5 |
| OBJ:ECDSA-P384 | Kesesuaian ECDSA-P384 terhadap standar | M-NONCE | SCN-DS-INT-S | DS-S-02 | — | FIPS-186-5, RFC-6979 |
| OBJ:ECDSA-P384 | Kesesuaian ECDSA-P384 terhadap standar | M-NONCE | SCN-DS-INT-S | DS-S-03 | — | FIPS-186-5 |
| OBJ:ECDSA-P384 | Kesesuaian ECDSA-P384 terhadap standar | M-PKV | SCN-DS-INT-S | DS-S-04 | — | SP-800-186 |
| OBJ:ECDSA-P384 | Kesesuaian ECDSA-P384 terhadap standar | M-KEYSIZE | SCN-DS-SIS-S | DS-S-07 | — | SP-800-57, FIPS-204, SP-800-186 |
| OBJ:ECDSA-P384 | Kesesuaian ECDSA-P384 terhadap standar | M-SIGMAL | SCN-DS-INT-S | DS-S-08 | — | FIPS-186-5 |
| OBJ:SHA-384 | Kesesuaian SHA-384, HKDF terhadap standar | M-AVAL | SCN-HF-INT-S | HF-S-02 | — | SP-800-22 |
| OBJ:SHA-384 | Kesesuaian SHA-384, HKDF terhadap standar | M-GENERIC | SCN-HF-INT-S | HF-S-03 | — | SP-800-107, FIPS-202 |
| OBJ:SHA-384 | Kesesuaian SHA-384, HKDF terhadap standar | M-PAD | SCN-HF-INT-S | HF-S-04 | — | SP-800-107 |
| OBJ:SHA-384 | Kesesuaian SHA-384, HKDF terhadap standar | M-KEYSIZE | SCN-HF-SIS-S | HF-S-06 | — | SP-800-57, SP-800-107 |
| OBJ:ECDH-P384 | Kesesuaian ECDH-P384, X25519, ML-KEM-768 terhadap standar | M-KEYSIZE | SCN-PK-KOM-S | PK-S-01 | — | SP-800-57, ISO-18032 |
| OBJ:ECDH-P384 | Kesesuaian ECDH-P384, X25519 terhadap standar | M-PKV | SCN-PK-INT-S | PK-S-03 | — | SP-800-56A, SP-800-186 |
| OBJ:ML-KEM-768 | Kesesuaian ML-KEM-768 terhadap standar | M-KAT | SCN-PK-INT-S | PK-S-05 | — | FIPS-203 |
| OBJ:ECDH-P384 | Kesesuaian ECDH-P384, X25519, ML-KEM-768 terhadap standar | M-KEYSIZE | SCN-PK-SIS-S | PK-S-06 | — | FIPS-203, SP-800-131A |
| C-CONF | Kerahasiaan kunci sesi | M-KEYSIZE | SCN-PR-KOM-S | PR-S-01 | — | RFC-8446 |
| C-MAUTH | Autentikasi mutual | M-KEYSIZE | SCN-PR-KOM-S | PR-S-01 | — | RFC-8446 |
| C-FS | Forward secrecy | M-KEYSIZE | SCN-PR-KOM-S | PR-S-01 | — | RFC-8446 |
| C-DOWN | Ketahanan downgrade | M-FUZZ | SCN-PR-INT-S | PR-S-02 | — | RFC-8446 |
| C-CONF | Kerahasiaan kunci sesi | M-PKV | SCN-PR-INT-S | PR-S-03 | — | RFC-8446, SP-800-56A |
| C-REPLAY | Ketahanan replay | M-NONCE | SCN-PR-INT-S | PR-S-04 | — | RFC-8446 |
| C-MAUTH | Autentikasi mutual | M-PKV | SCN-PR-SIS-S | PR-S-05 | — | RFC-5280 |
| C-FS | Forward secrecy | M-KEYSIZE | SCN-PR-SIS-S | PR-S-06 | — | RFC-8446 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-TIMING | SCN-BC-KOM-I | BC-I-01 | — | ISO-17825, ISO-19790 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-TIMING | SCN-BC-INT-I | BC-I-02 | — | ISO-17825 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-FUZZ | SCN-BC-INT-I | BC-I-03 | — | ISO-29119, ISO-18045 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM terhadap standar | M-SELFTEST | SCN-BC-SIS-I | BC-I-06 | — | ISO-19790 |
| OBJ:ECDSA-P384 | Kesesuaian ECDSA-P384 terhadap standar | M-TIMING | SCN-DS-KOM-I | DS-I-01 | — | ISO-17825 |
| OBJ:ECDSA-P384 | Kesesuaian ECDSA-P384 terhadap standar | M-FUZZ | SCN-DS-INT-I | DS-I-04 | — | ISO-29119 |
| OBJ:SHA-384 | Kesesuaian SHA-384, HKDF terhadap standar | M-TIMING | SCN-HF-INT-I | HF-I-02 | — | ISO-17825 |
| OBJ:SHA-384 | Kesesuaian SHA-384, HKDF terhadap standar | M-FUZZ | SCN-HF-INT-I | HF-I-03 | — | ISO-29119 |
| OBJ:SHA-384 | Kesesuaian SHA-384, HKDF terhadap standar | M-KAT | SCN-HF-SIS-I | HF-I-05 | — | ISO-29119 |
| OBJ:ECDH-P384 | Kesesuaian ECDH-P384, X25519, ML-KEM-768 terhadap standar | M-TIMING | SCN-PK-KOM-I | PK-I-01 | — | ISO-17825 |
| OBJ:ECDH-P384 | Kesesuaian ECDH-P384, X25519, ML-KEM-768 terhadap standar | M-FUZZ | SCN-PK-INT-I | PK-I-02 | — | ISO-29119 |
| OBJ:ECDH-P384 | Kesesuaian ECDH-P384, X25519, ML-KEM-768 terhadap standar | M-ORACLE | SCN-PK-INT-I | PK-I-03 | — | ISO-17825 |
| OBJ:TLS 1.3 | Kesesuaian TLS 1.3 terhadap standar | M-FUZZ | SCN-PR-INT-I | PR-I-01 | — | ISO-29119 |
| OBJ:TLS 1.3 | Kesesuaian TLS 1.3 terhadap standar | M-FUZZ | SCN-PR-INT-I | PR-I-02 | — | ISO-29119 |
| OBJ:TLS 1.3 | Kesesuaian TLS 1.3 terhadap standar | M-TIMING | SCN-PR-INT-I | PR-I-03 | — | ISO-17825 |
| OBJ:TLS 1.3 | Kesesuaian TLS 1.3 terhadap standar | M-FUZZ | SCN-PR-SIS-I | PR-I-04 | — | ISO-29119 |
| OBJ:TLS 1.3 | Kesesuaian TLS 1.3 terhadap standar | M-ZEROIZE | SCN-PR-SIS-I | PR-I-05 | — | RFC-8446 |
| OBJ:TLS 1.3 | Kesesuaian TLS 1.3 terhadap standar | M-FUZZ | SCN-PR-SIS-I | PR-I-06 | — | ISO-29119 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, SHA-384, HKDF terhadap standar | M-KAT | SCN-XA-INT-K | XA-K-01 | — | ISO-18367 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, SHA-384, HKDF terhadap standar | M-ZEROIZE | SCN-XA-SIS-S | XA-S-02 | — | SP-800-57, ISO-19790 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, SHA-384, HKDF terhadap standar | M-KEYSIZE | SCN-XA-SIS-S | XA-S-03 | — | FIPS-203, FIPS-204, SP-800-131A |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, SHA-384, HKDF terhadap standar | M-TIMING | SCN-XA-SIS-S | XA-S-04 | — | ISO-17825, ISO-20085 |
| OBJ:AES-256-GCM | Kesesuaian AES-256-GCM, SHA-384, HKDF terhadap standar | M-SELFTEST | SCN-XA-SIS-I | XA-I-01 | — | ISO-19790 |

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
