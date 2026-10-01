# Dokumen Skenario Pengujian — Cryptan.ID SecureLib

**Cryptan.ID Test Suite** · Modul **UK-2** · Unit J.61KRP00.013.1 — *Menyusun Skenario Pengujian* · SKKNI 2023-004 (Cryptographic Analyst)

Dibangkitkan 2026-10-01T13:47:12+07:00 · model 3 tingkat · masukan UK-1: `outputs/uk1 (5 algoritma)`

> Objek uji & data produk ILUSTRATIF. HASIL UJI LANGSUNG = dihitung kode; LITERATUR/ACUAN = dikutip dengan rujukan; PERLU_VERIFIKASI = belum dapat dihitung/dicocokkan, tidak dikarang.

## Ringkasan

- Objek uji: **33** kombinasi · kategori: block, stream, hash, pke, signature
- Metode UK-1 ditelaah: 27 (relevan 27) · sel kosong diisi templat: 21
- Skenario: **49** · test case: **91** (K 32 · S 35 · I 24)
- Verifikasi terhadap spesifikasi desain: **LULUS** (0 temuan)
- Expected value: 25 cocok vektor resmi · 381 kriteria · 39 PERLU_VERIFIKASI

## 1. Profil Objek Uji & Ruang Parameter

| Atribut | Nilai |
|---|---|
| Produk | Cryptan.ID SecureLib 1.0.0 (hipotetis) |
| Deskripsi | Library kriptografi perangkat lunak (shared object) untuk Linux x86-64 |
| Jenis produk | library |
| Model tingkat | 3 (Komponen → Integrasi → Sistem) |
| SL ISO/IEC 19790 | tidak berlaku |
| Fitur | aead, api, error_codes, fuzzing_harness, kem, key_import_export, keygen, multi_thread, rng_internal, self_tests, signature, software_library, streaming_api, timing_measurement |

**Klaim keamanan:**

| ID | Klaim | Tag |
|---|---|---|
| C-STRENGTH | Tingkat keamanan ≥ 112 bit untuk seluruh algoritma approved (SP 800-57) | bit_security |
| C-AEAD | AEAD (AES-GCM, ChaCha20-Poly1305): kerahasiaan IND-CPA + integritas INT-CTXT bila nonce unik | aead, nonce_misuse |
| C-PKE | RSA-OAEP: IND-CCA2; galat dekripsi seragam (tanpa oracle) | ind_cca2, oracle |
| C-SIG | ECDSA/EdDSA/ML-DSA: EUF-CMA; nonce tidak berulang/bias | euf_cma, nonce_bias |
| C-HASH | SHA3-256/SHA-2: collision 2^(n/2), preimage 2^n | collision, preimage |
| C-CT | Operasi dengan data rahasia berjalan constant-time pada x86-64 | constant_time |
| C-RNG | Kunci & nonce dari HMAC_DRBG/CTR_DRBG (SP 800-90A) dengan entropi memadai | rng |

**Objek uji (algorithms_under_test):**

| ID | Kategori | Varian | Kunci | Strength | Status NIST |
|---|---|---|---|---|---|
| AES-128-CTR | block | CTR | 128 | 128 | acceptable |
| AES-256-GCM | block | GCM | 256 | 256 | acceptable |
| AES-256-KW | block | KW | 256 | 256 | acceptable |
| XTS-AES-256 | block | XTS | 256 | 128 | acceptable |
| PRESENT-80 | block | ECB | 80 | 80 | not_nist |
| TDEA-3KEY | block | 3-key | 168 | 112 | disallowed |
| CHACHA20-256 | stream | ChaCha20 | 256 | 256 | not_nist |
| CHACHA20-POLY1305 | stream | ChaCha20-Poly1305 | 256 | 256 | not_nist |
| BLAKE2B-512 | hash | BLAKE2b-512 | — | 256 | not_nist |
| SHA-1 | hash | SHA-1 | — | <80 | disallowed |
| SHA-256 | hash | SHA-256 | — | 128 | acceptable |
| SHA-384 | hash | SHA-384 | — | 192 | acceptable |
| SHA-512/256 | hash | SHA-512/256 | — | 128 | acceptable |
| SHA3-256 | hash | SHA3-256 | — | 128 | acceptable |
| SHAKE256 | hash | SHAKE256 | — | 256 | acceptable |
| CMAC-AES-128 | block | CMAC | 128 | 128 | acceptable |
| ASCON-AEAD128 | block | Ascon-AEAD128 | 128 | 128 | acceptable |
| HMAC-SHA-256-K128 | hash | SHA-256 | 128 | 128 | acceptable |
| HMAC-SHA-256-K256 | hash | SHA-256 | 256 | 256 | acceptable |
| ECDH-P384 | pke | P-384 | 384 | 192 | acceptable |
| FFDHE3072 | pke | ffdhe | 3072 | 128 | acceptable |
| ML-KEM-768 | pke | ML-KEM-768 | — | 192 | acceptable |
| RSA-OAEP-2048 | pke | OAEP | 2048 | 112 | acceptable |
| RSA-OAEP-3072 | pke | OAEP | 3072 | 128 | acceptable |
| RSAES-PKCS1-V1_5-1024 | pke | PKCS1-v1_5-ENC | 1024 | 80 | disallowed |
| X25519 | pke | X25519 | 255 | 128 | PERLU_VERIFIKASI |
| ECDSA-P256 | signature | P-256 | 256 | 128 | acceptable |
| ECDSA-P384 | signature | P-384 | 384 | 192 | acceptable |
| ED25519 | signature | Ed25519 | 255 | 128 | acceptable |
| ML-DSA-65 | signature | ML-DSA-65 | — | 192 | acceptable |
| RSA-PSS-3072 | signature | PSS | 3072 | 128 | acceptable |
| SLH-DSA-SHA2-128S | signature | SHA2-128s | — | 128 | acceptable |
| CTR-DRBG-AES-256 | rng | CTR_DRBG | 256 | 256 | acceptable |

### 1.1 Ruang parameter — block

| ID | Parameter | Kelas | Status | Nilai uji (teknik) |
|---|---|---|---|---|
| BC-KEY-LEN | Panjang kunci | Parameter publik/domain | Variabel | 0 [BVA, NEG]; 72 [BVA, NEG]; 80 [EP]; 128 [EP]; 168 [EP]; 256 [EP]; 192 [NEG, NEG]; 264 [BVA, NEG] |
| BC-KEY-VAL | Nilai kunci | Material rahasia | Variabel | acak (DRBG) [EP]; nol-semua (0x00…) [DEG]; satu-semua (0xFF…) [DEG]; low-density (HW = 1) [DEG]; high-density (HW = n−1) [DEG]; related-key (beda 1 bit) [BIT]; kunci lemah/semi-lemah (bila ada) [DEG] |
| BC-PT | Blok plaintext | Data masukan | Variabel | acak [EP]; nol-semua (0x00…) [DEG]; satu-semua (0xFF…) [DEG]; low-density (HW = 1) [DEG]; high-density (HW = n−1) [DEG]; periodik (0x55/0xAA) [DEG]; 1-bit flip pada tiap posisi (n = 128) [BIT] |
| BC-MODE | Mode operasi | Konfigurasi | Variabel | 3-key [EP]; Ascon-AEAD128 [EP]; CBC [EP, NEG]; CMAC [EP]; CTR [EP]; ECB [EP]; GCM [EP]; KW [EP]; XTS [EP] |
| BC-IV | IV/nonce | Material rahasia | Variabel | acak 96 bit [EP]; counter berurutan [EP]; nol [DEG, NEG]; berulang (reuse) [NEG, NEG]; dapat diprediksi (CBC) [NEG, NEG]; panjang non-96 bit (GCM) [BVA] |
| BC-LEN | Panjang pesan & padding | Data masukan | Variabel | 0 [BVA]; 1 [BVA]; 15 [BVA]; 16 [BVA]; 17 [BVA]; 1048576 [EP]; 1073741824 [BVA]; 1073741825 [BVA, NEG] |
| BC-ROUNDS | Jumlah ronde | Konfigurasi | Variabel | penuh (10/12/14) [EP]; tereduksi 2–4 ronde (analisis) [BVA] |
| ENV | Kondisi operasional | Kondisi lingkungan | Variabel | normal [EP]; beban tinggi multi-thread [EP]; memori terbatas [EP] |

Reduksi pairwise (t = 2. IPOG) atas 6 parameter Variabel: **9.408** kombinasi penuh → **60** kombinasi pairwise (99.4% berkurang; semua pasangan tercakup: True).

### 1.2 Ruang parameter — stream

| ID | Parameter | Kelas | Status | Nilai uji (teknik) |
|---|---|---|---|---|
| SC-KEY | Kunci | Material rahasia | Variabel | 256 bit acak [EP]; nol-semua (0x00…) [DEG]; satu-semua (0xFF…) [DEG]; low-density (HW = 1) [DEG]; high-density (HW = n−1) [DEG]; 248 bit [NEG, NEG] |
| SC-NONCE | IV/nonce | Material rahasia | Variabel | acak 96 bit [EP]; berurutan [EP]; beda 1 bit [BIT]; berulang [NEG, NEG]; panjang 64 bit [NEG, NEG] |
| SC-INIT | Ronde inisialisasi | Konfigurasi | Variabel | penuh (20 ronde) [EP]; tereduksi 4–7 ronde (analisis) [BVA] |
| SC-KSLEN | Panjang keystream | Data masukan | Variabel | 10^6 bit [EP]; 10^8 bit (100 × 10^6) [EP]; 2^30 bit [BVA]; 2^32 blok (batas counter) [BVA]; 2^32 + 1 blok [BVA, NEG] |
| SC-STATE | Ukuran state | Parameter publik/domain | Tetap | 512 bit (≥ 2 × kunci) [EP] |
| ENV | Kondisi operasional | Kondisi lingkungan | Variabel | normal [EP]; beban tinggi multi-thread [EP]; memori terbatas [EP] |

Reduksi pairwise (t = 2. IPOG) atas 3 parameter Variabel: **24** kombinasi penuh → **12** kombinasi pairwise (50.0% berkurang; semua pasangan tercakup: True).

### 1.3 Ruang parameter — hash

| ID | Parameter | Kelas | Status | Nilai uji (teknik) |
|---|---|---|---|---|
| HF-LEN-BLAKE2B-512 | Panjang pesan BLAKE2B-512 (b = 128 B) | Data masukan | Variabel | 0 [BVA]; 1 [BVA]; 127 [BVA]; 128 [BVA]; 129 [BVA]; 256 [BVA]; 1048576 [EP]; 104857600 [EP]; 1073741824 [BVA]; 1073741825 [BVA, NEG] |
| HF-LEN-SHA-1 | Panjang pesan SHA-1 (b = 64 B) | Data masukan | Variabel | 0 [BVA]; 1 [BVA]; 55 [BVA]; 56 [BVA]; 63 [BVA]; 64 [BVA]; 65 [BVA]; 1048576 [EP]; 104857600 [EP]; 1073741824 [BVA]; 1073741825 [BVA, NEG] |
| HF-LEN-SHA-256 | Panjang pesan SHA-256 (b = 64 B) | Data masukan | Variabel | 0 [BVA]; 1 [BVA]; 55 [BVA]; 56 [BVA]; 63 [BVA]; 64 [BVA]; 65 [BVA]; 1048576 [EP]; 104857600 [EP]; 1073741824 [BVA]; 1073741825 [BVA, NEG] |
| HF-LEN-SHA-384 | Panjang pesan SHA-384 (b = 128 B) | Data masukan | Variabel | 0 [BVA]; 1 [BVA]; 111 [BVA]; 112 [BVA]; 127 [BVA]; 128 [BVA]; 129 [BVA]; 1048576 [EP]; 104857600 [EP]; 1073741824 [BVA]; 1073741825 [BVA, NEG] |
| HF-LEN-SHA-512/256 | Panjang pesan SHA-512/256 (b = 128 B) | Data masukan | Variabel | 0 [BVA]; 1 [BVA]; 111 [BVA]; 112 [BVA]; 127 [BVA]; 128 [BVA]; 129 [BVA]; 1048576 [EP]; 104857600 [EP]; 1073741824 [BVA]; 1073741825 [BVA, NEG] |
| HF-LEN-SHA3-256 | Panjang pesan SHA3-256 (b = 136 B) | Data masukan | Variabel | 0 [BVA]; 1 [BVA]; 135 [BVA]; 136 [BVA]; 137 [BVA]; 272 [BVA]; 1048576 [EP]; 104857600 [EP]; 1073741824 [BVA]; 1073741825 [BVA, NEG] |
| HF-LEN-SHAKE256 | Panjang pesan SHAKE256 (b = 136 B) | Data masukan | Variabel | 0 [BVA]; 1 [BVA]; 135 [BVA]; 136 [BVA]; 137 [BVA]; 272 [BVA]; 1048576 [EP]; 104857600 [EP]; 1073741824 [BVA]; 1073741825 [BVA, NEG] |
| HF-PAT | Pola pesan | Data masukan | Variabel | acak [EP]; nol-semua (0x00…) [DEG]; satu-semua (0xFF…) [DEG]; low-density (HW = 1) [DEG]; high-density (HW = n−1) [DEG]; periodik (0x55/0xAA) [DEG]; beda 1 bit [BIT] |
| HF-DIG | Panjang digest | Konfigurasi | Variabel | penuh [EP]; terpotong t = 128 bit [EP]; XOF 256/512 bit [EP]; terpotong t = 32 bit (analisis birthday) [BVA] |
| HF-CHUNK | Pemecahan input | Konfigurasi | Variabel | one-shot [EP]; update bertahap acak (1…b+7 byte) [EP] |
| HF-ROUNDS | Jumlah ronde | Konfigurasi | Variabel | penuh [EP]; tereduksi (analisis) [BVA] |
| HF-KEY | Kunci/salt (HMAC, KDF) | Material rahasia | Variabel | kunci < blok [BVA]; kunci = blok [BVA]; kunci > blok (di-hash dulu) [BVA]; kunci 0 byte [NEG, NEG] |
| ENV | Kondisi operasional | Kondisi lingkungan | Variabel | normal [EP]; beban tinggi multi-thread [EP]; memori terbatas [EP] |

Reduksi pairwise (t = 2. IPOG) atas 12 parameter Variabel: **2.449.440.000** kombinasi penuh → **150** kombinasi pairwise (100.0% berkurang; semua pasangan tercakup: True).

### 1.4 Ruang parameter — pke

| ID | Parameter | Kelas | Status | Nilai uji (teknik) |
|---|---|---|---|---|
| PK-DOM | Ukuran kunci & domain | Parameter publik/domain | Variabel | ECDH-P384 [EP]; FFDHE3072 [EP]; ML-KEM-768 [EP]; RSA-OAEP-2048 [EP]; RSA-OAEP-3072 [EP]; RSAES-PKCS1-V1_5-1024 [EP]; X25519 [EP]; RSA-1024 [NEG, NEG]; RSA-2047 (modulus ganjil-bit) [BVA, NEG] |
| PK-KEYGEN | Kualitas pembangkitan kunci | Material rahasia | Tetap | DRBG produk (normal) [EP]; entropi rendah (simulasi, batch-GCD) [NEG, NEG] |
| PK-PAD | Skema padding | Konfigurasi | Variabel | OAEP (SHA-256/MGF1) [EP]; PKCS#1 v1.5 [NEG]; FO transform (KEM) [EP] |
| PK-CT | Ciphertext masukan | Data masukan | Tetap | valid [EP]; termodifikasi 1 bit [BIT, NEG]; malformed (panjang ±1) [NEG, NEG]; di luar rentang (c ≥ n) [BVA, NEG] |
| PK-PEER | Kunci publik lawan | Data masukan | Tetap | valid [EP]; titik tidak di kurva [NEG, NEG]; subgrup kecil / low-order [NEG, NEG]; titik tak hingga [BVA, NEG] |
| PK-KEYS | Panjang modulus/kunci | Parameter publik/domain | Variabel | 0 [BVA, NEG]; 254 [BVA, NEG]; 255 [EP]; 384 [EP]; 1024 [EP]; 2048 [EP]; 3072 [EP]; 256 [NEG, NEG]; 512 [NEG, NEG]; 3073 [BVA, NEG] |
| ENV | Kondisi operasional | Kondisi lingkungan | Variabel | normal [EP]; beban tinggi multi-thread [EP]; memori terbatas [EP] |

Reduksi pairwise (t = 2. IPOG) atas 4 parameter Variabel: **315** kombinasi penuh → **35** kombinasi pairwise (88.9% berkurang; semua pasangan tercakup: True).

### 1.5 Ruang parameter — signature

| ID | Parameter | Kelas | Status | Nilai uji (teknik) |
|---|---|---|---|---|
| DS-ALG | Kurva & hash / parameter set | Parameter publik/domain | Variabel | ECDSA-P256 [EP]; ECDSA-P384 [EP]; ED25519 [EP]; ML-DSA-65 [EP]; RSA-PSS-3072 [EP]; SLH-DSA-SHA2-128S [EP] |
| DS-NONCE | Mode nonce | Konfigurasi | Tetap | rfc6979 [EP]; bias beberapa bit (simulasi) [NEG, NEG]; berulang (simulasi) [NEG, NEG] |
| DS-MSG | Panjang pesan | Data masukan | Variabel | 0 [BVA]; 1 [BVA]; 55 [BVA]; 56 [BVA]; 63 [BVA]; 64 [BVA]; 65 [BVA]; 1048576 [EP]; 104857600 [EP] |
| DS-D | Kunci privat d | Material rahasia | Variabel | acak [EP]; Hamming weight rendah [DEG]; Hamming weight tinggi [DEG]; d = 1 [BVA]; d = n − 1 [BVA]; d = 0 [BVA, NEG]; d = n [BVA, NEG] |
| DS-ENC | Encoding (r, s) | Data masukan | Variabel | DER kanonik [EP]; DER non-kanonik [NEG, NEG]; r atau s = 0 [BVA, NEG]; r atau s ≥ n [BVA, NEG]; s ↔ n − s [NEG] |
| DS-Q | Kunci publik Q | Data masukan | Tetap | valid [EP]; titik tak hingga O [BVA, NEG]; di luar kurva [NEG, NEG]; koordinat ≥ p [BVA, NEG] |
| DS-N | Ukuran sampel | Konfigurasi | Variabel | N = 1.000.000 tanda tangan (uji nonce) [EP]; 100.000 trace/pengukuran (side-channel) [EP] |
| DS-PQC | Parameter PQC & state | Parameter publik/domain | Variabel | ML-DSA-65 [EP]; SLH-DSA-SHA2-128S [EP]; indeks OTS dipakai ulang (stateful) [NEG, NEG] |
| ENV | Kondisi operasional | Kondisi lingkungan | Variabel | normal [EP]; beban tinggi multi-thread [EP]; memori terbatas [EP] |

Reduksi pairwise (t = 2. IPOG) atas 6 parameter Variabel: **1.296** kombinasi penuh → **54** kombinasi pairwise (95.8% berkurang; semua pasangan tercakup: True).

## 2. Telaah Metode & Parameter (KUK 1.1, 1.2)

Empat kebutuhan pengujian SKKNI: N1 jenis algoritma · N2 desain & teknik implementasi · N3 tren serangan · N4 best practice.

| Metode | Sel (tingkat × lapis) | N1 | N2 | N3 | N4 | Asal UK-1 | Putusan |
|---|---|---|---|---|---|---|---|
| M-FUZZ Uji negatif & fuzzing API (masukan malformed, panjang ekstrem) | Integrasi × I | ✔ | ✔ | ✔ | ✔ | AES-128, ChaCha20, SHA3-256, RSA-OAEP-2048, ECDSA-P256 | RELEVAN |
| M-NONCE Uji keunikan & bias nonce (statistik + kelayakan lattice HNP) | Integrasi × I | ✔ | ✔ | ✔ | ✔ | AES-128, ChaCha20, ECDSA-P256 | RELEVAN |
| M-SP80022 Uji keacakan statistik NIST SP 800-22 (15 uji) | Komponen × S | ✔ | ✔ | ✔ | ✔ | AES-128, ChaCha20, SHA3-256 | RELEVAN |
| M-TIMING Analisis timing leakage (dudect / Welch t-test, fixed-vs-random) | Integrasi × I | ✔ | ✔ | ✔ | ✔ | AES-128, ChaCha20, SHA3-256, RSA-OAEP-2048, ECDSA-P256 | RELEVAN |
| M-ZEROIZE Uji zeroization material kunci (memory dump pasca-operasi) | Sistem × I | ✔ | ✔ | ✔ | ✔ | AES-128, ChaCha20, SHA3-256, RSA-OAEP-2048, ECDSA-P256 | RELEVAN |
| M-AVAL Uji avalanche & Strict Avalanche Criterion (fungsi penuh) | Komponen × S | ✔ | ✔ | ✔ | ✔ | AES-128, ChaCha20, SHA3-256 | RELEVAN |
| M-DIFFUSION Analisis difusi (branch number/MDS, ronde menuju difusi penuh, avalanche per ronde) | Komponen × S | ✔ | ✔ | ✔ | ✔ | AES-128, ChaCha20, SHA3-256 | RELEVAN |
| M-RNG Asesmen RBG / sumber entropi (SP 800-90A/B, ISO/IEC 18031) | Integrasi × I | ✔ | ✔ | ✔ | ✔ | AES-128, ChaCha20, RSA-OAEP-2048, ECDSA-P256 | RELEVAN |
| M-SBOX Analisis sifat S-box / fungsi nonlinear (NL, DDT, LAT, derajat, SAC) | Komponen × S | ✔ | ✔ | ✔ | ✔ | AES-128, SHA3-256 | RELEVAN |
| M-KEYSIZE Evaluasi ukuran kunci & tingkat keamanan (SP 800-57 / 131A) | Sistem × S | ✔ | ✔ | ✔ | ✔ | AES-128, ChaCha20, SHA3-256, RSA-OAEP-2048, ECDSA-P256 | RELEVAN |
| M-DIFF Kriptanalisis diferensial (pencarian trail / batas S-box aktif) | Komponen × S | ✔ | ✔ | ✔ | ✔ | AES-128, SHA3-256 | RELEVAN |
| M-INT Serangan integral / Square pada ronde tereduksi | Komponen × S | ✔ | ✔ | ✔ | ✔ | AES-128 | RELEVAN |
| M-LIN Kriptanalisis linear (LAT, batas korelasi trail) | Komponen × S | ✔ | ✔ | ✔ | ✔ | AES-128 | RELEVAN |
| M-KAT Known Answer Test (KAT) terhadap vektor resmi | Komponen × K | ✔ | ✔ | ✔ | ✔ | AES-128, ChaCha20, SHA3-256, RSA-OAEP-2048, ECDSA-P256 | RELEVAN |
| M-MCT Monte Carlo Test (MCT) & Multi-block Message Test (MMT) gaya CAVP | Komponen × K | ✔ | ✔ | ✔ | ✔ | AES-128, SHA3-256 | RELEVAN |
| M-SELFTEST Uji self-test & error state modul (ISO/IEC 19790 / 24759) | Sistem × I | ✔ | ✔ | ✔ | ✔ | AES-128, ChaCha20, SHA3-256, RSA-OAEP-2048, ECDSA-P256 | RELEVAN |
| M-BOOL Analisis fungsi Boolean komponen nonlinear (NL, CI, derajat) | Komponen × S | ✔ | ✔ | ✔ | ✔ | ChaCha20 | RELEVAN |
| M-LC Kompleksitas linear (Berlekamp–Massey) & periode keystream | Komponen × S | ✔ | ✔ | ✔ | ✔ | ChaCha20 | RELEVAN |
| M-PAD Uji kesesuaian padding (pad10*1 / MD-strengthening) pada batas blok | Komponen × K | ✔ | ✔ | ✔ | ✔ | SHA3-256 | RELEVAN |
| M-ORACLE Uji oracle galat dekripsi OAEP (Manger) — keseragaman galat & timing | Integrasi × I | ✔ | ✔ | ✔ | ✔ | RSA-OAEP-2048 | RELEVAN |
| M-PKV Validasi kunci publik (positif & negatif) | Komponen × K | ✔ | ✔ | ✔ | ✔ | RSA-OAEP-2048, ECDSA-P256 | RELEVAN |
| M-PRIME Uji primalitas & validasi pembangkitan kunci (ISO/IEC 18032, FIPS 186-5 App. A/B) | Komponen × K | ✔ | ✔ | ✔ | ✔ | RSA-OAEP-2048 | RELEVAN |
| M-RSAWEAK Baterai kunci lemah RSA (Fermat, Pollard p−1, batch-GCD, Wiener) | Komponen × S | ✔ | ✔ | ✔ | ✔ | RSA-OAEP-2048 | RELEVAN |
| M-FACT Percobaan faktorisasi modulus (GNFS) | Sistem × S | ✔ | ✔ | ✔ | ✔ | RSA-OAEP-2048 | RELEVAN |
| M-SIGMAL Uji penolakan (r,s) non-kanonik & malleability | Komponen × K | ✔ | ✔ | ✔ | ✔ | ECDSA-P256 | RELEVAN |
| M-CURVE Validasi parameter domain kurva (prima, orde, diskriminan, MOV/anomalous) | Komponen × K | ✔ | ✔ | ✔ | ✔ | ECDSA-P256 | RELEVAN |
| M-ECDLP Estimasi & uji Pollard rho ECDLP | Sistem × S | ✔ | ✔ | ✔ | ✔ | ECDSA-P256 | RELEVAN |

Sel kosong (21) diisi dari templat kategori materi: block:Komponen×I, block:Integrasi×K, block:Integrasi×S, block:Sistem×K, hash:Komponen×I, hash:Integrasi×K, hash:Integrasi×S, hash:Sistem×K, pke:Komponen×I, pke:Integrasi×K, pke:Integrasi×S, pke:Sistem×K, signature:Komponen×S, signature:Komponen×I, signature:Integrasi×K, signature:Integrasi×S, signature:Sistem×K, stream:Komponen×I, stream:Integrasi×K, stream:Integrasi×S, stream:Sistem×K

Teknik penetapan nilai uji: EP = Partisi ekuivalensi; BVA = Analisis nilai batas; DEG = Input degeneratif/berpola; BIT = Variasi 1-bit (diferensial); TWAY = Kombinatorial t-way (pairwise); NEG = Negative testing

## 3. Matriks Skenario Lapis × Tingkat (KUK 2.1)

**block**

| Tingkat | Uji Kesesuaian | Uji Keamanan | Uji Implementasi |
|---|---|---|---|
| Komponen | SCN-BC-KOM-K: BC-K-01 | SCN-BC-KOM-S: BC-S-01 | SCN-BC-KOM-I: BC-I-01 |
| Integrasi | SCN-BC-INT-K: BC-K-02, BC-K-03, BC-K-04, BC-K-05 | SCN-BC-INT-S: BC-S-02, BC-S-03, BC-S-04 | SCN-BC-INT-I: BC-I-02, BC-I-03 |
| Sistem | SCN-BC-SIS-K: BC-K-06 | SCN-BC-SIS-S: BC-S-05, BC-S-06 | SCN-BC-SIS-I: BC-I-05, BC-I-06 |

**stream**

| Tingkat | Uji Kesesuaian | Uji Keamanan | Uji Implementasi |
|---|---|---|---|
| Komponen | SCN-SC-KOM-K: SC-K-01 | SCN-SC-KOM-S: SC-S-01 | SCN-SC-KOM-I: SC-I-01 |
| Integrasi | SCN-SC-INT-K: SC-K-02, SC-K-03, SC-K-04, SC-K-05 | SCN-SC-INT-S: SC-S-02, SC-S-03, SC-S-04 | SCN-SC-INT-I: SC-I-02, SC-I-03 |
| Sistem | SCN-SC-SIS-K: SC-K-06 | SCN-SC-SIS-S: SC-S-05, SC-S-06 | SCN-SC-SIS-I: SC-I-04, SC-I-05 |

**hash**

| Tingkat | Uji Kesesuaian | Uji Keamanan | Uji Implementasi |
|---|---|---|---|
| Komponen | SCN-HF-KOM-K: HF-K-01 | SCN-HF-KOM-S: HF-S-01 | SCN-HF-KOM-I: HF-I-01 |
| Integrasi | SCN-HF-INT-K: HF-K-02, HF-K-03, HF-K-04, HF-K-05 | SCN-HF-INT-S: HF-S-02, HF-S-03, HF-S-04, HF-S-05 | SCN-HF-INT-I: HF-I-02, HF-I-03 |
| Sistem | SCN-HF-SIS-K: HF-K-06 | SCN-HF-SIS-S: HF-S-06 | SCN-HF-SIS-I: HF-I-04, HF-I-05, HF-I-06 |

**pke**

| Tingkat | Uji Kesesuaian | Uji Keamanan | Uji Implementasi |
|---|---|---|---|
| Komponen | SCN-PK-KOM-K: PK-K-01 | SCN-PK-KOM-S: PK-S-01 | SCN-PK-KOM-I: PK-I-01 |
| Integrasi | SCN-PK-INT-K: PK-K-02, PK-K-03, PK-K-04, PK-K-05 | SCN-PK-INT-S: PK-S-02, PK-S-03, PK-S-04, PK-S-05 | SCN-PK-INT-I: PK-I-02, PK-I-03 |
| Sistem | SCN-PK-SIS-K: PK-K-06 | SCN-PK-SIS-S: PK-S-06 | SCN-PK-SIS-I: PK-I-04, PK-I-05 |

**signature**

| Tingkat | Uji Kesesuaian | Uji Keamanan | Uji Implementasi |
|---|---|---|---|
| Komponen | SCN-DS-KOM-K: DS-K-01, DS-K-02 | SCN-DS-KOM-S: DS-S-01 | SCN-DS-KOM-I: DS-I-01 |
| Integrasi | SCN-DS-INT-K: DS-K-03, DS-K-04, DS-K-05, DS-K-08 | SCN-DS-INT-S: DS-S-02, DS-S-03, DS-S-04, DS-S-05, DS-S-08 | SCN-DS-INT-I: DS-I-04 |
| Sistem | SCN-DS-SIS-K: DS-K-07 | SCN-DS-SIS-S: DS-S-07 | SCN-DS-SIS-I: TIDAK BERLAKU — tidak ada resep yang memenuhi fitur produk |

**cross**

| Tingkat | Uji Kesesuaian | Uji Keamanan | Uji Implementasi |
|---|---|---|---|
| Integrasi | SCN-XA-INT-K: XA-K-01 | SCN-XA-INT-S: XA-S-01 | — |
| Sistem | — | SCN-XA-SIS-S: XA-S-02, XA-S-04, XA-S-03 | SCN-XA-SIS-I: XA-I-01 |

**Lintas-algoritma:** RNG / Sumber Entropi → Pembangkitan Kunci → KDF → Cipher / MAC / Signature → Protokol → Produk · skenario: XA-K-01, XA-S-01, XA-S-02, XA-S-04, XA-I-01, XA-S-03 · PQC relevan: True

**Resep tidak berlaku (fitur/objek tidak dimiliki produk — aturan f):**

| Resep | Alasan |
|---|---|
| BC-I-04 | fitur produk tidak ada: power_glitch |
| SC-I-06 | fitur produk tidak ada: side_channel_lab |
| PK-I-06 | fitur produk tidak ada: power_glitch |
| DS-K-06 | fitur produk tidak ada: pdf_signing |
| DS-S-06 | fitur produk tidak ada: pdf_signing, certificates |
| DS-I-02 | fitur produk tidak ada: side_channel_lab, token |
| DS-I-03 | fitur produk tidak ada: power_glitch |
| DS-I-05 | fitur produk tidak ada: key_non_exportable |
| DS-I-06 | fitur produk tidak ada: multi_doc_signing |
| DS-S-09 | fitur produk tidak ada: key_non_exportable |

## 4. Laporan Verifikasi terhadap Spesifikasi Desain (KUK 2.2 — aspek kritis)

Status keseluruhan: **LULUS** · 0 temuan

| Aturan | Deskripsi | Diperiksa | Status | Temuan |
|---|---|---|---|---|
| (a) | Cakupan algoritma, varian, panjang kunci, mode & parameter set profil | 33 | LULUS | — |
| (b) | Nilai di luar spesifikasi hanya sebagai negative test (harapan ditolak) | 335 | LULUS | — |
| (c) | Setiap klaim keamanan punya ≥ 1 skenario Uji Keamanan | 7 | LULUS | — |
| (d) | Setiap metode UK-1 punya ≥ 1 skenario | 27 | LULUS | — |
| (e) | Modul: 11 area ISO/IEC 19790 (7.2–7.12) tercakup / dijustifikasi | 0 | TIDAK BERLAKU | — |
| (f) | Tidak ada skenario untuk fitur/objek yang tidak dimiliki produk | 91 | LULUS | — |

## 5. Katalog Test Case (KUK 2.3)

### 5.1 Uji Kesesuaian

| ID | Tingkat | Area | Parameter & nilai uji | Prosedur | Kriteria lulus | Metode UK-1 | Prioritas | Pelaksana |
|---|---|---|---|---|---|---|---|---|
| BC-K-01 | Komponen | — | 4 nilai (Panjang kunci) | 1. Ambil vektor contoh per ronde (FIPS 197 App. B/C) untuk kunci yang didukung 2. Jalankan unit enkripsi produk dengan trace nilai antara (build analisis) 3. Bandingkan state awal/akhir tiap ronde & round key dengan implementasi referensi core/ 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruh nilai antara & round key identik 100% | M-KAT, M-SBOX | Tinggi | Penguji lab (Cryptographic Analyst) |
| BC-K-02 | Integrasi | — | 12 nilai (Mode operasi, Panjang kunci) | 1. Muat berkas expected value untuk target 2. Eksekusi enkripsi/dekripsi produk pada setiap vektor 3. Catat keluaran & bandingkan byte-per-byte 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Ciphertext/tag/plaintext identik 100% dengan vektor resmi; vektor invalid ditolak | M-KAT | Tinggi | Penguji lab (Cryptographic Analyst) |
| BC-K-03 | Integrasi | — | 15 nilai (Mode operasi, Panjang pesan & padding) | 1. Jalankan MCT 100 × 1000 iterasi berantai (gaya CAVP) 2. Jalankan MMT 1–10 blok per mode 3. Bandingkan 100 checkpoint dengan core/ atau pustaka tepercaya 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | 100% checkpoint identik | M-MCT | Sedang | Penguji lab (Cryptographic Analyst) |
| BC-K-04 | Integrasi | — | 14 nilai (Blok plaintext, Panjang pesan & padding) | 1. Bangkitkan pesan pada setiap nilai batas panjang (0, 1, b−1, b, b+1, 1 MiB) 2. Enkripsi lalu dekripsi dengan kunci & nonce yang sama 3. Bandingkan dengan pesan asli 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | D(E(x)) = x untuk 100% kasus | M-KAT, M-FUZZ | Sedang | Penguji lab (Cryptographic Analyst) |
| BC-K-05 | Integrasi | — | 17 nilai (Mode operasi, Panjang kunci) | 1. Panggil API dengan panjang kunci & mode yang tidak didukung (nilai NEG ruang parameter) 2. Catat kode galat 3. Pastikan tidak ada keluaran kriptografis 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruh parameter di luar spesifikasi ditolak dengan galat terdefinisi | M-FUZZ | Tinggi | Penguji lab (Cryptographic Analyst) |
| BC-K-06 | Sistem | — | 8 nilai (Mode operasi) | 1. Enkripsi data dengan produk, dekripsi dengan pustaka referensi (OpenSSL/pyca) 2. Lakukan arah sebaliknya 3. Periksa format (IV ∥ CT ∥ tag) sesuai dokumentasi 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Interoperabel dua arah 100% | M-KAT | Sedang | Penguji lab + test engineer |
| DS-K-01 | Komponen | — | Titik khusus: O, P + (−P), P + P, n·G | 1. Hitung O, P + (−P), P + P, n·G dengan produk 2. Hitung yang sama dengan implementasi referensi core/ 3. Bandingkan seluruh hasil 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Hasil identik 100%; n·G = O | M-CURVE, M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| DS-K-02 | Komponen | — | Pesan 0, 55, 56, 64, 65 byte dan 1 MB · 9 nilai (Panjang pesan) | 1. Hash pesan pada nilai batas panjang (b = 64: 0, 55, 56, 64, 65 byte) dan 1 MB 2. Jalankan MCT SHA-256 3. Bandingkan digest 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Digest identik 100% | M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| DS-K-03 | Integrasi | — | 100 pasangan kunci hasil KeyGen | 1. Bangkitkan 100 pasangan kunci 2. Periksa 1 ≤ d ≤ n − 1 3. Periksa Q = d·G valid di kurva (validasi penuh) 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | 100% pasangan kunci valid | M-PKV | Sedang | Penguji lab (Cryptographic Analyst) |
| DS-K-04 | Integrasi | — | Vektor uji RFC 6979 (P-256, SHA-256) | 1. Gunakan d & pesan dari vektor RFC 6979 A.2.5 2. Bangkitkan (r, s) dengan produk 3. Bandingkan dengan vektor acuan 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | (r, s) identik dengan vektor acuan | M-KAT | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-K-05 | Integrasi | — | ≥ 500 vektor SigVer: valid dan seluruh variasi encoding invalid · 2 nilai (Encoding (r, s)) | 1. Muat vektor SigVer (Wycheproof + mutasi encoding) 2. Verifikasi tiap vektor dengan produk 3. Catat terima/tolak per vektor 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Valid diterima; seluruh invalid ditolak | M-KAT, M-SIGMAL | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-K-07 | Sistem | — | ECDSA-P256, ECDSA-P384, ED25519, ML-DSA-65 | 1. Tanda tangani pesan dengan produk; verifikasi dengan OpenSSL/pyca 2. Arah sebaliknya 3. Untuk EdDSA/ML-DSA gunakan vektor resmi 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Status verifikasi konsisten dua arah | M-KAT | Sedang | Penguji lab + test engineer |
| DS-K-08 | Integrasi | — | ED25519, ML-DSA-65, RSA-PSS-3072, SLH-DSA-SHA2-128S | 1. Muat vektor RFC 8032 / Wycheproof / ACVP 2. Verifikasi & tanda tangani 3. Invalid harus ditolak 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Identik 100%; invalid ditolak | M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-K-01 | Komponen | — | BLAKE2B-512, SHA-1, SHA-256, SHA-384 | 1. Bandingkan konstanta ronde & offset rotasi dengan standar 2. Jalankan permutasi pada state uji (core/) 3. Periksa padding pad10*1 / MD-strengthening pada batas b 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Identik 100% | M-KAT, M-PAD | Tinggi | Penguji lab (Cryptographic Analyst) |
| HF-K-02 | Integrasi | — | 74 nilai (Panjang pesan BLAKE2B-512 (b = 128 B), Panjang pesan SHA-1 (b = 64 B), Panjang pesan SHA-256 (b = 64 B)) | 1. Hash pesan pada setiap nilai batas (0, 1, b−L−1, b−L, b−1, b, b+1, 1 MiB) 2. Bandingkan dengan expected value (dua implementasi independen + vektor resmi) 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Digest identik 100% | M-KAT, M-PAD | Tinggi | Penguji lab (Cryptographic Analyst) |
| HF-K-03 | Integrasi | — | BLAKE2B-512, SHA-1, SHA-256, SHA-384 | 1. MCT 100 × 1000 iterasi (gaya CAVP) 2. Bandingkan checkpoint 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | 100% checkpoint identik | M-MCT | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-K-04 | Integrasi | — | 6 nilai (Panjang digest, Pemecahan input) | 1. Hash pesan 1 MiB sekaligus dan bertahap acak (1…b+7 byte) 2. Untuk XOF: minta 256 & 512 bit 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Digest identik; prefiks XOF konsisten | M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-K-05 | Integrasi | — | 3 nilai (Kunci/salt (HMAC, KDF)) | 1. Muat vektor HMAC (Wycheproof/RFC 4231) & KDF 2. Eksekusi; bandingkan tag 3. Vektor invalid harus ditolak 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Identik 100% | M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-K-06 | Sistem | — | BLAKE2B-512, SHA-1, SHA-256, SHA-384 | 1. Verifikasi silang digest berkas dengan sha3sum/OpenSSL 2. Periksa label domain separation 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Konsisten | M-KAT | Sedang | Penguji lab + test engineer |
| PK-K-01 | Komponen | — | ECDH-P384, FFDHE3072, ML-KEM-768, RSA-OAEP-2048 | 1. Uji primalitas p, q kunci sampel (Miller–Rabin 64) 2. Periksa parameter domain kurva/grup 3. Bandingkan aritmetika dengan core/ 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruh pemeriksaan LULUS | M-PRIME, M-CURVE, M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| PK-K-02 | Integrasi | — | 7 nilai (Ukuran kunci & domain) | 1. Muat expected value target (PKCS#1 / Wycheproof / RFC 7748) 2. Eksekusi pada tiap vektor 3. Bandingkan keluaran; invalid ditolak 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Identik 100%; invalid ditolak | M-KAT | Tinggi | Penguji lab (Cryptographic Analyst) |
| PK-K-03 | Integrasi | — | RSA-OAEP-2048, RSA-OAEP-3072, RSAES-PKCS1-V1_5-1024 | 1. m = 0, 1, k−2hLen−2 (maks OAEP), k−2hLen−1 (melebihi) 2. Enkripsi lalu dekripsi 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Round-trip 100%; m terlalu panjang ditolak | M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| PK-K-04 | Integrasi | — | ECDH-P384, FFDHE3072, ML-KEM-768, RSA-OAEP-2048 | 1. Bangkitkan 100 kunci 2. Periksa syarat FIPS 186-5 A.1.3 / validitas titik 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | 100% kunci valid | M-PRIME | Sedang | Penguji lab (Cryptographic Analyst) |
| PK-K-05 | Integrasi | — | 19 nilai (Panjang modulus/kunci, Ukuran kunci & domain) | 1. Impor RSA-1024, modulus 2047 bit, kurva tak didukung 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruhnya ditolak | M-PKV | Sedang | Penguji lab (Cryptographic Analyst) |
| PK-K-06 | Sistem | — | ECDH-P384, FFDHE3072, ML-KEM-768, RSA-OAEP-2048 | 1. Ekspor/impor kunci ke OpenSSL 2. Enkripsi produk ↔ dekripsi OpenSSL 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Interoperabel dua arah | M-KAT | Sedang | Penguji lab + test engineer |
| SC-K-01 | Komponen | — | CHACHA20-256, CHACHA20-POLY1305 | 1. Ambil vektor quarter-round & block function (RFC 8439 §2.1.1, §2.3.2) 2. Jalankan unit produk 3. Bandingkan state 16 word 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | State identik 100% | M-KAT | Tinggi | Penguji lab (Cryptographic Analyst) |
| SC-K-02 | Integrasi | — | 8 nilai (IV/nonce, Kunci) | 1. Muat expected value target (RFC 8439 / Wycheproof) 2. Enkripsi & dekripsi pada setiap vektor 3. Bandingkan keluaran & tag 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Identik 100%; tag invalid ditolak | M-KAT | Tinggi | Penguji lab (Cryptographic Analyst) |
| SC-K-03 | Integrasi | — | 4 nilai (Panjang keystream) | 1. Enkripsi pesan panjang sekaligus vs bertahap dengan counter awal 0/1 2. Mulai ulang dari counter tengah 3. Bandingkan keystream 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Keystream konsisten | M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| SC-K-04 | Integrasi | — | 11 nilai (IV/nonce, Kunci) | 1. Panggil API dengan kunci 248 bit, nonce 64 bit 2. Catat kode galat 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Ditolak dengan galat terdefinisi | M-FUZZ | Sedang | Penguji lab (Cryptographic Analyst) |
| SC-K-05 | Integrasi | — | CHACHA20-POLY1305 | 1. Balik 1 bit ciphertext/AAD/tag 2. Dekripsi 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruh modifikasi ditolak | M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| SC-K-06 | Sistem | — | CHACHA20-256, CHACHA20-POLY1305 | 1. Enkripsi dengan produk, dekripsi dengan OpenSSL/libsodium dan sebaliknya 2. Simulasikan bit loss/delay 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Interoperabel; galat sinkronisasi terdeteksi | M-KAT | Sedang | Penguji lab + test engineer |
| XA-K-01 | Integrasi | — | AES-128-CTR, AES-256-GCM, AES-256-KW, XTS-AES-256 | 1. Jalankan alur end-to-end dengan data uji tetap 2. Periksa endianness, encoding (DER/raw), panjang parameter & kode galat antar-komponen 3. Bandingkan keluaran tiap tahap dengan referensi 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Format & kode galat konsisten di seluruh rantai | M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |

### 5.2 Uji Keamanan

| ID | Tingkat | Area | Parameter & nilai uji | Prosedur | Kriteria lulus | Metode UK-1 | Prioritas | Pelaksana |
|---|---|---|---|---|---|---|---|---|
| BC-S-01 | Komponen | — | 2 nilai (Jumlah ronde) | 1. Ekstrak S-box dari produk (white/grey box) atau gunakan S-box standar 2. Hitung NL, DDT, LAT, derajat, SAC secara exhaustive 3. Bandingkan dengan nilai acuan desain 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | NL = 112, DU = 4, derajat = 7 (AES) | M-SBOX | Sedang | Penguji lab (Cryptographic Analyst) |
| BC-S-02 | Integrasi | — | 14 nilai (Blok plaintext, Nilai kunci) | 1. Bangkitkan dataset key-avalanche, plaintext-avalanche, low/high-density, korelasi P–C 2. Ukur fraksi bit berubah (N = 10 000 sampel) 3. Jalankan SP 800-22 pada keystream/keluaran (100 × 10^6 bit) 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Avalanche rerata n/2 (σ ≈ √n/2); proporsi lolos ≥ ambang SP 800-22; P-value_T ≥ 0,0001 | M-AVAL, M-SP80022 | Sedang | Penguji lab (Cryptographic Analyst) |
| BC-S-03 | Integrasi | — | 6 nilai (IV/nonce) | 1. Kirim dua pesan dengan kunci & nonce sama ke API 2. Periksa apakah produk mendeteksi/menolak reuse 3. Bila tidak, tunjukkan XOR plaintext bocor dari XOR ciphertext 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Reuse ditolak/terdeteksi; nonce yang dibangkitkan produk tidak pernah berulang (≥ 2^16 pesan) | M-NONCE | Tinggi | Penguji lab (Cryptographic Analyst) |
| BC-S-04 | Integrasi | — | 2 nilai (Jumlah ronde) | 1. Bangun varian ronde tereduksi (2–4 ronde) dengan core/ 2. Jalankan distinguisher diferensial/linear/integral (Λ-set 2^8) 3. Bandingkan margin dengan serangan literatur (UK-1) 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Serangan hanya berhasil pada ronde tereduksi; kompleksitas ronde penuh ≥ klaim bit security | M-DIFF, M-LIN, M-INT | Sedang | Penguji lab (Cryptographic Analyst) |
| BC-S-05 | Sistem | — | 7 nilai (Panjang pesan & padding) | 1. Baca batas data per kunci dari dokumentasi/profil 2. Hitung 2^(n/2) blok untuk tiap target 3. Uji API melewati batas (maks + 1) 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Batas ≤ 2^(n/2) blok dan ditegakkan produk (pesan berlebih ditolak/rekey) | M-KEYSIZE | Sedang | Penguji lab + test engineer |
| BC-S-06 | Sistem | — | AES-128-CTR, AES-256-GCM, AES-256-KW, XTS-AES-256 | 1. Bandingkan security strength tiap target dengan SP 800-57 & status SP 800-131A 2. Tandai algoritma legacy/disallowed (mis. TDEA, PRESENT-80) 3. Periksa bahwa legacy hanya untuk dekripsi 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Strength ≥ 112 bit untuk layanan approved; legacy hanya legacy use | M-KEYSIZE | Tinggi | Penguji lab + test engineer |
| DS-S-01 | Komponen | — | Parameter domain P-256 di dalam produk | 1. Ekstrak p, a, b, G, n, h dari produk 2. Cocokkan dengan SP 800-186 3. Uji primalitas n; h = 1 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Identik; n prima, h = 1 | M-CURVE | Sedang | Penguji lab (Cryptographic Analyst) |
| DS-S-02 | Integrasi | — | N = 10^6 tanda tangan, pesan acak, d uji diketahui · 3 nilai (Mode nonce, Ukuran sampel) | 1. Bangkitkan N tanda tangan, pesan acak, d uji diketahui 2. Hitung k = s⁻¹(e + r·d) mod n 3. Uji bias MSB/LSB (χ²) & keacakan bit k 4. Simulasikan serangan lattice/HNP 5. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada bias signifikan (α = 0,01); serangan HNP simulasi gagal | M-NONCE | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-S-03 | Integrasi | — | N tanda tangan dari DS-S-02, kedua mode nonce · 1 nilai (Mode nonce) | 1. Gunakan N tanda tangan dari DS-S-02 untuk kedua mode nonce 2. Cari r berulang untuk pesan berbeda 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada r berulang | M-NONCE | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-S-04 | Integrasi | — | Q = O, Q di luar kurva, koordinat ≥ p · 4 nilai (Kunci publik Q) | 1. Masukkan Q = O, Q di luar kurva, koordinat ≥ p ke verifier 2. Masukkan ke proses impor sertifikat 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruhnya ditolak | M-PKV | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-S-05 | Integrasi | — | Keluaran DRBG pembangkit d dan k (mode acak) | 1. Kumpulkan keluaran DRBG (mode acak) 2. Estimasi min-entropi SP 800-90B 3. Jalankan SP 800-22 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Min-entropi ≥ klaim; lolos uji statistik | M-RNG | Sedang | Penguji lab (Cryptographic Analyst) |
| DS-S-07 | Sistem | — | ECDSA-P256, ECDSA-P384, ED25519, ML-DSA-65 | 1. Hitung strength tiap skema (SP 800-57/FIPS 204) 2. Tandai skema rentan kuantum (IR 8547) 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Strength ≥ 112 bit; rencana migrasi PQC | M-KEYSIZE, M-ECDLP | Sedang | Penguji lab + test engineer |
| DS-S-08 | Integrasi | — | 5 nilai (Encoding (r, s)) | 1. Kirim (r, n−s), r/s = 0, ≥ n, DER non-kanonik 2. Catat terima/tolak 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Di luar rentang ditolak; kebijakan low-s didokumentasikan | M-SIGMAL | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-S-01 | Komponen | — | SHA3-256, SHAKE256 | 1. Hitung DDT & derajat χ 2. Ukur difusi per ronde Keccak-f 3. Bandingkan dengan acuan (DU 8, derajat 2) 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Sesuai acuan desain | M-SBOX, M-DIFFUSION | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-S-02 | Integrasi | — | 7 nilai (Pola pesan) | 1. 10 000 pasangan pesan beda 1 bit 2. Uji χ² byte keluaran 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Avalanche n/2 (σ ≈ √n/2); χ² p ≥ 0,01 | M-AVAL, M-SP80022 | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-S-03 | Integrasi | — | 4 nilai (Panjang digest) | 1. Cari collision pada digest terpotong t = 16/24/32 bit 2. Bandingkan kerja empiris dengan √(π/2·2^t) 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Kerja empiris ±20% dari prediksi; klaim penuh = min(n/2, c/2) | M-GENERIC, M-KEYSIZE | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-S-04 | Integrasi | — | BLAKE2B-512, SHA-1, SHA-256, SHA-384 | 1. Untuk SHA-2: tunjukkan length-extension pada H(k ∥ m) 2. Pastikan produk memakai HMAC untuk autentikasi 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada konstruksi H(k ∥ m) pada produk | M-PAD | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-S-05 | Integrasi | — | SHA3-256, SHAKE256 | 1. Bandingkan serangan literatur (collision 5/24 ronde) dengan jumlah ronde 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Margin ≥ 20% | M-DIFF | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-S-06 | Sistem | — | BLAKE2B-512, SHA-1, SHA-256, SHA-384 | 1. Hitung strength klasik & kuantum (Grover: preimage 2^(n/2)) 2. Bandingkan dengan umur data produk 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Strength ≥ 112 bit (klasik) untuk umur data | M-KEYSIZE | Sedang | Penguji lab + test engineer |
| PK-S-01 | Komponen | — | ECDH-P384, FFDHE3072, ML-KEM-768, RSA-OAEP-2048 | 1. Hitung strength (SP 800-57) per target 2. Periksa \|p−q\|, d, kehalusan p−1 (UK-1) 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Strength ≥ 112 bit; prima kuat | M-KEYSIZE, M-PRIME, M-FACT | Sedang | Penguji lab (Cryptographic Analyst) |
| PK-S-02 | Integrasi | — | 4 nilai (Ciphertext masukan, Skema padding) | 1. Kirim kelas ciphertext invalid (y≠0, lHash salah, tanpa 0x01, c ≥ n) 2. Catat pesan galat & waktu (10^5 per kelas) 3. Uji Welch t antar kelas 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Satu jenis galat; \|t\| < 4,5 | M-ORACLE | Tinggi | Penguji lab (Cryptographic Analyst) |
| PK-S-03 | Integrasi | — | 4 nilai (Kunci publik lawan) | 1. Kirim titik di luar kurva, low-order, titik tak hingga 2. Periksa penolakan & shared secret nol 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Seluruhnya ditolak | M-PKV | Tinggi | Penguji lab (Cryptographic Analyst) |
| PK-S-04 | Integrasi | — | RSA-OAEP-2048, RSA-OAEP-3072, RSAES-PKCS1-V1_5-1024 | 1. Bangkitkan ≥ 1000 kunci RSA 2. Batch-GCD seluruh modulus 3. Uji Fermat/Pollard p−1/Wiener 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | 0 faktor bersama; 0 kunci lemah | M-RSAWEAK, M-RNG | Sedang | Penguji lab (Cryptographic Analyst) |
| PK-S-05 | Integrasi | — | ML-KEM-768 | 1. 10^6 encaps/decaps 2. Ciphertext dimodifikasi → harus menghasilkan kunci pseudoacak (implicit rejection) 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Laju kegagalan ≤ klaim (2^-139 ML-KEM-512…); implicit rejection benar | M-KAT | Sedang | Penguji lab (Cryptographic Analyst) |
| PK-S-06 | Sistem | — | ECDH-P384, FFDHE3072, ML-KEM-768, RSA-OAEP-2048 | 1. Inventarisasi target rentan kuantum 2. Uji penggantian ke ML-KEM / hybrid tanpa ubah arsitektur 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Rencana migrasi sesuai IR 8547; mode hybrid berfungsi | M-KEYSIZE | Sedang | Penguji lab + test engineer |
| SC-S-01 | Komponen | — | CHACHA20-256, CHACHA20-POLY1305 | 1. Hitung NL/derajat/CI fungsi carry 2. Ukur avalanche per ronde permutasi 3. Tentukan ronde difusi penuh 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Derajat 2, NL 2; difusi penuh ≤ 4 ronde | M-BOOL, M-DIFFUSION | Sedang | Penguji lab (Cryptographic Analyst) |
| SC-S-02 | Integrasi | — | 4 nilai (Panjang keystream) | 1. Bangkitkan 100 barisan × 10^6 bit (kunci & nonce acak) 2. Jalankan 15 uji SP 800-22 3. Hitung kompleksitas linear (Berlekamp–Massey, N = 10^4) 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Proporsi ≥ ambang; P-value_T ≥ 0,0001; \|L − N/2\| ≤ 3 | M-SP80022, M-LC | Sedang | Penguji lab (Cryptographic Analyst) |
| SC-S-03 | Integrasi | — | 5 nilai (IV/nonce, Ronde inisialisasi) | 1. Balik 1 bit kunci/nonce (10 000 sampel) 2. Ukur fraksi bit berubah 3. Uji bias diferensial 3–4 ronde (analisis) 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Avalanche ≈ 0,5; distinguisher hanya pada ronde tereduksi | M-AVAL, M-ARX-PNB | Sedang | Penguji lab (Cryptographic Analyst) |
| SC-S-04 | Integrasi | — | 10 nilai (IV/nonce, Panjang keystream) | 1. Kirim 2^16 pesan, kumpulkan nonce 2. Uji pemakaian ulang nonce dengan kunci sama 3. Minta keystream > 2^32 blok 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada nonce berulang; overflow ditolak | M-NONCE | Tinggi | Penguji lab (Cryptographic Analyst) |
| SC-S-05 | Sistem | — | CHACHA20-256, CHACHA20-POLY1305 | 1. Rekam dua sesi dengan nonce sama (simulasi cacat) 2. Tunjukkan kebocoran XOR & bit-flipping tanpa MAC 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Produk mencegah kondisi; AEAD menolak modifikasi | M-NONCE | Sedang | Penguji lab + test engineer |
| SC-S-06 | Sistem | — | CHACHA20-256, CHACHA20-POLY1305 | 1. Bandingkan ruang kunci & serangan terbaik literatur (UK-1) 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Serangan terbaik ronde penuh ≥ 2^256 (brute force) | M-KEYSIZE | Sedang | Penguji lab + test engineer |
| XA-S-01 | Integrasi | — | AES-128-CTR, AES-256-GCM, AES-256-KW, XTS-AES-256 | 1. Kumpulkan keluaran DRBG produk 2. Estimasi min-entropi (SP 800-90B) & SP 800-22 3. Gagalkan sumber entropi (simulasi) dan pastikan keygen berhenti 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Min-entropi ≥ klaim; uji statistik lolos; kegagalan hulu terdeteksi | M-RNG | Tinggi | Penguji lab (Cryptographic Analyst) |
| XA-S-02 | Sistem | — | AES-128-CTR, AES-256-GCM, AES-256-KW, XTS-AES-256 | 1. Jalankan siklus lengkap untuk satu kunci tiap kelas primitif 2. Verifikasi kebijakan rotasi & batas penggunaan 3. Pastikan pemusnahan (zeroize) di akhir 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Setiap transisi sesuai kebijakan; kunci termusnahkan | M-ZEROIZE, M-KEYSIZE | Sedang | Penguji lab + test engineer |
| XA-S-03 | Sistem | — | AES-128-CTR, AES-256-GCM, AES-256-KW, XTS-AES-256 | 1. Ganti algoritma rentan kuantum ke padanan PQC (ML-KEM/ML-DSA) melalui konfigurasi 2. Uji mode hybrid 3. Pastikan arsitektur & format tidak berubah 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Penggantian berhasil tanpa perubahan arsitektur; sesuai rencana IR 8547 | M-KEYSIZE | Sedang | Penguji lab + test engineer |
| XA-S-04 | Sistem | — | AES-128-CTR, AES-256-GCM, AES-256-KW, XTS-AES-256 | 1. Pilih operasi dengan data rahasia (dekripsi RSA-OAEP, signing ECDSA, verifikasi tag AEAD) 2. Kumpulkan ≥ 10^6 pengukuran waktu dari sisi pemanggil API (remote-timing) 3. Coba pulihkan bit kunci/nonce dengan analisis statistik (gaya Brumley–Boneh) 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tidak ada informasi kunci yang dapat dipulihkan; \|t\| < 4,5 pada seluruh operasi | M-TIMING, M-CACHE | Tinggi | Penguji lab + test engineer |

### 5.3 Uji Implementasi

| ID | Tingkat | Area | Parameter & nilai uji | Prosedur | Kriteria lulus | Metode UK-1 | Prioritas | Pelaksana |
|---|---|---|---|---|---|---|---|---|
| BC-I-01 | Komponen | — | 7 nilai (Nilai kunci) | 1. Ukur waktu enkripsi fixed-vs-random key (10^6 pengukuran, dudect) 2. Lakukan Flush+Reload pada tabel bila tersedia 3. Dump memori setelah free konteks 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | \|t\| < 4,5; tidak ada sisa round key di memori | M-TIMING, M-ZEROIZE | Tinggi | Penguji lab (Cryptographic Analyst) |
| BC-I-02 | Integrasi | — | 7 nilai (Panjang pesan & padding) | 1. Kirim ciphertext dengan padding/tag rusak pada posisi berbeda 2. Ukur waktu respons & kode galat (10^5 sampel per kelas) 3. Uji Welch t antar kelas 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Galat seragam; \|t\| < 4,5 | M-TIMING | Sedang | Penguji lab (Cryptographic Analyst) |
| BC-I-03 | Integrasi | — | 7 nilai (Panjang pesan & padding) | 1. Bangkitkan 10^6 masukan malformed (panjang 0, maks+1, NULL, unaligned) 2. Jalankan di bawah ASan/UBSan 3. Catat crash/hang & kode galat 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tanpa crash/hang/sanitizer error; galat terdefinisi | M-FUZZ | Sedang | Penguji lab (Cryptographic Analyst) |
| BC-I-05 | Sistem | — | 3 nilai (Kondisi operasional) | 1. Ukur throughput 1/4/8 thread untuk tiap target 2. Jalankan 24 jam beban tinggi 3. Periksa konsistensi hasil & penggunaan memori 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Sesuai klaim kinerja; tanpa degradasi keamanan/kebocoran memori | M-SELFTEST | Sedang | Penguji lab + test engineer |
| BC-I-06 | Sistem | — | AES-128-CTR, AES-256-GCM, AES-256-KW, XTS-AES-256 | 1. Picu galat (tag salah, kunci salah, self-test gagal) 2. Periksa pesan galat & log 3. Pastikan tidak ada material kunci/plaintext di log 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Galat terdefinisi; log tanpa data rahasia | M-SELFTEST, M-ZEROIZE | Sedang | Penguji lab + test engineer |
| DS-I-01 | Komponen | — | Fixed-vs-random d dan k; 10^5 pengukuran waktu | 1. Fixed-vs-random d dan k 2. 10^5 pengukuran waktu perkalian skalar 3. Uji TVLA (Welch t) 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | \|t\| < 4,5 | M-TIMING | Tinggi | Penguji lab (Cryptographic Analyst) |
| DS-I-04 | Integrasi | — | 10^6 input DER/ASN.1 malformed | 1. Bangkitkan 10^6 input DER/ASN.1 malformed 2. Fuzzing parser 3. Catat crash/hang & galat 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tanpa crash/hang; galat seragam | M-FUZZ | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-I-01 | Komponen | — | BLAKE2B-512, SHA-1, SHA-256, SHA-384 | 1. Hash pesan 2^32 + 1 byte (streaming) 2. Bandingkan dengan referensi 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Digest benar; tanpa overflow | M-FUZZ | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-I-02 | Integrasi | — | BLAKE2B-512, SHA-1, SHA-256, SHA-384 | 1. Tag benar vs salah per posisi byte (10^5) 2. Welch t 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | \|t\| < 4,5 | M-TIMING | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-I-03 | Integrasi | — | BLAKE2B-512, SHA-1, SHA-256, SHA-384 | 1. Urutan update/final menyimpang 10^6 kali 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tanpa crash; galat terdefinisi | M-FUZZ | Sedang | Penguji lab (Cryptographic Analyst) |
| HF-I-04 | Sistem | — | BLAKE2B-512, SHA-1, SHA-256, SHA-384 | 1. Hash 10 GiB; ukur GB/s 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Sesuai klaim kinerja | M-SELFTEST | Sedang | Penguji lab + test engineer |
| HF-I-05 | Sistem | — | BLAKE2B-512, SHA-1, SHA-256, SHA-384 | 1. Rusak 1 byte berkas; verifikasi 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Kerusakan terdeteksi | M-KAT | Sedang | Penguji lab + test engineer |
| HF-I-06 | Sistem | — | HMAC-SHA-256-K128, HMAC-SHA-256-K256 | 1. Dump memori pasca-destroy 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | 0 sisa kunci | M-ZEROIZE | Sedang | Penguji lab + test engineer |
| PK-I-01 | Komponen | — | ECDH-P384, FFDHE3072, ML-KEM-768, RSA-OAEP-2048 | 1. dudect fixed-vs-random kunci privat (10^6) 2. Periksa verifikasi hasil CRT sebelum keluaran 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | \|t\| < 4,5; hasil CRT diverifikasi | M-TIMING | Tinggi | Penguji lab (Cryptographic Analyst) |
| PK-I-02 | Integrasi | — | 1 nilai (Ciphertext masukan) | 1. 10^6 ciphertext/DER kunci malformed di bawah sanitizer 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tanpa crash; galat seragam | M-FUZZ | Sedang | Penguji lab (Cryptographic Analyst) |
| PK-I-03 | Integrasi | — | ECDH-P384, FFDHE3072, ML-KEM-768, RSA-OAEP-2048 | 1. Kelas galat berbeda, 10^5 sampel 2. Welch t 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | \|t\| < 4,5 | M-ORACLE, M-TIMING | Sedang | Penguji lab (Cryptographic Analyst) |
| PK-I-04 | Sistem | — | ECDH-P384, FFDHE3072, ML-KEM-768, RSA-OAEP-2048 | 1. Ekspor/hapus kunci; dump memori 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Kunci privat tidak tersisa/terkunci sesuai kebijakan | M-ZEROIZE | Sedang | Penguji lab + test engineer |
| PK-I-05 | Sistem | — | ECDH-P384, FFDHE3072, ML-KEM-768, RSA-OAEP-2048 | 1. Ukur ops/detik decrypt/decaps 1–8 thread 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Sesuai klaim kinerja | M-SELFTEST | Sedang | Penguji lab + test engineer |
| SC-I-01 | Komponen | — | CHACHA20-256, CHACHA20-POLY1305 | 1. dudect fixed-vs-random key (10^6 pengukuran) 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | \|t\| < 4,5 | M-TIMING | Sedang | Penguji lab (Cryptographic Analyst) |
| SC-I-02 | Integrasi | — | CHACHA20-POLY1305 | 1. Tag benar vs salah pada posisi byte berbeda (10^5 sampel) 2. Welch t 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | \|t\| < 4,5 | M-TIMING | Sedang | Penguji lab (Cryptographic Analyst) |
| SC-I-03 | Integrasi | — | CHACHA20-256, CHACHA20-POLY1305 | 1. 10^6 masukan malformed di bawah sanitizer 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Tanpa crash/hang | M-FUZZ | Sedang | Penguji lab (Cryptographic Analyst) |
| SC-I-04 | Sistem | — | CHACHA20-256, CHACHA20-POLY1305 | 1. Dump memori pasca-destroy 2. Cari pola kunci uji 3. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | 0 kemunculan | M-ZEROIZE | Sedang | Penguji lab + test engineer |
| SC-I-05 | Sistem | — | CHACHA20-256, CHACHA20-POLY1305 | 1. Ukur MB/s 1–8 thread 2. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Sesuai klaim kinerja | M-SELFTEST | Sedang | Penguji lab + test engineer |
| XA-I-01 | Sistem | — | 15 nilai (Kondisi operasional) | 1. Hentikan proses saat operasi kunci 2. Restart & jalankan ulang self-test 3. Uji di bawah beban tinggi 4. Catat hasil per nilai parameter, bandingkan dengan expected value & kriteria lulus, lalu tetapkan kategori hasil (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif) | Sifat keamanan tidak menurun; tidak ada keluaran parsial | M-SELFTEST | Sedang | Penguji lab + test engineer |

**Narasi empiris (contoh):**

- **BC-K-01** — Penguji melakukan verifikasi S-box, permutasi, key schedule & nilai antara per ronde pada AES-128-CTR, AES-256-GCM, AES-256-KW, XTS-AES-256, CMAC-AES-128 dengan 4 nilai parameter uji. Uji dinyatakan Memenuhi bila: Seluruh nilai antara & round key identik 100%.
- **BC-K-02** — Penguji melakukan kAT per algoritma × mode × panjang kunci pada AES-128-CTR, AES-256-GCM, AES-256-KW, XTS-AES-256, PRESENT-80, TDEA-3KEY dan 2 objek lain dengan 12 nilai parameter uji. Uji dinyatakan Memenuhi bila: Ciphertext/tag/plaintext identik 100% dengan vektor resmi; vektor invalid ditolak.
- **BC-K-03** — Penguji melakukan monte Carlo Test & Multi-block Message Test pada AES-128-CTR, AES-256-GCM, AES-256-KW, XTS-AES-256, PRESENT-80, TDEA-3KEY dan 2 objek lain dengan 15 nilai parameter uji. Uji dinyatakan Memenuhi bila: 100% checkpoint identik.
- **BC-K-04** — Penguji melakukan round-trip D(E(x)) = x pada nilai batas panjang pesan pada AES-128-CTR, AES-256-GCM, AES-256-KW, XTS-AES-256, PRESENT-80, TDEA-3KEY dan 2 objek lain dengan 14 nilai parameter uji. Uji dinyatakan Memenuhi bila: D(E(x)) = x untuk 100% kasus.
- **BC-K-05** — Penguji melakukan penolakan parameter di luar spesifikasi (negative test) pada AES-128-CTR, AES-256-GCM, AES-256-KW, XTS-AES-256, PRESENT-80, TDEA-3KEY dan 2 objek lain dengan 17 nilai parameter uji. Uji dinyatakan Memenuhi bila: Seluruh parameter di luar spesifikasi ditolak dengan galat terdefinisi. Seluruh masukan pada uji ini bersifat negatif, sehingga hasil yang benar adalah PENOLAKAN.
- **BC-K-06** — Penguji melakukan interoperabilitas format ciphertext dengan implementasi referensi pada AES-128-CTR, AES-256-GCM, AES-256-KW, XTS-AES-256, PRESENT-80, TDEA-3KEY dan 2 objek lain dengan 8 nilai parameter uji. Uji dinyatakan Memenuhi bila: Interoperabel dua arah 100%.
- **DS-K-01** — Penguji melakukan aritmetika kurva pada titik khusus pada ECDSA-P256, ECDSA-P384. Uji dinyatakan Memenuhi bila: Hasil identik 100%; n·G = O.
- **DS-K-02** — Penguji melakukan sHA-256: Short/Long Message & Monte Carlo Test pada SHA-1, SHA-256, SHA-384, SHA-512/256 dengan 9 nilai parameter uji. Uji dinyatakan Memenuhi bila: Digest identik 100%.

## 6. Expected Value & Kriteria Keputusan (KUK 2.4)

Kriteria keputusan materi: **Deterministik**: KAT/MCT cocok 100%; vektor invalid seluruhnya ditolak.; **Statistik**: α = 0,01; proporsi lolos dalam interval kepercayaan; p-value terdistribusi seragam.; **Kriptanalitik**: Kompleksitas serangan terbaik ≥ klaim tingkat keamanan (bit security).; **Implementasi**: Tidak ada kebocoran terukur (mis. TVLA |t| < 4,5) dan galat seragam.

| Berkas expected | Target | Jenis | Status | Cocok/total | SHA-256 |
|---|---|---|---|---|---|
| curve_points__ECDSA-P256 | ECDSA-P256 | deterministic | COCOK_VEKTOR_RESMI | 4/4 | c630bf4399771847… |
| domain_params__ECDSA-P256 | ECDSA-P256 | deterministic | COCOK_VEKTOR_RESMI | 2/2 | e303e371ae4d4950… |
| hash_boundaries__BLAKE2B-512 | BLAKE2B-512 | deterministic | COCOK_VEKTOR_RESMI | 13/13 | 0e25ac774a3ddfa1… |
| hash_boundaries__SHA-1 | SHA-1 | deterministic | COCOK_VEKTOR_RESMI | 8/8 | 544db293d925c1de… |
| hash_boundaries__SHA-256 | SHA-256 | deterministic | COCOK_VEKTOR_RESMI | 9/9 | 0d9fbf5706c154ea… |
| hash_boundaries__SHA-384 | SHA-384 | deterministic | COCOK_VEKTOR_RESMI | 14/14 | f1c022d02827c04b… |
| hash_boundaries__SHA-512_256 | SHA-512/256 | deterministic | COCOK_VEKTOR_RESMI | 14/14 | 8274b7b778dea48f… |
| hash_boundaries__SHA3-256 | SHA3-256 | deterministic | COCOK_VEKTOR_RESMI | 16/16 | defd9434dc037be3… |
| hash_boundaries__SHAKE256 | SHAKE256 | deterministic | COCOK_VEKTOR_RESMI | 13/13 | d372a99363a793a2… |
| kat__AES-128-CTR | AES-128-CTR | deterministic | COCOK_VEKTOR_RESMI | 7/7 | 3d743d956ce882c6… |
| kat__AES-256-GCM | AES-256-GCM | deterministic | COCOK_VEKTOR_RESMI | 66/66 | 0f59a33f04b0a9e0… |
| kat__AES-256-KW | AES-256-KW | deterministic | COCOK_VEKTOR_RESMI | 68/68 | 48a4be6bfba21e8d… |
| kat__CHACHA20-256 | CHACHA20-256 | deterministic | COCOK_VEKTOR_RESMI | 3/3 | 809f2c2c9c9bd28f… |
| kat__CHACHA20-POLY1305 | CHACHA20-POLY1305 | deterministic | COCOK_VEKTOR_RESMI | 316/316 | b40874a805fcc063… |
| kat__CMAC-AES-128 | CMAC-AES-128 | deterministic | COCOK_VEKTOR_RESMI | 102/102 | 58712a70a704e00f… |
| kat__ECDH-P384 | ECDH-P384 | deterministic | COCOK_VEKTOR_RESMI | 1047/1047 | 3bfdb1e13c460060… |
| kat__ED25519 | ED25519 | deterministic | COCOK_VEKTOR_RESMI | 151/151 | fc38470cf283c6f9… |
| kat__HMAC-SHA-256-K128 | HMAC-SHA-256-K128 | deterministic | COCOK_VEKTOR_RESMI | 3/3 | 4b866969d8950ef3… |
| kat__HMAC-SHA-256-K256 | HMAC-SHA-256-K256 | deterministic | COCOK_VEKTOR_RESMI | 81/81 | 1d47b843c727cea5… |
| kat__RSA-OAEP-2048 | RSA-OAEP-2048 | deterministic | COCOK_VEKTOR_RESMI | 49/49 | 98f6fb1b1a73af13… |
| kat__RSA-OAEP-3072 | RSA-OAEP-3072 | deterministic | COCOK_VEKTOR_RESMI | 37/37 | 7265d044276aead3… |
| kat__X25519 | X25519 | deterministic | COCOK_VEKTOR_RESMI | 518/518 | b2e8dc378d852a7d… |
| rfc6979__ECDSA-P256 | ECDSA-P256 | deterministic | COCOK_VEKTOR_RESMI | 4/4 | 1b343225ff5109f2… |
| rfc6979__ECDSA-P384 | ECDSA-P384 | deterministic | COCOK_VEKTOR_RESMI | 4/4 | 7fdb67c736ef8c90… |
| sigver__ECDSA-P256 | ECDSA-P256 | deterministic | COCOK_VEKTOR_RESMI | 516/516 | c331a7418794f46d… |
| curve_points__ECDSA-P384 | ECDSA-P384 | deterministic | PERLU_VERIFIKASI | — | 83c50eef835c9c1c… |
| domain_params__ECDSA-P384 | ECDSA-P384 | deterministic | PERLU_VERIFIKASI | — | f375ffa0b05ed27c… |
| interop__AES-128-CTR | AES-128-CTR | deterministic | KRITERIA | — | 8bbe9a1dd1ab8bcd… |
| interop__AES-256-GCM | AES-256-GCM | deterministic | KRITERIA | — | c3fd2e9032182df7… |
| interop__AES-256-KW | AES-256-KW | deterministic | KRITERIA | — | 6eff993a6c53e742… |
| interop__ASCON-AEAD128 | ASCON-AEAD128 | deterministic | KRITERIA | — | 1fb82808f12f36ac… |
| interop__BLAKE2B-512 | BLAKE2B-512 | deterministic | KRITERIA | — | b63c4650023015f8… |
| interop__CHACHA20-256 | CHACHA20-256 | deterministic | KRITERIA | — | 054e751a40f0d48f… |
| interop__CHACHA20-POLY1305 | CHACHA20-POLY1305 | deterministic | KRITERIA | — | 5ddae08d4b537842… |
| interop__CMAC-AES-128 | CMAC-AES-128 | deterministic | KRITERIA | — | d052cb67251760f6… |
| interop__CTR-DRBG-AES-256 | CTR-DRBG-AES-256 | deterministic | KRITERIA | — | 73d50793fd23436e… |
| interop__ECDH-P384 | ECDH-P384 | deterministic | KRITERIA | — | f77fc68abcf96e77… |
| interop__ECDSA-P256 | ECDSA-P256 | deterministic | KRITERIA | — | fcaadd1b30e48dba… |
| interop__ECDSA-P384 | ECDSA-P384 | deterministic | KRITERIA | — | b69dd3a4b9d29cf3… |
| interop__ED25519 | ED25519 | deterministic | KRITERIA | — | 3513fbebb7d26dc8… |
| interop__FFDHE3072 | FFDHE3072 | deterministic | KRITERIA | — | 635a4b705a124e7c… |
| interop__HMAC-SHA-256-K128 | HMAC-SHA-256-K128 | deterministic | KRITERIA | — | 5105bad5c4d3dd3f… |
| interop__HMAC-SHA-256-K256 | HMAC-SHA-256-K256 | deterministic | KRITERIA | — | de81c56a27b1e18e… |
| interop__ML-DSA-65 | ML-DSA-65 | deterministic | KRITERIA | — | a4c671c11f0cd71a… |
| interop__ML-KEM-768 | ML-KEM-768 | deterministic | KRITERIA | — | 7b20edd23004b0e1… |
| interop__PRESENT-80 | PRESENT-80 | deterministic | KRITERIA | — | 28430839e4828dbb… |
| interop__RSA-OAEP-2048 | RSA-OAEP-2048 | deterministic | KRITERIA | — | 31ddb1a864e3b4f3… |
| interop__RSA-OAEP-3072 | RSA-OAEP-3072 | deterministic | KRITERIA | — | 7d91d90f7601942b… |
| interop__RSA-PSS-3072 | RSA-PSS-3072 | deterministic | KRITERIA | — | 39d62bfc79ad1a0e… |
| interop__RSAES-PKCS1-V1_5-1024 | RSAES-PKCS1-V1_5-1024 | deterministic | KRITERIA | — | fed15dba7517f114… |
| interop__SHA-1 | SHA-1 | deterministic | KRITERIA | — | 64b32c674a6b7946… |
| interop__SHA-256 | SHA-256 | deterministic | KRITERIA | — | 7201df6e641b2a4f… |
| interop__SHA-384 | SHA-384 | deterministic | KRITERIA | — | 65563f7481293e7a… |
| interop__SHA-512_256 | SHA-512/256 | deterministic | KRITERIA | — | 292f1041299f25b9… |
| interop__SHA3-256 | SHA3-256 | deterministic | KRITERIA | — | 6ef15dab85c09669… |
| interop__SHAKE256 | SHAKE256 | deterministic | KRITERIA | — | 6eec26c4f4fd9830… |
| interop__SLH-DSA-SHA2-128S | SLH-DSA-SHA2-128S | deterministic | KRITERIA | — | ba0dc1d75beab4a5… |
| interop__TDEA-3KEY | TDEA-3KEY | deterministic | KRITERIA | — | f92b09bfb1d0d472… |
| interop__X25519 | X25519 | deterministic | KRITERIA | — | 63564c0a3c90999a… |
| interop__XTS-AES-256 | XTS-AES-256 | deterministic | KRITERIA | — | 34f88aa2ee19f470… |
| kat__ASCON-AEAD128 | ASCON-AEAD128 | deterministic | PERLU_VERIFIKASI | — | b4aec655b41f4f0f… |
| kat__FFDHE3072 | FFDHE3072 | deterministic | PERLU_VERIFIKASI | — | d92594517e9a129a… |
| kat__ML-DSA-65 | ML-DSA-65 | deterministic | PERLU_VERIFIKASI | — | 6e23bbd13f57f036… |
| kat__ML-KEM-768 | ML-KEM-768 | deterministic | PERLU_VERIFIKASI | — | e9164ebaad954160… |
| kat__PRESENT-80 | PRESENT-80 | deterministic | PERLU_VERIFIKASI | — | 9d773c4c57dcab23… |
| kat__RSA-PSS-3072 | RSA-PSS-3072 | deterministic | PERLU_VERIFIKASI | — | eb8ac8913dcb8e75… |
| kat__RSAES-PKCS1-V1_5-1024 | RSAES-PKCS1-V1_5-1024 | deterministic | PERLU_VERIFIKASI | — | a8df90259f7eaaf5… |
| kat__SLH-DSA-SHA2-128S | SLH-DSA-SHA2-128S | deterministic | PERLU_VERIFIKASI | — | b9897724352acd34… |
| kat__TDEA-3KEY | TDEA-3KEY | deterministic | PERLU_VERIFIKASI | — | 780eb3abddbc05c8… |
| kat__XTS-AES-256 | XTS-AES-256 | deterministic | PERLU_VERIFIKASI | — | 65abad93e93a9dd6… |
| keygen_validate__ECDH-P384 | ECDH-P384 | deterministic | KRITERIA | — | 592ce0b4c7c6918b… |
| keygen_validate__ECDSA-P256 | ECDSA-P256 | deterministic | KRITERIA | — | a58409404cdbd688… |
| keygen_validate__ECDSA-P384 | ECDSA-P384 | deterministic | KRITERIA | — | 93cb4069f6cda862… |
| keygen_validate__FFDHE3072 | FFDHE3072 | deterministic | KRITERIA | — | 2ac106096ff92687… |
| keygen_validate__ML-KEM-768 | ML-KEM-768 | deterministic | KRITERIA | — | f31246f1be140cf4… |
| keygen_validate__RSA-OAEP-2048 | RSA-OAEP-2048 | deterministic | KRITERIA | — | c07f85842fc43cdd… |
| keygen_validate__RSA-OAEP-3072 | RSA-OAEP-3072 | deterministic | KRITERIA | — | 9467999ab8f1d2f6… |
| keygen_validate__RSAES-PKCS1-V1_5-1024 | RSAES-PKCS1-V1_5-1024 | deterministic | KRITERIA | — | 3adeeee94f0427de… |
| keygen_validate__X25519 | X25519 | deterministic | KRITERIA | — | 20cf29f9f9a1eee2… |
| mct__AES-128-CTR | AES-128-CTR | deterministic | KRITERIA | — | aa659d2a79441b29… |
| mct__AES-256-GCM | AES-256-GCM | deterministic | KRITERIA | — | 5909577e4030f3b3… |
| mct__AES-256-KW | AES-256-KW | deterministic | KRITERIA | — | 2cb481bed5951d09… |
| mct__ASCON-AEAD128 | ASCON-AEAD128 | deterministic | KRITERIA | — | c964919cd4f8010a… |
| mct__BLAKE2B-512 | BLAKE2B-512 | deterministic | KRITERIA | — | 9086f2cccaa99af0… |
| mct__CMAC-AES-128 | CMAC-AES-128 | deterministic | KRITERIA | — | fc3f5e273dada56f… |
| mct__PRESENT-80 | PRESENT-80 | deterministic | KRITERIA | — | 84b6012b5dbf7544… |
| mct__SHA-1 | SHA-1 | deterministic | KRITERIA | — | d69ffe9cad08f642… |
| mct__SHA-256 | SHA-256 | deterministic | KRITERIA | — | 6bd284dc3043d86a… |
| mct__SHA-384 | SHA-384 | deterministic | KRITERIA | — | 5646a3d56f444350… |
| mct__SHA-512_256 | SHA-512/256 | deterministic | KRITERIA | — | 5ac3f7c21237763e… |
| mct__SHA3-256 | SHA3-256 | deterministic | KRITERIA | — | e181093e263e1dee… |
| mct__SHAKE256 | SHAKE256 | deterministic | KRITERIA | — | 0027c59f3e88f925… |
| mct__TDEA-3KEY | TDEA-3KEY | deterministic | KRITERIA | — | 8b1bca6550383d17… |
| mct__XTS-AES-256 | XTS-AES-256 | deterministic | KRITERIA | — | 3880940fc999f3c2… |
| nonce_reuse__AES-128-CTR | AES-128-CTR | negative | KRITERIA | — | 4b2ad92f9ab0e522… |
| nonce_reuse__AES-256-GCM | AES-256-GCM | negative | KRITERIA | — | aacf7248f558d335… |
| nonce_reuse__CHACHA20-256 | CHACHA20-256 | negative | KRITERIA | — | 65c56eaa6aa53339… |
| nonce_reuse__CHACHA20-POLY1305 | CHACHA20-POLY1305 | negative | KRITERIA | — | 96061efb3a2d663b… |
| performance__AES-128-CTR | AES-128-CTR | implementation | PERLU_VERIFIKASI | — | 1fad30a63de48f03… |
| performance__AES-256-GCM | AES-256-GCM | implementation | PERLU_VERIFIKASI | — | 599fba162a789cb4… |
| performance__AES-256-KW | AES-256-KW | implementation | PERLU_VERIFIKASI | — | 136df3fab6081419… |
| performance__ASCON-AEAD128 | ASCON-AEAD128 | implementation | PERLU_VERIFIKASI | — | 2cfe2cab23a985b5… |
| performance__BLAKE2B-512 | BLAKE2B-512 | implementation | PERLU_VERIFIKASI | — | 45ffd0137d6be284… |
| performance__CHACHA20-256 | CHACHA20-256 | implementation | PERLU_VERIFIKASI | — | 1d0364df654b1925… |
| performance__CHACHA20-POLY1305 | CHACHA20-POLY1305 | implementation | PERLU_VERIFIKASI | — | 880c61a2bbf10ad7… |
| performance__CMAC-AES-128 | CMAC-AES-128 | implementation | PERLU_VERIFIKASI | — | ef4a172fb7b869ab… |
| performance__ECDH-P384 | ECDH-P384 | implementation | PERLU_VERIFIKASI | — | 4fbf96720fd01858… |
| performance__FFDHE3072 | FFDHE3072 | implementation | PERLU_VERIFIKASI | — | ac49bdb3abe597b2… |
| performance__HMAC-SHA-256-K128 | HMAC-SHA-256-K128 | implementation | PERLU_VERIFIKASI | — | f04dc9016eedf6c7… |
| performance__HMAC-SHA-256-K256 | HMAC-SHA-256-K256 | implementation | PERLU_VERIFIKASI | — | 709a6dfa6b2b25d8… |
| performance__ML-KEM-768 | ML-KEM-768 | implementation | PERLU_VERIFIKASI | — | b8a90ca8ab88c2d7… |
| performance__PRESENT-80 | PRESENT-80 | implementation | PERLU_VERIFIKASI | — | 73dc85c2a31d3426… |
| performance__RSA-OAEP-2048 | RSA-OAEP-2048 | implementation | PERLU_VERIFIKASI | — | 9c214e37545321bd… |
| performance__RSA-OAEP-3072 | RSA-OAEP-3072 | implementation | PERLU_VERIFIKASI | — | 8eccd6bffb37e0ee… |
| performance__RSAES-PKCS1-V1_5-1024 | RSAES-PKCS1-V1_5-1024 | implementation | PERLU_VERIFIKASI | — | 74203a4cea6e1786… |
| performance__SHA-1 | SHA-1 | implementation | PERLU_VERIFIKASI | — | 9169b229a8dac86c… |
| performance__SHA-256 | SHA-256 | implementation | PERLU_VERIFIKASI | — | 14f4736f3ae751b1… |
| performance__SHA-384 | SHA-384 | implementation | PERLU_VERIFIKASI | — | 611388767cc80827… |
| performance__SHA-512_256 | SHA-512/256 | implementation | PERLU_VERIFIKASI | — | 9d3b35d7e6f19770… |
| performance__SHA3-256 | SHA3-256 | implementation | PERLU_VERIFIKASI | — | 293488ebc798f7fa… |

## 7. Pemetaan Parameter → Kemungkinan Hasil Uji (KUK 2.5)

Kategori hasil: **Memenuhi** — Seluruh kriteria terpenuhi pada semua variasi parameter yang ditetapkan.; **Memenuhi dengan Catatan** — Lulus, tetapi terdapat batasan penggunaan (mis. batas data per kunci, parameter minimum).; **Tidak Memenuhi** — Minimal satu kriteria gagal; parameter pemicu kegagalan diidentifikasi.; **Inkonklusif** — Bukti statistik belum cukup; diperlukan sampel lebih besar atau uji lanjutan.

| Kondisi temuan | Parameter pemicu | Kemungkinan hasil | Tindak lanjut | Sumber |
|---|---|---|---|---|
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
| PRESENT-80 strength 80 bit < 112 | ukuran kunci | Tidak Memenuhi | Ganti ke varian ≥ 128 bit | algorithms_under_test |
| TDEA-3KEY dipakai untuk layanan approved | status NIST disallowed | Tidak Memenuhi | Batasi ke dekripsi/verifikasi legacy; Memenuhi dengan Catatan bila hanya legacy use | algorithms_under_test |
| SHA-1 dipakai untuk layanan approved | status NIST disallowed | Tidak Memenuhi | Batasi ke dekripsi/verifikasi legacy; Memenuhi dengan Catatan bila hanya legacy use | algorithms_under_test |
| RSA-OAEP-2048 (112 bit) rentan kuantum | ukuran kunci/domain | Memenuhi dengan Catatan | Diterima hingga 2030 (IR 8547); migrasi ke ML-KEM/ML-DSA | algorithms_under_test |
| RSAES-PKCS1-V1_5-1024 dipakai untuk layanan approved | status NIST disallowed | Tidak Memenuhi | Batasi ke dekripsi/verifikasi legacy; Memenuhi dengan Catatan bila hanya legacy use | algorithms_under_test |

## 8. Matriks Keterlacakan

| Kebutuhan | Uraian | Metode UK-1 | Skenario | Test case | Area | Standar |
|---|---|---|---|---|---|---|
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-BC-KOM-K | BC-K-01 | — | FIPS-197, ISO-18367 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-BC-KOM-K | BC-K-01 | — | FIPS-197, ISO-18367 |
| AES-128:K-09 | Komponen nonlinear memenuhi batas acuan NL/DU/derajat | M-SBOX | SCN-BC-KOM-K | BC-K-01 | — | FIPS-197, ISO-18367 |
| SHA3-256:K-05 | Komponen nonlinear memenuhi batas acuan NL/DU/derajat | M-SBOX | SCN-BC-KOM-K | BC-K-01 | — | FIPS-197, ISO-18367 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-BC-INT-K | BC-K-02 | — | FIPS-197, SP-800-38A, SP-800-38D, ISO-18367 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-BC-INT-K | BC-K-02 | — | FIPS-197, SP-800-38A, SP-800-38D, ISO-18367 |
| AES-128:I-03 | Implementasi konsisten pada iterasi berantai & pesan multi-blok | M-MCT | SCN-BC-INT-K | BC-K-03 | — | ISO-18367 |
| SHA3-256:I-03 | Implementasi konsisten pada iterasi berantai & pesan multi-blok | M-MCT | SCN-BC-INT-K | BC-K-03 | — | ISO-18367 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-BC-INT-K | BC-K-04 | — | SP-800-38A, ISO-29119 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-BC-INT-K | BC-K-04 | — | SP-800-38A, ISO-29119 |
| AES-128:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-BC-INT-K | BC-K-04 | — | SP-800-38A, ISO-29119 |
| ChaCha20:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-BC-INT-K | BC-K-04 | — | SP-800-38A, ISO-29119 |
| AES-128:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-BC-INT-K | BC-K-05 | — | ISO-29119, ISO-19790 |
| ChaCha20:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-BC-INT-K | BC-K-05 | — | ISO-29119, ISO-19790 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-BC-SIS-K | BC-K-06 | — | ISO-18367 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-BC-SIS-K | BC-K-06 | — | ISO-18367 |
| ECDSA-P256:I-01 | Parameter domain identik dengan SP 800-186 & lolos uji validitas | M-CURVE | SCN-DS-KOM-K | DS-K-01 | — | FIPS-186-5, SP-800-186 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-DS-KOM-K | DS-K-01 | — | FIPS-186-5, SP-800-186 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-DS-KOM-K | DS-K-01 | — | FIPS-186-5, SP-800-186 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-DS-KOM-K | DS-K-02 | — | FIPS-180-4 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-DS-KOM-K | DS-K-02 | — | FIPS-180-4 |
| RSA-OAEP-2048:I-04 | Produk menolak kunci publik/titik tidak valid | M-PKV | SCN-DS-INT-K | DS-K-03 | — | FIPS-186-5, SP-800-186 |
| ECDSA-P256:I-04 | Produk menolak kunci publik/titik tidak valid | M-PKV | SCN-DS-INT-K | DS-K-03 | — | FIPS-186-5, SP-800-186 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-DS-INT-K | DS-K-04 | — | RFC-6979, FIPS-186-5 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-DS-INT-K | DS-K-04 | — | RFC-6979, FIPS-186-5 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-DS-INT-K | DS-K-05 | — | FIPS-186-5, ISO-14888-3 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-DS-INT-K | DS-K-05 | — | FIPS-186-5, ISO-14888-3 |
| ECDSA-P256:I-06 | Verifikasi menolak r,s ∉ [1, n−1]; kebijakan low-S terdokumentasi | M-SIGMAL | SCN-DS-INT-K | DS-K-05 | — | FIPS-186-5, ISO-14888-3 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-DS-SIS-K | DS-K-07 | — | ISO-18367 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-DS-SIS-K | DS-K-07 | — | ISO-18367 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-DS-INT-K | DS-K-08 | — | FIPS-186-5, FIPS-204, FIPS-205 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-DS-INT-K | DS-K-08 | — | FIPS-186-5, FIPS-204, FIPS-205 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-HF-KOM-K | HF-K-01 | — | FIPS-202, FIPS-180-4, ISO-10118-3 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-HF-KOM-K | HF-K-01 | — | FIPS-202, FIPS-180-4, ISO-10118-3 |
| SHA3-256:I-04 | Padding benar untuk panjang r−2, r−1, r, r+1 byte | M-PAD | SCN-HF-KOM-K | HF-K-01 | — | FIPS-202, FIPS-180-4, ISO-10118-3 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-HF-INT-K | HF-K-02 | — | FIPS-202, FIPS-180-4 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-HF-INT-K | HF-K-02 | — | FIPS-202, FIPS-180-4 |
| SHA3-256:I-04 | Padding benar untuk panjang r−2, r−1, r, r+1 byte | M-PAD | SCN-HF-INT-K | HF-K-02 | — | FIPS-202, FIPS-180-4 |
| AES-128:I-03 | Implementasi konsisten pada iterasi berantai & pesan multi-blok | M-MCT | SCN-HF-INT-K | HF-K-03 | — | ISO-18367 |
| SHA3-256:I-03 | Implementasi konsisten pada iterasi berantai & pesan multi-blok | M-MCT | SCN-HF-INT-K | HF-K-03 | — | ISO-18367 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-HF-INT-K | HF-K-04 | — | FIPS-202 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-HF-INT-K | HF-K-04 | — | FIPS-202 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-HF-INT-K | HF-K-05 | — | SP-800-107, FIPS-202 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-HF-INT-K | HF-K-05 | — | SP-800-107, FIPS-202 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-HF-SIS-K | HF-K-06 | — | ISO-18367 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-HF-SIS-K | HF-K-06 | — | ISO-18367 |
| RSA-OAEP-2048:K-03 | p, q prima kuat; \|p−q\| > 2^(nlen/2−100); d > 2^(nlen/2); e ∈ (2^16, 2^256) | M-PRIME | SCN-PK-KOM-K | PK-K-01 | — | ISO-18032, FIPS-186-5 |
| ECDSA-P256:I-01 | Parameter domain identik dengan SP 800-186 & lolos uji validitas | M-CURVE | SCN-PK-KOM-K | PK-K-01 | — | ISO-18032, FIPS-186-5 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-PK-KOM-K | PK-K-01 | — | ISO-18032, FIPS-186-5 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-PK-KOM-K | PK-K-01 | — | ISO-18032, FIPS-186-5 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-PK-INT-K | PK-K-02 | — | RFC-8017, ISO-18033-2, SP-800-56B |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-PK-INT-K | PK-K-02 | — | RFC-8017, ISO-18033-2, SP-800-56B |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-PK-INT-K | PK-K-03 | — | RFC-8017 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-PK-INT-K | PK-K-03 | — | RFC-8017 |
| RSA-OAEP-2048:K-03 | p, q prima kuat; \|p−q\| > 2^(nlen/2−100); d > 2^(nlen/2); e ∈ (2^16, 2^256) | M-PRIME | SCN-PK-INT-K | PK-K-04 | — | FIPS-186-5 |
| RSA-OAEP-2048:I-04 | Produk menolak kunci publik/titik tidak valid | M-PKV | SCN-PK-INT-K | PK-K-05 | — | SP-800-56B, SP-800-131A |
| ECDSA-P256:I-04 | Produk menolak kunci publik/titik tidak valid | M-PKV | SCN-PK-INT-K | PK-K-05 | — | SP-800-56B, SP-800-131A |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-PK-SIS-K | PK-K-06 | — | ISO-18367 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-PK-SIS-K | PK-K-06 | — | ISO-18367 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-SC-KOM-K | SC-K-01 | — | RFC-8439, ISO-18367 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-SC-KOM-K | SC-K-01 | — | RFC-8439, ISO-18367 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-SC-INT-K | SC-K-02 | — | RFC-8439, ISO-18367 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-SC-INT-K | SC-K-02 | — | RFC-8439, ISO-18367 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-SC-INT-K | SC-K-03 | — | RFC-8439 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-SC-INT-K | SC-K-03 | — | RFC-8439 |
| AES-128:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-SC-INT-K | SC-K-04 | — | ISO-29119 |
| ChaCha20:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-SC-INT-K | SC-K-04 | — | ISO-29119 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-SC-INT-K | SC-K-05 | — | RFC-8439 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-SC-INT-K | SC-K-05 | — | RFC-8439 |
| C-AEAD | AEAD (AES-GCM, ChaCha20-Poly1305): kerahasiaan IND-CPA + integritas INT-CTXT bila nonce unik | M-KAT | SCN-SC-INT-K | SC-K-05 | — | RFC-8439 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-SC-SIS-K | SC-K-06 | — | ISO-18367 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-SC-SIS-K | SC-K-06 | — | ISO-18367 |
| AES-128:K-09 | Komponen nonlinear memenuhi batas acuan NL/DU/derajat | M-SBOX | SCN-BC-KOM-S | BC-S-01 | — | FIPS-197, ISO-18033-3 |
| SHA3-256:K-05 | Komponen nonlinear memenuhi batas acuan NL/DU/derajat | M-SBOX | SCN-BC-KOM-S | BC-S-01 | — | FIPS-197, ISO-18033-3 |
| C-STRENGTH | Tingkat keamanan ≥ 112 bit untuk seluruh algoritma approved (SP 800-57) | M-SBOX | SCN-BC-KOM-S | BC-S-01 | — | FIPS-197, ISO-18033-3 |
| AES-128:K-01 | Perubahan 1 bit masukan/kunci mengubah ≈ 50% bit keluaran | M-AVAL | SCN-BC-INT-S | BC-S-02 | — | SP-800-22 |
| ChaCha20:K-01 | Perubahan 1 bit masukan/kunci mengubah ≈ 50% bit keluaran | M-AVAL | SCN-BC-INT-S | BC-S-02 | — | SP-800-22 |
| AES-128:K-10 | Keluaran (keystream/CTR/digest berantai) tak terbedakan dari acak | M-SP80022 | SCN-BC-INT-S | BC-S-02 | — | SP-800-22 |
| ChaCha20:K-08 | Keluaran (keystream/CTR/digest berantai) tak terbedakan dari acak | M-SP80022 | SCN-BC-INT-S | BC-S-02 | — | SP-800-22 |
| AES-128:K-07 | Nonce tidak pernah berulang dan tidak bias | M-NONCE | SCN-BC-INT-S | BC-S-03 | — | SP-800-38A, SP-800-38D |
| ChaCha20:K-06 | Nonce tidak pernah berulang dan tidak bias | M-NONCE | SCN-BC-INT-S | BC-S-03 | — | SP-800-38A, SP-800-38D |
| C-AEAD | AEAD (AES-GCM, ChaCha20-Poly1305): kerahasiaan IND-CPA + integritas INT-CTXT bila nonce unik | M-NONCE | SCN-BC-INT-S | BC-S-03 | — | SP-800-38A, SP-800-38D |
| C-AEAD | AEAD (AES-GCM, ChaCha20-Poly1305): kerahasiaan IND-CPA + integritas INT-CTXT bila nonce unik | M-NONCE | SCN-BC-INT-S | BC-S-03 | — | SP-800-38A, SP-800-38D |
| AES-128:K-02 | Tidak ada karakteristik diferensial ronde penuh dengan probabilitas > 2^-k | M-DIFF | SCN-BC-INT-S | BC-S-04 | — | ISO-15408 |
| SHA3-256:K-02 | Tidak ada karakteristik diferensial ronde penuh dengan probabilitas > 2^-k | M-DIFF | SCN-BC-INT-S | BC-S-04 | — | ISO-15408 |
| AES-128:K-06 | Tidak ada aproksimasi linear ronde penuh dengan korelasi > 2^-64 | M-LIN | SCN-BC-INT-S | BC-S-04 | — | ISO-15408 |
| AES-128:K-04 | Margin keamanan ronde memadai terhadap serangan struktural | M-INT | SCN-BC-INT-S | BC-S-04 | — | ISO-15408 |
| C-STRENGTH | Tingkat keamanan ≥ 112 bit untuk seluruh algoritma approved (SP 800-57) | M-DIFF | SCN-BC-INT-S | BC-S-04 | — | ISO-15408 |
| AES-128:K-05 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-BC-SIS-S | BC-S-05 | — | SP-800-38D, SP-800-57 |
| ChaCha20:K-04 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-BC-SIS-S | BC-S-05 | — | SP-800-38D, SP-800-57 |
| C-STRENGTH | Tingkat keamanan ≥ 112 bit untuk seluruh algoritma approved (SP 800-57) | M-KEYSIZE | SCN-BC-SIS-S | BC-S-05 | — | SP-800-38D, SP-800-57 |
| AES-128:K-05 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-BC-SIS-S | BC-S-06 | — | SP-800-57, SP-800-131A |
| ChaCha20:K-04 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-BC-SIS-S | BC-S-06 | — | SP-800-57, SP-800-131A |
| C-STRENGTH | Tingkat keamanan ≥ 112 bit untuk seluruh algoritma approved (SP 800-57) | M-KEYSIZE | SCN-BC-SIS-S | BC-S-06 | — | SP-800-57, SP-800-131A |
| ECDSA-P256:I-01 | Parameter domain identik dengan SP 800-186 & lolos uji validitas | M-CURVE | SCN-DS-KOM-S | DS-S-01 | — | SP-800-186, FIPS-186-5 |
| C-STRENGTH | Tingkat keamanan ≥ 112 bit untuk seluruh algoritma approved (SP 800-57) | M-CURVE | SCN-DS-KOM-S | DS-S-01 | — | SP-800-186, FIPS-186-5 |
| AES-128:K-07 | Nonce tidak pernah berulang dan tidak bias | M-NONCE | SCN-DS-INT-S | DS-S-02 | — | FIPS-186-5, RFC-6979 |
| ChaCha20:K-06 | Nonce tidak pernah berulang dan tidak bias | M-NONCE | SCN-DS-INT-S | DS-S-02 | — | FIPS-186-5, RFC-6979 |
| C-SIG | ECDSA/EdDSA/ML-DSA: EUF-CMA; nonce tidak berulang/bias | M-NONCE | SCN-DS-INT-S | DS-S-02 | — | FIPS-186-5, RFC-6979 |
| C-SIG | ECDSA/EdDSA/ML-DSA: EUF-CMA; nonce tidak berulang/bias | M-NONCE | SCN-DS-INT-S | DS-S-02 | — | FIPS-186-5, RFC-6979 |
| AES-128:K-07 | Nonce tidak pernah berulang dan tidak bias | M-NONCE | SCN-DS-INT-S | DS-S-03 | — | FIPS-186-5 |
| ChaCha20:K-06 | Nonce tidak pernah berulang dan tidak bias | M-NONCE | SCN-DS-INT-S | DS-S-03 | — | FIPS-186-5 |
| C-SIG | ECDSA/EdDSA/ML-DSA: EUF-CMA; nonce tidak berulang/bias | M-NONCE | SCN-DS-INT-S | DS-S-03 | — | FIPS-186-5 |
| C-SIG | ECDSA/EdDSA/ML-DSA: EUF-CMA; nonce tidak berulang/bias | M-NONCE | SCN-DS-INT-S | DS-S-03 | — | FIPS-186-5 |
| RSA-OAEP-2048:I-04 | Produk menolak kunci publik/titik tidak valid | M-PKV | SCN-DS-INT-S | DS-S-04 | — | SP-800-186 |
| ECDSA-P256:I-04 | Produk menolak kunci publik/titik tidak valid | M-PKV | SCN-DS-INT-S | DS-S-04 | — | SP-800-186 |
| C-SIG | ECDSA/EdDSA/ML-DSA: EUF-CMA; nonce tidak berulang/bias | M-PKV | SCN-DS-INT-S | DS-S-04 | — | SP-800-186 |
| AES-128:K-08 | RBG yang dipakai disetujui (SP 800-90A) dengan entropi memadai | M-RNG | SCN-DS-INT-S | DS-S-05 | — | SP-800-90B, SP-800-22 |
| ChaCha20:K-07 | RBG yang dipakai disetujui (SP 800-90A) dengan entropi memadai | M-RNG | SCN-DS-INT-S | DS-S-05 | — | SP-800-90B, SP-800-22 |
| C-RNG | Kunci & nonce dari HMAC_DRBG/CTR_DRBG (SP 800-90A) dengan entropi memadai | M-RNG | SCN-DS-INT-S | DS-S-05 | — | SP-800-90B, SP-800-22 |
| C-SIG | ECDSA/EdDSA/ML-DSA: EUF-CMA; nonce tidak berulang/bias | M-RNG | SCN-DS-INT-S | DS-S-05 | — | SP-800-90B, SP-800-22 |
| AES-128:K-05 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-DS-SIS-S | DS-S-07 | — | SP-800-57, FIPS-204, SP-800-186 |
| ChaCha20:K-04 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-DS-SIS-S | DS-S-07 | — | SP-800-57, FIPS-204, SP-800-186 |
| ECDSA-P256:K-01 | ECDLP tidak terpecahkan (≥ 2^128 operasi) | M-ECDLP | SCN-DS-SIS-S | DS-S-07 | — | SP-800-57, FIPS-204, SP-800-186 |
| C-STRENGTH | Tingkat keamanan ≥ 112 bit untuk seluruh algoritma approved (SP 800-57) | M-KEYSIZE | SCN-DS-SIS-S | DS-S-07 | — | SP-800-57, FIPS-204, SP-800-186 |
| C-SIG | ECDSA/EdDSA/ML-DSA: EUF-CMA; nonce tidak berulang/bias | M-KEYSIZE | SCN-DS-SIS-S | DS-S-07 | — | SP-800-57, FIPS-204, SP-800-186 |
| ECDSA-P256:I-06 | Verifikasi menolak r,s ∉ [1, n−1]; kebijakan low-S terdokumentasi | M-SIGMAL | SCN-DS-INT-S | DS-S-08 | — | FIPS-186-5 |
| C-SIG | ECDSA/EdDSA/ML-DSA: EUF-CMA; nonce tidak berulang/bias | M-SIGMAL | SCN-DS-INT-S | DS-S-08 | — | FIPS-186-5 |
| AES-128:K-09 | Komponen nonlinear memenuhi batas acuan NL/DU/derajat | M-SBOX | SCN-HF-KOM-S | HF-S-01 | — | FIPS-202 |
| SHA3-256:K-05 | Komponen nonlinear memenuhi batas acuan NL/DU/derajat | M-SBOX | SCN-HF-KOM-S | HF-S-01 | — | FIPS-202 |
| AES-128:K-03 | Lapisan difusi mencapai difusi penuh dengan margin ronde memadai | M-DIFFUSION | SCN-HF-KOM-S | HF-S-01 | — | FIPS-202 |
| ChaCha20:K-03 | Lapisan difusi mencapai difusi penuh dengan margin ronde memadai | M-DIFFUSION | SCN-HF-KOM-S | HF-S-01 | — | FIPS-202 |
| AES-128:K-01 | Perubahan 1 bit masukan/kunci mengubah ≈ 50% bit keluaran | M-AVAL | SCN-HF-INT-S | HF-S-02 | — | SP-800-22 |
| ChaCha20:K-01 | Perubahan 1 bit masukan/kunci mengubah ≈ 50% bit keluaran | M-AVAL | SCN-HF-INT-S | HF-S-02 | — | SP-800-22 |
| AES-128:K-10 | Keluaran (keystream/CTR/digest berantai) tak terbedakan dari acak | M-SP80022 | SCN-HF-INT-S | HF-S-02 | — | SP-800-22 |
| ChaCha20:K-08 | Keluaran (keystream/CTR/digest berantai) tak terbedakan dari acak | M-SP80022 | SCN-HF-INT-S | HF-S-02 | — | SP-800-22 |
| AES-128:K-05 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-HF-INT-S | HF-S-03 | — | SP-800-107, FIPS-202 |
| ChaCha20:K-04 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-HF-INT-S | HF-S-03 | — | SP-800-107, FIPS-202 |
| C-HASH | SHA3-256/SHA-2: collision 2^(n/2), preimage 2^n | M-GENERIC | SCN-HF-INT-S | HF-S-03 | — | SP-800-107, FIPS-202 |
| C-HASH | SHA3-256/SHA-2: collision 2^(n/2), preimage 2^n | M-GENERIC | SCN-HF-INT-S | HF-S-03 | — | SP-800-107, FIPS-202 |
| C-STRENGTH | Tingkat keamanan ≥ 112 bit untuk seluruh algoritma approved (SP 800-57) | M-GENERIC | SCN-HF-INT-S | HF-S-03 | — | SP-800-107, FIPS-202 |
| SHA3-256:I-04 | Padding benar untuk panjang r−2, r−1, r, r+1 byte | M-PAD | SCN-HF-INT-S | HF-S-04 | — | SP-800-107 |
| AES-128:K-02 | Tidak ada karakteristik diferensial ronde penuh dengan probabilitas > 2^-k | M-DIFF | SCN-HF-INT-S | HF-S-05 | — | FIPS-202 |
| SHA3-256:K-02 | Tidak ada karakteristik diferensial ronde penuh dengan probabilitas > 2^-k | M-DIFF | SCN-HF-INT-S | HF-S-05 | — | FIPS-202 |
| C-HASH | SHA3-256/SHA-2: collision 2^(n/2), preimage 2^n | M-DIFF | SCN-HF-INT-S | HF-S-05 | — | FIPS-202 |
| AES-128:K-05 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-HF-SIS-S | HF-S-06 | — | SP-800-57, SP-800-107 |
| ChaCha20:K-04 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-HF-SIS-S | HF-S-06 | — | SP-800-57, SP-800-107 |
| C-STRENGTH | Tingkat keamanan ≥ 112 bit untuk seluruh algoritma approved (SP 800-57) | M-KEYSIZE | SCN-HF-SIS-S | HF-S-06 | — | SP-800-57, SP-800-107 |
| C-HASH | SHA3-256/SHA-2: collision 2^(n/2), preimage 2^n | M-KEYSIZE | SCN-HF-SIS-S | HF-S-06 | — | SP-800-57, SP-800-107 |
| AES-128:K-05 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-PK-KOM-S | PK-S-01 | — | SP-800-57, ISO-18032 |
| ChaCha20:K-04 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-PK-KOM-S | PK-S-01 | — | SP-800-57, ISO-18032 |
| RSA-OAEP-2048:K-03 | p, q prima kuat; \|p−q\| > 2^(nlen/2−100); d > 2^(nlen/2); e ∈ (2^16, 2^256) | M-PRIME | SCN-PK-KOM-S | PK-S-01 | — | SP-800-57, ISO-18032 |
| RSA-OAEP-2048:K-01 | Modulus tidak terfaktorkan dengan sumber daya realistis | M-FACT | SCN-PK-KOM-S | PK-S-01 | — | SP-800-57, ISO-18032 |
| C-STRENGTH | Tingkat keamanan ≥ 112 bit untuk seluruh algoritma approved (SP 800-57) | M-KEYSIZE | SCN-PK-KOM-S | PK-S-01 | — | SP-800-57, ISO-18032 |
| C-PKE | RSA-OAEP: IND-CCA2; galat dekripsi seragam (tanpa oracle) | M-KEYSIZE | SCN-PK-KOM-S | PK-S-01 | — | SP-800-57, ISO-18032 |
| RSA-OAEP-2048:I-03 | Semua kegagalan dekripsi menghasilkan galat & waktu yang tak terbedakan | M-ORACLE | SCN-PK-INT-S | PK-S-02 | — | SP-800-56B, ISO-17825 |
| C-PKE | RSA-OAEP: IND-CCA2; galat dekripsi seragam (tanpa oracle) | M-ORACLE | SCN-PK-INT-S | PK-S-02 | — | SP-800-56B, ISO-17825 |
| C-PKE | RSA-OAEP: IND-CCA2; galat dekripsi seragam (tanpa oracle) | M-ORACLE | SCN-PK-INT-S | PK-S-02 | — | SP-800-56B, ISO-17825 |
| RSA-OAEP-2048:I-04 | Produk menolak kunci publik/titik tidak valid | M-PKV | SCN-PK-INT-S | PK-S-03 | — | SP-800-56A, SP-800-186 |
| ECDSA-P256:I-04 | Produk menolak kunci publik/titik tidak valid | M-PKV | SCN-PK-INT-S | PK-S-03 | — | SP-800-56A, SP-800-186 |
| RSA-OAEP-2048:K-05 | Kunci produk tidak rentan terhadap serangan kunci lemah | M-RSAWEAK | SCN-PK-INT-S | PK-S-04 | — | ISO-18032, SP-800-90A |
| AES-128:K-08 | RBG yang dipakai disetujui (SP 800-90A) dengan entropi memadai | M-RNG | SCN-PK-INT-S | PK-S-04 | — | ISO-18032, SP-800-90A |
| ChaCha20:K-07 | RBG yang dipakai disetujui (SP 800-90A) dengan entropi memadai | M-RNG | SCN-PK-INT-S | PK-S-04 | — | ISO-18032, SP-800-90A |
| C-RNG | Kunci & nonce dari HMAC_DRBG/CTR_DRBG (SP 800-90A) dengan entropi memadai | M-RSAWEAK | SCN-PK-INT-S | PK-S-04 | — | ISO-18032, SP-800-90A |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-PK-INT-S | PK-S-05 | — | FIPS-203 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-PK-INT-S | PK-S-05 | — | FIPS-203 |
| C-PKE | RSA-OAEP: IND-CCA2; galat dekripsi seragam (tanpa oracle) | M-KAT | SCN-PK-INT-S | PK-S-05 | — | FIPS-203 |
| AES-128:K-05 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-PK-SIS-S | PK-S-06 | — | FIPS-203, SP-800-131A |
| ChaCha20:K-04 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-PK-SIS-S | PK-S-06 | — | FIPS-203, SP-800-131A |
| C-STRENGTH | Tingkat keamanan ≥ 112 bit untuk seluruh algoritma approved (SP 800-57) | M-KEYSIZE | SCN-PK-SIS-S | PK-S-06 | — | FIPS-203, SP-800-131A |
| ChaCha20:K-02 | Fungsi nonlinear memiliki NL & derajat sesuai desain | M-BOOL | SCN-SC-KOM-S | SC-S-01 | — | ISO-18033-4 |
| AES-128:K-03 | Lapisan difusi mencapai difusi penuh dengan margin ronde memadai | M-DIFFUSION | SCN-SC-KOM-S | SC-S-01 | — | ISO-18033-4 |
| ChaCha20:K-03 | Lapisan difusi mencapai difusi penuh dengan margin ronde memadai | M-DIFFUSION | SCN-SC-KOM-S | SC-S-01 | — | ISO-18033-4 |
| AES-128:K-10 | Keluaran (keystream/CTR/digest berantai) tak terbedakan dari acak | M-SP80022 | SCN-SC-INT-S | SC-S-02 | — | SP-800-22 |
| ChaCha20:K-08 | Keluaran (keystream/CTR/digest berantai) tak terbedakan dari acak | M-SP80022 | SCN-SC-INT-S | SC-S-02 | — | SP-800-22 |
| ChaCha20:K-05 | Kompleksitas linear keystream mendekati N/2 | M-LC | SCN-SC-INT-S | SC-S-02 | — | SP-800-22 |
| AES-128:K-01 | Perubahan 1 bit masukan/kunci mengubah ≈ 50% bit keluaran | M-AVAL | SCN-SC-INT-S | SC-S-03 | — | ISO-18033-4 |
| ChaCha20:K-01 | Perubahan 1 bit masukan/kunci mengubah ≈ 50% bit keluaran | M-AVAL | SCN-SC-INT-S | SC-S-03 | — | ISO-18033-4 |
| C-STRENGTH | Tingkat keamanan ≥ 112 bit untuk seluruh algoritma approved (SP 800-57) | M-AVAL | SCN-SC-INT-S | SC-S-03 | — | ISO-18033-4 |
| AES-128:K-07 | Nonce tidak pernah berulang dan tidak bias | M-NONCE | SCN-SC-INT-S | SC-S-04 | — | RFC-8439 |
| ChaCha20:K-06 | Nonce tidak pernah berulang dan tidak bias | M-NONCE | SCN-SC-INT-S | SC-S-04 | — | RFC-8439 |
| C-AEAD | AEAD (AES-GCM, ChaCha20-Poly1305): kerahasiaan IND-CPA + integritas INT-CTXT bila nonce unik | M-NONCE | SCN-SC-INT-S | SC-S-04 | — | RFC-8439 |
| C-AEAD | AEAD (AES-GCM, ChaCha20-Poly1305): kerahasiaan IND-CPA + integritas INT-CTXT bila nonce unik | M-NONCE | SCN-SC-INT-S | SC-S-04 | — | RFC-8439 |
| AES-128:K-07 | Nonce tidak pernah berulang dan tidak bias | M-NONCE | SCN-SC-SIS-S | SC-S-05 | — | RFC-8439 |
| ChaCha20:K-06 | Nonce tidak pernah berulang dan tidak bias | M-NONCE | SCN-SC-SIS-S | SC-S-05 | — | RFC-8439 |
| C-AEAD | AEAD (AES-GCM, ChaCha20-Poly1305): kerahasiaan IND-CPA + integritas INT-CTXT bila nonce unik | M-NONCE | SCN-SC-SIS-S | SC-S-05 | — | RFC-8439 |
| AES-128:K-05 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-SC-SIS-S | SC-S-06 | — | SP-800-57 |
| ChaCha20:K-04 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-SC-SIS-S | SC-S-06 | — | SP-800-57 |
| C-STRENGTH | Tingkat keamanan ≥ 112 bit untuk seluruh algoritma approved (SP 800-57) | M-KEYSIZE | SCN-SC-SIS-S | SC-S-06 | — | SP-800-57 |
| AES-128:I-05 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-BC-KOM-I | BC-I-01 | — | ISO-17825, ISO-19790 |
| ChaCha20:I-04 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-BC-KOM-I | BC-I-01 | — | ISO-17825, ISO-19790 |
| AES-128:I-06 | Kunci/CSP dihapus dari memori setelah dipakai | M-ZEROIZE | SCN-BC-KOM-I | BC-I-01 | — | ISO-17825, ISO-19790 |
| ChaCha20:I-05 | Kunci/CSP dihapus dari memori setelah dipakai | M-ZEROIZE | SCN-BC-KOM-I | BC-I-01 | — | ISO-17825, ISO-19790 |
| C-CT | Operasi dengan data rahasia berjalan constant-time pada x86-64 | M-TIMING | SCN-BC-KOM-I | BC-I-01 | — | ISO-17825, ISO-19790 |
| AES-128:I-05 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-BC-INT-I | BC-I-02 | — | ISO-17825 |
| ChaCha20:I-04 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-BC-INT-I | BC-I-02 | — | ISO-17825 |
| C-AEAD | AEAD (AES-GCM, ChaCha20-Poly1305): kerahasiaan IND-CPA + integritas INT-CTXT bila nonce unik | M-TIMING | SCN-BC-INT-I | BC-I-02 | — | ISO-17825 |
| C-CT | Operasi dengan data rahasia berjalan constant-time pada x86-64 | M-TIMING | SCN-BC-INT-I | BC-I-02 | — | ISO-17825 |
| AES-128:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-BC-INT-I | BC-I-03 | — | ISO-29119, ISO-18045 |
| ChaCha20:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-BC-INT-I | BC-I-03 | — | ISO-29119, ISO-18045 |
| AES-128:I-04 | Power-on self-test (KAT) & conditional test (pairwise) berjalan; error state memblokir layanan | M-SELFTEST | SCN-BC-SIS-I | BC-I-05 | — | ISO-29119 |
| ChaCha20:I-03 | Power-on self-test (KAT) & conditional test (pairwise) berjalan; error state memblokir layanan | M-SELFTEST | SCN-BC-SIS-I | BC-I-05 | — | ISO-29119 |
| AES-128:I-04 | Power-on self-test (KAT) & conditional test (pairwise) berjalan; error state memblokir layanan | M-SELFTEST | SCN-BC-SIS-I | BC-I-06 | — | ISO-19790 |
| ChaCha20:I-03 | Power-on self-test (KAT) & conditional test (pairwise) berjalan; error state memblokir layanan | M-SELFTEST | SCN-BC-SIS-I | BC-I-06 | — | ISO-19790 |
| AES-128:I-06 | Kunci/CSP dihapus dari memori setelah dipakai | M-ZEROIZE | SCN-BC-SIS-I | BC-I-06 | — | ISO-19790 |
| ChaCha20:I-05 | Kunci/CSP dihapus dari memori setelah dipakai | M-ZEROIZE | SCN-BC-SIS-I | BC-I-06 | — | ISO-19790 |
| AES-128:I-05 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-DS-KOM-I | DS-I-01 | — | ISO-17825 |
| ChaCha20:I-04 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-DS-KOM-I | DS-I-01 | — | ISO-17825 |
| C-CT | Operasi dengan data rahasia berjalan constant-time pada x86-64 | M-TIMING | SCN-DS-KOM-I | DS-I-01 | — | ISO-17825 |
| AES-128:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-DS-INT-I | DS-I-04 | — | ISO-29119 |
| ChaCha20:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-DS-INT-I | DS-I-04 | — | ISO-29119 |
| AES-128:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-HF-KOM-I | HF-I-01 | — | FIPS-180-4 |
| ChaCha20:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-HF-KOM-I | HF-I-01 | — | FIPS-180-4 |
| AES-128:I-05 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-HF-INT-I | HF-I-02 | — | ISO-17825 |
| ChaCha20:I-04 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-HF-INT-I | HF-I-02 | — | ISO-17825 |
| C-CT | Operasi dengan data rahasia berjalan constant-time pada x86-64 | M-TIMING | SCN-HF-INT-I | HF-I-02 | — | ISO-17825 |
| AES-128:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-HF-INT-I | HF-I-03 | — | ISO-29119 |
| ChaCha20:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-HF-INT-I | HF-I-03 | — | ISO-29119 |
| AES-128:I-04 | Power-on self-test (KAT) & conditional test (pairwise) berjalan; error state memblokir layanan | M-SELFTEST | SCN-HF-SIS-I | HF-I-04 | — | ISO-29119 |
| ChaCha20:I-03 | Power-on self-test (KAT) & conditional test (pairwise) berjalan; error state memblokir layanan | M-SELFTEST | SCN-HF-SIS-I | HF-I-04 | — | ISO-29119 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-HF-SIS-I | HF-I-05 | — | ISO-29119 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-HF-SIS-I | HF-I-05 | — | ISO-29119 |
| AES-128:I-06 | Kunci/CSP dihapus dari memori setelah dipakai | M-ZEROIZE | SCN-HF-SIS-I | HF-I-06 | — | ISO-19790 |
| ChaCha20:I-05 | Kunci/CSP dihapus dari memori setelah dipakai | M-ZEROIZE | SCN-HF-SIS-I | HF-I-06 | — | ISO-19790 |
| AES-128:I-05 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-PK-KOM-I | PK-I-01 | — | ISO-17825 |
| ChaCha20:I-04 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-PK-KOM-I | PK-I-01 | — | ISO-17825 |
| C-CT | Operasi dengan data rahasia berjalan constant-time pada x86-64 | M-TIMING | SCN-PK-KOM-I | PK-I-01 | — | ISO-17825 |
| AES-128:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-PK-INT-I | PK-I-02 | — | ISO-29119 |
| ChaCha20:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-PK-INT-I | PK-I-02 | — | ISO-29119 |
| RSA-OAEP-2048:I-03 | Semua kegagalan dekripsi menghasilkan galat & waktu yang tak terbedakan | M-ORACLE | SCN-PK-INT-I | PK-I-03 | — | ISO-17825 |
| AES-128:I-05 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-PK-INT-I | PK-I-03 | — | ISO-17825 |
| ChaCha20:I-04 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-PK-INT-I | PK-I-03 | — | ISO-17825 |
| C-PKE | RSA-OAEP: IND-CCA2; galat dekripsi seragam (tanpa oracle) | M-ORACLE | SCN-PK-INT-I | PK-I-03 | — | ISO-17825 |
| AES-128:I-06 | Kunci/CSP dihapus dari memori setelah dipakai | M-ZEROIZE | SCN-PK-SIS-I | PK-I-04 | — | ISO-19790 |
| ChaCha20:I-05 | Kunci/CSP dihapus dari memori setelah dipakai | M-ZEROIZE | SCN-PK-SIS-I | PK-I-04 | — | ISO-19790 |
| AES-128:I-04 | Power-on self-test (KAT) & conditional test (pairwise) berjalan; error state memblokir layanan | M-SELFTEST | SCN-PK-SIS-I | PK-I-05 | — | ISO-29119 |
| ChaCha20:I-03 | Power-on self-test (KAT) & conditional test (pairwise) berjalan; error state memblokir layanan | M-SELFTEST | SCN-PK-SIS-I | PK-I-05 | — | ISO-29119 |
| AES-128:I-05 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-SC-KOM-I | SC-I-01 | — | ISO-17825 |
| ChaCha20:I-04 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-SC-KOM-I | SC-I-01 | — | ISO-17825 |
| C-CT | Operasi dengan data rahasia berjalan constant-time pada x86-64 | M-TIMING | SCN-SC-KOM-I | SC-I-01 | — | ISO-17825 |
| AES-128:I-05 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-SC-INT-I | SC-I-02 | — | ISO-17825 |
| ChaCha20:I-04 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-SC-INT-I | SC-I-02 | — | ISO-17825 |
| C-CT | Operasi dengan data rahasia berjalan constant-time pada x86-64 | M-TIMING | SCN-SC-INT-I | SC-I-02 | — | ISO-17825 |
| C-AEAD | AEAD (AES-GCM, ChaCha20-Poly1305): kerahasiaan IND-CPA + integritas INT-CTXT bila nonce unik | M-TIMING | SCN-SC-INT-I | SC-I-02 | — | ISO-17825 |
| AES-128:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-SC-INT-I | SC-I-03 | — | ISO-29119 |
| ChaCha20:I-01 | API menolak masukan tidak valid tanpa crash/kebocoran | M-FUZZ | SCN-SC-INT-I | SC-I-03 | — | ISO-29119 |
| AES-128:I-06 | Kunci/CSP dihapus dari memori setelah dipakai | M-ZEROIZE | SCN-SC-SIS-I | SC-I-04 | — | ISO-19790 |
| ChaCha20:I-05 | Kunci/CSP dihapus dari memori setelah dipakai | M-ZEROIZE | SCN-SC-SIS-I | SC-I-04 | — | ISO-19790 |
| AES-128:I-04 | Power-on self-test (KAT) & conditional test (pairwise) berjalan; error state memblokir layanan | M-SELFTEST | SCN-SC-SIS-I | SC-I-05 | — | ISO-29119 |
| ChaCha20:I-03 | Power-on self-test (KAT) & conditional test (pairwise) berjalan; error state memblokir layanan | M-SELFTEST | SCN-SC-SIS-I | SC-I-05 | — | ISO-29119 |
| AES-128:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-XA-INT-K | XA-K-01 | — | ISO-18367 |
| ChaCha20:I-02 | Implementasi menghasilkan keluaran identik dengan vektor uji resmi | M-KAT | SCN-XA-INT-K | XA-K-01 | — | ISO-18367 |
| AES-128:K-08 | RBG yang dipakai disetujui (SP 800-90A) dengan entropi memadai | M-RNG | SCN-XA-INT-S | XA-S-01 | — | SP-800-90A, SP-800-90B, SP-800-22 |
| ChaCha20:K-07 | RBG yang dipakai disetujui (SP 800-90A) dengan entropi memadai | M-RNG | SCN-XA-INT-S | XA-S-01 | — | SP-800-90A, SP-800-90B, SP-800-22 |
| C-RNG | Kunci & nonce dari HMAC_DRBG/CTR_DRBG (SP 800-90A) dengan entropi memadai | M-RNG | SCN-XA-INT-S | XA-S-01 | — | SP-800-90A, SP-800-90B, SP-800-22 |
| AES-128:I-06 | Kunci/CSP dihapus dari memori setelah dipakai | M-ZEROIZE | SCN-XA-SIS-S | XA-S-02 | — | SP-800-57, ISO-19790 |
| ChaCha20:I-05 | Kunci/CSP dihapus dari memori setelah dipakai | M-ZEROIZE | SCN-XA-SIS-S | XA-S-02 | — | SP-800-57, ISO-19790 |
| AES-128:K-05 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-XA-SIS-S | XA-S-02 | — | SP-800-57, ISO-19790 |
| ChaCha20:K-04 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-XA-SIS-S | XA-S-02 | — | SP-800-57, ISO-19790 |
| C-STRENGTH | Tingkat keamanan ≥ 112 bit untuk seluruh algoritma approved (SP 800-57) | M-ZEROIZE | SCN-XA-SIS-S | XA-S-02 | — | SP-800-57, ISO-19790 |
| AES-128:K-05 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-XA-SIS-S | XA-S-03 | — | FIPS-203, FIPS-204, SP-800-131A |
| ChaCha20:K-04 | Tingkat keamanan ≥ 112 bit dan status 'acceptable' menurut SP 800-131A | M-KEYSIZE | SCN-XA-SIS-S | XA-S-03 | — | FIPS-203, FIPS-204, SP-800-131A |
| C-STRENGTH | Tingkat keamanan ≥ 112 bit untuk seluruh algoritma approved (SP 800-57) | M-KEYSIZE | SCN-XA-SIS-S | XA-S-03 | — | FIPS-203, FIPS-204, SP-800-131A |
| AES-128:I-05 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-XA-SIS-S | XA-S-04 | — | ISO-17825, ISO-20085 |
| ChaCha20:I-04 | Waktu eksekusi tidak bergantung pada data rahasia | M-TIMING | SCN-XA-SIS-S | XA-S-04 | — | ISO-17825, ISO-20085 |
| C-CT | Operasi dengan data rahasia berjalan constant-time pada x86-64 | M-TIMING | SCN-XA-SIS-S | XA-S-04 | — | ISO-17825, ISO-20085 |
| AES-128:I-04 | Power-on self-test (KAT) & conditional test (pairwise) berjalan; error state memblokir layanan | M-SELFTEST | SCN-XA-SIS-I | XA-I-01 | — | ISO-19790 |
| ChaCha20:I-03 | Power-on self-test (KAT) & conditional test (pairwise) berjalan; error state memblokir layanan | M-SELFTEST | SCN-XA-SIS-I | XA-I-01 | — | ISO-19790 |

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
