# Daftar Algoritma yang Diuji — Cryptan.ID SecureLib

*Cryptan.ID Test Suite · modul `algo_catalog` · UK-1 KUK 1.1 — informasi desain produk (daftar algoritma yang diuji) · dibangkitkan 2026-10-01T09:06:06+07:00*

## Ringkasan

Total **6** kombinasi algoritma × varian × panjang kunci.

| Primitif | Jumlah kombinasi |
|---|---|
| Block cipher | 1 |
| Stream cipher | 1 |
| Fungsi hash / XOF | 1 |
| PKC / KEM / key agreement | 2 |
| Tanda tangan digital | 1 |
| **Total** | **6** |

Sumber input: dropdown = 6

## Daftar algoritma

| No | Primitif | Algoritma | Varian | Panjang kunci | Security strength | Status NIST | Standar | Sumber input | Bukti |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Block cipher | AES | CTR | 128 | 128 bit | acceptable | FIPS 197, SP 800-38A, ISO/IEC 18033-3 | dropdown | [AES:CTR:128] dipilih: AES:CTR:128 |
| 2 | Stream cipher | ChaCha | ChaCha20 | 256 | 256 bit | not_nist | RFC 8439 | dropdown | [CHACHA:ChaCha20] dipilih: CHACHA:ChaCha20 |
| 3 | Fungsi hash / XOF | SHA-3 | SHA3-256 | — | 128 bit | acceptable | FIPS 202, ISO/IEC 10118-3 | dropdown | [SHA-3:SHA3-256] dipilih: SHA-3:SHA3-256 |
| 4 | PKC / KEM / key agreement | ML-KEM | ML-KEM-768 | — | 192 bit (kategori 3) | acceptable | FIPS 203 | dropdown | [ML-KEM:768] dipilih: ML-KEM:768 |
| 5 | PKC / KEM / key agreement | RSA | OAEP | 2048 | 112 bit | acceptable | SP 800-56B Rev.2, RFC 8017, ISO/IEC 18033-2 | dropdown | [RSA:OAEP:2048] dipilih: RSA:OAEP:2048 |
| 6 | Tanda tangan digital | ECDSA | P-256 | 256 | 128 bit | acceptable | FIPS 186-5, SP 800-186, ISO/IEC 14888-3 | dropdown | [ECDSA:P-256] dipilih: ECDSA:P-256 |

## Peringatan otomatis

| Tingkat | Kode | Pesan |
|---|---|---|
| SEDANG | QUANTUM_VULNERABLE | RSA-OAEP-2048: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| SEDANG | QUANTUM_VULNERABLE | ECDSA-P256: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |

## Tautan ke UK-1

Berkas ini ditautkan ke `config/product_profile.yaml` (`algorithms_under_test`).
Profil UK-1 tersedia untuk: config/profiles/aes128.yaml, config/profiles/chacha20.yaml, config/profiles/ecdsa_p256.yaml, config/profiles/rsa_oaep_2048.yaml, config/profiles/sha3_256.yaml.
Kombinasi tanpa profil UK-1 (1): ML-KEM-768

