# Daftar Algoritma yang Diuji — Cryptan.ID SecureLib

*Cryptan.ID Test Suite · modul `algo_catalog` · UK-1 KUK 1.1 — informasi desain produk (daftar algoritma yang diuji) · dibangkitkan 2026-10-01T09:16:53+07:00*

## Ringkasan

Total **33** kombinasi algoritma × varian × panjang kunci.

| Primitif | Jumlah kombinasi |
|---|---|
| Block cipher | 6 |
| Stream cipher | 2 |
| Fungsi hash / XOF | 7 |
| MAC / AEAD ringan | 4 |
| PKC / KEM / key agreement | 7 |
| Tanda tangan digital | 6 |
| DRBG | 1 |
| **Total** | **33** |

Sumber input: file = 32, dropdown = 6

## Daftar algoritma

| No | Primitif | Algoritma | Varian | Panjang kunci | Security strength | Status NIST | Standar | Sumber input | Bukti |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Block cipher | AES | CTR | 128 | 128 bit | acceptable | FIPS 197, SP 800-38A, ISO/IEC 18033-3 | dropdown, file | [datasheet_securelib.pdf:3] F) Security Policy excerpt - Approved algorithms Symmetric: AES-128-CTR, AES-256-GCM (SP 800-38D), XTS-AES-256 for storage, AES-256 |
| 2 | Block cipher | AES | GCM | 256 | 256 bit | acceptable | FIPS 197, SP 800-38D, ISO/IEC 18033-3, ISO/IEC 19772 | file | [datasheet_securelib.pdf:3] olicy excerpt - Approved algorithms Symmetric: AES-128-CTR, AES-256-GCM (SP 800-38D), XTS-AES-256 for storage, AES-256-KW Message a |
| 3 | Block cipher | AES | KW | 256 | 256 bit | acceptable | FIPS 197, SP 800-38F, RFC 3394 | file | [datasheet_securelib.pdf:3] 128-CTR, AES-256-GCM (SP 800-38D), XTS-AES-256 for storage, AES-256-KW Message authentication: HMAC-SHA-256 with 256-bit keys, CMA |
| 4 | Block cipher | AES | XTS | 256 | 128 bit | acceptable | FIPS 197, SP 800-38E, IEEE 1619 | file | [datasheet_securelib.pdf:3] lgorithms Symmetric: AES-128-CTR, AES-256-GCM (SP 800-38D), XTS-AES-256 for storage, AES-256-KW Message authentication: HMAC-SHA-25 |
| 5 | Block cipher | PRESENT | ECB | 80 | 80 bit | not_nist | ISO/IEC 29192-2 | file | [vendor_page.html:16] greement X25519, ffdhe3072 Lightweight (IoT) Ascon-AEAD128, PRESENT-80 |
| 6 | Block cipher | TDEA | 3-key | 168 | 112 bit | disallowed | SP 800-67 Rev.2, SP 800-131A Rev.2, ISO/IEC 18033-3 | file | [datasheet_securelib.pdf:9] (SP 800-90A) Legacy (non-approved, interoperability only): TDEA, SHA-1, RSA-1024 PKCS#1 v1.5 RSAES-PKCS1-v1_5 |
| 7 | Stream cipher | ChaCha | ChaCha20 | 256 | 256 bit | not_nist | RFC 8439 | dropdown | [CHACHA:ChaCha20] dipilih: CHACHA:ChaCha20 |
| 8 | Stream cipher | ChaCha | ChaCha20-Poly1305 | 256 | 256 bit | not_nist | RFC 8439 | file | [vendor_page.html:6] ryptographic Capabilities Service Algorithm Bulk encryption ChaCha20-Poly1305 (RFC 8439) Disk encryption XTS-AES-256 Hash SHA-512/256, BL |
| 9 | Fungsi hash / XOF | BLAKE2 | BLAKE2b-512 | — | 256 bit | not_nist | RFC 7693 | file | [vendor_page.html:10] 05 (RFC 8439) Disk encryption XTS-AES-256 Hash SHA-512/256, BLAKE2b Signatures ECDSA P-384, SLH-DSA-SHA2-128s Key agreement X25 |
| 10 | Fungsi hash / XOF | SHA-1 | SHA-1 | — | <80 | disallowed | FIPS 180-4, SP 800-131A Rev.2 | file | [datasheet_securelib.pdf:9] 00-90A) Legacy (non-approved, interoperability only): TDEA, SHA-1, RSA-1024 PKCS#1 v1.5 RSAES-PKCS1-v1_5 |
| 11 | Fungsi hash / XOF | SHA-2 | SHA-256 | — | 128 bit | acceptable | FIPS 180-4, ISO/IEC 10118-3 | file | [datasheet_securelib.pdf:5] tion: HMAC-SHA-256 with 256-bit keys, CMAC-AES-128 Hashing: SHA-256, SHA-384, SHA3-256, SHAKE256 Key establishment: ECDH P-384, |
| 12 | Fungsi hash / XOF | SHA-2 | SHA-384 | — | 192 bit | acceptable | FIPS 180-4, ISO/IEC 10118-3 | file | [datasheet_securelib.pdf:5] C-SHA-256 with 256-bit keys, CMAC-AES-128 Hashing: SHA-256, SHA-384, SHA3-256, SHAKE256 Key establishment: ECDH P-384, ML-KEM-7 |
| 13 | Fungsi hash / XOF | SHA-2 | SHA-512/256 | — | 128 bit | acceptable | FIPS 180-4 | file | [vendor_page.html:10] aCha20-Poly1305 (RFC 8439) Disk encryption XTS-AES-256 Hash SHA-512/256, BLAKE2b Signatures ECDSA P-384, SLH-DSA-SHA2-128s Key agre |
| 14 | Fungsi hash / XOF | SHA-3 | SHA3-256 | — | 128 bit | acceptable | FIPS 202, ISO/IEC 10118-3 | dropdown, file | [datasheet_securelib.pdf:5] with 256-bit keys, CMAC-AES-128 Hashing: SHA-256, SHA-384, SHA3-256, SHAKE256 Key establishment: ECDH P-384, ML-KEM-768 (FIPS 2 |
| 15 | Fungsi hash / XOF | SHA-3 | SHAKE256 | — | 256 bit | acceptable | FIPS 202 | file | [datasheet_securelib.pdf:5] bit keys, CMAC-AES-128 Hashing: SHA-256, SHA-384, SHA3-256, SHAKE256 Key establishment: ECDH P-384, ML-KEM-768 (FIPS 203), RSA-O |
| 16 | MAC / AEAD ringan | AES | CMAC | 128 | 128 bit | acceptable | FIPS 197, SP 800-38B, ISO/IEC 9797-1 | file | [datasheet_securelib.pdf:4] -KW Message authentication: HMAC-SHA-256 with 256-bit keys, CMAC-AES-128 Hashing: SHA-256, SHA-384, SHA3-256, SHAKE256 Key establish |
| 17 | MAC / AEAD ringan | Ascon | Ascon-AEAD128 | 128 | 128 bit | acceptable | SP 800-232 | file | [vendor_page.html:16] SHA2-128s Key agreement X25519, ffdhe3072 Lightweight (IoT) Ascon-AEAD128, PRESENT-80 |
| 18 | MAC / AEAD ringan | HMAC | SHA-256 | 128 | 128 bit | acceptable | FIPS 198-1, SP 800-107 Rev.1, ISO/IEC 9797-2 | file | [datasheet_securelib.pdf:4] XTS-AES-256 for storage, AES-256-KW Message authentication: HMAC-SHA-256 with 256-bit keys, CMAC-AES-128 Hashing: SHA-256, SHA-384, |
| 19 | MAC / AEAD ringan | HMAC | SHA-256 | 256 | 256 bit | acceptable | FIPS 198-1, SP 800-107 Rev.1, ISO/IEC 9797-2 | file | [datasheet_securelib.pdf:4] XTS-AES-256 for storage, AES-256-KW Message authentication: HMAC-SHA-256 with 256-bit keys, CMAC-AES-128 Hashing: SHA-256, SHA-384, |
| 20 | PKC / KEM / key agreement | ECDH | P-384 | 384 | 192 bit | acceptable | SP 800-56A Rev.3, SP 800-186 | file | [datasheet_securelib.pdf:6] ng: SHA-256, SHA-384, SHA3-256, SHAKE256 Key establishment: ECDH P-384, ML-KEM-768 (FIPS 203), RSA-OAEP 2048-bit and 3072-bit Digi |
| 21 | PKC / KEM / key agreement | FFDH | ffdhe | 3072 | 128 bit | acceptable | SP 800-56A Rev.3, RFC 7919 | file | [vendor_page.html:14] atures ECDSA P-384, SLH-DSA-SHA2-128s Key agreement X25519, ffdhe3072 Lightweight (IoT) Ascon-AEAD128, PRESENT-80 |
| 22 | PKC / KEM / key agreement | ML-KEM | ML-KEM-768 | — | 192 bit (kategori 3) | acceptable | FIPS 203 | dropdown, file | [datasheet_securelib.pdf:6] SHA-384, SHA3-256, SHAKE256 Key establishment: ECDH P-384, ML-KEM-768 (FIPS 203), RSA-OAEP 2048-bit and 3072-bit Digital signatur |
| 23 | PKC / KEM / key agreement | RSA | OAEP | 2048 | 112 bit | acceptable | SP 800-56B Rev.2, RFC 8017, ISO/IEC 18033-2 | dropdown, file | [datasheet_securelib.pdf:6] KE256 Key establishment: ECDH P-384, ML-KEM-768 (FIPS 203), RSA-OAEP 2048-bit and 3072-bit Digital signatures: ECDSA P-256, RSA-PSS  |
| 24 | PKC / KEM / key agreement | RSA | OAEP | 3072 | 128 bit | acceptable | SP 800-56B Rev.2, RFC 8017, ISO/IEC 18033-2 | file | [datasheet_securelib.pdf:6] KE256 Key establishment: ECDH P-384, ML-KEM-768 (FIPS 203), RSA-OAEP 2048-bit and 3072-bit Digital signatures: ECDSA P-256, RSA- |
| 25 | PKC / KEM / key agreement | RSA | PKCS1-v1_5-ENC | 1024 | 80 bit | disallowed | RFC 8017, SP 800-131A Rev.2 | file | [datasheet_securelib.pdf:9] , interoperability only): TDEA, SHA-1, RSA-1024 PKCS#1 v1.5 RSAES-PKCS1-v1_5 |
| 26 | PKC / KEM / key agreement | XECDH | X25519 | 255 | 128 bit | PERLU_VERIFIKASI | RFC 7748, SP 800-186 | file | [vendor_page.html:14] E2b Signatures ECDSA P-384, SLH-DSA-SHA2-128s Key agreement X25519, ffdhe3072 Lightweight (IoT) Ascon-AEAD128, PRESENT-80 |
| 27 | Tanda tangan digital | ECDSA | P-256 | 256 | 128 bit | acceptable | FIPS 186-5, SP 800-186, ISO/IEC 14888-3 | dropdown, file | [datasheet_securelib.pdf:7] PS 203), RSA-OAEP 2048-bit and 3072-bit Digital signatures: ECDSA P-256, RSA-PSS 3072, Ed25519, ML-DSA-65 Random bit generation: CT |
| 28 | Tanda tangan digital | ECDSA | P-384 | 384 | 192 bit | acceptable | FIPS 186-5, SP 800-186, ISO/IEC 14888-3 | file | [vendor_page.html:12] encryption XTS-AES-256 Hash SHA-512/256, BLAKE2b Signatures ECDSA P-384, SLH-DSA-SHA2-128s Key agreement X25519, ffdhe3072 Lightwei |
| 29 | Tanda tangan digital | EdDSA | Ed25519 | 255 | 128 bit | acceptable | FIPS 186-5, RFC 8032, SP 800-186 | file | [datasheet_securelib.pdf:7] and 3072-bit Digital signatures: ECDSA P-256, RSA-PSS 3072, Ed25519, ML-DSA-65 Random bit generation: CTR_DRBG-AES-256 (SP 800- |
| 30 | Tanda tangan digital | ML-DSA | ML-DSA-65 | — | 192 bit (kategori 3) | acceptable | FIPS 204 | file | [datasheet_securelib.pdf:7] bit Digital signatures: ECDSA P-256, RSA-PSS 3072, Ed25519, ML-DSA-65 Random bit generation: CTR_DRBG-AES-256 (SP 800-90A) Legacy |
| 31 | Tanda tangan digital | RSA | PSS | 3072 | 128 bit | acceptable | FIPS 186-5, RFC 8017, ISO/IEC 14888-2 | file | [datasheet_securelib.pdf:7] OAEP 2048-bit and 3072-bit Digital signatures: ECDSA P-256, RSA-PSS 3072, Ed25519, ML-DSA-65 Random bit generation: CTR_DRBG-AES-256 |
| 32 | Tanda tangan digital | SLH-DSA | SHA2-128s | — | 128 bit (kategori 1) | acceptable | FIPS 205 | file | [vendor_page.html:12] S-AES-256 Hash SHA-512/256, BLAKE2b Signatures ECDSA P-384, SLH-DSA-SHA2-128s Key agreement X25519, ffdhe3072 Lightweight (IoT) Ascon-AEA |
| 33 | DRBG | DRBG | CTR_DRBG | 256 | 256 bit | acceptable | SP 800-90A Rev.1, ISO/IEC 18031 | file | [datasheet_securelib.pdf:8] 56, RSA-PSS 3072, Ed25519, ML-DSA-65 Random bit generation: CTR_DRBG-AES-256 (SP 800-90A) Legacy (non-approved, interoperability onl |

## Peringatan otomatis

| Tingkat | Kode | Pesan |
|---|---|---|
| TINGGI | STRENGTH_LT_112 | PRESENT-80: security strength 80 bit < 112 bit (SP 800-57 Pt.1) |
| TINGGI | STATUS_DISALLOWED | TDEA-3KEY: status NIST disallowed (SP 800-131A Rev.2) |
| TINGGI | STATUS_DISALLOWED | SHA-1: status NIST disallowed (SP 800-131A Rev.2) |
| TINGGI | STRENGTH_LT_112 | SHA-1: security strength <80 bit < 112 bit (SP 800-57 Pt.1) |
| SEDANG | QUANTUM_VULNERABLE | ECDH-P384: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| SEDANG | QUANTUM_VULNERABLE | FFDHE3072: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| SEDANG | QUANTUM_VULNERABLE | RSA-OAEP-2048: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| SEDANG | QUANTUM_VULNERABLE | RSA-OAEP-3072: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| TINGGI | STATUS_DISALLOWED | RSAES-PKCS1-V1_5-1024: status NIST disallowed (SP 800-131A Rev.2) |
| TINGGI | STRENGTH_LT_112 | RSAES-PKCS1-V1_5-1024: security strength 80 bit < 112 bit (SP 800-57 Pt.1) |
| SEDANG | QUANTUM_VULNERABLE | RSAES-PKCS1-V1_5-1024: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| SEDANG | QUANTUM_VULNERABLE | X25519: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| INFO | PERLU_VERIFIKASI | X25519: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| SEDANG | QUANTUM_VULNERABLE | ECDSA-P256: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| SEDANG | QUANTUM_VULNERABLE | ECDSA-P384: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| SEDANG | QUANTUM_VULNERABLE | ED25519: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| SEDANG | QUANTUM_VULNERABLE | RSA-PSS-3072: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |

## Tautan ke UK-1

Berkas ini ditautkan ke `config/product_profile.yaml` (`algorithms_under_test`).
Profil UK-1 tersedia untuk: config/profiles/aes128.yaml, config/profiles/chacha20.yaml, config/profiles/ecdsa_p256.yaml, config/profiles/rsa_oaep_2048.yaml, config/profiles/sha3_256.yaml.
Kombinasi tanpa profil UK-1 (28): AES-256-GCM, AES-256-KW, XTS-AES-256, PRESENT-80, TDEA-3KEY, CHACHA20-POLY1305, BLAKE2B-512, SHA-1, SHA-256, SHA-384, SHA-512/256, SHAKE256, CMAC-AES-128, ASCON-AEAD128, HMAC-SHA-256-K128, HMAC-SHA-256-K256, ECDH-P384, FFDHE3072, ML-KEM-768, RSA-OAEP-3072, RSAES-PKCS1-V1_5-1024, X25519, ECDSA-P384, ED25519, ML-DSA-65, RSA-PSS-3072, SLH-DSA-SHA2-128S, CTR-DRBG-AES-256

## Kandidat belum dikonfirmasi (tidak masuk daftar akhir)

| ID | Keyakinan | Bukti |
|---|---|---|
| ECDH-P256 | 0.5 | [securelib_crypto.c:25] i tanda tangan ECDSA */     return EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); } |
| HMAC-SHA-384-K192 | 0.4 | [CryptoService.java:27] te[] m) throws Exception {         Mac h = Mac.getInstance("HmacSHA384");         h.init(k);         return h.doFinal(m);     } } |
| HMAC-SHA-384-K384 | 0.4 | [CryptoService.java:27] te[] m) throws Exception {         Mac h = Mac.getInstance("HmacSHA384");         h.init(k);         return h.doFinal(m);     } } |
