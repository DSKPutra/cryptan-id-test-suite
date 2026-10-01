# Daftar Algoritma yang Diuji — Cryptan.ID SecureLib

*Cryptan.ID Test Suite · modul `algo_catalog` · UK-1 KUK 1.1 — informasi desain produk (daftar algoritma yang diuji) · dibangkitkan 2026-10-01T09:06:14+07:00*

## Ringkasan

Total **137** kombinasi algoritma × varian × panjang kunci.

| Primitif | Jumlah kombinasi |
|---|---|
| Block cipher | 15 |
| Fungsi hash / XOF | 22 |
| MAC / AEAD ringan | 17 |
| PKC / KEM / key agreement | 62 |
| Tanda tangan digital | 3 |
| DRBG | 5 |
| KDF | 13 |
| **Total** | **137** |

Sumber input: link = 137

## Daftar algoritma

| No | Primitif | Algoritma | Varian | Panjang kunci | Security strength | Status NIST | Standar | Sumber input | Bukti |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Block cipher | AES | AES-XPN | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:78] TML - DEMO only AES-KW - HTML AES-KWP - HTML AES-OFB - HTML AES-XPN - HTML AES-XTS 1.0 - HTML - no longer supported by ACVTS A |
| 2 | Block cipher | AES | CBC | 128 | 128 bit | acceptable | FIPS 197, SP 800-38A, ISO/IEC 18033-3 | link | [https://pages.nist.gov/ACVP/:67] endpoints defined. Supported Algorithms Block Cipher Modes AES-CBC - HTML AES-CFB1 - HTML AES-CFB8 - HTML AES-CFB128 - HTML AE |
| 3 | Block cipher | AES | CCM | 256 | 256 bit | acceptable | FIPS 197, SP 800-38C | link | [https://pages.nist.gov/ACVP/:128] Hash-128 - HTML TupleHash-256 - HTML Message Authentication AES-CCM - HTML AES-GMAC - HTML CMAC-AES - HTML CMAC-TDES - HTML H |
| 4 | Block cipher | AES | CFB1 | 128 | 128 bit | acceptable | FIPS 197, SP 800-38A | link | [https://pages.nist.gov/ACVP/:68] ned. Supported Algorithms Block Cipher Modes AES-CBC - HTML AES-CFB1 - HTML AES-CFB8 - HTML AES-CFB128 - HTML AES-CTR - HTML A |
| 5 | Block cipher | AES | CFB8 | 128 | 128 bit | acceptable | FIPS 197, SP 800-38A | link | [https://pages.nist.gov/ACVP/:69] lgorithms Block Cipher Modes AES-CBC - HTML AES-CFB1 - HTML AES-CFB8 - HTML AES-CFB128 - HTML AES-CTR - HTML AES-ECB - HTML AE |
| 6 | Block cipher | AES | CTR | 128 | 128 bit | acceptable | FIPS 197, SP 800-38A, ISO/IEC 18033-3 | link | [https://pages.nist.gov/ACVP/:71] BC - HTML AES-CFB1 - HTML AES-CFB8 - HTML AES-CFB128 - HTML AES-CTR - HTML AES-ECB - HTML AES-GCM - HTML AES-GCM-SIV - HTML -  |
| 7 | Block cipher | AES | ECB | 128 | 128 bit | acceptable | FIPS 197, SP 800-38A, ISO/IEC 18033-3 | link | [https://pages.nist.gov/ACVP/:72] FB1 - HTML AES-CFB8 - HTML AES-CFB128 - HTML AES-CTR - HTML AES-ECB - HTML AES-GCM - HTML AES-GCM-SIV - HTML - DEMO only AES-K |
| 8 | Block cipher | AES | FF1 | 128 | 128 bit | acceptable | FIPS 197, SP 800-38G | link | [https://pages.nist.gov/ACVP/:81] .0 - HTML - no longer supported by ACVTS AES-XTS 2.0 - HTML AES-FF1 - HTML AES-FF3-1 - HTML - DEMO only Ascon-AEAD128 - HTML T |
| 9 | Block cipher | AES | FF3-1 | 128 | 128 bit | PERLU_VERIFIKASI | FIPS 197, SP 800-38G Rev.1 | link | [https://pages.nist.gov/ACVP/:82] longer supported by ACVTS AES-XTS 2.0 - HTML AES-FF1 - HTML AES-FF3-1 - HTML - DEMO only Ascon-AEAD128 - HTML TDES-CBC - HTML  |
| 10 | Block cipher | AES | GCM | 128 | 128 bit | acceptable | FIPS 197, SP 800-38D, ISO/IEC 18033-3, ISO/IEC 19772 | link | [https://pages.nist.gov/ACVP/:73] CFB8 - HTML AES-CFB128 - HTML AES-CTR - HTML AES-ECB - HTML AES-GCM - HTML AES-GCM-SIV - HTML - DEMO only AES-KW - HTML AES-KW |
| 11 | Block cipher | AES | GCM-SIV | 128 | 128 bit | PERLU_VERIFIKASI | RFC 8452 | link | [https://pages.nist.gov/ACVP/:74] -CFB128 - HTML AES-CTR - HTML AES-ECB - HTML AES-GCM - HTML AES-GCM-SIV - HTML - DEMO only AES-KW - HTML AES-KWP - HTML AES-OF |
| 12 | Block cipher | AES | KW | 128 | 128 bit | acceptable | FIPS 197, SP 800-38F, RFC 3394 | link | [https://pages.nist.gov/ACVP/:75] ES-ECB - HTML AES-GCM - HTML AES-GCM-SIV - HTML - DEMO only AES-KW - HTML AES-KWP - HTML AES-OFB - HTML AES-XPN - HTML AES-XTS |
| 13 | Block cipher | AES | KWP | 128 | 128 bit | acceptable | FIPS 197, SP 800-38F, RFC 5649 | link | [https://pages.nist.gov/ACVP/:76] AES-GCM - HTML AES-GCM-SIV - HTML - DEMO only AES-KW - HTML AES-KWP - HTML AES-OFB - HTML AES-XPN - HTML AES-XTS 1.0 - HTML -  |
| 14 | Block cipher | AES | OFB | 128 | 128 bit | acceptable | FIPS 197, SP 800-38A | link | [https://pages.nist.gov/ACVP/:77] AES-GCM-SIV - HTML - DEMO only AES-KW - HTML AES-KWP - HTML AES-OFB - HTML AES-XPN - HTML AES-XTS 1.0 - HTML - no longer suppo |
| 15 | Block cipher | TDEA | 3-key | 168 | 112 bit | disallowed | SP 800-67 Rev.2, SP 800-131A Rev.2, ISO/IEC 18033-3 | link | [https://pages.nist.gov/ACVP/:84] F1 - HTML AES-FF3-1 - HTML - DEMO only Ascon-AEAD128 - HTML TDES-CBC - HTML TDES-CBCI - HTML TDES-CFB1 - HTML TDES-CFB8 - HT |
| 16 | Fungsi hash / XOF | Ascon | Ascon-CXOF128 | — | 128 bit | acceptable | SP 800-232 | link | [https://pages.nist.gov/ACVP/:116] 384 2.0 - HTML SHA3-512 2.0 - HTML XOFs Ascon-XOF128 - HTML Ascon-CXOF128 - HTML SHAKE-128 - HTML SHAKE-256 - HTML cSHAKE-128 |
| 17 | Fungsi hash / XOF | Ascon | Ascon-Hash256 | — | 128 bit | acceptable | SP 800-232 | link | [https://pages.nist.gov/ACVP/:98] TDES-KW - HTML TDES-OFB - HTML TDES-OFBI - HTML Secure Hash Ascon-Hash256 - HTML SHA-1 - HTML SHA-224 - HTML SHA-256 - HTML SH |
| 18 | Fungsi hash / XOF | Ascon | Ascon-XOF128 | — | 128 bit | acceptable | SP 800-232 | link | [https://pages.nist.gov/ACVP/:115] 256 2.0 - HTML SHA3-384 2.0 - HTML SHA3-512 2.0 - HTML XOFs Ascon-XOF128 - HTML Ascon-CXOF128 - HTML SHAKE-128 - HTML SHAKE-2 |
| 19 | Fungsi hash / XOF | ParallelHash | ParallelHash-128 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:123] 28 - HTML cSHAKE-256 - HTML KMAC-128 - HTML KMAC-256 - HTML ParallelHash-128 - HTML ParallelHash-256 - HTML TupleHash-128 - H |
| 20 | Fungsi hash / XOF | ParallelHash | ParallelHash-256 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:124] TML KMAC-128 - HTML KMAC-256 - HTML ParallelHash-128 - HTML ParallelHash-256 - HTML TupleHash-128 - HTML TupleHash-256 - HTML |
| 21 | Fungsi hash / XOF | SHA-1 | SHA-1 | — | <80 | disallowed | FIPS 180-4, SP 800-131A Rev.2 | link | [https://pages.nist.gov/ACVP/:99] FB - HTML TDES-OFBI - HTML Secure Hash Ascon-Hash256 - HTML SHA-1 - HTML SHA-224 - HTML SHA-256 - HTML SHA-384 - HTML SHA-512 |
| 22 | Fungsi hash / XOF | SHA-2 | SHA-224 | — | 112 bit | acceptable | FIPS 180-4, ISO/IEC 10118-3 | link | [https://pages.nist.gov/ACVP/:100] S-OFBI - HTML Secure Hash Ascon-Hash256 - HTML SHA-1 - HTML SHA-224 - HTML SHA-256 - HTML SHA-384 - HTML SHA-512 - HTML SHA-5 |
| 23 | Fungsi hash / XOF | SHA-2 | SHA-256 | — | 128 bit | acceptable | FIPS 180-4, ISO/IEC 10118-3 | link | [https://pages.nist.gov/ACVP/:101] ecure Hash Ascon-Hash256 - HTML SHA-1 - HTML SHA-224 - HTML SHA-256 - HTML SHA-384 - HTML SHA-512 - HTML SHA-512/224 - HTML S |
| 24 | Fungsi hash / XOF | SHA-2 | SHA-384 | — | 192 bit | acceptable | FIPS 180-4, ISO/IEC 10118-3 | link | [https://pages.nist.gov/ACVP/:102] n-Hash256 - HTML SHA-1 - HTML SHA-224 - HTML SHA-256 - HTML SHA-384 - HTML SHA-512 - HTML SHA-512/224 - HTML SHA-512/256 - HT |
| 25 | Fungsi hash / XOF | SHA-2 | SHA-512 | — | 256 bit | acceptable | FIPS 180-4, ISO/IEC 10118-3 | link | [https://pages.nist.gov/ACVP/:103] L SHA-1 - HTML SHA-224 - HTML SHA-256 - HTML SHA-384 - HTML SHA-512 - HTML SHA-512/224 - HTML SHA-512/256 - HTML SHA3-224 1.0 |
| 26 | Fungsi hash / XOF | SHA-2 | SHA-512/224 | — | 112 bit | acceptable | FIPS 180-4 | link | [https://pages.nist.gov/ACVP/:104] SHA-224 - HTML SHA-256 - HTML SHA-384 - HTML SHA-512 - HTML SHA-512/224 - HTML SHA-512/256 - HTML SHA3-224 1.0 - HTML - no lo |
| 27 | Fungsi hash / XOF | SHA-2 | SHA-512/256 | — | 128 bit | acceptable | FIPS 180-4 | link | [https://pages.nist.gov/ACVP/:105] 256 - HTML SHA-384 - HTML SHA-512 - HTML SHA-512/224 - HTML SHA-512/256 - HTML SHA3-224 1.0 - HTML - no longer supported by A |
| 28 | Fungsi hash / XOF | SHA-3 | SHA3-224 | — | 112 bit | acceptable | FIPS 202, ISO/IEC 10118-3 | link | [https://pages.nist.gov/ACVP/:106] - HTML SHA-512 - HTML SHA-512/224 - HTML SHA-512/256 - HTML SHA3-224 1.0 - HTML - no longer supported by ACVTS SHA3-256 1.0 - |
| 29 | Fungsi hash / XOF | SHA-3 | SHA3-256 | — | 128 bit | acceptable | FIPS 202, ISO/IEC 10118-3 | link | [https://pages.nist.gov/ACVP/:107] 6 - HTML SHA3-224 1.0 - HTML - no longer supported by ACVTS SHA3-256 1.0 - HTML - no longer supported by ACVTS SHA3-384 1.0 - |
| 30 | Fungsi hash / XOF | SHA-3 | SHA3-384 | — | 192 bit | acceptable | FIPS 202, ISO/IEC 10118-3 | link | [https://pages.nist.gov/ACVP/:108] by ACVTS SHA3-256 1.0 - HTML - no longer supported by ACVTS SHA3-384 1.0 - HTML - no longer supported by ACVTS SHA3-512 1.0 - |
| 31 | Fungsi hash / XOF | SHA-3 | SHA3-512 | — | 256 bit | acceptable | FIPS 202, ISO/IEC 10118-3 | link | [https://pages.nist.gov/ACVP/:109] by ACVTS SHA3-384 1.0 - HTML - no longer supported by ACVTS SHA3-512 1.0 - HTML - no longer supported by ACVTS SHA3-224 2.0 - |
| 32 | Fungsi hash / XOF | SHA-3 | SHAKE128 | — | 128 bit | acceptable | FIPS 202 | link | [https://pages.nist.gov/ACVP/:117] 12 2.0 - HTML XOFs Ascon-XOF128 - HTML Ascon-CXOF128 - HTML SHAKE-128 - HTML SHAKE-256 - HTML cSHAKE-128 - HTML cSHAKE-256 -  |
| 33 | Fungsi hash / XOF | SHA-3 | SHAKE256 | — | 256 bit | acceptable | FIPS 202 | link | [https://pages.nist.gov/ACVP/:118] s Ascon-XOF128 - HTML Ascon-CXOF128 - HTML SHAKE-128 - HTML SHAKE-256 - HTML cSHAKE-128 - HTML cSHAKE-256 - HTML KMAC-128 - H |
| 34 | Fungsi hash / XOF | SHA-3 | cSHAKE | 128 | 128 bit | acceptable | SP 800-185 | link | [https://pages.nist.gov/ACVP/:119] HTML Ascon-CXOF128 - HTML SHAKE-128 - HTML SHAKE-256 - HTML cSHAKE-128 - HTML cSHAKE-256 - HTML KMAC-128 - HTML KMAC-256 - HT |
| 35 | Fungsi hash / XOF | SHA-3 | cSHAKE | 256 | 256 bit | acceptable | SP 800-185 | link | [https://pages.nist.gov/ACVP/:120] - HTML SHAKE-128 - HTML SHAKE-256 - HTML cSHAKE-128 - HTML cSHAKE-256 - HTML KMAC-128 - HTML KMAC-256 - HTML ParallelHash-128 |
| 36 | Fungsi hash / XOF | TupleHash | TupleHash-128 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:125] -256 - HTML ParallelHash-128 - HTML ParallelHash-256 - HTML TupleHash-128 - HTML TupleHash-256 - HTML Message Authentication  |
| 37 | Fungsi hash / XOF | TupleHash | TupleHash-256 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:126] ash-128 - HTML ParallelHash-256 - HTML TupleHash-128 - HTML TupleHash-256 - HTML Message Authentication AES-CCM - HTML AES-GM |
| 38 | MAC / AEAD ringan | AES | CMAC | 256 | 256 bit | acceptable | FIPS 197, SP 800-38B, ISO/IEC 9797-1 | link | [https://pages.nist.gov/ACVP/:130] HTML Message Authentication AES-CCM - HTML AES-GMAC - HTML CMAC-AES - HTML CMAC-TDES - HTML HMAC-SHA-1 1.0 - HTML HMAC-SHA2-2 |
| 39 | MAC / AEAD ringan | AES | GMAC | 256 | 256 bit | acceptable | FIPS 197, SP 800-38D | link | [https://pages.nist.gov/ACVP/:129] TupleHash-256 - HTML Message Authentication AES-CCM - HTML AES-GMAC - HTML CMAC-AES - HTML CMAC-TDES - HTML HMAC-SHA-1 1.0 -  |
| 40 | MAC / AEAD ringan | Ascon | Ascon-AEAD128 | 128 | 128 bit | acceptable | SP 800-232 | link | [https://pages.nist.gov/ACVP/:83] -XTS 2.0 - HTML AES-FF1 - HTML AES-FF3-1 - HTML - DEMO only Ascon-AEAD128 - HTML TDES-CBC - HTML TDES-CBCI - HTML TDES-CFB1 -  |
| 41 | MAC / AEAD ringan | HMAC | SHA-1 | 128 | 128 bit | acceptable | FIPS 198-1, SP 800-107 Rev.1, ISO/IEC 9797-2 | link | [https://pages.nist.gov/ACVP/:132] CCM - HTML AES-GMAC - HTML CMAC-AES - HTML CMAC-TDES - HTML HMAC-SHA-1 1.0 - HTML HMAC-SHA2-224 1.0 - HTML HMAC-SHA2-256 1.0  |
| 42 | MAC / AEAD ringan | HMAC | SHA-224 | 224 | 224 bit | acceptable | FIPS 198-1, SP 800-107 Rev.1 | link | [https://pages.nist.gov/ACVP/:133] HTML CMAC-AES - HTML CMAC-TDES - HTML HMAC-SHA-1 1.0 - HTML HMAC-SHA2-224 1.0 - HTML HMAC-SHA2-256 1.0 - HTML HMAC-SHA2-384 1 |
| 43 | MAC / AEAD ringan | HMAC | SHA-256 | 256 | 256 bit | acceptable | FIPS 198-1, SP 800-107 Rev.1, ISO/IEC 9797-2 | link | [https://pages.nist.gov/ACVP/:134] -TDES - HTML HMAC-SHA-1 1.0 - HTML HMAC-SHA2-224 1.0 - HTML HMAC-SHA2-256 1.0 - HTML HMAC-SHA2-384 1.0 - HTML HMAC-SHA2-512 1 |
| 44 | MAC / AEAD ringan | HMAC | SHA-384 | 384 | 384 bit | acceptable | FIPS 198-1, SP 800-107 Rev.1 | link | [https://pages.nist.gov/ACVP/:135] .0 - HTML HMAC-SHA2-224 1.0 - HTML HMAC-SHA2-256 1.0 - HTML HMAC-SHA2-384 1.0 - HTML HMAC-SHA2-512 1.0 - HTML HMAC-SHA2-512/2 |
| 45 | MAC / AEAD ringan | HMAC | SHA-512 | 512 | 512 bit | acceptable | FIPS 198-1, SP 800-107 Rev.1 | link | [https://pages.nist.gov/ACVP/:136] .0 - HTML HMAC-SHA2-256 1.0 - HTML HMAC-SHA2-384 1.0 - HTML HMAC-SHA2-512 1.0 - HTML HMAC-SHA2-512/224 1.0 - HTML HMAC-SHA2-5 |
| 46 | MAC / AEAD ringan | HMAC | SHA-512/224 | 224 | 224 bit | acceptable | FIPS 198-1 | link | [https://pages.nist.gov/ACVP/:137] .0 - HTML HMAC-SHA2-384 1.0 - HTML HMAC-SHA2-512 1.0 - HTML HMAC-SHA2-512/224 1.0 - HTML HMAC-SHA2-512/256 1.0 - HTML HMAC-SH |
| 47 | MAC / AEAD ringan | HMAC | SHA-512/256 | 256 | 256 bit | acceptable | FIPS 198-1 | link | [https://pages.nist.gov/ACVP/:138] HTML HMAC-SHA2-512 1.0 - HTML HMAC-SHA2-512/224 1.0 - HTML HMAC-SHA2-512/256 1.0 - HTML HMAC-SHA3-224 1.0 - HTML HMAC-SHA3-25 |
| 48 | MAC / AEAD ringan | HMAC | SHA3-224 | 224 | 224 bit | acceptable | FIPS 198-1, FIPS 202 | link | [https://pages.nist.gov/ACVP/:139] L HMAC-SHA2-512/224 1.0 - HTML HMAC-SHA2-512/256 1.0 - HTML HMAC-SHA3-224 1.0 - HTML HMAC-SHA3-256 1.0 - HTML HMAC-SHA3-384 1 |
| 49 | MAC / AEAD ringan | HMAC | SHA3-256 | 256 | 256 bit | acceptable | FIPS 198-1, FIPS 202 | link | [https://pages.nist.gov/ACVP/:140] HTML HMAC-SHA2-512/256 1.0 - HTML HMAC-SHA3-224 1.0 - HTML HMAC-SHA3-256 1.0 - HTML HMAC-SHA3-384 1.0 - HTML HMAC-SHA3-512 1. |
| 50 | MAC / AEAD ringan | HMAC | SHA3-384 | 192 | 192 bit | acceptable | FIPS 198-1, FIPS 202 | link | [https://pages.nist.gov/ACVP/:152] .0 - HTML HMAC-SHA3-224 2.0 - HTML HMAC-SHA3-256 2.0 - HTML HMAC-SHA3-384 2.0 - HTML HMAC-SHA3-512 2.0 - HTML KMAC-128 - HTML |
| 51 | MAC / AEAD ringan | HMAC | SHA3-384 | 384 | 384 bit | acceptable | FIPS 198-1, FIPS 202 | link | [https://pages.nist.gov/ACVP/:141] .0 - HTML HMAC-SHA3-224 1.0 - HTML HMAC-SHA3-256 1.0 - HTML HMAC-SHA3-384 1.0 - HTML HMAC-SHA3-512 1.0 - HTML HMAC-SHA-1 2.0  |
| 52 | MAC / AEAD ringan | HMAC | SHA3-512 | 256 | 256 bit | acceptable | FIPS 198-1, FIPS 202 | link | [https://pages.nist.gov/ACVP/:142] .0 - HTML HMAC-SHA3-256 1.0 - HTML HMAC-SHA3-384 1.0 - HTML HMAC-SHA3-512 1.0 - HTML HMAC-SHA-1 2.0 - HTML HMAC-SHA2-224 2.0  |
| 53 | MAC / AEAD ringan | KMAC | KMAC | 128 | 128 bit | acceptable | SP 800-185 | link | [https://pages.nist.gov/ACVP/:121] - HTML SHAKE-256 - HTML cSHAKE-128 - HTML cSHAKE-256 - HTML KMAC-128 - HTML KMAC-256 - HTML ParallelHash-128 - HTML ParallelH |
| 54 | MAC / AEAD ringan | KMAC | KMAC | 256 | 256 bit | acceptable | SP 800-185 | link | [https://pages.nist.gov/ACVP/:122] - HTML cSHAKE-128 - HTML cSHAKE-256 - HTML KMAC-128 - HTML KMAC-256 - HTML ParallelHash-128 - HTML ParallelHash-256 - HTML Tu |
| 55 | PKC / KEM / key agreement | KAS | KAS ECC CDH-Component | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:236] KAS ECC OnePassUnified - HTML KAS ECC staticUnified - HTML KAS ECC CDH-Component - HTML KAS FFC dhHybrid1 - HTML KAS FFC mqv2 |
| 56 | PKC / KEM / key agreement | KAS | KAS ECC CDH-Component Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:211] Sp800-56Ar3 - HTML KAS ECC staticUnified Sp800-56Ar3 - HTML KAS ECC CDH-Component Sp800-56Ar3 - HTML KAS FFC dhHybrid1 Sp800- |
| 57 | PKC / KEM / key agreement | KAS | KAS ECC OnePassUnified | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:195] d - HTML KAS ECC onePassDh - HTML KAS ECC onePassMqv - HTML KAS ECC OnePassUnified - HTML KAS ECC staticUnified - HTML KAS FF |
| 58 | PKC / KEM / key agreement | KAS | KAS ECC OnePassUnified Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:209] Dh Sp800-56Ar3 - HTML KAS ECC onePassMqv Sp800-56Ar3 - HTML KAS ECC OnePassUnified Sp800-56Ar3 - HTML KAS ECC staticUnified S |
| 59 | PKC / KEM / key agreement | KAS | KAS ECC SSC OnePassUnified Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:249] p800-56Ar3 - HTML KAS ECC SSC onePassMqv Sp800-56Ar3 - HTML KAS ECC SSC OnePassUnified Sp800-56Ar3 - HTML KAS ECC SSC staticU |
| 60 | PKC / KEM / key agreement | KAS | KAS ECC SSC ephemeralUnified Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:244] qv1 - HTML KAS FFC dhOneFlow - HTML KAS FFC dhStatic - HTML KAS ECC SSC ephemeralUnified Sp800-56Ar3 - HTML KAS ECC SSC fullM |
| 61 | PKC / KEM / key agreement | KAS | KAS ECC SSC fullMqv Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:245] atic - HTML KAS ECC SSC ephemeralUnified Sp800-56Ar3 - HTML KAS ECC SSC fullMqv Sp800-56Ar3 - HTML KAS ECC SSC fullUnified Sp |
| 62 | PKC / KEM / key agreement | KAS | KAS ECC SSC fullUnified Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:246] d Sp800-56Ar3 - HTML KAS ECC SSC fullMqv Sp800-56Ar3 - HTML KAS ECC SSC fullUnified Sp800-56Ar3 - HTML KAS ECC SSC onePassDh  |
| 63 | PKC / KEM / key agreement | KAS | KAS ECC SSC onePassDh Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:247] 800-56Ar3 - HTML KAS ECC SSC fullUnified Sp800-56Ar3 - HTML KAS ECC SSC onePassDh Sp800-56Ar3 - HTML KAS ECC SSC onePassMqv S |
| 64 | PKC / KEM / key agreement | KAS | KAS ECC SSC onePassMqv Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:248] Sp800-56Ar3 - HTML KAS ECC SSC onePassDh Sp800-56Ar3 - HTML KAS ECC SSC onePassMqv Sp800-56Ar3 - HTML KAS ECC SSC OnePassUnif |
| 65 | PKC / KEM / key agreement | KAS | KAS ECC SSC staticUnified Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:250] -56Ar3 - HTML KAS ECC SSC OnePassUnified Sp800-56Ar3 - HTML KAS ECC SSC staticUnified Sp800-56Ar3 - HTML KAS FFC SSC dhHybrid |
| 66 | PKC / KEM / key agreement | KAS | KAS ECC ephemeralUnified | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:190] 0 component based tests) are considered "full KAS" testing. KAS ECC ephemeralUnified - HTML KAS ECC fullMqv - HTML KAS ECC fu |
| 67 | PKC / KEM / key agreement | KAS | KAS ECC ephemeralUnified Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:204] qv1 - HTML KAS FFC dhOneFlow - HTML KAS FFC dhStatic - HTML KAS ECC ephemeralUnified Sp800-56Ar3 - HTML KAS ECC fullMqv Sp800 |
| 68 | PKC / KEM / key agreement | KAS | KAS ECC fullMqv | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:191] sidered "full KAS" testing. KAS ECC ephemeralUnified - HTML KAS ECC fullMqv - HTML KAS ECC fullUnified - HTML KAS ECC onePass |
| 69 | PKC / KEM / key agreement | KAS | KAS ECC fullMqv Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:205] dhStatic - HTML KAS ECC ephemeralUnified Sp800-56Ar3 - HTML KAS ECC fullMqv Sp800-56Ar3 - HTML KAS ECC fullUnified Sp800-56Ar |
| 70 | PKC / KEM / key agreement | KAS | KAS ECC fullUnified | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:192] ing. KAS ECC ephemeralUnified - HTML KAS ECC fullMqv - HTML KAS ECC fullUnified - HTML KAS ECC onePassDh - HTML KAS ECC onePa |
| 71 | PKC / KEM / key agreement | KAS | KAS ECC fullUnified Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:206] ified Sp800-56Ar3 - HTML KAS ECC fullMqv Sp800-56Ar3 - HTML KAS ECC fullUnified Sp800-56Ar3 - HTML KAS ECC onePassDh Sp800-56 |
| 72 | PKC / KEM / key agreement | KAS | KAS ECC onePassDh | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:193] ed - HTML KAS ECC fullMqv - HTML KAS ECC fullUnified - HTML KAS ECC onePassDh - HTML KAS ECC onePassMqv - HTML KAS ECC OnePas |
| 73 | PKC / KEM / key agreement | KAS | KAS ECC onePassDh Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:207] v Sp800-56Ar3 - HTML KAS ECC fullUnified Sp800-56Ar3 - HTML KAS ECC onePassDh Sp800-56Ar3 - HTML KAS ECC onePassMqv Sp800-56A |
| 74 | PKC / KEM / key agreement | KAS | KAS ECC onePassMqv | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:194] - HTML KAS ECC fullUnified - HTML KAS ECC onePassDh - HTML KAS ECC onePassMqv - HTML KAS ECC OnePassUnified - HTML KAS ECC st |
| 75 | PKC / KEM / key agreement | KAS | KAS ECC onePassMqv Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:208] ied Sp800-56Ar3 - HTML KAS ECC onePassDh Sp800-56Ar3 - HTML KAS ECC onePassMqv Sp800-56Ar3 - HTML KAS ECC OnePassUnified Sp80 |
| 76 | PKC / KEM / key agreement | KAS | KAS ECC staticUnified | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:196] TML KAS ECC onePassMqv - HTML KAS ECC OnePassUnified - HTML KAS ECC staticUnified - HTML KAS FFC dhHybrid1 - HTML KAS FFC mqv |
| 77 | PKC / KEM / key agreement | KAS | KAS ECC staticUnified Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:210] p800-56Ar3 - HTML KAS ECC OnePassUnified Sp800-56Ar3 - HTML KAS ECC staticUnified Sp800-56Ar3 - HTML KAS ECC CDH-Component Sp |
| 78 | PKC / KEM / key agreement | KAS | KAS FFC SSC dhEphem Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:253] rid1 Sp800-56Ar3 - HTML KAS FFC SSC mqv2 Sp800-56Ar3 - HTML KAS FFC SSC dhEphem Sp800-56Ar3 - HTML KAS FFC SSC dhHybridOneFlo |
| 79 | PKC / KEM / key agreement | KAS | KAS FFC SSC dhHybrid1 Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:251] 0-56Ar3 - HTML KAS ECC SSC staticUnified Sp800-56Ar3 - HTML KAS FFC SSC dhHybrid1 Sp800-56Ar3 - HTML KAS FFC SSC mqv2 Sp800-5 |
| 80 | PKC / KEM / key agreement | KAS | KAS FFC SSC dhHybridOneFlow Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:254] 2 Sp800-56Ar3 - HTML KAS FFC SSC dhEphem Sp800-56Ar3 - HTML KAS FFC SSC dhHybridOneFlow Sp800-56Ar3 - HTML KAS FFC SSC mqv1 S |
| 81 | PKC / KEM / key agreement | KAS | KAS FFC SSC dhOneFlow Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:256] Flow Sp800-56Ar3 - HTML KAS FFC SSC mqv1 Sp800-56Ar3 - HTML KAS FFC SSC dhOneFlow Sp800-56Ar3 - HTML KAS FFC SSC dhStatic Sp8 |
| 82 | PKC / KEM / key agreement | KAS | KAS FFC SSC dhStatic Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:257] Sp800-56Ar3 - HTML KAS FFC SSC dhOneFlow Sp800-56Ar3 - HTML KAS FFC SSC dhStatic Sp800-56Ar3 - HTML KAS IFC SSC KAS1 Sp800-56 |
| 83 | PKC / KEM / key agreement | KAS | KAS FFC SSC mqv1 Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:255] 56Ar3 - HTML KAS FFC SSC dhHybridOneFlow Sp800-56Ar3 - HTML KAS FFC SSC mqv1 Sp800-56Ar3 - HTML KAS FFC SSC dhOneFlow Sp800-5 |
| 84 | PKC / KEM / key agreement | KAS | KAS FFC SSC mqv2 Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:252] Sp800-56Ar3 - HTML KAS FFC SSC dhHybrid1 Sp800-56Ar3 - HTML KAS FFC SSC mqv2 Sp800-56Ar3 - HTML KAS FFC SSC dhEphem Sp800-56A |
| 85 | PKC / KEM / key agreement | KAS | KAS FFC dhEphem | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:199] Unified - HTML KAS FFC dhHybrid1 - HTML KAS FFC mqv2 - HTML KAS FFC dhEphem - HTML KAS FFC dhHybridOneFlow - HTML KAS FFC mqv |
| 86 | PKC / KEM / key agreement | KAS | KAS FFC dhEphem Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:214] hHybrid1 Sp800-56Ar3 - HTML KAS FFC mqv2 Sp800-56Ar3 - HTML KAS FFC dhEphem Sp800-56Ar3 - HTML KAS FFC dhHybridOneFlow Sp800- |
| 87 | PKC / KEM / key agreement | KAS | KAS FFC dhHybrid1 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:197] KAS ECC OnePassUnified - HTML KAS ECC staticUnified - HTML KAS FFC dhHybrid1 - HTML KAS FFC mqv2 - HTML KAS FFC dhEphem - HTM |
| 88 | PKC / KEM / key agreement | KAS | KAS FFC dhHybrid1 Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:212] Sp800-56Ar3 - HTML KAS ECC CDH-Component Sp800-56Ar3 - HTML KAS FFC dhHybrid1 Sp800-56Ar3 - HTML KAS FFC mqv2 Sp800-56Ar3 - H |
| 89 | PKC / KEM / key agreement | KAS | KAS FFC dhHybridOneFlow | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:200] dhHybrid1 - HTML KAS FFC mqv2 - HTML KAS FFC dhEphem - HTML KAS FFC dhHybridOneFlow - HTML KAS FFC mqv1 - HTML KAS FFC dhOneF |
| 90 | PKC / KEM / key agreement | KAS | KAS FFC dhHybridOneFlow Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:215] mqv2 Sp800-56Ar3 - HTML KAS FFC dhEphem Sp800-56Ar3 - HTML KAS FFC dhHybridOneFlow Sp800-56Ar3 - HTML KAS FFC mqv1 Sp800-56Ar |
| 91 | PKC / KEM / key agreement | KAS | KAS FFC dhOneFlow | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:202] m - HTML KAS FFC dhHybridOneFlow - HTML KAS FFC mqv1 - HTML KAS FFC dhOneFlow - HTML KAS FFC dhStatic - HTML KAS ECC ephemera |
| 92 | PKC / KEM / key agreement | KAS | KAS FFC dhOneFlow Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:217] dOneFlow Sp800-56Ar3 - HTML KAS FFC mqv1 Sp800-56Ar3 - HTML KAS FFC dhOneFlow Sp800-56Ar3 - HTML KAS FFC dhStatic Sp800-56Ar3 |
| 93 | PKC / KEM / key agreement | KAS | KAS FFC dhStatic | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:203] OneFlow - HTML KAS FFC mqv1 - HTML KAS FFC dhOneFlow - HTML KAS FFC dhStatic - HTML KAS ECC ephemeralUnified Sp800-56Ar3 - HT |
| 94 | PKC / KEM / key agreement | KAS | KAS FFC dhStatic Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:218] qv1 Sp800-56Ar3 - HTML KAS FFC dhOneFlow Sp800-56Ar3 - HTML KAS FFC dhStatic Sp800-56Ar3 - HTML KAS IFC KAS1-basic - HTML KAS |
| 95 | PKC / KEM / key agreement | KAS | KAS FFC mqv1 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:201] HTML KAS FFC dhEphem - HTML KAS FFC dhHybridOneFlow - HTML KAS FFC mqv1 - HTML KAS FFC dhOneFlow - HTML KAS FFC dhStatic - HT |
| 96 | PKC / KEM / key agreement | KAS | KAS FFC mqv1 Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:216] 800-56Ar3 - HTML KAS FFC dhHybridOneFlow Sp800-56Ar3 - HTML KAS FFC mqv1 Sp800-56Ar3 - HTML KAS FFC dhOneFlow Sp800-56Ar3 - H |
| 97 | PKC / KEM / key agreement | KAS | KAS FFC mqv2 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:198] HTML KAS ECC staticUnified - HTML KAS FFC dhHybrid1 - HTML KAS FFC mqv2 - HTML KAS FFC dhEphem - HTML KAS FFC dhHybridOneFlow |
| 98 | PKC / KEM / key agreement | KAS | KAS FFC mqv2 Sp800-56Ar3 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:213] ent Sp800-56Ar3 - HTML KAS FFC dhHybrid1 Sp800-56Ar3 - HTML KAS FFC mqv2 Sp800-56Ar3 - HTML KAS FFC dhEphem Sp800-56Ar3 - HTM |
| 99 | PKC / KEM / key agreement | KAS | KAS IFC KAS1-Party_V-confirmation | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:220] S FFC dhStatic Sp800-56Ar3 - HTML KAS IFC KAS1-basic - HTML KAS IFC KAS1-Party_V-confirmation - HTML KAS IFC KAS2-basic - HTM |
| 100 | PKC / KEM / key agreement | KAS | KAS IFC KAS1-basic | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:219] Flow Sp800-56Ar3 - HTML KAS FFC dhStatic Sp800-56Ar3 - HTML KAS IFC KAS1-basic - HTML KAS IFC KAS1-Party_V-confirmation - HTM |
| 101 | PKC / KEM / key agreement | KAS | KAS IFC KAS2-Party_U-confirmation | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:223] AS2-basic - HTML KAS IFC KAS2-bilateral-confirmation - HTML KAS IFC KAS2-Party_U-confirmation - HTML KAS IFC KAS2-Party_V-con |
| 102 | PKC / KEM / key agreement | KAS | KAS IFC KAS2-Party_V-confirmation | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:224] onfirmation - HTML KAS IFC KAS2-Party_U-confirmation - HTML KAS IFC KAS2-Party_V-confirmation - HTML KTS IFC KTS-OAEP-basic - |
| 103 | PKC / KEM / key agreement | KAS | KAS IFC KAS2-basic | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:221] KAS1-basic - HTML KAS IFC KAS1-Party_V-confirmation - HTML KAS IFC KAS2-basic - HTML KAS IFC KAS2-bilateral-confirmation - HT |
| 104 | PKC / KEM / key agreement | KAS | KAS IFC KAS2-bilateral-confirmation | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:222] KAS1-Party_V-confirmation - HTML KAS IFC KAS2-basic - HTML KAS IFC KAS2-bilateral-confirmation - HTML KAS IFC KAS2-Party_U-co |
| 105 | PKC / KEM / key agreement | KAS | KAS IFC SSC KAS1 Sp800-56Br2 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:258] Sp800-56Ar3 - HTML KAS FFC SSC dhStatic Sp800-56Ar3 - HTML KAS IFC SSC KAS1 Sp800-56Br2 - HTML KAS IFC SSC KAS2 Sp800-56Br2 - |
| 106 | PKC / KEM / key agreement | KAS | KAS IFC SSC KAS2 Sp800-56Br2 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:259] atic Sp800-56Ar3 - HTML KAS IFC SSC KAS1 Sp800-56Br2 - HTML KAS IFC SSC KAS2 Sp800-56Br2 - HTML KDA Testing SP800-56Cr1/r2 St |
| 107 | PKC / KEM / key agreement | RSA | PKCS1-v1_5-ENC | 1024 | 80 bit | disallowed | RFC 8017, SP 800-131A Rev.2 | link | [https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program:106] 0-56A), ECDSA Signature (FIPS 186-4), KDF (SP 800-135), RSA PKCS1-v1.5 RSASP1 (F |
| 108 | PKC / KEM / key agreement | RSA | PKCS1-v1_5-ENC | 2048 | 112 bit | disallowed | RFC 8017, SP 800-131A Rev.2 | link | [https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program:106] 0-56A), ECDSA Signature (FIPS 186-4), KDF (SP 800-135), RSA PKCS1-v1.5 RSASP1 (F |
| 109 | PKC / KEM / key agreement | RSA | PKCS1-v1_5-ENC | 3072 | 128 bit | disallowed | RFC 8017, SP 800-131A Rev.2 | link | [https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program:106] 0-56A), ECDSA Signature (FIPS 186-4), KDF (SP 800-135), RSA PKCS1-v1.5 RSASP1 (F |
| 110 | PKC / KEM / key agreement | RSA | PKCS1-v1_5-ENC | 4096 | 152 bit | disallowed | RFC 8017, SP 800-131A Rev.2 | link | [https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program:106] 0-56A), ECDSA Signature (FIPS 186-4), KDF (SP 800-135), RSA PKCS1-v1.5 RSASP1 (F |
| 111 | PKC / KEM / key agreement | RSA | PKCS1-v1_5-ENC | 7680 | 192 bit | disallowed | RFC 8017, SP 800-131A Rev.2 | link | [https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program:106] 0-56A), ECDSA Signature (FIPS 186-4), KDF (SP 800-135), RSA PKCS1-v1.5 RSASP1 (F |
| 112 | PKC / KEM / key agreement | RSA | PKCS1-v1_5-ENC | 15360 | 256 bit | disallowed | RFC 8017, SP 800-131A Rev.2 | link | [https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program:106] 0-56A), ECDSA Signature (FIPS 186-4), KDF (SP 800-135), RSA PKCS1-v1.5 RSASP1 (F |
| 113 | PKC / KEM / key agreement | SafePrimes | SafePrimes KeyGen | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:295] .42 (Component) - HTML PBKDF - HTML SPDM - HTML Safe Primes SafePrimes KeyGen - HTML SafePrimes KeyVer - HTML Conditioning Co |
| 114 | PKC / KEM / key agreement | SafePrimes | SafePrimes KeyVer | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:296] KDF - HTML SPDM - HTML Safe Primes SafePrimes KeyGen - HTML SafePrimes KeyVer - HTML Conditioning Components ConditioningComp |
| 115 | PKC / KEM / key agreement | XECDH | X25519 | 255 | 128 bit | PERLU_VERIFIKASI | RFC 7748, SP 800-186 | link | [https://pages.nist.gov/ACVP/:24] RBGs Digital Signature SP 800-56 Series Algorithms RFC 7748 curve25519 and curve448 KDFs Safe Primes Conditioning Components S |
| 116 | PKC / KEM / key agreement | XECDH | X448 | 448 | 224 bit | PERLU_VERIFIKASI | RFC 7748, SP 800-186 | link | [https://pages.nist.gov/ACVP/:24] gnature SP 800-56 Series Algorithms RFC 7748 curve25519 and curve448 KDFs Safe Primes Conditioning Components Stateful Hash-Ba |
| 117 | Tanda tangan digital | RSA | PKCS1-v1_5-SIG | 2048 | 112 bit | acceptable | FIPS 186-5, RFC 8017 | link | [https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program:106] 0-56A), ECDSA Signature (FIPS 186-4), KDF (SP 800-135), RSA PKCS1-v1.5 RSASP1 (F |
| 118 | Tanda tangan digital | RSA | PKCS1-v1_5-SIG | 3072 | 128 bit | acceptable | FIPS 186-5, RFC 8017 | link | [https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program:106] 0-56A), ECDSA Signature (FIPS 186-4), KDF (SP 800-135), RSA PKCS1-v1.5 RSASP1 (F |
| 119 | Tanda tangan digital | RSA | PKCS1-v1_5-SIG | 4096 | 152 bit | acceptable | FIPS 186-5, RFC 8017 | link | [https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program:106] 0-56A), ECDSA Signature (FIPS 186-4), KDF (SP 800-135), RSA PKCS1-v1.5 RSASP1 (F |
| 120 | DRBG | DRBG | CTR_DRBG | 128 | 128 bit | acceptable | SP 800-90A Rev.1, ISO/IEC 18031 | link | [https://pages.nist.gov/ACVP/:157] C-SHA3-512 2.0 - HTML KMAC-128 - HTML KMAC-256 - HTML DRBGs ctrDRBG-AES-128 - HTML ctrDRBG-AES-192 - HTML ctrDRBG-AES-256 - H |
| 121 | DRBG | DRBG | CTR_DRBG | 192 | 192 bit | acceptable | SP 800-90A Rev.1, ISO/IEC 18031 | link | [https://pages.nist.gov/ACVP/:158] MAC-128 - HTML KMAC-256 - HTML DRBGs ctrDRBG-AES-128 - HTML ctrDRBG-AES-192 - HTML ctrDRBG-AES-256 - HTML ctrDRBG-TDES - HTML |
| 122 | DRBG | DRBG | CTR_DRBG | 256 | 256 bit | acceptable | SP 800-90A Rev.1, ISO/IEC 18031 | link | [https://pages.nist.gov/ACVP/:159] - HTML DRBGs ctrDRBG-AES-128 - HTML ctrDRBG-AES-192 - HTML ctrDRBG-AES-256 - HTML ctrDRBG-TDES - HTML HASH DRBG - HTML HMAC D |
| 123 | DRBG | DRBG | HMAC_DRBG | 256 | 256 bit | acceptable | SP 800-90A Rev.1, ISO/IEC 18031 | link | [https://pages.nist.gov/ACVP/:162] ctrDRBG-AES-256 - HTML ctrDRBG-TDES - HTML HASH DRBG - HTML HMAC DRBG - HTML Digital Signature RSA mode: keyGen - HTML RSA mo |
| 124 | DRBG | DRBG | Hash_DRBG | 256 | 256 bit | acceptable | SP 800-90A Rev.1, ISO/IEC 18031 | link | [https://pages.nist.gov/ACVP/:161] G-AES-192 - HTML ctrDRBG-AES-256 - HTML ctrDRBG-TDES - HTML HASH DRBG - HTML HMAC DRBG - HTML Digital Signature RSA mode: key |
| 125 | KDF | ConditioningComponent | ConditioningComponent BlockCipher_DF | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:299] tioning Components ConditioningComponent AES-CBC-MAC - HTML ConditioningComponent BlockCipher_DF - HTML ConditioningComponent |
| 126 | KDF | ConditioningComponent | ConditioningComponent Hash_DF | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:300] -CBC-MAC - HTML ConditioningComponent BlockCipher_DF - HTML ConditioningComponent Hash_DF - HTML Stateful Hash-Based Signatur |
| 127 | KDF | KDA | KDA OneStep Sp800-56Cr1 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:263] red a valid KAS implementation. KDA HKDF Sp800-56Cr1 - HTML KDA OneStep Sp800-56Cr1 - HTML KDA TwoStep Sp800-56Cr1 - HTML KDA |
| 128 | KDF | KDA | KDA OneStep Sp800-56Cr2 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:266] KDA TwoStep Sp800-56Cr1 - HTML KDA HKDF Sp800-56Cr2 - HTML KDA OneStep Sp800-56Cr2 - HTML KDA OneStepNoCounter Sp800-56Cr2 -  |
| 129 | KDF | KDA | KDA OneStepNoCounter Sp800-56Cr2 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:267] KDA HKDF Sp800-56Cr2 - HTML KDA OneStep Sp800-56Cr2 - HTML KDA OneStepNoCounter Sp800-56Cr2 - HTML KDA TwoStep Sp800-56Cr2 -  |
| 130 | KDF | KDA | KDA TwoStep Sp800-56Cr1 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:264] KDA HKDF Sp800-56Cr1 - HTML KDA OneStep Sp800-56Cr1 - HTML KDA TwoStep Sp800-56Cr1 - HTML KDA HKDF Sp800-56Cr2 - HTML KDA One |
| 131 | KDF | KDA | KDA TwoStep Sp800-56Cr2 | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:268] Sp800-56Cr2 - HTML KDA OneStepNoCounter Sp800-56Cr2 - HTML KDA TwoStep Sp800-56Cr2 - HTML KAS KC Testing SP800-56 Standalone  |
| 132 | KDF | KDF | HKDF | — | PERLU_VERIFIKASI | acceptable | SP 800-56C Rev.2, RFC 5869 | link | [https://pages.nist.gov/ACVP/:262] KAS" testing) to be considered a valid KAS implementation. KDA HKDF Sp800-56Cr1 - HTML KDA OneStep Sp800-56Cr1 - HTML KDA Two |
| 133 | KDF | KDF | PBKDF2 | — | PERLU_VERIFIKASI | acceptable | SP 800-132, RFC 8018 | link | [https://pages.nist.gov/ACVP/:292] TML ANSX9.63 (Component) - HTML ANSX9.42 (Component) - HTML PBKDF - HTML SPDM - HTML Safe Primes SafePrimes KeyGen - HTML Saf |
| 134 | KDF | KDF | SP800-108-Counter | — | PERLU_VERIFIKASI | acceptable | SP 800-108 Rev.1 | link | [https://pages.nist.gov/ACVP/:277] CDH keyGen - HTML XECDH keyVer - HTML XECDH SSC - HTML KDFs Counter KDF - HTML Feedback KDF - HTML Double Pipeline Iterator K |
| 135 | KDF | KDF | SP800-108-DoublePipeline | — | PERLU_VERIFIKASI | acceptable | SP 800-108 Rev.1 | link | [https://pages.nist.gov/ACVP/:279] ECDH SSC - HTML KDFs Counter KDF - HTML Feedback KDF - HTML Double Pipeline Iterator KDF - HTML KMAC KDF - HTML IKEv1 (Compon |
| 136 | KDF | KDF | SP800-108-Feedback | — | PERLU_VERIFIKASI | acceptable | SP 800-108 Rev.1 | link | [https://pages.nist.gov/ACVP/:278] ECDH keyVer - HTML XECDH SSC - HTML KDFs Counter KDF - HTML Feedback KDF - HTML Double Pipeline Iterator KDF - HTML KMAC KDF  |
| 137 | KDF | SPDM | SPDM | — | PERLU_VERIFIKASI | PERLU_VERIFIKASI | NIST ACVP specification | link | [https://pages.nist.gov/ACVP/:293] (Component) - HTML ANSX9.42 (Component) - HTML PBKDF - HTML SPDM - HTML Safe Primes SafePrimes KeyGen - HTML SafePrimes KeyV |

## Peringatan otomatis

| Tingkat | Kode | Pesan |
|---|---|---|
| INFO | PERLU_VERIFIKASI | ACVP-AES-XPN: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | AES-128-FF3-1: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | AES-128-GCM-SIV: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| TINGGI | STATUS_DISALLOWED | TDEA-3KEY: status NIST disallowed (SP 800-131A Rev.2) |
| INFO | PERLU_VERIFIKASI | ACVP-PARALLELHASH-128: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-PARALLELHASH-256: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| TINGGI | STATUS_DISALLOWED | SHA-1: status NIST disallowed (SP 800-131A Rev.2) |
| TINGGI | STRENGTH_LT_112 | SHA-1: security strength <80 bit < 112 bit (SP 800-57 Pt.1) |
| INFO | PERLU_VERIFIKASI | ACVP-TUPLEHASH-128: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-TUPLEHASH-256: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-CDH-COMPONENT: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-CDH-COMPONENT-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-ONEPASSUNIFIED: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-ONEPASSUNIFIED-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-SSC-ONEPASSUNIFIED-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-SSC-EPHEMERALUNIFIED-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-SSC-FULLMQV-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-SSC-FULLUNIFIED-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-SSC-ONEPASSDH-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-SSC-ONEPASSMQV-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-SSC-STATICUNIFIED-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-EPHEMERALUNIFIED: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-EPHEMERALUNIFIED-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-FULLMQV: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-FULLMQV-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-FULLUNIFIED: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-FULLUNIFIED-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-ONEPASSDH: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-ONEPASSDH-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-ONEPASSMQV: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-ONEPASSMQV-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-STATICUNIFIED: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-ECC-STATICUNIFIED-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-SSC-DHEPHEM-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-SSC-DHHYBRID1-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-SSC-DHHYBRIDONEFLOW-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-SSC-DHONEFLOW-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-SSC-DHSTATIC-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-SSC-MQV1-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-SSC-MQV2-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-DHEPHEM: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-DHEPHEM-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-DHHYBRID1: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-DHHYBRID1-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-DHHYBRIDONEFLOW: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-DHHYBRIDONEFLOW-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-DHONEFLOW: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-DHONEFLOW-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-DHSTATIC: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-DHSTATIC-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-MQV1: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-MQV1-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-MQV2: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-FFC-MQV2-SP800-56AR3: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-IFC-KAS1-PARTY-V-CONFIRMATION: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-IFC-KAS1-BASIC: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-IFC-KAS2-PARTY-U-CONFIRMATION: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-IFC-KAS2-PARTY-V-CONFIRMATION: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-IFC-KAS2-BASIC: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-IFC-KAS2-BILATERAL-CONFIRMATION: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-IFC-SSC-KAS1-SP800-56BR2: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KAS-IFC-SSC-KAS2-SP800-56BR2: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| TINGGI | STATUS_DISALLOWED | RSAES-PKCS1-V1_5-1024: status NIST disallowed (SP 800-131A Rev.2) |
| TINGGI | STRENGTH_LT_112 | RSAES-PKCS1-V1_5-1024: security strength 80 bit < 112 bit (SP 800-57 Pt.1) |
| SEDANG | QUANTUM_VULNERABLE | RSAES-PKCS1-V1_5-1024: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| TINGGI | STATUS_DISALLOWED | RSAES-PKCS1-V1_5-2048: status NIST disallowed (SP 800-131A Rev.2) |
| SEDANG | QUANTUM_VULNERABLE | RSAES-PKCS1-V1_5-2048: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| TINGGI | STATUS_DISALLOWED | RSAES-PKCS1-V1_5-3072: status NIST disallowed (SP 800-131A Rev.2) |
| SEDANG | QUANTUM_VULNERABLE | RSAES-PKCS1-V1_5-3072: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| TINGGI | STATUS_DISALLOWED | RSAES-PKCS1-V1_5-4096: status NIST disallowed (SP 800-131A Rev.2) |
| SEDANG | QUANTUM_VULNERABLE | RSAES-PKCS1-V1_5-4096: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| TINGGI | STATUS_DISALLOWED | RSAES-PKCS1-V1_5-7680: status NIST disallowed (SP 800-131A Rev.2) |
| SEDANG | QUANTUM_VULNERABLE | RSAES-PKCS1-V1_5-7680: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| TINGGI | STATUS_DISALLOWED | RSAES-PKCS1-V1_5-15360: status NIST disallowed (SP 800-131A Rev.2) |
| SEDANG | QUANTUM_VULNERABLE | RSAES-PKCS1-V1_5-15360: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| INFO | PERLU_VERIFIKASI | ACVP-SAFEPRIMES-KEYGEN: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-SAFEPRIMES-KEYVER: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| SEDANG | QUANTUM_VULNERABLE | X25519: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| INFO | PERLU_VERIFIKASI | X25519: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| SEDANG | QUANTUM_VULNERABLE | X448: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| INFO | PERLU_VERIFIKASI | X448: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| SEDANG | QUANTUM_VULNERABLE | RSASSA-PKCS1-V1_5-2048: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| SEDANG | QUANTUM_VULNERABLE | RSASSA-PKCS1-V1_5-3072: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| SEDANG | QUANTUM_VULNERABLE | RSASSA-PKCS1-V1_5-4096: rentan kuantum — NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205 |
| INFO | PERLU_VERIFIKASI | ACVP-CONDITIONINGCOMPONENT-BLOCKCIPHER-DF: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-CONDITIONINGCOMPONENT-HASH-DF: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KDA-ONESTEP-SP800-56CR1: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KDA-ONESTEP-SP800-56CR2: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KDA-ONESTEPNOCOUNTER-SP800-56CR2: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KDA-TWOSTEP-SP800-56CR1: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-KDA-TWOSTEP-SP800-56CR2: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | HKDF: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | PBKDF2: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | KDF108-COUNTER: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | KDF108-DOUBLE-PIPELINE: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | KDF108-FEEDBACK: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |
| INFO | PERLU_VERIFIKASI | ACVP-SPDM: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer |

## Tautan ke UK-1

Berkas ini ditautkan ke `config/product_profile.yaml` (`algorithms_under_test`).
Profil UK-1 tersedia untuk: config/profiles/aes128.yaml, config/profiles/sha3_256.yaml.
Kombinasi tanpa profil UK-1 (135): ACVP-AES-XPN, AES-128-CBC, AES-256-CCM, AES-128-CFB1, AES-128-CFB8, AES-128-ECB, AES-128-FF1, AES-128-FF3-1, AES-128-GCM, AES-128-GCM-SIV, AES-128-KW, AES-128-KWP, AES-128-OFB, TDEA-3KEY, ASCON-CXOF128, ASCON-HASH256, ASCON-XOF128, ACVP-PARALLELHASH-128, ACVP-PARALLELHASH-256, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-384, SHA3-512, SHAKE128, SHAKE256, cSHAKE128, cSHAKE256, ACVP-TUPLEHASH-128, ACVP-TUPLEHASH-256, CMAC-AES-256, GMAC-AES-256, ASCON-AEAD128, HMAC-SHA-1-K128, HMAC-SHA-224-K224 …

## Kandidat belum dikonfirmasi (tidak masuk daftar akhir)

| ID | Keyakinan | Bukti |
|---|---|---|
| AES-128-CFB128 | 0.4 | [https://pages.nist.gov/ACVP/:70] Cipher Modes AES-CBC - HTML AES-CFB1 - HTML AES-CFB8 - HTML AES-CFB128 - HTML AES-CTR - HTML AES-ECB - HTML AES-GCM - HTML AES |
| AES-192-CBC | 0.4 | [https://pages.nist.gov/ACVP/:298] KeyVer - HTML Conditioning Components ConditioningComponent AES-CBC-MAC - HTML ConditioningComponent BlockCipher_DF - HTML Co |
| AES-192-CFB128 | 0.4 | [https://pages.nist.gov/ACVP/:70] Cipher Modes AES-CBC - HTML AES-CFB1 - HTML AES-CFB8 - HTML AES-CFB128 - HTML AES-CTR - HTML AES-ECB - HTML AES-GCM - HTML AES |
| AES-256-CBC | 0.4 | [https://pages.nist.gov/ACVP/:298] KeyVer - HTML Conditioning Components ConditioningComponent AES-CBC-MAC - HTML ConditioningComponent BlockCipher_DF - HTML Co |
| AES-256-CFB128 | 0.4 | [https://pages.nist.gov/ACVP/:70] Cipher Modes AES-CBC - HTML AES-CFB1 - HTML AES-CFB8 - HTML AES-CFB128 - HTML AES-CTR - HTML AES-ECB - HTML AES-GCM - HTML AES |
| GMAC-AES-128 | 0.4 | [https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program:87] CBC, CFB and OFB modes. Block Cipher Modes CCM, CMAC, GCM / GMAC / XPN, Key Wrap, |
| GMAC-AES-192 | 0.4 | [https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program:87] CBC, CFB and OFB modes. Block Cipher Modes CCM, CMAC, GCM / GMAC / XPN, Key Wrap, |
| HMAC-SHA-1-K160 | 0.4 | [https://pages.nist.gov/ACVP/:143] .0 - HTML HMAC-SHA3-384 1.0 - HTML HMAC-SHA3-512 1.0 - HTML HMAC-SHA-1 2.0 - HTML HMAC-SHA2-224 2.0 - HTML HMAC-SHA2-256 2.0  |
| LMS-HSS-N192 | 0.4 | [https://pages.nist.gov/ACVP/:302] ningComponent Hash_DF - HTML Stateful Hash-Based Signatures LMS keyGen - HTML LMS sigGen - HTML LMS sigVer - HTML Stateless |
| LMS-HSS-N256 | 0.4 | [https://pages.nist.gov/ACVP/:302] ningComponent Hash_DF - HTML Stateful Hash-Based Signatures LMS keyGen - HTML LMS sigGen - HTML LMS sigVer - HTML Stateless |
| RSA-OAEP-1024 | 0.4 | [https://pages.nist.gov/ACVP/:225] ion - HTML KAS IFC KAS2-Party_V-confirmation - HTML KTS IFC KTS-OAEP-basic - HTML KTS IFC KTS-OAEP-Party_V-confirmation - HTM |
| RSA-OAEP-15360 | 0.4 | [https://pages.nist.gov/ACVP/:225] ion - HTML KAS IFC KAS2-Party_V-confirmation - HTML KTS IFC KTS-OAEP-basic - HTML KTS IFC KTS-OAEP-Party_V-confirmation - HTM |
| RSA-OAEP-2048 | 0.4 | [https://pages.nist.gov/ACVP/:225] ion - HTML KAS IFC KAS2-Party_V-confirmation - HTML KTS IFC KTS-OAEP-basic - HTML KTS IFC KTS-OAEP-Party_V-confirmation - HTM |
| RSA-OAEP-3072 | 0.4 | [https://pages.nist.gov/ACVP/:225] ion - HTML KAS IFC KAS2-Party_V-confirmation - HTML KTS IFC KTS-OAEP-basic - HTML KTS IFC KTS-OAEP-Party_V-confirmation - HTM |
| RSA-OAEP-4096 | 0.4 | [https://pages.nist.gov/ACVP/:225] ion - HTML KAS IFC KAS2-Party_V-confirmation - HTML KTS IFC KTS-OAEP-basic - HTML KTS IFC KTS-OAEP-Party_V-confirmation - HTM |
| RSA-OAEP-7680 | 0.4 | [https://pages.nist.gov/ACVP/:225] ion - HTML KAS IFC KAS2-Party_V-confirmation - HTML KTS IFC KTS-OAEP-basic - HTML KTS IFC KTS-OAEP-Party_V-confirmation - HTM |
| XTS-AES-256 | 0.4 | [https://pages.nist.gov/ACVP/:79] AES-KW - HTML AES-KWP - HTML AES-OFB - HTML AES-XPN - HTML AES-XTS 1.0 - HTML - no longer supported by ACVTS AES-XTS 2.0 - HTM |
| XTS-AES-512 | 0.4 | [https://pages.nist.gov/ACVP/:79] AES-KW - HTML AES-KWP - HTML AES-OFB - HTML AES-XPN - HTML AES-XTS 1.0 - HTML - no longer supported by ACVTS AES-XTS 2.0 - HTM |
