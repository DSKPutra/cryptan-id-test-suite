"""Cryptan.ID Test Suite — core/

Implementasi referensi algoritma (pure Python) + utilitas analisis bersama
yang dipakai oleh seluruh modul UK (UK-1 s.d. UK-8).

Algoritma yang didukung (satu per kelas primitif):
  - Block cipher   : AES-128        (core.aes)        — FIPS 197
  - Stream cipher  : ChaCha20       (core.chacha20)   — RFC 8439
  - Fungsi hash    : SHA3-256       (core.keccak)     — FIPS 202
  - PKC            : RSA-OAEP-2048  (core.rsa_oaep)   — SP 800-56B / ISO/IEC 18033-2
  - Tanda tangan   : ECDSA P-256    (core.ecdsa_p256) — FIPS 186-5 / SP 800-186

CATATAN KEAMANAN: implementasi ini untuk keperluan praktikum/pengujian
(referensi & analisis). Tidak constant-time dan TIDAK untuk produksi.
"""

__version__ = "1.0.0"
APP_NAME = "Cryptan.ID Test Suite"
