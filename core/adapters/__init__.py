"""Adapter implementasi kriptografi — satu-satunya jalan mesin uji (std_report) ke implementasi.

Backend:
  pyca     — pyca/cryptography (OpenSSL)
  pycrypto — pycryptodome
  stdlib   — hashlib / hmac (OpenSSL melalui CPython)
  core     — implementasi referensi Cryptan.ID (core/, pure Python, independen dari OpenSSL)
  oqs      — liboqs-python (opsional, PQC)

`backends_for(row)` mengembalikan daftar adapter yang mendukung satu kombinasi katalog
(baris algo_catalog: id, family, variant, key_bits, primitive). Setiap adapter punya `kind`:
  cipher · aead · mac · hash · xof · rsa_pke · kem · kex · sig · kdf · prime
Operasi yang tidak didukung melempar NotSupported.
"""
from .base import KIND, NotSupported, kind_of  # noqa: F401
from . import pyca, pycrypto, stdlib, core_ref, oqs_be

BACKENDS = [pyca, pycrypto, stdlib, core_ref, oqs_be]


def backends_for(row: dict) -> list:
    out = []
    for b in BACKENDS:
        try:
            a = b.get(row)
        except NotSupported:
            a = None
        except Exception:                          # backend rusak/tidak terpasang → tidak tersedia
            a = None
        if a is not None:
            out.append(a)
    return out


def versions() -> dict:
    v = {}
    for b in BACKENDS:
        try:
            v[b.NAME] = b.version()
        except Exception as e:                     # pragma: no cover
            v[b.NAME] = f"tidak tersedia ({type(e).__name__})"
    return v
