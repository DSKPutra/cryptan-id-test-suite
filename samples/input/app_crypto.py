"""Contoh source code produk (ILUSTRATIF) — Python hashlib / pyca cryptography."""
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding

def fingerprint(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()

def legacy_checksum(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()          # hanya kompatibilitas

def sign_ecdsa(data: bytes):
    key = ec.generate_private_key(ec.SECP384R1())   # kunci tanda tangan ECDSA
    return key.sign(data, ec.ECDSA(hashes.SHA384()))

def sign_ed25519(data: bytes):
    return ed25519.Ed25519PrivateKey.generate().sign(data)
