"""Tipe dasar adapter."""

KIND = ["cipher", "aead", "mac", "hash", "xof", "rsa_pke", "kem", "kex", "sig", "kdf", "prime", "none"]
AEAD_VARIANTS = {"GCM", "CCM", "GCM-SIV"}
MAC_VARIANTS = {"CMAC", "GMAC"}


class NotSupported(Exception):
    pass


def kind_of(row: dict) -> str:
    prim, fam, var = row["primitive"], row.get("family", ""), row.get("variant", "")
    if prim == "block_cipher":
        return "aead" if var in AEAD_VARIANTS else "cipher"
    if prim == "mac":
        return "mac"
    if prim == "hash":
        return "xof" if var.startswith(("SHAKE", "cSHAKE")) or "XOF" in var else "hash"
    if prim == "pkc_kem":
        if fam == "RSA":
            return "rsa_pke"
        if fam == "ML-KEM":
            return "kem"
        if fam in ("ECDH", "XECDH", "FFDH"):
            return "kex"
        if fam == "PrimeGen":
            return "prime"
        return "none"
    if prim == "signature":
        return "sig"
    if prim == "kdf":
        return "kdf"
    return "none"


class Adapter:
    """Basis adapter. Subkelas mengisi metode sesuai `kind`."""
    backend = "?"

    def __init__(self, row: dict, kind: str):
        self.row, self.kind = row, kind
        self.key_bits = row.get("key_bits")
        self.variant = row.get("variant")

    @property
    def name(self):
        return self.backend

    def __repr__(self):
        return f"<{self.backend}:{self.row['id']}>"

    # cipher/aead:  encrypt(key, nonce, data, aad=b"") / decrypt(...)
    # mac:          mac(key, msg)
    # hash/xof:     digest(msg, outlen=None); digest_chunks(chunks, outlen=None)
    # rsa_pke:      keygen() → (sk, pk); encrypt(pk, m); decrypt(sk, c)
    # kem:          keygen(); encaps(pk) → (ct, ss); decaps(sk, ct) → ss
    # kex:          keygen(); agree(sk, pk_peer); public_bytes(pk); load_public(bytes)
    # sig:          keygen(); sign(sk, m); verify(pk, m, sig) → bool
    # kdf:          derive(**params) → bytes
    # prime:        is_prime(n) → bool; gen_prime(bits) → int
