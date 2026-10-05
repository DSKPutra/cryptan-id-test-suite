"""Backend pycryptodome (implementasi independen dari OpenSSL)."""
import Crypto
from Crypto.Cipher import AES, DES3, PKCS1_OAEP, PKCS1_v1_5 as PKCS1_ENC
from Crypto.Hash import (CMAC, HMAC, SHA1, SHA224, SHA256, SHA384, SHA512, SHA3_224, SHA3_256, SHA3_384, SHA3_512,
                         SHAKE128, SHAKE256, KMAC128, KMAC256, cSHAKE128, cSHAKE256, RIPEMD160)
from Crypto.PublicKey import DSA, ECC, RSA
from Crypto.Signature import DSS, eddsa, pkcs1_15, pss
from Crypto.Util import number

from . import keys
from .base import Adapter, NotSupported, kind_of

NAME = "pycrypto"
HASH = {"SHA-1": SHA1, "SHA-224": SHA224, "SHA-256": SHA256, "SHA-384": SHA384, "SHA-512": SHA512,
        "SHA-512/224": (SHA512, "224"), "SHA-512/256": (SHA512, "256"), "SHA3-224": SHA3_224, "SHA3-256": SHA3_256,
        "SHA3-384": SHA3_384, "SHA3-512": SHA3_512, "RIPEMD-160": RIPEMD160}
CURVE = {"P-224": "P-224", "P-256": "P-256", "P-384": "P-384", "P-521": "P-521"}
SIG_HASH = {"P-224": SHA224, "P-256": SHA256, "P-384": SHA384, "P-521": SHA512}
MODE = {"ECB": (AES.MODE_ECB, None), "CBC": (AES.MODE_CBC, None), "CFB8": (AES.MODE_CFB, 8),
        "CFB128": (AES.MODE_CFB, 128), "OFB": (AES.MODE_OFB, None), "CTR": (AES.MODE_CTR, None)}


def version():
    return Crypto.__version__


class A(Adapter):
    backend = NAME


def _hnew(var, data=b""):
    h = HASH[var]
    if isinstance(h, tuple):
        return h[0].new(data, truncate=h[1])
    return h.new(data)


def _aes(key, var, nonce):
    m, seg = MODE[var]
    if var == "ECB":
        return AES.new(key, m)
    if var == "CTR":
        return AES.new(key, m, nonce=b"", initial_value=nonce)
    if seg:
        return AES.new(key, m, iv=nonce, segment_size=seg)
    return AES.new(key, m, iv=nonce)


def get(row):
    k = kind_of(row)
    fam, var, kb, rid = row["family"], row["variant"], row.get("key_bits"), row["id"]
    a = A(row, k)
    if k == "cipher":
        if fam == "AES" and var in MODE:
            a.mode, a.block, a.needs_iv, a.full_blocks = var, 16, var != "ECB", var in ("ECB", "CBC")
            a.encrypt = lambda key, n, data, aad=b"": _aes(key, var, n).encrypt(data)
            a.decrypt = lambda key, n, data, aad=b"": _aes(key, var, n).decrypt(data)
            return a
        if fam == "TDEA":
            a.mode, a.block, a.needs_iv, a.full_blocks = "CBC", 8, True, True
            a.encrypt = lambda key, n, data, aad=b"": DES3.new(key, DES3.MODE_CBC, iv=n).encrypt(data)
            a.decrypt = lambda key, n, data, aad=b"": DES3.new(key, DES3.MODE_CBC, iv=n).decrypt(data)
            return a
        raise NotSupported(var)
    if k == "aead":
        if var not in ("GCM", "CCM"):
            raise NotSupported(var)
        mode = AES.MODE_GCM if var == "GCM" else AES.MODE_CCM
        a.mode, a.nonce_len, a.tag_len = var, 12, 16

        def enc(key, nonce, data, aad=b""):
            c = AES.new(key, mode, nonce=nonce, mac_len=16)
            c.update(aad)
            ct, tag = c.encrypt_and_digest(data)
            return ct + tag

        def dec(key, nonce, data, aad=b""):
            c = AES.new(key, mode, nonce=nonce, mac_len=16)
            c.update(aad)
            return c.decrypt_and_verify(data[:-16], data[-16:])
        a.encrypt, a.decrypt = enc, dec
        return a
    if k == "mac":
        if fam == "HMAC" and var in HASH and not isinstance(HASH[var], tuple):
            a.mac = lambda key, msg: HMAC.new(key, msg, HASH[var]).digest()
            return a
        if fam == "AES" and var == "CMAC":
            a.mac = lambda key, msg: CMAC.new(key, msg, ciphermod=AES).digest()
            return a
        if fam == "AES" and var == "GMAC":
            def g(key, msg, nonce=b"\x00" * 12):
                c = AES.new(key, AES.MODE_GCM, nonce=nonce)
                c.update(msg)
                return c.digest()
            a.mac, a.nonce_len = g, 12
            return a
        if fam == "KMAC":
            K = KMAC128 if kb == 128 else KMAC256
            a.mac = lambda key, msg, outlen=32, custom=b"": K.new(key=key, data=msg, mac_len=outlen, custom=custom).digest()
            return a
        raise NotSupported(var)
    if k in ("hash", "xof"):
        if var in HASH:
            a.digest = lambda msg, outlen=None: _hnew(var, msg).digest()

            def dc(chunks, outlen=None):
                h = _hnew(var)
                for c in chunks:
                    h.update(c)
                return h.digest()
            a.digest_chunks = dc
            return a
        if var in ("SHAKE128", "SHAKE256"):
            S = SHAKE128 if var == "SHAKE128" else SHAKE256
            a.digest = lambda msg, outlen=32: S.new(msg).read(outlen)

            def dc(chunks, outlen=32):
                h = S.new()
                for c in chunks:
                    h.update(c)
                return h.read(outlen)
            a.digest_chunks = dc
            return a
        if var == "cSHAKE":
            S = cSHAKE128 if kb == 128 else cSHAKE256
            a.digest = lambda msg, outlen=32, custom=b"": S.new(data=msg, custom=custom).read(outlen)
            a.digest_chunks = lambda chunks, outlen=32, custom=b"": S.new(data=b"".join(chunks), custom=custom).read(outlen)
            return a
        raise NotSupported(var)
    if k == "rsa_pke":
        oaep = var == "OAEP"

        def kg(bits=kb):
            return _loaded("RSA", bits, keys.pem("RSA", bits, lambda: RSA.generate(bits).export_key(format="PEM", pkcs=8)), RSA)
        a.keygen = kg
        if oaep:
            a.encrypt = lambda pk, m: PKCS1_OAEP.new(pk, hashAlgo=SHA256).encrypt(m)
            a.decrypt = lambda sk, c: PKCS1_OAEP.new(sk, hashAlgo=SHA256).decrypt(c)
        else:
            a.encrypt = lambda pk, m: PKCS1_ENC.new(pk).encrypt(m)

            def d(sk, c):
                out = PKCS1_ENC.new(sk).decrypt(c, None)
                if out is None:
                    raise ValueError("decryption error")
                return out
            a.decrypt = d
        a.max_msg = (kb // 8) - 2 * 32 - 2 if oaep else (kb // 8) - 11
        a.export_public = lambda pk: pk.export_key(format="DER")
        a.import_public = RSA.import_key
        a.export_private = lambda sk: sk.export_key(format="DER", pkcs=8)
        a.import_private = RSA.import_key
        return a
    if k == "kex":
        from Crypto.Protocol.DH import key_agreement
        if fam == "ECDH" and var in CURVE:
            a.keygen = lambda: (lambda sk: (sk, sk.public_key()))(ECC.generate(curve=CURVE[var]))
            a.agree = lambda sk, pk: key_agreement(static_priv=sk, static_pub=pk, kdf=lambda x: x)
            a.export_public = lambda pk: pk.export_key(format="DER")
            a.import_public = ECC.import_key
            return a
        if fam == "XECDH" and var in ("X25519", "X448"):
            cv = {"X25519": "Curve25519", "X448": "Curve448"}[var]
            a.keygen = lambda: (lambda sk: (sk, sk.public_key()))(ECC.generate(curve=cv))
            a.agree = lambda sk, pk: key_agreement(static_priv=sk, static_pub=pk, kdf=lambda x: x)
            a.export_public = lambda pk: pk.export_key(format="raw")
            a.import_public = lambda b: (ECC.import_x25519_public_key(b) if var == "X25519" else ECC.import_x448_public_key(b))
            return a
        raise NotSupported(fam)
    if k == "sig":
        if fam == "RSA" and var in ("PSS", "PKCS1-v1_5-SIG"):
            def kg(bits=kb):
                return _loaded("RSA", bits, keys.pem("RSA", bits, lambda: RSA.generate(bits).export_key(format="PEM", pkcs=8)), RSA)
            sch = pss if var == "PSS" else pkcs1_15
            a.keygen = kg
            a.sign = lambda sk, m: sch.new(sk).sign(SHA256.new(m))
            a.verify = lambda pk, m, s: _ok(lambda: sch.new(pk).verify(SHA256.new(m), s))
            a.export_public = lambda pk: pk.export_key(format="DER")
            a.import_public = RSA.import_key
            return a
        if fam == "ECDSA" and var in CURVE:
            h = SIG_HASH[var]
            a.keygen = lambda: (lambda sk: (sk, sk.public_key()))(ECC.generate(curve=CURVE[var]))
            a.sign = lambda sk, m: DSS.new(sk, "fips-186-3", encoding="der").sign(h.new(m))
            a.verify = lambda pk, m, s: _ok(lambda: DSS.new(pk, "fips-186-3", encoding="der").verify(h.new(m), s))
            a.export_public = lambda pk: pk.export_key(format="DER")
            a.import_public = ECC.import_key
            return a
        if fam == "EdDSA":
            cv = {"Ed25519": "Ed25519", "Ed448": "Ed448"}[var]
            a.keygen = lambda: (lambda sk: (sk, sk.public_key()))(ECC.generate(curve=cv))
            a.sign = lambda sk, m: eddsa.new(sk, "rfc8032").sign(m)
            a.verify = lambda pk, m, s: _ok(lambda: eddsa.new(pk, "rfc8032").verify(m, s))
            a.export_public = lambda pk: pk.export_key(format="DER")
            a.import_public = ECC.import_key
            return a
        if fam == "DSA":
            def kg(bits=kb):
                return _loaded("DSA", bits, keys.pem("DSA", bits, lambda: DSA.generate(bits).export_key(format="PEM", pkcs8=True)), DSA)
            a.keygen = kg
            a.sign = lambda sk, m: DSS.new(sk, "fips-186-3", encoding="der").sign(SHA256.new(m))
            a.verify = lambda pk, m, s: _ok(lambda: DSS.new(pk, "fips-186-3", encoding="der").verify(SHA256.new(m), s))
            a.export_public = lambda pk: pk.export_key(format="DER")
            a.import_public = DSA.import_key
            return a
        raise NotSupported(fam)
    if k == "prime":
        a.is_prime = lambda n: bool(number.isPrime(n))
        a.gen_prime = lambda bits: number.getPrime(bits)
        return a
    if k == "kdf" and var == "PBKDF2":
        from Crypto.Protocol.KDF import PBKDF2
        a.derive = lambda password, salt, iterations, length, h="SHA-256": PBKDF2(password, salt, length, iterations, hmac_hash_module=HASH[h])
        return a
    if k == "kdf" and var == "HKDF":
        from Crypto.Protocol.KDF import HKDF
        a.derive = lambda ikm, salt, info, length, h="SHA-256": HKDF(ikm, length, salt or b"\x00" * 32, HASH[h], 1, info)
        return a
    raise NotSupported(k)


_KEYS = {}


def _loaded(fam, bits, pem, mod):
    if (fam, bits) not in _KEYS:
        sk = mod.import_key(pem)
        _KEYS[(fam, bits)] = (sk, sk.publickey())
    return _KEYS[(fam, bits)]


def _ok(fn):
    try:
        fn()
        return True
    except (ValueError, TypeError):
        return False
