"""Backend pyca/cryptography (OpenSSL)."""
import cryptography
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import cmac, hashes, hmac as chmac, keywrap, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa, x448, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, AESGCM, AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC, CounterLocation, Mode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from . import keys
from .base import Adapter, NotSupported, kind_of

NAME = "pyca"
HASH = {"SHA-1": hashes.SHA1, "SHA-224": hashes.SHA224, "SHA-256": hashes.SHA256, "SHA-384": hashes.SHA384,
        "SHA-512": hashes.SHA512, "SHA-512/224": hashes.SHA512_224, "SHA-512/256": hashes.SHA512_256,
        "SHA3-224": hashes.SHA3_224, "SHA3-256": hashes.SHA3_256, "SHA3-384": hashes.SHA3_384, "SHA3-512": hashes.SHA3_512,
        "SM3": hashes.SM3}
XOF = {"SHAKE128": hashes.SHAKE128, "SHAKE256": hashes.SHAKE256}
CURVES = {"P-224": ec.SECP224R1, "P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}
SIG_HASH = {"P-224": hashes.SHA224, "P-256": hashes.SHA256, "P-384": hashes.SHA384, "P-521": hashes.SHA512}
BP = {256: ec.BrainpoolP256R1, 384: ec.BrainpoolP384R1, 512: ec.BrainpoolP512R1}
try:                                   # cryptography ≥ 47: CFB/CFB8/OFB dipindah ke decrepit
    from cryptography.hazmat.decrepit.ciphers import modes as _dm
    _CFB, _CFB8, _OFB = _dm.CFB, _dm.CFB8, _dm.OFB
except ImportError:                    # pragma: no cover
    _CFB, _CFB8, _OFB = modes.CFB, modes.CFB8, modes.OFB
MODES = {"ECB": lambda n: modes.ECB(), "CBC": modes.CBC, "CFB8": _CFB8, "CFB128": _CFB, "OFB": _OFB, "CTR": modes.CTR}


def version():
    return cryptography.__version__


class A(Adapter):
    backend = NAME


def _blockalg(row, key):
    fam = row["family"]
    if fam == "AES":
        return algorithms.AES(key)
    if fam == "TDEA":
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        return TripleDES(key)
    if fam == "Camellia":
        from cryptography.hazmat.decrepit.ciphers.algorithms import Camellia
        return Camellia(key)
    if fam == "SEED":
        from cryptography.hazmat.decrepit.ciphers.algorithms import SEED
        return SEED(key)
    if fam == "SM4":
        return algorithms.SM4(key)
    raise NotSupported(fam)


def get(row):
    k = kind_of(row)
    fam, var, kb, rid = row["family"], row["variant"], row.get("key_bits"), row["id"]
    a = A(row, k)
    if k == "cipher":
        if fam not in ("AES", "TDEA", "Camellia", "SEED", "SM4"):
            raise NotSupported(fam)
        if fam in ("Camellia", "SEED", "SM4"):        # entri "ECB/CBC/…": uji pada ECB (blok tunggal) + CBC
            var = "ECB"
        if fam == "TDEA":
            var = "CBC"
        if var in MODES:
            a.block = 8 if fam == "TDEA" else 16

            def enc(key, nonce, data, aad=b"", _v=var):
                c = Cipher(_blockalg(row, key), MODES[_v](nonce) if _v != "ECB" else modes.ECB()).encryptor()
                return c.update(data) + c.finalize()

            def dec(key, nonce, data, aad=b"", _v=var):
                c = Cipher(_blockalg(row, key), MODES[_v](nonce) if _v != "ECB" else modes.ECB()).decryptor()
                return c.update(data) + c.finalize()
            a.encrypt, a.decrypt, a.mode = enc, dec, var
            a.needs_iv = var != "ECB"
            a.full_blocks = var in ("ECB", "CBC")
            return a
        if var == "XTS" and fam == "AES":
            a.block, a.mode, a.needs_iv, a.full_blocks = 16, "XTS", True, False
            a.min_len = 16
            a.encrypt = lambda key, tweak, data, aad=b"": (lambda c: c.update(data) + c.finalize())(Cipher(algorithms.AES(key), modes.XTS(tweak)).encryptor())
            a.decrypt = lambda key, tweak, data, aad=b"": (lambda c: c.update(data) + c.finalize())(Cipher(algorithms.AES(key), modes.XTS(tweak)).decryptor())
            return a
        if var in ("KW", "KWP") and fam == "AES":
            a.mode, a.needs_iv, a.block = var, False, 8
            if var == "KW":
                a.encrypt = lambda key, n, data, aad=b"": keywrap.aes_key_wrap(key, data)
                a.decrypt = lambda key, n, data, aad=b"": keywrap.aes_key_unwrap(key, data)
            else:
                a.encrypt = lambda key, n, data, aad=b"": keywrap.aes_key_wrap_with_padding(key, data)
                a.decrypt = lambda key, n, data, aad=b"": keywrap.aes_key_unwrap_with_padding(key, data)
            return a
        raise NotSupported(var)
    if k == "aead":
        cls = {"GCM": AESGCM, "CCM": AESCCM, "GCM-SIV": AESGCMSIV}[var]
        a.mode, a.nonce_len, a.tag_len = var, 12, 16

        def enc(key, nonce, data, aad=b""):
            return cls(key).encrypt(nonce, data, aad or None)

        def dec(key, nonce, data, aad=b""):
            return cls(key).decrypt(nonce, data, aad or None)
        a.encrypt, a.decrypt = enc, dec
        return a
    if k == "mac":
        if fam == "HMAC":
            h = HASH.get(var)
            if not h:
                raise NotSupported(var)

            def m(key, msg):
                x = chmac.HMAC(key, h())
                x.update(msg)
                return x.finalize()
            a.mac = m
            return a
        if fam == "AES" and var == "CMAC":
            def m(key, msg):
                x = cmac.CMAC(algorithms.AES(key))
                x.update(msg)
                return x.finalize()
            a.mac = m
            return a
        if fam == "AES" and var == "GMAC":
            a.mac = lambda key, msg, nonce=b"\x00" * 12: AESGCM(key).encrypt(nonce, b"", msg)
            a.nonce_len = 12
            return a
        raise NotSupported(var)
    if k in ("hash", "xof"):
        if var in HASH:
            def d(msg, outlen=None, _h=HASH[var]):
                x = hashes.Hash(_h())
                x.update(msg)
                return x.finalize()

            def dc(chunks, outlen=None, _h=HASH[var]):
                x = hashes.Hash(_h())
                for c in chunks:
                    x.update(c)
                return x.finalize()
            a.digest, a.digest_chunks = d, dc
            return a
        if var in XOF:
            def dx(msg, outlen=32, _h=XOF[var]):
                x = hashes.Hash(_h(digest_size=outlen))
                x.update(msg)
                return x.finalize()

            def dc(chunks, outlen=32, _h=XOF[var]):
                x = hashes.Hash(_h(digest_size=outlen))
                for c in chunks:
                    x.update(c)
                return x.finalize()
            a.digest, a.digest_chunks = dx, dc
            return a
        raise NotSupported(var)
    if k == "rsa_pke":
        oaep = var == "OAEP"
        if not oaep and var != "PKCS1-v1_5-ENC":
            raise NotSupported(var)
        pad = (lambda: padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None)) if oaep else padding.PKCS1v15

        def kg(bits=kb):
            p = keys.pem("RSA", bits, lambda: rsa.generate_private_key(65537, bits).private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            return _loaded("RSA", bits, p)
        a.keygen = kg
        a.encrypt = lambda pk, m: pk.encrypt(m, pad())
        a.decrypt = lambda sk, c: sk.decrypt(c, pad())
        a.export_private = lambda sk: sk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        a.export_public = lambda pk: pk.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        a.import_public = serialization.load_der_public_key
        a.import_private = lambda b: serialization.load_der_private_key(b, None)
        a.max_msg = (kb // 8) - 2 * 32 - 2 if oaep else (kb // 8) - 11
        return a
    if k == "kem":
        from cryptography.hazmat.primitives.asymmetric import mlkem
        cls = {"ML-KEM-768": getattr(mlkem, "MLKEM768PrivateKey", None), "ML-KEM-1024": getattr(mlkem, "MLKEM1024PrivateKey", None)}.get(var)
        if cls is None:
            raise NotSupported(var)
        a.keygen = lambda: (lambda sk: (sk, sk.public_key()))(cls.generate())
        a.encaps = lambda pk: (lambda r: (r[1], r[0]))(pk.encapsulate())
        a.decaps = lambda sk, ct: sk.decapsulate(ct)
        a.export_public = lambda pk: pk.public_bytes_raw()
        a.import_public = (lambda b: getattr(mlkem, var.replace("-", "").replace("MLKEM", "MLKEM") + "PublicKey").from_public_bytes(b))
        return a
    if k == "kex":
        if fam == "ECDH":
            curve = CURVES.get(var)
            if not curve:
                raise NotSupported(var)
            a.keygen = lambda: (lambda sk: (sk, sk.public_key()))(ec.generate_private_key(curve()))
            a.agree = lambda sk, pk: sk.exchange(ec.ECDH(), pk)
            a.export_public = lambda pk: pk.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            a.import_public = serialization.load_der_public_key
            return a
        if fam == "XECDH":
            mod = {"X25519": x25519, "X448": x448}[var]
            P = getattr(mod, var + "PrivateKey")
            Pub = getattr(mod, var + "PublicKey")
            a.keygen = lambda: (lambda sk: (sk, sk.public_key()))(P.generate())
            a.agree = lambda sk, pk: sk.exchange(pk)
            a.export_public = lambda pk: pk.public_bytes_raw()
            a.import_public = Pub.from_public_bytes
            return a
        raise NotSupported(fam)
    if k == "sig":
        if fam == "RSA" and var in ("PSS", "PKCS1-v1_5-SIG"):
            pad = (lambda: padding.PSS(padding.MGF1(hashes.SHA256()), 32)) if var == "PSS" else padding.PKCS1v15

            def kg(bits=kb):
                p = keys.pem("RSA", bits, lambda: rsa.generate_private_key(65537, bits).private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                return _loaded("RSA", bits, p)
            a.keygen = kg
            a.sign = lambda sk, m: sk.sign(m, pad(), hashes.SHA256())
            a.verify = lambda pk, m, s: _ok(lambda: pk.verify(s, m, pad(), hashes.SHA256()))
        elif fam == "ECDSA" and (var in CURVES or rid.startswith("ECDSA-BRAINPOOL")):
            curve = CURVES.get(var) or BP[kb]
            h = SIG_HASH.get(var) or {256: hashes.SHA256, 384: hashes.SHA384, 512: hashes.SHA512}[kb]
            a.keygen = lambda: (lambda sk: (sk, sk.public_key()))(ec.generate_private_key(curve()))
            a.sign = lambda sk, m: sk.sign(m, ec.ECDSA(h()))
            a.verify = lambda pk, m, s: _ok(lambda: pk.verify(s, m, ec.ECDSA(h())))
        elif fam == "EdDSA":
            P = {"Ed25519": ed25519.Ed25519PrivateKey, "Ed448": ed448.Ed448PrivateKey}[var]
            a.keygen = lambda: (lambda sk: (sk, sk.public_key()))(P.generate())
            a.sign = lambda sk, m: sk.sign(m)
            a.verify = lambda pk, m, s: _ok(lambda: pk.verify(s, m))
        elif fam == "DSA":
            def kg(bits=kb):
                p = keys.pem("DSA", bits, lambda: dsa.generate_private_key(bits).private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                return _loaded("DSA", bits, p)
            a.keygen = kg
            a.sign = lambda sk, m: sk.sign(m, hashes.SHA256())
            a.verify = lambda pk, m, s: _ok(lambda: pk.verify(s, m, hashes.SHA256()))
        elif fam == "ML-DSA":
            from cryptography.hazmat.primitives.asymmetric import mldsa
            P = getattr(mldsa, var.replace("-", "") + "PrivateKey")
            a.keygen = lambda: (lambda sk: (sk, sk.public_key()))(P.generate())
            a.sign = lambda sk, m: sk.sign(m)
            a.verify = lambda pk, m, s: _ok(lambda: pk.verify(s, m))
        else:
            raise NotSupported(fam)
        a.export_public = lambda pk: pk.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        a.import_public = serialization.load_der_public_key
        return a
    if k == "kdf":
        if var == "HKDF":
            a.derive = lambda ikm, salt, info, length, h="SHA-256": HKDF(HASH[h](), length, salt or None, info).derive(ikm)
            return a
        if var == "PBKDF2":
            a.derive = lambda password, salt, iterations, length, h="SHA-256": PBKDF2HMAC(HASH[h](), length, salt, iterations).derive(password)
            return a
        if var == "SP800-108-Counter":
            a.derive = lambda key, label, context, length, h="SHA-256": KBKDFHMAC(HASH[h](), Mode.CounterMode, length, 4, 4,
                                                                                 CounterLocation.BeforeFixed, label, context, None).derive(key)
            return a
        raise NotSupported(var)
    raise NotSupported(k)


_KEYS = {}


def _loaded(fam, bits, pem):
    """Muat kunci uji sekali per proses. Validasi RSA penuh dilewati (kunci uji sudah tervalidasi saat
    dibangkitkan; validasi OpenSSL untuk RSA-15360 ≈ 9 detik per pemuatan)."""
    if (fam, bits) not in _KEYS:
        kw = {"unsafe_skip_rsa_key_validation": True} if fam == "RSA" else {}
        sk = serialization.load_pem_private_key(pem, None, **kw)
        _KEYS[(fam, bits)] = (sk, sk.public_key())
    return _KEYS[(fam, bits)]


def _ok(fn):
    try:
        fn()
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


__all__ = ["get", "version", "InvalidTag", "NAME"]
