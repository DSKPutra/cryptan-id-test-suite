"""Backend pustaka standar Python (hashlib / hmac)."""
import hashlib
import hmac
import platform

from .base import Adapter, NotSupported, kind_of

NAME = "stdlib"
HASH = {"SHA-1": "sha1", "SHA-224": "sha224", "SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512",
        "SHA-512/224": "sha512_224", "SHA-512/256": "sha512_256", "SHA3-224": "sha3_224", "SHA3-256": "sha3_256",
        "SHA3-384": "sha3_384", "SHA3-512": "sha3_512", "SM3": "sm3", "RIPEMD-160": "ripemd160"}


def version():
    import ssl
    return f"Python {platform.python_version()} · {ssl.OPENSSL_VERSION}"


class A(Adapter):
    backend = NAME


def _have(name):
    try:
        hashlib.new(name)
        return True
    except ValueError:
        return False


def get(row):
    k = kind_of(row)
    fam, var = row["family"], row["variant"]
    a = A(row, k)
    if k == "hash" and var in HASH and _have(HASH[var]):
        n = HASH[var]
        a.digest = lambda msg, outlen=None: hashlib.new(n, msg).digest()

        def dc(chunks, outlen=None):
            h = hashlib.new(n)
            for c in chunks:
                h.update(c)
            return h.digest()
        a.digest_chunks = dc
        return a
    if k == "xof" and var in ("SHAKE128", "SHAKE256"):
        f = hashlib.shake_128 if var == "SHAKE128" else hashlib.shake_256
        a.digest = lambda msg, outlen=32: f(msg).digest(outlen)

        def dc(chunks, outlen=32):
            h = f()
            for c in chunks:
                h.update(c)
            return h.digest(outlen)
        a.digest_chunks = dc
        return a
    if k == "mac" and fam == "HMAC" and var in HASH and _have(HASH[var]):
        a.mac = lambda key, msg: hmac.new(key, msg, HASH[var]).digest()
        return a
    if k == "kdf" and var == "PBKDF2":
        def pb(password, salt, iterations, length, h="SHA-256"):
            if length is not None and length <= 0:
                raise ValueError("panjang keluaran PBKDF2 tidak valid")
            return hashlib.pbkdf2_hmac(HASH[h], password, salt, iterations, length)
        a.derive = pb
        return a
    if k == "kdf" and var == "HKDF":                     # RFC 5869 di atas hmac (pustaka standar)
        def hkdf(ikm, salt, info, length, h="SHA-256"):
            n = HASH[h]
            hl = hashlib.new(n).digest_size
            if not 0 < length <= 255 * hl:                # RFC 5869 §2.3
                raise ValueError("panjang keluaran HKDF tidak valid")
            prk = hmac.new(salt or b"\x00" * hl, ikm, n).digest()
            okm, t, i = b"", b"", 1
            while len(okm) < length:
                t = hmac.new(prk, t + info + bytes([i]), n).digest()
                okm += t
                i += 1
            return okm[:length]
        a.derive = hkdf
        return a
    if k == "kdf" and var.startswith("SP800-108"):        # SP 800-108 Rev.1 KDF di atas HMAC (r = 32 bit)
        mode = var.split("-")[-1]

        def kbkdf(key, label, context, length, h="SHA-256", iv=b""):
            n = HASH[h]
            if length <= 0:
                raise ValueError("panjang keluaran KDF tidak valid")
            L = (length * 8).to_bytes(4, "big")
            fixed = label + b"\x00" + context + L
            out, i, k_prev = b"", 1, iv
            a_i = fixed
            while len(out) < length:
                ctr = i.to_bytes(4, "big")
                if mode == "Counter":
                    blk = hmac.new(key, ctr + fixed, n).digest()
                elif mode == "Feedback":
                    blk = hmac.new(key, k_prev + ctr + fixed, n).digest()
                    k_prev = blk
                else:                                       # DoublePipeline
                    a_i = hmac.new(key, a_i, n).digest()
                    blk = hmac.new(key, a_i + ctr + fixed, n).digest()
                out += blk
                i += 1
            return out[:length]
        a.derive = kbkdf
        return a
    raise NotSupported(k)
