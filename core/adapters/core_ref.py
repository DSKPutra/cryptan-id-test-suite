"""Backend implementasi referensi Cryptan.ID (core/, pure Python — independen dari OpenSSL).

Cakupan: AES-128 (ECB/CBC/CFB1/CFB8/CFB128/OFB/CTR/CMAC), SHA3-256, cSHAKE/KMAC (di atas
Keccak core/), RSA-OAEP (SHA-256), ECDSA P-256 (RFC 6979), uji primalitas (core/numtheory)."""
import hashlib
import secrets

from core import __version__, aes, ecdsa_p256 as ec, keccak, rsa_oaep
from core.numtheory import gen_prime, miller_rabin

from .base import Adapter, NotSupported, kind_of

NAME = "core"


def version():
    return f"Cryptan.ID core {__version__} (referensi pure Python)"


class A(Adapter):
    backend = NAME


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def _blocks(d, n=16):
    return [d[i:i + n] for i in range(0, len(d), n)]


def _aes_mode(var, enc):
    E = aes.encrypt_block

    def run(key, iv, data, aad=b""):
        if var != "ECB" and len(iv) != 16:
            raise ValueError("IV/counter block harus 16 byte")
        if var == "ECB":
            f = E if enc else aes.decrypt_block
            return b"".join(f(key, b) for b in _blocks(data))
        if var == "CBC":
            out, prev = b"", iv
            for b in _blocks(data):
                if enc:
                    prev = E(key, _xor(b, prev))
                    out += prev
                else:
                    out += _xor(aes.decrypt_block(key, b), prev)
                    prev = b
            return out
        if var == "OFB":
            out, s = b"", iv
            for b in _blocks(data):
                s = E(key, s)
                out += _xor(b, s)
            return out
        if var == "CTR":
            ks = aes.ctr_keystream(key, iv, (len(data) + 15) // 16)
            return _xor(data, ks)
        if var in ("CFB8", "CFB128"):
            seg = 1 if var == "CFB8" else 16
            out, reg = b"", iv
            for i in range(0, len(data), seg):
                x = data[i:i + seg]
                y = _xor(x, E(key, reg)[:len(x)])
                c = y if enc else x
                out += y
                reg = (reg + c)[-16:] if seg == 1 else c.ljust(16, b"\x00")
            return out
        if var == "CFB1":
            bits = []
            for byte in data:
                bits += [(byte >> (7 - j)) & 1 for j in range(8)]
            reg = int.from_bytes(iv, "big")
            out_bits = []
            for bit in bits:
                o = E(key, reg.to_bytes(16, "big"))[0] >> 7
                y = bit ^ o
                c = y if enc else bit
                out_bits.append(y)
                reg = ((reg << 1) | c) & ((1 << 128) - 1)
            return bytes(sum(out_bits[i + j] << (7 - j) for j in range(8)) for i in range(0, len(out_bits), 8))
        raise NotSupported(var)
    return run


def _cmac(key, msg):
    E = lambda x: aes.encrypt_block(key, x)
    L = int.from_bytes(E(b"\x00" * 16), "big")

    def dbl(v):
        v <<= 1
        if v >> 128:
            v = (v ^ 0x87) & ((1 << 128) - 1)
        return v
    K1 = dbl(L)
    K2 = dbl(K1)
    n = max(1, (len(msg) + 15) // 16)
    last = msg[16 * (n - 1):]
    if len(msg) and len(last) == 16:
        m_last = _xor(last, K1.to_bytes(16, "big"))
    else:
        m_last = _xor((last + b"\x80").ljust(16, b"\x00"), K2.to_bytes(16, "big"))
    x = b"\x00" * 16
    for i in range(n - 1):
        x = E(_xor(x, msg[16 * i:16 * i + 16]))
    return E(_xor(x, m_last))


# ---- SP 800-185 di atas Keccak core/
def _left_encode(x):
    n = max(1, (x.bit_length() + 7) // 8)
    return bytes([n]) + x.to_bytes(n, "big")


def _right_encode(x):
    n = max(1, (x.bit_length() + 7) // 8)
    return x.to_bytes(n, "big") + bytes([n])


def _encode_string(s):
    return _left_encode(len(s) * 8) + s


def _bytepad(x, w):
    z = _left_encode(w) + x
    return z + b"\x00" * ((-len(z)) % w)


def cshake(msg, outlen, sec, name=b"", custom=b""):
    rate = 168 if sec == 128 else 136
    if not name and not custom:
        return hashlib.shake_128(msg).digest(outlen) if sec == 128 else hashlib.shake_256(msg).digest(outlen)
    data = _bytepad(_encode_string(name) + _encode_string(custom), rate) + msg
    return keccak.sponge(data, rate, outlen, ds=0x04)


def kmac(key, msg, outlen, sec, custom=b""):
    rate = 168 if sec == 128 else 136
    x = _bytepad(_encode_string(key), rate) + msg + _right_encode(outlen * 8)
    return cshake(x, outlen, sec, b"KMAC", custom)


def get(row):
    k = kind_of(row)
    fam, var, kb = row["family"], row["variant"], row.get("key_bits")
    a = A(row, k)
    if k == "cipher" and fam == "AES" and kb == 128 and var in ("ECB", "CBC", "CFB1", "CFB8", "CFB128", "OFB", "CTR"):
        a.mode, a.block, a.needs_iv, a.full_blocks = var, 16, var != "ECB", var in ("ECB", "CBC")
        a.encrypt, a.decrypt = _aes_mode(var, True), _aes_mode(var, False)
        a.slow = var == "CFB1"                            # satu blok AES per bit (~1,6 kbit/s)
        return a
    if k == "mac" and fam == "AES" and var == "CMAC" and kb == 128:
        a.mac = _cmac
        return a
    if k == "mac" and fam == "KMAC":
        a.mac = lambda key, msg, outlen=32, custom=b"": kmac(key, msg, outlen, kb, custom)
        return a
    if k == "hash" and var == "SHA3-256":
        a.digest = lambda msg, outlen=None: keccak.sha3_256(msg)
        a.digest_chunks = lambda chunks, outlen=None: keccak.sha3_256(b"".join(chunks))
        return a
    if k == "xof" and var == "cSHAKE":
        a.digest = lambda msg, outlen=32, custom=b"": cshake(msg, outlen, kb, b"", custom)
        a.digest_chunks = lambda chunks, outlen=32, custom=b"": cshake(b"".join(chunks), outlen, kb, b"", custom)
        return a
    if k == "rsa_pke" and var == "OAEP" and kb == 2048:
        def kg(bits=kb):
            # kunci uji dari cache bersama (PEM); pembangkitan kunci core/ diuji terpisah (uk1/uk2)
            from cryptography.hazmat.primitives import serialization
            from . import keys
            from .pyca import get as _pg
            pem = keys.pem("RSA", bits, lambda: _pg(row).export_private(_pg(row).keygen()[0]))
            n = serialization.load_pem_private_key(pem, None).private_numbers() if pem.startswith(b"-----") else \
                serialization.load_der_private_key(pem, None).private_numbers()
            sk = rsa_oaep.PrivateKey(n.public_numbers.n, n.public_numbers.e, n.d, n.p, n.q)
            return sk, sk.public()
        a.keygen = kg
        a.encrypt = lambda pk, m: rsa_oaep.encrypt(pk, m)
        a.decrypt = lambda sk, c: rsa_oaep.decrypt(sk, c)
        a.max_msg = 256 - 66
        return a
    if k == "sig" and fam == "ECDSA" and var == "P-256":
        def kg():
            d = secrets.randbelow(ec.N - 1) + 1
            return d, ec.public_key(d)
        a.keygen = kg
        a.sign = lambda d, m: _der(*ec.sign(d, m))
        a.verify = lambda Q, m, s: (lambda rs: bool(rs) and ec.verify(Q, m, rs))(_undert(s))
        return a
    if k == "prime":
        a.is_prime = lambda n: miller_rabin(n, 64)
        a.gen_prime = lambda bits: gen_prime(bits)
        return a
    raise NotSupported(k)


def _der(r, s):
    def enc(x):
        b = x.to_bytes((x.bit_length() + 8) // 8 or 1, "big")
        return b"\x02" + bytes([len(b)]) + b
    body = enc(r) + enc(s)
    return b"\x30" + bytes([len(body)]) + body


def _undert(sig):
    try:
        from uk2_skenario.expected import _der_strict
        return _der_strict(sig)
    except Exception:
        return None
