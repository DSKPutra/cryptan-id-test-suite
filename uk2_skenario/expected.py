"""KUK 2.4 — Expected value disusun objektif & independen dari implementasi yang diuji.

Deterministik : dihitung dengan implementasi referensi core/ atau pustaka tepercaya (pyca/cryptography,
                hashlib/hmac) lalu DICOCOKKAN dengan vektor resmi (FIPS/SP 800-38A/RFC 8439/RFC 6979/
                RFC 8448/PKCS#1/Wycheproof). Yang tidak dapat dihitung/dicocokkan → PERLU_VERIFIKASI.
Statistik     : α = 0,01; proporsi ≥ p̂ − 3√(p̂(1−p̂)/s); P-value_T ≥ 0,0001; avalanche n/2, σ = √n/2.
Kriptanalitik : kompleksitas serangan terbaik (literatur UK-1) ≥ klaim bit security.
Implementasi  : TVLA |t| < 4,5; tanpa crash/hang; galat & waktu respons seragam.
Negatif       : ditolak dengan kode galat yang diharapkan.
Setiap berkas outputs/uk2/expected/*.json dicatat hash SHA-256-nya di manifest.
"""
import hashlib
import hmac
import json
import math
import re
from pathlib import Path

from core import aes, chacha20, ecdsa_p256 as ec, kat as core_kat, keccak, rsa_oaep, stats

VEC = Path(__file__).parent / "data" / "vectors"
DIRECT = "HASIL UJI LANGSUNG"
LIT = "LITERATUR/ACUAN"
OK_OFFICIAL = "COCOK_VEKTOR_RESMI"
VERIFY = "PERLU_VERIFIKASI"
CRITERIA = "KRITERIA"
ALPHA = 0.01
ERR = {"param": "E_INVALID_PARAMETER", "auth": "E_AUTH_FAILED", "decrypt": "E_DECRYPT", "format": "E_FORMAT",
       "state": "E_STATE", "key": "E_INVALID_KEY"}


def _wy(name):
    return json.loads((VEC / name).read_text())


def _wy_ref(name):
    d = _wy(name)
    return f"Wycheproof {name} ({d.get('algorithm')}, {d.get('numberOfTests')} uji; C2SP/wycheproof, Apache-2.0)"


# =============================================================== DETERMINISTIK
def _core_kat(alg):
    r = core_kat.run(alg)
    return {"vectors": [{"id": c["id"], "source": c["source"], "match": c["pass"]} for c in r["cases"]],
            "total": r["total"], "matched": r["passed"]}


SP80038A_CTR = {  # SP 800-38A F.5.1 CTR-AES128.Encrypt
    "key": "2b7e151628aed2a6abf7158809cf4f3c", "ctr": "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    "pt": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    "ct": "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee"}
HASH_ABC = {  # FIPS 180-4 / FIPS 202 / RFC 7693 contoh "abc" (vektor resmi)
    "SHA-256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    "SHA-384": "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    "SHA-512/256": "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
    "SHA3-256": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    "BLAKE2B-512": "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
}
SHAKE256_EMPTY_512 = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
HASHLIB = {"SHA-256": "sha256", "SHA-384": "sha384", "SHA-512/256": "sha512_256", "SHA3-256": "sha3_256",
           "BLAKE2B-512": "blake2b", "SHA-1": "sha1", "SHA-224": "sha224", "SHA-512": "sha512", "SHA3-384": "sha3_384",
           "SHA3-512": "sha3_512", "SHA3-224": "sha3_224"}


def kat_aes_ctr():
    import binascii
    k, c0, pt, ct = (bytes.fromhex(SP80038A_CTR[x]) for x in ("key", "ctr", "pt", "ct"))
    ks = aes.ctr_keystream(k, c0, 4)
    core_ct = bytes(a ^ b for a, b in zip(pt, ks))
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    e = Cipher(algorithms.AES(k), modes.CTR(c0)).encryptor()
    lib_ct = e.update(pt) + e.finalize()
    base = _core_kat("AES-128")
    vec = base["vectors"] + [{"id": "SP800-38A-F.5.1", "source": "SP 800-38A F.5.1 CTR-AES128 (4 blok)",
                              "pt": binascii.hexlify(pt).decode(), "ct": SP80038A_CTR["ct"],
                              "match": core_ct == ct and lib_ct == ct}]
    return {"vectors": vec, "total": len(vec), "matched": sum(v["match"] for v in vec),
            "independent": ["core/aes.py", "pyca/cryptography (OpenSSL)"]}


def _wy_aead(name, keysize, make):
    d = _wy(name)
    out, ok = [], 0
    for g in d["testGroups"]:
        if g.get("keySize") != keysize or g.get("ivSize", 96) != 96 or g.get("tagSize", 128) != 128:
            continue
        for t in g["tests"]:
            k, iv, aad, msg, ct, tag = (bytes.fromhex(t[x]) for x in ("key", "iv", "aad", "msg", "ct", "tag"))
            try:
                got = make(k).decrypt(iv, ct + tag, aad)
                lib = "valid" if got == msg else "invalid"
            except Exception:
                lib = "invalid"
            expect = "reject" if t["result"] == "invalid" else "accept"
            match = (lib == "valid") == (expect == "accept") or t["result"] == "acceptable"
            ok += match
            out.append({"tcId": t["tcId"], "key": t["key"], "iv": t["iv"], "aad": t["aad"], "msg": t["msg"], "ct": t["ct"],
                        "tag": t["tag"], "result": t["result"], "expect": expect, "flags": t["flags"], "match": match})
    return {"vectors": out, "total": len(out), "matched": ok, "independent": ["pyca/cryptography (OpenSSL)"], "ref": _wy_ref(name)}


def kat_aes_gcm(keysize):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return _wy_aead("aes_gcm_test.json", keysize, AESGCM)


def kat_chacha_poly():
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    return _wy_aead("chacha20_poly1305_test.json", 256, ChaCha20Poly1305)


def kat_aes_kw(keysize):
    from cryptography.hazmat.primitives import keywrap
    d = _wy("aes_wrap_test.json")
    out, ok = [], 0
    for g in d["testGroups"]:
        if g["keySize"] != keysize:
            continue
        for t in g["tests"]:
            k, msg, ct = (bytes.fromhex(t[x]) for x in ("key", "msg", "ct"))
            try:
                lib = "valid" if keywrap.aes_key_unwrap(k, ct) == msg else "invalid"
            except Exception:
                lib = "invalid"
            match = (lib == "valid") == (t["result"] == "valid") or t["result"] == "acceptable"
            ok += match
            out.append({"tcId": t["tcId"], "key": t["key"], "msg": t["msg"], "ct": t["ct"], "result": t["result"], "match": match})
    return {"vectors": out, "total": len(out), "matched": ok, "independent": ["pyca/cryptography"], "ref": _wy_ref("aes_wrap_test.json")}


def kat_hmac256(keysize):
    d = _wy("hmac_sha256_test.json")
    out, ok = [], 0
    for g in d["testGroups"]:
        if g["keySize"] != keysize or g["tagSize"] != 256:
            continue
        for t in g["tests"]:
            k, msg, tag = (bytes.fromhex(t[x]) for x in ("key", "msg", "tag"))
            got = hmac.new(k, msg, "sha256").digest()
            match = (got == tag) == (t["result"] == "valid")
            ok += match
            out.append({"tcId": t["tcId"], "key": t["key"], "msg": t["msg"], "tag": t["tag"], "result": t["result"], "match": match})
    return {"vectors": out, "total": len(out), "matched": ok, "independent": ["Python hmac/hashlib"], "ref": _wy_ref("hmac_sha256_test.json")}


def kat_cmac(keysize):
    from cryptography.hazmat.primitives import cmac
    from cryptography.hazmat.primitives.ciphers import algorithms
    d = _wy("aes_cmac_test.json")
    out, ok = [], 0
    for g in d["testGroups"]:
        if g["keySize"] != keysize or g["tagSize"] != 128:
            continue
        for t in g["tests"]:
            k, msg, tag = (bytes.fromhex(t[x]) for x in ("key", "msg", "tag"))
            c = cmac.CMAC(algorithms.AES(k))
            c.update(msg)
            got = c.finalize()
            match = (got == tag) == (t["result"] == "valid")
            ok += match
            out.append({"tcId": t["tcId"], "key": t["key"], "msg": t["msg"], "tag": t["tag"], "result": t["result"], "match": match})
    return {"vectors": out, "total": len(out), "matched": ok, "independent": ["pyca/cryptography"], "ref": _wy_ref("aes_cmac_test.json")}


def kat_rsa_oaep(bits):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    out, ok = [], 0
    base = _core_kat("RSA-OAEP-2048") if bits == 2048 else {"vectors": [], "total": 0, "matched": 0}
    d = _wy(f"rsa_oaep_{bits}_sha256_mgf1sha256_test.json")
    for g in d["testGroups"]:
        sk = serialization.load_der_private_key(bytes.fromhex(g["privateKeyPkcs8"]), None)
        n = sk.private_numbers()
        core_key = rsa_oaep.PrivateKey(n.public_numbers.n, n.public_numbers.e, n.d, n.p, n.q)
        for t in g["tests"]:
            ct, msg, label = (bytes.fromhex(t[x]) for x in ("ct", "msg", "label"))
            try:
                lib = sk.decrypt(ct, padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), label or None)) == msg
            except Exception:
                lib = False
            try:
                cr = rsa_oaep.decrypt(core_key, ct, label=label, hash_name="sha256") == msg
            except Exception:
                cr = False
            valid = t["result"] == "valid"
            match = (lib == valid) and (cr == valid) or t["result"] == "acceptable"
            ok += match
            out.append({"tcId": t["tcId"], "ct": t["ct"], "msg": t["msg"], "label": t["label"], "result": t["result"],
                        "core": cr, "lib": lib, "match": match})
    return {"vectors": base["vectors"] + out, "total": base["total"] + len(out), "matched": base["matched"] + ok,
            "independent": ["core/rsa_oaep.py", "pyca/cryptography"], "ref": _wy_ref(f"rsa_oaep_{bits}_sha256_mgf1sha256_test.json") + "; PKCS#1 v2.1 oaep-vect.txt"}


def kat_ecdh384():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec as cec
    d = _wy("ecdh_secp384r1_test.json")
    out, ok = [], 0
    for g in d["testGroups"]:
        for t in g["tests"]:
            try:
                pub = serialization.load_der_public_key(bytes.fromhex(t["public"]))
                priv = cec.derive_private_key(int(t["private"], 16), cec.SECP384R1())
                got = priv.exchange(cec.ECDH(), pub).hex()
                lib = "valid" if got == t["shared"] else "invalid"
            except Exception:
                lib = "invalid"
            match = (lib == "valid") == (t["result"] == "valid") or t["result"] == "acceptable"
            ok += match
            out.append({"tcId": t["tcId"], "public": t["public"], "private": t["private"], "shared": t["shared"],
                        "result": t["result"], "flags": t["flags"], "match": match})
    return {"vectors": out, "total": len(out), "matched": ok, "independent": ["pyca/cryptography"], "ref": _wy_ref("ecdh_secp384r1_test.json")}


def kat_x25519():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    d = _wy("x25519_test.json")
    out, ok = [], 0
    for g in d["testGroups"]:
        for t in g["tests"]:
            try:
                got = X25519PrivateKey.from_private_bytes(bytes.fromhex(t["private"])).exchange(
                    X25519PublicKey.from_public_bytes(bytes.fromhex(t["public"]))).hex()
                lib = "valid" if got == t["shared"] else "invalid"
            except Exception:
                lib = "invalid"          # mis. shared secret nol (low-order) ditolak pustaka
            match = (lib == "valid") == (t["result"] == "valid") or t["result"] == "acceptable"
            ok += match
            out.append({"tcId": t["tcId"], "public": t["public"], "private": t["private"], "shared": t["shared"],
                        "result": t["result"], "flags": t["flags"], "match": match})
    return {"vectors": out, "total": len(out), "matched": ok, "independent": ["pyca/cryptography"], "ref": _wy_ref("x25519_test.json"),
            "note": "Vektor 'acceptable' (low-order, shared secret nol) wajib DITOLAK menurut profil (PR-S-03)"}


def kat_ed25519():
    from cryptography.hazmat.primitives import serialization
    d = _wy("ed25519_test.json")
    out, ok = [], 0
    for g in d["testGroups"]:
        pk = serialization.load_der_public_key(bytes.fromhex(g["publicKeyDer"]))
        for t in g["tests"]:
            try:
                pk.verify(bytes.fromhex(t["sig"]), bytes.fromhex(t["msg"]))
                lib = "valid"
            except Exception:
                lib = "invalid"
            match = (lib == "valid") == (t["result"] == "valid")
            ok += match
            out.append({"tcId": t["tcId"], "pub": g["publicKeyDer"], "msg": t["msg"], "sig": t["sig"], "result": t["result"], "match": match})
    return {"vectors": out, "total": len(out), "matched": ok, "independent": ["pyca/cryptography"], "ref": _wy_ref("ed25519_test.json")}


def kat_hash(tid):
    name = tid.replace("-512", "-512") if tid != "BLAKE2B-512" else tid
    h = HASHLIB.get(name)
    vec = []
    if name in HASH_ABC and h:
        got = hashlib.new(h, b"abc").digest().hex()
        core = keccak.sha3_256(b"abc").hex() if name == "SHA3-256" else None
        vec.append({"id": f"{name}-abc", "msg": "616263", "md": HASH_ABC[name], "match": got == HASH_ABC[name] and core in (None, got)})
    if name == "SHAKE256":
        got = hashlib.shake_256(b"").hexdigest(64)
        vec.append({"id": "SHAKE256-empty-512", "msg": "", "md": SHAKE256_EMPTY_512, "match": got == SHAKE256_EMPTY_512})
    if name == "SHA3-256":
        vec += _core_kat("SHA3-256")["vectors"]
    return {"vectors": vec, "total": len(vec), "matched": sum(1 for x in vec if x["match"]),
            "independent": ["hashlib (OpenSSL)"] + (["core/keccak.py"] if name == "SHA3-256" else [])}


def hash_boundaries(tid, lengths):
    """Digest pada nilai batas panjang pesan — dua implementasi independen bila tersedia + vektor resmi 'abc'."""
    h = HASHLIB.get(tid) or ("shake_256" if tid == "SHAKE256" else None)
    if not h:
        return None
    base = kat_hash(tid)
    vec = []
    for n in lengths:
        if not isinstance(n, int) or n > (1 << 20):
            continue
        m = bytes((i * 7 + 1) & 0xFF for i in range(n))       # pesan uji deterministik
        got = hashlib.shake_256(m).hexdigest(64) if tid == "SHAKE256" else hashlib.new(h, m).hexdigest()
        core = keccak.sha3_256(m).hex() if tid == "SHA3-256" else None
        vec.append({"len": n, "msg_gen": "m[i] = (7i + 1) mod 256", "md": got, "core": core,
                    "match": core in (None, got)})
    official = base["total"] > 0 and base["matched"] == base["total"]
    return {"vectors": base["vectors"] + vec, "total": base["total"] + len(vec),
            "matched": base["matched"] + sum(v["match"] for v in vec),
            "independent": base["independent"], "official_match": official}


def rfc6979():
    r = _core_kat("ECDSA-P256")
    data = json.loads((Path(core_kat.__file__).parent / "vectors" / "ecdsa_p256.json").read_text())
    r["vectors"] = [{**v, **next((c for c in data["cases"] if c["id"] == v["id"]), {})} for v in r["vectors"]]
    r["independent"] = ["core/ecdsa_p256.py"]
    return r


def _der_strict(sig: bytes):
    """Parser DER ketat ECDSA-Sig-Value (SEQUENCE{INTEGER r, INTEGER s}); None bila tidak kanonik."""
    def rd_len(b, i):
        if i >= len(b):
            return None, i
        L = b[i]
        if L < 0x80:
            return L, i + 1
        n = L & 0x7F
        if n == 0 or n > 2 or i + 1 + n > len(b) or b[i + 1] == 0:
            return None, i
        v = int.from_bytes(b[i + 1:i + 1 + n], "big")
        if v < 0x80:
            return None, i
        return v, i + 1 + n

    def rd_int(b, i):
        if i >= len(b) or b[i] != 0x02:
            return None, i
        L, j = rd_len(b, i + 1)
        if L is None or L == 0 or j + L > len(b):
            return None, i
        v = b[j:j + L]
        if v[0] & 0x80 or (L > 1 and v[0] == 0 and not v[1] & 0x80):
            return None, i
        return int.from_bytes(v, "big"), j + L
    if len(sig) < 2 or sig[0] != 0x30:
        return None
    L, i = rd_len(sig, 1)
    if L is None or i + L != len(sig):
        return None
    r, i = rd_int(sig, i)
    if r is None:
        return None
    s, i = rd_int(sig, i)
    if s is None or i != len(sig):
        return None
    return r, s


def _der_encode(r, s):
    def enc(x):
        b = x.to_bytes((x.bit_length() + 8) // 8 or 1, "big")
        return b"\x02" + bytes([len(b)]) + b
    body = enc(r) + enc(s)
    return b"\x30" + bytes([len(body)]) + body


def sigver_p256():
    """≥ 500 vektor SigVer: Wycheproof (resmi) + mutasi encoding dari tanda tangan RFC 6979 (dihitung core/)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec as cec
    d = _wy("ecdsa_secp256r1_sha256_test.json")
    out, ok = [], 0
    for g in d["testGroups"]:
        Q = (int(g["publicKey"]["wx"], 16), int(g["publicKey"]["wy"], 16))
        pk = serialization.load_der_public_key(bytes.fromhex(g["publicKeyDer"]))
        for t in g["tests"]:
            msg, sig = bytes.fromhex(t["msg"]), bytes.fromhex(t["sig"])
            rs = _der_strict(sig)
            core_ok = bool(rs) and ec.is_on_curve(Q) and ec.verify(Q, msg, rs)
            try:
                pk.verify(sig, msg, cec.ECDSA(hashes.SHA256()))
                lib_ok = True
            except Exception:
                lib_ok = False
            valid = t["result"] == "valid"
            match = (core_ok == valid and lib_ok == valid) or t["result"] == "acceptable"
            ok += match
            out.append({"id": f"wy-{t['tcId']}", "source": "Wycheproof", "qx": g["publicKey"]["wx"], "qy": g["publicKey"]["wy"],
                        "msg": t["msg"], "sig": t["sig"], "result": t["result"], "expect": "accept" if valid else "reject",
                        "comment": t["comment"], "core": core_ok, "lib": lib_ok, "match": match})
    # mutasi encoding (HASIL UJI LANGSUNG): kunci uji RFC 6979 A.2.5
    dkey = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    Q = ec.public_key(dkey)
    pk = cec.EllipticCurvePublicNumbers(Q[0], Q[1], cec.SECP256R1()).public_key()
    muts = []
    for i in range(4):
        m = f"cryptan-uk2-{i}".encode()
        r, s = ec.sign(dkey, m)
        muts += [(m, _der_encode(r, s), "valid", "RFC 6979 valid"),
                 (m, _der_encode(r, ec.N - s), "valid", "s ↔ n−s (malleable, high-s) — diterima FIPS 186-5; catat kebijakan low-s"),
                 (m, _der_encode(0, s), "invalid", "r = 0"), (m, _der_encode(r, 0), "invalid", "s = 0"),
                 (m, _der_encode(r + ec.N, s), "invalid", "r ≥ n"), (m, _der_encode(r, s + ec.N), "invalid", "s ≥ n"),
                 (m, b"\x30\x81" + _der_encode(r, s)[1:], "invalid", "panjang DER non-minimal"),
                 (m + b"x", _der_encode(r, s), "invalid", "pesan diubah")]
    for j, (m, sig, res, com) in enumerate(muts):
        rs = _der_strict(sig)
        core_ok = bool(rs) and ec.verify(Q, m, rs)
        try:
            pk.verify(sig, m, cec.ECDSA(hashes.SHA256()))
            lib_ok = True
        except Exception:
            lib_ok = False
        valid = res == "valid"
        match = core_ok == valid and lib_ok == valid
        ok += match
        out.append({"id": f"mut-{j + 1}", "source": DIRECT, "qx": f"{Q[0]:064x}", "qy": f"{Q[1]:064x}", "msg": m.hex(), "sig": sig.hex(),
                    "result": res, "expect": "accept" if valid else "reject", "comment": com, "core": core_ok, "lib": lib_ok, "match": match})
    return {"vectors": out, "total": len(out), "matched": ok, "independent": ["core/ecdsa_p256.py (+ parser DER ketat)", "pyca/cryptography"],
            "ref": _wy_ref("ecdsa_secp256r1_sha256_test.json") + " + mutasi encoding (HASIL UJI LANGSUNG)"}


def curve_points():
    from cryptography.hazmat.primitives.asymmetric import ec as cec
    G = ec.G
    twoG = ec.point_add(G, G)
    lib2 = cec.derive_private_key(2, cec.SECP256R1()).public_key().public_numbers()
    negG = (G[0], (-G[1]) % ec.P)
    vec = [{"case": "P + P = 2G", "x": f"{twoG[0]:064x}", "y": f"{twoG[1]:064x}", "match": (lib2.x, lib2.y) == twoG},
           {"case": "P + (−P) = O", "result": "O", "match": ec.point_add(G, negG) is ec.INF},
           {"case": "n·G = O", "result": "O", "match": ec.scalar_mult(ec.N - 1, G) == negG},
           {"case": "O + P = P", "match": ec.point_add(ec.INF, G) == G}]
    return {"vectors": vec, "total": len(vec), "matched": sum(v["match"] for v in vec), "independent": ["core/ecdsa_p256.py", "pyca/cryptography"]}


def domain_params():
    from core.numtheory import miller_rabin
    vec = [{"param": k, "value": f"{v:x}"} for k, v in (("p", ec.P), ("a", ec.A), ("b", ec.B), ("Gx", ec.GX), ("Gy", ec.GY), ("n", ec.N))]
    vec += [{"param": "h", "value": "1"}, {"check": "n prima", "match": miller_rabin(ec.N, 64)}, {"check": "G di kurva", "match": ec.is_on_curve(ec.G)}]
    return {"vectors": vec, "total": 2, "matched": int(miller_rabin(ec.N, 64)) + int(ec.is_on_curve(ec.G)),
            "independent": ["core/ecdsa_p256.py"], "note": "Konstanta acuan SP 800-186 §3.2.1.3; konsistensi dikonfirmasi oleh KAT RFC 6979 & interop pyca"}


def rfc8448():
    """Hitung ulang seluruh HKDF-Extract/Expand pada jejak RFC 8448 §3 (TLS_AES_128_GCM_SHA256)."""
    txt = (VEC / "rfc8448.txt").read_text()
    # buang header/footer halaman RFC (form feed, "Thomson … [Page n]", "RFC 8448 … January 2019")
    txt = "\n".join(l for l in txt.replace("\f", "\n").splitlines()
                    if not re.match(r"^(Thomson\s|RFC 8448\s)", l))
    sec = txt[txt.find("\n3.  Simple 1-RTT Handshake"):txt.find("\n4.  Resumed 0-RTT Handshake")]
    fields = []
    for m in re.finditer(r"^\s{6}([A-Za-z][A-Za-z ]*?) \((\d+) octets\):((?:[ \n]+[0-9a-f]{2})+)", sec, re.M):
        fields.append((m.group(1).strip(), bytes.fromhex("".join(m.group(3).split()))))
    vec, prk, salt, ikm = [], None, None, None
    pending = {}
    for name, val in fields:
        if name == "salt":
            salt = val
        elif name == "IKM":
            ikm = val
        elif name == "secret" and salt is not None and ikm is not None:
            got = hmac.new(salt, ikm, "sha256").digest()
            vec.append({"op": "HKDF-Extract", "salt": salt.hex(), "ikm": ikm.hex(), "expected": val.hex(), "match": got == val})
            salt = ikm = None
        elif name == "PRK":
            prk = val
        elif name.endswith("info"):
            pending[name[:-4].strip()] = val
        elif name.endswith("expanded") and prk is not None:
            key = name[:-8].strip()
            info = pending.pop(key, None)
            if info is None:
                continue
            L = len(val)
            okm, t, i = b"", b"", 1
            while len(okm) < L:
                t = hmac.new(prk, t + info + bytes([i]), "sha256").digest()
                okm += t
                i += 1
            vec.append({"op": "HKDF-Expand-Label", "label": info[3:3 + info[2]].decode(errors="replace"), "prk": prk.hex(),
                        "info": info.hex(), "expected": val.hex(), "match": okm[:L] == val})
    return {"vectors": vec, "total": len(vec), "matched": sum(v["match"] for v in vec), "independent": ["Python hmac (HKDF RFC 5869)"],
            "ref": "RFC 8448 §3 Simple 1-RTT Handshake", "note": "Jejak RFC 8448 memakai SHA-256; untuk TLS_AES_256_GCM_SHA384 tidak ada jejak resmi → PERLU_VERIFIKASI (gunakan vektor interop)"}


# =============================================================== STATISTIK / KRIPTANALITIK / IMPLEMENTASI
def statistical(kind, tc):
    s = 100
    thr = stats.sp80022_proportion_threshold(s, ALPHA)
    base = {"alpha": ALPHA, "sp800_22": {"sequences": s, "bits_per_sequence": 10 ** 6, "proportion_min": round(thr, 5),
                                         "proportion_formula": "0,99 − 3·√(0,99·0,01/s)", "min_pass_of_100": math.ceil(thr * s),
                                         "uniformity_p_value_T_min": 0.0001}}
    if kind in ("avalanche_sp80022",):
        n = 128 if tc["category"] == "block" else 512 if tc["category"] == "stream" else 256
        N = 10000
        base["avalanche"] = {"output_bits_n": n, "mean_hw": n / 2, "sigma_hw": math.sqrt(n) / 2,
                             "mean_fraction": 0.5, "acceptance_fraction": [round(0.5 - 3 * 0.5 / math.sqrt(n * N), 5), round(0.5 + 3 * 0.5 / math.sqrt(n * N), 5)],
                             "samples_N": N}
    if kind == "nonce_stats":
        base["nonce"] = {"repeated_r_allowed": 0, "msb_lsb_bias_test": "χ² df=255 pada 8 bit teratas/terbawah k, p ≥ 0,01",
                         "hnp_rule": "bias ≥ 1 bit → Tidak Memenuhi (lattice/HNP)", "samples_N": 10 ** 6}
    if kind == "rng_stats":
        base["sp800_90b"] = {"min_entropy_per_sample": "≥ klaim vendor (PERLU_VERIFIKASI: nilai klaim)", "health_tests": ["Repetition Count", "Adaptive Proportion"]}
    if kind == "generic_bound":
        base["generic"] = {f"t={t}": {"expected_work": round(math.sqrt(math.pi / 2 * 2 ** t), 1), "tolerance": "±20%"} for t in (16, 24, 32)}
    return base


IMPL = {
    "tvla": {"tvla_abs_t_max": 4.5, "measurements_min": 10 ** 5, "method": "Welch t fixed-vs-random (ISO/IEC 17825)"},
    "oracle": {"error_classes": 1, "tvla_abs_t_max": 4.5, "error_code": ERR["decrypt"]},
    "fuzz": {"crash": 0, "hang": 0, "sanitizer_errors": 0, "executions_min": 10 ** 6, "error_code": ERR["format"]},
    "zeroize": {"residual_key_occurrences": 0},
    "fault": {"faulty_outputs_released": 0},
    "performance": {"criterion": "sesuai klaim kinerja produk", "status": VERIFY},
    "error_handling": {"defined_error_codes": True, "secret_in_logs": 0},
    "sast": {"high_findings": 0, "branch_coverage_min": 0.9},
    "selftest": {"output_inhibited_on_error": True, "error_code": ERR["state"]},
    "tamper": {"detected": True, "ssp_zeroised": True},
}


def build(ctx, recipes: list, out_dir: Path, attacks: list = None) -> dict:
    """Bangkitkan semua berkas expected; kembalikan indeks {(gen, target): ref} + manifest SHA-256."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cache, refs, manifest = {}, {}, []
    attacks = attacks or ctx.attacks
    obj = {o["id"]: o for o in ctx.objects}

    def det(gen, tid):
        o = obj.get(tid, {})
        if gen in ("kat", "kat_gcm256"):
            if tid == "AES-128-CTR":
                return kat_aes_ctr(), [LIT + ": FIPS 197, SP 800-38A F.1.1/F.5.1"]
            if tid in ("AES-128-GCM", "AES-192-GCM", "AES-256-GCM"):
                return kat_aes_gcm(o.get("key_bits") or 256), [_wy_ref("aes_gcm_test.json")]
            if tid.endswith("-KW") and o.get("key_bits"):
                return kat_aes_kw(o["key_bits"]), [_wy_ref("aes_wrap_test.json")]
            if tid == "CHACHA20-256":
                r = _core_kat("ChaCha20")
                r["independent"] = ["core/chacha20.py"]
                return r, ["RFC 8439 §2.3.2, §2.4.2, A.1"]
            if tid == "CHACHA20-POLY1305":
                return kat_chacha_poly(), [_wy_ref("chacha20_poly1305_test.json")]
            if tid.startswith("HMAC-SHA-256-K"):
                return kat_hmac256(o["key_bits"]), [_wy_ref("hmac_sha256_test.json")]
            if tid.startswith("CMAC-AES-") and o.get("key_bits") in (128, 192, 256):
                return kat_cmac(o["key_bits"]), [_wy_ref("aes_cmac_test.json")]
            if tid in ("RSA-OAEP-2048", "RSA-OAEP-3072"):
                return kat_rsa_oaep(o["key_bits"]), []
            if tid == "ECDH-P384":
                return kat_ecdh384(), []
            if tid == "X25519":
                return kat_x25519(), []
            if tid == "ED25519":
                return kat_ed25519(), []
            if tid == "ECDSA-P256":
                return rfc6979(), ["RFC 6979 A.2.5"]
            if tid == "HKDF":
                return rfc8448(), ["RFC 8448 §3 (HKDF-SHA256 key schedule TLS 1.3)"]
            if tid in HASHLIB or tid == "SHAKE256":
                return kat_hash(tid), ["FIPS 180-4 / FIPS 202 / RFC 7693 (contoh 'abc')"]
            return None, []
        if gen == "hash_boundaries":
            lens = []
            for c in ctx_ps["categories"].values():
                for p in c["params"]:
                    if p["id"] in (f"HF-LEN-{tid}",) or (p["id"] == "DS-MSG"):
                        lens += [v["value"] for v in p["values"] if v["in_spec"]]
            r = hash_boundaries(tid, sorted(set(x for x in lens if isinstance(x, int))) or [0, 1, 55, 56, 63, 64, 65])
            return r, ["FIPS 180-4 / FIPS 202 (contoh 'abc')"] if r else []
        if gen == "rfc6979":
            return rfc6979(), ["RFC 6979 A.2.5"]
        if gen == "sigver" and tid == "ECDSA-P256":
            return sigver_p256(), []
        if gen == "curve_points" and tid == "ECDSA-P256":
            return curve_points(), ["SP 800-186 (P-256)"]
        if gen == "domain_params" and tid == "ECDSA-P256":
            return domain_params(), ["SP 800-186 §3.2.1.3"]
        if gen == "rfc8448":
            return rfc8448(), ["RFC 8448 §3"]
        return None, []

    ctx_ps = build.pspace
    for r in recipes:
        e = r.get("expected", {})
        kind, gen = e.get("kind"), e.get("gen")
        for tid in r["targets"]:
            key = (gen, tid)
            if key in cache:
                refs[(r["id"], tid)] = cache[key]
                continue
            rec = {"id": f"{gen}__{re.sub(r'[^A-Za-z0-9_.-]+', '_', tid)}", "generator": gen, "kind": kind, "target": tid}
            if kind in ("deterministic", "negative") and gen in ("kat", "kat_gcm256", "hash_boundaries", "rfc6979", "sigver",
                                                                 "curve_points", "domain_params", "rfc8448"):
                res, rf = det(gen, tid)
                if res:
                    official = res["total"] > 0 and res["matched"] == res["total"]
                    rec.update(source=DIRECT + " (dicocokkan dengan " + LIT + ")", status=OK_OFFICIAL if official else VERIFY,
                               references=rf + ([res["ref"]] if res.get("ref") else []), independent=res.get("independent", []),
                               summary={"total": res["total"], "matched": res["matched"]}, vectors=res["vectors"],
                               decision="Deterministik: keluaran produk identik 100% dengan expected; vektor 'invalid' wajib ditolak")
                    if res.get("note"):
                        rec["note"] = res["note"]
                else:
                    rec.update(source=VERIFY, status=VERIFY, references=[],
                               note=f"Expected value deterministik untuk {tid} belum dapat dihitung/dicocokkan (vektor resmi ACVP/CAVP belum dimuat) — "
                                    "JANGAN dikarang; unduh vektor ACVP untuk algoritma ini",
                               decision="Deterministik: identik 100% dengan vektor resmi (menunggu vektor)")
            elif kind == "negative":
                rec.update(source=DIRECT, status=CRITERIA, decision="Seluruh masukan negatif DITOLAK",
                           expected_errors=sorted(set(ERR.values())), reject=True,
                           cases=[pv for pv in r.get("param_values", []) if not pv["in_spec"]])
            elif kind == "statistical":
                rec.update(source=DIRECT + " (rumus)", status=CRITERIA, criteria=statistical(gen, r),
                           decision="Statistik: lolos bila seluruh kriteria terpenuhi; di tepi interval → Inkonklusif (perbesar sampel)")
            elif kind == "cryptanalytic":
                o = obj.get(tid, {})
                strength = o.get("security_strength_bits")
                best = sorted({a["id"]: a for a in attacks if a.get("complexity", {}).get("time_log2") and (
                    a.get("primitives") == "all" or (o and _cat_prim(o) in a.get("primitives", [])))}.values(),
                    key=lambda a: a["complexity"]["time_log2"])[:3]
                measurable = isinstance(strength, int) or (isinstance(strength, str) and strength.startswith("<"))
                rec.update(source=LIT, status=CRITERIA if measurable else VERIFY,
                           criteria={"claimed_security_bits": strength, "min_required_bits": 112,
                                     "best_attacks_literature": [{"id": a["id"], "name": a["name"], "time_log2": a["complexity"]["time_log2"],
                                                                  "status": a["status"]} for a in best],
                                     "rule": "kompleksitas serangan terbaik (ronde penuh) ≥ klaim bit security"},
                           decision="Kriptanalitik: Memenuhi bila serangan terbaik ≥ klaim; Memenuhi dengan Catatan bila 112 ≤ klaim < 128 (transisi 2030)")
            elif kind == "implementation":
                rec.update(source=LIT + " (ISO/IEC 17825/19790)", status=VERIFY if IMPL.get(gen, {}).get("status") == VERIFY else CRITERIA,
                           criteria=IMPL.get(gen, {"criterion": r.get("pass")}), decision=r.get("pass"))
            else:
                rec.update(source=DIRECT, status=CRITERIA, criteria={"pass": r.get("pass")}, decision=r.get("pass"))
            path = out_dir / f"{rec['id']}.json"
            data = json.dumps(rec, indent=1, ensure_ascii=False, default=str)
            path.write_text(data, encoding="utf-8")
            digest = hashlib.sha256(data.encode()).hexdigest()
            ref = {"file": f"expected/{path.name}", "sha256": digest, "status": rec["status"], "kind": kind}
            manifest.append({**ref, "id": rec["id"], "target": tid, "generator": gen,
                             "summary": rec.get("summary")})
            cache[key] = ref
            refs[(r["id"], tid)] = ref
    (out_dir / "MANIFEST.json").write_text(json.dumps(sorted(manifest, key=lambda m: m["id"]), indent=1, ensure_ascii=False), encoding="utf-8")
    return {"refs": refs, "manifest": manifest}


def _cat_prim(o):
    return {"block_cipher": "block_cipher", "stream_cipher": "stream_cipher", "hash": "hash", "mac": "hash", "kdf": "hash",
            "pkc_kem": "pkc", "signature": "dss", "drbg": "hash"}[o["primitive"]]


build.pspace = {"categories": {}}
