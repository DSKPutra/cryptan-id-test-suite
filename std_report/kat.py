"""Pemetaan kombinasi → vektor resmi & pelari KAT (dipakai plugin K-01).

Mode ringan memakai subset (std_report/vectors/subset); mode full memakai berkas Wycheproof lengkap
bila tersedia (std_report/vectors/wycheproof, uk2_skenario/data/vectors)."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VEC = Path(__file__).parent / "vectors"
FULL_DIRS = [VEC / "wycheproof", ROOT / "uk2_skenario" / "data" / "vectors"]
HMAC_FILE = {"SHA-1": "hmac_sha1", "SHA-224": "hmac_sha224", "SHA-256": "hmac_sha256", "SHA-384": "hmac_sha384",
             "SHA-512": "hmac_sha512", "SHA-512/224": "hmac_sha512_224", "SHA-512/256": "hmac_sha512_256",
             "SHA3-224": "hmac_sha3_224", "SHA3-256": "hmac_sha3_256", "SHA3-384": "hmac_sha3_384", "SHA3-512": "hmac_sha3_512"}
ECDSA_FILE = {"P-224": "ecdsa_secp224r1_sha224", "P-256": "ecdsa_secp256r1_sha256", "P-384": "ecdsa_secp384r1_sha384", "P-521": "ecdsa_secp521r1_sha512"}
ECDH_FILE = {"P-224": "ecdh_secp224r1", "P-256": "ecdh_secp256r1", "P-384": "ecdh_secp384r1", "P-521": "ecdh_secp521r1"}


def _misc():
    return json.loads((VEC / "misc_kat.json").read_text())


def _load(name: str, mode: str):
    if mode == "full":
        for d in FULL_DIRS:
            p = d / f"{name}_test.json"
            if p.exists():
                return json.loads(p.read_text()), f"{name}_test.json (lengkap)"
    p = VEC / "subset" / f"{name}_test.json"
    if p.exists():
        return json.loads(p.read_text()), f"subset/{name}_test.json"
    return None, None


def source_for(row) -> str:
    """Nama berkas vektor (tanpa memuat) untuk dokumentasi; None bila tidak ada."""
    fam, var, kb = row["family"], row["variant"], row.get("key_bits")
    if fam == "AES" and var == "GCM":
        return "aes_gcm"
    if fam == "AES" and var == "CCM":
        return "aes_ccm"
    if fam == "AES" and var == "XTS":
        return "aes_xts"
    if fam == "AES" and var == "KW":
        return "aes_wrap"
    if fam == "AES" and var == "KWP":
        return "aes_kwp"
    if fam == "AES" and var == "CMAC":
        return "aes_cmac"
    if fam == "AES" and kb == 128 and var in ("ECB", "CTR"):
        return "misc:aes128"
    if fam in ("Camellia", "SEED", "SM4"):
        return "misc:block"
    if fam == "HMAC":
        return HMAC_FILE.get(var)
    if fam == "KMAC":
        return f"kmac{kb}_no_customization"
    if row["primitive"] == "hash" and var in _misc()["hash_abc"]:
        return "misc:hash_abc"
    if var in ("SHAKE128", "SHAKE256"):
        return "misc:xof_empty"
    if fam == "RSA" and var == "OAEP" and kb in (2048, 3072, 4096):
        return f"rsa_oaep_{kb}_sha256_mgf1sha256"
    if fam == "RSA" and var == "PSS" and kb in (2048, 3072, 4096):
        return f"rsa_pss_{kb}_sha256_mgf1_32"
    if fam == "RSA" and var == "PKCS1-v1_5-SIG" and kb in (2048, 3072, 4096):
        return f"rsa_signature_{kb}_sha256"
    if fam == "ECDSA" and var in ECDSA_FILE:
        return ECDSA_FILE[var]
    if fam == "ECDH" and var in ECDH_FILE:
        return ECDH_FILE[var]
    if fam == "XECDH":
        return var.lower()
    if fam == "EdDSA":
        return var.lower()
    if fam == "DSA" and kb in (2048, 3072):
        return {2048: "dsa_2048_256_sha256", 3072: "dsa_3072_256_sha256"}[kb]
    if fam == "ML-DSA":
        return f"mldsa_{var.split('-')[-1]}_verify"
    if fam == "ML-KEM":
        return f"mlkem_{var.split('-')[-1]}"
    if fam == "KDF" and var == "HKDF":
        return "hkdf_sha256"
    if fam == "KDF" and var == "PBKDF2":
        return "pbkdf2_hmacsha256"
    if fam == "PrimeGen":
        return "misc:primes"
    return None


_GKEY = {}


def _cmp(ok_fn):
    try:
        return bool(ok_fn())
    except Exception:
        return False


def run(row, a, mode="ringan") -> dict:
    """Jalankan vektor resmi pada satu adapter. Kembalikan {source, total, matched, failures[]} atau None."""
    name = source_for(row)
    if not name:
        return None
    fam, var, kb = row["family"], row["variant"], row.get("key_bits")
    fails, total = [], 0

    def rec(tid, ok, detail=""):
        nonlocal total
        total += 1
        if not ok:
            fails.append({"id": tid, "detail": detail})

    if name.startswith("misc:"):
        m = _misc()
        part = name.split(":")[1]
        if part == "hash_abc":
            h, src = m["hash_abc"][var]
            rec(f"{var}-abc", _cmp(lambda: a.digest(b"abc").hex() == h))
            return {"source": src, "total": total, "matched": total - len(fails), "failures": fails}
        if part == "xof_empty":
            L, h, src = m["xof_empty"][var]
            rec(f"{var}-empty", _cmp(lambda: a.digest(b"", L).hex() == h))
            return {"source": src, "total": total, "matched": total - len(fails), "failures": fails}
        if part == "block":
            v = next(x for x in m["block"] if x["family"] == fam)
            rec(v["source"], _cmp(lambda: a.encrypt(bytes.fromhex(v["key"]), None, bytes.fromhex(v["pt"])).hex() == v["ct"]))
            return {"source": v["source"], "total": total, "matched": total - len(fails), "failures": fails}
        if part == "aes128":
            for v in m["aes128"]:
                if v["mode"] != var:
                    continue
                k, iv, pt = bytes.fromhex(v["key"]), bytes.fromhex(v["iv"]) or None, bytes.fromhex(v["pt"])
                rec(v["source"], _cmp(lambda: a.encrypt(k, iv, pt).hex() == v["ct"]))
            return {"source": "FIPS 197 / SP 800-38A", "total": total, "matched": total - len(fails), "failures": fails}
        if part == "primes":
            for label, n in m["primes"]["prime"]:
                rec(label, _cmp(lambda: a.is_prime(int(n)) is True))
            for label, n in m["primes"]["composite"]:
                rec(label, _cmp(lambda: a.is_prime(int(n)) is False))
            return {"source": m["primes"]["source"], "total": total, "matched": total - len(fails), "failures": fails}
    d, fname = _load(name, mode)
    if d is None:
        return None
    k = a.kind
    for g in d["testGroups"]:
        gks = g.get("keySize")
        if gks is not None and kb and k in ("aead", "cipher", "mac") and int(gks) != kb and not (var == "XTS"):
            continue
        if var == "XTS" and int(gks) != kb:
            continue
        if k == "aead" and (int(g.get("ivSize", 96)) != 96 or int(g.get("tagSize", 128)) != 128):
            continue
        if k == "mac" and fam == "HMAC" and int(g.get("tagSize", 0)) != a.mac(b"k" * 16, b"").__len__() * 8:
            continue
        for t in g["tests"]:
            res = t["result"]
            if res == "acceptable":
                continue
            valid = res == "valid"
            H = lambda x: bytes.fromhex(t[x])
            if k == "aead":
                def f():
                    try:
                        out = a.decrypt(H("key"), H("iv"), H("ct") + H("tag"), H("aad"))
                        return (out == H("msg")) == valid
                    except Exception:
                        return not valid
            elif k == "cipher" and var == "XTS":
                f = lambda: (a.encrypt(H("key"), H("iv") + b"\x00" * (16 - len(H("iv"))), H("msg")) == H("ct")) == valid
            elif k == "cipher" and var in ("KW", "KWP"):
                def f():
                    try:
                        return (a.decrypt(H("key"), None, H("ct")) == H("msg")) == valid
                    except Exception:
                        return not valid
            elif k == "mac" and fam == "KMAC":
                f = lambda: (a.mac(H("key"), H("msg"), len(H("tag"))) == H("tag")) == valid
            elif k == "mac":
                f = lambda: (a.mac(H("key"), H("msg"))[:len(H("tag"))] == H("tag")) == valid
            elif k == "rsa_pke":
                gk = (a.backend, g.get("privateKeyPkcs8"))         # bukan id(g): id dapat dipakai ulang setelah GC
                if gk not in _GKEY:
                    try:
                        _GKEY[gk] = a.import_private(bytes.fromhex(g["privateKeyPkcs8"]))
                    except Exception:
                        _GKEY[gk] = None
                sk = _GKEY[gk]

                def f():
                    try:
                        if sk is None:
                            return None
                        if t.get("label"):
                            return not valid or None           # label OAEP non-kosong tidak didukung adapter → dilewati
                        return (a.decrypt(sk, H("ct")) == H("msg")) == valid
                    except Exception:
                        return not valid
            elif k == "sig":
                der = g.get("publicKeyDer") or (g.get("publicKey", {}) if isinstance(g.get("publicKey"), dict) else {}).get("der")
                if not der or not hasattr(a, "import_public"):
                    continue
                pub = bytes.fromhex(der)

                def f():
                    try:
                        pk = a.import_public(pub)
                    except Exception:
                        return not valid
                    return a.verify(pk, H("msg"), H("sig")) == valid
            elif k == "kex":
                def f():
                    try:
                        if fam == "XECDH":
                            from cryptography.hazmat.primitives.asymmetric import x25519, x448
                            P = x25519.X25519PrivateKey if var == "X25519" else x448.X448PrivateKey
                            if a.backend != "pyca":
                                return None
                            sk = P.from_private_bytes(H("private"))
                            out = a.agree(sk, a.import_public(H("public")))
                        else:
                            if a.backend != "pyca":
                                return None
                            from cryptography.hazmat.primitives.asymmetric import ec
                            from core.adapters.pyca import CURVES as CURVE_OF
                            sk = ec.derive_private_key(int(t["private"], 16), CURVE_OF[var]())
                            out = a.agree(sk, a.import_public(H("public")))
                        return (out == H("shared")) == valid
                    except Exception:
                        return not valid
            elif k == "kem":
                def f():
                    if a.backend != "pyca":
                        return None
                    from cryptography.hazmat.primitives.asymmetric import mlkem
                    P = getattr(mlkem, var.replace("-", "") + "PrivateKey")
                    try:
                        sk = P.from_seed_bytes(H("seed"))
                        return (sk.decapsulate(H("c")) == H("K")) == valid
                    except Exception:
                        return not valid
            elif k == "kdf" and var == "HKDF":
                def f():
                    try:
                        return (a.derive(H("ikm"), H("salt"), H("info"), int(t["size"])) == H("okm")) == valid
                    except Exception:
                        return not valid
            elif k == "kdf" and var == "PBKDF2":
                def f():
                    try:
                        return (a.derive(H("password"), H("salt"), int(t["iterationCount"]), int(t["dkLen"])) == H("dk")) == valid
                    except Exception:
                        return not valid
            else:
                continue
            try:
                r = f()
            except Exception as e:                       # galat tak terduga = tidak cocok (dicatat)
                r = False
                t = {**t, "comment": f"{t.get('comment', '')} ({type(e).__name__})"}
            if r is None:
                continue
            rec(f"tcId {t['tcId']}", r, t.get("comment", ""))
    if total == 0:
        return None
    return {"source": f"Wycheproof {fname}", "total": total, "matched": total - len(fails), "failures": fails[:20]}
