"""Runner Known Answer Test (KAT) untuk implementasi referensi di core/.

Setiap algoritma diuji terhadap vektor dari standar resmi (FIPS 197,
SP 800-38A, RFC 8439, FIPS 202/NIST CSRC, PKCS#1 v2.1, RFC 6979).
Kriteria lulus: 100% vektor cocok. Hasilnya HASIL UJI LANGSUNG.

  python -m core.kat            # semua algoritma
  python -m core.kat AES-128
"""
import json
import sys
from pathlib import Path

from . import aes, chacha20, ecdsa_p256, keccak, rsa_oaep

VEC = Path(__file__).parent / "vectors"


def _load(name):
    return json.loads((VEC / name).read_text())


def _msg(c):
    if "msg_ascii" in c:
        return c["msg_ascii"].encode()
    if "msg_repeat" in c:
        return bytes.fromhex(c["msg_repeat"]["byte"]) * c["msg_repeat"]["count"]
    return bytes.fromhex(c.get("msg", ""))


def kat_aes128():
    res = []
    for c in _load("aes128.json")["cases"]:
        k, pt, ct = (bytes.fromhex(c[x]) for x in ("key", "pt", "ct"))
        got = aes.encrypt_block(k, pt)
        ok = got == ct and aes.decrypt_block(k, ct) == pt
        res.append({"id": c["id"], "source": c["source"], "pass": ok, "got": got.hex()})
    return res


def kat_chacha20():
    res = []
    for c in _load("chacha20.json")["cases"]:
        k, n = bytes.fromhex(c["key"]), bytes.fromhex(c["nonce"])
        if c["type"] == "block":
            got = chacha20.block(k, c["counter"], n)
        else:
            got = chacha20.encrypt(k, n, c["pt_ascii"].encode(), c["counter"])
        res.append({"id": c["id"], "source": c["source"], "pass": got.hex() == c["out"], "got": got.hex()})
    return res


def kat_sha3_256():
    res = []
    for c in _load("sha3_256.json")["cases"]:
        got = keccak.sha3_256(_msg(c)).hex()
        res.append({"id": c["id"], "source": c["source"], "pass": got == c["md"], "got": got})
    return res


def kat_rsa_oaep():
    data = _load("rsa_oaep_pkcs1.json")
    res = []
    for key in data["keys"]:
        kv = {x: int(key["key"][x], 16) for x in ("n", "e", "d", "p", "q")}
        priv = rsa_oaep.PrivateKey(kv["n"], kv["e"], kv["d"], kv["p"], kv["q"])
        for c in key["cases"]:
            m, seed, ct = (bytes.fromhex(c[x]) for x in ("msg", "seed", "ct"))
            got = rsa_oaep.encrypt(priv.public(), m, hash_name="sha1", seed=seed)
            ok = got == ct and rsa_oaep.decrypt(priv, ct, hash_name="sha1") == m
            res.append({"id": f"PKCS1-OAEP-{c['id']}", "source": f"{data['source']} (kunci {key['bits']}-bit)",
                        "pass": ok, "got": got.hex()[:32] + "…"})
    return res


def kat_ecdsa_p256():
    data = _load("ecdsa_p256.json")
    d = int(data["key"]["d"], 16)
    Q = (int(data["key"]["Qx"], 16), int(data["key"]["Qy"], 16))
    res = [{"id": "RFC6979-A.2.5-pubkey", "source": data["source"], "pass": ecdsa_p256.public_key(d) == Q,
            "got": "Q = d·G"}]
    import hashlib
    for c in data["cases"]:
        m = _msg(c)
        k = ecdsa_p256.rfc6979_k(d, hashlib.new(c["hash"], m).digest(), c["hash"])
        r, s = ecdsa_p256.sign(d, m, hash_name=c["hash"])
        ok = (k == int(c["k"], 16) and r == int(c["r"], 16) and s == int(c["s"], 16)
              and ecdsa_p256.verify(Q, m, (r, s), c["hash"]))
        res.append({"id": c["id"], "source": data["source"], "pass": ok, "got": f"r={r:064X}"[:24] + "…"})
    return res


RUNNERS = {
    "AES-128": kat_aes128,
    "ChaCha20": kat_chacha20,
    "SHA3-256": kat_sha3_256,
    "RSA-OAEP-2048": kat_rsa_oaep,
    "ECDSA-P256": kat_ecdsa_p256,
}


def run(algorithm: str) -> dict:
    cases = RUNNERS[algorithm]()
    passed = sum(c["pass"] for c in cases)
    return {"algorithm": algorithm, "total": len(cases), "passed": passed,
            "status": "LULUS" if passed == len(cases) else "GAGAL", "cases": cases}


def main(argv=None):
    algs = (argv or sys.argv[1:]) or list(RUNNERS)
    rc = 0
    for a in algs:
        r = run(a)
        print(f"[{r['status']}] {a}: {r['passed']}/{r['total']} vektor cocok")
        for c in r["cases"]:
            print(f"    {'✔' if c['pass'] else '✘'} {c['id']}")
        rc |= r["status"] != "LULUS"
    return rc


if __name__ == "__main__":
    sys.exit(main())
