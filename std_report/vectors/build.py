"""Bangun vektor KAT std_report: subset Wycheproof (seimbang valid/invalid) + vektor resmi lain,
dengan SOURCES.json (sumber, URL, lisensi, SHA-256 subset & berkas asli).

  python -m std_report.vectors.build      # dari std_report/vectors/wycheproof/ (lengkap, tidak di-commit)

Vektor "misc" (contoh 'abc' FIPS 180-4/202, RFC 3713, RFC 4269, GB/T 32907, SP 800-38A) telah
dicocokkan dengan ≥ 2 backend sebelum disimpan; yang tidak cocok tidak dimasukkan.
"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).parent
ROOT = HERE.parents[1]
FULL = [HERE / "wycheproof", ROOT / "uk2_skenario" / "data" / "vectors"]
SUBSET = HERE / "subset"
MAX_PER_FILE = 48
WY_URL = "https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/"

MISC = {
    "source": "Vektor resmi dari dokumen standar (dikutip; dicocokkan ≥ 2 backend di Cryptan.ID)",
    "hash_abc": {
        "SHA-1": ["a9993e364706816aba3e25717850c26c9cd0d89d", "FIPS 180-4 (contoh NIST 'abc')"],
        "SHA-224": ["23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", "FIPS 180-4 (contoh NIST 'abc')"],
        "SHA-256": ["ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "FIPS 180-4 (contoh NIST 'abc')"],
        "SHA-384": ["cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", "FIPS 180-4 (contoh NIST 'abc')"],
        "SHA-512": ["ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", "FIPS 180-4 (contoh NIST 'abc')"],
        "SHA-512/224": ["4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa", "FIPS 180-4 (contoh NIST 'abc')"],
        "SHA-512/256": ["53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23", "FIPS 180-4 (contoh NIST 'abc')"],
        "SHA3-224": ["e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf", "FIPS 202 (contoh NIST 'abc')"],
        "SHA3-256": ["3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", "FIPS 202 (contoh NIST 'abc')"],
        "SHA3-384": ["ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25", "FIPS 202 (contoh NIST 'abc')"],
        "SHA3-512": ["b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0", "FIPS 202 (contoh NIST 'abc')"],
        "SM3": ["66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0", "GB/T 32905-2016 contoh A.1 ('abc')"],
        "RIPEMD-160": ["8eb208f7e05d987a9b044a8e98c6b087f15a0bfc", "ISO/IEC 10118-3 / Dobbertin et al. ('abc')"],
    },
    "xof_empty": {
        "SHAKE128": [32, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26", "FIPS 202 (contoh NIST, pesan kosong)"],
        "SHAKE256": [64, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be", "FIPS 202 (contoh NIST, pesan kosong)"],
    },
    "block": [
        {"family": "Camellia", "key": "0123456789abcdeffedcba9876543210", "pt": "0123456789abcdeffedcba9876543210", "ct": "67673138549669730857065648eabe43", "source": "RFC 3713 App. A (Camellia-128)"},
        {"family": "SEED", "key": "00000000000000000000000000000000", "pt": "000102030405060708090a0b0c0d0e0f", "ct": "5ebac6e0054e166819aff1cc6d346cdb", "source": "RFC 4269 App. B (SEED)"},
        {"family": "SM4", "key": "0123456789abcdeffedcba9876543210", "pt": "0123456789abcdeffedcba9876543210", "ct": "681edf34d206965e86b3e94f536e4246", "source": "GB/T 32907-2016 contoh 1 (SM4)"},
    ],
    "aes128": [
        {"mode": "ECB", "key": "2b7e151628aed2a6abf7158809cf4f3c", "iv": "", "pt": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
         "ct": "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf", "source": "SP 800-38A F.1.1"},
        {"mode": "CTR", "key": "2b7e151628aed2a6abf7158809cf4f3c", "iv": "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
         "pt": "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
         "ct": "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee", "source": "SP 800-38A F.5.1"},
        {"mode": "ECB", "key": "000102030405060708090a0b0c0d0e0f", "iv": "", "pt": "00112233445566778899aabbccddeeff", "ct": "69c4e0d86a7b0430d8cdb78070b4c55a", "source": "FIPS 197 App. C.1"},
    ],
    "primes": {
        "prime": [["2^127 − 1 (Mersenne M127)", str(2 ** 127 - 1)], ["2^521 − 1 (Mersenne M521, p P-521)", str(2 ** 521 - 1)],
                  ["p P-256 (SP 800-186)", str(0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF)],
                  ["n P-256 (SP 800-186)", str(0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551)]],
        "composite": [["561 (bilangan Carmichael)", "561"], ["41041 (Carmichael)", "41041"], ["M127 × M61", str((2 ** 127 - 1) * (2 ** 61 - 1))],
                      ["3215031751 (strong pseudoprime basis 2,3,5,7)", "3215031751"]],
        "source": "Fakta matematis (bilangan Mersenne/Carmichael; parameter SP 800-186)",
    },
}


def _subset(d: dict) -> dict:
    groups = d["testGroups"]
    per = max(2, MAX_PER_FILE // max(1, len(groups)))
    out = []
    for g in groups:
        tests = g["tests"]
        valid = [t for t in tests if t["result"] == "valid"][:max(1, per // 2)]
        other = [t for t in tests if t["result"] != "valid"][:max(1, per - len(valid))]
        out.append({**g, "tests": valid + other})
    keep, n = [], 0
    for g in out:
        if n >= MAX_PER_FILE and keep:
            break
        keep.append(g)
        n += len(g["tests"])
    return {k: v for k, v in d.items() if k != "testGroups"} | {"testGroups": keep, "subsetOf": d.get("numberOfTests")}


def main():
    SUBSET.mkdir(parents=True, exist_ok=True)
    sources = []
    for d in FULL:
        for f in sorted(d.glob("*_test.json")):
            raw = f.read_bytes()
            data = json.loads(raw)
            sub = json.dumps(_subset(data), indent=0, ensure_ascii=False).encode()
            (SUBSET / f.name).write_bytes(sub)
            sources.append({"file": f"subset/{f.name}", "source": f"Wycheproof (C2SP) — {data.get('algorithm')}", "url": WY_URL + f.name,
                            "license": "Apache-2.0", "tests_subset": sum(len(g["tests"]) for g in _subset(data)["testGroups"]),
                            "tests_full": data.get("numberOfTests"), "sha256": hashlib.sha256(sub).hexdigest(),
                            "sha256_original": hashlib.sha256(raw).hexdigest()})
    misc = json.dumps(MISC, indent=1, ensure_ascii=False).encode()
    (HERE / "misc_kat.json").write_bytes(misc)
    sources.append({"file": "misc_kat.json", "source": MISC["source"], "url": "-", "license": "kutipan dokumen standar",
                    "sha256": hashlib.sha256(misc).hexdigest()})
    for f in sorted((ROOT / "core" / "vectors").glob("*.json")):
        sources.append({"file": f"../../core/vectors/{f.name}", "source": "core/vectors (FIPS 197, SP 800-38A, RFC 8439, FIPS 202, PKCS#1, RFC 6979)",
                        "url": "-", "license": "kutipan dokumen standar", "sha256": hashlib.sha256(f.read_bytes()).hexdigest()})
    (HERE / "SOURCES.json").write_text(json.dumps(sources, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"{len(sources)} sumber vektor → {HERE / 'SOURCES.json'}")


if __name__ == "__main__":
    main()
