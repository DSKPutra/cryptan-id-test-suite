"""Ekstrak vektor RSA-OAEP resmi PKCS#1 v2.1 (oaep-vect.txt, RSA Laboratories;
salinan di repo pyca/cryptography) → core/vectors/rsa_oaep_pkcs1.json.

Pemakaian:
  curl -O https://raw.githubusercontent.com/pyca/cryptography/main/vectors/cryptography_vectors/asymmetric/RSA/pkcs-1v2-1d2-vec/oaep-vect.txt
  python scripts/extract_oaep_vectors.py oaep-vect.txt
"""
import json
import re
import sys
from pathlib import Path

SOURCE = ("PKCS #1 v2.1 oaep-vect.txt (RSA Laboratories), via "
          "github.com/pyca/cryptography/vectors/.../pkcs-1v2-1d2-vec/oaep-vect.txt")


def parse(text: str, wanted=(1, 10)):
    out = []
    blocks = re.split(r"# Example (\d+): A (\d+)-bit RSA key pair", text)
    for i in range(1, len(blocks), 3):
        ex, bits, body = int(blocks[i]), int(blocks[i + 1]), blocks[i + 2]
        if ex not in wanted:
            continue
        fields = re.findall(r"# ([^\n:]+):\s*\n((?:[0-9a-f]{2}[ \n]*)+)", body)
        get = lambda name, idx=0: [v for k, v in fields if k.strip() == name][idx]
        hexs = lambda s: "".join(s.split())
        key = {"n": hexs(get("Modulus")), "e": hexs(get("Exponent")),
               "d": hexs(get("Exponent", 1)), "p": hexs(get("Prime 1")), "q": hexs(get("Prime 2"))}
        msgs = [hexs(v) for k, v in fields if k.strip() == "Message"]
        seeds = [hexs(v) for k, v in fields if k.strip() == "Seed"]
        cts = [hexs(v) for k, v in fields if k.strip() == "Encryption"]
        cases = [{"id": f"{ex}.{j + 1}", "msg": m, "seed": s, "ct": c}
                 for j, (m, s, c) in enumerate(zip(msgs, seeds, cts))]
        out.append({"example": ex, "bits": bits, "key": key, "cases": cases})
    return out


if __name__ == "__main__":
    data = parse(Path(sys.argv[1]).read_text())
    dest = Path(__file__).resolve().parents[1] / "core" / "vectors" / "rsa_oaep_pkcs1.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps({"source": SOURCE, "hash": "sha1", "mgf": "MGF1-SHA1",
                                "keys": data}, indent=2))
    print(f"{sum(len(k['cases']) for k in data)} vektor → {dest}")
