"""Isi field `source_body` & `source_doc` pada algo_catalog/data/catalog_seed.yaml (std_report Bagian 1).

Aturan:
  1. Diturunkan dari field `standards` yang sudah ada: FIPS xxx → FIPS; SP 800-xx → NIST-SP;
     ISO/IEC xxxxx → ISO-IEC. SP 800-131A & SP 800-57 adalah sumber STATUS/KEKUATAN, bukan
     dokumen spesifikasi algoritme, sehingga tidak dimasukkan ke source_doc.
  2. Ditambah keanggotaan terkurasi (EXTRA) untuk dokumen wajib yang belum tercantum.
  3. Keanggotaan yang belum dipastikan diberi akhiran " (PERLU_VERIFIKASI)" — tidak dikarang.
Penyisipan berbasis teks (komentar & format seed dipertahankan). Idempoten.
"""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "algo_catalog" / "data" / "catalog_seed.yaml"
STATUS_ONLY = {"SP 800-131A", "SP 800-131A Rev.2", "SP 800-57"}
V = " (PERLU_VERIFIKASI)"

EXTRA = {  # id entri → dokumen tambahan
    "AES-CCM": ["ISO/IEC 19772"],
    "AES-KW": ["ISO/IEC 19772"], "AES-KWP": ["ISO/IEC 19772" + V],
    "AES-CMAC": ["ISO/IEC 9797-1"],
    "HMAC-SHA-1": ["ISO/IEC 9797-2"], "HMAC-SHA-224": ["ISO/IEC 9797-2"], "HMAC-SHA-256": ["ISO/IEC 9797-2"],
    "HMAC-SHA-384": ["ISO/IEC 9797-2"], "HMAC-SHA-512": ["ISO/IEC 9797-2"],
    "HMAC-SHA-512/224": ["ISO/IEC 9797-2" + V], "HMAC-SHA-512/256": ["ISO/IEC 9797-2" + V],
    "HMAC-SHA3-224": ["ISO/IEC 9797-2" + V], "HMAC-SHA3-256": ["ISO/IEC 9797-2" + V],
    "HMAC-SHA3-384": ["ISO/IEC 9797-2" + V], "HMAC-SHA3-512": ["ISO/IEC 9797-2" + V],
    "SHAKE128": ["ISO/IEC 10118-3"], "SHAKE256": ["ISO/IEC 10118-3"],
    "SHA-512/224": ["ISO/IEC 10118-3" + V], "SHA-512/256": ["ISO/IEC 10118-3" + V],
    "TDEA-3KEY": ["SP 800-38A"],
    "DSA": ["ISO/IEC 14888-3"],
    "RSASSA-PKCS1-V1_5": ["ISO/IEC 14888-2" + V],
    "X25519": ["SP 800-56A" + V], "X448": ["SP 800-56A" + V],
    "KMAC": ["SP 800-185"], "CSHAKE": ["SP 800-185"],
}
FIX = {  # dokumen di `standards` yang keanggotaannya belum pasti
    "ECDSA-BRAINPOOL": {"ISO/IEC 14888-3": "ISO/IEC 14888-3" + V},
}


def norm(doc: str):
    d = doc.strip()
    if d in STATUS_ONLY:
        return None
    m = re.match(r"FIPS (\d+-?\d*)", d)
    if m:
        return "FIPS", f"FIPS {m.group(1)}"
    m = re.match(r"SP (800-\d+[A-G]?)", d)
    if m:
        return "NIST-SP", "SP " + d.split("SP ", 1)[1].split(" (")[0]
    m = re.match(r"ISO/IEC (\d+(?:-\d+)?)", d)
    if m:
        return "ISO-IEC", "ISO/IEC " + m.group(1)
    return None


def derive(e: dict):
    bodies, docs = [], []
    for d in e.get("standards", []) + EXTRA.get(e["id"], []):
        verify = d.endswith(V)
        n = norm(d.replace(V, ""))
        if not n:
            continue
        body, doc = n
        doc = FIX.get(e["id"], {}).get(doc, doc + (V if verify else ""))
        if doc.replace(V, "") not in [x.replace(V, "") for x in docs]:
            docs.append(doc)
        if body not in bodies:
            bodies.append(body)
    return bodies, docs


def main():
    text = SEED.read_text(encoding="utf-8")
    entries = yaml.safe_load(text)["entries"]
    n = 0
    for e in entries:
        bodies, docs = derive(e)
        frag = f"source_body: [{', '.join(bodies)}], source_doc: [{', '.join(repr(x) if ' ' in x or ',' in x else x for x in docs)}],"
        frag = frag.replace("'", '"')
        pat = re.compile(r"(- \{id: " + re.escape(e["id"]) + r", )(source_body: \[[^\]]*\], source_doc: \[[^\]]*\], )?")
        text, k = pat.subn(lambda m: m.group(1) + frag + " ", text, count=1)
        n += k
    SEED.write_text(text, encoding="utf-8")
    print(f"{n}/{len(entries)} entri diisi source_body/source_doc")


if __name__ == "__main__":
    main()
