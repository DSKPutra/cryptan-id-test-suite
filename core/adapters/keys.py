"""Cache kunci uji (ILUSTRATIF, bukan kunci produksi) RSA & DSA — pembangkitannya lambat (RSA 7680/15360
dapat memakan menit). Disimpan sebagai PEM PKCS#8 di std_report/vectors/testkeys/ dan dipakai ulang
oleh semua backend (kunci = data uji; pembangkitan kunci sendiri diuji terpisah)."""
from pathlib import Path

CACHE = Path(__file__).resolve().parents[2] / "std_report" / "vectors" / "testkeys"
SLOW = {("RSA", 7680), ("RSA", 15360), ("DSA", 3072)}


def pem(family: str, bits: int, generate) -> bytes:
    """PEM kunci privat uji; dibangkitkan sekali (lewat `generate()`) lalu dipakai ulang."""
    CACHE.mkdir(parents=True, exist_ok=True)
    p = CACHE / f"TESTKEY-{family}-{bits}.pem"
    if p.exists():
        return p.read_bytes()
    data = generate()
    if family in ("RSA", "DSA"):
        p.write_bytes(data)
    return data
