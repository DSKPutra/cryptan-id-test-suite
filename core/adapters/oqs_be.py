"""Backend liboqs-python (opsional; PQC). Tidak dimuat bila liboqs tidak terpasang."""
from .base import Adapter, NotSupported, kind_of

NAME = "oqs"
SIG = {f"SLH-DSA-{h}-{s}{v}": f"SPHINCS+-{h}-{s}{v}-simple" for h in ("SHA2", "SHAKE") for s in ("128", "192", "256") for v in "sf"}
KEM = {"ML-KEM-512": "ML-KEM-512", "ML-KEM-768": "ML-KEM-768", "ML-KEM-1024": "ML-KEM-1024"}


def _oqs():
    import importlib.util
    if importlib.util.find_spec("oqs") is None:
        raise NotSupported("liboqs-python tidak terpasang")
    import oqs                     # noqa: F401  (dapat mencoba membangun liboqs — hanya bila terpasang)
    return oqs


def version():
    return _oqs().oqs_python_version()


class A(Adapter):
    backend = NAME


def get(row):
    k = kind_of(row)
    oqs = _oqs()
    a = A(row, k)
    rid = row["id"].upper()
    if k == "kem" and rid in KEM and KEM[rid] in oqs.get_enabled_kem_mechanisms():
        alg = KEM[rid]

        def kg():
            kem = oqs.KeyEncapsulation(alg)
            pk = kem.generate_keypair()
            return kem, pk
        a.keygen = kg
        a.encaps = lambda pk: oqs.KeyEncapsulation(alg).encap_secret(pk)
        a.decaps = lambda sk, ct: sk.decap_secret(ct)
        return a
    if k == "sig" and rid in SIG and SIG[rid] in oqs.get_enabled_sig_mechanisms():
        alg = SIG[rid]

        def kg():
            s = oqs.Signature(alg)
            pk = s.generate_keypair()
            return s, pk
        a.keygen = kg
        a.sign = lambda sk, m: sk.sign(m)
        a.verify = lambda pk, m, s: oqs.Signature(alg).verify(m, s, pk)
        return a
    raise NotSupported(k)
