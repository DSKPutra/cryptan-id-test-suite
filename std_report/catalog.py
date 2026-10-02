"""Bagian 1 — Daftar algoritme standar (FIPS · NIST SP 800 · ISO/IEC).

Sumber: algo_catalog (seed + cache scraping) dengan field `source_body`/`source_doc`, ditambah
entri pelengkap std_report/data/supplement.yaml untuk dokumen wajib yang belum punya entri.
Satu baris = satu kombinasi algoritme × varian × panjang kunci.
"""
from pathlib import Path

import yaml

from algo_catalog import catalog as ac
from algo_catalog.schema import PRIMITIVES, Entry

DATA = Path(__file__).parent / "data"
BODIES = {"FIPS": "FIPS", "NIST-SP": "NIST SP 800", "ISO-IEC": "ISO/IEC"}
VERIFY = "PERLU_VERIFIKASI"
REQUIRED_DOCS = {
    "FIPS": ["FIPS 180-4", "FIPS 186-5", "FIPS 197", "FIPS 198-1", "FIPS 202", "FIPS 203", "FIPS 204", "FIPS 205"],
    "NIST-SP": ["SP 800-38A", "SP 800-38B", "SP 800-38C", "SP 800-38D", "SP 800-38E", "SP 800-38F", "SP 800-38G", "SP 800-56A",
                "SP 800-56B", "SP 800-56C", "SP 800-90A", "SP 800-108", "SP 800-132", "SP 800-185", "SP 800-208", "SP 800-232"],
    "ISO-IEC": ["ISO/IEC 18033-2", "ISO/IEC 18033-3", "ISO/IEC 18033-4", "ISO/IEC 29192-2", "ISO/IEC 29192-3", "ISO/IEC 29192-5",
                "ISO/IEC 10118-3", "ISO/IEC 9797-1", "ISO/IEC 9797-2", "ISO/IEC 14888-2", "ISO/IEC 14888-3", "ISO/IEC 9796-2",
                "ISO/IEC 19772", "ISO/IEC 18031", "ISO/IEC 18032"],
}


def _supplement():
    d = yaml.safe_load((DATA / "supplement.yaml").read_text(encoding="utf-8"))
    return [Entry.from_dict(dict(x)) for x in d["entries"]]


def load_entries():
    seed = ac.load(use_cache=False)
    allx = ac.load(use_cache=True)
    seed_ids = {e.id for e in seed}
    scraped = [e for e in allx if e.id not in seed_ids]
    return seed + _supplement(), scraped


def rows(entries, sources=None, primitives=None) -> list:
    out = []
    for e in entries:
        if not e.source_body:
            continue
        if sources and not set(e.source_body) & set(sources):
            continue
        if primitives and e.primitive not in primitives:
            continue
        for k in e.keys():
            r = e.combo_row(k)
            r["doc_verify"] = [d for d in e.source_doc if VERIFY in d]
            r["source_body_label"] = [BODIES[b] for b in e.source_body]
            out.append(r)
    return out


def out_of_scope(entries) -> list:
    return [{"id": e.id, "family": e.family, "variant": e.variant, "standards": e.standards,
             "reason": "tidak didefinisikan di FIPS / NIST SP 800 / ISO/IEC (mis. RFC, standar nasional lain)"}
            for e in entries if not e.source_body]


def doc_coverage(rs) -> dict:
    have = {}
    for r in rs:
        for d in r["source_doc"]:
            base = d.replace(f" ({VERIFY})", "")
            for req in sum(REQUIRED_DOCS.values(), []):
                if base == req or base.startswith(req + " ") or base.startswith(req + "."):
                    have.setdefault(req, set()).add(r["id"])
    return {req: sorted(have.get(req, [])) for req in sum(REQUIRED_DOCS.values(), [])}


def build(sources=None, primitives=None) -> dict:
    entries, scraped = load_entries()
    rs = rows(entries, sources, primitives)
    cov = doc_coverage(rows(entries))
    return {"rows": rs, "primitives": PRIMITIVES, "bodies": BODIES,
            "counts": {b: sum(1 for r in rs if b in r["source_body"]) for b in BODIES},
            "doc_coverage": cov, "missing_docs": [d for d, ids in cov.items() if not ids],
            "out_of_scope": out_of_scope(entries),
            "scraped_appendix": [{"id": e.id, "family": e.family, "variant": e.variant, "status": e.status(None) if not e.key_bits else e.status(e.key_bits[0]),
                                  "source": e.source.get("url")} for e in scraped]}
