"""Bagian 2 — Menjalankan semua uji → outputs/std_report/results.json (satu berkas, ber-JSON Schema)."""
import datetime as dt
import json
import os
import platform
import time
from pathlib import Path

from core import APP_NAME, __version__
from core.adapters import backends_for, kind_of, versions

from . import catalog
from .tests import DICATAT, GAGAL, INKON, LULUS, STATUSES, TB, TDD, Ctx, registry

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "outputs" / "std_report"
SCHEMA = Path(__file__).parent / "schema" / "results.schema.json"
SEED = 20261002


def overall(tests: list) -> str:
    emp = [t for t in tests if t["plugin"] != "S-04" and t["status"] not in (TB, DICATAT)]
    if any(t["status"] in (GAGAL, INKON) for t in tests):
        return "TEMUAN"
    if not emp or all(t["status"] == TDD for t in emp):
        return "TIDAK_DAPAT_DIUJI"
    if any(t["status"] == TDD for t in emp):
        return "LULUS_SEBAGIAN"
    return "LULUS_SEMUA"


def perlu_verifikasi(cat: dict, algos: list) -> list:
    out = []
    for r in cat["rows"]:
        for d in r.get("doc_verify", []):
            out.append({"item": r["id"], "jenis": "keanggotaan dokumen", "detail": d})
        for f in ("security_strength_bits", "status_nist"):
            if str(r.get(f)) == "PERLU_VERIFIKASI":
                out.append({"item": r["id"], "jenis": f, "detail": "nilai belum dipastikan (algo_catalog seed)"})
        if "PERLU_VERIFIKASI" in (r.get("notes") or ""):
            out.append({"item": r["id"], "jenis": "catatan", "detail": r["notes"]})
    for e in cat["scraped_appendix"]:
        out.append({"item": e["id"], "jenis": "entri hasil scraping ACVP", "detail": f"{e['variant']} — status & keanggotaan dokumen belum dikurasi"})
    seen, uniq = set(), []
    for x in out:
        k = (x["item"], x["jenis"], x["detail"])
        if k not in seen:
            seen.add(k)
            uniq.append(x)
    return uniq


def run(mode="ringan", only=None, sources=None, primitives=None, seed=SEED, progress=None, out_dir=OUT) -> dict:
    t_start = time.time()
    cat = catalog.build(sources, primitives)
    rows = cat["rows"]
    if only:
        keys = [o.strip().upper() for o in only]
        rows = [r for r in rows if any(k in r["id"].upper() or k == r["family"].upper() for k in keys)]
    plugins = registry()
    algos, evidence = [], {}
    for idx, r in enumerate(rows):
        kind = kind_of(r)
        bs = backends_for(r)
        ctx = Ctx(r, kind, bs, mode, seed)
        tests = [p.execute(ctx) for p in plugins]
        evidence.update(ctx.evidence)
        algos.append({**{k: r[k] for k in ("id", "entry_id", "primitive", "primitive_label", "family", "variant", "key_bits",
                                           "block_or_output_bits", "security_strength_bits", "security_category", "status_nist",
                                           "standards", "quantum_vulnerable", "source_body", "source_doc")},
                      "kind": kind, "backends": [b.backend for b in bs], "tests": tests, "overall": overall(tests)})
        if progress:
            progress(idx + 1, len(rows), r["id"])
    statuses = {s: 0 for s in STATUSES}
    for a in algos:
        for t in a["tests"]:
            statuses[t["status"]] += 1
    kpi = {"terdaftar": len(algos),
           "diuji": sum(a["overall"] != "TIDAK_DAPAT_DIUJI" for a in algos),
           "lulus_semua": sum(a["overall"] == "LULUS_SEMUA" for a in algos),
           "lulus_sebagian": sum(a["overall"] == "LULUS_SEBAGIAN" for a in algos),
           "punya_temuan": sum(a["overall"] == "TEMUAN" for a in algos),
           "tidak_dapat_diuji": sum(a["overall"] == "TIDAK_DAPAT_DIUJI" for a in algos)}
    by_prim = {}
    for a in algos:
        d = by_prim.setdefault(a["primitive"], {s: 0 for s in STATUSES})
        for t in a["tests"]:
            d[t["status"]] += 1
    import numpy
    import reportlab
    vec_sources = json.loads((Path(__file__).parent / "vectors" / "SOURCES.json").read_text())
    res = {
        "schema": "cryptan.std_report.results.v1",
        "tool": {"name": APP_NAME, "module": "std_report", "version": __version__},
        "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "mode": mode, "seed": seed,
        "filters": {"sources": sources, "primitives": primitives, "only": only},
        "environment": {"os": f"{platform.system()} {platform.release()} ({platform.machine()})", "cpu": platform.processor() or platform.machine(),
                        "cpu_count": os.cpu_count(), "python": platform.python_version(),
                        "libraries": {**versions(), "numpy": numpy.__version__, "reportlab": reportlab.Version},
                        "duration_s": round(time.time() - t_start, 2)},
        "tests_catalog": [{"id": p.id, "name": p.name, "layer": p.layer, "criteria": p.criteria} for p in plugins],
        "sample_sizes": {"ringan": {"avalanche": 200, "sp800_22": "10 × 100.000 bit", "timing": 300, "mct_iter": 20, "round_trip": 4, "uji_silang": 8},
                         "full": {"avalanche": 10000, "sp800_22": "100 × 1.000.000 bit", "timing": 5000, "mct_iter": 1000, "round_trip": 32, "uji_silang": 64}}[mode],
        "catalog": {"counts_by_body": cat["counts"], "doc_coverage": cat["doc_coverage"], "missing_docs": cat["missing_docs"],
                    "out_of_scope": cat["out_of_scope"], "scraped_appendix": cat["scraped_appendix"], "bodies": cat["bodies"],
                    "primitives": cat["primitives"]},
        "algorithms": algos,
        "summary": {"kpi": kpi, "status_counts": statuses, "by_primitive": by_prim},
        "evidence": evidence,
        "vectors": vec_sources,
        "perlu_verifikasi": perlu_verifikasi(cat, algos),
    }
    res["schema_errors"] = validate(res)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(json.dumps(res, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    return res


def validate(res: dict) -> list:
    try:
        import jsonschema
    except ImportError:
        return ["jsonschema tidak terpasang"]
    schema = json.loads(SCHEMA.read_text())
    v = jsonschema.Draft202012Validator(schema)
    return [f"{'/'.join(map(str, e.path))}: {e.message}" for e in list(v.iter_errors(json.loads(json.dumps(res, default=str))))[:20]]
