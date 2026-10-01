"""Orkestrasi UK-2: EK 1 (telaah metode & parameter) → EK 2 (desain, verifikasi, test case, expected, kompilasi)."""
import datetime as dt
import shutil
from collections import Counter
from pathlib import Path

from core import APP_NAME, __version__

from . import compiler, context, designer, expected, method_review, param_space, testcase, verifier

UNIT = {"code": "J.61KRP00.013.1", "title": "Menyusun Skenario Pengujian", "module": "UK-2", "skkni": "SKKNI 2023-004 (Cryptographic Analyst)",
        "bukti": "Skenario pengujian produk kriptografi",
        "aspek_kritis": "Ketepatan memverifikasi skenario pengujian sesuai spesifikasi desain produk"}


def run(profile: str, uk1: str = None, out: Path = Path("outputs/uk2"), docx: bool = True) -> dict:
    ctx = context.load(profile, uk1)
    review = method_review.review(ctx)                    # KUK 1.1
    pspace = param_space.build(ctx)                       # KUK 1.2
    design = designer.design(ctx, review, pspace)         # KUK 2.1
    ver = verifier.verify(ctx, design, review)            # KUK 2.2
    exp_dir = out / "expected"
    shutil.rmtree(exp_dir, ignore_errors=True)
    expected.build.pspace = pspace
    exp = expected.build(ctx, design["recipes"], exp_dir)  # KUK 2.4
    tcs = testcase.build(ctx, design, ver, exp, pspace)   # KUK 2.3
    R = {
        "schema": "cryptan.uk2.skenario.v1", "app": {"name": APP_NAME, "version": __version__}, "unit": UNIT,
        "generated_at": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "inputs": {"profile": context.rel(ctx.profile_path), "uk1": ctx.uk1_source, "notes": ctx.notes},
        "profile": {"product": ctx.profile["product"], "product_type": ctx.uk2.get("product_type"), "testing_model": ctx.model,
                    "tiers": ctx.tiers, "security_level": ctx.security_level, "features": sorted(ctx.features), "claims": ctx.claims,
                    "categories": ctx.categories(), "is_module": ctx.is_module,
                    "objects": [{**o, "category": context.category_of(o)} for o in ctx.objects]},
        "method_review": review, "param_space": pspace,
        "design": {k: design[k] for k in ("matrix", "excluded", "iso_mapping", "cross", "summary")},
        "scenarios": design["scenarios"], "verification": ver,
        "expected": {"dir": "expected/", "manifest": exp["manifest"], "summary": dict(Counter(m["status"] for m in exp["manifest"]))},
        "test_cases": tcs,
        "decision_criteria": ctx.templates["decision_criteria"], "outcome_categories": ctx.templates["outcome_categories"],
        "governance": ctx.iso.get("governance") if ctx.model == 4 else None,
    }
    for k in ("COCOK_VEKTOR_RESMI", "KRITERIA", "PERLU_VERIFIKASI"):
        R["expected"]["summary"].setdefault(k, 0)
    R["traceability"] = compiler.traceability(ctx, design["scenarios"], tcs)   # KUK 2.5
    R["outcome_map"] = compiler.outcome_map(ctx, tcs)
    R["handoff_uk3"] = {"note": "Masukan runner UK-3 (Melakukan Pengujian): eksekusi test_cases[].runner dengan expected/*.json",
                        "schema": "uk2_skenario/schema/uk2_skenario.schema.json",
                        "actions": sorted({t["runner"]["action"] for t in tcs}), "test_cases": len(tcs)}
    files = compiler.write_all(R, out, docx=docx)
    return {"result": R, "files": files}
