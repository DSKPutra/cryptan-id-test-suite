"""KUK 2.1 — Skenario didesain dari hasil telaah.

Mengisi matriks 3 lapis × 3/4 tingkat dari templat kategori materi (templates.yaml) dan resep
(recipes.yaml), memakai metode hasil telaah (KUK 1.1) dan ruang parameter (KUK 1.2).
Ditambah skenario lintas-algoritma (RNG → keygen → KDF → cipher/MAC/signature → protokol → produk),
siklus hidup kunci, kondisi operasional, crypto-agility/PQC; untuk modul dipetakan ke area ISO/IEC 19790.
"""
import copy

import yaml

from .context import DATA, LAYERS, TIER_CODE, category_of

TIER_ABBR = {"Komponen": "KOM", "Integrasi": "INT", "Sistem": "SIS", "Unit": "UNI", "UAT": "UAT"}
EX_FILE = {"DS": "ecdsa_p256_token", "PR": "tls13_gateway"}


def load_recipes() -> dict:
    return yaml.safe_load((DATA / "recipes.yaml").read_text(encoding="utf-8"))


def _example_index(ctx) -> dict:
    idx = {}
    for name, ex in ctx.examples.items():
        for tc in ex.get("test_cases", []):
            idx[tc["id"]] = {**tc, "_example": name}
    return idx


def resolve(ctx) -> list:
    """Resep lengkap: gabungkan entri `from_example` dengan tabel contoh materi."""
    R = load_recipes()
    ex = _example_index(ctx)
    dflt = R["defaults"]
    out = []
    for cat, items in R["categories"].items():
        for r in items:
            r = copy.deepcopy(r)
            if "from_example" in r:
                e = ex[r["from_example"]]
                r.setdefault("id", e["id"])
                r.setdefault("layer", e["layer"])
                lvl = e.get("level", "Integrasi")
                r.setdefault("level", "Komponen" if lvl == "Model" else lvl)
                if lvl == "Model":
                    r["level_note"] = "Model formal (materi)"
                r.setdefault("pass", e["pass"])
                r["material"] = {"params": e["params"], "procedure": e["procedure"], "pass": e["pass"], "source": e["_example"]}
            r["category"] = cat
            r.setdefault("priority", dflt["priority"])
            r.setdefault("executor", dflt["executor"].get(r["level"], "Penguji lab"))
            out.append(r)
    mod = R["module"]
    for e in ctx.examples.get("hsm_x_sl3", {}).get("test_cases", []):
        meta = mod["meta"].get(e["id"], {})
        r = {"id": e["id"], "category": "module", "level": e["level"], "layer": e["layer"], "area": e["area"],
             "title": e["procedure"], "steps": list(mod["default_steps"]), "pass": e["pass"],
             "material": {"params": e["params"], "procedure": e["procedure"], "pass": e["pass"], "source": "hsm_x_sl3"},
             "priority": meta.get("priority", dflt["priority"]), "executor": dflt["executor"].get(e["level"], "Penguji lab"), **meta}
        r["steps"][1] = f"{e['procedure']} (area {e['area']})"
        out.append(r)
    for r in R["cross"]:
        r = copy.deepcopy(r)
        r["category"] = "cross"
        r.setdefault("priority", dflt["priority"])
        r.setdefault("executor", dflt["executor"].get(r["level"], "Penguji lab"))
        out.append(r)
    return out


def _match(obj: dict, applies: dict) -> bool:
    if not applies:
        return True
    for key, vals in applies.items():
        if obj.get(key) in vals or (key == "family" and any(obj.get("family", "").startswith(x) for x in vals)):
            return True
    return False


def _targets(ctx, r) -> list:
    if r["category"] == "module":
        objs = ctx.objects
        if r["id"] in ("U-K-01",):
            objs = [o for o in objs if o.get("variant") == "GCM"]
        elif r["id"] == "U-K-02":
            objs = [o for o in objs if o["primitive"] == "signature"]
        elif r["id"] == "U-K-03":
            objs = [o for o in objs if o["primitive"] == "drbg"]
        return [o["id"] for o in objs]
    if r["category"] == "cross":
        return [o["id"] for o in ctx.objects]
    if r["category"] == "protocol":
        return [ctx.uk2.get("protocol", {}).get("name", "protokol")]
    gen = r.get("expected", {}).get("gen")
    objs = [o for o in ctx.objects_in(r["category"]) if _match(o, r.get("applies"))]
    if gen == "kat_gcm256":
        objs = [o for o in ctx.objects if o["id"] == "AES-256-GCM"]
    if r["id"] == "DS-K-02":                      # SHA-256 pada skema tanda tangan
        objs = [o for o in ctx.objects if o["id"].startswith("SHA-")] or objs
    return [o["id"] for o in objs]


def design(ctx, review: dict, pspace: dict) -> dict:
    recipes = resolve(ctx)
    cats = ctx.categories()
    chosen, excluded = [], []
    for r in recipes:
        c = r["category"]
        if ctx.model == 4 and c not in ("module", "cross"):
            continue                                  # model 4 tingkat: ID U/I/S/A (algoritma = target)
        if ctx.model == 3 and c == "module":
            continue
        if c not in ("module", "cross") and c not in cats:
            continue
        miss = [f for f in r.get("requires", []) if f not in ctx.features]
        if miss:
            excluded.append({"id": r["id"], "reason": f"fitur produk tidak ada: {', '.join(miss)}", "category": c})
            continue
        tg = _targets(ctx, r)
        if not tg:
            excluded.append({"id": r["id"], "reason": "tidak ada objek uji yang sesuai (applies)", "category": c})
            continue
        r = {**r, "targets": tg}
        chosen.append(r)
    tiers = ctx.tiers
    # skenario = sel matriks lapis × tingkat per kategori (+ modul, lintas-algoritma)
    scenarios, matrix = [], {}
    groups = (["module"] if ctx.model == 4 else cats) + ["cross"]
    tmpl = ctx.templates["categories"]
    fw4 = ctx.iso.get("framework_3x4", {})
    fw4_by_tier = dict(zip(["Unit", "Integrasi", "Sistem", "UAT"], fw4.values()))
    for g in groups:
        matrix[g] = {}
        for t in tiers:
            for L in "KSI":
                rs = [r for r in chosen if r["category"] == g and r["level"] == t and r["layer"] == L]
                if g == "cross" and not rs:
                    continue
                code = tmpl[g]["code"] if g in tmpl else ("M" if g == "module" else "XA")
                sid = f"SCN-{code}-{TIER_ABBR[t]}-{L}"
                if g in tmpl:
                    cell = tmpl[g]["matrix"].get(t, {}).get(L, "")
                elif g == "module":
                    cell = fw4_by_tier.get(t, {}).get(L, "")
                else:
                    cell = "; ".join(r["title"] for r in rs)
                ms = sorted({m for r in rs for m in r.get("methods", [])})
                uk1_cell = review["cells"].get(g, {}).get(f"{t}|{L}", []) if g in review["cells"] else []
                pids = sorted({p for r in rs for p in r.get("params", [])})
                sc = {"id": sid, "group": g, "category_label": tmpl[g]["label"] if g in tmpl else ("Modul ISO/IEC 19790" if g == "module" else "Lintas-algoritma"),
                      "tier": t, "layer": L, "layer_label": LAYERS[L], "template_cell": cell,
                      "recipes": [r["id"] for r in rs], "methods": ms, "uk1_methods_in_cell": uk1_cell,
                      "filled_from_template": not uk1_cell, "params": pids,
                      "objects": sorted({x for r in rs for x in r["targets"]}),
                      "areas": sorted({r["area"] for r in rs if r.get("area")}),
                      "claims": sorted({c for r in rs for c in r.get("claims", [])}),
                      "status": "TERISI" if rs else "TIDAK BERLAKU — tidak ada resep yang memenuhi fitur produk"}
                scenarios.append(sc)
                matrix[g].setdefault(t, {})[L] = sid
    # pemetaan area ISO/IEC 19790 (modul)
    iso_map = None
    if ctx.is_module:
        iso_map = {a["area"]: {t: sorted(r["id"] for r in chosen if r.get("area") == a["area"] and r["level"] == t) for t in tiers}
                   for a in ctx.iso["areas"]}
    cross = {"chain": ctx.templates["cross_algorithm"]["chain"],
             "themes": ctx.templates["cross_algorithm"]["themes"],
             "recipes": [r["id"] for r in chosen if r["category"] == "cross"],
             "pqc_relevant": any(o.get("quantum_vulnerable") for o in ctx.objects)}
    return {"recipes": chosen, "excluded": excluded, "scenarios": scenarios, "matrix": matrix,
            "iso_mapping": iso_map, "cross": cross,
            "summary": {"scenarios": len(scenarios), "filled": sum(s["status"] == "TERISI" for s in scenarios),
                        "recipes": len(chosen), "excluded": len(excluded)}}
