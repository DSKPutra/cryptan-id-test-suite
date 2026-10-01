"""KUK 2.2 — Skenario diverifikasi terhadap spesifikasi desain (ASPEK KRITIS).

Pemeriksaan otomatis skenario (hasil designer) terhadap product_profile.yaml & algorithms_under_test:
  (a) setiap algoritma, varian, panjang kunci, mode & parameter set di profil tercakup
  (b) nilai di luar spesifikasi hanya muncul sebagai negative test dengan harapan DITOLAK
  (c) setiap klaim keamanan produk punya ≥ 1 skenario Uji Keamanan
  (d) setiap metode UK-1 (relevan) punya ≥ 1 skenario
  (e) modul: ke-11 area 7.2–7.12 tercakup atau dijustifikasi "—" sesuai SL target
  (f) tidak ada skenario yang merujuk fitur/objek yang tidak dimiliki produk
"""
LULUS, TEMUAN = "LULUS", "TEMUAN"
RULES = {
    "a": "Cakupan algoritma, varian, panjang kunci, mode & parameter set profil",
    "b": "Nilai di luar spesifikasi hanya sebagai negative test (harapan ditolak)",
    "c": "Setiap klaim keamanan punya ≥ 1 skenario Uji Keamanan",
    "d": "Setiap metode UK-1 punya ≥ 1 skenario",
    "e": "Modul: 11 area ISO/IEC 19790 (7.2–7.12) tercakup / dijustifikasi",
    "f": "Tidak ada skenario untuk fitur/objek yang tidak dimiliki produk",
}
# Justifikasi "—" yang sah per area bila SL target rendah (ISO/IEC 19790 §7; mis. keamanan fisik SL 1 minimal)
JUSTIFIABLE = {"7.6": "Lingkungan operasi tidak dapat dimodifikasi (non-modifiable) — persyaratan minimal",
               "7.7": "SL 1: persyaratan keamanan fisik minimal (komponen tingkat produksi)",
               "7.8": "SL 1–2: mitigasi non-invasif opsional bila tidak diklaim",
               "7.12": "Tidak ada klaim mitigasi serangan lain dalam security policy"}


def _key_spec(ctx) -> dict:
    """Panjang kunci yang didukung per famili+varian (dari algorithms_under_test)."""
    spec = {}
    for o in ctx.objects:
        spec.setdefault((o["family"], o["variant"]), set()).add(o.get("key_bits"))
    return spec


def verify(ctx, design: dict, review: dict) -> dict:
    recs = design["recipes"]
    findings = {k: [] for k in RULES}
    checks = {k: 0 for k in RULES}
    obj_ids = {o["id"] for o in ctx.objects}

    # (a) cakupan objek uji — ≥ 1 skenario Uji Kesesuaian per kombinasi + ≥ 1 skenario apa pun
    for o in ctx.objects:
        checks["a"] += 1
        k = [r["id"] for r in recs if o["id"] in r["targets"] and r["layer"] == "K"]
        if not k:
            findings["a"].append({"object": o["id"], "detail": f"{o['id']} ({o['family']} {o['variant']}, kunci {o.get('key_bits') or '—'}) tanpa skenario Uji Kesesuaian"})
    # (b) nilai di luar spesifikasi
    spec = _key_spec(ctx)
    for r in recs:
        neg = r.get("expected", {}).get("kind") == "negative"
        for pv in r.get("param_values", []):
            checks["b"] += 1
            if not pv["in_spec"] and not neg:
                findings["b"].append({"scenario": r["id"], "detail": f"{r['id']}: nilai di luar spesifikasi '{pv['value']}' ({pv['name']}) dipakai pada uji POSITIF"})
            if not pv["in_spec"] and neg and pv.get("expect") != "DITOLAK":
                findings["b"].append({"scenario": r["id"], "detail": f"{r['id']}: nilai '{pv['value']}' negatif tanpa harapan DITOLAK"})
        for kb in r.get("key_bits_used", []):                  # deklarasi eksplisit (mis. skenario disisipkan)
            checks["b"] += 1
            for t in r["targets"]:
                o = next((x for x in ctx.objects if x["id"] == t), None)
                if o and kb not in spec.get((o["family"], o["variant"]), set()) and not neg:
                    findings["b"].append({"scenario": r["id"], "detail": f"{r['id']}: panjang kunci {kb} bit tidak didukung {o['family']}-{o['variant']} "
                                                                        f"(spesifikasi {sorted(x for x in spec[(o['family'], o['variant'])] if x)}) dipakai sebagai uji positif"})
    # (c) klaim keamanan
    for c in ctx.claims:
        checks["c"] += 1
        for tag in c.get("tags", []):
            s = [r["id"] for r in recs if r["layer"] == "S" and tag in r.get("claims", [])]
            if not s:
                findings["c"].append({"claim": c["id"], "detail": f"Klaim {c['id']} '{c['claim']}' (tag {tag}) tanpa skenario Uji Keamanan"})
    # (d) metode UK-1
    for m in review["methods"]:
        if not m["relevant"]:
            continue
        checks["d"] += 1
        if not any(m["method_id"] in r.get("methods", []) for r in recs):
            findings["d"].append({"method": m["method_id"], "detail": f"Metode UK-1 {m['method_id']} ({m['name']}) tidak dipakai skenario mana pun"})
    # (e) area ISO/IEC 19790
    coverage = None
    if ctx.is_module:
        coverage = {}
        sl = ctx.security_level or 0
        justified = {a: j for a, j in JUSTIFIABLE.items() if (a == "7.7" and sl <= 1) or (a == "7.8" and sl <= 2)}
        for a in ctx.iso["areas"]:
            checks["e"] += 1
            ids = sorted(r["id"] for r in recs if r.get("area") == a["area"])
            coverage[a["area"]] = {t: sorted(r["id"] for r in recs if r.get("area") == a["area"] and r["level"] == t) for t in ctx.tiers}
            if not ids and a["area"] not in justified:
                findings["e"].append({"area": a["area"], "detail": f"Area {a['area']} {a['name']} kosong pada semua tingkat tanpa justifikasi (SL {sl})"})
    # (f) fitur/objek yang tidak dimiliki
    for r in recs:
        checks["f"] += 1
        miss = [f for f in r.get("requires", []) if f not in ctx.features]
        if miss:
            findings["f"].append({"scenario": r["id"], "detail": f"{r['id']} memerlukan fitur yang tidak dimiliki produk: {', '.join(miss)}"})
        bad = [t for t in r["targets"] if r["category"] not in ("protocol",) and t not in obj_ids]
        if bad:
            findings["f"].append({"scenario": r["id"], "detail": f"{r['id']} merujuk objek yang tidak ada di profil: {', '.join(bad)}"})
    rules = [{"rule": k, "desc": RULES[k], "checked": checks[k],
              "status": ("TIDAK BERLAKU" if k == "e" and not ctx.is_module else (TEMUAN if findings[k] else LULUS)),
              "findings": findings[k]} for k in RULES]
    total = sum(len(v) for v in findings.values())
    return {"rules": rules, "total_findings": total, "status": LULUS if total == 0 else TEMUAN,
            "iso_coverage": coverage, "verified_recipes": [r["id"] for r in recs]}


def to_markdown(ver: dict, title: str) -> str:
    L = [f"# Laporan Verifikasi Skenario — {title}", "", f"Status keseluruhan: **{ver['status']}** · {ver['total_findings']} temuan", "",
         "| Aturan | Deskripsi | Diperiksa | Status |", "|---|---|---|---|"]
    L += [f"| ({r['rule']}) | {r['desc']} | {r['checked']} | **{r['status']}** |" for r in ver["rules"]]
    for r in ver["rules"]:
        if r["findings"]:
            L += ["", f"## Temuan aturan ({r['rule']})", ""] + [f"- {f['detail']}" for f in r["findings"]]
    return "\n".join(L) + "\n"
