"""KUK 3.2 — Kesimpulan ditentukan berdasarkan olah data: keputusan per TC → per sasaran uji (empat kategori),
pencatat temuan (F-xx + CVSS 3.1), demonstrasi dampak F-01, dan rumusan yang lolos pemeriksa."""
import json

from .. import CATEGORIES, GAGAL, INKONKLUSIF, LULUS, MEMENUHI, MEMENUHI_CATATAN, TDD, TERBLOKIR, TIDAK_MEMENUHI
from .. import products as P
from ..evidence import append
from ..prep.documents import load_scenario
from ..run.runner import load_run, run_dir
from . import cvss, wording

SEVERITY_RANK = {c: i for i, c in enumerate([MEMENUHI, MEMENUHI_CATATAN, INKONKLUSIF, TIDAK_MEMENUHI])}


def objective(rows: list) -> dict:
    """Aturan agregasi (materi slide 41): TC wajib GAGAL → Tidak Memenuhi; TERBLOKIR/TIDAK DAPAT DIUJI/bukti statistik
    kurang → tidak boleh Memenuhi (Inkonklusif); semua LULUS tetapi ada batasan → Memenuhi dengan Catatan."""
    fail_m = [r["id"] for r in rows if r["status"] == GAGAL and r.get("wajib", True)]
    fail_o = [r["id"] for r in rows if r["status"] == GAGAL and not r.get("wajib", True)]
    blocked = [r["id"] for r in rows if r["status"] in (TERBLOKIR, TDD)]
    inconcl = [r["id"] for r in rows if r.get("inconclusive")]
    notes = [f"{r['id']}: {r['batasan']}" for r in rows if r.get("batasan") and r["status"] == LULUS]
    if fail_m:
        cat, why = TIDAK_MEMENUHI, f"TC wajib GAGAL: {', '.join(fail_m)}"
    elif blocked or inconcl:
        cat, why = INKONKLUSIF, "; ".join(x for x in [f"TERBLOKIR/TIDAK DAPAT DIUJI: {', '.join(blocked)}" if blocked else "",
                                                       f"bukti tidak konsisten: {', '.join(inconcl)}" if inconcl else ""] if x)
    elif fail_o or notes:
        cat, why = MEMENUHI_CATATAN, "; ".join(([f"TC tidak wajib GAGAL: {', '.join(fail_o)}"] if fail_o else []) + notes)
    else:
        cat, why = MEMENUHI, "semua TC LULUS tanpa batasan"
    return {"kategori": cat, "alasan": why, "tc": [r["id"] for r in rows],
            "lulus": sum(r["status"] == LULUS for r in rows), "total": len(rows)}


def demo_nonce_reuse(module) -> dict:
    """Bagian 4: dua berkas dengan password sama pada v1.1 → C1 ⊕ C2 = P1 ⊕ P2, sehingga P1 = C1 ⊕ C2 ⊕ P2."""
    p1, p2 = b"GAJI DIREKTUR: 90 JUTA", b"RAPAT PUKUL 09.00 WIB!"
    pw = b"password-sama"
    b1, b2 = module.encrypt(pw, p1), module.encrypt(pw, p2)
    c1, c2 = b1[32:32 + len(p1)], b2[32:32 + len(p2)]
    same_nonce = b1[20:32] == b2[20:32]
    x = bytes(a ^ b for a, b in zip(c1, c2))
    rec = bytes(a ^ b for a, b in zip(x, p2))
    return {"nonce_sama": same_nonce, "c1_xor_c2_sama_dengan_p1_xor_p2": x == bytes(a ^ b for a, b in zip(p1, p2)),
            "p2_diketahui": p2.decode(), "p1_dipulihkan": rec.decode(errors="replace"), "berhasil": rec == p1,
            "nonce_hex": b1[20:32].hex(), "c1_hex": c1.hex(), "c2_hex": c2.hex()}


def conclude(product_id, run_id, out_root=None, pernyataan=None) -> dict:
    rec = load_run(product_id, run_id, out_root)
    sc = load_scenario(product_id)
    sas = sc.get("sasaran", {}) if isinstance(sc.get("sasaran"), dict) else {}
    tcmap = {t["id"]: t for t in sc.get("test_cases", []) if isinstance(t, dict)}
    d = run_dir(product_id, run_id, out_root)
    per_version, findings, statements = {}, [], []
    fno = 0
    for ver, vr in rec["versi"].items():
        groups = {}
        for r in vr["tc"]:
            groups.setdefault(r.get("sasaran") or "—", []).append(r)
        objs = {k: {**objective(v), "nama": sas.get(k, k)} for k, v in groups.items()}
        worst = max((o["kategori"] for o in objs.values()), key=lambda c: SEVERITY_RANK[c])
        counts = {s: sum(r["status"] == s for r in vr["tc"]) for s in (LULUS, GAGAL, TERBLOKIR, TDD)}
        total = len(vr["tc"])
        metode = sorted({r["metode"] for r in vr["tc"] if r.get("metode")})
        stmt = (f"Pada {P.REGISTRY[product_id]['nama']} versi {ver}, dengan metode {', '.join(metode) or '—'}, "
                f"{counts[LULUS]} dari {total} TC lulus ({counts[GAGAL]} GAGAL, {counts[TERBLOKIR]} TERBLOKIR, {counts[TDD]} tidak dapat diuji).")
        statements.append(stmt)
        if any(r.get("metode") == "NIST SP 800-22" and r["status"] == LULUS for r in vr["tc"]):
            statements.append(f"Versi {ver}: tidak ditemukan bukti ketidakacakan pada uji SP 800-22 yang dijalankan.")
        for r in vr["tc"]:
            if r["status"] != GAGAL:
                continue
            fno += 1
            tpl = (tcmap.get(r["id"]) or {}).get("temuan") or {}
            fid = tpl.get("id") or f"F-{fno:02d}"
            sc_ = cvss.score(tpl["cvss"]) if tpl.get("cvss") else None
            ev_sha = None
            if r.get("bukti"):
                import hashlib
                ev_sha = hashlib.sha256((d / r["bukti"]).read_bytes()).hexdigest()
            f = {"id": fid, "judul": tpl.get("judul") or f"Ketidaksesuaian pada {r['id']}", "versi": ver, "test_case": f"{r['id']} GAGAL",
                 "bukti": f"{r['actual']} (berkas {r.get('bukti')}, SHA-256 {ev_sha[:16] if ev_sha else '—'}…)",
                 "dampak": tpl.get("dampak") or "Perlu dinilai penguji", "acuan": tpl.get("acuan") or (r.get("expected") or {}).get("sumber"),
                 "keparahan": f"CVSS 3.1 · {sc_['base_score']} ({sc_['severity']})" if sc_ else "belum dinilai (isi vektor CVSS)",
                 "cvss": sc_, "rekomendasi": tpl.get("rekomendasi")}
            if fid == "F-01" and product_id == "securefile":
                try:
                    demo = demo_nonce_reuse(P.load(product_id, ver))
                    f["demonstrasi_dampak"] = demo
                    out = d / "evidence" / f"v{ver}" / "demo_F-01.json"
                    out.write_text(json.dumps(demo, indent=1, ensure_ascii=False), encoding="utf-8")
                    append(d, [out])
                except Exception as e:  # noqa: BLE001
                    f["demonstrasi_dampak"] = {"galat": str(e)}
            findings.append(f)
        per_version[ver] = {"sasaran": objs, "keseluruhan": worst, "rekap": counts, "total": total,
                            "tingkat_lulus": counts[LULUS] / total if total else 0}
    checks = [wording.check(s) for s in statements + ([pernyataan] if pernyataan else [])]
    res = {"schema": "cryptan.uk3.kesimpulan.v1", "run_id": run_id, "produk": product_id, "kategori": CATEGORIES,
           "per_versi": per_version, "temuan": findings, "pernyataan": statements, "pemeriksaan_rumusan": checks,
           "pernyataan_penguji": pernyataan, "aturan_agregasi": "TC wajib GAGAL → Tidak Memenuhi; TERBLOKIR/TIDAK DAPAT DIUJI/bukti "
           "statistik kurang → tidak boleh Memenuhi; semua LULUS dengan batasan → Memenuhi dengan Catatan"}
    out = d / "kesimpulan.json"
    out.write_text(json.dumps(res, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    append(d, [out])
    return res
