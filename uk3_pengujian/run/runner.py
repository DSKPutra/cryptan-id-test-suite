"""KUK 2.2 — Pengujian diterapkan berdasarkan test case.

Status: LULUS / GAGAL / TERBLOKIR / TIDAK DAPAT DIUJI. Setiap eksekusi menulis satu baris log: ID TC & skenario,
waktu mulai–selesai, versi produk & hash, data uji/seed, hasil aktual vs expected, status, berkas bukti.
Baris pertama setiap log = catatan lingkungan. Setiap run diberi run_id dan disimpan (tidak ada pengulangan diam-diam)."""
import csv
import datetime as dt
import hashlib
import json
import secrets
from pathlib import Path

from .. import GAGAL, LULUS, OUT, TDD, TERBLOKIR, rel
from .. import products as P
from ..evidence import write_manifest
from ..prep import documents
from ..prep.inventory import environment_note
from . import planner
from .testtypes import Ctx, load_all


class NotReady(RuntimeError):
    """Checklist kesiapan belum terpenuhi → halaman/perintah Jalankan terkunci."""


class RerunWithoutReason(RuntimeError):
    """Run ulang tanpa alasan tercatat tidak diperbolehkan."""


def uk3_dir(product_id, out_root=None) -> Path:
    return (Path(out_root) if out_root else OUT) / product_id / "uk3"


def runs_index(product_id, out_root=None) -> list:
    f = uk3_dir(product_id, out_root) / "runs_index.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else []


def run_dir(product_id, run_id, out_root=None) -> Path:
    return uk3_dir(product_id, out_root) / "runs" / run_id


def load_run(product_id, run_id, out_root=None) -> dict:
    return json.loads((run_dir(product_id, run_id, out_root) / "run.json").read_text(encoding="utf-8"))


def _now():
    return dt.datetime.now().astimezone()


def _ts(d):
    return d.strftime("%Y-%m-%d %H:%M:%S")


def _short(x, n=160):
    x = str(x)
    return x if len(x) <= n else x[:n - 1] + "…"


def run(product_id, versions=None, select="all", alasan=None, params=None, out_root=None, scenario=None, seed=2026,
        progress=None) -> dict:
    """Jalankan TC terpilih pada versi produk. scenario: override skenario (mis. untuk uji alur). params: deviasi n/m."""
    if not P.in_scope(product_id):
        raise PermissionError(f"Produk '{product_id}' tidak tercantum di ruang lingkup/izin (products/ruang_lingkup.yaml)")
    prep = documents.latest(product_id, out_root)
    if not prep:
        raise NotReady("Tahap 1 (Siapkan) belum dijalankan untuk produk ini")
    if not prep["checklist"]["siap"]:
        kurang = [i["uraian"] for i in prep["checklist"]["items"] if i["status"] == "Tidak"]
        raise NotReady("Checklist kesiapan belum terpenuhi: " + "; ".join(kurang))
    prior = runs_index(product_id, out_root)
    if prior and not alasan:
        raise RerunWithoutReason(f"Sudah ada {len(prior)} run untuk produk ini; isi alasan run ulang (dicatat di laporan)")
    sc = scenario or documents.load_scenario(product_id)
    deviasi = []
    for tid, ov in (params or {}).items():
        locked = prep["parameter_terkunci"].get(tid) or {}
        for k, v in ov.items():
            if locked.get(k) != v:
                deviasi.append({"tc": tid, "parameter": k, "terkunci": locked.get(k), "dipakai": v,
                                "alasan": alasan or "tidak diisi"})
    if deviasi and not alasan:
        raise RerunWithoutReason("Parameter n/m diubah setelah dikunci: alasan deviasi wajib diisi")

    load_all()
    from .testtypes import EXECUTORS
    pl = planner.plan(product_id, select)
    if scenario:
        tmap = {t["id"]: t for t in scenario.get("test_cases", [])}
        for t in pl["tc"]:
            if t["id"] in tmap:
                t.update({k: v for k, v in tmap[t["id"]].items()})
    started = _now()
    run_id = started.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)
    d = run_dir(product_id, run_id, out_root)
    (d / "evidence").mkdir(parents=True, exist_ok=True)
    env = environment_note()
    vers = P.versions(product_id)
    chosen = versions or list(vers)
    results = {}
    total = len(chosen) * len(pl["tc"])
    done = 0
    for ver in chosen:
        v = vers[ver]
        fp = P.fingerprint(product_id, ver)
        log_name = f"log_{product_id}_v{ver}.txt".replace("/", "_")
        lines = [env, f"# produk {P.REGISTRY[product_id]['nama']} v{ver} | {fp} | {v['label']} | run_id {run_id}",
                 "# TC · skenario | mulai–selesai | versi produk & hash | data uji / seed | aktual vs expected | status | bukti"]
        status, rows = {}, []
        mod, load_err = None, None
        if v["tersedia"]:
            try:
                mod = P.load(product_id, ver)
            except Exception as e:  # noqa: BLE001
                load_err = f"{type(e).__name__}: {e}"
        ctx = Ctx(product_id, ver, mod, sc, seed, params)
        for tc in pl["tc"]:
            t0 = _now()
            row = {"id": tc["id"], "skenario": tc.get("skenario"), "judul": tc["judul"], "tahap": tc["tahap"], "jenis": tc["jenis"],
                   "sasaran": tc.get("sasaran"), "wajib": tc.get("wajib", True), "negatif": tc.get("negatif", False),
                   "expected": tc.get("expected", {}), "data_uji": tc.get("data_uji"), "seed": None, "batasan": None,
                   "inconclusive": False, "metode": None, "analisis": None}
            blk = planner.blocked_by(tc, status)
            if not v["tersedia"] or load_err:
                st, actual = TDD, (v["catatan"] or load_err or "produk tidak tersedia")
            elif not tc.get("executor") or tc["executor"] not in EXECUTORS:
                st, actual = TDD, f"eksekutor untuk aksi '{tc.get('aksi_uk2') or tc.get('executor')}' belum tersedia"
            elif blk:
                st, actual = TERBLOKIR, "bergantung pada " + ", ".join(blk)
            else:
                try:
                    out = EXECUTORS[tc["executor"]](ctx, tc)
                    st = LULUS if out["passed"] else GAGAL
                    actual = out["actual"]
                    row.update({k: out.get(k) for k in ("metode", "analisis", "seed", "batasan", "inconclusive", "data")})
                    row["batasan"] = out.get("batasan")
                except Exception as e:  # noqa: BLE001 — galat tak terduga dicatat apa adanya
                    st, actual = GAGAL, f"galat tak terduga {type(e).__name__}: {e}"
            t1 = _now()
            status[tc["id"]] = st
            ev_name = None
            if st in (LULUS, GAGAL):
                ev_name = f"evidence/v{ver}/{tc['id']}.json"
                (d / ev_name).parent.mkdir(parents=True, exist_ok=True)
                (d / ev_name).write_text(json.dumps({"tc": tc["id"], "versi": ver, "status": st, "actual": actual,
                                                     "expected": tc.get("expected"), "data": row.get("data"),
                                                     "analisis": row.get("analisis"), "seed": row.get("seed")},
                                                    indent=1, ensure_ascii=False, default=str), encoding="utf-8")
            row.pop("data", None)
            row.update({"status": st, "actual": actual, "mulai": _ts(t0), "selesai": _ts(t1),
                        "durasi_s": round((t1 - t0).total_seconds(), 3), "bukti": ev_name})
            exp = tc.get("expected", {})
            exp_txt = exp.get("nilai") or exp.get("kriteria") or ""
            data_seed = (tc.get("data_uji") or "") + (f" / seed {row['seed']}" if row.get("seed") is not None else "")
            lines.append(" | ".join([f"{tc['id']} · {tc.get('skenario') or '—'}", f"{_ts(t0)}–{t1.strftime('%H:%M:%S')}",
                                     f"v{ver} · {fp}", _short(data_seed, 80), f"aktual: {_short(actual)} vs expected: {_short(exp_txt, 80)}",
                                     st, ev_name or "—"]))
            rows.append(row)
            done += 1
            if progress:
                progress(done, total, f"v{ver} {tc['id']} {st}")
        (d / log_name).write_text("\n".join(lines) + "\n", encoding="utf-8")
        results[ver] = {"versi": ver, "label": v["label"], "berkas": v["berkas"], "sha256": v["sha256"], "sidik_jari": fp,
                        "log": log_name, "tc": rows}
    finished = _now()
    _lembar(d, pl, results)
    rec = {"schema": "cryptan.uk3.run.v1", "run_id": run_id, "produk": product_id, "nama_produk": P.REGISTRY[product_id]["nama"],
           "mulai": started.isoformat(timespec="seconds"), "selesai": finished.isoformat(timespec="seconds"),
           "durasi_s": round((finished - started).total_seconds(), 2), "catatan_lingkungan": env, "seed": seed,
           "alasan_run": alasan or "run pertama", "deviasi": deviasi, "parameter_terkunci": prep["parameter_terkunci"],
           "prep_waktu": prep["waktu"], "rencana": {k: pl[k] for k in ("tahapan", "graf", "jumlah", "negatif", "peringatan", "tidak_dipilih")},
           "versi": results, "skenario_sha256": hashlib.sha256(json.dumps(sc, sort_keys=True, default=str).encode()).hexdigest()}
    (d / "run.json").write_text(json.dumps(rec, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    man = write_manifest(d)
    idx = runs_index(product_id, out_root)
    counts = {}
    for vr in results.values():
        for r in vr["tc"]:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
    idx.append({"run_id": run_id, "mulai": rec["mulai"], "alasan": rec["alasan_run"], "versi": list(results), "rekap": counts,
                "deviasi": len(deviasi), "manifest_sha256": hashlib.sha256((d / "evidence_manifest.json").read_bytes()).hexdigest(),
                "dir": rel(d)})
    (uk3_dir(product_id, out_root) / "runs_index.json").write_text(json.dumps(idx, indent=1, ensure_ascii=False), encoding="utf-8")
    rec["manifest"] = {"berkas": len(man["berkas"])}
    return rec


def _lembar(d, pl, results):
    """Lembar hasil berdampingan (templat KUK 1.1): TC × versi."""
    vers = list(results)
    with open(d / "lembar_hasil.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["TC", "Skenario", "Judul", "Tahap", "Jenis uji", "Expected"] + [f"v{v}" for v in vers] + ["Catatan"])
        for i, tc in enumerate(pl["tc"]):
            st = [results[v]["tc"][i]["status"] for v in vers]
            note = "; ".join(f"v{v}: {_short(results[v]['tc'][i]['actual'], 90)}" for v in vers
                             if results[v]["tc"][i]["status"] != LULUS)
            exp = tc.get("expected", {})
            w.writerow([tc["id"], tc.get("skenario"), tc["judul"], tc["tahap"], tc["jenis"],
                        _short(exp.get("nilai") or exp.get("kriteria") or "", 70)] + st + [note])
