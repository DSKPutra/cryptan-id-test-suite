"""KUK 1.1 — Dokumen uji dikumpulkan sesuai kebutuhan pengujian + checklist kesiapan (entry criteria).

Setiap dokumen dicatat versi, asal, dan SHA-256. Bila ada butir checklist "Tidak", pengujian tidak boleh dimulai:
butir yang kurang, penanggung jawab, dan tanggal ulang dicatat."""
import datetime as dt
import hashlib
import json
from pathlib import Path

import yaml

from .. import OUT, PKG, ROOT, rel
from .. import products as P

CHECKLIST = [
    ("skenario_final", "Dokumen skenario & test case versi final"),
    ("spesifikasi", "Spesifikasi desain produk"),
    ("produk_diterima", "Produk uji diterima + hash tercatat"),
    ("perangkat", "Perangkat uji terpasang & terverifikasi"),
    ("data_uji", "Data uji tersedia"),
    ("izin_jadwal", "Izin & jadwal disetujui"),
]


def _doc(jenis, nama, path, asal, dipakai, versi=None):
    p = ROOT / path if path else None
    ada = bool(p and p.exists())
    sha = None
    if ada:
        sha = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else hashlib.sha256(
            b"".join(f.read_bytes() for f in sorted(p.rglob("*.json")))).hexdigest()
    return {"jenis": jenis, "nama": nama, "berkas": rel(p) if p else None, "asal": asal, "dipakai_untuk": dipakai, "versi": versi,
            "ada": ada, "sha256": sha}


def scenario_file(product_id) -> Path:
    s = P.REGISTRY[product_id]["skenario"]
    return ROOT / "outputs" / "uk2" / "uk2_skenario.json" if s == "uk2" else PKG / "data" / s


def load_scenario(product_id) -> dict:
    f = scenario_file(product_id)
    if f.suffix == ".json":
        return json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
    return yaml.safe_load(f.read_text(encoding="utf-8"))


def collect(product_id) -> list:
    sc = load_scenario(product_id)
    f = scenario_file(product_id)
    docs = [
        _doc("Skenario, test case, expected value", f"Skenario uji {P.REGISTRY[product_id]['nama']}", rel(f),
             "UK-2 (uk2_skenario.json)" if f.suffix == ".json" else "UK-2 gaya skenario untuk produk latihan (Cryptan.ID)",
             "urutan uji dan pembanding hasil", sc.get("versi") or sc.get("schema")),
        _doc("Skenario UK-2 produk (SecureLib)", "uk2_skenario.json", "outputs/uk2/uk2_skenario.json", "UK-2", "test case lintas produk",
             None),
        _doc("Metode & parameter uji", "Keluaran UK-1 (metode, parameter)", "outputs/uk1", "UK-1", "cara olah data & kriteria lulus"),
        _doc("Spesifikasi desain produk & versinya", f"Registri produk: {product_id}", "uk3_pengujian/data/products.yaml",
             "pemilik produk", "memahami fungsi yang diuji", "1.0"),
        _doc("Ruang lingkup, batasan, izin tertulis", "ruang_lingkup.yaml", "products/ruang_lingkup.yaml", "pemilik produk",
             "batas apa yang boleh diuji", P.scope().get("versi")),
        _doc("Templat lembar hasil uji (belum diisi)", "templat_lembar_hasil.csv", "uk3_pengujian/data/templat_lembar_hasil.csv",
             "penguji", "mencatat hasil tiap test case", "1.0"),
    ]
    for ver, v in P.versions(product_id).items():
        if v["berkas"] and v["tersedia"]:
            docs.append({"jenis": "Produk uji", "nama": f"{P.REGISTRY[product_id]['nama']} v{ver} — {v['label']}",
                         "berkas": v["berkas"], "asal": P.REGISTRY[product_id]["pemilik"], "dipakai_untuk": "objek uji", "versi": ver,
                         "ada": True, "sha256": v["sha256"]})
    return docs


def checklist(product_id, docs, inv, overrides=None) -> dict:
    """Checklist kesiapan enam butir. overrides: {butir: (False, "alasan", "penanggung jawab", "YYYY-MM-DD")}."""
    sc = load_scenario(product_id)
    vers = P.versions(product_id)
    scope = P.scope()
    auto = {
        "skenario_final": (bool(sc) and (sc.get("status", "final") == "final"), "skenario belum final / tidak ada"),
        "spesifikasi": (bool(P.REGISTRY[product_id].get("spesifikasi")), "spesifikasi desain belum diterima"),
        "produk_diterima": (any(v["tersedia"] and v["sha256"] for v in vers.values()),
                            "produk belum diterima atau hash belum tercatat"),
        "perangkat": (inv["lengkap"] and inv["terverifikasi"], "perangkat wajib belum lengkap/terverifikasi: " + ", ".join(inv["kurang"])),
        "data_uji": (bool(sc), "data uji (vektor/parameter) belum tersedia"),
        "izin_jadwal": (bool(scope.get("izin", {}).get("disetujui") and scope.get("jadwal", {}).get("disetujui"))
                        and P.in_scope(product_id), "izin/jadwal belum disetujui atau produk di luar ruang lingkup"),
    }
    items = []
    for key, label in CHECKLIST:
        ok, why = auto[key]
        pj, ulang = "Penguji", None
        if overrides and key in overrides:
            ov = overrides[key]
            ok, why = ov[0], ov[1] if len(ov) > 1 else why
            pj = ov[2] if len(ov) > 2 else pj
            ulang = ov[3] if len(ov) > 3 else None
        items.append({"butir": key, "uraian": label, "status": "Ya" if ok else "Tidak",
                      "kekurangan": None if ok else why, "penanggung_jawab": None if ok else pj,
                      "tanggal_ulang": None if ok else (ulang or (dt.date.today() + dt.timedelta(days=1)).isoformat())})
    ready = all(i["status"] == "Ya" for i in items)
    return {"items": items, "siap": ready,
            "keputusan": "Pengujian boleh dimulai" if ready else "Pengujian TIDAK BOLEH dimulai — lengkapi butir yang kurang",
            "kriteria_keluar": "Semua TC dijalankan atau alasan tidak dijalankannya tercatat"}


def prepare(product_id, overrides=None, out_root=None) -> dict:
    """Tahap 1 'Siapkan' (KUK 1.1–1.2): dokumen + inventaris + checklist + kunci parameter n/m."""
    from .inventory import inventory
    if product_id not in P.REGISTRY:
        raise KeyError(product_id)
    inv = inventory()
    docs = collect(product_id)
    cl = checklist(product_id, docs, inv, overrides)
    sc = load_scenario(product_id)
    locked = {tc["id"]: tc.get("parameter_statistik") for tc in sc.get("test_cases", []) if isinstance(tc, dict)
              and tc.get("parameter_statistik")}
    res = {"schema": "cryptan.uk3.prep.v1", "produk": product_id, "nama_produk": P.REGISTRY[product_id]["nama"],
           "waktu": dt.datetime.now().astimezone().isoformat(timespec="seconds"), "dalam_ruang_lingkup": P.in_scope(product_id),
           "versi_produk": P.versions(product_id), "dokumen": docs, "inventaris": inv, "checklist": cl,
           "parameter_terkunci": locked,
           "parameter_terkunci_sha256": hashlib.sha256(json.dumps(locked, sort_keys=True).encode()).hexdigest(),
           "ruang_lingkup": P.scope()}
    d = (Path(out_root) if out_root else OUT) / product_id / "uk3"
    d.mkdir(parents=True, exist_ok=True)
    (d / "prep.json").write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    hist = d / "prep_riwayat"
    hist.mkdir(exist_ok=True)
    (hist / f"prep_{res['waktu'][:19].replace(':', '').replace('-', '')}.json").write_text(
        json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    return res


def latest(product_id, out_root=None):
    f = (Path(out_root) if out_root else OUT) / product_id / "uk3" / "prep.json"
    return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None
