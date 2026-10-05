"""Model data laporan — SATU-SATUNYA sumber angka untuk PDF, HTML, dan XLSX adalah results.json.

Semua turunan (KPI, matriks, temuan) dihitung ulang dari daftar algoritme di results.json,
sehingga filter laporan (--source/--primitive/--only-tested) tetap konsisten."""
import datetime as dt
import json
from collections import Counter, OrderedDict
from pathlib import Path

from ..runner import OUT
from ..tests import STATUSES

BULAN = ["Januari", "Februari", "Maret", "April", "Mei", "Juni", "Juli", "Agustus", "September", "Oktober", "November",
         "Desember"]
OVERALL = ["LULUS_SEMUA", "LULUS_SEBAGIAN", "TEMUAN", "TIDAK_DAPAT_DIUJI"]
BODY_ORDER = ["FIPS", "NIST-SP", "ISO-IEC"]
SOURCE_ALIASES = {"fips": "FIPS", "nist-sp": "NIST-SP", "nist": "NIST-SP", "sp": "NIST-SP", "iso-iec": "ISO-IEC", "iso": "ISO-IEC"}

FOLLOW_UP = {
    "K-01": "Laporkan ke pemelihara pustaka dengan ID vektor; hindari backend ini untuk verifikasi masukan tak tepercaya sampai diperbaiki.",
    "K-02": "Periksa batas ukuran pesan & parameter; ulangi pada mode full.",
    "K-03": "Bandingkan keluaran per iterasi antar-backend untuk menemukan titik divergensi.",
    "K-04": "Tambahkan validasi masukan (panjang kunci/IV/keluaran) di lapisan pemanggil; laporkan ke pemelihara pustaka.",
    "S-01": "Ulangi pada mode full (10.000 sampel); hasil mode ringan hanya indikatif.",
    "S-02": "Ulangi pada mode full (100 × 10⁶ bit) dan dengan NIST STS 2.1.2.",
    "S-03": "Periksa ulang implementasi komponen di core/ terhadap nilai acuan.",
    "I-01": "Konfirmasi dengan dudect/TVLA di lingkungan terkendali (ISO/IEC 17825); hasil Python hanya indikatif.",
    "I-03": "Tangani galat secara seragam; jangan bocorkan perbedaan kelas galat.",
}


def load(path=None) -> dict:
    p = Path(path) if path else OUT / "results.json"
    return json.loads(p.read_text(encoding="utf-8"))


def tanggal_id(iso: str) -> str:
    d = dt.datetime.fromisoformat(iso)
    return f"{d.day} {BULAN[d.month - 1]} {d.year}"


def norm_sources(sources):
    if not sources:
        return None
    if isinstance(sources, str):
        sources = sources.split(",")
    return [SOURCE_ALIASES.get(s.strip().lower(), s.strip().upper()) for s in sources if s.strip()]


def norm_list(v):
    if not v:
        return None
    if isinstance(v, str):
        v = v.split(",")
    return [x.strip() for x in v if x.strip()]


class Model:
    def __init__(self, res: dict, sources=None, primitives=None, only_tested=False, penyusun=None):
        self.res = res
        self.sources = norm_sources(sources)
        self.primitives = norm_list(primitives)
        self.only_tested = only_tested
        self.penyusun = penyusun
        algs = res["algorithms"]
        if self.sources:
            algs = [a for a in algs if set(a["source_body"]) & set(self.sources)]
        if self.primitives:
            algs = [a for a in algs if a["primitive"] in self.primitives]
        if only_tested:
            algs = [a for a in algs if a["overall"] != "TIDAK_DAPAT_DIUJI"]
        self.algs = algs
        self.filtered = bool(self.sources or self.primitives or only_tested)
        self.bodies = [b for b in BODY_ORDER if not self.sources or b in self.sources]
        self.tests = res["tests_catalog"]
        self.test_ids = [t["id"] for t in self.tests]
        self.prim_labels = res["catalog"]["primitives"]
        self.body_labels = res["catalog"]["bodies"]
        self.evidence = res.get("evidence", {})

    # ----------------------------------------------------------------- ringkasan
    def kpi(self) -> dict:
        c = Counter(a["overall"] for a in self.algs)
        return {"terdaftar": len(self.algs), "diuji": len(self.algs) - c["TIDAK_DAPAT_DIUJI"], "lulus_semua": c["LULUS_SEMUA"],
                "lulus_sebagian": c["LULUS_SEBAGIAN"], "punya_temuan": c["TEMUAN"], "tidak_dapat_diuji": c["TIDAK_DAPAT_DIUJI"]}

    def status_counts(self) -> dict:
        c = Counter(t["status"] for a in self.algs for t in a["tests"])
        return {s: c.get(s, 0) for s in STATUSES}

    def primitives_present(self):
        seen = OrderedDict()
        for k in self.prim_labels:
            if any(a["primitive"] == k for a in self.algs):
                seen[k] = self.prim_labels[k]
        return seen

    def overall_by_primitive(self) -> dict:
        out = OrderedDict()
        for k in self.primitives_present():
            c = Counter(a["overall"] for a in self.algs if a["primitive"] == k)
            out[k] = {o: c.get(o, 0) for o in OVERALL}
        return out

    def status_by_primitive(self) -> dict:
        out = OrderedDict()
        for k in self.primitives_present():
            c = Counter(t["status"] for a in self.algs if a["primitive"] == k for t in a["tests"])
            out[k] = {s: c.get(s, 0) for s in STATUSES}
        return out

    def applicability(self) -> dict:
        """Tabel uji × primitif: jumlah algoritme tempat uji berlaku (status ≠ TIDAK_BERLAKU)."""
        out = OrderedDict()
        for k in self.primitives_present():
            rows = [a for a in self.algs if a["primitive"] == k]
            out[k] = {tid: (sum(1 for a in rows for t in a["tests"] if t["plugin"] == tid and t["status"] != "TIDAK_BERLAKU"), len(rows))
                      for tid in self.test_ids}
        return out

    def by_body(self, body):
        """Algoritme suatu badan standar, dikelompokkan per primitif (urutan katalog)."""
        out = OrderedDict()
        for k, lbl in self.primitives_present().items():
            rows = [a for a in self.algs if a["primitive"] == k and body in a["source_body"]]
            if rows:
                out[k] = rows
        return out

    def body_counts(self):
        return {b: sum(1 for a in self.algs if b in a["source_body"]) for b in BODY_ORDER}

    @staticmethod
    def docs_for_body(a, body):
        pref = {"FIPS": ("FIPS",), "NIST-SP": ("SP ", "NIST "), "ISO-IEC": ("ISO",)}[body]
        docs = [d for d in a["source_doc"] if d.startswith(pref)]
        return docs or a["source_doc"]

    # ----------------------------------------------------------------- temuan
    def failing(self):
        """Uji GAGAL/INKONKLUSIF hasil uji langsung (S-04 = acuan literatur, dilaporkan terpisah)."""
        out = []
        for a in self.algs:
            for t in a["tests"]:
                if t["status"] in ("GAGAL", "INKONKLUSIF") and t["plugin"] != "S-04":
                    out.append((a, t, self.failure_detail(t)))
        return out

    def failure_detail(self, t) -> str:
        ev = self.evidence.get(t.get("evidence_id") or "", {}) or {}
        parts = []
        for be, d in (ev.get("per_backend") or {}).items():
            for f in (d.get("failures") or [])[:3]:
                parts.append(f"{be}: {f.get('id')}" + (f" ({f['detail']})" if f.get("detail") else ""))
        for c in ev.get("cases") or []:
            if not c.get("rejected", True):
                parts.append(f"diterima: {c['case']}")
        if not parts and t.get("reason"):
            parts.append(t["reason"])
        return "; ".join(parts)

    def s04(self, status):
        return [(a, t) for a in self.algs for t in a["tests"] if t["plugin"] == "S-04" and t["status"] == status]

    def weak_status(self):
        return [a for a in self.algs if a["status_nist"] in ("deprecated", "disallowed", "legacy_use")]

    def weak_strength(self):
        out = []
        for a in self.algs:
            s = a["security_strength_bits"]
            if (isinstance(s, (int, float)) and s < 112) or (isinstance(s, str) and s.startswith("<")):
                out.append(a)
        return out

    def quantum(self):
        groups = OrderedDict()
        for a in self.algs:
            if a.get("quantum_vulnerable"):
                groups.setdefault(a["family"], []).append(a)
        return groups

    def top_findings(self, limit=5):
        """3–5 temuan utama, disusun dari data (bukan teks tetap)."""
        out = []
        grp = OrderedDict()
        for a, t, det in self.failing():
            if t["status"] != "GAGAL":
                continue
            ev = self.evidence.get(t.get("evidence_id") or "", {}) or {}
            sig_parts, ids = [], []
            for be, d in (ev.get("per_backend") or {}).items():
                for f in d.get("failures") or []:
                    sig_parts.append(f"{be}: {f.get('detail') or f.get('id')}")
                    ids.append(str(f.get("id")))
            for c in ev.get("cases") or []:
                if not c.get("rejected", True):
                    sig_parts.append(f"diterima: {c['case']}")
            key = (t["plugin"], tuple(sig_parts) or (t.get("actual"),))
            g = grp.setdefault(key, {"test": t, "algs": [], "ids": [], "sig": sig_parts})
            g["algs"].append(a["id"])
            g["ids"] += ids
        for (plugin, _), g in grp.items():
            sig = "; ".join(g["sig"]) or g["test"].get("actual", "")
            if g["ids"]:
                sig += f" ({', '.join(dict.fromkeys(g['ids']))})"
            out.append(f"{plugin} GAGAL pada {', '.join(g['algs'])} — {sig}.")
        ws = self.s04("GAGAL")
        if ws:
            out.append(f"S-04 (kecukupan parameter, acuan SP 800-57/SP 800-131A): {len(ws)} algoritme tidak memenuhi ≥ 112 bit "
                       f"atau berstatus deprecated/disallowed/legacy, mis. {', '.join(a['id'] for a, _ in ws[:6])}.")
        q = sum(len(v) for v in self.quantum().values())
        if q:
            out.append(f"{q} algoritme rentan kuantum (NIST IR 8547): perlu rencana migrasi ke FIPS 203/204/205.")
        k = self.kpi()
        if k["tidak_dapat_diuji"]:
            out.append(f"{k['tidak_dapat_diuji']} algoritme tidak dapat diuji karena tidak ada backend di lingkungan uji "
                       f"(dilaporkan apa adanya, tidak dihitung lulus).")
        return out[:limit] if len(out) > limit else out

    def inkon_s04(self):
        return self.s04("INKONKLUSIF")

    # ----------------------------------------------------------------- lain-lain
    def histogram(self, t):
        ev = self.evidence.get(t.get("evidence_id") or "", {}) or {}
        return ev.get("histogram_fraction_0_1_bins20")

    def filename(self, ext, base_dir=None):
        d = dt.datetime.fromisoformat(self.res["generated_at"]).strftime("%Y%m%d")
        name = f"Laporan_Algoritme_Standar_{d}_{self.res['mode']}"
        if self.filtered:
            name += "_filter"
        return (Path(base_dir) if base_dir else OUT) / f"{name}.{ext}"
