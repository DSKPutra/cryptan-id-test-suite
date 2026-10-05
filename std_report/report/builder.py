"""Penyusun laporan PDF dari results.json (ReportLab Platypus).

Setiap angka di laporan berasal dari results.json lewat model.Model — tidak ada angka yang diketik tangan."""
import io
from pathlib import Path

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import CondPageBreak, Image, KeepTogether, NextPageTemplate, PageBreak

from .model import BODY_ORDER, FOLLOW_UP, OVERALL, Model, load, tanggal_id
from .template import (OVERALL_COLOR, STATUS_COLOR, THEME, Anchor, C, Caption, Heading, ListOf, LogoBox, NumberedCanvas, P,
                       ReportDoc, ST, Spacer, badge_cmds, badge_par, cm, data_table, kpi_cards, kv_table, make_toc, mono)

PW = A4[0] - 2 * THEME["page"]["margin_cm"] * cm          # lebar isi potret
LW = landscape(A4)[0] - 2 * THEME["page"]["margin_cm"] * cm

GLOSSARY = [
    ("ACVP / CAVP", "Automated Cryptographic Validation Protocol / Cryptographic Algorithm Validation Program (NIST)."),
    ("AEAD", "Authenticated Encryption with Associated Data — enkripsi terautentikasi (mis. GCM, CCM)."),
    ("Avalanche", "Sifat bahwa perubahan 1 bit masukan mengubah ±50% bit keluaran."),
    ("Backend", "Implementasi yang diakses lewat adapter (pyca/cryptography, pycryptodome, hashlib, core/, liboqs)."),
    ("DRBG", "Deterministic Random Bit Generator (SP 800-90A)."),
    ("Evidence ID", "Pengenal rekaman bukti mentah di results.json (bagian 'evidence')."),
    ("INDIKATIF", "Hasil dengan sampel kecil (mode ringan) atau pengukuran kasar; bukan dasar keputusan akhir."),
    ("KAT", "Known Answer Test — membandingkan keluaran dengan vektor uji resmi."),
    ("KDF", "Key Derivation Function (mis. PBKDF2, HKDF, SP 800-108)."),
    ("KEM", "Key Encapsulation Mechanism (mis. ML-KEM, FIPS 203)."),
    ("MCT / MMT", "Monte Carlo Test / Multi-block Message Test (CAVP)."),
    ("PERLU_VERIFIKASI", "Butir yang belum dapat dipastikan dari sumber primer; ditampilkan apa adanya."),
    ("PQC", "Post-Quantum Cryptography (FIPS 203, 204, 205)."),
    ("Security strength", "Kekuatan keamanan dalam bit menurut SP 800-57 Pt.1 Tabel 2."),
    ("TDD", "TIDAK DAPAT DIUJI — tidak ada backend atau vektor; tidak dihitung lulus."),
    ("T/B", "TIDAK BERLAKU — uji tidak relevan untuk primitif tersebut."),
    ("TVLA", "Test Vector Leakage Assessment — uji kebocoran kanal samping (fixed-vs-random, uji t Welch)."),
    ("Uji silang", "Membandingkan keluaran dua backend independen bila vektor resmi tidak tersedia (bukan KAT)."),
    ("Wycheproof", "Koleksi vektor uji kasus tepi C2SP/Google (Apache-2.0)."),
    ("XOF", "Extendable-Output Function (SHAKE, cSHAKE)."),
]


def _fmt(v):
    if v is None:
        return "—"
    if isinstance(v, bool):
        return "ya" if v else "tidak"
    if isinstance(v, float):
        return f"{v:g}"
    if isinstance(v, (list, tuple)):
        return ", ".join(_fmt(x) for x in v)
    return str(v)


def _params(p):
    if not p:
        return "—"
    return "; ".join(f"{k} = {_fmt(v)}" for k, v in p.items())


class Builder:
    def __init__(self, model: Model, ringkas=False):
        self.m = model
        self.ringkas = ringkas
        self.n_table = 0
        self.n_fig = 0
        self.story = []

    # ----------------------------------------------------------- helper
    def add(self, *fl):
        for f in fl:
            if isinstance(f, Caption):
                prev = self.story[-1] if self.story else None
                if not (isinstance(prev, Heading) or isinstance(prev, CondPageBreak)):
                    self.story.append(CondPageBreak(3.5 * cm))   # judul tabel tidak terpisah dari baris pertamanya
            self.story.append(f)

    def caption(self, kind, text):
        if kind == "table":
            self.n_table += 1
            return Caption("table", self.n_table, text)
        self.n_fig += 1
        return Caption("figure", self.n_fig, text)

    def h(self, text, level, key, toc=True):
        return Heading(text, level, key, toc)

    def para(self, text, style="body", raw=False):
        return P(text, style, raw)

    def bullets(self, items):
        return [P(f"•&nbsp;&nbsp;{_esc(x)}", "bullet", raw=True) for x in items]

    # ----------------------------------------------------------- bagian depan
    def cover(self):
        r, m = self.m.res, self.m
        ident = THEME["identity"]
        meta = [("Penyusun", m.penyusun or ident["penyusun_default"]), ("Instansi", ident["instansi"]),
                ("Tanggal", tanggal_id(r["generated_at"])), ("Versi tool", f"{r['tool']['name']} · {r['tool']['module']} {r['tool']['version']}"),
                ("Mode uji", r["mode"] + (" (indikatif untuk uji statistik)" if r["mode"] != "full" else "")),
                ("Seed", str(r["seed"]))]
        if m.filtered:
            meta.append(("Filter laporan", _filters_text(m)))
        self.add(Spacer(1, 1.6 * cm), LogoBox(), Spacer(1, 1.0 * cm),
                 P(THEME["title"], "cover_title"), Spacer(1, 0.3 * cm), P(THEME["subtitle"], "cover_sub"), Spacer(1, 1.2 * cm),
                 kv_table(meta, [4 * cm, PW - 4 * cm]), Spacer(1, 1.2 * cm),
                 _classification_box(ident["klasifikasi"]), Spacer(1, 2.2 * cm),
                 P(ident["copyright"], "small"),
                 P("Dokumen dihasilkan otomatis dari outputs/std_report/results.json. Setiap angka dalam laporan "
                   "dapat ditelusuri ke berkas tersebut.", "small"),
                 NextPageTemplate("portrait"), PageBreak())

    def approval(self):
        r, m = self.m.res, self.m
        self.add(self.h("Lembar Pengesahan dan Riwayat Revisi", 0, "pengesahan"),
                 self.caption("table", "Lembar pengesahan"))
        rows = [["Penyusun", m.penyusun or "", "", "", ""], ["Pemeriksa", "", "", "", ""], ["Penyetuju", "", "", "", ""]]
        self.add(data_table(["Peran", "Nama", "Jabatan", "Tanda tangan", "Tanggal"], rows,
                            [2.6 * cm, 4.4 * cm, 3.4 * cm, 3.8 * cm, 2.8 * cm], zebra=False,
                            extra=[("TOPPADDING", (0, 1), (-1, -1), 14), ("BOTTOMPADDING", (0, 1), (-1, -1), 14)]),
                 Spacer(1, 0.6 * cm), self.caption("table", "Riwayat revisi"),
                 data_table(["Versi", "Tanggal", "Uraian", "Oleh"],
                            [["1.0", tanggal_id(r["generated_at"]), "Terbitan awal — dihasilkan dari results.json "
                              f"(mode {r['mode']}, seed {r['seed']})", m.penyusun or ""]],
                            [1.6 * cm, 3.2 * cm, 8.6 * cm, 3.6 * cm]),
                 Spacer(1, 0.8 * cm),
                 P(f"Klasifikasi: {THEME['identity']['klasifikasi']}. Dokumen ini tidak untuk disebarluaskan di luar "
                   f"{THEME['identity']['instansi']} tanpa izin penyusun.", "small"),
                 PageBreak())

    def front_lists(self):
        self.add(P("Daftar Isi", "h1"), make_toc(), PageBreak(),
                 P("Daftar Tabel", "h1"), ListOf("LOT"), Spacer(1, 0.6 * cm),
                 CondPageBreak(6 * cm), P("Daftar Gambar", "h1"), ListOf("LOF"), PageBreak())

    # ----------------------------------------------------------- Bab 1
    def bab1(self):
        m, k = self.m, self.m.kpi()
        sc = m.status_counts()
        self.add(self.h("1  Ringkasan Eksekutif", 0, "bab1"),
                 P(f"Laporan ini memuat {k['terdaftar']} kombinasi algoritme × varian × panjang kunci dari standar "
                   f"{', '.join(m.body_labels[b] for b in m.bodies)}. Setiap kombinasi dijalankan terhadap "
                   f"{len(m.test_ids)} uji (lapis K, S, I) pada mode {m.res['mode']}."),
                 kpi_cards([(k["terdaftar"], "algoritme terdaftar"), (k["diuji"], "diuji"), (k["lulus_semua"], "lulus semua uji"),
                            (k["punya_temuan"], "punya temuan"), (k["tidak_dapat_diuji"], "tidak dapat diuji")], PW),
                 Spacer(1, 0.25 * cm),
                 P(f"Selain itu {k['lulus_sebagian']} algoritme lulus sebagian (sebagian uji tidak dapat dijalankan). "
                   f"Jumlah hasil per uji: " + ", ".join(f"{s.replace('_', ' ')} {n}" for s, n in sc.items()) + ".", "small"),
                 Spacer(1, 0.3 * cm))
        self.add(self.caption("figure", "Status keseluruhan algoritme per primitif"), self._chart_overall(), Spacer(1, 0.3 * cm))
        self.add(P("Temuan utama", "h2"), *self.bullets(m.top_findings()))
        self.add(PageBreak())

    def _chart_overall(self):
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        data = self.m.overall_by_primitive()
        labels = [self.m.prim_labels[k] for k in data]
        fig, ax = plt.subplots(figsize=(7.2, 3.3), dpi=200)
        left = [0] * len(labels)
        names = {"LULUS_SEMUA": "Lulus semua", "LULUS_SEBAGIAN": "Lulus sebagian", "TEMUAN": "Ada temuan",
                 "TIDAK_DAPAT_DIUJI": "Tidak dapat diuji"}
        for o in OVERALL:
            vals = [data[k][o] for k in data]
            ax.barh(labels, vals, left=left, color=THEME["colors"]["overall"][o], label=names[o], edgecolor="white", linewidth=0.6)
            for i, v in enumerate(vals):
                if v >= 3:
                    ax.text(left[i] + v / 2, i, str(v), ha="center", va="center", color="white", fontsize=7, fontweight="bold")
            left = [a + b for a, b in zip(left, vals)]
        ax.invert_yaxis()
        ax.set_xlabel("jumlah algoritme", fontsize=8)
        ax.tick_params(labelsize=7.5)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        ax.legend(fontsize=7, ncol=4, loc="upper center", bbox_to_anchor=(0.5, -0.2), frameon=False)
        fig.tight_layout()
        buf = io.BytesIO()
        fig.savefig(buf, format="png")
        plt.close(fig)
        buf.seek(0)
        w = PW
        return Image(buf, width=w, height=w * 3.3 / 7.2)

    # ----------------------------------------------------------- Bab 2
    def bab2(self):
        m, r = self.m, self.m.res
        self.add(self.h("2  Ruang Lingkup dan Metodologi", 0, "bab2"), self.h("2.1  Sumber standar", 1, "bab2-1"))
        bc = m.body_counts()
        cov = r["catalog"]["doc_coverage"]
        self.add(P("Daftar algoritme disusun dari katalog algo_catalog (catalog_seed.yaml + data tambahan std_report). "
                   "Setiap baris memiliki source_body dan source_doc; satu algoritme dapat tercantum di lebih dari satu sumber."),
                 self.caption("table", "Jumlah kombinasi algoritme per badan standar"),
                 data_table(["Badan standar", "Jumlah kombinasi", "Dokumen tercakup"],
                            [[m.body_labels[b], str(bc[b]), ", ".join(d for d in cov if _doc_body(d) == b)] for b in m.bodies],
                            [3.2 * cm, 2.8 * cm, PW - 6 * cm]))
        if r["catalog"]["missing_docs"]:
            self.add(P("Dokumen wajib yang belum tercakup: " + ", ".join(r["catalog"]["missing_docs"]), "small"))
        self.add(self.h("2.2  Tiga lapis uji", 1, "bab2-2"),
                 P("K (kesesuaian): KAT, round-trip, MCT/multi-blok, uji negatif. S (keamanan): avalanche, subset SP 800-22, "
                   "sifat komponen, kecukupan parameter. I (implementasi): variasi waktu (indikatif), kinerja (dicatat), "
                   "penanganan galat. Implementasi hanya diakses lewat core/adapters/."),
                 self.caption("table", "Katalog uji dan kriteria lulus"),
                 data_table(["ID", "Lapis", "Nama uji", "Kriteria"],
                            [[mono(t["id"]), t["layer"], t["name"], t["criteria"]] for t in m.tests],
                            [1.3 * cm, 1.2 * cm, 7.5 * cm, PW - 10 * cm]))
        app = m.applicability()
        self.add(CondPageBreak(7 * cm), self.caption("table", "Uji × primitif: jumlah algoritme tempat uji berlaku / jumlah algoritme"))
        hdr = ["Primitif"] + m.test_ids
        rows = [[m.prim_labels[k]] + [(f"{a}/{n}" if a else "—") for a, n in (v[t] for t in m.test_ids)] for k, v in app.items()]
        w0 = 3.6 * cm
        self.add(data_table(hdr, rows, [w0] + [(PW - w0) / len(m.test_ids)] * len(m.test_ids), header_style="cell_hdr"))
        ss = r["sample_sizes"]
        self.add(self.h("2.3  Mode uji dan ukuran sampel", 1, "bab2-3"),
                 P(f"Mode yang dipakai: {r['mode']}. Seed: {r['seed']}."),
                 self.caption("table", "Ukuran sampel"),
                 data_table(["Parameter", "Nilai"], [[k.replace("_", " "), _fmt(v)] for k, v in ss.items()], [6 * cm, PW - 6 * cm]))
        k = m.kpi()
        lim = [f"Mode {r['mode']}: hasil S-01, S-02, dan I-01 berlabel INDIKATIF; keputusan akhir memerlukan mode full."
               if r["mode"] != "full" else "Mode full: ukuran sampel sesuai spesifikasi laporan.",
               "I-01 diukur dari proses Python (perf_counter_ns) sehingga hanya indikatif; tidak menggantikan uji TVLA/dudect.",
               f"{k['tidak_dapat_diuji']} algoritme tidak memiliki backend di lingkungan uji dan berstatus TIDAK DAPAT DIUJI.",
               "S-04 adalah penilaian ACUAN/LITERATUR (SP 800-57, SP 800-131A, IR 8547), bukan hasil uji langsung.",
               "Uji silang dua backend dipakai bila vektor resmi tidak tersedia; label 'UJI SILANG' membedakannya dari KAT.",
               f"{len(r['catalog']['out_of_scope'])} entri katalog berada di luar FIPS/NIST SP/ISO/IEC dan tidak dimasukkan "
               f"(Tabel berikut); {len(r['catalog']['scraped_appendix'])} entri hasil scraping ACVP hanya dicantumkan di Lampiran C."]
        self.add(self.h("2.4  Keterbatasan", 1, "bab2-4"), *self.bullets(lim))
        oos = r["catalog"]["out_of_scope"]
        if oos:
            self.add(self.caption("table", "Entri katalog di luar tiga sumber standar"),
                     data_table(["ID", "Keluarga", "Varian", "Standar"],
                                [[mono(o["id"]), o["family"], o["variant"], ", ".join(o.get("standards") or [])] for o in oos],
                                [4 * cm, 3 * cm, 4 * cm, PW - 11 * cm]))
        self.add(PageBreak())

    # ----------------------------------------------------------- Bab 3
    def bab3(self):
        m = self.m
        self.add(self.h("3  Daftar Algoritme Standar", 0, "bab3"),
                 P("Status uji pada kolom terakhir adalah status keseluruhan dari Bab 4–5. Kekuatan keamanan dan status "
                   "NIST bersumber dari katalog (SP 800-57 Pt.1, SP 800-131A Rev.2)."))
        num = {"FIPS": "3.1", "NIST-SP": "3.2", "ISO-IEC": "3.3"}
        widths = [0.8 * cm, 3.2 * cm, 1.8 * cm, 1.8 * cm, 1.2 * cm, 1.6 * cm, 1.8 * cm, 2.8 * cm, 2.0 * cm]
        for b in m.bodies:
            groups = m.by_body(b)
            self.add(CondPageBreak(5 * cm), self.h(f"{num[b]}  {m.body_labels[b]}", 1, f"bab3-{b}"))
            if not groups:
                self.add(P("Tidak ada algoritme pada filter ini."))
                continue
            for prim, rows in groups.items():
                self.add(self.caption("table", f"{m.body_labels[b]} — {m.prim_labels[prim]}"))
                body, extra = [], []
                for i, a in enumerate(rows, 1):
                    body.append([str(i), mono(a["id"]), a["family"], a["variant"], _fmt(a["key_bits"]),
                                 _fmt(a["security_strength_bits"]), _fmt(a["status_nist"]),
                                 ", ".join(m.docs_for_body(a, b)), badge_par(a["overall"], overall=True)])
                    extra += badge_cmds(8, i, a["overall"], OVERALL_COLOR)
                self.add(data_table(["No", "ID", "Algoritme", "Varian", "Kunci (bit)", "Kekuatan (bit)", "Status NIST",
                                     "Dokumen sumber", "Status uji"], body, widths, extra=extra), Spacer(1, 0.3 * cm))
        self.add(NextPageTemplate("landscape"), PageBreak())

    # ----------------------------------------------------------- Bab 4 (lanskap)
    def bab4(self):
        m = self.m
        self.add(self.h("4  Matriks Hasil Uji", 0, "bab4"),
                 P("Baris = algoritme, kolom = uji. Setiap sel memuat teks status: LULUS, GAGAL, INKON (inkonklusif), "
                   "TDD (tidak dapat diuji), T/B (tidak berlaku), CATAT (kinerja dicatat tanpa kriteria).", "small"))
        ids = m.test_ids
        w_id, w_all = 4.6 * cm, 2.9 * cm
        w_t = (LW - w_id - w_all) / len(ids)
        for prim, lbl in m.primitives_present().items():
            rows = [a for a in m.algs if a["primitive"] == prim]
            self.add(CondPageBreak(6 * cm), self.h(f"4.{list(m.primitives_present()).index(prim) + 1}  {lbl}", 1, f"bab4-{prim}"),
                     self.caption("table", f"Matriks hasil uji — {lbl}"))
            body, extra = [], []
            for i, a in enumerate(rows, 1):
                st = {t["plugin"]: t["status"] for t in a["tests"]}
                body.append([mono(a["id"])] + [badge_par(st.get(t, "TIDAK_BERLAKU"), short=True) for t in ids] +
                            [badge_par(a["overall"], overall=True)])
                for j, t in enumerate(ids, 1):
                    extra += badge_cmds(j, i, st.get(t, "TIDAK_BERLAKU"))
                extra += badge_cmds(len(ids) + 1, i, a["overall"], OVERALL_COLOR)
            self.add(data_table(["Algoritme"] + ids + ["Keseluruhan"], body, [w_id] + [w_t] * len(ids) + [w_all], zebra=False,
                                extra=extra + [("LINEBELOW", (0, 1), (-1, -1), 0.6, "white"),
                                               ("LINEAFTER", (0, 1), (-1, -1), 0.6, "white")]),
                     Spacer(1, 0.4 * cm))
        self.add(NextPageTemplate("portrait"), PageBreak())

    # ----------------------------------------------------------- Bab 5
    def bab5(self):
        m = self.m
        self.add(self.h("5  Hasil Rinci per Algoritme", 0, "bab5"),
                 P("Satu kartu per kombinasi algoritme. Uji yang tidak berlaku atau tidak dapat diuji dengan alasan yang sama "
                   "digabung dalam satu baris. Evidence ID merujuk ke bagian 'evidence' di results.json.", "small"))
        widths = [1.15 * cm, 2.4 * cm, 2.7 * cm, 3.5 * cm, 2.3 * cm, 1.65 * cm, 1.1 * cm, PW - 14.8 * cm]
        for pi, (prim, lbl) in enumerate(m.primitives_present().items(), 1):
            self.add(CondPageBreak(6 * cm), self.h(f"5.{pi}  {lbl}", 1, f"bab5-{prim}"))
            for a in (x for x in m.algs if x["primitive"] == prim):
                self._card(a, widths)

    def _card(self, a, widths):
        m = self.m
        ident = (f"<b>{_esc(a['id'])}</b> &nbsp;·&nbsp; {_esc(a['family'])} {_esc(a['variant'])} &nbsp;·&nbsp; kunci "
                 f"{_esc(_fmt(a['key_bits']))} bit &nbsp;·&nbsp; strength {_esc(_fmt(a['security_strength_bits']))} bit &nbsp;·&nbsp; "
                 f"status NIST {_esc(_fmt(a['status_nist']))} &nbsp;·&nbsp; {_esc(', '.join(a['source_doc']))} &nbsp;·&nbsp; "
                 f"backend: {_esc(', '.join(a['backends']) or 'tidak ada')}")
        head = [Anchor(a["id"], 2, f"card-{a['id']}"), P(f"Kartu {a['id']}", "h3"), P(ident, "cell", raw=True),
                Spacer(1, 0.12 * cm)]
        rows, extra, merged = [], [], {}
        for t in a["tests"]:
            if t["status"] in ("TIDAK_BERLAKU", "TIDAK_DAPAT_DIUJI"):
                merged.setdefault((t["status"], t.get("reason") or ""), []).append(t["plugin"])
                continue
            act = t.get("actual") or ""
            if t.get("label"):
                act = f"[{t['label']}] {act}"
            if t.get("reason") and t["status"] != "LULUS":
                act += f" — {t['reason']}"
            rows.append([mono(t["plugin"]), P(t["name"], "cell_small"), P(_params(t.get("parameters")), "cell_small"),
                         P(act, "cell_small"), P(t.get("criteria") or "", "cell_small"), badge_par(t["status"]),
                         P(f"{t['duration_s']:.3f}" if t.get("duration_s") is not None else "—", "cell_small"),
                         mono(t.get("evidence_id") or "—", "cell_mono_small")])
            extra += badge_cmds(5, len(rows), t["status"])
        for (st, reason), ids in merged.items():
            rows.append([mono(", ".join(ids)), P("Tidak berlaku" if st == "TIDAK_BERLAKU" else "Tidak dapat diuji", "cell_small"),
                         P("—", "cell_small"), P(reason.replace("TDD:", "") or "—", "cell_small"), P("—", "cell_small"),
                         badge_par(st), P("—", "cell_small"), P("—", "cell_small")])
            extra += badge_cmds(5, len(rows), st)
        tbl = data_table(["Uji", "Nama", "Parameter", "Hasil aktual", "Kriteria", "Status", "Detik", "Evidence"], rows,
                         widths, extra=extra)
        block = head + [tbl]
        hist = next((m.histogram(t) for t in a["tests"] if t["plugin"] == "S-01" and m.histogram(t)), None)
        self.add(CondPageBreak(5 * cm), *block)
        if hist:
            self.add(KeepTogether([Spacer(1, 0.15 * cm), P(f"Histogram avalanche {a['id']} (fraksi bit berubah, 20 kelas; S-01)", "caption"),
                                   _hist_drawing(hist)]))
        self.add(Spacer(1, 0.45 * cm))

    # ----------------------------------------------------------- Bab 6
    def bab6(self):
        m = self.m
        self.add(PageBreak(), self.h("6  Temuan dan Peringatan", 0, "bab6"))
        fails = m.failing()
        self.add(self.h("6.1  Uji GAGAL / INKONKLUSIF (hasil uji langsung)", 1, "bab6-1"))
        if fails:
            rows, extra = [], []
            for i, (a, t, det) in enumerate(fails, 1):
                rows.append([mono(a["id"]), mono(t["plugin"]), badge_par(t["status"]), P((t.get("actual") or "") +
                             (f" — {det}" if det else ""), "cell_small"),
                             P(_fmt((t.get("parameters") or {}).get("sumber")) if (t.get("parameters") or {}).get("sumber")
                               else (t.get("source") or ""), "cell_small"),
                             P(FOLLOW_UP.get(t["plugin"], "Tinjau bukti dan ulangi pada mode full."), "cell_small")])
                extra += badge_cmds(2, i, t["status"])
            self.add(self.caption("table", "Uji GAGAL dan INKONKLUSIF"),
                     data_table(["Algoritme", "Uji", "Status", "Hasil & bukti", "Rujukan", "Tindak lanjut"], rows,
                                [2.6 * cm, 1.0 * cm, 1.7 * cm, 5.0 * cm, 2.7 * cm, PW - 13.0 * cm], extra=extra))
        else:
            self.add(P("Tidak ada uji langsung yang GAGAL atau INKONKLUSIF."))
        ws = m.weak_status()
        self.add(self.h("6.2  Algoritme deprecated / disallowed / legacy", 1, "bab6-2"))
        if ws:
            self.add(self.caption("table", "Status NIST tidak acceptable (SP 800-131A Rev.2)"),
                     data_table(["Algoritme", "Status NIST", "Strength (bit)", "Dokumen", "Tindak lanjut"],
                                [[mono(a["id"]), a["status_nist"], _fmt(a["security_strength_bits"]), ", ".join(a["source_doc"]),
                                  "Jangan dipakai untuk perlindungan baru; hanya untuk memproses data lama (legacy)."] for a in ws],
                                [3.6 * cm, 2.2 * cm, 1.9 * cm, 4.2 * cm, PW - 11.9 * cm]))
        else:
            self.add(P("Tidak ada."))
        wk = m.weak_strength()
        self.add(self.h("6.3  Kekuatan keamanan < 112 bit", 1, "bab6-3"))
        if wk:
            self.add(self.caption("table", "Kekuatan keamanan di bawah 112 bit (SP 800-57 Pt.1)"),
                     data_table(["Algoritme", "Strength (bit)", "Status NIST", "Tindak lanjut"],
                                [[mono(a["id"]), _fmt(a["security_strength_bits"]), _fmt(a["status_nist"]),
                                  "Ganti dengan parameter ≥ 112 bit (≥ 128 bit untuk masa pakai panjang)."] for a in wk],
                                [4 * cm, 2.4 * cm, 2.6 * cm, PW - 9 * cm]))
        else:
            self.add(P("Tidak ada."))
        q = m.quantum()
        self.add(self.h("6.4  Rentan kuantum (NIST IR 8547)", 1, "bab6-4"))
        if q:
            self.add(self.caption("table", "Algoritme rentan kuantum per keluarga"),
                     data_table(["Keluarga", "Jumlah", "Algoritme", "Tindak lanjut"],
                                [[fam, str(len(v)), P(", ".join(a["id"] for a in v), "cell_small"),
                                  "Rencanakan migrasi ke ML-KEM (FIPS 203) / ML-DSA (FIPS 204) / SLH-DSA (FIPS 205)."]
                                 for fam, v in q.items()], [3 * cm, 1.5 * cm, 7.5 * cm, PW - 12 * cm]))
        else:
            self.add(P("Tidak ada."))
        ik = m.inkon_s04()
        self.add(self.h("6.5  Kecukupan parameter belum dapat dipastikan", 1, "bab6-5"),
                 P(f"{len(ik)} algoritme berstatus INKONKLUSIF pada S-04 karena kekuatan atau statusnya PERLU_VERIFIKASI "
                   "(lihat Lampiran C)."))
        self.add(PageBreak())

    # ----------------------------------------------------------- Bab 7
    def bab7(self):
        m = self.m
        self.add(self.h("7  Kesimpulan", 0, "bab7"),
                 self.caption("table", "Ringkasan status keseluruhan per primitif (jumlah algoritme)"))
        rows = []
        for prim, d in m.overall_by_primitive().items():
            tot = sum(d.values())
            rows.append([m.prim_labels[prim], str(tot), str(tot - d["TIDAK_DAPAT_DIUJI"]), str(d["LULUS_SEMUA"]),
                         str(d["LULUS_SEBAGIAN"]), str(d["TEMUAN"]), str(d["TIDAK_DAPAT_DIUJI"])])
        k = m.kpi()
        rows.append(["Total", str(k["terdaftar"]), str(k["diuji"]), str(k["lulus_semua"]), str(k["lulus_sebagian"]),
                     str(k["punya_temuan"]), str(k["tidak_dapat_diuji"])])
        self.add(data_table(["Primitif", "Terdaftar", "Diuji", "Lulus semua", "Lulus sebagian", "Ada temuan", "Tidak dapat diuji"],
                            rows, [4.4 * cm] + [(PW - 4.4 * cm) / 6] * 6,
                            extra=[("FONTNAME", (0, len(rows)), (-1, len(rows)), "DejaVuSans-Bold"),
                                   ("BACKGROUND", (0, len(rows)), (-1, len(rows)), C["accent_light"])]))
        self.add(Spacer(1, 0.3 * cm), P("Batas keabsahan hasil", "h2"), *self.bullets([
            f"Pada mode {m.res['mode']} dengan seed {m.res['seed']}, {k['lulus_semua']} dari {k['terdaftar']} algoritme lulus "
            f"semua uji yang dapat dijalankan dan {k['punya_temuan']} algoritme memiliki temuan.",
            "Hasil berlaku untuk versi pustaka di Lampiran A dan tidak menyatakan bahwa suatu produk 'aman'.",
            "Tidak ditemukannya bukti ketidakacakan atau kebocoran waktu bukan bukti keamanan; uji statistik dan I-01 pada "
            "mode ringan bersifat indikatif.",
            "Algoritme berstatus TIDAK DAPAT DIUJI tidak dinilai dan tidak boleh dianggap lulus.",
            "Butir PERLU_VERIFIKASI (Lampiran C) harus dipastikan terhadap teks standar sebelum laporan dipakai sebagai acuan."]))
        self.add(Spacer(1, 0.6 * cm), P(THEME["identity"]["copyright"], "small"), PageBreak())

    # ----------------------------------------------------------- Lampiran
    def appendices(self):
        r, m = self.m.res, self.m
        env = r["environment"]
        self.add(self.h("Lampiran A  Lingkungan Uji", 0, "lampA"), self.caption("table", "Lingkungan uji"),
                 kv_table([("Sistem operasi", env["os"]), ("CPU", f"{env['cpu']} ({env['cpu_count']} inti)"), ("Python", env["python"]),
                           ("Seed", str(r["seed"])), ("Mode", r["mode"]), ("Durasi total uji", f"{env['duration_s']} s"),
                           ("Waktu pembuatan results.json", r["generated_at"])] +
                          [(f"Pustaka: {k}", v) for k, v in env["libraries"].items()], [5 * cm, PW - 5 * cm]),
                 PageBreak())
        self.add(self.h("Lampiran B  Sumber Vektor Uji", 0, "lampB"), self.caption("table", "Berkas vektor uji, sumber, dan SHA-256"),
                 data_table(["Berkas", "Sumber", "Lisensi", "Uji (subset/penuh)", "SHA-256 (berkas subset)"],
                            [[mono(v["file"], "cell_small"), P(v["source"], "cell_small"), P(v.get("license", "—"), "cell_small"),
                              P(f"{v.get('tests_subset', '—')}/{v.get('tests_full', '—')}", "cell_small"),
                              mono(v["sha256"], "cell_small")] for v in r["vectors"]],
                            [4.3 * cm, 3.5 * cm, 1.9 * cm, 1.6 * cm, PW - 11.3 * cm]),
                 PageBreak())
        pv = r["perlu_verifikasi"]
        self.add(self.h("Lampiran C  Daftar PERLU_VERIFIKASI", 0, "lampC"),
                 P(f"{len(pv)} butir belum dipastikan dari sumber primer, termasuk {len(r['catalog']['scraped_appendix'])} entri hasil "
                   "scraping ACVP yang belum dikurasi. Butir-butir ini ditampilkan apa adanya."),
                 self.caption("table", "Butir PERLU_VERIFIKASI"),
                 data_table(["No", "Butir", "Jenis", "Rincian"],
                            [[str(i), mono(x["item"], "cell_small"), P(x["jenis"], "cell_small"), P(x["detail"], "cell_small")]
                             for i, x in enumerate(pv, 1)], [0.9 * cm, 4.6 * cm, 3.4 * cm, PW - 8.9 * cm]),
                 PageBreak())
        self.add(self.h("Lampiran D  Glosarium", 0, "lampD"), self.caption("table", "Glosarium dan singkatan"),
                 data_table(["Istilah", "Arti"], [[P(a, "cell_b"), b] for a, b in GLOSSARY], [3.6 * cm, PW - 3.6 * cm]),
                 Spacer(1, 1 * cm), P(THEME["identity"]["copyright"], "small"))

    # ----------------------------------------------------------- susun
    def build(self, path):
        self.cover()
        self.approval()
        self.front_lists()
        self.bab1()
        self.bab2()
        self.bab3()
        self.bab4()
        if not self.ringkas:
            self.bab5()
        self.bab6()
        self.bab7()
        self.appendices()
        r = self.m.res
        meta = {"title": THEME["title"], "short_title": THEME["short_title"], "penyusun": self.m.penyusun or THEME["identity"]["penyusun_default"],
                "klasifikasi": THEME["identity"]["klasifikasi"], "tanggal": tanggal_id(r["generated_at"]),
                "subject": f"{THEME['subtitle']} — mode {r['mode']}", "creator": f"{r['tool']['name']} {r['tool']['module']} {r['tool']['version']}",
                "keywords": "FIPS, NIST SP 800, ISO/IEC, KAT, kriptografi"}
        doc = ReportDoc(path, meta)
        doc.multiBuild(self.story, canvasmaker=NumberedCanvas, maxPasses=6)
        return path


# --------------------------------------------------------------------------- utilitas
def _esc(s):
    from xml.sax.saxutils import escape
    return escape(str(s))


def _doc_body(d):
    return "FIPS" if d.startswith("FIPS") else "ISO-IEC" if d.startswith("ISO") else "NIST-SP"


def _filters_text(m):
    parts = []
    if m.sources:
        parts.append("sumber " + ", ".join(m.sources))
    if m.primitives:
        parts.append("primitif " + ", ".join(m.primitives))
    if m.only_tested:
        parts.append("hanya yang diuji")
    return "; ".join(parts)


def _classification_box(text):
    from reportlab.platypus import Table, TableStyle
    t = Table([[P(f"KLASIFIKASI: {text}", "cell_hdr")]], colWidths=[7 * cm], hAlign="LEFT")
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), STATUS_COLOR["GAGAL"]), ("TOPPADDING", (0, 0), (-1, -1), 6),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 6), ("LEFTPADDING", (0, 0), (-1, -1), 10)]))
    return t


def _hist_drawing(hist):
    w, h = 9 * cm, 3.4 * cm
    d = Drawing(w, h)
    bc = VerticalBarChart()
    bc.x, bc.y, bc.width, bc.height = 28, 18, w - 36, h - 26
    bc.data = [hist]
    bc.bars[0].fillColor = C["accent"]
    bc.bars[0].strokeColor = None
    bc.valueAxis.valueMin = 0
    bc.valueAxis.labels.fontName = "DejaVuSans"
    bc.valueAxis.labels.fontSize = 6
    bc.categoryAxis.categoryNames = [f"{i * 0.05:.2f}" if i % 5 == 0 else "" for i in range(20)]
    bc.categoryAxis.labels.fontName = "DejaVuSans"
    bc.categoryAxis.labels.fontSize = 6
    bc.barSpacing = 0.5
    d.add(bc)
    d.add(String(w - 4, 2, "fraksi bit berubah", fontName="DejaVuSans", fontSize=6, textAnchor="end", fillColor=C["muted"]))
    return d


def build_pdf(res=None, out=None, ringkas=False, sources=None, primitives=None, only_tested=False, penyusun=None) -> Path:
    res = res or load()
    m = Model(res, sources, primitives, only_tested, penyusun)
    path = Path(out) if out else m.filename("pdf")
    path.parent.mkdir(parents=True, exist_ok=True)
    Builder(m, ringkas).build(path)
    return path
