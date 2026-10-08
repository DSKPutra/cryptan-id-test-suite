"""GUI Streamlit UK-3 — Melakukan Pengujian Terhadap Produk Kriptografi (Cryptan.ID Test Suite).

  streamlit run uk3_pengujian/app.py

Alur: 1 Siapkan → 2 Jalankan → 3 Olah data → 4 Simpulkan & laporkan (+ Lab Keacakan).
Tahap berikutnya terkunci sampai tahap sebelumnya selesai."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import numpy as np  # noqa: E402
import streamlit as st  # noqa: E402

from uk3_pengujian import KUK, UNIT, UNIT_TITLE  # noqa: E402
from uk3_pengujian import products as P  # noqa: E402
from uk3_pengujian.prep import documents  # noqa: E402
from uk3_pengujian.run import planner, runner  # noqa: E402

st.set_page_config(page_title="Cryptan.ID — UK-3 Pengujian", page_icon="🔐", layout="wide")
ACC = "#3D7A74"
st.markdown(f"<div style='background:{ACC};color:#fff;padding:8px 14px;border-radius:6px'><b>UK-3 · {UNIT_TITLE}</b> "
            f"<span style='opacity:.8'>({UNIT})</span></div>", unsafe_allow_html=True)
st.caption("Cryptan.ID Test Suite · © Cryptan.ID — made by Dea Saka Kurnia Putra")

PAGES = ["1 Siapkan", "2 Jalankan", "3 Olah data", "4 Simpulkan & laporkan", "Lab Keacakan"]
with st.sidebar:
    pid = st.selectbox("Produk uji", list(P.REGISTRY), format_func=lambda k: P.REGISTRY[k]["nama"])
    prep = documents.latest(pid)
    idx = runner.runs_index(pid)
    rid = st.selectbox("Run", [x["run_id"] for x in reversed(idx)]) if idx else None
    rdir = runner.run_dir(pid, rid) if rid else None
    done = {"prep": bool(prep and prep["checklist"]["siap"]), "run": bool(rid),
            "analisis": bool(rdir and (rdir / "analisis.json").exists())}
    lock = {PAGES[0]: False, PAGES[1]: not done["prep"], PAGES[2]: not done["run"], PAGES[3]: not done["analisis"], PAGES[4]: False}
    page = st.radio("Tahap", PAGES, format_func=lambda p: ("🔒 " if lock[p] else "") + p)
    st.caption("KUK: " + {PAGES[0]: "1.1–1.2", PAGES[1]: "2.1–2.2", PAGES[2]: "3.1", PAGES[3]: "3.2–3.3", PAGES[4]: "3.1 (keacakan)"}[page])


def locked(msg):
    st.warning(f"🔒 Tahap ini terkunci: {msg}")
    st.stop()


def badge(s):
    c = {"LULUS": "#2E7D32", "GAGAL": "#C62828", "TERBLOKIR": "#B26A00", "TIDAK DAPAT DIUJI": "#6B7280", "Memenuhi": "#2E7D32",
         "Memenuhi dengan Catatan": ACC, "Inkonklusif": "#B26A00", "Tidak Memenuhi": "#C62828"}.get(s, "#6B7280")
    return f"<span style='background:{c};color:#fff;padding:1px 7px;border-radius:3px;font-weight:600'>{s}</span>"


# ------------------------------------------------------------------------------------------- 1 Siapkan
if page == PAGES[0]:
    st.header("1 · Siapkan pengujian")
    st.caption(f"KUK 1.1 {KUK['1.1']} · KUK 1.2 {KUK['1.2']}")
    st.subheader("Checklist kesiapan (entry criteria)")
    ov = {}
    cols = st.columns(3)
    for i, (k, label) in enumerate(documents.CHECKLIST):
        v = cols[i % 3].selectbox(label, ["otomatis", "Ya", "Tidak"], key=f"cl-{k}")
        if v != "otomatis":
            ov[k] = (v == "Ya", "ditandai penguji", "Penguji")
    if st.button("Siapkan / perbarui", type="primary"):
        with st.spinner("inventarisasi & verifikasi alat…"):
            prep = documents.prepare(pid, ov or None)
        st.rerun()
    if prep:
        cl = prep["checklist"]
        (st.success if cl["siap"] else st.error)(cl["keputusan"])
        st.dataframe([{"Butir": i["uraian"], "Status": i["status"], "Kekurangan": i["kekurangan"], "PJ": i["penanggung_jawab"],
                       "Tanggal ulang": i["tanggal_ulang"]} for i in cl["items"]], hide_index=True, use_container_width=True)
        st.subheader("Dokumen uji (KUK 1.1)")
        st.dataframe([{"Jenis": d["jenis"], "Berkas": d["berkas"], "Asal": d["asal"], "Versi": d["versi"], "Ada": d["ada"],
                       "SHA-256": (d["sha256"] or "")[:24]} for d in prep["dokumen"]], hide_index=True, use_container_width=True)
        st.subheader("Perangkat & verifikasi alat (KUK 1.2)")
        st.code(prep["inventaris"]["catatan_lingkungan"], language=None)
        c1, c2 = st.columns(2)
        c1.dataframe([{"Perangkat": r["perangkat"], "Versi": r["versi"], "Status": r["status"]} for r in prep["inventaris"]["perangkat"]],
                     hide_index=True, use_container_width=True)
        c2.dataframe([{"Uji": c["uji"], "Expected": c["expected"][:20], "Aktual": c["actual"][:20], "Lulus": c["lulus"]}
                      for c in prep["inventaris"]["verifikasi"]], hide_index=True, use_container_width=True)
        st.caption("Parameter statistik dikunci: " + json.dumps(prep["parameter_terkunci"], ensure_ascii=False))

# ------------------------------------------------------------------------------------------- 2 Jalankan
elif page == PAGES[1]:
    st.header("2 · Jalankan tahapan pengujian")
    if lock[page]:
        locked("checklist kesiapan belum 'Ya' semua (halaman 1)")
    pl = planner.plan(pid)
    st.subheader("Tahapan (KUK 2.1)")
    st.dataframe([{"Tahap": s["tahap"], "Nama": s["nama"], "Alasan": s["alasan"], "TC": ", ".join(s["tc"])} for s in pl["tahapan"]],
                 hide_index=True, use_container_width=True)
    for w in pl["peringatan"]:
        st.warning(w)
    with st.expander("Sembilan langkah pengujian algoritma"):
        st.table([{"No": a, "Langkah": b, "Contoh": c, "Bila gagal": d} for a, b, c, d in pl["sembilan_langkah"]])
    with st.expander("Graf ketergantungan (smoke/KAT gagal → TERBLOKIR)"):
        st.code("\n".join(f"{a} → {b}" for a, b in pl["graf"]) or "—", language=None)
    st.subheader("Eksekusi (KUK 2.2)")
    sel = st.multiselect("Test case", [t["id"] for t in pl["tc"]], default=[t["id"] for t in pl["tc"]])
    alasan = st.text_input("Alasan run" + (" (wajib — sudah ada run sebelumnya)" if idx else ""), "" if idx else "run pertama")
    if st.button("Jalankan", type="primary", disabled=bool(idx) and not alasan.strip()):
        bar = st.progress(0.0)
        try:
            r = runner.run(pid, None, sel, alasan.strip() or None, progress=lambda i, n, t: bar.progress(i / n, text=t))
            st.success(f"run_id {r['run_id']} selesai ({r['durasi_s']} s)")
            st.rerun()
        except (runner.NotReady, runner.RerunWithoutReason, PermissionError) as e:
            st.error(str(e))
    if rid:
        rec = runner.load_run(pid, rid)
        st.caption(f"Run terpilih {rid} · alasan: {rec['alasan_run']}")
        vers = list(rec["versi"])
        rows = []
        for i, t in enumerate(rec["versi"][vers[0]]["tc"]):
            rows.append(f"<tr><td><code>{t['id']}</code></td><td>{t['judul']}</td>" +
                        "".join(f"<td>{badge(rec['versi'][v]['tc'][i]['status'])}</td>" for v in vers) + "</tr>")
        st.markdown("<table><tr><th>TC</th><th>Judul</th>" + "".join(f"<th>v{v}</th>" for v in vers) + "</tr>" + "".join(rows) + "</table>",
                    unsafe_allow_html=True)
        v = st.selectbox("Log versi", vers)
        st.code((runner.run_dir(pid, rid) / rec["versi"][v]["log"]).read_text(encoding="utf-8"), language=None)

# ------------------------------------------------------------------------------------------- 3 Olah data
elif page == PAGES[2]:
    st.header("3 · Olah data hasil pengujian")
    st.caption(f"KUK 3.1 {KUK['3.1']}")
    if lock[page]:
        locked("belum ada run (halaman 2)")
    from uk3_pengujian.analysis.analyze import analyze
    if st.button("Analisis run ini", type="primary") or not done["analisis"]:
        analyze(pid, rid)
        st.rerun()
    an = json.loads((rdir / "analisis.json").read_text(encoding="utf-8"))
    (st.success if an["konsisten"] else st.error)("Keputusan TC konsisten dengan olah data" if an["konsisten"] else "Ada keputusan yang tidak konsisten")
    for m in an["metode"]:
        st.subheader(m["metode"])
        st.caption("Aturan: " + m["aturan"])
        st.dataframe([{"Versi": b["versi"], "TC": b["tc"], "Status": b["status"], "Olah data": b["olah"]} for b in m["baris"]],
                     hide_index=True, use_container_width=True)
        if m["metode"] == "NIST SP 800-22":
            for b in m["baris"]:
                for t, r in (b.get("analisis") or {}).items():
                    st.bar_chart({"jumlah p-value": r["histogram"]}, height=160)
                    st.caption(f"{b['tc']} {t}: histogram 10 interval")
    if an["galat_seragam"]:
        st.caption("Keseragaman kelas galat: " + json.dumps(an["galat_seragam"], ensure_ascii=False))

# ------------------------------------------------------------------------------------------- 4 Simpulkan
elif page == PAGES[3]:
    st.header("4 · Simpulkan & laporkan")
    st.caption(f"KUK 3.2 {KUK['3.2']} · KUK 3.3 {KUK['3.3']}")
    if lock[page]:
        locked("olah data belum dijalankan (halaman 3)")
    from uk3_pengujian.conclude import cvss, wording
    from uk3_pengujian.conclude.decide import conclude
    txt = st.text_area("Rumusan kesimpulan penguji (diperiksa otomatis)", "")
    if st.button("Tentukan kesimpulan", type="primary"):
        conclude(pid, rid, pernyataan=txt or None)
    kf = rdir / "kesimpulan.json"
    if kf.exists():
        k = json.loads(kf.read_text(encoding="utf-8"))
        for v, x in k["per_versi"].items():
            st.markdown(f"**v{v}** — keseluruhan {badge(x['keseluruhan'])} · tingkat lulus {x['rekap']['LULUS']}/{x['total']}",
                        unsafe_allow_html=True)
            st.markdown("".join(f"<div>{s} {badge(o['kategori'])} {o['nama']} — <i>{o['alasan']}</i></div>"
                                for s, o in sorted(x["sasaran"].items())), unsafe_allow_html=True)
        st.subheader("Temuan")
        for f in k["temuan"]:
            st.markdown(f"**{f['id']} · {f['judul']}** (v{f['versi']}) — {f['keparahan']}")
            st.write(f"TC: {f['test_case']} · Dampak: {f['dampak']} · Acuan: {f['acuan']}")
            if (f.get("demonstrasi_dampak") or {}).get("berhasil"):
                d = f["demonstrasi_dampak"]
                st.info(f"C1 ⊕ C2 = P1 ⊕ P2 → P2 “{d['p2_diketahui']}” diketahui → P1 dipulihkan “{d['p1_dipulihkan']}”")
        st.subheader("Pemeriksa rumusan")
        for c in k["pemeriksaan_rumusan"]:
            (st.success if c["diterima"] else st.error)(c["teks"])
            for m in c["masalah"]:
                st.caption(f"✗ '{m['kutipan']}': {m['alasan']}. Saran: " + " / ".join(c["saran"]))
    st.subheader("Kalkulator CVSS 3.1")
    vec = st.text_input("Vektor", "AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    try:
        r = cvss.score(vec)
        st.markdown(f"Base score **{r['base_score']} ({r['severity']})**")
        st.table([{"Langkah": a, "Perhitungan": b, "Hasil": str(c)} for a, b, c in r["langkah"]])
    except Exception as e:  # noqa: BLE001
        st.error(str(e))
    st.subheader("Laporan (7 bagian)")
    penguji = st.text_input("Nama penguji", (prep or {}).get("ruang_lingkup", {}).get("penguji", ""))
    if st.button("Buat laporan PDF + DOCX + uk3_hasil_uji.json"):
        from uk3_pengujian.report.build import report
        with st.spinner("menyusun laporan…"):
            report(pid, rid, penguji=penguji or None)
    for name, mime in (("Laporan_Hasil_Pengujian.pdf", "application/pdf"),
                       ("Laporan_Hasil_Pengujian.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
                       ("uk3_hasil_uji.json", "application/json"), ("lembar_hasil.csv", "text/csv")):
        f = rdir / name
        if f.exists():
            st.download_button(f"Unduh {name}", f.read_bytes(), file_name=name, mime=mime, key=name)
    from uk3_pengujian.evidence import verify
    v = verify(rdir)
    (st.success if v["ok"] else st.error)(f"Manifest bukti: {v['kesimpulan']} ({v['diperiksa']} berkas)")

# ------------------------------------------------------------------------------------------- Lab
else:
    st.header("Lab Keacakan")
    st.info("Five basic tests hanya untuk studi kasus; hasil resmi memakai NIST STS lengkap. "
            "Lolos uji keacakan adalah syarat perlu, bukan syarat cukup.")
    from uk3_pengujian.rng import generators as G
    from uk3_pengujian.rng import lab, multiseq, sts
    src = st.radio("Sumber barisan", ["tempel teks", "unggah berkas", "bangkitkan"], horizontal=True)
    bits = None
    if src == "tempel teks":
        bits = G.from_text(st.text_area("Barisan bit", "1100000000101001001110110111110111011010011111110100010011101000111011101001000110100000010110001011"))
    elif src == "unggah berkas":
        up = st.file_uploader("Berkas ASCII (0/1) atau biner")
        fmt = st.selectbox("Format", ["auto", "ascii", "biner"])
        if up:
            bits = G.from_file(up.getvalue(), fmt)
    else:
        c1, c2, c3 = st.columns(3)
        kind = c1.selectbox("Generator", list(G.SOURCES), format_func=lambda k: G.SOURCES[k])
        n = c2.number_input("n bit", 10, 2_000_000, 100 if kind == "python" else 100_000)
        kw = {}
        if kind in ("prng", "python", "bias"):
            kw["seed"] = c3.number_input("seed", 0, 10**9, 13 if kind == "python" else 2026)
        if kind == "bias":
            kw["p"] = st.slider("P(1)", 0.0, 1.0, 0.51, 0.01)
        if kind == "lfsr":
            kw["taps"] = tuple(int(x) for x in c3.text_input("tap (pisah koma)", "3,5").split(","))
            kw["state"] = st.text_input("keadaan awal", "01100")
            kw["shift"] = st.selectbox("arah geser", ["right", "left"])
        if kind == "pola":
            kw["pat"] = c3.text_input("pola", "1100")
        bits = G.generate(kind, int(n), **kw)
        st.caption(f"Sumber: {G.SOURCES[kind]} · parameter {kw}")
    if bits is not None and len(bits):
        tabs = st.tabs(["Golomb", "Five basic tests", "SP 800-22", "Banyak barisan", "Panjang barisan", "NIST STS", "Kompleksitas linear"])
        r = lab.run_lab(bits, d=8)
        with tabs[0]:
            g = r["golomb"]
            st.write(f"G1 {'✓' if g['G1']['ok'] else '✗'} n₀ = {g['G1']['n0']}, n₁ = {g['G1']['n1']} · G2 {'✓' if g['G2']['ok'] else '✗'} · "
                     f"G3 {'✓' if g['G3']['ok'] else '✗'} → {g['conclusion']}")
            st.table([{"Panjang": x["length"], "Teramati": x["observed"], "Blok": x["blocks"], "Gap": x["gaps"], "Ideal": round(x["ideal"], 2)}
                      for x in g["G2"]["table"]])
            st.line_chart({"C(τ)": list(g["G3"]["C"].values())}, height=180)
        with tabs[1]:
            d = st.number_input("d autokorelasi", 1, max(1, len(bits) // 2), 8)
            b5 = lab.run_lab(bits, ("basic5",), d=int(d))["basic5"]
            st.table([{"Uji": t["test"], "Statistik": t.get("statistic_name"), "Nilai": None if t.get("statistic") is None else round(t["statistic"], 4),
                       "Kritis α=0,01": None if t.get("critical") is None else round(t["critical"], 4),
                       "p-value": None if t.get("p_value") is None else round(t["p_value"], 4), "Keputusan": t["decision"]} for t in b5["tests"]])
            st.caption(b5["summary"])
        with tabs[2]:
            enforce = st.checkbox("Periksa n minimum", True)
            for t in lab.run_lab(bits, ("sp80022",), enforce_min=enforce)["sp80022"]:
                st.markdown(f"**{t['name']}** — {t['status']}" + (f", p = {t['p_value']:.6f}" if t["p_value"] is not None else f" ({t.get('reason')})"))
                if t["test"] in ("monobit", "block_frequency", "runs") and t["p_value"] is not None:
                    st.table([{"Langkah": a, "Perhitungan": b, "Hasil": c} for a, b, c in t["steps"]])
        with tabs[3]:
            m = st.number_input("m barisan", 10, 1000, 100)
            nn = st.number_input("n bit per barisan", 100, 1_000_000, 10_000)
            gen = st.selectbox("Generator", ["prng", "bias"], key="msgen", format_func=lambda g: G.SOURCES[g])
            if st.button("Analisis m barisan (n & m dikunci sebelum melihat hasil)"):
                seqs = [G.prng(int(nn), 2026 + i) if gen == "prng" else G.biased(int(nn), 0.51, 2026 + i) for i in range(int(m))]
                a = multiseq.analyze(seqs)
                st.session_state["multi"] = a
            a = st.session_state.get("multi")
            if a:
                st.table([{"Uji": t, "Lulus": v["passed"], "Proporsi": round(v["proportion"], 4), "Batas bawah": round(v["low"], 4),
                           "P-value_T": round(v["p_value_T"], 4), "OK": v["ok"]} for t, v in a["tests"].items() if v.get("runnable")])
                for t, v in a["tests"].items():
                    if v.get("runnable"):
                        st.bar_chart({t: v["histogram"]}, height=150)
                st.caption(a["conclusion"] + ". " + a["note"])
        with tabs[4]:
            if st.button("Jalankan eksperimen n = 10⁴, 10⁵, 10⁶ (m = 100)"):
                st.session_state["len"] = multiseq.length_experiment()
            if st.session_state.get("len"):
                st.table(st.session_state["len"]["rows"])
                st.caption(st.session_state["len"]["lesson"])
        with tabs[5]:
            st.write("Pembuat berkas masukan STS & pembaca finalAnalysisReport.txt")
            rep = st.file_uploader("finalAnalysisReport.txt", key="sts")
            if rep:
                pr = sts.parse_report(rep.getvalue().decode(errors="replace"))
                st.write(pr["conclusion"], f"· SHA-256 {pr['sha256'][:16]}…")
                st.table([{"Uji": x["test"], "C1–C10": " ".join(map(str, x["C"])), "P-VALUE": x["p_value_T"], "PROPORTION": f"{x['passed']}/{x['total']}",
                           "*": "*" if x["uniformity_flag"] or x["proportion_flag"] else ""} for x in pr["rows"]])
        with tabs[6]:
            lc = r["linear"]
            st.write(f"L = {lc['L']} (dari {lc['n_dianalisis']} bit; barisan acak ≈ n/2). Polinomial koneksi C(x) = {lc['polynomial']}; "
                     f"karakteristik {lc['characteristic']}. Cukup {lc['bits_needed']} bit untuk memulihkan LFSR (Berlekamp–Massey).")
        if st.button("Simpan hasil lab"):
            st.success(f"tersimpan: {lab.save(r)}")
