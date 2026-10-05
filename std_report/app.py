"""GUI Streamlit — Daftar Algoritme Standar + Hasil Semua Uji + Export to PDF (Cryptan.ID Test Suite).

  streamlit run std_report/app.py

Daftar algoritme dengan filter (sumber, primitif, status), tombol "Jalankan semua uji" dengan progres,
tabel hasil, dan tombol Export to PDF / HTML / XLSX. Laporan selalu dibuat dari results.json."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from std_report import catalog, runner  # noqa: E402
from std_report.report.model import BODY_ORDER, Model, load  # noqa: E402
from std_report.report.template import THEME  # noqa: E402

st.set_page_config(page_title="Cryptan.ID — Algoritme Standar & Hasil Uji", page_icon="🔐", layout="wide")
ident = THEME["identity"]
st.markdown(f"<div style='background:{THEME['colors']['accent']};color:#fff;padding:8px 14px;border-radius:6px;"
            f"display:flex;justify-content:space-between'><b>{THEME['title']}</b>"
            f"<span style='background:#C62828;padding:0 8px;border-radius:3px'>{ident['klasifikasi']}</span></div>",
            unsafe_allow_html=True)
st.caption(f"{THEME['subtitle']} · {ident['instansi']} · {ident['copyright']}")

RESULTS = runner.OUT / "results.json"


@st.cache_data
def _catalog():
    return catalog.build()


def _results():
    return load(RESULTS) if RESULTS.exists() else None


cat = _catalog()
res = _results()
bodies = cat["bodies"]
prims = cat["primitives"]

with st.sidebar:
    st.subheader("Filter")
    f_src = st.multiselect("Sumber standar", BODY_ORDER, default=BODY_ORDER, format_func=lambda b: bodies[b])
    f_prim = st.multiselect("Primitif", list(prims), default=list(prims), format_func=lambda p: prims[p])
    overall = ["LULUS_SEMUA", "LULUS_SEBAGIAN", "TEMUAN", "TIDAK_DAPAT_DIUJI"]
    f_stat = st.multiselect("Status uji", overall, default=overall, disabled=res is None)
    st.divider()
    st.subheader("Identitas laporan")
    penyusun = st.text_input("Nama penyusun / pengunduh dokumen", placeholder="wajib diisi sebelum export")
    st.text_input("Instansi", ident["instansi"], disabled=True)
    st.text_input("Klasifikasi", ident["klasifikasi"], disabled=True)

tab_list, tab_run, tab_res, tab_exp = st.tabs(["Daftar algoritme", "Jalankan uji", "Hasil uji", "Export"])

with tab_list:
    rows = [r for r in cat["rows"] if set(r["source_body"]) & set(f_src) and r["primitive"] in f_prim]
    st.write(f"**{len(rows)}** kombinasi algoritme × varian × panjang kunci — " +
             ", ".join(f"{bodies[b]}: {sum(1 for r in rows if b in r['source_body'])}" for b in BODY_ORDER))
    status_of = {a["id"]: a["overall"] for a in res["algorithms"]} if res else {}
    st.dataframe([{"ID": r["id"], "Primitif": prims[r["primitive"]], "Keluarga": r["family"], "Varian": r["variant"],
                   "Kunci (bit)": r["key_bits"], "Kekuatan (bit)": str(r["security_strength_bits"]), "Status NIST": str(r["status_nist"]),
                   "Sumber": ", ".join(bodies[b] for b in r["source_body"]), "Dokumen": ", ".join(r["source_doc"]),
                   "Status uji": status_of.get(r["id"], "belum dijalankan")}
                  for r in rows if not res or status_of.get(r["id"]) in f_stat or r["id"] not in status_of],
                 use_container_width=True, hide_index=True, height=520)

with tab_run:
    mode = st.radio("Mode", ["ringan", "full"], horizontal=True,
                    help="ringan: < 5 menit, uji statistik indikatif · full: 100 × 10⁶ bit, 10.000 sampel avalanche (lama)")
    if st.button("Jalankan semua uji", type="primary"):
        bar = st.progress(0.0, text="menyiapkan…")

        def prog(i, n, rid):
            bar.progress(i / n, text=f"[{i}/{n}] {rid}")
        r = runner.run(mode, None, f_src if len(f_src) < 3 else None, f_prim if len(f_prim) < len(prims) else None, progress=prog)
        bar.progress(1.0, text=f"selesai dalam {r['environment']['duration_s']} s")
        if r["schema_errors"]:
            st.error(f"results.json tidak lolos skema: {r['schema_errors'][:3]}")
        else:
            st.success("results.json diperbarui dan lolos JSON Schema.")
        st.rerun()
    if res:
        st.info(f"Hasil terakhir: {res['generated_at']} · mode {res['mode']} · seed {res['seed']} · "
                f"durasi {res['environment']['duration_s']} s")

with tab_res:
    if not res:
        st.warning("Belum ada results.json — jalankan uji dulu.")
    else:
        m = Model(res, f_src, f_prim)
        algs = [a for a in m.algs if a["overall"] in f_stat]
        k = m.kpi()
        cols = st.columns(5)
        for c, (lbl, v) in zip(cols, [("Terdaftar", k["terdaftar"]), ("Diuji", k["diuji"]), ("Lulus semua", k["lulus_semua"]),
                                      ("Punya temuan", k["punya_temuan"]), ("Tidak dapat diuji", k["tidak_dapat_diuji"])]):
            c.metric(lbl, v)
        st.subheader("Matriks hasil uji")
        st.dataframe([{"Algoritme": a["id"], **{t["plugin"]: t["status"] for t in a["tests"]}, "Keseluruhan": a["overall"]}
                      for a in algs], use_container_width=True, hide_index=True, height=420)
        pick = st.selectbox("Rincian algoritme", [a["id"] for a in algs])
        if pick:
            a = next(x for x in algs if x["id"] == pick)
            st.dataframe([{"Uji": t["plugin"], "Nama": t["name"], "Status": t["status"], "Hasil aktual": t.get("actual") or t.get("reason", ""),
                           "Kriteria": t.get("criteria", ""), "Durasi (s)": t.get("duration_s"), "Evidence": t.get("evidence_id")}
                          for t in a["tests"]], use_container_width=True, hide_index=True)
        st.subheader("Temuan utama")
        for x in m.top_findings():
            st.markdown(f"- {x}")

with tab_exp:
    if not res:
        st.warning("Belum ada results.json — jalankan uji dulu.")
    else:
        ringkas = st.checkbox("Ringkas (tanpa Bab 5 hasil rinci)")
        only_tested = st.checkbox("Hanya algoritme yang dapat diuji")
        kw = dict(sources=f_src if len(f_src) < 3 else None, primitives=f_prim if len(f_prim) < len(prims) else None,
                  only_tested=only_tested, penyusun=penyusun.strip() or None)
        if not penyusun.strip():
            st.warning("Isi nama penyusun / pengunduh dokumen di panel kiri sebelum export.")
        c1, c2, c3 = st.columns(3)
        if c1.button("Export to PDF", type="primary", disabled=not penyusun.strip()):
            from std_report.report.builder import build_pdf
            with st.spinner("menyusun PDF…"):
                p = build_pdf(res, ringkas=ringkas, **kw)
            st.session_state["pdf"] = (p.name, p.read_bytes())
        if c2.button("Buat HTML", disabled=not penyusun.strip()):
            from std_report.report.export import build_html
            p = build_html(res, ringkas=ringkas, **kw)
            st.session_state["html"] = (p.name, p.read_bytes())
        if c3.button("Buat XLSX", disabled=not penyusun.strip()):
            from std_report.report.export import build_xlsx
            p = build_xlsx(res, **kw)
            st.session_state["xlsx"] = (p.name, p.read_bytes())
        mimes = {"pdf": "application/pdf", "html": "text/html",
                 "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
        for key, mime in mimes.items():
            if key in st.session_state:
                name, data = st.session_state[key]
                st.download_button(f"Unduh {name}", data, file_name=name, mime=mime, key=f"dl-{key}")
        st.caption(f"Klasifikasi {ident['klasifikasi']}: jangan unggah laporan ke layanan publik.")
