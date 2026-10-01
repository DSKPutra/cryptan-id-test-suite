"""GUI Streamlit — Daftar Algoritma yang Diuji (Cryptan.ID Test Suite, UK-1 KUK 1.1).

  streamlit run algo_catalog/app.py

Tab: Link · File · Dropdown. Panel kanan: daftar terpilih (hapus, tambah, ubah
panjang kunci). Deteksi otomatis wajib dikonfirmasi sebelum masuk daftar akhir.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from algo_catalog import catalog, extract, link, output, picker  # noqa: E402
from algo_catalog.normalize import Matcher, best  # noqa: E402
from algo_catalog.schema import PRIMITIVES  # noqa: E402
from algo_catalog.selection import Selection, warnings_for  # noqa: E402

st.set_page_config(page_title="Cryptan.ID — Daftar Algoritma Uji", page_icon="🔐", layout="wide")


@st.cache_resource
def _catalog():
    E = catalog.load()
    return E, Matcher(E)


E, M = _catalog()
if "sel" not in st.session_state:
    st.session_state.sel = Selection(E)
    st.session_state.cands = []          # deteksi menunggu konfirmasi
sel: Selection = st.session_state.sel

st.title("🔐 Daftar Algoritma yang Diuji")
st.caption(f"Cryptan.ID Test Suite · modul algo_catalog · UK-1 KUK 1.1 · katalog {len(E)} entri / "
           f"{catalog.count_combinations(E)['total']} kombinasi")

left, right = st.columns([3, 2], gap="large")


def _queue(dets, typ, ref):
    for d in dets:
        st.session_state.cands.append({**d, "input_type": typ, "ref": ref})


with left:
    t_link, t_file, t_drop = st.tabs(["🔗 Link", "📄 File", "🗂️ Dropdown"])
    with t_link:
        urls = st.text_area("URL halaman web / PDF (satu per baris)", placeholder="https://pages.nist.gov/ACVP/")
        if st.button("Unduh & deteksi", key="go_link"):
            for u in [x.strip() for x in urls.splitlines() if x.strip()]:
                try:
                    with st.spinner(f"Mengunduh {u} (menghormati robots.txt)…"):
                        page = link.fetch(u)
                    dets = best(M.find(page["text"]))
                    _queue(dets, "link", u)
                    st.success(f"{u}: {len(dets)} deteksi ({page['kind']})")
                except link.FetchError as e:
                    st.error(str(e))
    with t_file:
        ups = st.file_uploader("Unggah berkas", accept_multiple_files=True,
                               type=[x.lstrip(".") for x in sorted(extract.SUPPORTED)])
        kb = st.number_input("Panjang kunci default untuk alias tanpa kunci (0 = cari di konteks)", 0, 16384, 0, step=64)
        if st.button("Deteksi", key="go_file") and ups:
            for f in ups:
                try:
                    text = extract.bytes_to_text(f.name, f.getvalue())
                    dets = best(M.find(text, key_bits=kb or None))
                    _queue(dets, "file", f.name)
                    st.success(f"{f.name}: {len(dets)} deteksi")
                except extract.ExtractError as e:
                    st.error(f"{f.name}: {e}")
    with t_drop:
        tree = catalog.tree(E)
        q = st.text_input("Cari (nama algoritma / varian / ID)", "").lower()
        prim = st.selectbox("Primitif", list(tree), format_func=lambda p: PRIMITIVES[p])
        fams = [f for f, vs in tree[prim].items() if not q or q in f.lower() or any(q in v["variant"].lower() or any(q in c.lower() for c in v["combos"]) for v in vs)]
        fam = st.selectbox("Algoritma", fams) if fams else None
        if fam:
            vs = tree[prim][fam]
            all_v = st.checkbox("Pilih semua varian")
            vnames = [v["variant"] for v in vs]
            chosen_v = vnames if all_v else st.multiselect("Varian / mode / kurva / parameter set", vnames)
            combos = []
            for v in vs:
                if v["variant"] in chosen_v:
                    combos += v["combos"]
            picks = st.multiselect("Panjang kunci / kombinasi", combos, default=combos if all_v else [])
            if st.button("Tambahkan ke daftar", key="go_drop") and picks:
                ids = sel.add_pick([picker.parse_pick(c, E)[0] for c in picks], f"{fam}: {', '.join(chosen_v)}")
                st.success(f"Ditambahkan: {', '.join(ids)}")

    if st.session_state.cands:
        st.subheader("Konfirmasi hasil deteksi otomatis")
        st.caption("Centang kombinasi yang benar; skor keyakinan & potongan bukti ditampilkan.")
        rows = []
        for i, d in enumerate(st.session_state.cands):
            rows.append({"terima": d["confidence"] >= 0.6, "ID kanonik": d["id"], "keyakinan": d["confidence"],
                         "kunci dari": d["key_from"], "cocok": d["match"], "sumber": f"{d['input_type']}: {d['ref']}",
                         "bukti": d["evidence"]})
        edited = st.data_editor(rows, hide_index=True, width="stretch", key="cand_editor",
                                disabled=["ID kanonik", "keyakinan", "kunci dari", "cocok", "sumber", "bukti"])
        c1, c2 = st.columns(2)
        if c1.button("✔ Konfirmasi pilihan"):
            for d, r in zip(st.session_state.cands, edited):
                if r["terima"]:
                    sel.add_detections([d], d["input_type"], d["ref"], auto_confirm_at=0.0)
            st.session_state.cands = []
            st.rerun()
        if c2.button("✖ Buang semua kandidat"):
            st.session_state.cands = []
            st.rerun()

with right:
    final = sel.final()
    st.subheader(f"Daftar terpilih ({len(final)})")
    if final:
        st.dataframe([{"ID": r["id"], "Primitif": PRIMITIVES[r["primitive"]], "Kunci": r["key_bits"] or "—",
                       "Strength": r["security_strength_bits"], "Status": r["status_nist"],
                       "Sumber": ", ".join(sorted({i["type"] for i in r["inputs"]}))} for r in final],
                     hide_index=True, width="stretch")
        with st.expander("Sunting daftar"):
            rm = st.multiselect("Hapus", [r["id"] for r in final])
            if st.button("Hapus terpilih") and rm:
                sel.remove(rm)
                st.rerun()
            multi = [r for r in final if len(sel.entries[r["entry_id"]].key_bits) > 1]
            if multi:
                tgt = st.selectbox("Ubah panjang kunci", [r["id"] for r in multi])
                ent = sel.entries[next(r["entry_id"] for r in multi if r["id"] == tgt)]
                nk = st.selectbox("Kunci baru", ent.key_bits)
                if st.button("Ubah kunci"):
                    sel.change_key(tgt, nk)
                    st.rerun()
        warns = [w for r in final for w in warnings_for(r)]
        if warns:
            st.subheader("⚠️ Peringatan")
            for w in warns:
                (st.error if w["level"] == "TINGGI" else st.warning if w["level"] == "SEDANG" else st.info)(w["message"])
        if st.button("💾 Simpan keluaran (outputs/algo_catalog) & tautkan ke product_profile.yaml", type="primary"):
            res = output.write_all(final, ROOT / "outputs" / "algo_catalog", pending=sel.pending())
            st.success("Tersimpan: " + ", ".join(Path(f).name for f in res["files"].values() if f))
            for k in ("yaml", "csv", "md", "xlsx"):
                f = res["files"].get(k)
                if f:
                    st.download_button(f"Unduh {Path(f).name}", Path(f).read_bytes(), file_name=Path(f).name, key=f"dl_{k}")
    else:
        st.info("Belum ada algoritma. Gunakan tab Link, File, atau Dropdown.")
