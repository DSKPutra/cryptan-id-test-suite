"""UK-3 — uji alur (Bagian 6 prompt UK-3): SecureFile v1.0/v1.1, checklist mengunci Jalankan, KAT digagalkan → TERBLOKIR,
manifest mendeteksi perubahan 1 byte, pemeriksa rumusan, CVSS, run ulang beralasan, dan cakupan KUK 1.1–3.3."""
import copy
import json

import pytest

from conftest import ROOT
from uk3_pengujian import GAGAL, LULUS, MEMENUHI, TERBLOKIR
from uk3_pengujian import products as P
from uk3_pengujian.conclude import cvss, wording
from uk3_pengujian.conclude.decide import conclude
from uk3_pengujian.evidence import EvidenceMismatch, append, verify
from uk3_pengujian.prep import documents
from uk3_pengujian.report.build import report
from uk3_pengujian.run import planner, runner


@pytest.fixture(scope="module")
def sf(tmp_path_factory):
    out = tmp_path_factory.mktemp("uk3")
    documents.prepare("securefile", out_root=out)
    rec = runner.run("securefile", out_root=out)
    return out, rec


def _st(rec, ver):
    return {t["id"]: t["status"] for t in rec["versi"][ver]["tc"]}


# ---------------------------------------------------------------- KUK 2.2: SecureFile v1.0 vs v1.1
def test_securefile_v10_all_tc03_07_pass(sf):
    st = _st(sf[1], "1.0")
    assert all(st[t] == LULUS for t in ("TC-03", "TC-04", "TC-05", "TC-06", "TC-07"))
    assert all(v == LULUS for v in st.values())


def test_securefile_v11_only_tc06_fails(sf):
    st = _st(sf[1], "1.1")
    assert [t for t, s in st.items() if s != LULUS] == ["TC-06"] and st["TC-06"] == GAGAL
    row = next(t for t in sf[1]["versi"]["1.1"]["tc"] if t["id"] == "TC-06")
    assert "salt unik 1/20" in row["actual"]


def test_log_first_line_is_environment_and_columns(sf):
    out, rec = sf
    d = runner.run_dir("securefile", rec["run_id"], out)
    lines = (d / "log_securefile_v1.1.txt").read_text().splitlines()
    assert lines[0].startswith("# ") and "Python" in lines[0] and "alat terverifikasi" in lines[0]
    tc06 = next(x for x in lines if x.startswith("TC-06"))
    cols = tc06.split(" | ")
    assert len(cols) == 7 and cols[5] == GAGAL and cols[6].endswith("TC-06.json")
    assert cols[2].startswith("v1.1 · securefile_v11 ") and P.versions("securefile")["1.1"]["sha256"][:16] in cols[2]


def test_lembar_hasil_side_by_side_and_reports(sf):
    out, rec = sf
    d = runner.run_dir("securefile", rec["run_id"], out)
    lembar = (d / "lembar_hasil.csv").read_text().splitlines()
    assert lembar[0].split(";")[6:8] == ["v1.0", "v1.1"]
    assert next(r for r in lembar if r.startswith("TC-06;")).split(";")[6:8] == [LULUS, GAGAL]
    files = report("securefile", rec["run_id"], out, penguji="Penguji Pytest")
    assert set(files) == {"json", "pdf", "docx"}
    from pypdf import PdfReader
    pdf = PdfReader(str(d / "Laporan_Hasil_Pengujian.pdf"))
    import re
    text = re.sub(r"\s+", " ", "\n".join(p.extract_text() for p in pdf.pages))
    for sec in ("1 Identitas produk", "2 Lingkungan", "3 Metode", "4 Rekap", "5 Temuan", "6 Bukti", "7 Kesimpulan"):
        assert sec in text, sec
    assert f"Halaman 2 dari {len(pdf.pages)}" in pdf.pages[1].extract_text()
    hj = json.loads((d / "uk3_hasil_uji.json").read_text())
    assert hj["versi"]["1.1"]["keseluruhan"] == "Tidak Memenuhi" and hj["temuan"][0]["cvss_score"] == 6.2
    pub = runner.uk3_dir("securefile", out)
    for f in ("uk3_hasil_uji.json", "lembar_hasil.csv", "evidence_manifest.json", "Laporan_Hasil_Pengujian.pdf",
              "Laporan_Hasil_Pengujian.docx", "log_securefile_v1.0.txt"):
        assert (pub / f).exists(), f
    from docx import Document
    doc = Document(str(d / "Laporan_Hasil_Pengujian.docx"))
    assert any("7  Kesimpulan" in p.text for p in doc.paragraphs)
    assert "NUMPAGES" in doc.sections[0].footer._element.xml


def test_conclusion_categories_and_finding(sf):
    out, rec = sf
    k = conclude("securefile", rec["run_id"], out)
    v10, v11 = k["per_versi"]["1.0"], k["per_versi"]["1.1"]
    assert v11["sasaran"]["S4"]["kategori"] == "Tidak Memenuhi" and v11["keseluruhan"] == "Tidak Memenuhi"
    assert v10["sasaran"]["S4"]["kategori"] == "Memenuhi dengan Catatan"        # N = 20 → batasan tercatat
    assert v10["sasaran"]["S1"]["kategori"] == MEMENUHI
    f = k["temuan"][0]
    assert f["id"] == "F-01" and f["judul"] == "Nonce GCM berulang" and f["cvss"]["base_score"] == 6.2
    demo = f["demonstrasi_dampak"]
    assert demo["nonce_sama"] and demo["c1_xor_c2_sama_dengan_p1_xor_p2"] and demo["p1_dipulihkan"] == "GAJI DIREKTUR: 90 JUTA"
    assert all(c["diterima"] for c in k["pemeriksaan_rumusan"])


def test_analysis_consistent(sf):
    from uk3_pengujian.analysis.analyze import analyze
    out, rec = sf
    a = analyze("securefile", rec["run_id"], out)
    assert a["konsisten"] and {"KAT", "Uji negatif", "Keunikan nonce/salt", "Kinerja"} <= {m["metode"] for m in a["metode"]}
    assert all(g["seragam"] for g in a["galat_seragam"])


# ---------------------------------------------------------------- KUK 1.1: checklist mengunci Jalankan
def test_checklist_no_locks_run(tmp_path):
    r = documents.prepare("securefile", {"izin_jadwal": (False, "izin belum ditandatangani", "Pemilik produk", "2026-10-09")}, out_root=tmp_path)
    assert not r["checklist"]["siap"]
    item = next(i for i in r["checklist"]["items"] if i["butir"] == "izin_jadwal")
    assert item["status"] == "Tidak" and item["penanggung_jawab"] == "Pemilik produk" and item["tanggal_ulang"] == "2026-10-09"
    with pytest.raises(runner.NotReady):
        runner.run("securefile", out_root=tmp_path)


def test_out_of_scope_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(P, "in_scope", lambda pid: False)
    with pytest.raises(PermissionError):
        runner.run("securefile", out_root=tmp_path)


# ---------------------------------------------------------------- KAT digagalkan → TERBLOKIR, tidak boleh Memenuhi
def test_failed_kat_blocks_dependents(tmp_path):
    documents.prepare("securefile", out_root=tmp_path)
    sc = copy.deepcopy(documents.load_scenario("securefile"))
    for t in sc["test_cases"]:
        if t["id"] == "TC-01":
            t["expected"]["nilai"] = "00" * 64                  # sengaja salah
    rec = runner.run("securefile", ["1.0"], "SF-SMOKE,TC-01,TC-02,TC-03,TC-04,TC-07", out_root=tmp_path, scenario=sc)
    st = _st(rec, "1.0")
    assert st["TC-01"] == GAGAL and st["TC-03"] == TERBLOKIR and st["TC-04"] == TERBLOKIR and st["TC-07"] == TERBLOKIR
    k = conclude("securefile", rec["run_id"], tmp_path)
    assert k["per_versi"]["1.0"]["keseluruhan"] != MEMENUHI
    assert k["per_versi"]["1.0"]["sasaran"]["S2"]["kategori"] == "Inkonklusif"
    assert k["per_versi"]["1.0"]["sasaran"]["S3"]["kategori"] == "Inkonklusif"


# ---------------------------------------------------------------- integritas bukti & run ulang
def test_manifest_detects_one_byte_change(sf, tmp_path):
    import shutil
    out, rec = sf
    d = tmp_path / "copy"
    shutil.copytree(runner.run_dir("securefile", rec["run_id"], out), d)
    assert verify(d)["ok"]
    f = d / "evidence" / "v1.1" / "TC-06.json"
    b = bytearray(f.read_bytes())
    b[10] ^= 1
    f.write_bytes(bytes(b))
    v = verify(d)
    assert not v["ok"] and v["berubah"][0]["path"] == "evidence/v1.1/TC-06.json"
    new = d / "catatan.txt"
    new.write_text("x")
    with pytest.raises(EvidenceMismatch):
        append(d, [new])


def test_rerun_requires_reason_and_deviation_recorded(tmp_path):
    documents.prepare("securefile", out_root=tmp_path)
    runner.run("securefile", ["1.0"], "SF-SMOKE", out_root=tmp_path)
    with pytest.raises(runner.RerunWithoutReason):
        runner.run("securefile", ["1.0"], "SF-SMOKE", out_root=tmp_path)
    rec = runner.run("securefile", ["1.0"], "SF-SMOKE,TC-01,TC-02,TC-03,TC-06", alasan="uji ulang: N diperbesar",
                     params={"TC-06": {"N": 25}}, out_root=tmp_path)
    assert rec["deviasi"] == [{"tc": "TC-06", "parameter": "N", "terkunci": 20, "dipakai": 25, "alasan": "uji ulang: N diperbesar"}]
    idx = runner.runs_index("securefile", tmp_path)
    assert len(idx) == 2 and idx[1]["alasan"] == "uji ulang: N diperbesar"
    tc06 = next(t for t in rec["versi"]["1.0"]["tc"] if t["id"] == "TC-06")
    assert "20/25" not in tc06["actual"] and "/25" in tc06["actual"]


# ---------------------------------------------------------------- KUK 3.2: rumusan & CVSS
def test_wording_checker_rejects_produk_aman():
    assert not wording.check("Kesimpulan: produk aman digunakan.")["diterima"]
    assert not wording.check("RNG terbukti acak")["diterima"]
    assert wording.check("Pada versi 1.0, dengan metode KAT, 13 dari 13 TC lulus.")["diterima"]
    assert wording.check("Tidak ditemukan bukti ketidakacakan")["diterima"]


def test_cvss_material_vector():
    r = cvss.score("AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    assert round(r["iss"], 2) == 0.56 and round(r["impact"], 3) == 3.595 and round(r["exploitability"], 3) == 2.515
    assert r["base_score"] == 6.2 and r["severity"] == "Medium"
    assert cvss.score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")["base_score"] == 9.8
    assert cvss.score("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")["base_score"] == 10.0


# ---------------------------------------------------------------- KUK 2.1: planner (termasuk UK-2)
def test_planner_stages_and_negative_share():
    p = planner.plan("securefile")
    assert [s["tahap"] for s in p["tahapan"]] == [1, 2, 3, 4, 5, 6]
    assert p["tahapan"][0]["tc"] == ["SF-SMOKE"] and set(p["tahapan"][1]["tc"]) == {"TC-01", "TC-02"}
    assert p["negatif"] >= p["jumlah"] / 3 and not p["peringatan"]
    assert len(p["sembilan_langkah"]) == 9
    small = planner.plan("securefile", "SF-SMOKE,TC-01,TC-03")
    assert small["peringatan"] and "sepertiga" in small["peringatan"][0]


@pytest.mark.skipif(not (ROOT / "outputs" / "uk2" / "uk2_skenario.json").exists(), reason="keluaran UK-2 belum ada")
def test_planner_reads_uk2_scenario():
    p = planner.plan("securelib")
    assert p["jumlah"] == 92 and p["tc"][0]["id"] == "SL-SMOKE"
    assert all(t["tahap"] in range(1, 7) for t in p["tc"])


def test_pustaka_tc_library():
    out = documents.prepare.__globals__["OUT"]  # noqa: F841 — pastikan modul termuat
    p = planner.plan("pustaka")
    ids = {t["id"] for t in p["tc"]}
    assert {"TC-BC-01", "TC-AE-01", "TC-SC-01", "TC-H-01a", "TC-H-01b", "TC-PK-01", "TC-PK-03", "TC-PK-04", "TC-DS-01", "TC-DS-02",
            "E2", "E3", "E4", "TC-AE-02"} <= ids


def test_pustaka_run(tmp_path):
    documents.prepare("pustaka", out_root=tmp_path)
    rec = runner.run("pustaka", out_root=tmp_path)
    st = next(iter(rec["versi"].values()))
    bad = {t["id"]: t["actual"] for t in st["tc"] if t["status"] != LULUS and t["id"] != "TC-WT-01"}
    assert not bad, bad
    ds02 = next(t for t in st["tc"] if t["id"] == "TC-DS-02")
    assert ds02["actual"] == "(r, n − s) diterima" and ds02["batasan"]


# ---------------------------------------------------------------- cakupan KUK & kebersihan keluaran
def test_every_kuk_has_page_function_test():
    app = (ROOT / "uk3_pengujian" / "app.py").read_text()
    mapping = {
        "1.1": ("1 Siapkan", "uk3_pengujian.prep.documents", "checklist", "test_checklist_no_locks_run"),
        "1.2": ("1 Siapkan", "uk3_pengujian.prep.inventory", "verify_tools", "test_log_first_line_is_environment_and_columns"),
        "2.1": ("2 Jalankan", "uk3_pengujian.run.planner", "plan", "test_planner_stages_and_negative_share"),
        "2.2": ("2 Jalankan", "uk3_pengujian.run.runner", "run", "test_securefile_v11_only_tc06_fails"),
        "3.1": ("3 Olah data", "uk3_pengujian.analysis.analyze", "analyze", "test_analysis_consistent"),
        "3.2": ("4 Simpulkan", "uk3_pengujian.conclude.decide", "conclude", "test_conclusion_categories_and_finding"),
        "3.3": ("4 Simpulkan & laporkan", "uk3_pengujian.report.build", "report", "test_lembar_hasil_side_by_side_and_reports"),
    }
    import importlib
    for kuk, (page, mod, fn, test) in mapping.items():
        assert page in app, kuk
        assert callable(getattr(importlib.import_module(mod), fn)), kuk
        assert test in globals(), kuk
        assert f"KUK {kuk}" in importlib.import_module(mod).__doc__ or kuk in importlib.import_module(mod).__doc__, kuk


def test_no_absolute_paths_in_outputs(sf):
    out, rec = sf
    d = runner.run_dir("securefile", rec["run_id"], out)
    for f in ("run.json", "evidence_manifest.json"):
        assert "/Users/" not in (d / f).read_text() and str(ROOT) not in (d / f).read_text()
