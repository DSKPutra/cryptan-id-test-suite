"""UK-2 — Menyusun Skenario Pengujian (J.61KRP00.013.1): test per KUK 1.1–2.5,
uji reproduksi materi (DS-*, PR-*, U/I/S/A-*, cakupan area 7.2–7.12) & uji verifier."""
import copy
import hashlib
import json
import re
from pathlib import Path

import pytest

from conftest import ROOT
from uk2_skenario import (compiler, context, designer, expected, method_review, param_space, pipeline,
                          testcase, verifier)

S = ROOT / "samples" / "uk2"
PROFILES = {
    "produk": (ROOT / "config" / "product_profile.yaml", ROOT / "outputs" / "uk1"),
    "ecdsa": (S / "ecdsa_p256_token" / "product_profile.yaml", S / "ecdsa_p256_token" / "uk1_stub.json"),
    "tls": (S / "tls13_gateway" / "product_profile.yaml", S / "tls13_gateway" / "uk1_stub.json"),
    "hsm": (S / "hsm_x_sl3" / "product_profile.yaml", S / "hsm_x_sl3" / "uk1_stub.json"),
}
_runs = {}


@pytest.fixture(scope="session")
def run(tmp_path_factory):
    def get(name):
        if name not in _runs:
            prof, uk1 = PROFILES[name]
            out = tmp_path_factory.mktemp(f"uk2_{name}")
            _runs[name] = (pipeline.run(str(prof), str(uk1), out, docx=(name == "hsm")), out)
        return _runs[name]
    return get


def stages(name):
    prof, uk1 = PROFILES[name]
    ctx = context.load(str(prof), str(uk1))
    rv = method_review.review(ctx)
    ps = param_space.build(ctx)
    ds = designer.design(ctx, rv, ps)
    return ctx, rv, ps, ds


# ===================================================================== KUK 1.1
def test_kuk_1_1_methods_reviewed_against_four_needs(run):
    R = run("produk")[0]["result"]
    mr = R["method_review"]
    assert mr["summary"]["methods"] >= 20
    for m in mr["methods"]:
        assert set(m["needs"]) == {"N1_jenis_algoritma", "N2_desain_implementasi", "N3_tren_serangan", "N4_best_practice"}
        assert m["layer"] in "KSI" and m["tier"] in ("Komponen", "Integrasi", "Sistem")


def test_kuk_1_1_cells_and_empty_cells_reported(run):
    mr = run("produk")[0]["result"]["method_review"]
    assert set(mr["cells"]) == {"block", "stream", "hash", "pke", "signature"}
    assert all(len(c) == 9 for c in mr["cells"].values())             # 3 tingkat × 3 lapis
    assert mr["empty_cells"] and all(e["action"].startswith("diisi") for e in mr["empty_cells"])


def test_kuk_1_1_irrelevant_method_detected():
    ctx, *_ = stages("produk")
    ctx.uk1 = copy.deepcopy(ctx.uk1)
    ctx.uk1[0]["selection"]["selected"].append({"method_id": "M-TVLA", "name": "TVLA", "layer": "Implementasi & sistem", "level": "Sistem"})
    rv = method_review.review(ctx)
    tvla = next(m for m in rv["methods"] if m["method_id"] == "M-TVLA")
    assert not tvla["relevant"] and "desain implementasi" in tvla["verdict"]      # produk tanpa side_channel_lab
    assert tvla in rv["irrelevant"]


# ===================================================================== KUK 1.2
def test_kuk_1_2_five_classes_and_status(run):
    ps = run("produk")[0]["result"]["param_space"]
    classes = {p["class"] for c in ps["categories"].values() for p in c["params"]}
    assert classes == set(param_space.CLASSES)
    assert {p["status"] for c in ps["categories"].values() for p in c["params"]} == {"Tetap", "Variabel"}


def test_kuk_1_2_boundary_values_sha256():
    vals = [v["value"] for v in param_space._msg_lengths(64, 8, None)]
    assert {0, 1, 55, 56, 63, 64, 65} <= set(vals)                       # 0, b−L−1, b−L, b−1, b, b+1
    sponge = [v["value"] for v in param_space._msg_lengths(136, 0, 1000)]
    assert {135, 136, 137, 1000, 1001} <= set(sponge)
    assert next(v for v in param_space._msg_lengths(136, 0, 1000) if v["value"] == 1001)["negative"]


def test_kuk_1_2_techniques_and_negatives(run):
    ps = run("produk")[0]["result"]["param_space"]
    tech = {v["technique"] for c in ps["categories"].values() for p in c["params"] for v in p["values"]}
    assert {"EP", "BVA", "DEG", "BIT", "NEG"} <= tech
    keylen = next(p for p in ps["categories"]["block"]["params"] if p["id"] == "BC-KEY-LEN")
    assert any(v["value"] == 0 and v["negative"] for v in keylen["values"])
    assert all(v["in_spec"] for v in keylen["values"] if v["value"] in keylen["spec"])


def test_kuk_1_2_pairwise_reduction_and_coverage(run):
    for c in run("produk")[0]["result"]["param_space"]["categories"].values():
        pw = c["pairwise"]
        assert pw["all_pairs_covered"]
        assert pw["pairwise_combinations"] <= max(pw["full_combinations"], 1)
    hashpw = run("produk")[0]["result"]["param_space"]["categories"]["hash"]["pairwise"]
    assert hashpw["full_combinations"] > 10 ** 6 and hashpw["pairwise_combinations"] < 500


def test_kuk_1_2_ipog_small():
    p = {"a": ["1", "2", "3"], "b": ["x", "y"], "c": ["p", "q"], "d": ["m", "n"]}
    t = param_space.pairwise(p)
    assert param_space.covers_all_pairs(t, p) and len(t) < 3 * 2 * 2 * 2 and len(t) >= 6


# ===================================================================== KUK 2.1
def test_kuk_2_1_matrix_layers_tiers(run):
    R = run("produk")[0]["result"]
    for g, m in R["design"]["matrix"].items():
        if g == "cross":
            continue
        assert set(m) == {"Komponen", "Integrasi", "Sistem"} and all(set(v) == set("KSI") for v in m.values())
    assert any(s["filled_from_template"] for s in R["scenarios"])


def test_kuk_2_1_cross_algorithm_scenarios(run):
    R = run("produk")[0]["result"]
    ids = {t["id"] for t in R["test_cases"]}
    assert {"XA-K-01", "XA-S-01", "XA-S-02", "XA-I-01", "XA-S-03"} <= ids          # rantai, siklus kunci, operasional, PQC
    assert R["design"]["cross"]["chain"][0].startswith("RNG")


def test_kuk_2_1_features_exclude_inapplicable(run):
    exc = {e["id"]: e["reason"] for e in run("produk")[0]["result"]["design"]["excluded"]}
    assert "power_glitch" in exc["DS-I-03"] and "pdf_signing" in exc["DS-K-06"]


@pytest.mark.parametrize("name,example", [("ecdsa", "ecdsa_p256_token"), ("tls", "tls13_gateway"), ("hsm", "hsm_x_sl3")])
def test_kuk_2_1_reproduces_material_examples(run, name, example):
    R = run(name)[0]["result"]
    ex = json.loads(json.dumps(context.load(*map(str, PROFILES[name])).examples[example]))
    want = {t["id"] for t in ex["test_cases"]}
    have = {t["id"]: t for t in R["test_cases"]}
    assert want <= set(have), sorted(want - set(have))
    for t in ex["test_cases"]:                                                   # parameter, prosedur & kriteria dari materi
        tc = have[t["id"]]
        assert tc["material_reference"]["params"] == t["params"] and tc["pass"] == t["pass"]
        if "area" in t:
            assert tc["area"] == t["area"]


def test_kuk_2_1_hsm_area_coverage_matches_material(run):
    R = run("hsm")[0]["result"]
    ex = context.load(*map(str, PROFILES["hsm"])).examples["hsm_x_sl3"]["coverage"]
    got = R["verification"]["iso_coverage"]
    assert set(got) == {f"7.{i}" for i in range(2, 13)}
    for area, tiers in ex.items():
        for tier, ids in tiers.items():
            assert sorted(got[area][tier]) == sorted(ids), (area, tier)


# ===================================================================== KUK 2.2 (aspek kritis)
@pytest.mark.parametrize("name", list(PROFILES))
def test_kuk_2_2_verification_passes(run, name):
    v = run(name)[0]["result"]["verification"]
    assert v["status"] == "LULUS", [f["detail"] for r in v["rules"] for f in r["findings"]]
    assert {r["rule"] for r in v["rules"]} == set("abcdef")


def _faulty(name):
    ctx, rv, ps, ds = stages(name)
    return ctx, rv, copy.deepcopy(ds)


def test_kuk_2_2_detects_unsupported_key_as_positive():
    ctx, rv, ds = _faulty("produk")
    bad = copy.deepcopy(next(r for r in ds["recipes"] if r["id"] == "BC-K-02"))
    bad.update(id="BC-K-99", targets=["AES-128-CTR"], key_bits_used=[192])
    bad["param_values"] = [{"param": "BC-KEY-LEN", "name": "Panjang kunci", "class": "Parameter publik/domain", "value": 192,
                            "technique": "NEG", "in_spec": False, "expect": "diterima/diproses"}]
    ds["recipes"].append(bad)
    v = verifier.verify(ctx, ds, rv)
    rb = next(r for r in v["rules"] if r["rule"] == "b")
    assert rb["status"] == "TEMUAN" and any("192" in f["detail"] for f in rb["findings"])


def test_kuk_2_2_detects_claim_without_security_scenario():
    ctx, rv, ds = _faulty("produk")
    ctx.profile = copy.deepcopy(ctx.profile)
    ctx.profile["uk2"]["claims"].append({"id": "C-PQ", "claim": "Tahan komputer kuantum", "tags": ["quantum_safe"]})
    v = verifier.verify(ctx, ds, rv)
    assert any("C-PQ" in f["detail"] for f in next(r for r in v["rules"] if r["rule"] == "c")["findings"])


def test_kuk_2_2_detects_empty_iso_area():
    ctx, rv, ds = _faulty("hsm")
    ds["recipes"] = [r for r in ds["recipes"] if r.get("area") != "7.6"]
    v = verifier.verify(ctx, ds, rv)
    re_ = next(r for r in v["rules"] if r["rule"] == "e")
    assert re_["status"] == "TEMUAN" and any("7.6" in f["detail"] for f in re_["findings"])


def test_kuk_2_2_low_sl_justifies_physical_area():
    ctx, rv, ds = _faulty("hsm")
    ctx.profile = copy.deepcopy(ctx.profile)
    ctx.profile["uk2"]["iso19790_security_level"] = 1
    ds["recipes"] = [r for r in ds["recipes"] if r.get("area") != "7.7"]
    v = verifier.verify(ctx, ds, rv)
    assert not any("7.7" in f["detail"] for f in next(r for r in v["rules"] if r["rule"] == "e")["findings"])


def test_kuk_2_2_detects_feature_object_method_and_coverage_gaps():
    ctx, rv, ds = _faulty("produk")
    bad = copy.deepcopy(ds["recipes"][0])
    bad.update(id="BC-I-99", requires=["physical_access"], targets=["AES-512-ZZZ"])
    ds["recipes"].append(bad)
    ds["recipes"] = [r for r in ds["recipes"] if "M-LC" not in r.get("methods", []) and "SALSA" not in "".join(r["targets"])]
    ds["recipes"] = [r if "ASCON-AEAD128" not in r["targets"] or r["layer"] != "K" else {**r, "targets": [t for t in r["targets"] if t != "ASCON-AEAD128"]}
                     for r in ds["recipes"]]
    v = {r["rule"]: r for r in verifier.verify(ctx, ds, rv)["rules"]}
    assert v["f"]["status"] == "TEMUAN" and any("physical_access" in f["detail"] for f in v["f"]["findings"])
    assert any("AES-512-ZZZ" in f["detail"] for f in v["f"]["findings"])
    assert v["d"]["status"] == "TEMUAN" and any("M-LC" in f["detail"] for f in v["d"]["findings"])
    assert v["a"]["status"] == "TEMUAN" and any("ASCON-AEAD128" in f["detail"] for f in v["a"]["findings"])


def test_kuk_2_2_report_markdown(run):
    out = run("produk")[1]
    md = (out / "laporan_verifikasi.md").read_text()
    assert "Status keseluruhan: **LULUS**" in md and md.count("| (") == 6


# ===================================================================== KUK 2.3
@pytest.mark.parametrize("name", list(PROFILES))
def test_kuk_2_3_test_case_fields_and_ids(run, name):
    R = run(name)[0]["result"]
    pat = re.compile(r"^[UISA]-[KSI]-\d{2}$" if R["profile"]["testing_model"] == 4 else r"^[A-Z]{2}-[KSI]-\d{2}$")
    for t in R["test_cases"]:
        if t["category"] != "cross":
            assert pat.match(t["id"]), t["id"]
        assert t["steps"][0].startswith("1. ") and len(t["steps"]) >= 2
        for f in ("tier", "layer", "targets", "prerequisites", "pass", "methods", "standards", "priority", "executor", "narrative"):
            assert t[f], (t["id"], f)
        assert t["runner"]["action"] in testcase.RUNNER_ACTIONS
        assert t["narrative"].startswith("Penguji ")
    assert len({t["id"] for t in R["test_cases"]}) == len(R["test_cases"])


def test_kuk_2_3_hsm_governance_executor(run):
    R = run("hsm")[0]["result"]
    t = next(x for x in R["test_cases"] if x["id"] == "S-S-01")
    assert t["tier"] == "Sistem" and t["area"] == "7.7" and "ISO/IEC 17025" in t["executor"]
    assert any("Kriteria masuk" in p for p in t["prerequisites"])


@pytest.mark.parametrize("name", list(PROFILES))
def test_kuk_2_3_json_schema_valid(run, name):
    assert run(name)[0]["result"]["schema_errors"] == []


def test_kuk_2_3_negative_cases_expect_rejection(run):
    for t in run("produk")[0]["result"]["test_cases"]:
        for p in t["parameters"]:
            if not p["in_spec"]:
                assert t["negative"] and p["expect"] == "DITOLAK", t["id"]


# ===================================================================== KUK 2.4
def test_kuk_2_4_deterministic_expected_match_official_vectors(run):
    R, out = run("produk")
    det = [m for m in R["result"]["expected"]["manifest"] if m["status"] == "COCOK_VEKTOR_RESMI"]
    assert len(det) >= 20
    for m in det:
        assert m["summary"]["matched"] == m["summary"]["total"] > 0, m["id"]


def test_kuk_2_4_manifest_sha256_integrity(run):
    R, out = run("produk")
    for m in R["result"]["expected"]["manifest"][:80]:
        data = (out / m["file"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == m["sha256"]


def test_kuk_2_4_sigver_500_and_rfc8448():
    sv = expected.sigver_p256()
    assert sv["total"] >= 500 and sv["matched"] == sv["total"]
    assert sum(v["expect"] == "reject" for v in sv["vectors"]) > sum(v["expect"] == "accept" for v in sv["vectors"])
    rf = expected.rfc8448()
    assert rf["total"] >= 20 and rf["matched"] == rf["total"]


@pytest.mark.parametrize("fn", ["kat_aes_ctr", "kat_chacha_poly", "kat_ecdh384", "kat_x25519", "kat_ed25519", "curve_points"])
def test_kuk_2_4_trusted_library_cross_checks(fn):
    r = getattr(expected, fn)()
    assert r["matched"] == r["total"] > 0


def test_kuk_2_4_uncomputable_marked_perlu_verifikasi(run):
    man = {m["id"]: m for m in run("produk")[0]["result"]["expected"]["manifest"]}
    assert man["kat__ML-KEM-768"]["status"] == "PERLU_VERIFIKASI"
    assert man["kat__XTS-AES-256"]["status"] == "PERLU_VERIFIKASI"


def test_kuk_2_4_statistical_criteria():
    st = expected.statistical("avalanche_sp80022", {"category": "block"})
    assert abs(st["sp800_22"]["proportion_min"] - 0.96015) < 1e-5 and st["sp800_22"]["uniformity_p_value_T_min"] == 0.0001
    assert st["avalanche"]["mean_hw"] == 64 and abs(st["avalanche"]["sigma_hw"] - 128 ** 0.5 / 2) < 1e-9
    assert expected.IMPL["tvla"]["tvla_abs_t_max"] == 4.5


# ===================================================================== KUK 2.5
def test_kuk_2_5_outputs_and_chapters(run):
    out = run("hsm")[1]
    for f in ("uk2_skenario.json", "UK2_Dokumen_Skenario_Pengujian.md", "UK2_Dokumen_Skenario_Pengujian.docx", "test_cases.csv",
              "test_cases.xlsx", "matriks_keterlacakan.csv", "laporan_verifikasi.md", "expected/MANIFEST.json"):
        assert (out / f).exists(), f
    md = (out / "UK2_Dokumen_Skenario_Pengujian.md").read_text()
    for n in range(1, 10):
        assert re.search(rf"^## {n}\. ", md, re.M), n
    assert "Tata Kelola Pengujian" in md                                   # model 4 tingkat


def test_kuk_2_5_outcome_map_categories(run):
    for name in ("ecdsa", "tls", "hsm"):
        om = run(name)[0]["result"]["outcome_map"]
        assert {o["outcome"] for o in om} <= set(testcase.OUTCOMES)
        assert any(o["source"].startswith("materi") for o in om)          # tabel pemetaan materi direproduksi
    om = run("produk")[0]["result"]["outcome_map"]
    assert any("PRESENT-80" in o["condition"] and o["outcome"] == "Tidak Memenuhi" for o in om)


def test_kuk_2_5_traceability_chain(run):
    tr = run("produk")[0]["result"]["traceability"]
    assert tr and all(r["scenario"].startswith("SCN-") and r["test_case"] and r["method"] for r in tr)
    assert any(r["requirement_id"].startswith("C-") for r in tr) and any(":K-" in r["requirement_id"] for r in tr)


def test_cli_accepts_uk1_json_path(tmp_path):
    from uk2_skenario.__main__ import main
    rc = main(["--profile", "samples/uk2/ecdsa_p256_token/product_profile.yaml", "--uk1", "samples/uk2/ecdsa_p256_token/uk1_stub.json",
               "--out", str(tmp_path), "--no-docx"])
    assert rc == 0 and (tmp_path / "uk2_skenario.json").exists()


def test_context_stub_when_uk1_missing():
    ctx = context.load(str(PROFILES["ecdsa"][0]), None)
    assert ctx.uk1[0]["schema"] == "STUB_UK1" and any("STUB_UK1" in n for n in ctx.notes)


@pytest.mark.parametrize("name", list(PROFILES))
def test_no_local_path_leak_in_outputs(run, name):
    out = run(name)[1]
    for f in ("uk2_skenario.json", "laporan_verifikasi.md"):
        assert "/Users/" not in (out / f).read_text() and "/private/" not in (out / f).read_text()
