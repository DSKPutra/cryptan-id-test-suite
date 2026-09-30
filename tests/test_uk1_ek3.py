"""EK 3 — Memilih metode pengujian (KUK 3.1, 3.2) + keterlacakan + E2E."""
import json
import re

import pytest

from uk1_metode import pipeline, report
from conftest import ALL, profile_of


# ---------------------------------------------------------------- KUK 3.1
@pytest.mark.parametrize("alg", list(ALL))
def test_kuk_3_1_mandatory_selected_and_rejections_explained(result, alg):
    sel = result(alg)["selection"]
    ids = {s["method_id"] for s in sel["selected"]}
    assert {"M-KAT", "M-KEYSIZE"} <= ids
    assert all(s["reason"] for s in sel["selected"] + sel["rejected"])
    assert all(s["reason"].startswith("Ditolak") for s in sel["rejected"])


def test_kuk_3_1_grey_box_rejects_white_box_and_missing_tools(result):
    rej = {s["method_id"]: s["reason"] for s in result("AES-128")["selection"]["rejected"]}
    assert "white-box" in rej["M-CODEREVIEW"]
    assert "Alat tidak tersedia" in rej["M-TVLA"]


def test_kuk_3_1_weak_component_drives_selection(result):
    sel = {s["method_id"]: s for s in result("AES-128")["selection"]["selected"]}
    assert "C-IMPL-TBL" in sel["M-TIMING"]["weak_targets"] and sel["M-TIMING"]["score"] == 3.0
    assert sel["M-DIFF"]["variant"] == "tereduksi"


def test_kuk_3_1_black_box_selects_fewer_methods():
    p = profile_of("ECDSA-P256")
    p["tester"]["access"] = "black_box"
    r = pipeline.run(p, quick=True)
    ids = {s["method_id"] for s in r["selection"]["selected"]}
    assert "M-NONCE" not in ids and "M-TIMING" not in ids and "M-KAT" in ids


# ---------------------------------------------------------------- KUK 3.2
def test_kuk_3_2_sp80022_parameters(result):
    prm = result("ChaCha20")["parameters"]["M-SP80022"]
    assert prm["sequences_m"] == 100 and prm["bits_per_sequence_n"] == 10 ** 6
    assert prm["alpha"] == 0.01 and abs(prm["proportion_threshold"] - 0.96015) < 1e-5
    assert prm["min_pass_sequences"] == 97            # 96/100 = 0,96 < 0,9601 (NIST STS: "≈ 96")
    assert prm["uniformity_p_value_T_min"] == 0.0001 and len(prm["tests"]) == 15


def test_kuk_3_2_every_selected_method_has_measurable_parameters(result):
    for alg in ALL:
        r = result(alg)
        for s in r["selection"]["selected"]:
            prm = r["parameters"][s["method_id"]]
            assert len(prm) >= 3, s["method_id"]


def test_kuk_3_2_kat_and_timing_parameters(result):
    prm = result("RSA-OAEP-2048")["parameters"]
    assert prm["M-KAT"]["pass_criterion"].startswith("100%") and prm["M-KAT"]["vector_count"] == 12
    assert prm["M-TIMING"]["threshold_abs_t"] == 4.5


# ---------------------------------------------------------------- Keterlacakan
def test_traceability_ids_and_columns(result):
    tr = result("SHA3-256")["traceability"]
    assert tr and all(re.fullmatch(r"[KI]-\d{2}", t["id"]) for t in tr)
    assert {"K", "I"} == {t["id"][0] for t in tr}
    assert all(t["requirement"] and t["method_id"] and t["reference"] and t["pass_criteria"] for t in tr)


# ---------------------------------------------------------------- E2E
def test_end_to_end_outputs(tmp_path, result):
    r = result("SHA3-256")
    files = report.write_all(r, tmp_path, docx=True)
    for k in ("json", "md", "csv_map", "csv_trace"):
        assert files[k].exists() and files[k].stat().st_size > 0
    data = json.loads(files["json"].read_text())
    assert data["schema"] == "cryptan.uk1.penetapan_metode.v1"
    assert data["handoff_uk2"]["methods"]
    md = files["md"].read_text()
    for n in range(1, 9):
        assert re.search(rf"^## {n}\. ", md, re.M), f"Bab {n} hilang"
    assert "HASIL UJI LANGSUNG" in md and "HASIL LITERATUR" in md


def test_cli_runs(tmp_path):
    from uk1_metode.__main__ import main
    assert main(["--profile", "config/profiles/sha3_256.yaml", "--out", str(tmp_path), "--quick", "--no-docx"]) == 0
    idx = json.loads((tmp_path / "index.json").read_text())
    assert idx["algorithms"][0]["id"] == "SHA3-256"
