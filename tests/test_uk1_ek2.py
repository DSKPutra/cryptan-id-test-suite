"""EK 2 — Menelaah kesesuaian metode pengujian terhadap desain (KUK 2.1–2.3)."""
import copy
import math

import pytest

from uk1_metode import component_analysis as ca, decompose, mapping, resources
from conftest import ALL, profile_of


# ---------------------------------------------------------------- KUK 2.1
@pytest.mark.parametrize("alg", list(ALL))
def test_kuk_2_1_decomposition_and_analysis(result, alg):
    r = result(alg)
    comps = {c["id"]: c for c in r["components"]}
    assert len(comps) >= 9
    for c in comps.values():
        assert c["status"] in ca.RANK and c["findings"]
        assert all(f["source"] in (ca.DIRECT, ca.LIT, ca.CLAIM) for f in c["findings"])
    assert comps["C-CONF"]["status"] == "OK"


def test_kuk_2_1_aes_reference_values_and_table_flag(result):
    comps = {c["id"]: c for c in result("AES-128")["components"]}
    m = comps["C-SBOX"]["metrics"]
    assert (m["nonlinearity"], m["differential_uniformity"], m["max_coordinate_degree"]) == (112, 4, 7)
    assert comps["C-DIFF"]["metrics"]["branch_number"]["branch_number"] == 5
    assert comps["C-IMPL-TBL"]["flag_weak"] is True


def test_kuk_2_1_weak_component_flagged_when_below_reference():
    p = profile_of("AES-128")
    p = copy.deepcopy(p)
    p["algorithm"]["reference_values"]["nonlinearity"] = 120      # acuan fiktif di atas NL AES
    out = ca._aes(p, True)
    assert any(f["status"] == "BERPOTENSI_LEMAH" and f["check"].startswith("Nonlinearitas") for f in out["C-SBOX"]["findings"])


def test_kuk_2_1_sha3_chi_and_padding(result):
    comps = {c["id"]: c for c in result("SHA3-256")["components"]}
    assert comps["C-CHI"]["metrics"]["differential_uniformity"] == 8
    assert comps["C-CHI"]["metrics"]["max_coordinate_degree"] == 2
    assert comps["C-PAD"]["status"] == "OK"
    assert comps["C-SPONGE"]["metrics"]["collision_bits"] == 128


def test_kuk_2_1_pkc_and_dss_checks(result):
    rsa = {c["id"]: c for c in result("RSA-OAEP-2048")["components"]}
    assert rsa["C-MOD"]["metrics"]["security_bits"] == 112
    assert rsa["C-PKV"]["status"] == "OK" and rsa["C-OAEP"]["findings"][0]["status"] == "OK"
    ecd = {c["id"]: c for c in result("ECDSA-P256")["components"]}
    assert ecd["C-CURVE"]["status"] == "OK"
    assert ecd["C-SIG"]["metrics"]["malleable_accepted"] is True        # (r, n−s) → PERHATIAN
    assert ecd["C-NONCE"]["metrics"]["unique_r"] == ecd["C-NONCE"]["metrics"]["samples"]


def test_kuk_2_1_stream_linear_complexity(result):
    c = {c["id"]: c for c in result("ChaCha20")["components"]}["C-KS-OUT"]
    assert abs(c["metrics"]["linear_complexity"] - c["metrics"]["lc_sample_bits"] / 2) <= 3


# ---------------------------------------------------------------- KUK 2.2
def test_kuk_2_2_matrix_three_layers_and_levels(result):
    r = result("AES-128")
    layers = {m["layer"] for m in r["matrix"]}
    assert layers == set(mapping.LAYERS)
    assert {m["level"] for m in r["matrix"]} == set(mapping.LEVELS)
    row = next(m for m in r["matrix"] if m["component_id"] == "C-IMPL-TBL" and m["method_id"] == "M-TIMING")
    assert "A-BC-09" in row["attacks"] and "ISO-17825" in row["standards"]


def test_kuk_2_2_access_adapted_to_tester_level():
    p = profile_of("RSA-OAEP-2048")
    white = {m["id"]: m for m in mapping.methods_for(p)}["M-CODEREVIEW"]
    assert not mapping.access_ok(white, p)                          # grey box
    p["tester"]["access"] = "white_box"
    assert mapping.access_ok(white, p)
    p["tester"]["access"] = "black_box"
    grey = {m["id"]: m for m in mapping.methods_for(p)}["M-ORACLE"]
    assert not mapping.access_ok(grey, p)


# ---------------------------------------------------------------- KUK 2.3
def _m(**cost):
    return {"id": "M-X", "cost": cost}


def test_kuk_2_3_benchmark_positive_rates(result):
    for alg in ALL:
        b = result(alg)["resources"]["benchmark"]
        assert b["source"] == "HASIL UJI LANGSUNG" and b["ops_per_sec"]["primary"] > 0


def test_kuk_2_3_feasibility_statuses():
    p = profile_of("AES-128")
    bench = {"ops_per_sec": {"primary": 1e4}}
    full = resources.estimate(_m(op="primary", ops_log2=128), p, bench)
    assert full["status"] == resources.TIDAK and full["time_human"].endswith("tahun")
    red = resources.estimate(_m(op="primary", ops_log2=128, reduced={"desc": "r", "ops_log2": 20}), p, bench)
    assert red["status"] == resources.REDUKSI
    ok = resources.estimate(_m(op="primary", bits=100_000_000), p, bench)
    assert ok["status"] == resources.LAYAK and math.isclose(ok["ops_log2"], math.log2(1e8 / 128), rel_tol=1e-3)
    tool = resources.estimate(_m(op="primary", ops_log2=10, tools=["oscilloscope"]), p, bench)
    assert tool["status"] == resources.TIDAK and "oscilloscope" in tool["reason"]


def test_kuk_2_3_time_formula():
    p = profile_of("AES-128")
    e = resources.estimate(_m(op="primary", ops_log2=30), p, {"ops_per_sec": {"primary": 2 ** 10}})
    assert math.isclose(e["seconds"], 2 ** 30 / (2 ** 10 * 8), rel_tol=1e-9)    # 8 core


def test_kuk_2_3_capacity():
    c = resources.capacity(profile_of("SHA3-256"))
    assert c["person_hours"] == 3 * 10 * 8
