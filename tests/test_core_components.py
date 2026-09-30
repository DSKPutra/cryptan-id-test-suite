"""Kriteria penerimaan: sifat komponen algoritma standar = acuan materi."""
import pytest

from core import aes, boolean as B, keccak, stats


@pytest.fixture(scope="module")
def aes_sbox():
    return B.sbox_profile(aes.SBOX, 8, 8)


def test_aes_sbox_nonlinearity_112(aes_sbox):
    assert aes_sbox["nonlinearity"] == 112


def test_aes_sbox_differential_uniformity_4(aes_sbox):
    assert aes_sbox["differential_uniformity"] == 4


def test_aes_sbox_algebraic_degree_7(aes_sbox):
    assert aes_sbox["max_coordinate_degree"] == 7


def test_aes_sbox_no_fixed_points_and_bijective(aes_sbox):
    assert aes_sbox["fixed_points"] == 0 and aes_sbox["bijective"]
    assert aes.SBOX[0x00] == 0x63 and aes.SBOX[0x53] == 0xED   # FIPS 197 Gambar 7


def test_aes_mixcolumns_branch_number_5_mds():
    bn = B.branch_number(aes.MIX_MATRIX)
    assert bn["mds"] and bn["branch_number"] == 5 and bn["empirical_upper_bound"] == 5


def test_keccak_chi_du_8_degree_2():
    p = B.sbox_profile(keccak.CHI_SBOX, 5, 5)
    assert p["differential_uniformity"] == 8
    assert p["max_coordinate_degree"] == 2


def test_non_mds_matrix_detected():
    assert not B.is_mds([[1, 1, 0, 0], [0, 1, 1, 0], [0, 0, 1, 1], [1, 0, 0, 1]])


def test_weak_sbox_flagged_by_metrics():
    ident = list(range(256))
    p = B.sbox_profile(ident, 8, 8)
    assert p["nonlinearity"] == 0 and p["differential_uniformity"] == 256 and p["max_coordinate_degree"] == 1


def test_berlekamp_massey_lfsr():
    # LFSR x^4 + x + 1 (periode 15) → kompleksitas linear 4
    s = [1, 0, 0, 0]
    for i in range(60):
        s.append(s[i] ^ s[i + 1])
    assert B.berlekamp_massey(s) == 4


def test_boolean_majority_profile():
    maj = [bin(x).count("1") >= 2 for x in range(8)]
    p = B.boolean_profile([int(v) for v in maj], 3)
    assert p["algebraic_degree"] == 2 and p["nonlinearity"] == 2 and p["balanced"]


def test_sp80022_threshold_96_of_100():
    t = stats.sp80022_proportion_threshold(100)
    assert abs(t - 0.9601) < 1e-4


def test_sp80022_monobit_example():
    # SP 800-22 §2.1.8: ε = 1011010101, P-value = 0.527089
    r = stats.monobit_test([int(c) for c in "1011010101"])
    assert abs(r["p_value"] - 0.527089) < 1e-6


def test_sp80022_runs_example():
    # SP 800-22 §2.3.8: ε = 1001101011, P-value = 0.147232
    r = stats.runs_test([int(c) for c in "1001101011"])
    assert abs(r["p_value"] - 0.147232) < 1e-6


def test_igamc_known_value():
    # Q(a=1, x) = e^{-x}
    import math
    assert abs(stats.igamc(1, 2.0) - math.exp(-2)) < 1e-12
    assert abs(stats.igamc(3, 0.5) - 0.9856123) < 1e-6
