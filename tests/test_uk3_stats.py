"""UK-3 — angka contoh dari materi dijadikan unit test (Bagian 6 prompt UK-3).

Sumber: 'UK 3 Melakukan Pengujian Produk Kriptografi – 9 JP' (slide 25–41) dan
'Materi UK3_Pengujian Keacakan' (slide 13–26)."""
import math

import numpy as np
import pytest

from uk3_pengujian import stats
from uk3_pengujian.rng import basic5, generators, golomb, lfsr, multiseq, sp80022, sts

SEQ100 = ("1100000000" "1010010011" "1011011111" "0111011010" "0111111101"
          "0001001110" "1000111011" "1010010001" "1010000001" "0110001011")


# --------------------------------------------------------------- SP 800-22 (slide 29–34)
def test_monobit_document_example():
    r = sp80022.monobit("1011010101", enforce_min=False)
    assert r["statistic"]["S"] == 2
    assert round(r["statistic"]["s_obs"], 3) == 0.632
    assert round(r["p_value"], 3) == 0.527 and r["status"] == "LULUS"


def test_monobit_n_minimum_enforced():
    r = sp80022.monobit("1011010101")
    assert r["status"] == "tidak dapat dijalankan" and r["p_value"] is None


def test_monobit_60_40_and_70_30():
    a = sp80022.monobit("1" * 60 + "0" * 40)
    b = sp80022.monobit("1" * 70 + "0" * 30)
    assert round(a["p_value"], 4) == 0.0455 and a["status"] == "LULUS"
    assert round(b["p_value"], 6) == 0.000063 and b["status"] == "GAGAL"


def test_runs_document_example():
    r = sp80022.runs("1001101011", enforce_min=False)
    assert r["statistic"]["pi"] == 0.6 and r["statistic"]["V"] == 7
    assert round(r["p_value"], 3) == 0.147
    assert r["steps"][2][1] == "1 · 00 · 11 · 0 · 1 · 0 · 11"


def test_block_frequency_document_example():
    r = sp80022.block_frequency("0110011010", M=3, enforce_min=False)
    assert round(r["statistic"]["chi2"], 6) == 1.0 and round(r["p_value"], 3) == 0.801


def test_sp80022_reference_examples():
    """Contoh ε 100 bit dari SP 800-22 Rev.1a (§2.1.8, §2.3.8, §2.13.8, §2.2.8, §2.12.8, §2.11.8, §2.4.8)."""
    eps = ("1100100100001111110110101010001000100001011010001100001000110100110001001100011001100010100010111000")
    assert round(sp80022.monobit(eps)["p_value"], 6) == 0.109599
    assert round(sp80022.runs(eps)["p_value"], 6) == 0.500798
    assert [round(x, 6) for x in sp80022.cusum(eps)["p_values"]] == [0.219194, 0.114866]
    assert round(sp80022.block_frequency(eps, M=10)["p_value"], 6) == 0.706438
    assert round(sp80022.approximate_entropy(eps, m=2, enforce_min=False)["p_value"], 6) == 0.235301
    assert [round(x, 6) for x in sp80022.serial("0011011101", m=3, enforce_min=False)["p_values"]] == [0.808792, 0.670320]
    lr = ("11001100000101010110110001001100111000000000001001001101010100010001001111010110100000001101011111001100"
          "111001101101100010110010")
    assert round(sp80022.longest_run(lr)["p_value"], 6) == 0.180609


def test_proportion_m1000_and_m100():
    iv = stats.proportion_interval(1000)
    assert round(iv["half_width"], 4) == 0.0094
    assert (round(iv["low"], 4), round(iv["high"], 4)) == (0.9806, 0.9994)
    assert stats.proportion_decision(988, 1000)["ok"] and not stats.proportion_decision(975, 1000)["ok"]
    assert round(stats.proportion_interval(100)["low"], 4) == 0.9602


def test_uniformity_example():
    u = stats.uniformity(counts=[12, 8, 9, 11, 10, 10, 9, 11, 12, 8])
    assert round(u["chi2"], 4) == 2.0 and round(u["p_value_T"], 3) == 0.991 and u["ok"]


# --------------------------------------------------------------- analisis data (slide 26, 36–38)
def test_welch_t_pin_example():
    r = stats.welch_t(mean1=1200, sd1=40, n1=1000, mean2=1215, sd2=42, n2=1000)
    assert round(r["var_n1"], 3) == 1.6 and round(r["var_n2"], 3) == 1.764
    assert round(r["t"], 2) == 8.18 and r["leak"]


def test_confidence_interval_example():
    data = [0.82, 0.85, 0.80, 0.84, 0.83, 0.86, 0.81, 0.84, 0.83, 0.82]
    ci = stats.confidence_interval(data)
    assert round(ci["mean"], 3) == 0.830 and round(ci["sd"], 4) == 0.0183
    assert round(ci["t_quantile"], 3) == 2.262 and round(ci["half_width"], 3) == 0.013
    assert (round(ci["low"], 3), round(ci["high"], 3)) == (0.817, 0.843)


def test_min_entropy_example():
    assert round(stats.shannon_entropy([0.6, 0.4]), 3) == 0.971
    h = stats.min_entropy(0.6)
    assert round(h, 3) == 0.737 and stats.raw_bits_needed(256, h) == 348


def test_avalanche_z():
    assert round(stats.avalanche_z(128.11, 256, 10000)["z"], 2) == pytest.approx(1.38, abs=0.03)
    assert stats.avalanche_z(63.43, 128, 128)["ok"]


# --------------------------------------------------------------- five basic tests & Golomb (materi keacakan)
def test_seq100_reproducible_from_seed13():
    s = generators.python_randint(100, 13)
    assert "".join(map(str, s)) == SEQ100
    assert int((s == 0).sum()) == 49 and int(s.sum()) == 51


def test_five_basic_tests_seq100():
    r = {t["test"]: t for t in basic5.run_all(SEQ100, d=8)["tests"]}
    assert round(r["frekuensi"]["statistic"], 4) == 0.0400
    assert round(r["serial"]["statistic"], 4) == 0.0711
    assert round(r["poker"]["statistic"], 4) == 0.4000 and r["poker"]["m"] == 2 and r["poker"]["k"] == 50
    assert round(r["runs"]["statistic"], 4) == 0.3374 and r["runs"]["k"] == 2
    assert round(r["autokorelasi"]["statistic"], 4) == 0.4170 and r["autokorelasi"]["A"] == 48
    assert [round(r[k]["critical"], 4) for k in ("frekuensi", "serial", "poker", "runs", "autokorelasi")] == \
        [6.6349, 9.2103, 11.3449, 9.2103, 2.5758]
    assert [round(r[k]["p_value"], 4) for k in ("frekuensi", "serial", "poker", "runs", "autokorelasi")] == \
        [0.8415, 0.9651, 0.9402, 0.8448, 0.6767]
    assert all(t["decision"] == "Terima H₀" for t in r.values())


def test_five_basic_tests_pattern_1100():
    r = {t["test"]: t for t in basic5.run_all("1100" * 25, d=8)["tests"]}
    assert round(r["poker"]["statistic"], 4) == 50.0
    assert round(r["runs"]["statistic"], 4) == 136.1448
    assert round(r["autokorelasi"]["statistic"], 4) == -9.5917
    assert round(r["serial"]["statistic"], 4) == 0.0303
    assert {k for k, v in r.items() if v["decision"] == "Tolak H₀"} == {"poker", "runs", "autokorelasi"}


def test_golomb_seq100():
    g = golomb.check(SEQ100, max_tau=10)
    assert g["G1"] == {"n0": 49, "n1": 51, "diff": 2, "ok": False}
    assert (g["G2"]["runs"], g["G2"]["blocks"], g["G2"]["gaps"]) == (48, 24, 24) and not g["G2"]["ok"]
    t = {row["length"]: (row["observed"], row["blocks"], row["gaps"]) for row in g["G2"]["table"]}
    assert t[1] == (25, 12, 13) and t[2] == (9, 4, 5) and t[3] == (9, 5, 4)
    assert [round(v, 2) for v in g["G3"]["C"].values()] == [0.04, 0.08, 0.12, 0.04, -0.08, -0.16, 0.08, -0.04, 0.08, 0.16]


def test_m_sequence_period15():
    s = lfsr.recurrence((1, 1, 0, 0), (0, 0, 0, 1), 15)             # x⁴ + x + 1
    assert "".join(map(str, s)) == "000100110101111"
    g = golomb.check(s)
    assert g["G1"]["ok"] and g["G2"]["ok"] and g["G3"]["ok"] and g["all_ok"]
    assert all(round(v, 6) == round(-1 / 15, 6) for v in g["G3"]["C"].values())
    bm = lfsr.berlekamp_massey(s)
    assert bm["L"] == 4 and bm["characteristic"] == "x^4 + x + 1" and bm["bits_needed"] == 8
    long = lfsr.recurrence((1, 1, 0, 0), (0, 0, 0, 1), 60)
    assert lfsr.predict(long[:8], 60) == long                      # 2L bit cukup untuk memulihkan seluruh keluaran


def test_lfsr_exercise_slide18():
    out = lfsr.lfsr((3, 5), "01100", 31, "right")
    assert "".join(map(str, out)) == "0011011101010000100101100111110"
    assert lfsr.period(lfsr.lfsr((3, 5), "01100", 93, "right")) == 31


# --------------------------------------------------------------- banyak barisan & STS
def test_multiseq_good_vs_biased():
    good = multiseq.analyze([generators.prng(10_000, i) for i in range(20)], ("monobit", "runs"))
    bad = multiseq.analyze([generators.biased(100_000, 0.51, i) for i in range(20)], ("monobit",))
    assert good["tests"]["monobit"]["prop_ok"] and good["tests"]["runs"]["prop_ok"]
    assert not bad["tests"]["monobit"]["prop_ok"] and bad["conclusion"] == "Ditemukan indikasi ketidakacakan"


def test_sts_report_roundtrip(tmp_path):
    a = multiseq.analyze([generators.prng(10_000, i) for i in range(100)])
    parsed = sts.parse_report(sts.render_report(a))
    assert parsed["tests"] == 3 and parsed["rows"][0]["test"] == "Frequency"
    assert parsed["rows"][0]["C"] == a["tests"]["monobit"]["histogram"]
    flagged = sts.parse_report("  0   0   0   0   0   0   0   0   0 100  0.000000 *   90/100  *  Frequency\n")
    assert flagged["flagged"] == ["Frequency"] and flagged["rows"][0]["proportion"] == 0.9
    info = sts.write_input([generators.prng(1000, 1), generators.prng(1000, 2)], tmp_path / "data.txt")
    assert (tmp_path / "data.txt").read_text().count("1") + (tmp_path / "data.txt").read_text().count("0") == 2000
    assert info["petunjuk"][0] == "./assess 1000"


def test_no_uint8_overflow():
    """Catatan pengajar: bit uint8 yang dijumlah langsung akan overflow; fungsi kita mengonversi ke int64."""
    bits = np.ones(1000, dtype=np.uint8)
    assert int(sp80022.to_bits(bits).sum()) == 1000
    assert sp80022.monobit(np.concatenate([bits[:500], np.zeros(500, np.uint8)]))["p_value"] == pytest.approx(1.0)
