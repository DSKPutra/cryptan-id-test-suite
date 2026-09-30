"""EK 1 — Mengidentifikasi informasi yang relevan (KUK 1.1–1.3)."""
import pytest

from uk1_metode import attack_kb, profile, standards_kb
from conftest import ALL, ROOT, profile_of


# ---------------------------------------------------------------- KUK 1.1
def test_kuk_1_1_product_profile_loads_all_five_algorithms():
    ps = profile.load_profiles(ROOT / "config" / "product_profile.yaml")
    assert [p["algorithm"]["id"] for p in ps] == list(ALL)
    assert {p["algorithm"]["primitive"] for p in ps} == set(profile.PRIMITIVES)


def test_kuk_1_1_extends_inherits_shared_sections():
    p = profile_of("AES-128")
    assert p["implementation"]["platform"] == "linux-x86_64-library"
    assert p["tester"]["access"] == "grey_box"
    assert "algorithms" not in p


def test_kuk_1_1_incomplete_profile_rejected(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("product: {name: X}\nalgorithm: {id: X, primitive: quantum}\n")
    with pytest.raises(profile.ProfileError) as e:
        profile.load_profiles(f)
    msg = str(e.value)
    assert "algorithm.primitive" in msg and "resources" in msg and "tester.access" in msg


def test_kuk_1_1_summary_has_product_profile_fields():
    s = profile.summarize(profile_of("RSA-OAEP-2048"))
    assert s["algorithm"]["primitive_label"].startswith("Kriptografi kunci publik")
    assert s["completeness"]["status"] == "LENGKAP"


# ---------------------------------------------------------------- KUK 1.2
def test_kuk_1_2_filter_by_primitive_and_platform():
    ids = {a["id"] for a in attack_kb.filter_for(profile_of("AES-128"))}
    assert {"A-BC-02", "A-BC-09", "A-X-01", "A-L-02"} <= ids      # biclique, cache-timing x86, Spectre, C
    assert "A-BC-10" not in ids                                     # power/EM hanya embedded/HSM
    cross = {"A-P-11", "A-SC-07"}                                   # RNG lemah & counter wrap: lintas primitif
    assert not any(i.startswith(("A-SC", "A-H-", "A-P-", "A-D-")) for i in ids - cross)
    assert "A-BC-08" not in ids                                     # padding oracle hanya mode CBC


def test_kuk_1_2_filter_by_structure_and_language():
    ids = {a["id"] for a in attack_kb.filter_for(profile_of("ChaCha20"))}
    assert "A-SC-02" in ids and "A-SC-04" not in ids                # ARX, bukan LFSR
    ids = {a["id"] for a in attack_kb.filter_for(profile_of("ECDSA-P256"))}
    assert "A-D-06" not in ids                                      # CVE Java; produk C


def test_kuk_1_2_entries_have_model_complexity_refs_status():
    for a in attack_kb.load_all():
        assert a["category"] in attack_kb.CATEGORIES
        assert a["refs"] and a["model"] and a["status"]
        assert set(a["complexity"]) == {"time_log2", "data_log2", "memory_log2"}
    s = attack_kb.summary(attack_kb.filter_for(profile_of("SHA3-256")))
    assert all(s["by_category"][c] for c in ("desain", "bahasa", "platform"))


# ---------------------------------------------------------------- KUK 1.3
@pytest.mark.parametrize("prim,must", [
    ("block_cipher", {"FIPS-197", "ISO-18033-3", "SP-800-38A", "SP-800-22"}),
    ("stream_cipher", {"ISO-18033-4", "SP-800-22"}),
    ("hash", {"FIPS-202", "ISO-10118-3", "SP-800-107"}),
    ("pkc", {"ISO-18033-2", "SP-800-56B", "ISO-18032"}),
    ("dss", {"FIPS-186-5", "SP-800-186", "ISO-14888-3"}),
])
def test_kuk_1_3_references_per_primitive(prim, must):
    ids = {r["id"] for r in standards_kb.references_for(prim)}
    assert must <= ids
    assert {"ISO-18367", "ISO-19790", "ISO-24759", "ISO-17825", "SP-800-57"} <= ids


def test_kuk_1_3_all_mapped_ids_exist_in_catalog():
    kb = standards_kb.load()
    for lst in list(kb["by_primitive"].values()) + [kb["common"]]:
        for item in lst:
            assert item["id"] in kb["catalog"]
