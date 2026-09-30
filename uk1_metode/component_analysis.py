"""KUK 2.1 (bagian 2) — Telaah komponen berpotensi lemah.

Menghitung LANGSUNG sifat komponen (HASIL UJI LANGSUNG) dan membandingkannya
dengan nilai acuan desain/standar. Status per temuan:
  OK                — memenuhi acuan
  PERHATIAN         — memenuhi acuan desain tetapi memerlukan verifikasi pada
                      produk / ada risiko implementasi (klaim profil)
  BERPOTENSI_LEMAH  — di bawah acuan atau kelemahan terdeteksi
"""
import hashlib
import math
import random
import secrets
import struct
import time

from core import aes, boolean as B, chacha20, ecdsa_p256 as ec, kat, keccak, rsa_oaep, stats
from core.numtheory import SMALL_PRIMES, bytes_to_int, int_to_bytes, miller_rabin

DIRECT = "HASIL UJI LANGSUNG"
LIT = "HASIL LITERATUR"
CLAIM = "KLAIM PROFIL"
RANK = {"OK": 0, "PERHATIAN": 1, "BERPOTENSI_LEMAH": 2}

# SP 800-57 Part 1 Rev.5 Tabel 2 — kekuatan keamanan IFC (RSA)
RSA_STRENGTH = [(15360, 256), (7680, 192), (3072, 128), (2048, 112), (1024, 80)]


def _f(check, value, reference, status, note="", source=DIRECT):
    return {"check": check, "value": value, "reference": reference, "status": status,
            "note": note, "source": source}


def _cmp(check, value, ref, ok, note="", weak="BERPOTENSI_LEMAH"):
    return _f(check, value, ref, "OK" if ok else weak, note)


def _round(x, n=4):
    return round(x, n) if isinstance(x, float) else x


def _rounds_to_diffusion(fn_by_round, max_rounds, in_len, samples, tol=0.02):
    curve = []
    full = None
    for r in range(1, max_rounds + 1):
        av = B.avalanche(lambda x, r=r: fn_by_round(x, r), in_len, samples, seed=r)
        curve.append({"rounds": r, "mean": _round(av["mean"]), "min": _round(av["min"])})
        if full is None and abs(av["mean"] - 0.5) <= tol and av["min"] > 0.3:
            full = r
    return curve, full


def _bits_quick(data: bytes):
    bits = B.bytes_to_bits(data)
    return [stats.monobit_test(bits), stats.runs_test(bits)]


# ======================================================================= AES
def _aes(p, q):
    ref = p["algorithm"].get("reference_values", {})
    notes = p["algorithm"].get("implementation_notes", {})
    rounds = p["algorithm"]["parameters"]["rounds"]
    n = 100 if q else 400
    out = {}

    sp = B.sbox_profile(aes.SBOX, 8, 8)
    out["C-SBOX"] = {"metrics": sp, "findings": [
        _cmp("Nonlinearitas (NL)", sp["nonlinearity"], f"≥ {ref.get('nonlinearity', 112)}", sp["nonlinearity"] >= ref.get("nonlinearity", 112)),
        _cmp("Keseragaman diferensial (DU, DDT maks)", sp["differential_uniformity"], f"≤ {ref.get('differential_uniformity', 4)}",
             sp["differential_uniformity"] <= ref.get("differential_uniformity", 4), f"DP maks = {sp['differential_uniformity']}/256 = 2^{math.log2(sp['differential_uniformity']/256):.0f}"),
        _cmp("|LAT| maks / korelasi linear maks", f"{sp['max_abs_lat']} / {sp['max_correlation']}", "≤ 16 / 2^-3", sp["max_abs_lat"] <= 16),
        _cmp("Derajat aljabar", sp["max_coordinate_degree"], f"≥ {ref.get('algebraic_degree', 7)}", sp["max_coordinate_degree"] >= ref.get("algebraic_degree", 7)),
        _cmp("SAC (deviasi maks dari 0,5)", _round(sp["sac"]["max_deviation"]), "≤ 0,125", sp["sac"]["max_deviation"] <= 0.125, weak="PERHATIAN"),
        _cmp("Titik tetap / titik tetap berlawanan", f"{sp['fixed_points']} / {sp['opposite_fixed_points']}", "0 / 0",
             sp["fixed_points"] == 0 and sp["opposite_fixed_points"] == 0, weak="PERHATIAN"),
        _cmp("Bijektif", sp["bijective"], "True", sp["bijective"]),
    ]}

    bn = B.branch_number(aes.MIX_MATRIX)
    curve, full = _rounds_to_diffusion(lambda x, r: aes.encrypt_block(bytes(16), x, r), 4, 16, n)
    out["C-DIFF"] = {"metrics": {"branch_number": bn, "avalanche_per_round": curve, "rounds_full_diffusion": full}, "findings": [
        _cmp("Branch number MixColumns", bn["branch_number"], f"= {ref.get('branch_number', 5)} (optimal, MDS)", bn["branch_number"] >= ref.get("branch_number", 5)),
        _cmp("MDS (semua submatriks non-singular)", bn["mds"], "True", bn["mds"]),
        _cmp("Ronde menuju difusi penuh (avalanche ≈ 0,5)", full, f"≤ {rounds // 2}", full is not None and full <= rounds // 2),
    ]}

    active = bn["branch_number"] ** 2          # wide trail: 4 ronde ≥ B^2 S-box aktif
    dp_log2 = active * math.log2(sp["differential_uniformity"] / 256)
    lc_log2 = active * math.log2(sp["max_correlation"])
    best_attacked = 7
    margin = (rounds - best_attacked) / rounds
    out["C-ROUND"] = {"metrics": {"rounds": rounds, "min_active_sboxes_4r": active, "dp_trail_4r_log2": dp_log2,
                                  "corr_trail_4r_log2": lc_log2, "best_attacked_rounds_lit": best_attacked}, "findings": [
        _cmp("Batas probabilitas trail diferensial 4 ronde", f"2^{dp_log2:.0f}", "≤ 2^-128", dp_log2 <= -128,
             f"{active} S-box aktif × DP maks (dihitung dari DU & branch number)"),
        _cmp("Batas korelasi trail linear 4 ronde", f"2^{lc_log2:.0f}", "≤ 2^-64", lc_log2 <= -64),
        _f("Margin keamanan ronde (serangan non-biclique terbaik 7/10)", f"{margin:.0%}", "≥ 20%",
           "OK" if margin >= 0.2 else "PERHATIAN", "Lihat A-BC-06", LIT),
    ]}

    rng = random.Random(7)
    key = bytes(rng.getrandbits(8) for _ in range(16))
    kav = B.avalanche(lambda k: aes.encrypt_block(k, bytes(16)), 16, n, seed=11)
    rk0 = aes.key_expansion(key)
    k2 = bytearray(key); k2[0] ^= 1
    rk1 = aes.key_expansion(bytes(k2))
    rk_diff = sum(bin(a ^ b).count("1") for a, b in zip(rk0[-1], rk1[-1])) / 128
    out["C-KS"] = {"metrics": {"key_avalanche": kav, "last_round_key_bitdiff": rk_diff}, "findings": [
        _cmp("Avalanche kunci → ciphertext", _round(kav["mean"]), "0,5 ± 0,02", abs(kav["mean"] - 0.5) <= 0.02),
        _cmp("Difusi key schedule (beda bit round key terakhir, 1 bit kunci)", _round(rk_diff), "≥ 0,3", rk_diff >= 0.3, weak="PERHATIAN"),
        _f("Biclique ronde penuh", "2^126.1", "≥ 2^112", "OK", "Keunggulan 1,9 bit atas brute force (A-BC-02)", LIT),
    ]}

    kb = p["algorithm"]["parameters"]["key_bits"]
    out["C-KEY"] = {"metrics": {"key_bits": kb, "security_bits": kb}, "findings": [
        _cmp("Tingkat keamanan (SP 800-57)", f"{kb} bit", "≥ 128 bit", kb >= 128, weak="PERHATIAN")]}

    ks = aes.ctr_keystream(key, bytes(16), 64 if q else 256)
    rt = _bits_quick(ks)
    nonce_bits = 64 if "64-bit" in str(notes.get("nonce_generation", "")) else 96
    out["C-MODE"] = {"metrics": {"quick_randomness": rt, "random_nonce_bits": nonce_bits,
                                 "birthday_messages_log2": nonce_bits / 2}, "findings": [
        _cmp("Pra-uji keacakan keystream CTR (Monobit, Runs; α = 0,01)",
             ", ".join(f"{t['test']} p={t['p_value']:.3f}" for t in rt), "p ≥ 0,01", all(t["pass"] for t in rt),
             f"{rt[0]['n']} bit; uji penuh SP 800-22 pada metode M-SP80022"),
        _f("Batas tabrakan nonce acak", f"2^{nonce_bits / 2:.0f} pesan", "rekey sebelum 2^32 pesan",
           "PERHATIAN" if nonce_bits <= 64 else "OK",
           f"Nonce acak {nonce_bits}-bit (klaim profil: {notes.get('nonce_generation', '-')})", CLAIM),
    ]}

    tb = bool(notes.get("table_based"))
    out["C-IMPL-TBL"] = {"metrics": {"table_based": tb}, "findings": [
        _f("Implementasi berbasis tabel pada CPU ber-cache", "Ya" if tb else "Tidak", "tanpa lookup bergantung-rahasia (bitsliced/AES-NI)",
           "BERPOTENSI_LEMAH" if tb else "OK", "Rentan cache-timing (A-BC-09); wajib M-TIMING/M-CACHE", CLAIM)]}
    return out


# ======================================================================= ChaCha20
def _chacha(p, q):
    ref = p["algorithm"].get("reference_values", {})
    par = p["algorithm"]["parameters"]
    notes = p["algorithm"].get("implementation_notes", {})
    n = 60 if q else 200
    out = {}

    maj = [((x & 1) & (x >> 1 & 1)) ^ ((x & 1) & (x >> 2 & 1)) ^ ((x >> 1 & 1) & (x >> 2 & 1)) for x in range(8)]
    bp = B.boolean_profile(maj, 3)
    # Probabilitas penjumlahan modular = XOR (ukuran nonlinearitas ARX), 8-bit, eksak
    eq = sum(((a + b) & 0xFF) == (a ^ b) for a in range(256) for b in range(256)) / 65536
    out["C-ARX"] = {"metrics": {"carry_majority": bp, "p_add_equals_xor_8bit": eq}, "findings": [
        _cmp("Derajat aljabar fungsi carry (mayoritas)", bp["algebraic_degree"], f"= {ref.get('carry_degree', 2)}", bp["algebraic_degree"] >= ref.get("carry_degree", 2)),
        _cmp("Nonlinearitas fungsi carry (n=3)", bp["nonlinearity"], "= 2 (maks untuk n=3)", bp["nonlinearity"] == 2),
        _f("Imunitas korelasi carry", bp["correlation_immunity"], "0 (sifat mayoritas)", "OK",
           "Tidak relevan untuk ARX tanpa LFSR; dicatat untuk analisis korelasi"),
        _cmp("P[(a+b) mod 2^8 = a⊕b]", _round(eq, 5), "≈ (3/4)^7 ≈ 0,1335", abs(eq - 0.75 ** 7) < 1e-3),
    ]}

    base_key = bytes(range(32))

    def perm(x, r):
        st = chacha20.initial_state(base_key[:16] + x, 0, bytes(12))
        return struct.pack("<16L", *chacha20.permute(st, r))
    curve, full = _rounds_to_diffusion(perm, 6, 16, n)
    out["C-DIFF"] = {"metrics": {"avalanche_per_round": curve, "rounds_full_diffusion": full}, "findings": [
        _cmp("Ronde menuju difusi penuh (permutasi, tanpa feed-forward)", full, f"≤ {ref.get('rounds_full_diffusion_max', 4)}",
             full is not None and full <= ref.get("rounds_full_diffusion_max", 4))]}

    rounds = par["rounds"]
    margin = (rounds - 7) / rounds
    out["C-ROUND"] = {"metrics": {"rounds": rounds, "best_attacked_rounds_lit": 7}, "findings": [
        _f("Margin keamanan ronde (serangan terbaik 7/20)", f"{margin:.0%}", "≥ 20%", "OK" if margin >= 0.2 else "PERHATIAN",
           "A-SC-02 / A-SC-03", LIT)]}

    nb = par["nonce_bits"]
    max_bytes = (1 << par["counter_bits"]) * 64
    claimed = notes.get("max_message_bytes", 0)
    wrap = chacha20.block(base_key, (1 << 32), bytes(12)) == chacha20.block(base_key, 0, bytes(12))
    out["C-STATE"] = {"metrics": {"nonce_bits": nb, "max_bytes_per_nonce": max_bytes, "reference_counter_wraps": wrap}, "findings": [
        _f("Batas tabrakan nonce acak 96-bit", f"2^{nb / 2:.0f} pesan", "rekey ≤ 2^32 pesan (p tabrakan ≤ 2^-32)", "PERHATIAN",
           f"Klaim profil: {notes.get('nonce_generation', '-')}", CLAIM),
        _f("Batas panjang pesan per nonce (counter 32-bit)", f"{max_bytes} byte (2^{math.log2(max_bytes):.0f})",
           f"produk menolak > batas (klaim {claimed})", "PERHATIAN" if claimed >= max_bytes else "OK",
           "Counter implementasi referensi wrap-around" if wrap else "", DIRECT),
    ]}

    ks = chacha20.keystream(base_key, bytes(12), 128 if q else 512, 1)
    bits = B.bytes_to_bits(ks)
    lc_n = 400 if q else 2000
    L = B.berlekamp_massey(bits[:lc_n])
    rt = _bits_quick(ks)
    out["C-KS-OUT"] = {"metrics": {"linear_complexity": L, "lc_sample_bits": lc_n, "quick_randomness": rt}, "findings": [
        _cmp("Kompleksitas linear (Berlekamp–Massey)", L, f"≈ N/2 = {lc_n // 2} (±3)", abs(L - lc_n / 2) <= 3),
        _cmp("Pra-uji keacakan keystream (Monobit, Runs)", ", ".join(f"{t['test']} p={t['p_value']:.3f}" for t in rt),
             "p ≥ 0,01", all(t["pass"] for t in rt)),
    ]}
    kb = par["key_bits"]
    out["C-KEY"] = {"metrics": {"key_bits": kb, "security_bits": kb}, "findings": [
        _cmp("Tingkat keamanan (SP 800-57)", f"{kb} bit", "≥ 128 bit", kb >= 128)]}
    return out


# ======================================================================= SHA3-256
def _sha3(p, q):
    ref = p["algorithm"].get("reference_values", {})
    par = p["algorithm"]["parameters"]
    n = 30 if q else 120
    out = {}
    sp = B.sbox_profile(keccak.CHI_SBOX, 5, 5)
    out["C-CHI"] = {"metrics": sp, "findings": [
        _cmp("Keseragaman diferensial χ", sp["differential_uniformity"], f"= {ref.get('chi_differential_uniformity', 8)}",
             sp["differential_uniformity"] <= ref.get("chi_differential_uniformity", 8)),
        _f("Derajat aljabar χ", sp["max_coordinate_degree"], f"= {ref.get('chi_algebraic_degree', 2)} (by design)",
           "PERHATIAN" if sp["max_coordinate_degree"] <= 2 else "OK",
           "Derajat rendah dikompensasi 24 ronde; relevan untuk serangan aljabar/kubus ronde tereduksi (A-H-03/04)"),
        _cmp("Nonlinearitas χ", sp["nonlinearity"], "= 8", sp["nonlinearity"] >= 8),
        _cmp("Bijektif", sp["bijective"], "True", sp["bijective"]),
    ]}

    def perm(x, r):
        A = [int.from_bytes(x[8 * i:8 * i + 8], "little") for i in range(25)]
        return b"".join(v.to_bytes(8, "little") for v in keccak.keccak_f(A, r))
    curve, full = _rounds_to_diffusion(perm, 4, 200, n)
    out["C-DIFF"] = {"metrics": {"avalanche_per_round": curve, "rounds_full_diffusion": full}, "findings": [
        _cmp("Ronde menuju difusi penuh Keccak-f[1600]", full, f"≤ {par['rounds'] // 4}", full is not None and full <= par["rounds"] // 4)]}

    margin = (par["rounds"] - 5) / par["rounds"]
    out["C-ROUND"] = {"metrics": {"rounds": par["rounds"], "best_practical_collision_rounds_lit": 5}, "findings": [
        _f("Margin keamanan ronde (collision praktis 5/24)", f"{margin:.0%}", "≥ 20%", "OK" if margin >= 0.2 else "PERHATIAN", "A-H-03", LIT)]}

    rate = par["rate_bits"] // 8
    lengths = [0, 1, rate - 2, rate - 1, rate, rate + 1, 2 * rate - 1, 2 * rate]
    pad_ok = [keccak.sha3_256(b"\xa5" * L) == hashlib.sha3_256(b"\xa5" * L).digest() for L in lengths]
    single = keccak.pad10star1(rate - 1, rate)
    out["C-PAD"] = {"metrics": {"lengths_tested": lengths, "results": pad_ok, "pad_len_r_minus_1": single.hex()}, "findings": [
        _cmp("Digest pada panjang batas rate (r−2, r−1, r, r+1, …) = hashlib", f"{sum(pad_ok)}/{len(pad_ok)}", "100%", all(pad_ok)),
        _cmp("Padding satu byte (panjang ≡ r−1)", "0x" + single.hex(), "0x86 (01 ∥ 10*1)", single == b"\x86"),
    ]}

    c, nbits = par["capacity_bits"], par["output_bits"]
    coll, pre = min(nbits / 2, c / 2), min(nbits, c / 2)
    av = B.avalanche(keccak.sha3_256, 64, n * 2, seed=5)
    out["C-SPONGE"] = {"metrics": {"collision_bits": coll, "preimage_bits": pre, "hash_avalanche": av}, "findings": [
        _cmp("Kekuatan collision min(n/2, c/2)", f"{coll:.0f} bit", f"≥ {ref.get('collision_bits', 128)}", coll >= ref.get("collision_bits", 128)),
        _cmp("Kekuatan preimage min(n, c/2)", f"{pre:.0f} bit", f"≥ {ref.get('preimage_bits', 256)}", pre >= ref.get("preimage_bits", 256)),
        _cmp("Avalanche digest penuh", _round(av["mean"]), "0,5 ± 0,02", abs(av["mean"] - 0.5) <= 0.02),
    ]}
    return out


# ======================================================================= RSA-OAEP
def _rsa_strength(bits):
    return next((s for b, s in RSA_STRENGTH if bits >= b), 0)


def _oaep_em(priv, db_body: bytes, y: int, hash_name="sha256"):
    """Bangun ciphertext yang terdekripsi ke EM dengan DB tertentu (uji oracle)."""
    k = priv.k
    h = hashlib.new(hash_name).digest_size
    seed = secrets.token_bytes(h)
    db = db_body.ljust(k - h - 1, b"\x00")[:k - h - 1]
    mdb = rsa_oaep._xor(db, rsa_oaep.mgf1(seed, k - h - 1, hash_name))
    ms = rsa_oaep._xor(seed, rsa_oaep.mgf1(mdb, h, hash_name))
    em = bytes([y]) + ms + mdb
    m = bytes_to_int(em) % priv.n
    return int_to_bytes(pow(m, priv.e, priv.n), k)


def _pkcs1_n1024() -> int:
    """Modulus 1024-bit sah (PKCS#1 Example 1) sebagai kasus negatif ukuran kunci."""
    import json
    from pathlib import Path
    data = json.loads((Path(kat.__file__).parent / "vectors" / "rsa_oaep_pkcs1.json").read_text())
    return int(data["keys"][0]["key"]["n"], 16)


def _rsa(p, q):
    par = p["algorithm"]["parameters"]
    notes = p["algorithm"].get("implementation_notes", {})
    bits, e, hname = par["modulus_bits"], par["public_exponent"], par.get("hash", "sha256")
    nkeys = 1 if q else int(notes.get("sample_keys", 3))
    rng = random.Random(2023)          # RNG uji deterministik (ilustratif, reproducible)
    t0 = time.perf_counter()
    keys = [rsa_oaep.generate_keypair(bits, e, rng) for _ in range(nkeys)]
    kg_time = (time.perf_counter() - t0) / nkeys
    out = {}

    sec = _rsa_strength(bits)
    out["C-MOD"] = {"metrics": {"modulus_bits": bits, "security_bits": sec, "sample_keys": nkeys}, "findings": [
        _cmp("Tingkat keamanan IFC (SP 800-57 Tabel 2)", f"{sec} bit", "≥ 112 bit", sec >= 112),
        _f("Status transisi SP 800-131A", "acceptable" if sec >= 112 else "disallowed",
           "≥ 128 bit untuk perlindungan melampaui 2030", "PERHATIAN" if sec < 128 else "OK",
           "112-bit hanya disetujui hingga 2030 (SP 800-57 Tabel 4)", LIT),
    ]}

    pr = []
    for kp in keys:
        half = bits // 2
        pm1 = kp.p - 1
        for s in SMALL_PRIMES[:1000]:
            while pm1 % s == 0:
                pm1 //= s
        while pm1 % 2 == 0:
            pm1 //= 2
        pr.append({
            "p_prime": miller_rabin(kp.p, 64), "q_prime": miller_rabin(kp.q, 64),
            "pq_distance_log2": _round(math.log2(abs(kp.p - kp.q))), "pq_distance_ok": abs(kp.p - kp.q) > (1 << (half - 100)),
            "p_lower_bound_ok": kp.p > math.isqrt(1 << (2 * half - 1)) and kp.q > math.isqrt(1 << (2 * half - 1)),
            "p_minus_1_rough_part_bits": pm1.bit_length(),
            "d_bits": kp.d.bit_length(),
        })
    out["C-PRIME"] = {"metrics": {"keys": pr, "keygen_seconds_avg": _round(kg_time, 3)}, "findings": [
        _cmp("p, q prima (Miller–Rabin 64 iterasi)", all(x["p_prime"] and x["q_prime"] for x in pr), "True", all(x["p_prime"] and x["q_prime"] for x in pr)),
        _cmp("|p − q| > 2^(nlen/2 − 100)", f"min 2^{min(x['pq_distance_log2'] for x in pr)}", f"> 2^{bits // 2 - 100}", all(x["pq_distance_ok"] for x in pr),
             "Mitigasi faktorisasi Fermat"),
        _cmp("p, q ≥ √2·2^(nlen/2−1)", all(x["p_lower_bound_ok"] for x in pr), "True", all(x["p_lower_bound_ok"] for x in pr)),
        _cmp("Bagian kasar p−1 setelah pembagian prima < 2^14", f"min {min(x['p_minus_1_rough_part_bits'] for x in pr)} bit", "≥ 160 bit",
             all(x["p_minus_1_rough_part_bits"] >= 160 for x in pr), "Mitigasi Pollard p−1", weak="PERHATIAN"),
    ]}

    out["C-EXP-E"] = {"metrics": {"e": e}, "findings": [
        _cmp("Eksponen publik e ∈ (2^16, 2^256), ganjil", e, "65537 disarankan", (1 << 16) < e < (1 << 256) and e % 2 == 1)]}

    n0 = keys[0].n
    wiener = math.log2(n0) / 4 - math.log2(3)
    bd = 0.292 * math.log2(n0)
    dmin = min(k.d.bit_length() for k in keys)
    out["C-EXP-D"] = {"metrics": {"d_bits_min": dmin, "wiener_bound_bits": _round(wiener, 1), "boneh_durfee_bound_bits": _round(bd, 1)}, "findings": [
        _cmp("d > 2^(nlen/2) (FIPS 186-5)", f"{dmin} bit", f"> {bits // 2} bit", dmin > bits // 2),
        _cmp("d di atas batas Boneh–Durfee N^0,292", f"{dmin} bit", f"> {bd:.0f} bit", dmin > bd),
    ]}

    kp = keys[0]
    h = hashlib.new(hname).digest_size
    lh = hashlib.new(hname, b"").digest()
    classes = {
        "y≠0": lambda: _oaep_em(kp, lh + b"\x01msg", 1, hname),
        "lHash salah": lambda: _oaep_em(kp, secrets.token_bytes(h) + b"\x01msg", 0, hname),
        "tanpa pemisah 0x01": lambda: _oaep_em(kp, lh, 0, hname),
    }
    reps = 15 if q else 40
    errs, times = {}, {}
    for name, mk in classes.items():
        msgs, ts = set(), []
        for _ in range(reps):
            ct = mk()
            t = time.perf_counter()
            try:
                rsa_oaep.decrypt(kp, ct, hash_name=hname)
                msgs.add("DITERIMA")
            except rsa_oaep.DecryptionError as ex:
                msgs.add(f"{type(ex).__name__}: {ex}")
            ts.append(time.perf_counter() - t)
        errs[name], times[name] = sorted(msgs), ts
    uniform = len({m for v in errs.values() for m in v}) == 1 and "DITERIMA" not in str(errs)
    names = list(times)
    tmax = max(abs(stats.welch_t(times[a], times[b])) for i, a in enumerate(names) for b in names[i + 1:])
    out["C-OAEP"] = {"metrics": {"error_messages": errs, "welch_t_max": _round(tmax, 2), "samples_per_class": reps}, "findings": [
        _cmp("Keseragaman pesan galat antar kelas kegagalan", "seragam" if uniform else "BERBEDA", "satu jenis galat", uniform,
             "Mitigasi Manger (A-P-06) — implementasi referensi"),
        _f("Beda waktu antar kelas galat (Welch |t| maks)", _round(tmax, 2), "< 4,5 (indikatif, n kecil)",
           "OK" if tmax < 4.5 else "PERHATIAN", "Pengukuran pada implementasi referensi; produk diuji di M-ORACLE"),
    ]}
    hb = hashlib.new(hname).digest_size * 4
    out["C-HASH"] = {"metrics": {"hash": hname, "collision_bits": hb}, "findings": [
        _cmp(f"Kekuatan hash OAEP ({hname})", f"{hb} bit", f"≥ {sec} bit", hb >= sec)]}
    out["C-MODEXP"] = {"metrics": {"crt": par.get("crt", False)}, "findings": [
        _f("Eksponensiasi modular constant-time pada produk", "tidak diketahui (grey box)", "constant-time + blinding",
           "PERHATIAN", "A-P-08/A-P-09; CRT → juga relevan fault (A-P-10) bila platform embedded", CLAIM)]}

    v = rsa_oaep.validate_public_key(kp.public())
    neg = {
        "modulus genap": rsa_oaep.validate_public_key(rsa_oaep.PublicKey(kp.n + 1, e))["valid"],
        "e = 3": rsa_oaep.validate_public_key(rsa_oaep.PublicKey(kp.n, 3))["valid"],
        "modulus prima": rsa_oaep.validate_public_key(rsa_oaep.PublicKey(kp.p, e), min_bits=1)["valid"],
        "modulus 1024-bit": rsa_oaep.validate_public_key(rsa_oaep.PublicKey(_pkcs1_n1024(), e))["valid"],
    }
    out["C-PKV"] = {"metrics": {"positive": v, "negative_accepted": neg}, "findings": [
        _cmp("Kunci valid diterima", v["valid"], "True", v["valid"]),
        _cmp("Kunci tidak valid ditolak (4 kasus)", f"{sum(not x for x in neg.values())}/4", "4/4", not any(neg.values())),
    ]}
    return out


# ======================================================================= ECDSA
def _ecdsa(p, q):
    notes = p["algorithm"].get("implementation_notes", {})
    out = {}
    N, P = ec.N, ec.P
    disc = (4 * ec.A ** 3 + 27 * ec.B ** 2) % P
    order_ok = ec.scalar_mult(N - 1, ec.G) == (ec.GX, (-ec.GY) % P)
    mov_ok = all(pow(P, k, N) != 1 for k in range(1, 21))
    rho = 0.5 * math.log2(math.pi * N / 4)
    out["C-CURVE"] = {"metrics": {"rho_log2": _round(rho, 2)}, "findings": [
        _cmp("p prima & n prima", miller_rabin(P, 64) and miller_rabin(N, 64), "True", miller_rabin(P, 64) and miller_rabin(N, 64)),
        _cmp("Diskriminan 4a³+27b² ≠ 0", disc != 0, "True", disc != 0),
        _cmp("G di kurva & n·G = O", ec.is_on_curve(ec.G) and order_ok, "True", ec.is_on_curve(ec.G) and order_ok),
        _cmp("Kofaktor h", ec.H, "1", ec.H == 1),
        _cmp("Bukan kurva anomalous (n ≠ p) & MOV: p^k ≠ 1 mod n (k ≤ 20)", N != P and mov_ok, "True", N != P and mov_ok),
        _cmp("Biaya Pollard rho √(πn/4)", f"2^{rho:.1f}", "≥ 2^127", rho >= 127),
    ]}

    d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    Q = ec.public_key(d)
    good = ec.validate_public_key(Q)["valid"]
    neg = {"titik di luar kurva": ec.validate_public_key((Q[0], (Q[1] + 1) % P))["valid"],
           "koordinat ≥ p": ec.validate_public_key((Q[0] + P, Q[1]))["valid"],
           "titik tak hingga": ec.validate_public_key(ec.INF)["valid"]}
    out["C-PKV"] = {"metrics": {"negative_accepted": neg}, "findings": [
        _cmp("Kunci publik valid diterima", good, "True", good),
        _cmp("Kunci publik tidak valid ditolak (3 kasus)", f"{sum(not x for x in neg.values())}/3", "3/3", not any(neg.values())),
    ]}

    m = 64 if q else 512
    ks, rs = [], set()
    for i in range(m):
        msg = f"pesan-{i}".encode()
        r, s = ec.sign(d, msg)
        e = int.from_bytes(hashlib.sha256(msg).digest(), "big")
        ks.append(pow(s, -1, N) * (e + r * d) % N)      # pemulihan k (kunci uji diketahui)
        rs.add(r)
    counts = [0] * 16
    for k in ks:
        counts[k >> 252] += 1
    chi = stats.chi_square_uniform(counts)
    out["C-NONCE"] = {"metrics": {"samples": m, "unique_r": len(rs), "msb4_chi2": chi, "mode": notes.get("nonce_generation")}, "findings": [
        _cmp("Keunikan nonce (r unik)", f"{len(rs)}/{m}", f"{m}/{m}", len(rs) == m),
        _cmp("Bias 4 bit teratas k (χ², df=15)", f"p = {chi['p_value']:.3f}", "p ≥ 0,01", chi["p_value"] >= 0.01),
    ]}

    reps = 6 if q else 20
    rng = random.Random(3)
    lo = [(1 << 255) | rng.getrandbits(8) for _ in range(reps)]
    hi = [(1 << 256) - 1 - rng.getrandbits(8) for _ in range(reps)]

    def tm(k):
        t = time.perf_counter(); ec.scalar_mult(k); return time.perf_counter() - t
    t_stat = stats.welch_t([tm(k) for k in lo], [tm(k) for k in hi])
    out["C-SMUL"] = {"metrics": {"welch_t_hw_low_vs_high": _round(t_stat, 2), "samples": reps}, "findings": [
        _f("Timing perkalian skalar referensi (HW rendah vs tinggi)", _round(abs(t_stat), 2), "|t| < 4,5",
           "OK" if abs(t_stat) < 4.5 else "PERHATIAN",
           "Double-and-add referensi tidak constant-time; produk wajib diuji M-TIMING (A-D-07)"),
    ]}

    r, s = ec.sign(d, b"sample")
    rej = {"r=0": ec.verify(Q, b"sample", (0, s)), "s=0": ec.verify(Q, b"sample", (r, 0)),
           "r=n": ec.verify(Q, b"sample", (N, s)), "s=n": ec.verify(Q, b"sample", (r, N)),
           "(0,0)": ec.verify(Q, b"sample", (0, 0))}
    malleable = ec.verify(Q, b"sample", (r, N - s))
    low_s = bool(notes.get("low_s_enforced"))
    out["C-SIG"] = {"metrics": {"out_of_range_accepted": rej, "malleable_accepted": malleable}, "findings": [
        _cmp("(r,s) di luar [1, n−1] ditolak (5 kasus)", f"{sum(not x for x in rej.values())}/5", "5/5", not any(rej.values())),
        _f("Malleability (r, n−s) diterima", malleable, "ditolak bila protokol butuh low-S",
           "PERHATIAN" if malleable and not low_s else "OK", "A-D-05; klaim profil low_s_enforced=" + str(low_s)),
    ]}
    out["C-HASH"] = {"metrics": {"hash": "sha256", "collision_bits": 128}, "findings": [
        _cmp("Kekuatan hash vs kurva (SP 800-57)", "128 bit", "≥ 128 bit", True)]}
    return out


# ======================================================================= implementasi (umum)
def _impl(p, kat_result):
    impl = p["implementation"]
    lang = impl["language"]
    out = {
        "C-API": {"metrics": {"language": lang}, "findings": [
            _f("Bahasa implementasi tanpa memory safety", lang, "memory-safe atau fuzzing ekstensif",
               "PERHATIAN" if lang in ("C", "C++") else "OK", "A-L-02 / A-H-07", CLAIM)]},
        "C-MEM": {"metrics": {}, "findings": [
            _f("Zeroization material kunci", "tidak dapat diverifikasi (grey box)", "CSP dihapus pasca-pakai (ISO/IEC 19790)",
               "PERHATIAN", "A-L-03", CLAIM)]},
        "C-SELFTEST": {"metrics": {"self_tests": impl.get("self_tests")}, "findings": [
            _f("Self-test tersedia", impl.get("self_tests"), "True (POST KAT + conditional)", "OK" if impl.get("self_tests") else "BERPOTENSI_LEMAH",
               "Diverifikasi di M-SELFTEST", CLAIM)]},
        "C-RNG": {"metrics": {"rng": impl.get("rng")}, "findings": [
            _f("RBG yang dipakai", impl.get("rng"), "DRBG SP 800-90A + sumber entropi SP 800-90B",
               "OK" if "800-90A" in str(impl.get("rng")) else "PERHATIAN", "Diverifikasi di M-RNG", CLAIM)]},
        "C-PLAT": {"metrics": {"platform": impl["platform"]}, "findings": [
            _f("Platform ber-cache bersama & speculative execution", impl.get("platform_desc", impl["platform"]),
               "operasi rahasia constant-time", "PERHATIAN", "A-X-01 / A-X-02", LIT)]},
        "C-CONF": {"metrics": {"kat": {k: v for k, v in kat_result.items() if k != "cases"}}, "findings": [
            _cmp("KAT implementasi referensi (core/)", f"{kat_result['passed']}/{kat_result['total']} {kat_result['status']}", "100% cocok",
                 kat_result["status"] == "LULUS", "Vektor: " + "; ".join(sorted({c['source'].split(' (')[0] for c in kat_result['cases']})))]},
    }
    return out


ANALYZERS = {"block_cipher": _aes, "stream_cipher": _chacha, "hash": _sha3, "pkc": _rsa, "dss": _ecdsa}


def analyze(profile: dict, components: list, quick: bool = False) -> dict:
    """Jalankan telaah untuk semua komponen hasil dekomposisi."""
    kat_result = kat.run(profile["algorithm"]["id"])
    res = ANALYZERS[profile["algorithm"]["primitive"]](profile, quick)
    res.update(_impl(profile, kat_result))
    out = {}
    for c in components:
        r = res.get(c["id"], {"metrics": {}, "findings": [
            _f("Belum dianalisis langsung", "-", "-", "PERHATIAN", "Diuji pada metode terkait", CLAIM)]})
        worst = max((f["status"] for f in r["findings"]), key=RANK.get, default="OK")
        out[c["id"]] = {**c, **r, "status": worst,
                        "flag_weak": worst == "BERPOTENSI_LEMAH"}
    return {"components": out, "kat": kat_result}
