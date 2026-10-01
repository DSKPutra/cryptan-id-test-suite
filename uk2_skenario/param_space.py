"""KUK 1.2 — Parameter ditelaah sesuai metode.

Klasifikasi 5 kelas (materi slide 4): material rahasia · data masukan · parameter publik/domain ·
konfigurasi · kondisi lingkungan. Status Tetap/Variabel ditentukan dari profil produk.
Nilai uji dibangkitkan otomatis dengan 6 teknik:
  EP partisi ekuivalensi · BVA nilai batas (0, min, b−1, b, b+1, maks, di luar rentang)
  DEG input degeneratif/berpola · BIT variasi 1-bit · TWAY kombinatorial pairwise · NEG negative testing
"""
import itertools
import math

from .context import category_of

CLASSES = ["Material rahasia", "Data masukan", "Parameter publik/domain", "Konfigurasi", "Kondisi lingkungan"]
TECH = {"EP": "Partisi ekuivalensi", "BVA": "Analisis nilai batas", "DEG": "Input degeneratif/berpola",
        "BIT": "Variasi 1-bit (diferensial)", "TWAY": "Kombinatorial t-way (pairwise)", "NEG": "Negative testing"}
# (ukuran blok b dalam byte, panjang field panjang L dalam byte) untuk batas padding hash
HASH_BLOCK = {"SHA-1": (64, 8), "SHA-224": (64, 8), "SHA-256": (64, 8), "SHA-384": (128, 16), "SHA-512": (128, 16),
              "SHA-512/224": (128, 16), "SHA-512/256": (128, 16), "SHA3-224": (144, 0), "SHA3-256": (136, 0),
              "SHA3-384": (104, 0), "SHA3-512": (72, 0), "SHAKE128": (168, 0), "SHAKE256": (136, 0),
              "BLAKE2b-512": (128, 0), "BLAKE2s-256": (64, 0), "SM3": (64, 8)}
DEGENERATE = ["nol-semua (0x00…)", "satu-semua (0xFF…)", "low-density (HW = 1)", "high-density (HW = n−1)", "periodik (0x55/0xAA)"]
MiB = 1 << 20


def v(value, tech, in_spec=True, note=""):
    return {"value": value, "technique": tech, "in_spec": in_spec, "negative": not in_spec, "note": note}


def P(pid, name, cls, values, spec=None, status=None, template=None, objects=None):
    status = status or ("Variabel" if len({str(x["value"]) for x in values if x["in_spec"]}) > 1 else "Tetap")
    return {"id": pid, "name": name, "class": cls, "status": status, "spec": spec, "values": values,
            "template_param": template, "objects": objects or []}


def _keys(objs):
    return sorted({o["key_bits"] for o in objs if o.get("key_bits")})


def _bva_keys(keys, step=8):
    """Nilai batas panjang kunci: 0, min−step, setiap kunci (EP), maks+step, dan nilai antara tidak didukung."""
    out = [v(0, "BVA", False, "panjang kunci 0"), v(keys[0] - step, "BVA", False, "min − 8 bit")]
    out += [v(k, "EP", True, "panjang didukung") for k in keys]
    gaps = [k for k in (128, 192, 256, 384, 512, 2048, 3072, 4096) if keys[0] < k < keys[-1] and k not in keys]
    out += [v(k, "NEG", False, "di dalam rentang tetapi tidak didukung") for k in gaps[:2]]
    out += [v(keys[-1] + step, "BVA", False, "maks + 8 bit")]
    return out


def _msg_lengths(b, L, max_bytes):
    if L:   # Merkle–Damgård: batas padding b − L − 1, b − L
        pts = [0, 1, b - L - 1, b - L, b - 1, b, b + 1]
    else:   # sponge / lainnya: batas rate
        pts = [0, 1, b - 1, b, b + 1, 2 * b]
    out = [v(n, "BVA", True, f"{n} byte") for n in sorted(set(pts))]
    out += [v(MiB, "EP", True, "1 MiB (Long Message)"), v(100 * MiB, "EP", True, "100 MiB")]
    if max_bytes:
        out += [v(max_bytes, "BVA", True, "batas maksimum klaim"), v(max_bytes + 1, "BVA", False, "maks + 1 byte → ditolak")]
    return out


def _env(ctx):
    pr = ctx.uk2.get("parameters", {})
    conds = pr.get("operating_conditions") or (["normal", "beban tinggi multi-thread", "memori terbatas"]
                                               if ctx.uk2.get("product_type") == "library" else ["normal"])
    return P("ENV", "Kondisi operasional", "Kondisi lingkungan", [v(c, "EP", True) for c in conds])


# --------------------------------------------------------------------- per kategori
def block(ctx, objs):
    keys = _keys(objs) or [128]
    modes = sorted({o["variant"] for o in objs})
    tested_modes = sorted(set(modes) | {"ECB", "CBC", "CTR", "GCM", "XTS"})
    lim = ctx.uk2.get("limits", {}).get("max_message_bytes")
    return [
        P("BC-KEY-LEN", "Panjang kunci", "Parameter publik/domain", _bva_keys(keys), keys, template="Panjang & nilai kunci", objects=[o["id"] for o in objs]),
        P("BC-KEY-VAL", "Nilai kunci", "Material rahasia",
          [v("acak (DRBG)", "EP")] + [v(d, "DEG") for d in DEGENERATE[:4]] + [v("related-key (beda 1 bit)", "BIT"), v("kunci lemah/semi-lemah (bila ada)", "DEG")],
          template="Panjang & nilai kunci"),
        P("BC-PT", "Blok plaintext", "Data masukan",
          [v("acak", "EP")] + [v(d, "DEG") for d in DEGENERATE] + [v("1-bit flip pada tiap posisi (n = 128)", "BIT")], template="Blok plaintext"),
        P("BC-MODE", "Mode operasi", "Konfigurasi", [v(m, "EP", m in modes, "" if m in modes else "tidak didukung produk → harus ditolak") for m in tested_modes],
          modes, template="Mode operasi"),
        P("BC-IV", "IV/nonce", "Material rahasia",
          [v("acak 96 bit", "EP"), v("counter berurutan", "EP"), v("nol", "DEG", False, "nonce nol (jika dilarang)"),
           v("berulang (reuse)", "NEG", False, "nonce reuse → ditolak/terdeteksi"), v("dapat diprediksi (CBC)", "NEG", False),
           v("panjang non-96 bit (GCM)", "BVA", True)], template="IV/nonce"),
        P("BC-LEN", "Panjang pesan & padding", "Data masukan",
          [v(0, "BVA", True, "0 byte"), v(1, "BVA"), v(15, "BVA", True, "b − 1"), v(16, "BVA", True, "b"), v(17, "BVA", True, "b + 1"),
           v(MiB, "EP", True, "1 MiB")] + ([v(lim, "BVA", True, "batas data per kunci"), v(lim + 1, "BVA", False, "melebihi batas")] if lim else []),
          template="Panjang pesan & padding"),
        P("BC-ROUNDS", "Jumlah ronde", "Konfigurasi", [v("penuh (10/12/14)", "EP"), v("tereduksi 2–4 ronde (analisis)", "BVA", True, "hanya pada build analisis")],
          status="Variabel", template="Jumlah ronde"),
    ]


def stream(ctx, objs):
    keys = _keys(objs) or [256]
    return [
        P("SC-KEY", "Kunci", "Material rahasia", [v(f"{k} bit acak", "EP") for k in keys] + [v(d, "DEG") for d in DEGENERATE[:4]]
          + [v(f"{keys[0] - 8} bit", "NEG", False, "panjang tidak didukung")], keys, template="Kunci", objects=[o["id"] for o in objs]),
        P("SC-NONCE", "IV/nonce", "Material rahasia", [v("acak 96 bit", "EP"), v("berurutan", "EP"), v("beda 1 bit", "BIT"),
          v("berulang", "NEG", False, "IV reuse → keystream identik"), v("panjang 64 bit", "NEG", False)], template="IV/nonce"),
        P("SC-INIT", "Ronde inisialisasi", "Konfigurasi", [v("penuh (20 ronde)", "EP"), v("tereduksi 4–7 ronde (analisis)", "BVA")], status="Variabel", template="Ronde inisialisasi"),
        P("SC-KSLEN", "Panjang keystream", "Data masukan", [v("10^6 bit", "EP"), v("10^8 bit (100 × 10^6)", "EP"), v("2^30 bit", "BVA"),
          v("2^32 blok (batas counter)", "BVA", True), v("2^32 + 1 blok", "BVA", False, "counter overflow → ditolak")], template="Panjang keystream"),
        P("SC-STATE", "Ukuran state", "Parameter publik/domain", [v("512 bit (≥ 2 × kunci)", "EP")], template="Ukuran state"),
    ]


def hashf(ctx, objs):
    out = []
    lim = ctx.uk2.get("limits", {}).get("max_message_bytes")
    for o in objs:
        name = o.get("variant") or o["id"]
        b, L = HASH_BLOCK.get(name, (64, 8))
        if o["primitive"] in ("hash",):
            out.append(P(f"HF-LEN-{o['id']}", f"Panjang pesan {o['id']} (b = {b} B)", "Data masukan", _msg_lengths(b, L, lim),
                         template="Panjang pesan", objects=[o["id"]]))
    out += [
        P("HF-PAT", "Pola pesan", "Data masukan", [v("acak", "EP")] + [v(d, "DEG") for d in DEGENERATE] + [v("beda 1 bit", "BIT")], template="Pola pesan"),
        P("HF-DIG", "Panjang digest", "Konfigurasi", [v("penuh", "EP"), v("terpotong t = 128 bit", "EP"), v("XOF 256/512 bit", "EP"),
          v("terpotong t = 32 bit (analisis birthday)", "BVA")], status="Variabel", template="Panjang digest"),
        P("HF-CHUNK", "Pemecahan input", "Konfigurasi", [v("one-shot", "EP"), v("update bertahap acak (1…b+7 byte)", "EP")], template="Pemecahan input"),
        P("HF-ROUNDS", "Jumlah ronde", "Konfigurasi", [v("penuh", "EP"), v("tereduksi (analisis)", "BVA")], status="Variabel", template="Jumlah ronde"),
    ]
    macs = [o for o in objs if o["primitive"] in ("mac", "kdf")]
    if macs:
        out.append(P("HF-KEY", "Kunci/salt (HMAC, KDF)", "Material rahasia",
                     [v("kunci < blok", "BVA"), v("kunci = blok", "BVA"), v("kunci > blok (di-hash dulu)", "BVA"), v("kunci 0 byte", "NEG", False)],
                     template="Kunci/salt (HMAC, KDF)", objects=[o["id"] for o in macs]))
    return out


def pke(ctx, objs):
    doms = sorted({o["id"] for o in objs})
    keys = _keys(objs)
    vals = [v(d, "EP") for d in doms]
    if any(o["family"] == "RSA" for o in objs):
        vals += [v("RSA-1024", "NEG", False, "di bawah 112 bit → ditolak"), v("RSA-2047 (modulus ganjil-bit)", "BVA", False)]
    return [
        P("PK-DOM", "Ukuran kunci & domain", "Parameter publik/domain", vals, doms, template="Ukuran kunci & domain", objects=doms),
        P("PK-KEYGEN", "Kualitas pembangkitan kunci", "Material rahasia", [v("DRBG produk (normal)", "EP"),
          v("entropi rendah (simulasi, batch-GCD)", "NEG", False, "harus terdeteksi")], template="Kualitas pembangkitan kunci"),
        P("PK-PAD", "Skema padding", "Konfigurasi", [v("OAEP (SHA-256/MGF1)", "EP", any("OAEP" in d for d in doms)),
          v("PKCS#1 v1.5", "NEG", any("PKCS1" in d for d in doms), "harus ditolak bila tidak didukung"), v("FO transform (KEM)", "EP", any("ML-KEM" in d for d in doms))],
          template="Skema padding"),
        P("PK-CT", "Ciphertext masukan", "Data masukan", [v("valid", "EP"), v("termodifikasi 1 bit", "BIT", False), v("malformed (panjang ±1)", "NEG", False),
          v("di luar rentang (c ≥ n)", "BVA", False)], template="Ciphertext masukan"),
        P("PK-PEER", "Kunci publik lawan", "Data masukan", [v("valid", "EP"), v("titik tidak di kurva", "NEG", False), v("subgrup kecil / low-order", "NEG", False),
          v("titik tak hingga", "BVA", False)], template="Kunci publik lawan"),
    ] + ([P("PK-KEYS", "Panjang modulus/kunci", "Parameter publik/domain", _bva_keys(keys, 1), keys)] if keys and max(keys) >= 1024 else [])


def signature(ctx, objs):
    pr = ctx.uk2.get("parameters", {})
    modes = pr.get("nonce_modes") or (["rfc6979"] if any(o["family"] == "ECDSA" for o in objs) else [])
    out = [
        P("DS-ALG", "Kurva & hash / parameter set", "Parameter publik/domain", [v(o["id"], "EP") for o in objs], [o["id"] for o in objs],
          template="Fungsi hash & pesan", objects=[o["id"] for o in objs]),
        P("DS-NONCE", "Mode nonce", "Konfigurasi", [v(m, "EP") for m in modes] + [v("bias beberapa bit (simulasi)", "NEG", False),
          v("berulang (simulasi)", "NEG", False)], modes, template="Nonce k (ECDSA/DSA/Schnorr)"),
        P("DS-MSG", "Panjang pesan", "Data masukan", _msg_lengths(64, 8, None)[:7] + [v(MiB, "EP", True, "1 MB"), v(100 * MiB, "EP", True, "100 MB")],
          template="Fungsi hash & pesan"),
        P("DS-D", "Kunci privat d", "Material rahasia", [v("acak", "EP"), v("Hamming weight rendah", "DEG"), v("Hamming weight tinggi", "DEG"),
          v("d = 1", "BVA"), v("d = n − 1", "BVA"), v("d = 0", "BVA", False), v("d = n", "BVA", False)]),
        P("DS-ENC", "Encoding (r, s)", "Data masukan", [v("DER kanonik", "EP"), v("DER non-kanonik", "NEG", False), v("r atau s = 0", "BVA", False),
          v("r atau s ≥ n", "BVA", False), v("s ↔ n − s", "NEG", True, "malleability — kebijakan low-s")], template="Encoding tanda tangan"),
        P("DS-Q", "Kunci publik Q", "Data masukan", [v("valid", "EP"), v("titik tak hingga O", "BVA", False), v("di luar kurva", "NEG", False),
          v("koordinat ≥ p", "BVA", False)], template="Kunci publik"),
        P("DS-N", "Ukuran sampel", "Konfigurasi", [v(f"N = {pr.get('sample_signatures', 10**6):,} tanda tangan (uji nonce)".replace(",", "."), "EP"),
          v(f"{pr.get('sample_traces', 10**5):,} trace/pengukuran (side-channel)".replace(",", "."), "EP")]),
    ]
    pqc = [o for o in objs if o["family"] in ("ML-DSA", "SLH-DSA", "LMS", "XMSS")]
    if pqc:
        out.append(P("DS-PQC", "Parameter PQC & state", "Parameter publik/domain", [v(o["id"], "EP") for o in pqc]
                     + [v("indeks OTS dipakai ulang (stateful)", "NEG", False)], template="Parameter PQC & state", objects=[o["id"] for o in pqc]))
    return out


def protocol(ctx, objs):
    pr = ctx.uk2.get("protocol", {})
    sup = set(pr.get("versions_supported", []))
    suites = set(pr.get("cipher_suites", []))
    groups = pr.get("groups", [])
    return [
        P("PR-VER", "Versi protokol", "Konfigurasi", [v(x, "EP" if x in sup else "NEG", x in sup) for x in pr.get("versions_tested", [])], sorted(sup),
          template="Versi & cipher suite"),
        P("PR-SUITE", "Cipher suite", "Konfigurasi", [v(x, "EP" if x in suites else "NEG", x in suites) for x in pr.get("cipher_suites_tested", [])],
          sorted(suites), template="Versi & cipher suite"),
        P("PR-GROUP", "Grup pertukaran kunci", "Parameter publik/domain", [v(g, "EP") for g in groups] + [v("grup tidak didukung (memicu HRR)", "BVA", True)],
          groups, template="Parameter pertukaran kunci"),
        P("PR-KS", "Nilai publik key share", "Data masukan", [v("valid", "EP"), v("di luar kurva", "NEG", False), v("titik tak hingga", "BVA", False),
          v("low-order X25519", "NEG", False), v("panjang salah", "BVA", False)], template="Parameter pertukaran kunci"),
        P("PR-CERT", "Sertifikat klien", "Material rahasia", [v(c, "EP" if c == "valid" else "NEG", c == "valid") for c in pr.get("certificates", ["valid"])],
          template="Kredensial & identitas"),
        P("PR-ORDER", "Urutan pesan", "Data masukan", [v("normal", "EP"), v("dilewati", "NEG", False), v("diulang", "NEG", False), v("disisipkan", "NEG", False)],
          template="Urutan & format pesan"),
        P("PR-0RTT", "Replay & 0-RTT", "Konfigurasi", [v(x, "EP") for x in pr.get("zero_rtt", ["nonaktif"])] + [v("replay ClientHello & early data", "NEG", False)],
          template="Nonce, timestamp, sequence"),
        P("PR-NET", "Kondisi jaringan", "Kondisi lingkungan", [v("normal", "EP")] + [v(x, "BVA") for x in pr.get("network_conditions", [])],
          template="Kondisi jaringan"),
    ]


def module(ctx):
    m = ctx.uk2.get("module", {})
    sl = ctx.security_level
    return [
        P("M-SL", "Tingkat keamanan target", "Parameter publik/domain", [v(f"SL {i}", "EP", i == sl, "target" if i == sl else "referensi") for i in (1, 2, 3, 4)],
          [sl], status="Tetap"),
        P("M-ALG", "Parameter algoritma", "Parameter publik/domain", [v(o["id"], "EP") for o in ctx.objects]
          + [v("IV GCM non-96 bit", "BVA"), v("tag 96 bit", "BVA"), v("parameter non-approved", "NEG", False, "ditolak / non-approved")]),
        P("M-ENT", "Kondisi sumber entropi", "Kondisi lingkungan", [v("normal", "EP"), v("suhu batas operasi", "BVA"), v("sumber dirusak/macet", "NEG", False)]),
        P("M-ROLE", "Peran & kredensial", "Material rahasia", [v(r, "EP") for r in m.get("roles", [])]
          + [v("kredensial salah", "NEG", False), v("kedaluwarsa", "NEG", False), v("berulang (brute force)", "NEG", False)]),
        P("M-STATE", "Status modul", "Konfigurasi", [v(s, "EP") for s in m.get("states", [])]),
        P("M-SSP", "Metode entri/output SSP", "Konfigurasi", [v(x, "EP", x != "plaintext" or (sl or 0) < 3,
          "plaintext dilarang untuk CSP pada SL 3" if x == "plaintext" else "") for x in m.get("ssp_entry", [])]),
        P("M-PHYS", "Kondisi fisik & lingkungan", "Kondisi lingkungan", [v("normal", "EP"), v("tutup dibuka", "NEG", False), v("pengeboran", "NEG", False),
          v("probing", "NEG", False), v("suhu/tegangan di luar rentang", "BVA", False)]),
        P("M-TRACE", "Kuantitas trace side-channel", "Konfigurasi", [v(n, "EP") for n in m.get("trace_counts", [10**5])]),
    ]


GEN = {"block": block, "stream": stream, "hash": hashf, "pke": pke, "signature": signature, "protocol": protocol}


# --------------------------------------------------------------------- pairwise (IPOG)
def pairwise(params: dict) -> list:
    """Bangkitkan himpunan uji yang mencakup semua pasangan nilai (2-way) — algoritma IPOG."""
    names = [n for n in params if params[n]]
    if len(names) < 2:
        return [dict(zip(names, c)) for c in itertools.product(*[params[n] for n in names])]
    names.sort(key=lambda n: -len(params[n]))
    tests = [list(c) for c in itertools.product(params[names[0]], params[names[1]])]
    for i in range(2, len(names)):
        vals = params[names[i]]
        uncovered = {(j, a, b) for j in range(i) for a in params[names[j]] for b in vals}
        for t in tests:                                     # pertumbuhan horizontal
            best = max(vals, key=lambda b: sum((j, t[j], b) in uncovered for j in range(i)))
            t.append(best)
            uncovered -= {(j, t[j], best) for j in range(i)}
        while uncovered:                                    # pertumbuhan vertikal
            j, a, b = next(iter(uncovered))
            t = [None] * (i + 1)
            t[j], t[i] = a, b
            for k in range(i):
                if t[k] is None:
                    t[k] = max(params[names[k]], key=lambda x: (k, x, b) in uncovered)
            tests.append(t)
            uncovered -= {(k, t[k], b) for k in range(i)}
    return [dict(zip(names, t)) for t in tests]


def covers_all_pairs(tests: list, params: dict) -> bool:
    names = list(params)
    for x, y in itertools.combinations(names, 2):
        need = {(a, b) for a in params[x] for b in params[y]}
        have = {(t[x], t[y]) for t in tests}
        if need - have:
            return False
    return True


def build(ctx) -> dict:
    """Ruang parameter per kategori + reduksi pairwise."""
    out = {"classes": CLASSES, "techniques": TECH, "categories": {}}
    for cat in ctx.categories():
        objs = ctx.objects_in(cat)
        params = GEN[cat](ctx, objs) + [_env(ctx)]
        tw_in = {p["id"]: [str(x["value"]) for x in p["values"] if x["in_spec"]] for p in params
                 if p["status"] == "Variabel" and p["class"] != "Material rahasia"}
        tw_in = {k: vv for k, vv in tw_in.items() if len(vv) > 1}
        full = math.prod(len(vv) for vv in tw_in.values()) if tw_in else 0
        tests = pairwise(tw_in) if tw_in else []
        out["categories"][cat] = {
            "objects": [o["id"] for o in objs], "params": params,
            "pairwise": {"parameters": list(tw_in), "full_combinations": full, "pairwise_combinations": len(tests),
                         "reduction_pct": round(100 * (1 - len(tests) / full), 1) if full else 0.0,
                         "all_pairs_covered": covers_all_pairs(tests, tw_in) if tests else True, "tests": tests},
            "counts": {c: sum(1 for p in params if p["class"] == c) for c in CLASSES},
            "negatives": sum(1 for p in params for x in p["values"] if x["negative"]),
        }
    if ctx.is_module:
        mp = module(ctx)
        tw_in = {p["id"]: [str(x["value"]) for x in p["values"] if x["in_spec"]] for p in mp if p["status"] == "Variabel"}
        tw_in = {k: vv for k, vv in tw_in.items() if len(vv) > 1}
        tests = pairwise(tw_in)
        full = math.prod(len(vv) for vv in tw_in.values())
        out["categories"]["module"] = {"objects": [o["id"] for o in ctx.objects], "params": mp,
                                       "pairwise": {"parameters": list(tw_in), "full_combinations": full, "pairwise_combinations": len(tests),
                                                    "reduction_pct": round(100 * (1 - len(tests) / full), 1) if full else 0.0,
                                                    "all_pairs_covered": covers_all_pairs(tests, tw_in), "tests": tests},
                                       "counts": {c: sum(1 for p in mp if p["class"] == c) for c in CLASSES},
                                       "negatives": sum(1 for p in mp for x in p["values"] if x["negative"])}
    return out
