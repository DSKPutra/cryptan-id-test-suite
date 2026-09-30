# 🔐 Cryptan.ID Test Suite

**Cryptan.ID Test Suite** adalah perangkat pengujian produk kriptografi untuk praktikum
**Pelatihan Sertifikasi Cryptographic Analyst (CA) Angkatan 1 — Politeknik Siber dan Sandi Negara**.
Repositori ini dibangun bertahap per Unit Kompetensi (UK-1 s.d. UK-8); setiap UK menghasilkan
**JSON terstruktur** yang menjadi masukan UK berikutnya.

| Modul | Unit | Status |
|---|---|---|
| **UK-1** | J.61KRP00.012.1 — Menentukan Metode Pengujian yang akan Dilakukan | ✅ selesai (`uk1_metode/`) |
| UK-2 | Menyusun Skenario Pengujian | ⏳ menyusul |
| UK-3 … UK-8 | — | ⏳ menyusul |

Objek praktikum mencakup **kelima kelas primitif** (satu profil per kelas):

| Kelas primitif | Algoritma | Implementasi referensi | Known Answer Test |
|---|---|---|---|
| Block cipher | AES-128 (mode CTR) | `core/aes.py` | FIPS 197 App. B & C.1, SP 800-38A F.1.1 |
| Stream cipher | ChaCha20 | `core/chacha20.py` | RFC 8439 §2.3.2, §2.4.2, A.1 |
| Fungsi hash | SHA3-256 | `core/keccak.py` | FIPS 202 / NIST CSRC examples + uji silang `hashlib` |
| PKC | RSA-OAEP-2048 | `core/rsa_oaep.py` | PKCS #1 v2.1 `oaep-vect.txt` (Example 1 & 10, 12 vektor) |
| DSS | ECDSA P-256 + SHA-256 | `core/ecdsa_p256.py` | RFC 6979 A.2.5 |

Profil produk (hipotetis): **Cryptan.ID SecureLib** — library perangkat lunak Linux x86-64, ditulis dalam C
dengan binding Python, diuji secara **grey box**. Seluruh data produk bersifat **ilustratif**.

---

## 🚀 Instalasi & menjalankan

```bash
make install        # python3 -m venv .venv && pip install -r requirements.txt
make kat            # KAT implementasi referensi → LULUS/GAGAL
make run            # UK-1 end-to-end untuk kelima algoritma
make test           # 68 unit test (pytest)
make serve          # dashboard statis di http://localhost:8000
```

Perintah utama UK-1 (tanpa `make`):

```bash
python -m uk1_metode --profile config/product_profile.yaml            # semua algoritma ("All")
python -m uk1_metode --profile config/profiles/aes128.yaml            # satu algoritma
python -m uk1_metode --profile config/product_profile.yaml --quick    # sampel kecil (demo/CI)
```

Kebutuhan: Python ≥ 3.10, `PyYAML`; opsional `python-docx` (keluaran DOCX) dan `cryptography`
(uji silang interoperabilitas dengan OpenSSL).

## 📁 Struktur repositori

```
cryptan-id-test-suite/
├── README.md                     # dokumen ini (peta KUK → file)
├── config/
│   ├── product_profile.yaml      # profil produk bersama (input semua UK) + daftar profil algoritma
│   └── profiles/                 # aes128 · chacha20 · sha3_256 · rsa_oaep_2048 · ecdsa_p256 (extends)
├── core/                         # implementasi referensi + util bersama (dipakai UK-1..UK-8)
│   ├── aes.py chacha20.py keccak.py rsa_oaep.py ecdsa_p256.py numtheory.py
│   ├── boolean.py                # Walsh/ANF, NL, DDT, LAT, derajat, SAC, branch number/MDS, Berlekamp–Massey
│   ├── stats.py                  # uji SP 800-22 (monobit, runs), igamc, χ², Welch t (TVLA)
│   ├── kat.py                    # runner Known Answer Test
│   └── vectors/                  # test vector resmi (JSON)
├── uk1_metode/                   # UK-1
│   ├── profile.py                # KUK 1.1
│   ├── attack_kb.py              # KUK 1.2  + data/attacks.yaml
│   ├── standards_kb.py           # KUK 1.3  + data/standards.yaml
│   ├── decompose.py              # KUK 2.1  (dekomposisi komponen)
│   ├── component_analysis.py     # KUK 2.1  (HASIL UJI LANGSUNG)
│   ├── mapping.py                # KUK 2.2  + data/methods.yaml
│   ├── resources.py              # KUK 2.3
│   ├── selector.py               # KUK 3.1
│   ├── parameters.py             # KUK 3.2
│   ├── traceability.py           # Matriks keterlacakan
│   ├── report.py                 # JSON + Markdown + DOCX + CSV
│   └── pipeline.py / __main__.py # orkestrasi & CLI
├── outputs/uk1/<algoritma>/      # contoh keluaran hasil eksekusi (lihat di bawah)
├── web/ + scripts/build_site.py  # dashboard statis (Vercel / Netlify)
└── tests/                        # pytest: core KAT, sifat komponen, EK 1, EK 2, EK 3, E2E
```

## 🧭 Peta KUK → modul → bagian dokumen → test

| EK | KUK | Yang dikerjakan kode | File | Bab dokumen | Test |
|---|---|---|---|---|---|
| 1 | 1.1 Informasi desain & teknik implementasi | Baca, gabung (`extends`) & validasi profil; Profil Produk | `profile.py`, `config/` | 1 | `test_uk1_ek1.py::test_kuk_1_1_*` |
| 1 | 1.2 Tren serangan terhadap platform | Basis serangan desain/protokol/bahasa/platform (model, kompleksitas log2, rujukan, status), filter otomatis | `attack_kb.py`, `data/attacks.yaml` | 2.2 | `test_kuk_1_2_*` |
| 1 | 1.3 Best practice metode pengujian | Primitif → standar ISO/IEC & NIST; Daftar Referensi | `standards_kb.py`, `data/standards.yaml` | 2.1 | `test_kuk_1_3_*` |
| 2 | 2.1 Komponen berpotensi lemah | Dekomposisi + hitung langsung NL, DDT, LAT, derajat, SAC, titik tetap, branch number/MDS, avalanche per ronde, BM, padding, kapasitas sponge, primalitas, Wiener/Boneh–Durfee, oracle OAEP, validasi kurva/kunci, bias nonce, malleability | `decompose.py`, `component_analysis.py`, `core/boolean.py` | 3 | `test_core_components.py`, `test_kuk_2_1_*` |
| 2 | 2.2 Best practice vs potensi kelemahan | Matriks Komponen → Kelemahan → Metode → Standar; 3 lapis × 3 level; penyesuaian akses | `mapping.py`, `data/methods.yaml` | 4 | `test_kuk_2_2_*` |
| 2 | 2.3 Kesesuaian sumber daya internal | Benchmark ops/detik, estimasi 2^k ÷ ops/detik, LAYAK / VERSI TEREDUKSI / TIDAK LAYAK, SDM/tools | `resources.py` | 5 | `test_kuk_2_3_*` |
| 3 | 3.1 Penetapan metode | Skor relevansi × kelayakan × akses; alasan pilih/tolak | `selector.py` | 6.1 | `test_uk1_ek3.py::test_kuk_3_1_*` |
| 3 | 3.2 Penetapan parameter | KAT, MCT, avalanche, SP 800-22 (100 × 10⁶ bit, α = 0,01, ambang proporsi), TVLA \|t\| > 4,5, ronde tereduksi, dll. | `parameters.py` | 6.2 | `test_kuk_3_2_*` |
| — | Keterlacakan | K-xx / I-xx → objek → metode → rujukan → kriteria lulus | `traceability.py` | 7 | `test_traceability_*` |

## 📤 Keluaran (`outputs/uk1/<algoritma>/`)

| File | Isi |
|---|---|
| `uk1_penetapan_metode.json` | Struktur lengkap (profil, referensi, serangan, komponen, matriks, sumber daya, metode, parameter, keterlacakan) + blok `handoff_uk2` — **masukan UK-2** |
| `UK1_Dokumen_Penetapan_Metode.md` / `.docx` | Dokumen bukti unjuk kerja, Bab 1–8 |
| `matriks_pemetaan.csv` | Matriks komponen–kelemahan–metode |
| `matriks_keterlacakan.csv` | Matriks keterlacakan |
| `outputs/uk1/index.json` | Indeks semua algoritma (dipakai dashboard) |

Contoh keluaran singkat (`make run`):

```
■ AES-128 (Block cipher)
  KAT core/          : [LULUS] 6/6
  Berpotensi lemah   : C-IMPL-TBL
  Perlu perhatian    : C-MODE, C-API, C-MEM, C-PLAT
  Metode terpilih    : 16 → M-FUZZ, M-NONCE, M-SP80022, M-TIMING, M-ZEROIZE, M-AVAL, M-DIFFUSION, M-RNG,
                            M-SBOX, M-KEYSIZE, M-DIFF*, M-INT*, M-LIN*, M-KAT, M-MCT, M-SELFTEST
  Metode ditolak     : 5 → M-BRUTE, M-CACHE, M-TVLA, M-FAULT, M-CODEREVIEW
■ RSA-OAEP-2048 (PKC)
  KAT core/          : [LULUS] 12/12
  Metode terpilih    : 12 → M-FUZZ, M-ORACLE, M-PKV, M-TIMING, … , M-FACT*, M-KAT, M-SELFTEST
(* = varian ronde/ukuran tereduksi)
```

Nilai acuan yang dijadikan unit test (HASIL UJI LANGSUNG): AES S-box **NL = 112, DU = 4, derajat = 7**,
MixColumns **branch number = 5 (MDS)**; χ Keccak **DU = 8, derajat = 2**.

## 🏷️ Konvensi sumber data

- **HASIL UJI LANGSUNG** — dihitung oleh kode pada saat eksekusi.
- **HASIL LITERATUR** — dikutip dari rujukan (`data/attacks.yaml`, `data/standards.yaml`).
- **KLAIM PROFIL** — berasal dari profil produk (grey box; wajib diverifikasi oleh metode terpilih).
- **`PERLU_VERIFIKASI`** — angka/klaim literatur yang wajib dicek ke sumber primer sebelum dikutip resmi.

## 📝 Catatan

**Asumsi**
- Produk, vendor, dan klaim implementasi (mis. AES berbasis tabel, nonce 64-bit) bersifat **ilustratif**.
- Benchmark memakai implementasi referensi pure Python → estimasi waktu adalah **batas atas konservatif**
  (`resources.speedup_factor` dapat dinaikkan untuk implementasi teroptimasi).
- Kunci RSA sampel dibangkitkan dengan RNG uji deterministik (seed) agar hasil dapat direproduksi —
  hanya untuk telaah, bukan kunci produksi.
- Implementasi `core/` tidak constant-time dan **tidak untuk produksi**; pengukuran timing pada `core/`
  bersifat indikatif, produk diuji melalui M-TIMING / M-ORACLE.

**Bertanda `PERLU_VERIFIKASI`** (lihat Bab 2 dokumen): kompleksitas integral 6 ronde AES (A-BC-05),
impossible differential/MITM 7 ronde (A-BC-06), DFA (A-BC-11), ChaCha PNB / differential-linear (A-SC-02/03),
preimage Keccak ronde tereduksi & zero-sum (A-H-04/05), jumlah query Manger & ROBOT (A-P-06/07),
HNP/Minerva (A-D-03), contoh timing Keyczar (A-L-01), serta tahun terbit SP 800-90C, SP 800-232, ISO/IEC 17825.

**Saran pengembangan untuk UK-2 (Menyusun Skenario Pengujian)**
- Baca `handoff_uk2` di `uk1_penetapan_metode.json`: setiap metode terpilih sudah membawa target komponen,
  varian (penuh/tereduksi), parameter terukur, dan ID kebutuhan (K-xx/I-xx).
- Turunkan tiap metode menjadi skenario (prakondisi, langkah, data uji, hasil yang diharapkan) sesuai
  ISO/IEC/IEEE 29119-3, lalu jadwalkan terhadap kapasitas jam-orang dari KUK 2.3.
- Implementasi eksekutor SP 800-22 lengkap (15 uji) dan harness dudect di `core/` agar dapat dipakai UK-3+.

## 🌐 Deploy

Dashboard statis (`web/`) membaca `outputs/uk1/*.json`. `vercel.json` dan `netlify.toml` menjalankan
`python3 scripts/build_site.py` dan mempublikasikan folder `site/`.

---
Dibuat oleh **Dea Saka Kurnia Putra** — Pelatihan Sertifikasi *Cryptographic Analyst* Angkatan 1.
Lisensi MIT.
