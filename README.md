# 🔐 Cryptan.ID Test Suite

**Cryptan.ID Test Suite** adalah perangkat pengujian produk kriptografi untuk praktikum
**Pelatihan Sertifikasi Cryptographic Analyst (CA) Angkatan 1 — Politeknik Siber dan Sandi Negara**.
Repositori ini dibangun bertahap per Unit Kompetensi (UK-1 s.d. UK-8); setiap UK menghasilkan
**JSON terstruktur** yang menjadi masukan UK berikutnya.

| Modul | Unit | Status |
|---|---|---|
| **algo_catalog** | Daftar Algoritma yang Diuji — melengkapi UK-1 KUK 1.1 | ✅ selesai (`algo_catalog/`) |
| **UK-1** | J.61KRP00.012.1 — Menentukan Metode Pengujian yang akan Dilakukan | ✅ selesai (`uk1_metode/`) |
| **UK-2** | J.61KRP00.013.1 — Menyusun Skenario Pengujian | ✅ selesai (`uk2_skenario/`) |
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
make test           # 214 unit test (pytest)
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
├── algo_catalog/                 # Daftar Algoritma yang Diuji (UK-1 KUK 1.1) — lihat bagian khusus di bawah
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
├── std_report/                   # Daftar algoritme standar + 11 uji + laporan PDF/HTML/XLSX (lihat bagian khusus)
│   ├── catalog.py runner.py kat.py sp80022.py tests/{k,s,i}.py schema/ vectors/
│   └── report/{theme.yaml,template.py,builder.py,model.py,export.py} · app.py (Streamlit) · __main__.py (CLI)
├── core/adapters/                # pyca · pycryptodome · stdlib · core · liboqs (opsional) — akses implementasi untuk std_report
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


## 🗂️ Modul `algo_catalog/` — Daftar Algoritma yang Diuji (UK-1 KUK 1.1)

Menyusun daftar lengkap algoritma yang akan diuji, berikut **semua varian** (mode, kurva, parameter set,
panjang digest) dan **semua varian panjang kuncinya**. Ada tiga cara input yang bisa digabung:

```mermaid
flowchart LR
  L["🔗 Link<br/>URL web / PDF"] --> X["Ekstraksi teks<br/>(HTML · PDF)"]
  F["📄 File<br/>PDF · DOCX · XLSX · CSV · JSON · YAML · TXT · MD · source code"] --> X
  X --> N["Normalisasi alias → ID kanonik<br/>+ skor keyakinan & bukti"]
  D["🗂️ Dropdown<br/>Primitif → Algoritma → Varian → Kunci"] --> G
  N --> C{"Konfirmasi<br/>pengguna"} --> G["Gabung · dedup · peringatan"]
  S["Katalog: seed YAML + cache scraping NIST"] -.-> N & D
  G --> O["outputs/algo_catalog/<br/>algorithms_under_test.yaml · .md · .csv · .xlsx"]
  O -->|tautan otomatis| P["config/product_profile.yaml → UK-1"]
```

| Komponen | File |
|---|---|
| Model data (`id`, `primitive`, `family`, `variant`, `key_bits`, `security_strength_bits`, `status_nist`, `standards`, `aliases`, `source`) | `algo_catalog/schema.py` |
| Katalog awal (offline) — 128 entri / 225 kombinasi | `algo_catalog/data/catalog_seed.yaml` |
| Cache hasil scraping (tanggal + URL sumber) | `algo_catalog/data/catalog_cache.json` |
| Sumber scraping (ACVP, CAVP, SP 800-131A, SP 800-57, IR 8547, ISO opsional) | `config/sources.yaml`, `algo_catalog/scraper.py` |
| Normalisasi alias & deteksi teks (stdlib, juga jalan di browser via Pyodide) | `algo_catalog/normalize.py` |
| Opsi Link (robots.txt, User-Agent, jeda) · File (parser per tipe) · Dropdown | `link.py` · `extract.py` · `picker.py` |
| Gabung/dedup/konfirmasi/peringatan · keluaran | `selection.py` · `output.py` |
| GUI Streamlit · CLI | `app.py` · `__main__.py` |
| Contoh input & keluaran | `samples/input/`, `samples/output/opsi_{file,dropdown,link}/` |

**Menjalankan**

```bash
make catalog-scrape                         # python -m algo_catalog scrape --refresh (offline → seed)
python -m algo_catalog list --tree          # tampilkan katalog (--primitive hash, dst.)
python -m algo_catalog select --url https://pages.nist.gov/ACVP/
python -m algo_catalog select --file samples/input/CryptoService.java --interactive
python -m algo_catalog select --pick "AES:GCM:128,256" "ECDSA:P-384" "ML-KEM:768" "AES:*"
make catalog                                # daftar produk dari samples (file + dropdown) → tautkan ke UK-1
make catalog-gui                            # streamlit run algo_catalog/app.py
```

Hasil deteksi otomatis (link/file) **wajib dikonfirmasi**:
- **`--interactive`:** konfirmasi satu per satu.
- **`--yes`:** terima otomatis deteksi dengan keyakinan ≥ `--min-confidence` (default 0,6).
- **Tanpa keduanya:** deteksi masuk bagian "kandidat belum dikonfirmasi".

Normalisasi menangani alias dengan maupun tanpa panjang kunci:
- `aes256gcm`, `AES/GCM/NoPadding` + kunci 256 (parameter `--key-bits` atau konteks `kg.init(256)`), dan `EVP_aes_256_gcm` → `AES-256-GCM`.
- `RSA/ECB/OAEPWithSHA-256…` + `initialize(3072)` → `RSA-OAEP-3072`.
- `ec.SECP384R1()` + "ECDSA" di dekatnya → `ECDSA-P384` dengan keyakinan lebih tinggi daripada `ECDH-P384`.

Contoh keluaran `make catalog`:

```
Daftar akhir: 33 kombinasi · Block cipher 6, Stream cipher 2, Fungsi hash / XOF 7, MAC / AEAD ringan 4,
              PKC / KEM / key agreement 7, Tanda tangan digital 6, DRBG 1
Peringatan: 6 tinggi · 10 sedang (rentan kuantum)
  ⚠ PRESENT-80: security strength 80 bit < 112 bit (SP 800-57 Pt.1)
  ⚠ TDEA-3KEY: status NIST disallowed (SP 800-131A Rev.2)
  ⚠ SHA-1: status NIST disallowed (SP 800-131A Rev.2)
  ⚠ RSAES-PKCS1-V1_5-1024: status NIST disallowed (SP 800-131A Rev.2)
  → outputs/algo_catalog/algorithms_under_test.yaml  (+ .json, Daftar_Algoritma_Uji.md/.csv/.xlsx)
  → config/product_profile.yaml  (ditautkan: algorithms_under_test)
```

Dashboard web (`katalog.html`) menyediakan opsi Dropdown dan deteksi File/teks di browser. Deteksi memakai
`normalize.py` yang sama melalui Pyodide.

**Asumsi algo_catalog**
- Status NIST dan security strength di seed dikurasi manual dari SP 800-131A Rev.2, SP 800-57 Pt.1 Tabel 2,
  SP 800-56A Rev.3/56B Rev.2 App. D (FFC/IFC > 3072), dan FIPS 202–205. Scraping hanya menambah entri baru
  (bertanda `PERLU_VERIFIKASI`) dan mencatat bukti `seen_in`; status di seed tidak diubah otomatis.
- `key_bits` untuk HMAC = panjang kunci HMAC yang umum. Untuk cSHAKE/KMAC = varian keamanan. Untuk LMS/XMSS = panjang hash *n*.
  Untuk DRBG = security strength instansiasi. Untuk XTS = 2 × kunci AES.
- Deteksi berbasis alias/regex. Penyebutan famili tanpa varian (mis. "AES-256" saja) tidak dipetakan;
  pilih variannya lewat Dropdown.
- Opsi Link di browser terbatas CORS; gunakan CLI/GUI untuk halaman non-CORS dan PDF.

**Entri bertanda `PERLU_VERIFIKASI`:**
- **Status NIST:** AES-FF3-1 (draf SP 800-38G Rev.1 mengusulkan penghapusan), AES-GCM-SIV, X25519/X448 (key agreement).
- **Security strength:** Poly1305, RC4, LMS/HSS, XMSS, HKDF, SP 800-108 KDF, PBKDF2.
- **Hasil scraping:** seluruh entri tambahan dari ACVP.

## 🧪 Modul `uk2_skenario/` — UK-2 Menyusun Skenario Pengujian (J.61KRP00.013.1)

**Bukti unjuk kerja:** skenario pengujian produk kriptografi. **Aspek kritis:** ketepatan memverifikasi skenario
terhadap spesifikasi desain produk, ditangani `verifier.py`.

```mermaid
flowchart LR
  P["config/product_profile.yaml<br/>+ algorithms_under_test"] --> R1["KUK 1.1 method_review<br/>4 kebutuhan SKKNI"]
  U["outputs/uk1 (UK-1)"] --> R1
  P --> R2["KUK 1.2 param_space<br/>5 kelas · EP/BVA/DEG/BIT/NEG · pairwise"]
  T["templat materi PPTX<br/>(data/templates.yaml, recipes.yaml)"] --> D
  R1 & R2 --> D["KUK 2.1 designer<br/>3 lapis × 3/4 tingkat"]
  D --> V{"KUK 2.2 verifier<br/>aturan a–f"}
  V --> TC["KUK 2.3 testcase"] & EX["KUK 2.4 expected<br/>core/ + vektor resmi"]
  TC & EX --> C["KUK 2.5 compiler<br/>dokumen · keterlacakan · pemetaan hasil"]
  C --> O["outputs/uk2/uk2_skenario.json → runner UK-3"]
```

| KUK | Modul | Isi | Bab | Test |
|---|---|---|---|---|
| 1.1 | `method_review.py` | Telaah metode UK-1 terhadap jenis algoritma, desain/implementasi, tren serangan, dan best practice; penempatan sel lapis × tingkat; sel kosong; metode tidak relevan | 2 | `test_kuk_1_1_*` |
| 1.2 | `param_space.py` | 5 kelas parameter, Tetap/Variabel; partisi ekuivalensi, nilai batas, degeneratif, 1-bit, negatif; reduksi pairwise IPOG (mis. hash 2.449.440.000 → 149) | 1, 2 | `test_kuk_1_2_*` |
| 2.1 | `designer.py`, `data/recipes.yaml` | Matriks 3 lapis × 3/4 tingkat dari templat 6 kategori; lintas-algoritma (RNG → keygen → KDF → cipher/MAC/signature → protokol → produk), siklus hidup kunci, kondisi operasional, PQC; area 19790 | 3 | `test_kuk_2_1_*` |
| 2.2 | `verifier.py` | Aturan (a) cakupan, (b) nilai di luar spesifikasi hanya negatif, (c) klaim → skenario keamanan, (d) metode UK-1, (e) 11 area 19790/SL, (f) fitur tidak dimiliki | 4 | `test_kuk_2_2_*` |
| 2.3 | `testcase.py`, `schema/` | ID `<KAT>-<K/S/I>-nn` / `<U/I/S/A>-<K/S/I>-nn`, langkah bernomor, prasyarat, pelaksana, objek `runner` UK-3, JSON Schema | 5 | `test_kuk_2_3_*` |
| 2.4 | `expected.py`, `data/vectors/` | Expected deterministik dihitung `core/` atau pustaka tepercaya lalu dicocokkan ke vektor resmi; kriteria statistik/kriptanalitik/implementasi/negatif; SHA-256 per berkas | 6 | `test_kuk_2_4_*` |
| 2.5 | `compiler.py` | Dokumen Bab 1–9 (+ tata kelola model 4), CSV/XLSX, keterlacakan, pemetaan parameter → hasil | 7, 8 | `test_kuk_2_5_*` |

**Menjalankan**

```bash
python -m uk2_skenario --profile config/product_profile.yaml --uk1 outputs/uk1/uk1_penetapan_metode.json   # (= folder outputs/uk1)
make uk2-samples        # 3 sampel materi: samples/uk2/{ecdsa_p256_token,tls13_gateway,hsm_x_sl3}/output
make uk2-templates      # ekstrak ulang templat dari PPTX lokal di docs/materi/ (tidak di-commit)
```

Keluaran `outputs/uk2/`:
- `uk2_skenario.json`: dapat dieksekusi runner UK-3; skema di `uk2_skenario/schema/`.
- `UK2_Dokumen_Skenario_Pengujian.md` dan `.docx`.
- `test_cases.csv` dan `.xlsx`, `matriks_keterlacakan.csv`, `laporan_verifikasi.md`.
- `expected/*.json` dan `expected/MANIFEST.json` (berisi SHA-256 tiap berkas).

```
■ produk — model 3 tingkat · 33 objek uji
  KUK 1.1 metode UK-1   : 27 ditelaah, 27 relevan, 21 sel kosong → templat
  KUK 1.2 pairwise      : block 9.408→60, stream 24→12, hash 2.449.440.000→149, pke 315→35, signature 1.296→54
  KUK 2.2 verifikasi    : LULUS (0 temuan) — (a)L (b)L (c)L (d)L (e)T (f)L
  KUK 2.3 test case     : 91 (K 32 · S 35 · I 24)
  KUK 2.4 expected      : 25 cocok vektor resmi · 381 kriteria · 39 PERLU_VERIFIKASI
```

**Uji reproduksi materi.** Ketiga sampel menghasilkan seluruh test case contoh materi:
- **ECDSA P-256 token:** DS-K/S/I-01..06.
- **TLS 1.3 gateway:** PR-K/S/I-01..06.
- **HSM-X SL 3:** 48 test case U/I/S/A.

Parameter, prosedur, dan kriteria test case tersebut sama dengan materi. Matriks cakupan area 7.2–7.12 HSM-X identik dengan
tabel materi. Selama pengembangan, verifier menemukan celah nyata yang kemudian ditutup. Contohnya klaim constant-time
tanpa skenario keamanan (kini XA-S-04) dan klaim "kunci tidak dapat diekspor" pada token (kini DS-S-09).

**Expected value yang cocok dengan vektor resmi** (semua 100%):
- **Blok & stream:** AES (FIPS 197, SP 800-38A F.1.1/F.5.1), ChaCha20 (RFC 8439), AES-GCM, ChaCha20-Poly1305, AES-KW.
- **Hash & MAC:** SHA-2/SHA-3/SHAKE/BLAKE2b ("abc"), HMAC-SHA-256, CMAC.
- **PKC & tanda tangan:** RSA-OAEP 2048/3072 (PKCS#1 + Wycheproof), ECDH P-384, X25519, Ed25519, ECDSA P-256 (RFC 6979 dan
  516 vektor SigVer: 484 Wycheproof + 32 mutasi encoding).
- **Protokol:** TLS 1.3 key schedule (RFC 8448, 22 operasi HKDF).

Vektor Wycheproof: C2SP/wycheproof (Apache-2.0), lisensi di `uk2_skenario/data/vectors/`.

**`PERLU_VERIFIKASI` (tidak dikarang):**
- **KAT tanpa vektor resmi yang dimuat:** ML-KEM-768, ML-DSA-65, SLH-DSA, RSA-PSS-3072, XTS-AES-256, PRESENT-80, TDEA,
  Ascon-AEAD128, FFDHE3072, ECDSA P-384 (titik/domain/SigVer). Perlu vektor ACVP/CAVP.
- **Kinerja:** produk belum mencantumkan klaim kinerja.
- **TLS:** suite SHA-384 (RFC 8448 hanya memuat jejak SHA-256), analisis formal (model Tamarin belum dibuat), dan spesifikasi hybrid
  X25519MLKEM768.

**Saran antarmuka untuk UK-3 (Melakukan Pengujian):**
- Baca `uk2_skenario.json` → `test_cases[].runner`, lalu cocokkan `action` ke eksekutor. Contoh: `kat_vectors`/`sigver_vectors`
  membaca `expected_files`, menjalankan produk (adapter C API/PKCS#11/pyca), lalu membandingkan per vektor.
- Verifikasi SHA-256 berkas expected terhadap `expected/MANIFEST.json` sebelum eksekusi.
- Catat hasil per nilai parameter, lalu petakan ke `outcome_map` (Memenuhi / Memenuhi dengan Catatan / Tidak Memenuhi / Inkonklusif).
- Aksi `manual` menghasilkan checklist bukti.
- Antarmuka adapter yang disarankan: `encrypt/decrypt/sign/verify/keygen/hash(target, inputs) → output | error_code`.

## 📑 Modul `std_report/` — Daftar Algoritme Standar + Hasil Semua Uji + Export PDF

Daftar lengkap algoritme dari **FIPS**, **NIST SP 800**, dan **ISO/IEC** (satu baris = algoritme × varian × panjang kunci),
lalu **11 uji** (lapis K kesesuaian, S keamanan, I implementasi) dijalankan lewat `core/adapters/`
(pyca/cryptography, pycryptodome, hashlib, `core/` referensi, liboqs opsional). Semua hasil masuk ke **satu berkas**
`outputs/std_report/results.json` (divalidasi JSON Schema), dan laporan PDF/HTML/XLSX dibuat **hanya** dari berkas itu.

```bash
python -m std_report list   --source iso-iec --primitive hash   # daftar algoritme
python -m std_report run    [--mode ringan|full] [--only AES,SHA3]  # semua uji → results.json (ringan ≈ 1,5–4 menit)
python -m std_report report --pdf --html --xlsx [--ringkas] [--only-tested] --penyusun "Nama Penyusun"
python -m std_report all    --pdf --penyusun "Nama Penyusun"     # list + run + report (offline, < 5 menit)
streamlit run std_report/app.py                                   # GUI: filter, jalankan uji, Export to PDF
make std-report                                                   # = all --pdf --html --xlsx
```

| Uji | Isi | Kriteria |
|---|---|---|
| K-01 | KAT vektor resmi (Wycheproof/FIPS/SP/RFC), atau **uji silang** dua backend bila vektor tidak ada | 100% cocok |
| K-02 · K-03 · K-04 | round-trip · MCT / multi-blok / one-shot vs bertahap · uji negatif | 100% · identik · semua ditolak |
| S-01 · S-02 | avalanche · subset SP 800-22 (6 uji) — **indikatif** di mode ringan | ≈ n/2 · proporsi & P-value_T |
| S-03 · S-04 | sifat komponen (AES, χ Keccak) · kecukupan parameter (SP 800-57, SP 800-131A, IR 8547 — ACUAN) | nilai acuan · ≥ 112 bit & acceptable |
| I-01 · I-02 · I-03 | variasi waktu (Welch t, indikatif) · kinerja (DICATAT) · input malformed | \|t\| < 4,5 · — · tanpa crash |

**Hasil mode ringan (seed 20261002):** 219 kombinasi — FIPS 118, NIST SP 800 114, ISO/IEC 142 (satu algoritme bisa
tercantum di beberapa sumber).

| Primitif | Terdaftar | Diuji | Lulus semua | Lulus sebagian | Ada temuan | Tidak dapat diuji |
|---|---:|---:|---:|---:|---:|---:|
| Block cipher | 56 | 48 | 35 | 8 | 5 | 8 |
| Stream cipher | 7 | 2 | 0 | 0 | 2 | 5 |
| Fungsi hash / XOF | 34 | 27 | 15 | 0 | 12 | 7 |
| MAC / AEAD ringan | 31 | 30 | 30 | 0 | 0 | 1 |
| PKC / KEM / key agreement | 31 | 17 | 11 | 0 | 6 | 14 |
| Tanda tangan digital | 44 | 25 | 10 | 3 | 12 | 19 |
| DRBG | 11 | 3 | 0 | 3 | 0 | 8 |
| KDF | 5 | 5 | 0 | 0 | 5 | 0 |
| **Total** | **219** | **157** | **101** | **14** | **42** | **62** |

"Ada temuan" mencakup GAGAL/INKONKLUSIF uji langsung **dan** S-04 (parameter < 112 bit, status legacy, atau kekuatan
`PERLU_VERIFIKASI`). Temuan uji langsung (bukan artefak mesin uji): pycryptodome 3.23 — ECDSA P-224/256/384/521 menerima
tanda tangan Wycheproof "k·G has a large x-coordinate" (tcId 322/350/382/419), Ed448 menerima R dengan y = 1 dan bit tanda x
(tcId 87), PBKDF2 & HKDF menerima panjang keluaran negatif (mengembalikan `b""`).

**Laporan PDF** (ReportLab Platypus; `report/theme.yaml` → `template.py` → `builder.py`): sampul, lembar pengesahan & revisi,
daftar isi/tabel/gambar, Bab 1–7, Lampiran A–D, matriks lanskap, header/footer "Halaman X dari Y", bookmark, header tabel
berulang. Nama berkas `Laporan_Algoritme_Standar_<YYYYMMDD>_<mode>.pdf`. Penyusun diisi pengguna (`--penyusun` / kolom GUI);
instansi XyberXecurity; © Cryptan.ID — made by Dea Saka Kurnia Putra.

> **Klasifikasi TERBATAS.** `outputs/std_report/` dan `samples/std_report/*.pdf` di-*gitignore* dan **tidak** dipublikasikan
> ke dashboard Vercel/Netlify/Lovable. Buat ulang secara lokal dengan perintah di atas.

`algo_catalog/` hanya ditambah dua field (`source_body`, `source_doc`) lewat `scripts/add_source_fields.py`; keanggotaan
dokumen ISO/IEC yang belum pasti ditandai `(PERLU_VERIFIKASI)` dan dikumpulkan di Lampiran C (132 butir, termasuk 79 entri
hasil scraping ACVP).

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
