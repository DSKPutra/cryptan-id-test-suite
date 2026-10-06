"""UK-3 — Melakukan Pengujian Terhadap Produk Kriptografi (J.61KRP00.014.1), Cryptan.ID Test Suite.

Alur: 1 Siapkan (KUK 1.1–1.2) → 2 Jalankan (KUK 2.1–2.2) → 3 Olah data (KUK 3.1) → 4 Simpulkan & laporkan
(KUK 3.2–3.3), ditambah Lab Keacakan. Setiap fungsi diberi komentar KUK yang dipenuhinya.
"""
from pathlib import Path

__version__ = "1.0.0"
UNIT = "J.61KRP00.014.1"
UNIT_TITLE = "Melakukan Pengujian Terhadap Produk Kriptografi"
ROOT = Path(__file__).resolve().parents[1]
PKG = Path(__file__).resolve().parent
OUT = ROOT / "outputs"

# status test case (materi slide 25)
LULUS, GAGAL, TERBLOKIR, TDD = "LULUS", "GAGAL", "TERBLOKIR", "TIDAK DAPAT DIUJI"
TC_STATUSES = [LULUS, GAGAL, TERBLOKIR, TDD]

# kategori kesimpulan per sasaran uji (materi slide 41)
MEMENUHI, MEMENUHI_CATATAN, TIDAK_MEMENUHI, INKONKLUSIF = ("Memenuhi", "Memenuhi dengan Catatan", "Tidak Memenuhi", "Inkonklusif")
CATEGORIES = [MEMENUHI, MEMENUHI_CATATAN, TIDAK_MEMENUHI, INKONKLUSIF]

KUK = {
    "1.1": "Dokumen uji dikumpulkan sesuai kebutuhan pengujian",
    "1.2": "Perangkat pendukung pengujian diinventarisasi sesuai kebutuhan uji",
    "2.1": "Tahapan pengujian diidentifikasi berdasarkan test case pengujian",
    "2.2": "Pengujian diterapkan berdasarkan test case pengujian",
    "3.1": "Data hasil pengujian dianalisis sesuai dengan metode pengujian",
    "3.2": "Kesimpulan ditentukan berdasarkan olah data hasil pengujian",
    "3.3": "Laporan hasil pengujian didokumentasikan berdasarkan data pengujian",
}

DIRECT, LITERATURE, VERIFY = "HASIL UJI LANGSUNG", "ACUAN/LITERATUR", "PERLU_VERIFIKASI"


def rel(p) -> str:
    """Path relatif terhadap root repo (jangan bocorkan path absolut ke keluaran)."""
    p = Path(p).resolve()
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return p.name
