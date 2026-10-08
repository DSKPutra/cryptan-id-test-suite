"""Pemeriksa rumusan kesimpulan (materi slide 40): tolak klaim berlebihan, sarankan rumusan terukur."""
import re

FORBIDDEN = [
    (r"\bproduk\s+(ini\s+)?(sudah\s+|telah\s+)?aman\b", "Klaim 'produk aman' melebihi bukti pengujian"),
    (r"\b(100\s*%|sepenuhnya|benar-benar|pasti|dijamin)\s+aman\b", "Klaim keamanan mutlak tidak dapat dibuktikan oleh pengujian"),
    (r"\b(terbukti|dipastikan|dijamin)\s+(benar-benar\s+)?acak\b", "Uji statistik hanya dapat menolak keacakan, tidak membuktikannya"),
    (r"\bacak\s+sempurna\b", "Uji statistik hanya dapat menolak keacakan, tidak membuktikannya"),
    (r"\b(tidak\s+dapat|mustahil)\s+(dibobol|diretas|ditembus)\b", "Klaim tidak dapat dibobol melebihi ruang lingkup uji"),
    (r"\bbebas\s+(celah|kerentanan|bug)\b", "Tidak ditemukannya celah bukan bukti tidak adanya celah"),
    (r"\bsecure\b|\bfully\s+secure\b", "Klaim 'secure' melebihi bukti pengujian"),
]
SUGGESTIONS = ["Pada versi X, dengan metode Y, 42 dari 46 TC lulus.",
               "Tidak ditemukan bukti ketidakacakan pada uji SP 800-22 (m barisan × n bit).",
               "Batasi kesimpulan pada versi produk, metode, dan test case yang dijalankan."]


def check(text: str) -> dict:
    issues = []
    for pat, why in FORBIDDEN:
        for m in re.finditer(pat, text, flags=re.IGNORECASE):
            issues.append({"kutipan": m.group(0), "alasan": why})
    return {"teks": text, "diterima": not issues, "masalah": issues, "saran": SUGGESTIONS if issues else []}
