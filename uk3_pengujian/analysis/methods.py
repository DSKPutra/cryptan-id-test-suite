"""KUK 3.1 — Data hasil pengujian dianalisis sesuai metode pengujian. Satu fungsi per metode (materi slide 39).

Fungsi-fungsi ini dipakai eksekutor saat menjalankan TC (keputusan per TC) dan oleh analyze.py untuk
menyusun tabel olah data per metode. Keduanya memakai fungsi yang sama → keputusan konsisten."""
from collections import Counter

from .. import stats
from ..rng import multiseq


def kat(actual_hex: str, expected_hex: str) -> dict:
    """KAT: banding byte demi byte; identik → LULUS."""
    a, e = (actual_hex or "").lower(), (expected_hex or "").lower()
    first = next((i // 2 for i in range(0, min(len(a), len(e)), 2) if a[i:i + 2] != e[i:i + 2]), None)
    if first is None and len(a) != len(e):
        first = min(len(a), len(e)) // 2
    return {"metode": "KAT", "identik": a == e and bool(e), "panjang_aktual": len(a) // 2, "panjang_expected": len(e) // 2,
            "byte_beda_pertama": first, "aturan": "identik byte demi byte → LULUS"}


def negative(cases: list) -> dict:
    """Uji negatif: semua masukan rusak ditolak, tidak ada plaintext keluar, galat seragam per kelompok."""
    n = len(cases)
    rej = sum(1 for c in cases if c.get("rejected"))
    leaked = [c["case"] for c in cases if c.get("plaintext_leaked")]
    groups = {}
    for c in cases:
        if c.get("rejected"):
            groups.setdefault(c.get("group", "default"), set()).add(c.get("error_class"))
    nonuni = {g: sorted(v) for g, v in groups.items() if len(v) > 1}
    return {"metode": "Uji negatif", "ditolak": rej, "total": n, "rejection_rate": rej / n if n else None,
            "semua_ditolak": rej == n and n > 0, "plaintext_bocor": leaked, "kelas_galat": {g: sorted(v) for g, v in groups.items()},
            "galat_seragam": not nonuni, "tidak_seragam": nonuni, "aturan": "semua masukan rusak ditolak dengan galat seragam → LULUS"}


def uniqueness(values: list, label: str = "nilai") -> dict:
    """Keunikan nonce/salt: hitung duplikat dari N enkripsi; 0 duplikat → LULUS."""
    c = Counter(values)
    dup = sum(v - 1 for v in c.values() if v > 1)
    return {"metode": "Keunikan nonce/salt", "label": label, "N": len(values), "unik": len(c), "duplikat": dup, "ok": dup == 0,
            "teks": f"{label} unik {len(c)}/{len(values)}", "aturan": "0 duplikat → LULUS"}


def sp80022(seqs: list, tests=("monobit", "block_frequency", "runs"), block_m=128) -> dict:
    """SP 800-22: proporsi lulus 0,99 − 3√(0,99·0,01/m) dan keseragaman P-value_T ≥ 0,0001."""
    a = multiseq.analyze(seqs, tests, block_m=block_m)
    a["metode"] = "NIST SP 800-22"
    a["ok"] = all(v.get("ok") for v in a["tests"].values() if v.get("runnable"))
    a["aturan"] = "proporsi ≥ batas bawah dan P-value_T ≥ 0,0001 → tidak ditemukan bukti ketidakacakan"
    return a


def timing(fixed: list, random: list) -> dict:
    """Timing (TVLA): Welch t; |t| ≤ 4,5 → tidak ada indikasi kebocoran."""
    r = stats.welch_t(fixed, random)
    r.update({"metode": "Timing (Welch t)", "ok": not r["leak"], "aturan": "|t| ≤ 4,5 → tidak ada indikasi bocor"})
    return r


def performance(times: list, warmup: int = 0, target: float = None) -> dict:
    """Kinerja: rata-rata, simpangan baku, selang kepercayaan 95%, p95; putaran pemanasan dibuang."""
    ci = stats.confidence_interval(times, warmup=warmup)
    ci.update({"metode": "Kinerja", "target": target, "ok": None if target is None else ci["high"] <= target,
               "aturan": "batas atas selang 95% ≤ target → memenuhi"})
    return ci


def avalanche(hds: list, n_bits: int) -> dict:
    """Avalanche: rerata jarak Hamming; z = (rerata − n/2)/(√n/2/√N); |z| ≤ 3 → konsisten ideal."""
    import numpy as np
    x = np.asarray(hds, float)
    r = stats.avalanche_z(float(x.mean()), n_bits, x.size)
    r.update({"metode": "Avalanche", "sd_teramati": float(x.std(ddof=1)), "aturan": "|z| ≤ 3 → tidak ditemukan penyimpangan"})
    return r


def min_entropy(bits) -> dict:
    """Min-entropy: −log2 p_maks (estimasi MCV per bit, SP 800-90B §6.3.1)."""
    r = stats.min_entropy_mcv(bits)
    r.update({"metode": "Min-entropy", "aturan": "H_min = −log₂ p_maks"})
    return r


def rejection_rate(rejected: int, total: int) -> dict:
    return {"metode": "Rejection rate", "ditolak": rejected, "total": total, "ok": rejected == total,
            "teks": f"rejection rate {rejected}/{total}"}


def differential(identical: int, total: int, seed=None) -> dict:
    return {"metode": "Uji diferensial", "identik": identical, "total": total, "seed": seed, "ok": identical == total,
            "teks": f"{identical}/{total} identik"}
