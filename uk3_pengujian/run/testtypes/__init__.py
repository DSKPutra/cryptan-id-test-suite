"""KUK 2.2 — Tujuh jenis uji dan oracle-nya (materi slide 16–18): smoke test, KAT, uji positif, uji negatif,
uji diferensial, uji properti, uji statistik (+ kinerja & timing pada tahap implementasi).

Setiap eksekutor menerima (ctx, tc) dan mengembalikan dict:
  actual (teks hasil aktual), passed (bool), data (data mentah untuk olah data KUK 3.1), metode (nama metode analisis),
  analisis (hasil fungsi analysis.methods), seed (bila ada), batasan (catatan), inconclusive (bool, mis. TVLA tidak konsisten).
Oracle selalu independen dari produk: vektor resmi, spesifikasi, atau implementasi lain."""
import hashlib

EXECUTORS = {}
TYPES = {
    "smoke": "Smoke test — layak diuji lebih lanjut? (spesifikasi dasar)",
    "kat": "KAT — keluaran sesuai standar? (vektor resmi)",
    "positif": "Uji positif — fitur bekerja untuk masukan sah? (spesifikasi)",
    "negatif": "Uji negatif — masukan salah ditolak dengan aman? (spesifikasi, Wycheproof)",
    "diferensial": "Uji diferensial — sama dengan implementasi lain? (implementasi independen)",
    "properti": "Uji properti — invarian selalu berlaku? (sifat matematis)",
    "statistik": "Uji statistik — tampak acak / tidak bocor? (distribusi teoretis)",
    "kinerja": "Kinerja — throughput/latensi (pengukuran berulang)",
    "timing": "Timing — variasi waktu (Welch t, TVLA)",
}


def executor(name):
    def deco(fn):
        EXECUTORS[name] = fn
        return fn
    return deco


class Ctx:
    """Konteks eksekusi satu versi produk: modul, skenario, seed, cache bersama antar-TC."""

    def __init__(self, product_id, version, module, scenario, seed=2026, params=None):
        self.product, self.version, self.mod, self.scenario = product_id, version, module, scenario
        self.seed = seed
        self.params = params or {}
        self.cache = {}

    def rand(self, n: int, tag: str = "") -> bytes:
        out, i = b"", 0
        while len(out) < n:
            out += hashlib.sha256(f"{self.seed}|{tag}|{i}".encode()).digest()
            i += 1
        return out[:n]

    def p(self, tc, key, default=None):
        """Parameter TC: override run (deviasi tercatat) → parameter_statistik → parameter."""
        ov = self.params.get(tc["id"], {})
        if key in ov:
            return ov[key]
        for sect in ("parameter_statistik", "parameter"):
            if key in (tc.get(sect) or {}):
                return tc[sect][key]
        return default


def try_call(fn, *a):
    """Jalankan fn; kembalikan (hasil, None) atau (None, exception)."""
    try:
        return fn(*a), None
    except Exception as e:  # noqa: BLE001 — galat produk adalah data uji
        return None, e


def load_all():
    from . import diferensial, kat, negatif, positif, properti, smoke, statistik, implementasi  # noqa: F401
    return EXECUTORS
