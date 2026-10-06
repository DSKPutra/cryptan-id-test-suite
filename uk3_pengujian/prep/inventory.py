"""KUK 1.2 — Inventarisasi perangkat pendukung & verifikasi alat dengan nilai yang diketahui.

Hasilnya menjadi 'catatan lingkungan' yang ditulis sebagai baris pertama setiap log."""
import datetime as dt
import hashlib
import os
import platform
import shutil
import ssl
import subprocess


def _ver(mod):
    try:
        m = __import__(mod)
        return getattr(m, "__version__", "terpasang")
    except Exception:
        return None


def _cmd(args):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=10).stdout.strip() or None
    except Exception:
        return None


def tools() -> list:
    """Daftar perangkat: wajib (Python, cryptography, OpenSSL, NumPy/SciPy) dan opsional (STS, SageMath, testssl.sh)."""
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend
    sts = shutil.which("assess") or (os.environ.get("NIST_STS_DIR") and os.path.join(os.environ["NIST_STS_DIR"], "assess"))
    openssl_cli = shutil.which("openssl")
    rows = [
        {"perangkat": "Sistem operasi", "versi": f"{platform.system()} {platform.release()} ({platform.machine()})", "wajib": True,
         "dipakai_untuk": "lingkungan uji"},
        {"perangkat": "Python", "versi": platform.python_version(), "wajib": True, "dipakai_untuk": "skrip uji, KAT, uji negatif"},
        {"perangkat": "cryptography (pyca)", "versi": cryptography.__version__, "wajib": True, "dipakai_untuk": "KAT, oracle, AES-GCM"},
        {"perangkat": "OpenSSL (backend cryptography)", "versi": backend.openssl_version_text(), "wajib": True,
         "dipakai_untuk": "pembanding independen hash & enkripsi"},
        {"perangkat": "OpenSSL (ssl Python)", "versi": ssl.OPENSSL_VERSION, "wajib": False, "dipakai_untuk": "hashlib"},
        {"perangkat": "OpenSSL CLI", "versi": _cmd([openssl_cli, "version"]) if openssl_cli else None, "wajib": False,
         "dipakai_untuk": "pemeriksaan silang SHA-256 baris perintah"},
        {"perangkat": "NumPy", "versi": _ver("numpy"), "wajib": True, "dipakai_untuk": "olah data statistik"},
        {"perangkat": "SciPy", "versi": _ver("scipy"), "wajib": True, "dipakai_untuk": "erfc, igamc, distribusi χ²/t"},
        {"perangkat": "pycryptodome", "versi": _ver("Crypto"), "wajib": False, "dipakai_untuk": "implementasi independen (uji diferensial)"},
        {"perangkat": "NIST STS 2.1.2", "versi": "terpasang" if sts and os.path.exists(sts) else None, "wajib": False,
         "dipakai_untuk": "15 uji SP 800-22 resmi (pembaca laporan tersedia di Lab Keacakan)"},
        {"perangkat": "SageMath", "versi": "terpasang" if shutil.which("sage") else None, "wajib": False,
         "dipakai_untuk": "memeriksa parameter kunci publik"},
        {"perangkat": "testssl.sh", "versi": "terpasang" if shutil.which("testssl.sh") else None, "wajib": False,
         "dipakai_untuk": "hanya bila produk memakai TLS"},
    ]
    for r in rows:
        r["status"] = "tersedia" if r["versi"] else ("TIDAK ADA (wajib)" if r["wajib"] else "tidak ada (opsional)")
    return rows


def verify_tools() -> list:
    """Uji coba alat dengan nilai yang diketahui sebelum dipakai (materi slide 12)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    from ..rng import sp80022
    checks = []

    def add(alat, uji, expected, actual, acuan):
        checks.append({"alat": alat, "uji": uji, "expected": expected, "actual": actual, "lulus": expected == actual, "acuan": acuan})

    add("hashlib (OpenSSL)", 'SHA-256("abc")', "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        hashlib.sha256(b"abc").hexdigest(), "FIPS 180-4 / materi slide 18")
    enc = Cipher(algorithms.AES(bytes.fromhex("000102030405060708090a0b0c0d0e0f")), modes.ECB()).encryptor()
    add("cryptography", "AES-128 FIPS 197 C.1", "69c4e0d86a7b0430d8cdb78070b4c55a",
        (enc.update(bytes.fromhex("00112233445566778899aabbccddeeff")) + enc.finalize()).hex(), "FIPS 197 Lampiran C.1")
    add("uk3 SP 800-22", "monobit ε = 1011010101", "0.527", f"{sp80022.monobit('1011010101', enforce_min=False)['p_value']:.3f}",
        "SP 800-22 §2.1.4 / materi slide 29")
    add("uk3 SP 800-22", "runs ε = 1001101011", "0.147", f"{sp80022.runs('1001101011', enforce_min=False)['p_value']:.3f}",
        "SP 800-22 §2.3.4 / materi slide 30")
    add("uk3 SP 800-22", "block frequency ε = 0110011010, M = 3", "0.801",
        f"{sp80022.block_frequency('0110011010', M=3, enforce_min=False)['p_value']:.3f}", "SP 800-22 §2.2.4 / materi slide 31")
    cli = shutil.which("openssl")
    if cli:
        try:
            out = subprocess.run([cli, "dgst", "-sha256"], input=b"abc", capture_output=True, timeout=10).stdout.decode()
            add("OpenSSL CLI", 'openssl dgst -sha256 "abc"', "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                out.strip().split()[-1] if out else "", "FIPS 180-4")
        except Exception:
            pass
    return checks


def environment_note(inv=None, checks=None) -> str:
    """Satu baris catatan lingkungan (baris pertama setiap log)."""
    inv = inv or tools()
    checks = checks if checks is not None else verify_tools()
    v = {r["perangkat"]: r["versi"] for r in inv}
    ok = sum(c["lulus"] for c in checks)
    return (f"# {dt.datetime.now().astimezone().isoformat(timespec='seconds')} | {v['Sistem operasi']} | Python {v['Python']} | "
            f"cryptography {v['cryptography (pyca)']} | {v['OpenSSL (backend cryptography)']} | NumPy {v['NumPy']} | SciPy {v['SciPy']} | "
            f"alat terverifikasi {ok}/{len(checks)}")


def inventory() -> dict:
    inv, checks = tools(), verify_tools()
    missing = [r["perangkat"] for r in inv if r["wajib"] and not r["versi"]]
    return {"perangkat": inv, "verifikasi": checks, "lengkap": not missing, "kurang": missing,
            "terverifikasi": all(c["lulus"] for c in checks), "catatan_lingkungan": environment_note(inv, checks)}
