"""KUK 2.3 — Kesesuaian dengan sumber daya internal.

(a) Benchmark mesin lab: operasi/detik implementasi referensi.
(b) Estimasi waktu tiap metode: 2^k ÷ (ops/detik × core × speedup).
(c) Status LAYAK / LAYAK VERSI TEREDUKSI / TIDAK LAYAK.
(d) Kecocokan SDM, jadwal, dan tools dari profil.
"""
import json
import math
import os
import platform
import time
from pathlib import Path

from core import aes, chacha20, ecdsa_p256 as ec, keccak, rsa_oaep

LAYAK, REDUKSI, TIDAK = "LAYAK", "LAYAK VERSI TEREDUKSI", "TIDAK LAYAK"
YEAR = 365.25 * 86400


def _rate(fn, min_time=0.25, min_iter=3) -> float:
    n, t0 = 0, time.perf_counter()
    while True:
        fn()
        n += 1
        el = time.perf_counter() - t0
        if el >= min_time and n >= min_iter:
            return n / el


def _rsa_test_key():
    d = json.loads((Path(rsa_oaep.__file__).parent / "vectors" / "rsa_oaep_pkcs1.json").read_text())
    k = d["keys"][-1]["key"]
    return rsa_oaep.PrivateKey(*(int(k[x], 16) for x in ("n", "e", "d", "p", "q")))


def benchmark(profile: dict, quick: bool = False) -> dict:
    """(a) Benchmark operasi utama algoritma pada mesin ini (HASIL UJI LANGSUNG)."""
    prim = profile["algorithm"]["primitive"]
    mt = 0.1 if quick else 0.4
    ops = {}
    if prim == "block_cipher":
        k, b = bytes(16), bytes(16)
        ops["encrypt"] = _rate(lambda: aes.encrypt_block(k, b), mt)
        ops["primary"] = ops["encrypt"]
    elif prim == "stream_cipher":
        k, n = bytes(32), bytes(12)
        ops["encrypt"] = _rate(lambda: chacha20.block(k, 1, n), mt)
        ops["primary"] = ops["encrypt"]
    elif prim == "hash":
        m = bytes(64)
        ops["hash"] = _rate(lambda: keccak.sha3_256(m), mt)
        ops["primary"] = ops["hash"]
    elif prim == "pkc":
        kp = _rsa_test_key()
        ct = rsa_oaep.encrypt(kp.public(), b"benchmark")
        ops["public_op"] = _rate(lambda: rsa_oaep.encrypt(kp.public(), b"benchmark"), mt)
        ops["private_op"] = _rate(lambda: rsa_oaep.decrypt(kp, ct), mt)
        ops["primary"] = ops["public_op"]
    elif prim == "dss":
        d = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
        Q = ec.public_key(d)
        sig = ec.sign(d, b"benchmark")
        ops["sign"] = _rate(lambda: ec.sign(d, b"benchmark"), mt)
        ops["verify"] = _rate(lambda: ec.verify(Q, b"benchmark", sig), mt)
        ops["point_add"] = _rate(lambda: ec.point_add(ec.G, Q), mt)
        ops["primary"] = ops["sign"]
    return {
        "source": "HASIL UJI LANGSUNG",
        "implementation": "referensi pure Python (core/) — batas bawah konservatif",
        "machine": {"python": platform.python_version(), "system": f"{platform.system()} {platform.machine()}",
                    "processor": platform.processor() or platform.machine(), "logical_cpus": os.cpu_count()},
        "ops_per_sec": {k: round(v, 2) for k, v in ops.items()},
    }


def human_time(seconds: float) -> str:
    if seconds == 0:
        return "0 detik (analitis)"
    if seconds < 60:
        return f"{seconds:.2f} detik"
    if seconds < 3600:
        return f"{seconds / 60:.1f} menit"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} jam"
    if seconds < YEAR:
        return f"{seconds / 86400:.1f} hari"
    y = seconds / YEAR
    return f"{y:.1f} tahun" if y < 1e6 else f"2^{math.log2(y):.1f} tahun"


def _ops_log2(cost: dict, profile: dict) -> float:
    if "bits" in cost:
        per = profile["algorithm"]["parameters"].get("output_bits_per_op", 256)
        return math.log2(cost["bits"] / per)
    return float(cost.get("ops_log2", 0))


def _seconds(ops_log2: float, rate: float, res: dict) -> float:
    cores = res["compute"].get("cores", 1) * res["compute"].get("machines", 1)
    speed = res.get("speedup_factor", 1)
    log_s = ops_log2 - math.log2(rate * cores * speed)
    return math.inf if log_s > 1000 else 2 ** log_s


def estimate(method: dict, profile: dict, bench: dict) -> dict:
    """(b)+(c) Estimasi waktu, data, memori & status kelayakan satu metode."""
    res = profile["resources"]
    cost = method["cost"]
    rates = bench["ops_per_sec"]
    op = cost.get("op", "primary")
    if op != "analysis" and op not in rates:
        op = "primary"
    rate = rates.get(op, rates["primary"])
    budget = res["method_budget_hours"] * 3600
    missing = [t for t in cost.get("tools", []) if t not in res["tools_available"]]

    if op == "analysis":
        k, sec = _ops_log2(cost, profile), 0.0
    else:
        k = _ops_log2(cost, profile)
        sec = _seconds(k, rate, res)
    out = {
        "method_id": method["id"], "op": op, "ops_per_sec": rate, "ops_log2": round(k, 2),
        "seconds": sec, "time_human": human_time(sec) if sec != math.inf else "∞",
        "log2_seconds": round(math.log2(sec), 1) if 0 < sec < math.inf else None,
        "data": f"2^{k:.1f} operasi/sampel" if op != "analysis" else "—",
        "memory": ("≈ %.1f MB" % (cost["bits"] / 8 / 1e6)) if "bits" in cost else ("≤ 2^%d B" % min(40, max(10, int(k) // 2 + 6)) if op != "analysis" else "—"),
        "effort_h": cost.get("effort_h", 0), "missing_tools": missing, "budget_seconds": budget, "reduced": None,
    }
    red = cost.get("reduced")
    if missing:
        red_missing = [t for t in (red or {}).get("tools", cost.get("tools", [])) if t not in res["tools_available"]]
        if red and not red_missing:
            rs = _seconds(red["ops_log2"], rate, res)
            out["reduced"] = {"desc": red["desc"], "ops_log2": red["ops_log2"], "seconds": rs, "time_human": human_time(rs)}
            if rs <= budget:
                out.update(status=REDUKSI, reason=f"Alat versi penuh tidak tersedia ({', '.join(missing)}); versi tereduksi {human_time(rs)}")
                return out
        out.update(status=TIDAK, reason=f"Alat tidak tersedia: {', '.join(missing)}")
        return out
    if sec <= budget:
        out.update(status=LAYAK, reason=f"Estimasi {out['time_human']} ≤ anggaran {res['method_budget_hours']} jam")
        return out
    if red:
        rs = _seconds(red["ops_log2"], rate, res)
        out["reduced"] = {"desc": red["desc"], "ops_log2": red["ops_log2"], "seconds": rs, "time_human": human_time(rs)}
        if rs <= budget:
            out.update(status=REDUKSI, reason=f"Versi penuh {out['time_human']} > anggaran; versi tereduksi {human_time(rs)}")
            return out
    out.update(status=TIDAK, reason=f"Estimasi {out['time_human']} melebihi anggaran {res['method_budget_hours']} jam, tanpa varian tereduksi layak")
    return out


def capacity(profile: dict) -> dict:
    """(d) Kapasitas SDM & jadwal."""
    r = profile["resources"]
    people = sum(p["count"] for p in r["personnel"])
    return {"personnel": r["personnel"], "people": people, "schedule_days": r["schedule_days"],
            "hours_per_day": r["hours_per_day"], "person_hours": people * r["schedule_days"] * r["hours_per_day"],
            "compute": r["compute"], "tools_available": r["tools_available"],
            "method_budget_hours": r["method_budget_hours"], "speedup_factor": r.get("speedup_factor", 1)}
