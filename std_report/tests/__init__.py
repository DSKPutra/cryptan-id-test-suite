"""Mesin uji std_report — plugin per uji, ID hasil `<ID-ALGORITME>/<K|S|I>-<nn>`.

Status: LULUS · GAGAL · INKONKLUSIF · TIDAK_DAPAT_DIUJI (tanpa backend/vektor) · TIDAK_BERLAKU ·
DICATAT (khusus I-02 kinerja: dicatat tanpa kriteria lulus/gagal). Hasil tidak pernah dipalsukan:
uji yang tidak dapat dijalankan tetap muncul dengan statusnya & alasannya.
"""
import hashlib
import json
import time

LULUS, GAGAL, INKON, TDD, TB, DICATAT = "LULUS", "GAGAL", "INKONKLUSIF", "TIDAK_DAPAT_DIUJI", "TIDAK_BERLAKU", "DICATAT"
STATUSES = [LULUS, GAGAL, INKON, TDD, TB, DICATAT]
DIRECT, ACUAN = "HASIL UJI LANGSUNG", "ACUAN/LITERATUR"


class Ctx:
    """Konteks satu kombinasi algoritme saat diuji."""

    def __init__(self, row, kind, backends, mode, rng_seed):
        self.row, self.kind, self.backends, self.mode = row, kind, backends, mode
        self.light = mode != "full"
        self.seed = rng_seed
        self.evidence = {}

    def rand(self, n, tag=""):
        """Byte deterministik (seed + tag) agar hasil dapat direproduksi."""
        out, i = b"", 0
        while len(out) < n:
            out += hashlib.sha256(f"{self.seed}|{self.row['id']}|{tag}|{i}".encode()).digest()
            i += 1
        return out[:n]

    def add_evidence(self, test_id, data) -> str:
        blob = json.dumps(data, sort_keys=True, default=str).encode()
        eid = f"EV-{hashlib.sha256(blob + test_id.encode()).hexdigest()[:10].upper()}"
        self.evidence[eid] = {"test": test_id, **data}
        return eid


class Plugin:
    id = "X-00"
    name = ""
    layer = "K"
    criteria = ""
    label = ""

    def applies(self, ctx):
        """(berlaku?, alasan bila tidak)."""
        return True, ""

    def run(self, ctx) -> dict:
        raise NotImplementedError

    def execute(self, ctx) -> dict:
        tid = f"{ctx.row['id']}/{self.id}"
        base = {"test_id": tid, "plugin": self.id, "name": self.name, "layer": self.layer, "criteria": self.criteria}
        ok, why = self.applies(ctx)
        if not ok:
            st = TDD if why.startswith("TDD:") else TB
            return {**base, "status": st, "reason": why.replace("TDD:", "").strip(), "parameters": {}, "actual": None,
                    "duration_s": 0.0, "evidence_id": None, "label": "", "source": DIRECT}
        t0 = time.perf_counter()
        try:
            r = self.run(ctx)
        except Exception as e:                              # galat internal mesin uji ≠ GAGAL algoritme
            r = {"status": INKON, "actual": None, "reason": f"galat mesin uji: {type(e).__name__}: {e}"[:300], "parameters": {}}
        dur = round(time.perf_counter() - t0, 4)
        ev = r.pop("evidence", None)
        eid = ctx.add_evidence(tid, ev) if ev else None
        return {**base, "label": r.pop("label", self.label), "source": r.pop("source", DIRECT), **r, "duration_s": dur, "evidence_id": eid}


def registry():
    from . import k, s, i
    return [k.K01(), k.K02(), k.K03(), k.K04(), s.S01(), s.S02(), s.S03(), s.S04(), i.I01(), i.I02(), i.I03()]
