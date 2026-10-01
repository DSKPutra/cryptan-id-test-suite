"""Penggabungan hasil tiga opsi input → daftar akhir (dedup, konfirmasi, peringatan)."""
from typing import Dict, List, Optional

from .catalog import by_id
from .schema import PRIMITIVES

IR8547 = ("NIST IR 8547 (ipd): algoritma kuantum-rentan (RSA, ECC, FFC) 112-bit deprecated setelah 2030 "
          "dan seluruhnya disallowed setelah 2035; migrasi ke FIPS 203/204/205")
BAD_STATUS = {"deprecated": "deprecated", "legacy_use": "hanya legacy use", "disallowed": "disallowed"}


def _strength_lt(v, bits=112) -> bool:
    if isinstance(v, (int, float)):
        return v < bits
    return isinstance(v, str) and v.startswith("<") and v[1:].isdigit() and int(v[1:]) <= bits


class Selection:
    def __init__(self, entries):
        self.entries = by_id(entries)
        self.items: Dict[str, dict] = {}

    # ------------------------------------------------------------ penambahan
    def _add(self, e, k, inp: dict, confirmed: bool):
        row = e.combo_row(k)
        cid = row["id"]
        it = self.items.get(cid)
        if it is None:
            it = self.items[cid] = {**row, "inputs": [], "confidence": 0.0, "confirmed": False}
        if not any(x["type"] == inp["type"] and x.get("ref") == inp.get("ref") for x in it["inputs"]):
            it["inputs"].append(inp)
        it["confidence"] = max(it["confidence"], inp.get("confidence", 1.0))
        it["confirmed"] = it["confirmed"] or confirmed
        return cid

    def add_pick(self, pairs, ref: str):
        return [self._add(e, k, {"type": "dropdown", "ref": ref, "confidence": 1.0, "evidence": f"dipilih: {ref}"}, True)
                for e, k in pairs]

    def add_detections(self, dets: List[dict], input_type: str, ref: str, auto_confirm_at: Optional[float] = None):
        ids = []
        for d in dets:
            e = self.entries[d["entry_id"]]
            conf = d["confidence"]
            inp = {"type": input_type, "ref": ref, "confidence": conf, "evidence": d["evidence"],
                   "match": d["match"], "line": d.get("line"), "key_from": d.get("key_from")}
            ids.append(self._add(e, d["key_bits"], inp, auto_confirm_at is not None and conf >= auto_confirm_at))
        return ids

    # ------------------------------------------------------------ penyuntingan
    def confirm(self, ids, value=True):
        for i in ids:
            if i in self.items:
                self.items[i]["confirmed"] = value

    def remove(self, ids):
        for i in ids:
            self.items.pop(i, None)

    def change_key(self, cid: str, new_key: int):
        it = self.items.pop(cid)
        e = self.entries[it["entry_id"]]
        if new_key not in e.key_bits:
            self.items[cid] = it
            raise ValueError(f"{e.id}: kunci {new_key} tidak didukung {e.key_bits}")
        nid = self._add(e, new_key, {"type": "edit", "ref": f"ubah dari {cid}", "confidence": 1.0, "evidence": "suntingan pengguna"}, True)
        self.items[nid]["inputs"] = it["inputs"] + self.items[nid]["inputs"]
        return nid

    # ------------------------------------------------------------ hasil
    def pending(self) -> List[dict]:
        return sorted((i for i in self.items.values() if not i["confirmed"]), key=lambda i: (-i["confidence"], i["id"]))

    def final(self) -> List[dict]:
        rows = [i for i in self.items.values() if i["confirmed"]]
        order = list(PRIMITIVES)
        return sorted(rows, key=lambda r: (order.index(r["primitive"]), r["family"], r["variant"], r["key_bits"] or 0))


def warnings_for(row: dict) -> List[dict]:
    out = []
    st, s = row["status_nist"], row["security_strength_bits"]
    if st in BAD_STATUS:
        out.append({"level": "TINGGI", "code": f"STATUS_{st.upper()}",
                    "message": f"{row['id']}: status NIST {BAD_STATUS[st]} (SP 800-131A Rev.2)"})
    if _strength_lt(s):
        out.append({"level": "TINGGI", "code": "STRENGTH_LT_112",
                    "message": f"{row['id']}: security strength {s} bit < 112 bit (SP 800-57 Pt.1)"})
    if row.get("quantum_vulnerable"):
        out.append({"level": "SEDANG", "code": "QUANTUM_VULNERABLE", "message": f"{row['id']}: rentan kuantum — {IR8547}"})
    if "PERLU_VERIFIKASI" in (str(st), str(s)):
        out.append({"level": "INFO", "code": "PERLU_VERIFIKASI",
                    "message": f"{row['id']}: status/strength bertanda PERLU_VERIFIKASI — cek sumber primer"})
    return out


def summarize(rows: List[dict]) -> dict:
    by = {p: 0 for p in PRIMITIVES}
    for r in rows:
        by[r["primitive"]] += 1
    return {"total_combinations": len(rows), "by_primitive": {p: n for p, n in by.items() if n},
            "families": sorted({r["family"] for r in rows}),
            "by_input": {t: sum(1 for r in rows if any(i["type"] == t for i in r["inputs"]))
                         for t in ("link", "file", "dropdown", "edit")}}
