"""Muat katalog: seed (offline) + cache hasil scraping (menambah/memperbarui).

Struktur dropdown bertingkat: Primitif → Algoritma (family) → Varian → Panjang kunci.
"""
import json
from pathlib import Path
from typing import Dict, List

from .schema import PRIMITIVES, Entry

DATA = Path(__file__).parent / "data"
SEED = DATA / "catalog_seed.yaml"
CACHE = DATA / "catalog_cache.json"


def _load_yaml(path: Path) -> dict:
    import yaml
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load(seed: Path = SEED, cache: Path = CACHE, use_cache: bool = True) -> List[Entry]:
    entries: Dict[str, Entry] = {}
    for d in _load_yaml(seed)["entries"]:
        e = Entry.from_dict(dict(d))
        entries[e.id] = e
    if use_cache and cache.exists():
        c = json.loads(cache.read_text(encoding="utf-8"))
        for d in c.get("entries", []):
            if d["id"] in entries:              # perbarui: hanya tambah bukti sumber & standar
                e = entries[d["id"]]
                e.source.setdefault("seen_in", [])
                for s in d.get("source", {}).get("seen_in", []):
                    if s not in e.source["seen_in"]:
                        e.source["seen_in"].append(s)
            else:                               # tambah entri baru dari scraping
                entries[d["id"]] = Entry.from_dict(dict(d))
        for upd in c.get("updates", []):
            e = entries.get(upd["id"])
            if e:
                e.source.setdefault("seen_in", [])
                if upd["url"] not in e.source["seen_in"]:
                    e.source["seen_in"].append(upd["url"])
    return list(entries.values())


def by_id(entries: List[Entry]) -> Dict[str, Entry]:
    return {e.id: e for e in entries}


def combo_index(entries: List[Entry]) -> Dict[str, tuple]:
    """ID kanonik kombinasi → (entri, kunci)."""
    idx = {}
    for e in entries:
        for k in e.keys():
            idx[e.combo(k).upper()] = (e, k)
    return idx


def tree(entries: List[Entry]) -> dict:
    """Hierarki dropdown."""
    t = {p: {} for p in PRIMITIVES}
    for e in entries:
        t[e.primitive].setdefault(e.family, []).append(
            {"entry_id": e.id, "variant": e.variant, "keys": e.key_bits,
             "combos": [e.combo(k) for k in e.keys()], "status": [e.status(k) for k in e.keys()]})
    return {p: dict(sorted(f.items())) for p, f in t.items() if f}


def count_combinations(entries: List[Entry]) -> dict:
    out = {p: 0 for p in PRIMITIVES}
    for e in entries:
        out[e.primitive] += len(e.keys())
    out["total"] = sum(out[p] for p in PRIMITIVES)
    return out


def export_json(entries: List[Entry], path: Path):
    """Katalog untuk dashboard web (dropdown + deteksi Pyodide)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"primitives": PRIMITIVES, "entries": [e.to_dict() for e in entries],
                                "counts": count_combinations(entries)}, ensure_ascii=False, indent=1), encoding="utf-8")
