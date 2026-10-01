"""Konteks UK-2: profil produk, daftar algoritma uji (algo_catalog), keluaran UK-1, templat materi.

Masukan:
  - config/product_profile.yaml (bagian `uk2`, `algorithms_under_test`, opsional `protocol`/`module`)
  - --uk1: berkas uk1_penetapan_metode.json, folder outputs/uk1 (index.json → per algoritma),
           atau stub bertanda STUB_UK1
"""
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import yaml

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(__file__).parent / "data"
LAYERS = {"K": "Uji Kesesuaian", "S": "Uji Keamanan", "I": "Uji Implementasi"}
TIERS = {3: ["Komponen", "Integrasi", "Sistem"], 4: ["Unit", "Integrasi", "Sistem", "UAT"]}
TIER_CODE = {"Unit": "U", "Integrasi": "I", "Sistem": "S", "UAT": "A"}
UK1_LAYER = {"Kesesuaian": "K", "Kekuatan algoritma": "S", "Implementasi & sistem": "I"}
CATEGORIES = ["block", "stream", "hash", "pke", "signature", "protocol"]


class ContextError(ValueError):
    pass


def _yaml(p: Path):
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def category_of(item: dict) -> str:
    """Kategori materi (6 kategori) untuk satu kombinasi algorithms_under_test; 'rng' = rantai lintas-algoritma."""
    prim, fam = item["primitive"], item.get("family", "")
    if prim == "block_cipher":
        return "block"
    if prim == "stream_cipher":
        return "stream"
    if prim in ("hash", "kdf"):
        return "hash"
    if prim == "mac":
        return {"HMAC": "hash", "KMAC": "hash", "Poly1305": "stream"}.get(fam, "block")
    if prim == "pkc_kem":
        return "pke"
    if prim == "signature":
        return "signature"
    if prim == "drbg":
        return "rng"
    return "hash"


@dataclass
class Context:
    profile_path: Path
    profile: dict
    objects: List[dict]
    uk1: List[dict]
    uk1_source: str
    templates: dict
    iso: dict
    examples: Dict[str, dict]
    methods_catalog: Dict[str, dict]
    attacks: List[dict]
    notes: List[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    @property
    def uk2(self) -> dict:
        return self.profile.get("uk2", {})

    @property
    def model(self) -> int:
        return int(self.uk2.get("testing_model", 3))

    @property
    def tiers(self) -> List[str]:
        return TIERS[self.model]

    @property
    def features(self) -> set:
        return set(self.uk2.get("features", []))

    @property
    def claims(self) -> List[dict]:
        return self.uk2.get("claims", [])

    @property
    def is_module(self) -> bool:
        return self.uk2.get("product_type") == "hsm" or self.uk2.get("iso19790_security_level") is not None

    @property
    def security_level(self) -> Optional[int]:
        return self.uk2.get("iso19790_security_level")

    def categories(self) -> List[str]:
        cats = {category_of(o) for o in self.objects} - {"rng"}
        if self.uk2.get("protocol") or "protocol_tls13" in self.features:
            cats.add("protocol")
        return [c for c in CATEGORIES if c in cats]

    def objects_in(self, cat: str) -> List[dict]:
        return [o for o in self.objects if category_of(o) == cat]

    def uk1_selected(self) -> List[dict]:
        """Metode terpilih UK-1 (gabungan semua algoritma) + algoritma asal."""
        out = []
        for r in self.uk1:
            alg = r.get("profile", {}).get("algorithm", {})
            for s in r.get("selection", {}).get("selected", []):
                out.append({**s, "uk1_algorithm": alg.get("id"), "uk1_primitive": alg.get("primitive"),
                            "stub": bool(r.get("stub"))})
        return out

    def tier_for_uk1_level(self, level: str) -> str:
        if self.model == 4:
            return {"Unit": "Unit", "Integrasi": "Integrasi", "Sistem": "Sistem"}.get(level, "Sistem")
        return {"Unit": "Komponen", "Integrasi": "Integrasi", "Sistem": "Sistem"}.get(level, "Sistem")


def load_uk1(path: Optional[Path], notes: list) -> (List[dict], str):
    if path is None:
        notes.append("STUB_UK1: keluaran UK-1 tidak diberikan — memakai stub minimal tanpa metode")
        return [{"schema": "STUB_UK1", "stub": True, "selection": {"selected": []}}], "STUB_UK1"
    path = Path(path)
    if path.is_dir():
        idx = path / "index.json"
        if not idx.exists():
            raise ContextError(f"{path}: tidak ada index.json — jalankan UK-1 dulu (python -m uk1_metode)")
        index = json.loads(idx.read_text(encoding="utf-8"))
        res = [json.loads((path / a["files"]["json"]).read_text(encoding="utf-8")) for a in index["algorithms"]]
        return res, f"{path.as_posix()} ({len(res)} algoritma)"
    if not path.exists():
        raise ContextError(f"{path}: berkas UK-1 tidak ditemukan")
    d = json.loads(path.read_text(encoding="utf-8"))
    if d.get("schema") == "STUB_UK1" or d.get("stub"):
        notes.append(f"STUB_UK1: {path.name} — {d.get('note', 'stub')}")
    return [d], path.as_posix()


def load(profile: str, uk1: Optional[str] = None) -> Context:
    pp = Path(profile).resolve()
    prof = _yaml(pp)
    notes = []
    aut_rel = prof.get("algorithms_under_test")
    if not aut_rel:
        raise ContextError("product_profile.yaml tidak memuat `algorithms_under_test` — jalankan `make catalog` (algo_catalog)")
    aut_path = (pp.parent / aut_rel).resolve()
    aut = _yaml(aut_path)
    objects = aut.get("items", [])
    if "uk2" not in prof:
        notes.append("Profil tanpa bagian `uk2` — memakai default (library, 3 tingkat, tanpa klaim)")
        prof["uk2"] = {"product_type": "library", "testing_model": 3, "features": [], "claims": []}
    uk1_res, uk1_src = load_uk1(Path(uk1) if uk1 else None, notes)
    mdata = _yaml(ROOT / "uk1_metode" / "data" / "methods.yaml")["methods"]
    adata = _yaml(ROOT / "uk1_metode" / "data" / "attacks.yaml")["attacks"]
    ex = {p.stem: _yaml(p) for p in sorted((DATA / "examples").glob("*.yaml"))}
    return Context(profile_path=pp, profile=prof, objects=objects, uk1=uk1_res, uk1_source=uk1_src,
                   templates=_yaml(DATA / "templates.yaml"), iso=_yaml(DATA / "iso19790.yaml"), examples=ex,
                   methods_catalog={m["id"]: m for m in mdata}, attacks=adata, notes=notes)


def rel(p) -> str:
    try:
        return Path(p).resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return Path(p).name
