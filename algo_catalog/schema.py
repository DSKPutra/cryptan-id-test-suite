"""Model data katalog algoritma (KUK 1.1 — informasi desain produk).

Satu *entri* katalog = algoritma × varian (mode / kurva / parameter set / digest)
dengan daftar panjang kunci. Satu *kombinasi* = entri × satu panjang kunci,
diberi ID kanonik dari template `combo_id` (mis. "AES-{k}-GCM" → "AES-256-GCM").

Pustaka standar saja (dipakai juga di browser via Pyodide).
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

PRIMITIVES = {
    "block_cipher": "Block cipher",
    "stream_cipher": "Stream cipher",
    "hash": "Fungsi hash / XOF",
    "mac": "MAC / AEAD ringan",
    "pkc_kem": "PKC / KEM / key agreement",
    "signature": "Tanda tangan digital",
    "drbg": "DRBG",
    "kdf": "KDF",
}
STATUSES = ("acceptable", "deprecated", "legacy_use", "disallowed", "not_nist", "PERLU_VERIFIKASI")
VERIFY = "PERLU_VERIFIKASI"
# Pemetaan ke kelas primitif profil UK-1 (config/profiles)
UK1_PRIMITIVE = {"block_cipher": "block_cipher", "stream_cipher": "stream_cipher", "hash": "hash",
                 "mac": "hash", "pkc_kem": "pkc", "signature": "dss", "drbg": "hash", "kdf": "hash"}


class SchemaError(ValueError):
    pass


def _per_key(value, k):
    """Nilai bisa skalar, 'key' (= panjang kunci), atau peta {kunci: nilai}."""
    if isinstance(value, dict):
        return value.get(k, value.get(str(k), VERIFY))
    if value == "key":
        return k
    return value


@dataclass
class Entry:
    id: str
    primitive: str
    family: str
    variant: str
    key_bits: List[int] = field(default_factory=list)
    block_or_output_bits: Optional[int] = None
    security_strength_bits: Any = None
    security_category: Any = None
    status_nist: Any = "PERLU_VERIFIKASI"
    standards: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    weak_aliases: List[str] = field(default_factory=list)
    context_hints: List[str] = field(default_factory=list)
    combo_id: Optional[str] = None
    auto_alias: bool = False
    quantum_vulnerable: bool = False
    source_body: List[str] = field(default_factory=list)    # FIPS | NIST-SP | ISO-IEC (boleh lebih dari satu)
    source_doc: List[str] = field(default_factory=list)     # mis. "FIPS 197", "SP 800-38D", "ISO/IEC 18033-3"
    notes: str = ""
    source: Dict[str, Any] = field(default_factory=lambda: {"type": "seed"})

    @classmethod
    def from_dict(cls, d: dict) -> "Entry":
        known = {f for f in cls.__dataclass_fields__}
        extra = set(d) - known
        if extra:
            raise SchemaError(f"{d.get('id')}: field tidak dikenal {sorted(extra)}")
        e = cls(**d)
        e.validate()
        return e

    def validate(self):
        if not self.id or not self.family or not self.variant:
            raise SchemaError(f"entri tanpa id/family/variant: {self}")
        if self.primitive not in PRIMITIVES:
            raise SchemaError(f"{self.id}: primitive '{self.primitive}' tidak dikenal")
        kb = self.key_bits
        if isinstance(kb, int):
            self.key_bits = [kb]
        elif kb is None:
            self.key_bits = []
        for k in self.keys():
            st = self.status(k)
            if st not in STATUSES:
                raise SchemaError(f"{self.id}: status '{st}' tidak dikenal")
        if self.key_bits and "{k}" not in (self.combo_id or "{k}") and len(self.key_bits) > 1:
            raise SchemaError(f"{self.id}: combo_id harus memuat {{k}} bila kunci > 1")

    # ------------------------------------------------------------ kombinasi
    def keys(self) -> list:
        return list(self.key_bits) or [None]

    def combo(self, k=None) -> str:
        tpl = self.combo_id or (f"{self.family}-{{k}}-{self.variant}" if self.key_bits else self.id)
        return tpl.replace("{k}", str(k)) if k is not None else tpl.replace("-{k}", "").replace("{k}", "")

    def strength(self, k=None):
        return _per_key(self.security_strength_bits, k)

    def category(self, k=None):
        return _per_key(self.security_category, k)

    def status(self, k=None):
        return _per_key(self.status_nist, k)

    def combinations(self) -> List[dict]:
        return [self.combo_row(k) for k in self.keys()]

    def combo_row(self, k=None) -> dict:
        return {
            "id": self.combo(k), "entry_id": self.id, "primitive": self.primitive,
            "primitive_label": PRIMITIVES[self.primitive], "family": self.family, "variant": self.variant,
            "key_bits": k, "block_or_output_bits": self.block_or_output_bits,
            "security_strength_bits": self.strength(k), "security_category": self.category(k),
            "status_nist": self.status(k), "standards": list(self.standards),
            "quantum_vulnerable": self.quantum_vulnerable, "notes": self.notes,
            "source_body": list(self.source_body), "source_doc": list(self.source_doc),
        }

    def to_dict(self) -> dict:
        return {f: getattr(self, f) for f in self.__dataclass_fields__}
