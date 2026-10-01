"""Opsi 3 (Dropdown) — pemilihan dari katalog: Primitif → Algoritma → Varian → Kunci.

Sintaks CLI `--pick`:
  "AES:GCM:128,256"     family:varian:kunci
  "AES:GCM"             semua panjang kunci varian itu
  "AES:*"               semua varian & kunci ("pilih semua varian")
  "ECDSA:P-384"         varian kurva (kunci tunggal)
  "ML-KEM:768"          varian dicocokkan juga sebagai akhiran ("ML-KEM-768")
  "AES-256-GCM"         langsung ID kanonik kombinasi
"""
from typing import List, Tuple

from .catalog import combo_index
from .normalize import canon_token


class PickError(ValueError):
    pass


def _variant_match(e, v: str) -> bool:
    cv, ce = canon_token(v), canon_token(e.variant)
    return cv == ce or ce.endswith(cv) or canon_token(e.id) == cv or canon_token(e.id).endswith(cv)


def parse_pick(spec: str, entries) -> List[Tuple[object, object]]:
    spec = spec.strip()
    idx = combo_index(entries)
    if ":" not in spec:
        hit = idx.get(spec.upper())
        if not hit:
            raise PickError(f"ID kanonik tidak dikenal: {spec}")
        return [hit]
    parts = spec.split(":")
    fam = canon_token(parts[0])
    fam_entries = [e for e in entries if canon_token(e.family) == fam]
    if not fam_entries:
        raise PickError(f"algoritma tidak dikenal: {parts[0]}")
    variant = parts[1] if len(parts) > 1 else "*"
    chosen = fam_entries if variant in ("*", "") else [e for e in fam_entries if _variant_match(e, variant)]
    if not chosen:
        raise PickError(f"varian '{variant}' tidak ada untuk {parts[0]} "
                        f"(tersedia: {', '.join(sorted({e.variant for e in fam_entries}))})")
    # pilih kecocokan varian paling persis bila ada beberapa (mis. "GCM" vs "GCM-SIV")
    exact = [e for e in chosen if canon_token(e.variant) == canon_token(variant)]
    if exact and variant not in ("*", ""):
        chosen = exact
    keys_spec = parts[2] if len(parts) > 2 else "*"
    out = []
    for e in chosen:
        if keys_spec in ("*", ""):
            ks = e.keys()
        else:
            try:
                want = [int(x) for x in keys_spec.split(",") if x.strip()]
            except ValueError as ex:
                raise PickError(f"panjang kunci tidak valid: {keys_spec}") from ex
            bad = [k for k in want if k not in e.key_bits]
            if bad:
                raise PickError(f"{e.id}: panjang kunci {bad} tidak didukung (tersedia {e.key_bits})")
            ks = want
        out += [(e, k) for k in ks]
    return out
