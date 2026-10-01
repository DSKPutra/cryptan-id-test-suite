"""Normalisasi alias → ID kanonik & deteksi algoritma dalam teks bebas.

Alias dipecah menjadi token huruf/angka; di antara token boleh ada 0–3 karakter
pemisah (spasi, -, _, /, .), sehingga "aes256gcm", "AES-256-GCM", "aes_256_gcm",
"EVP_aes_256_gcm" dan "id-aes256-GCM" cocok dengan pola yang sama. Token {k}
menangkap panjang kunci. Jika kunci tidak ada di alias, dicari angka panjang
kunci yang sah di sekitar kecocokan (konteks), mis. `kg.init(256)`.

Pustaka standar saja (juga dijalankan di browser via Pyodide).
"""
import re
from typing import Iterable, List, Optional

SEP = r"[ \t\-_/.:+^]{0,3}"     # pemisah antar-token (tanpa koma/titik koma/baris baru)
WINDOW = 250
TOKEN = re.compile(r"\{k\}|[A-Za-z]+|\d+")

CONF_EXPLICIT = 0.95      # alias memuat kunci / entri tanpa variasi kunci
CONF_GIVEN = 0.90         # kunci diberikan pemanggil (parameter)
CONF_CONTEXT = 0.75       # kunci ditemukan di konteks sekitar
CONF_UNKNOWN = 0.40       # kunci tidak diketahui → semua varian kunci
CONF_WEAK = 0.50          # alias ambigu (mis. "secp384r1": ECDSA atau ECDH)
HINT_BONUS = 0.25


def tokens(alias: str) -> List[str]:
    return TOKEN.findall(alias)


def alias_regex(alias: str, keys: Iterable[int]) -> Optional[re.Pattern]:
    """Alias berakhiran '*' = prefiks (mis. "RSA/ECB/OAEP*" cocok "…OAEPWithSHA-256…")."""
    prefix = alias.endswith("*")
    toks = tokens(alias.rstrip("*"))
    if not toks:
        return None
    keyalt = "|".join(str(k) for k in sorted(set(k for k in keys if k), reverse=True)) or r"\d+"
    parts = [f"(?P<k>{keyalt})" if t == "{k}" else re.escape(t) for t in toks]
    return re.compile(r"(?<![A-Za-z0-9])" + SEP.join(parts) + ("" if prefix else r"(?![A-Za-z0-9])"), re.I)


def canon_token(s: str) -> str:
    """Bentuk ringkas untuk perbandingan (huruf kecil, tanpa pemisah)."""
    return "".join(tokens(s)).lower()


def entry_aliases(e) -> List[tuple]:
    """(alias, kuat?) untuk satu entri: alias eksplisit + combo_id (+ auto_alias)."""
    out = [(a, True) for a in e.aliases]
    out.append((e.combo_id or e.id, True))
    if re.search(r"[^A-Za-z]", e.id):
        out.append((e.id, True))
    if e.auto_alias and e.key_bits:
        F, V = e.family, e.variant
        out += [(f"{F}-{{k}}-{V}", True), (f"{F}-{V}-{{k}}", True), (f"{V}-{F}-{{k}}", True),
                (f"{F}-{V}", True), (f"{F}/{V}", True)]
    out += [(a, False) for a in e.weak_aliases]
    seen, uniq = set(), []
    for a, strong in out:
        key = (tuple(t.lower() for t in tokens(a.rstrip("*"))), a.endswith("*"), strong)
        if key not in seen:
            seen.add(key)
            uniq.append((a, strong))
    return uniq


class Matcher:
    """Kumpulan pola terkompilasi untuk satu katalog."""

    def __init__(self, entries):
        self.entries = {e.id: e for e in entries}
        self.patterns = []
        for e in entries:
            for a, strong in entry_aliases(e):
                rx = alias_regex(a, e.key_bits)
                if rx:
                    self.patterns.append((rx, e, strong, a))

    # ------------------------------------------------------------------
    def _context_keys(self, text, start, end, e) -> list:
        """Daftar kunci: semua kunci sah yang disebut tepat setelah alias (≤ 40 karakter,
        mis. "RSA-OAEP 2048-bit and 3072-bit"); jika tidak ada, kunci terdekat dalam jendela."""
        if not e.key_bits:
            return []
        alt = "|".join(str(k) for k in e.key_bits)
        near = text[end:end + 40].split("\n")[0]
        after = [int(x) for x in re.findall(r"(?<!\d)(" + alt + r")(?!\d)", near)]
        if after:
            return sorted(set(after), key=after.index)
        k = self._context_key(text, start, end, e)
        return [k] if k else []

    def _context_key(self, text, start, end, e):
        if not e.key_bits:
            return None
        lo, hi = max(0, start - WINDOW), min(len(text), end + WINDOW)
        best = None
        for m in re.finditer(r"(?<!\d)(" + "|".join(str(k) for k in e.key_bits) + r")(?!\d)", text[lo:hi]):
            pos = lo + m.start()
            if start <= pos < end:          # angka di dalam alias itu sendiri (mis. "SHA256") bukan kunci
                continue
            d = start - pos if pos < start else pos - end
            if best is None or d < best[0]:
                best = (d, int(m.group(1)))
        return best[1] if best else None

    def _has_hint(self, text, start, end, e):
        if not e.context_hints:
            return False
        win = text[max(0, start - WINDOW): end + WINDOW].lower()
        return any(h.lower() in win for h in e.context_hints)

    def find(self, text: str, key_bits: Optional[int] = None, source: Optional[dict] = None) -> List[dict]:
        """Deteksi semua kombinasi dalam teks. Kecocokan yang berada di dalam
        rentang kecocokan lain yang lebih panjang (entri berbeda) dibuang."""
        raw = []
        for rx, e, strong, alias in self.patterns:
            for m in rx.finditer(text):
                raw.append((m.start(), m.end(), e, strong, alias, m))
        raw.sort(key=lambda r: (-(r[1] - r[0]), r[0]))
        kept = []
        for r in raw:
            s, t, e = r[0], r[1], r[2]
            if any(ks <= s and t <= kt and (kt - ks) > (t - s) and ke.id != e.id for ks, kt, ke, *_ in kept):
                continue
            if any(ks == s and kt == t and ke.id == e.id for ks, kt, ke, *_ in kept):
                continue
            kept.append(r)
        out = []
        for s, t, e, strong, alias, m in sorted(kept, key=lambda r: r[0]):
            gd = m.groupdict()
            if gd.get("k"):
                keys, conf, how = [int(gd["k"])], CONF_EXPLICIT, "alias"
            elif len(e.key_bits) <= 1:
                keys, conf, how = e.keys(), CONF_EXPLICIT, "alias"
            elif key_bits and key_bits in e.key_bits:
                keys, conf, how = [key_bits], CONF_GIVEN, "parameter"
            else:
                ck = self._context_keys(text, s, t, e)
                keys, conf, how = (ck, CONF_CONTEXT, "konteks") if ck else (e.keys(), CONF_UNKNOWN, "tidak terdeteksi")
            if not strong:
                conf = min(0.9, CONF_WEAK + (HINT_BONUS if self._has_hint(text, s, t, e) else 0.0))
                how = "alias ambigu" + (" + petunjuk konteks" if conf > CONF_WEAK else "")
            line = text.count("\n", 0, s) + 1
            snip = text[max(0, s - 60): t + 60].replace("\n", " ").strip()
            for k in keys:
                out.append({"id": e.combo(k), "entry_id": e.id, "key_bits": k, "confidence": round(conf, 2),
                            "match": m.group(0), "alias": alias, "key_from": how, "line": line,
                            "evidence": snip, "source": dict(source or {})})
        return out


def best(detections: List[dict]) -> List[dict]:
    """Satu deteksi terbaik per ID kanonik (keyakinan tertinggi)."""
    by = {}
    for d in detections:
        if d["id"] not in by or d["confidence"] > by[d["id"]]["confidence"]:
            by[d["id"]] = d
    return sorted(by.values(), key=lambda d: (-d["confidence"], d["id"]))


def normalize(matcher: Matcher, s: str, key_bits: Optional[int] = None, min_confidence: float = 0.6) -> List[str]:
    """String alias → daftar ID kanonik (keyakinan ≥ ambang)."""
    return [d["id"] for d in best(matcher.find(s, key_bits)) if d["confidence"] >= min_confidence]
