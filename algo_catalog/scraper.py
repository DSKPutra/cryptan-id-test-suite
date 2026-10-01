"""Scraper katalog (NIST ACVP/CAVP, SP 800-131A, SP 800-57, IR 8547, ISO opsional).

Aturan: hormati robots.txt, jeda antar-request, User-Agent jelas, cache ke
data/catalog_cache.json berisi tanggal & URL sumber. Bila sumber gagal (offline),
kontribusi lama sumber tersebut di cache DIPERTAHANKAN; seed tidak pernah dihapus.
"""
import datetime as dt
import json
import re
from pathlib import Path

import yaml

from . import catalog, link
from .normalize import Matcher, canon_token
from .schema import Entry

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "config" / "sources.yaml"
ACVP_LINK = re.compile(r'<a href="https://pages\.nist\.gov/ACVP/draft-[^"]+\.txt">([^<]+)</a>')

FAMILY_ALIASES = {"eddsa": "EdDSA", "tdes": "TDEA", "xecdh": "XECDH", "kmac": "KMAC", "hmac": "HMAC",
                  "cmac": "AES", "ascon": "Ascon"}


def guess_primitive(name: str) -> str:
    n = name.lower()
    rules = [
        (("drbg",), "drbg"),
        (("kdf", "kda", "pbkdf", "hkdf", "tls", "ssh", "ike", "snmp", "srtp", "tpm", "spdm", "ansx9", "conditioning"), "kdf"),
        (("hmac", "kmac", "cmac", "gmac", "aead"), "mac"),
        (("ml-kem", "kas", "kts", "xecdh", "safeprimes", "ecdh", "ffdh"), "pkc_kem"),
        (("dsa", "ecdsa", "eddsa", "rsa", "lms", "xmss", "slh"), "signature"),
        (("sha", "shake", "hash", "xof", "tuplehash", "parallelhash"), "hash"),
        (("aes", "tdes", "tdea", "camellia", "sm4"), "block_cipher"),
    ]
    for keys, prim in rules:
        if any(k in n for k in keys):
            return prim
    return "kdf"


def _slug(name: str) -> str:
    return "ACVP-" + re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-").upper()


def parse_acvp_index(html: str) -> list:
    return sorted({" ".join(n.split()) for n in ACVP_LINK.findall(html)})


def process_names(names, entries, url, source_id):
    """Cocokkan nama algoritma (ACVP) ke katalog; yang tidak dikenal → entri baru."""
    M = Matcher(entries)
    fams = {}
    for e in entries:
        fams.setdefault(canon_token(e.family), []).append(e.id)
    updates, new = [], []
    today = dt.date.today().isoformat()
    for name in names:
        dets = [d for d in M.find(name) if d["confidence"] >= 0.4]
        if dets:
            updates += [{"id": d["entry_id"], "url": url, "name": name, "source_id": source_id} for d in dets]
            continue
        fam = None
        for w in name.replace("(", " ").split():          # mis. "ML-DSA keyGen", "Deterministic ECDSA mode: sigGen"
            c = canon_token(FAMILY_ALIASES.get(canon_token(w), w))
            if c in fams:
                fam = c
                break
        if fam:
            updates += [{"id": i, "url": url, "name": name, "source_id": source_id} for i in fams[fam]]
            continue
        e = Entry(id=_slug(name), primitive=guess_primitive(name), family=name.split()[0].split("-")[0],
                  variant=name, status_nist="PERLU_VERIFIKASI", security_strength_bits="PERLU_VERIFIKASI",
                  standards=["NIST ACVP specification"], aliases=[name], combo_id=_slug(name),
                  notes="Ditambahkan otomatis dari indeks ACVP; lengkapi status & strength secara manual",
                  source={"type": "scrape", "url": url, "retrieved": today, "source_id": source_id})
        if e.id not in {x["id"] for x in new}:
            new.append(e.to_dict())
    return updates, new


def scrape(refresh: bool = True, sources_path: Path = SOURCES, cache_path: Path = catalog.CACHE,
           include_optional: bool = False, fetcher=link.fetch, raw_fetcher=None, delay: float = None,
           log=print) -> dict:
    cfg = yaml.safe_load(sources_path.read_text(encoding="utf-8"))
    delay = cfg.get("delay_seconds", link.DELAY_S) if delay is None else delay
    old = json.loads(cache_path.read_text(encoding="utf-8")) if cache_path.exists() else {"entries": [], "updates": [], "sources": []}
    if not refresh and cache_path.exists():
        log(f"cache dipakai apa adanya: {cache_path}")
        return old
    entries = catalog.load(use_cache=False)
    result = {"generated": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
              "user_agent": link.USER_AGENT, "sources": [], "entries": [], "updates": []}
    for src in cfg["sources"]:
        if src.get("optional") and not include_optional:
            continue
        sid, url = src["id"], src["url"]
        rec = {"id": sid, "url": url, "title": src.get("title"), "retrieved": dt.date.today().isoformat()}
        try:
            if src["parser"] == "acvp_index":
                raw = (raw_fetcher or _fetch_raw)(url, delay)
                names = parse_acvp_index(raw)
                ups, new = process_names(names, entries, url, sid)
                rec.update(status="ok", names=len(names), matched=len({u["id"] for u in ups}), added=len(new))
            else:
                page = fetcher(url, delay=delay)
                M = Matcher(entries)
                dets = [d for d in M.find(page["text"]) if d["confidence"] >= 0.6]
                ups = [{"id": d["entry_id"], "url": url, "name": d["match"], "source_id": sid} for d in dets]
                new = []
                rec.update(status="ok", kind=page.get("kind"), matched=len({u["id"] for u in ups}))
            result["updates"] += ups
            result["entries"] += [n for n in new if n["id"] not in {x["id"] for x in result["entries"]}]
            log(f"  ✔ {sid}: {rec.get('matched', 0)} entri cocok" + (f", {rec['added']} baru" if rec.get("added") else ""))
        except link.FetchError as e:
            rec.update(status="robots" if "robots" in str(e) else "error", error=str(e))
            # pertahankan kontribusi lama sumber ini (mode offline)
            result["updates"] += [u for u in old.get("updates", []) if u.get("source_id") == sid]
            result["entries"] += [n for n in old.get("entries", []) if n.get("source", {}).get("source_id") == sid]
            log(f"  ✘ {sid}: {e} — memakai cache lama/seed")
        result["sources"].append(rec)
    # dedup updates
    seen, ups = set(), []
    for u in result["updates"]:
        k = (u["id"], u["url"])
        if k not in seen:
            seen.add(k)
            ups.append(u)
    result["updates"] = ups
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(result, indent=1, ensure_ascii=False), encoding="utf-8")
    ok = sum(s["status"] == "ok" for s in result["sources"])
    log(f"cache → {cache_path} ({ok}/{len(result['sources'])} sumber OK, {len(result['entries'])} entri baru)")
    return result


def _fetch_raw(url: str, delay: float) -> str:
    """Unduh HTML mentah (perlu tautan untuk parser ACVP) dengan aturan sopan yang sama."""
    import urllib.error
    import urllib.request
    if not link.robots_allowed(url):
        raise link.FetchError(f"dilarang oleh robots.txt: {url}")
    link._polite_wait(url, delay)
    req = urllib.request.Request(url, headers={"User-Agent": link.USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=link.TIMEOUT_S, context=link.ssl_context()) as r:
            return r.read(link.MAX_BYTES).decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError) as e:
        raise link.FetchError(f"gagal mengunduh {url}: {e}") from e
