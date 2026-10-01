"""Opsi 1 (Link) — unduh halaman web / PDF secara sopan.

- Menghormati robots.txt (urllib.robotparser); URL yang dilarang tidak diunduh.
- User-Agent jelas + jeda antar-request ke host yang sama.
- Deteksi tipe: PDF (header %PDF / Content-Type) → pypdf; selain itu HTML → teks.
"""
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser

from .extract import html_to_text, pdf_to_text

USER_AGENT = "CryptanID-TestSuite/1.0 (+https://github.com/DSKPutra/cryptan-id-test-suite; praktikum Cryptographic Analyst)"
DELAY_S = 2.0
TIMEOUT_S = 30
MAX_BYTES = 25 * 1024 * 1024

_last_hit = {}
_robots = {}


class FetchError(RuntimeError):
    pass


def ssl_context():
    """Gunakan bundel CA certifi bila ada (Python python.org di macOS tidak membawa CA sistem)."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def _opener(req):
    return urllib.request.urlopen(req, timeout=TIMEOUT_S, context=ssl_context())


def robots_allowed(url: str, opener=_opener) -> bool:
    u = urllib.parse.urlsplit(url)
    base = f"{u.scheme}://{u.netloc}"
    if base not in _robots:
        rp = urllib.robotparser.RobotFileParser()
        try:
            with opener(urllib.request.Request(base + "/robots.txt", headers={"User-Agent": USER_AGENT})) as r:
                body = r.read(512 * 1024).decode("utf-8", errors="replace")
            ctype = r.headers.get("Content-Type", "") if hasattr(r, "headers") else ""
            # Banyak situs mengembalikan HTML (redirect/404) — anggap tidak ada robots.txt.
            rp.parse([] if "<html" in body[:500].lower() or "html" in ctype else body.splitlines())
        except (urllib.error.HTTPError, urllib.error.URLError, OSError):
            rp.parse([])
        _robots[base] = rp
    return _robots[base].can_fetch(USER_AGENT, url)


def _polite_wait(url: str, delay: float):
    host = urllib.parse.urlsplit(url).netloc
    wait = _last_hit.get(host, 0) + delay - time.monotonic()
    if wait > 0:
        time.sleep(wait)
    _last_hit[host] = time.monotonic()


def fetch(url: str, delay: float = DELAY_S, opener=_opener) -> dict:
    """Unduh URL → {url, content_type, text, bytes}. Melempar FetchError bila gagal/dilarang."""
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise FetchError(f"skema URL tidak didukung: {url}")
    if not robots_allowed(url, opener):
        raise FetchError(f"dilarang oleh robots.txt: {url}")
    _polite_wait(url, delay)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/pdf,*/*"})
    try:
        with opener(req) as r:
            data = r.read(MAX_BYTES + 1)
            ctype = r.headers.get("Content-Type", "") if hasattr(r, "headers") else ""
    except (urllib.error.HTTPError, urllib.error.URLError, OSError) as e:
        raise FetchError(f"gagal mengunduh {url}: {e}") from e
    if len(data) > MAX_BYTES:
        raise FetchError(f"berkas terlalu besar (> {MAX_BYTES // 1024 // 1024} MB): {url}")
    if data[:5] == b"%PDF-" or "pdf" in ctype.lower():
        text, kind = pdf_to_text(data), "pdf"
    else:
        text, kind = html_to_text(data.decode("utf-8", errors="replace")), "html"
    return {"url": url, "content_type": ctype or kind, "kind": kind, "text": text, "bytes": len(data)}
