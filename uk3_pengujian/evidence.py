"""Integritas bukti (Bagian 5): SHA-256 setiap log & berkas bukti dicatat di evidence_manifest.json; verifikasi ulang."""
import datetime as dt
import hashlib
import json
from pathlib import Path

MANIFEST = "evidence_manifest.json"


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def write_manifest(run_dir) -> dict:
    run_dir = Path(run_dir)
    files = sorted(p for p in run_dir.rglob("*") if p.is_file() and p.name != MANIFEST)
    man = {"schema": "cryptan.uk3.evidence_manifest.v1", "run_dir": run_dir.name,
           "dibuat": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
           "berkas": [{"path": str(p.relative_to(run_dir)), "bytes": p.stat().st_size, "sha256": _sha(p)} for p in files]}
    (run_dir / MANIFEST).write_text(json.dumps(man, indent=1, ensure_ascii=False), encoding="utf-8")
    return man


def verify(run_dir) -> dict:
    """Bandingkan hash berkas sekarang dengan manifest. Berkas diubah/hilang/baru dilaporkan."""
    run_dir = Path(run_dir)
    man = json.loads((run_dir / MANIFEST).read_text(encoding="utf-8"))
    changed, missing = [], []
    listed = set()
    for f in man["berkas"]:
        p = run_dir / f["path"]
        listed.add(f["path"])
        if not p.exists():
            missing.append(f["path"])
        elif _sha(p) != f["sha256"]:
            changed.append({"path": f["path"], "sha256_manifest": f["sha256"], "sha256_sekarang": _sha(p)})
    extra = [str(p.relative_to(run_dir)) for p in run_dir.rglob("*") if p.is_file() and p.name != MANIFEST
             and str(p.relative_to(run_dir)) not in listed]
    ok = not changed and not missing
    return {"ok": ok, "diperiksa": len(man["berkas"]), "berubah": changed, "hilang": missing, "baru": extra,
            "kesimpulan": "Semua bukti cocok dengan manifest" if ok else "KETIDAKCOCOKAN: bukti berubah/hilang setelah dicatat"}
