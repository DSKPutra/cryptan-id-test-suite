"""Ekspor data dashboard UK-3 ke web/data/uk3/ (statis; build Vercel/Netlify tidak memerlukan numpy)."""
import json
import shutil
from pathlib import Path

from . import ROOT
from .run.runner import run_dir, runs_index, uk3_dir

FILES = ("uk3_hasil_uji.json", "lembar_hasil.csv", "Laporan_Hasil_Pengujian.pdf", "Laporan_Hasil_Pengujian.docx", "evidence_manifest.json")


def export(out=None, products=("securefile", "pustaka")) -> dict:
    out = Path(out) if out else ROOT / "web" / "data" / "uk3"
    out.mkdir(parents=True, exist_ok=True)
    index = {"produk": []}
    for pid in products:
        idx = runs_index(pid)
        if not idx:
            continue
        rid = idx[-1]["run_id"]
        d = run_dir(pid, rid)
        if not (d / "uk3_hasil_uji.json").exists():
            from .report.build import report
            report(pid, rid)
        dst = out / pid
        shutil.rmtree(dst, ignore_errors=True)
        dst.mkdir(parents=True)
        for f in FILES + ("run.json", "analisis.json", "kesimpulan.json"):
            if (d / f).exists():
                shutil.copy2(d / f, dst / f)
        for f in d.glob("log_*.txt"):
            shutil.copy2(f, dst / f.name)
        prep = json.loads((uk3_dir(pid) / "prep.json").read_text(encoding="utf-8"))
        (dst / "prep.json").write_text(json.dumps({k: prep[k] for k in ("produk", "nama_produk", "waktu", "dokumen", "inventaris",
                                                                         "checklist", "parameter_terkunci")}, ensure_ascii=False, indent=1),
                                       encoding="utf-8")
        (dst / "runs_index.json").write_text(json.dumps(idx, ensure_ascii=False, indent=1), encoding="utf-8")
        index["produk"].append({"id": pid, "run_id": rid, "logs": sorted(f.name for f in d.glob("log_*.txt"))})
    (out / "lab.json").write_text(json.dumps(lab_examples(), ensure_ascii=False, indent=1, default=float), encoding="utf-8")
    (out / "index.json").write_text(json.dumps(index, ensure_ascii=False, indent=1), encoding="utf-8")
    return index


def lab_examples() -> dict:
    """Contoh Lab Keacakan & olah data dari materi (dihitung ulang oleh kode, bukan disalin)."""
    from . import stats
    from .conclude import cvss
    from .rng import basic5, generators, golomb, lfsr, multiseq, sp80022
    s100 = generators.python_randint(100, 13)
    mseq = lfsr.recurrence((1, 1, 0, 0), (0, 0, 0, 1), 15)
    ex5 = lfsr.lfsr((3, 5), "01100", 31, "right")
    strip = lambda r: {k: v for k, v in r.items() if k not in ("p_values",)}  # noqa: E731
    return {
        "barisan_100": "".join(map(str, s100)),
        "basic5_100": basic5.run_all(s100, d=8),
        "basic5_1100": basic5.run_all("1100" * 25, d=8),
        "golomb_100": golomb.check(s100, max_tau=10),
        "msequence": {"bits": "".join(map(str, mseq)), "golomb": golomb.check(mseq), "bm": lfsr.berlekamp_massey(mseq)},
        "lfsr5": {"bits": "".join(map(str, ex5)), "golomb": golomb.check(ex5), "bm": lfsr.berlekamp_massey(ex5)},
        "sp80022_contoh": [strip(sp80022.monobit("1011010101", enforce_min=False)), strip(sp80022.runs("1001101011", enforce_min=False)),
                           strip(sp80022.block_frequency("0110011010", M=3, enforce_min=False))],
        "proporsi": [stats.proportion_interval(m) for m in (100, 1000)],
        "keseragaman": stats.uniformity(counts=[12, 8, 9, 11, 10, 10, 9, 11, 12, 8]),
        "welch": stats.welch_t(mean1=1200, sd1=40, n1=1000, mean2=1215, sd2=42, n2=1000),
        "ci": stats.confidence_interval([0.82, 0.85, 0.80, 0.84, 0.83, 0.86, 0.81, 0.84, 0.83, 0.82]),
        "min_entropy": {"p1": 0.6, "h_min": stats.min_entropy(0.6), "shannon": stats.shannon_entropy([0.6, 0.4]),
                        "raw_bits_256": stats.raw_bits_needed(256, stats.min_entropy(0.6))},
        "cvss": cvss.score("AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        "panjang_barisan": multiseq.length_experiment(),
    }
