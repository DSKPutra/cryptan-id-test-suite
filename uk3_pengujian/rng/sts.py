"""NIST STS 2.1.2: pembuat berkas masukan (m barisan × n bit) dan pembaca finalAnalysisReport.txt (KUK 2.2/3.1).

Laporan asli disimpan beserta SHA-256-nya sebagai bukti."""
import hashlib
import re
from pathlib import Path

LINE = re.compile(r"^\s*((?:\d+\s+){10})(----|[0-9.]+)\s*(\*?)\s+(----|\d+/\d+)\s*(\*?)\s+(\S.*?)\s*$")


def write_input(seqs, path, fmt="ascii") -> dict:
    """Tulis m barisan bersambung; ASCII ('0'/'1') atau biner (byte dikemas). Petunjuk assess ikut dicatat."""
    path = Path(path)
    bits = "".join("".join(str(int(b)) for b in s) for s in seqs)
    if fmt == "ascii":
        path.write_text(bits)
    else:
        n = len(bits) - len(bits) % 8
        path.write_bytes(bytes(int(bits[i:i + 8], 2) for i in range(0, n, 8)))
    data = path.read_bytes()
    n = len(seqs[0]) if seqs else 0
    return {"file": path.name, "m": len(seqs), "n": n, "format": fmt, "sha256": hashlib.sha256(data).hexdigest(),
            "petunjuk": [f"./assess {n}", "generator 0 (Input File)", f"path berkas: {path.name}", "pilih semua uji (1), parameter bawaan (0)",
                         f"bitstreams = {len(seqs)}", f"format: {'0 (ASCII)' if fmt == 'ascii' else '1 (Binary)'}",
                         "baca experiments/AlgorithmTesting/finalAnalysisReport.txt"]}


def parse_report(text: str) -> dict:
    """Baca kolom C1–C10, P-VALUE, PROPORTION, dan tanda '*' (di luar batas → perlu analisis)."""
    rows = []
    for line in text.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        counts = [int(x) for x in m.group(1).split()]
        pv = None if m.group(2) == "----" else float(m.group(2))
        prop = m.group(4)
        a, b = (int(x) for x in prop.split("/")) if prop != "----" else (None, None)
        rows.append({"test": m.group(6), "C": counts, "p_value_T": pv, "uniformity_flag": bool(m.group(3)),
                     "passed": a, "total": b, "proportion": (a / b) if b else None, "proportion_flag": bool(m.group(5))})
    flagged = [r["test"] for r in rows if r["uniformity_flag"] or r["proportion_flag"]]
    return {"rows": rows, "tests": len(rows), "flagged": flagged, "sha256": hashlib.sha256(text.encode()).hexdigest(),
            "conclusion": "Tidak ditemukan bukti ketidakacakan" if rows and not flagged else
            ("Ada uji bertanda * — perlu analisis lanjutan" if rows else "Tidak ada baris hasil yang terbaca")}


NAMES = {"monobit": "Frequency", "block_frequency": "BlockFrequency", "runs": "Runs", "longest_run": "LongestRun",
         "cusum": "CumulativeSums", "serial": "Serial", "approximate_entropy": "ApproximateEntropy"}


def render_report(analysis: dict, generator="data/input.txt") -> str:
    """Susun laporan bergaya finalAnalysisReport dari analisis bawaan (format kolom sama, untuk perbandingan)."""
    hdr = ["-" * 78, "RESULTS FOR THE UNIFORMITY OF P-VALUES AND THE PROPORTION OF PASSING SEQUENCES", "-" * 78,
           f"   generator is <{generator}>", "-" * 78,
           " C1  C2  C3  C4  C5  C6  C7  C8  C9 C10  P-VALUE  PROPORTION  STATISTICAL TEST", "-" * 78]
    out = list(hdr)
    for t, v in analysis["tests"].items():
        if not v.get("runnable"):
            continue
        c = "".join(f"{x:>4d}" for x in v["histogram"])
        uflag = " *" if v["uniform_ok"] is False else "  "
        pflag = " *" if not v["prop_ok"] else "  "
        out.append(f"{c}  {v['p_value_T']:.6f}{uflag} {v['passed']:>4d}/{v['m']:<4d}{pflag}  {NAMES.get(t, t)}")
    return "\n".join(out) + "\n"
