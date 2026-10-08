"""Kalkulator CVSS 3.1 base score (FIRST CVSS v3.1 Specification §7) — KUK 3.2."""
import math

W = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44}, "UI": {"N": 0.85, "R": 0.62},
     "C": {"H": 0.56, "L": 0.22, "N": 0.0}, "I": {"H": 0.56, "L": 0.22, "N": 0.0}, "A": {"H": 0.56, "L": 0.22, "N": 0.0}}
PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
NAMES = {"AV": "Attack Vector", "AC": "Attack Complexity", "PR": "Privileges Required", "UI": "User Interaction", "S": "Scope",
         "C": "Confidentiality", "I": "Integrity", "A": "Availability"}


def roundup(x: float) -> float:
    """Roundup CVSS 3.1 (Lampiran A): pembulatan ke atas 1 desimal yang stabil terhadap galat floating point."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def parse(vector: str) -> dict:
    parts = dict(p.split(":") for p in vector.replace("CVSS:3.1/", "").split("/") if ":" in p)
    missing = [k for k in NAMES if k not in parts]
    if missing:
        raise ValueError(f"metrik tidak lengkap: {missing}")
    return parts


def severity(score: float) -> str:
    return "None" if score == 0 else "Low" if score < 4 else "Medium" if score < 7 else "High" if score < 9 else "Critical"


def score(vector: str) -> dict:
    m = parse(vector)
    iss = 1 - (1 - W["C"][m["C"]]) * (1 - W["I"][m["I"]]) * (1 - W["A"][m["A"]])
    changed = m["S"] == "C"
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    expl = 8.22 * W["AV"][m["AV"]] * W["AC"][m["AC"]] * PR[m["S"]][m["PR"]] * W["UI"][m["UI"]]
    if impact <= 0:
        base = 0.0
    else:
        base = roundup(min(1.08 * (impact + expl), 10)) if changed else roundup(min(impact + expl, 10))
    v = "CVSS:3.1/" + "/".join(f"{k}:{m[k]}" for k in NAMES)
    return {"vector": v, "metrics": m, "iss": iss, "impact": impact, "exploitability": expl, "base_score": base, "severity": severity(base),
            "langkah": [("ISS", f"1 − (1 − {W['C'][m['C']]})(1 − {W['I'][m['I']]})(1 − {W['A'][m['A']]})", round(iss, 3)),
                        (f"Impact (S:{m['S']})", "7,52(ISS−0,029) − 3,25(ISS−0,02)^15" if changed else f"6,42 × {round(iss, 3)}", round(impact, 3)),
                        ("Exploitability", f"8,22 × {W['AV'][m['AV']]} × {W['AC'][m['AC']]} × {PR[m['S']][m['PR']]} × {W['UI'][m['UI']]}",
                         round(expl, 3)),
                        ("Base score", "roundup(" + ("1,08 × " if changed else "") + "(Impact + Exploitability)), 1 desimal",
                         f"{base} ({severity(base)})")]}
