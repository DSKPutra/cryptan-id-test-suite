"""Bangkitkan samples/input/datasheet_securelib.pdf (PDF minimal, pustaka standar saja)."""
from pathlib import Path

LINES = [
    "Cryptan.ID SecureLib 1.0 - Product Datasheet (ILUSTRATIF)",
    "Security Policy excerpt - Approved algorithms",
    "Symmetric: AES-128-CTR, AES-256-GCM (SP 800-38D), XTS-AES-256 for storage, AES-256-KW",
    "Message authentication: HMAC-SHA-256 with 256-bit keys, CMAC-AES-128",
    "Hashing: SHA-256, SHA-384, SHA3-256, SHAKE256",
    "Key establishment: ECDH P-384, ML-KEM-768 (FIPS 203), RSA-OAEP 2048-bit and 3072-bit",
    "Digital signatures: ECDSA P-256, RSA-PSS 3072, Ed25519, ML-DSA-65",
    "Random bit generation: CTR_DRBG-AES-256 (SP 800-90A)",
    "Legacy (non-approved, interoperability only): TDEA, SHA-1, RSA-1024 PKCS#1 v1.5 RSAES-PKCS1-v1_5",
]


def build(lines):
    esc = lambda s: s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    content = "BT /F1 11 Tf 50 780 Td 14 TL\n" + "".join(f"({esc(l)}) Tj T*\n" for l in lines) + "ET"
    objs = ["<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
            f"<< /Length {len(content)} >>\nstream\n{content}\nendstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, offs = bytearray(b"%PDF-1.4\n"), []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += f"{i} 0 obj\n{o}\nendobj\n".encode("latin-1")
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += "".join(f"{o:010d} 00000 n \n" for o in offs).encode()
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


if __name__ == "__main__":
    p = Path(__file__).resolve().parents[1] / "samples" / "input" / "datasheet_securelib.pdf"
    p.write_bytes(build(LINES))
    print(p)
