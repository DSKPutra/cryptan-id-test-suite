"""Keccak-f[1600] & SHA3-256 (FIPS 202) — implementasi referensi pure Python.

Mengekspos pemetaan χ sebagai S-box 5-bit (CHI_SBOX) agar dapat dianalisis
(DDT, derajat aljabar) oleh core.boolean untuk KUK 2.1.
"""

RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
       [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]   # ROT[x][y]
M64 = (1 << 64) - 1


def _rol(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & M64 if n else v


def chi_row(a: int) -> int:
    """χ pada satu baris 5-bit: b_i = a_i ⊕ (¬a_{i+1} ∧ a_{i+2})."""
    bits = [(a >> i) & 1 for i in range(5)]
    return sum((bits[i] ^ ((bits[(i + 1) % 5] ^ 1) & bits[(i + 2) % 5])) << i for i in range(5))


CHI_SBOX = [chi_row(a) for a in range(32)]


def keccak_f(A, rounds: int = 24):
    """A: list 25 lane (indeks x + 5y). Menjalankan `rounds` ronde terakhir
    (konvensi ronde tereduksi: ronde 0..rounds-1)."""
    A = list(A)
    for rnd in range(rounds):
        C = [A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol(C[(x + 1) % 5], 1) for x in range(5)]
        A = [A[i] ^ D[i % 5] for i in range(25)]                     # θ
        B = [0] * 25
        for x in range(5):
            for y in range(5):
                B[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(A[x + 5 * y], ROT[x][y])  # ρ, π
        A = [B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y])
             for y in range(5) for x in range(5)]                     # χ (urutan x + 5y)
        A[0] ^= RC[rnd]                                            # ι
    return A


def pad10star1(msg_len: int, rate_bytes: int, ds: int = 0x06) -> bytes:
    """Padding SHA-3: domain-separation 01 + pad10*1 (FIPS 202 §B.2)."""
    q = rate_bytes - (msg_len % rate_bytes)
    if q == 1:
        return bytes([ds | 0x80])
    return bytes([ds]) + b"\x00" * (q - 2) + b"\x80"


def sponge(msg: bytes, rate_bytes: int, out_len: int, ds: int = 0x06, rounds: int = 24) -> bytes:
    data = msg + pad10star1(len(msg), rate_bytes, ds)
    A = [0] * 25
    for off in range(0, len(data), rate_bytes):
        blk = data[off:off + rate_bytes]
        for i in range(rate_bytes // 8):
            A[i] ^= int.from_bytes(blk[8 * i:8 * i + 8], "little")
        A = keccak_f(A, rounds)
    out = bytearray()
    while True:
        for i in range(rate_bytes // 8):
            out += A[i].to_bytes(8, "little")
        if len(out) >= out_len:
            return bytes(out[:out_len])
        A = keccak_f(A, rounds)


def sha3_256(msg: bytes, rounds: int = 24) -> bytes:
    return sponge(msg, 136, 32, 0x06, rounds)


SHA3_256_PARAMS = {"b": 1600, "rate_bits": 1088, "capacity_bits": 512, "output_bits": 256, "rounds": 24}
