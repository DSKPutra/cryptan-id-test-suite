"""AES (FIPS 197) — implementasi referensi pure Python.

S-box dibangkitkan secara aljabar (invers di GF(2^8) + transformasi affine)
sehingga dapat dianalisis langsung oleh core.boolean (KUK 2.1).
Mendukung jumlah ronde tereduksi (untuk uji kelayakan versi tereduksi, KUK 2.3).
"""

AES_POLY = 0x11B          # x^8 + x^4 + x^3 + x + 1
MIX_MATRIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
INV_MIX_MATRIX = [[14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]]


def gf_mul(a: int, b: int, poly: int = AES_POLY) -> int:
    """Perkalian di GF(2^8) modulo polinom AES."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= poly
        b >>= 1
    return r


def gf_inv(a: int) -> int:
    """Invers multiplikatif di GF(2^8) (a^254); 0 dipetakan ke 0."""
    if a == 0:
        return 0
    r, e, x = 1, 254, a
    while e:
        if e & 1:
            r = gf_mul(r, x)
        x = gf_mul(x, x)
        e >>= 1
    return r


def _build_sbox():
    sbox = []
    for x in range(256):
        b = gf_inv(x)
        s = b
        for sh in range(1, 5):
            s ^= ((b << sh) | (b >> (8 - sh))) & 0xFF
        sbox.append(s ^ 0x63)
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


SBOX, INV_SBOX = _build_sbox()
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def key_expansion(key: bytes, rounds: int = 10):
    """Key schedule AES-128 → daftar (rounds+1) round key 16-byte."""
    if len(key) != 16:
        raise ValueError("AES-128 membutuhkan kunci 16 byte")
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 4 * (rounds + 1)):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[(i // 4) - 1]
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [bytes(sum(w[4 * r:4 * r + 4], [])) for r in range(rounds + 1)]


def _sub_bytes(s, box):
    return [box[b] for b in s]


def _shift_rows(s):
    # state column-major: s[r + 4c]
    return [s[(r + 4 * ((c + r) % 4))] for c in range(4) for r in range(4)]


def _inv_shift_rows(s):
    return [s[(r + 4 * ((c - r) % 4))] for c in range(4) for r in range(4)]


def _mix_columns(s, m=MIX_MATRIX):
    out = []
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        for r in range(4):
            v = 0
            for k in range(4):
                v ^= gf_mul(m[r][k], col[k])
            out.append(v)
    return out


def _add(s, k):
    return [a ^ b for a, b in zip(s, k)]


def encrypt_block(key: bytes, pt: bytes, rounds: int = 10) -> bytes:
    """Enkripsi satu blok. rounds<10 → varian ronde tereduksi (MixColumns
    pada ronde terakhir dihilangkan, konsisten dengan struktur AES)."""
    rk = key_expansion(key, rounds)
    s = _add(list(pt), rk[0])
    for r in range(1, rounds):
        s = _add(_mix_columns(_shift_rows(_sub_bytes(s, SBOX))), rk[r])
    s = _add(_shift_rows(_sub_bytes(s, SBOX)), rk[rounds])
    return bytes(s)


def decrypt_block(key: bytes, ct: bytes, rounds: int = 10) -> bytes:
    rk = key_expansion(key, rounds)
    s = _add(list(ct), rk[rounds])
    s = _sub_bytes(_inv_shift_rows(s), INV_SBOX)
    for r in range(rounds - 1, 0, -1):
        s = _add(s, rk[r])
        s = _mix_columns(s, INV_MIX_MATRIX)
        s = _sub_bytes(_inv_shift_rows(s), INV_SBOX)
    return bytes(_add(s, rk[0]))


def ecb_encrypt(key: bytes, data: bytes) -> bytes:
    if len(data) % 16:
        raise ValueError("panjang data harus kelipatan 16")
    return b"".join(encrypt_block(key, data[i:i + 16]) for i in range(0, len(data), 16))


def ctr_keystream(key: bytes, counter_block: bytes, nblocks: int) -> bytes:
    """Keystream mode CTR (SP 800-38A) — dipakai untuk uji keacakan SP 800-22."""
    if len(counter_block) != 16:
        raise ValueError("counter block CTR harus 16 byte")
    ctr = int.from_bytes(counter_block, "big")
    out = bytearray()
    for i in range(nblocks):
        out += encrypt_block(key, ((ctr + i) % (1 << 128)).to_bytes(16, "big"))
    return bytes(out)
