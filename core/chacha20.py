"""ChaCha20 (RFC 8439) — implementasi referensi pure Python.

Parameter `rounds` (default 20) memungkinkan analisis ronde tereduksi
(ChaCha8/12 atau ronde ganjil) untuk KUK 2.1 / 2.3.
"""
import struct

MASK32 = 0xFFFFFFFF
CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)  # "expand 32-byte k"


def _rotl(v, c):
    return ((v << c) & MASK32) | (v >> (32 - c))


def quarter_round(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & MASK32; x[d] = _rotl(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & MASK32; x[b] = _rotl(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & MASK32; x[d] = _rotl(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & MASK32; x[b] = _rotl(x[b] ^ x[c], 7)


def initial_state(key: bytes, counter: int, nonce: bytes):
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("ChaCha20 membutuhkan kunci 32 byte dan nonce 12 byte")
    return (list(CONSTANTS) + list(struct.unpack("<8L", key)) + [counter & MASK32]
            + list(struct.unpack("<3L", nonce)))


def permute(state, rounds: int = 20):
    """Fungsi permutasi inti (tanpa feed-forward). rounds = jumlah ronde tunggal."""
    x = list(state)
    for i in range(rounds):
        if i % 2 == 0:   # column round
            quarter_round(x, 0, 4, 8, 12); quarter_round(x, 1, 5, 9, 13)
            quarter_round(x, 2, 6, 10, 14); quarter_round(x, 3, 7, 11, 15)
        else:            # diagonal round
            quarter_round(x, 0, 5, 10, 15); quarter_round(x, 1, 6, 11, 12)
            quarter_round(x, 2, 7, 8, 13); quarter_round(x, 3, 4, 9, 14)
    return x


def block(key: bytes, counter: int, nonce: bytes, rounds: int = 20) -> bytes:
    st = initial_state(key, counter, nonce)
    x = permute(st, rounds)
    return struct.pack("<16L", *[(a + b) & MASK32 for a, b in zip(x, st)])


def keystream(key: bytes, nonce: bytes, nbytes: int, counter: int = 0, rounds: int = 20) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < nbytes:
        out += block(key, counter + i, nonce, rounds)
        i += 1
    return bytes(out[:nbytes])


def encrypt(key: bytes, nonce: bytes, data: bytes, counter: int = 1, rounds: int = 20) -> bytes:
    ks = keystream(key, nonce, len(data), counter, rounds)
    return bytes(a ^ b for a, b in zip(data, ks))


decrypt = encrypt
