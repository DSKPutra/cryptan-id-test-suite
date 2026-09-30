"""ECDSA atas kurva P-256 (FIPS 186-5, SP 800-186, ISO/IEC 14888-3) —
implementasi referensi pure Python, koordinat Jacobian.

Nonce k: deterministik RFC 6979 (default) atau disuntikkan (untuk uji bias /
reuse nonce pada KUK 2.1).
"""
import hashlib
import hmac

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
H = 1
G = (GX, GY)
INF = None


def is_on_curve(Pt) -> bool:
    if Pt is INF:
        return False
    x, y = Pt
    return (y * y - (x * x * x + A * x + B)) % P == 0


def _to_jac(Pt):
    return (Pt[0], Pt[1], 1)


def _from_jac(J):
    X, Y, Z = J
    if Z == 0:
        return INF
    zi = pow(Z, -1, P)
    zi2 = zi * zi % P
    return (X * zi2 % P, Y * zi2 * zi % P)


def _jdouble(J):
    X, Y, Z = J
    if Y == 0 or Z == 0:
        return (0, 1, 0)
    YY = Y * Y % P
    S = 4 * X * YY % P
    ZZ = Z * Z % P
    M = 3 * (X - ZZ) * (X + ZZ) % P          # a = -3
    X3 = (M * M - 2 * S) % P
    Y3 = (M * (S - X3) - 8 * YY * YY) % P
    Z3 = 2 * Y * Z % P
    return (X3, Y3, Z3)


def _jadd(J1, J2):
    if J1[2] == 0:
        return J2
    if J2[2] == 0:
        return J1
    X1, Y1, Z1 = J1
    X2, Y2, Z2 = J2
    Z1Z1, Z2Z2 = Z1 * Z1 % P, Z2 * Z2 % P
    U1, U2 = X1 * Z2Z2 % P, X2 * Z1Z1 % P
    S1, S2 = Y1 * Z2 * Z2Z2 % P, Y2 * Z1 * Z1Z1 % P
    if U1 == U2:
        return _jdouble(J1) if S1 == S2 else (0, 1, 0)
    Hh = (U2 - U1) % P
    R = (S2 - S1) % P
    HH = Hh * Hh % P
    HHH = Hh * HH % P
    V = U1 * HH % P
    X3 = (R * R - HHH - 2 * V) % P
    Y3 = (R * (V - X3) - S1 * HHH) % P
    Z3 = Hh * Z1 * Z2 % P
    return (X3, Y3, Z3)


def scalar_mult(k: int, Pt=G):
    """Double-and-add (TIDAK constant-time — objek uji timing pada UK berikutnya)."""
    if Pt is INF or k % N == 0:
        return INF
    R = (0, 1, 0)
    Q = _to_jac(Pt)
    for bit in bin(k)[2:]:
        R = _jdouble(R)
        if bit == "1":
            R = _jadd(R, Q)
    return _from_jac(R)


def point_add(P1, P2):
    if P1 is INF:
        return P2
    if P2 is INF:
        return P1
    return _from_jac(_jadd(_to_jac(P1), _to_jac(P2)))


def public_key(d: int):
    return scalar_mult(d, G)


def validate_public_key(Q) -> dict:
    """Validasi penuh kunci publik EC (SP 800-186 D.1.1 / SP 800-56A 5.6.2.3.3)."""
    checks = {"not_infinity": Q is not INF}
    if Q is INF:
        checks["valid"] = False
        return checks
    x, y = Q
    checks["coords_in_range"] = 0 <= x < P and 0 <= y < P
    checks["on_curve"] = is_on_curve(Q)
    checks["order_n"] = scalar_mult(N - 1, Q) == (x, (-y) % P) if checks["on_curve"] else False
    checks["valid"] = all(checks.values())
    return checks


def _bits2int(b: bytes, qlen: int = 256) -> int:
    v = int.from_bytes(b, "big")
    blen = len(b) * 8
    return v >> (blen - qlen) if blen > qlen else v


def rfc6979_k(d: int, h1: bytes, hash_name: str = "sha256") -> int:
    """Nonce deterministik RFC 6979 §3.2."""
    rlen = 32
    x = d.to_bytes(rlen, "big")
    h = (_bits2int(h1) % N).to_bytes(rlen, "big")
    hlen = hashlib.new(hash_name).digest_size
    V = b"\x01" * hlen
    K = b"\x00" * hlen
    K = hmac.new(K, V + b"\x00" + x + h, hash_name).digest()
    V = hmac.new(K, V, hash_name).digest()
    K = hmac.new(K, V + b"\x01" + x + h, hash_name).digest()
    V = hmac.new(K, V, hash_name).digest()
    while True:
        T = b""
        while len(T) < rlen:
            V = hmac.new(K, V, hash_name).digest()
            T += V
        k = _bits2int(T[:rlen])
        if 1 <= k < N:
            return k
        K = hmac.new(K, V + b"\x00", hash_name).digest()
        V = hmac.new(K, V, hash_name).digest()


def sign(d: int, msg: bytes, k: int = None, hash_name: str = "sha256"):
    """Tanda tangan (r, s). k=None → RFC 6979."""
    h1 = hashlib.new(hash_name, msg).digest()
    e = _bits2int(h1)
    while True:
        kk = k if k is not None else rfc6979_k(d, h1, hash_name)
        R = scalar_mult(kk, G)
        r = R[0] % N
        s = pow(kk, -1, N) * (e + r * d) % N
        if r and s:
            return r, s
        if k is not None:
            raise ValueError("nonce k menghasilkan r=0 atau s=0")


def verify(Q, msg: bytes, sig, hash_name: str = "sha256", enforce_low_s: bool = False) -> bool:
    r, s = sig
    if not (1 <= r < N and 1 <= s < N):
        return False
    if enforce_low_s and s > N // 2:
        return False
    e = _bits2int(hashlib.new(hash_name, msg).digest())
    w = pow(s, -1, N)
    X = point_add(scalar_mult(e * w % N, G), scalar_mult(r * w % N, Q))
    if X is INF:
        return False
    return X[0] % N == r


CURVE_PARAMS = {"name": "P-256", "p_bits": 256, "n_bits": 256, "cofactor": H,
                "security_bits": 128}
