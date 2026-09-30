"""Kriteria penerimaan: core/ lolos KAT resmi + uji silang independen."""
import hashlib
import os
import random

import pytest

from core import aes, chacha20, ecdsa_p256 as ec, kat, keccak, rsa_oaep


@pytest.mark.parametrize("alg", list(kat.RUNNERS))
def test_kat_official_vectors_pass(alg):
    r = kat.run(alg)
    assert r["status"] == "LULUS", [c["id"] for c in r["cases"] if not c["pass"]]
    assert r["total"] >= 3


def test_sha3_matches_hashlib_random_lengths():
    rng = random.Random(1)
    for n in [0, 1, 135, 136, 137, 271, 272, 500]:
        m = bytes(rng.getrandbits(8) for _ in range(n))
        assert keccak.sha3_256(m) == hashlib.sha3_256(m).digest()


def test_aes_decrypt_inverts_encrypt():
    rng = random.Random(2)
    for _ in range(20):
        k, p = os.urandom(16), bytes(rng.getrandbits(8) for _ in range(16))
        assert aes.decrypt_block(k, aes.encrypt_block(k, p)) == p


def test_rsa_oaep_roundtrip_sha256_and_uniform_error():
    kp = rsa_oaep.generate_keypair(1024, rng=random.Random(5))
    ct = rsa_oaep.encrypt(kp.public(), b"cryptan.id")
    assert rsa_oaep.decrypt(kp, ct) == b"cryptan.id"
    bad = bytearray(ct); bad[-1] ^= 1
    with pytest.raises(rsa_oaep.DecryptionError, match="^decryption error$"):
        rsa_oaep.decrypt(kp, bytes(bad))


def test_ecdsa_sign_verify_and_reject_tampered():
    d = 0x1234567890ABCDEF
    Q = ec.public_key(d)
    sig = ec.sign(d, b"pesan")
    assert ec.verify(Q, b"pesan", sig)
    assert not ec.verify(Q, b"pesan!", sig)


# ---- interoperabilitas dengan pyca/cryptography (OpenSSL), bila terpasang
crypto = pytest.importorskip("cryptography", reason="uji silang opsional")


def test_interop_aes_chacha_with_openssl():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    k = os.urandom(16)
    p = os.urandom(16)
    enc = Cipher(algorithms.AES(k), modes.ECB()).encryptor()
    assert aes.encrypt_block(k, p) == enc.update(p) + enc.finalize()
    k2, n = os.urandom(32), os.urandom(12)
    data = os.urandom(200)
    full_nonce = (1).to_bytes(4, "little") + n
    enc = Cipher(algorithms.ChaCha20(k2, full_nonce), mode=None).encryptor()
    assert chacha20.encrypt(k2, n, data, counter=1) == enc.update(data)


def test_interop_rsa_oaep_and_ecdsa_with_openssl():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec as cec, padding, rsa, utils
    sk = rsa.generate_private_key(65537, 2048)
    nums = sk.private_numbers()
    kp = rsa_oaep.PrivateKey(nums.public_numbers.n, 65537, nums.d, nums.p, nums.q)
    ct = rsa_oaep.encrypt(kp.public(), b"interop")
    pad = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    assert sk.decrypt(ct, pad) == b"interop"
    assert rsa_oaep.decrypt(kp, sk.public_key().encrypt(b"balik", pad)) == b"balik"

    esk = cec.generate_private_key(cec.SECP256R1())
    d = esk.private_numbers().private_value
    r, s = ec.sign(d, b"interop")
    esk.public_key().verify(utils.encode_dss_signature(r, s), b"interop", cec.ECDSA(hashes.SHA256()))
    r2, s2 = utils.decode_dss_signature(esk.sign(b"balik", cec.ECDSA(hashes.SHA256())))
    pn = esk.public_key().public_numbers()
    assert ec.verify((pn.x, pn.y), b"balik", (r2, s2))
