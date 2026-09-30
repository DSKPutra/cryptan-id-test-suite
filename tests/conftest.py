import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from uk1_metode import pipeline  # noqa: E402
from uk1_metode.profile import load_profiles  # noqa: E402

PROFILE_DIR = ROOT / "config" / "profiles"
ALL = {"AES-128": "aes128", "ChaCha20": "chacha20", "SHA3-256": "sha3_256",
       "RSA-OAEP-2048": "rsa_oaep_2048", "ECDSA-P256": "ecdsa_p256"}


def profile_of(alg_id):
    return load_profiles(PROFILE_DIR / f"{ALL[alg_id]}.yaml")[0]


_cache = {}


@pytest.fixture(scope="session")
def result():
    """Hasil pipeline (mode quick) per algoritma, di-cache untuk satu sesi."""
    def get(alg_id):
        if alg_id not in _cache:
            _cache[alg_id] = pipeline.run(profile_of(alg_id), quick=True)
        return _cache[alg_id]
    return get
