import importlib.util
from pathlib import Path

import pytest

from triageguard import credentials, crypto, pipeline
from triageguard.crypto import identify, rsa_weak

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("make_synthetic", ROOT / "samples" / "make_synthetic.py")
make_synthetic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(make_synthetic)


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    p = tmp_path_factory.mktemp("s") / "synthetic.raw"
    p.write_bytes(make_synthetic.build())
    return p


def test_identifies_widened_cipher_scope(sample):
    algos = {a["algorithm"]: a["confidence"] for a in identify.identify_file(sample)}
    for name in ("AES", "AES-GCM", "ChaCha20/Salsa20", "Curve25519", "RSA"):
        assert algos.get(name, 0) >= 50, name


def test_no_false_positives_on_random_data():
    import os
    assert identify.identify_bytes(os.urandom(1 << 20)) == []


def test_rsa_weak_keys(sample):
    keys = crypto.analyse(sample)["rsa_keys"]
    tests = {t["test"] for k in keys for t in k["issues"]}
    assert {"modulus size", "small exponent", "shared prime (GCD)", "close primes (Fermat)", "shared modulus"} <= tests
    assert any(k["bits"] == 2048 and not k["issues"] for k in keys)  # the good key stays clean


def test_credentials(sample):
    found = credentials.scan(sample)
    kinds = {f["type"] for f in found}
    assert {"JWT", "OTP secret (otpauth URI)", "GitHub token"} <= kinds
    assert any("alg=none" in i for f in found if f["type"] == "JWT" for i in f["decoded"]["issues"])
    assert all("..." in f["preview"] for f in found)  # never stored in full


def test_end_to_end(sample, tmp_path):
    res = pipeline.run(sample, db_path=tmp_path / "t.db", workdir=tmp_path / "out", use_llm=False, log=lambda *_: None)
    text = Path(res["report"]).read_text()
    assert res["findings"] > 10 and "[F1]" in text and res["report_mode"] == "rules"
