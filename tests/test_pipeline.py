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


def test_weak_tls_flags():
    from triageguard.network import weak_tls
    w = weak_tls({"TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)": 1, "TLS_AES_256_GCM_SHA384 (0x1302)": 1,
                  "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)": 1}, {"TLS 1.0": 1, "TLS 1.3": 1})
    assert "forward secrecy" in w["TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)"]
    assert "TLS_AES_256_GCM_SHA384 (0x1302)" not in w
    assert "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)" in w and "TLS 1.0" in w and "TLS 1.3" not in w


def test_corrupt_modulus_is_not_a_weak_key():
    # a 2048-bit "modulus" divisible by 3 is damaged memory, not a broken key
    n = 3 * ((1 << 2046) + 12345)
    k = rsa_weak.assess([rsa_weak._key(n, 65537, "x", 0, "DER SPKI")])[0]
    assert k["corrupt"] and k["strength"] is None and k["issues"][0]["severity"] == "info"


def test_malfind_and_cmdline_heuristics():
    from triageguard.memory import suspicious_processes
    code = " ".join(["48"] * 64)
    vol = {
        "injected": [
            {"PID": 1, "Process": "MsMpEng.exe", "Start VPN": 0x1000, "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": code},
            {"PID": 2, "Process": "evil.exe", "Start VPN": 0x2000, "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": code},
            {"PID": 3, "Process": "host.exe", "Start VPN": 0x3000, "Protection": "PAGE_EXECUTE_READWRITE",
             "Hexdump": "4d 5a 90 00" + " 00" * 60},
        ],
        "cmdlines": [{"PID": 4, "Process": "notepad.exe", "Args": r'notepad.exe "C:\Users\a\Desktop\ransom_note.txt"'}],
    }
    sev = {f["pid"]: f["severity"] for f in suspicious_processes(vol)}
    assert sev == {1: "low", 2: "high", 3: "critical", 4: "medium"}


def test_shared_code_and_shell_parent_heuristics():
    from triageguard.memory import suspicious_processes
    stub = " ".join(["b0", "00", "eb", "70"] * 16)
    vol = {
        "injected": [{"PID": p, "Process": n, "Start VPN": 0x1000, "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": stub}
                     for p, n in ((10, "svchost.exe"), (11, "explorer.exe"), (12, "notepad.exe"))]
                    + [{"PID": 13, "Process": "evil.exe", "Start VPN": 0x2000, "Protection": "PAGE_EXECUTE_READWRITE",
                        "Hexdump": " ".join(["90"] * 64)}],
        "processes": [{"PID": 1, "PPID": 0, "ImageFileName": "vmtoolsd.exe"}, {"PID": 2, "PPID": 1, "ImageFileName": "cmd.exe"},
                      {"PID": 3, "PPID": 4, "ImageFileName": "cmd.exe"}, {"PID": 4, "PPID": 0, "ImageFileName": "explorer.exe"}],
    }
    sev = {f["pid"]: f["severity"] for f in suspicious_processes(vol)}
    assert sev == {10: "medium", 11: "medium", 12: "medium", 13: "high", 2: "medium"}  # shared code is medium, unique code high


def test_unreadable_extracted_region_is_a_finding_not_a_crash(sample, tmp_path, monkeypatch):
    from triageguard import memory, static
    region = tmp_path / "pid.1.vad.dmp"
    region.write_bytes(b"x" * 64)
    monkeypatch.setattr(memory, "extract", lambda dump, out: ({}, [region]))
    real = static.analyse
    monkeypatch.setattr(static, "analyse", lambda p: (_ for _ in ()).throw(OSError(22, "blocked")) if str(p) == str(region) else real(p))
    res = pipeline.run(sample, db_path=tmp_path / "t.db", workdir=tmp_path / "out", use_llm=False, log=lambda *_: None)
    from triageguard.store import Store
    kinds = {f["kind"]: f["severity"] for f in Store(tmp_path / "t.db").findings(res["run_id"])}
    assert kinds["blocked"] == "high"
