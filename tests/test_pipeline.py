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


def test_report_command_without_a_key_says_so(tmp_path, monkeypatch):
    from triageguard import cli
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("TRIAGEGUARD_LLM_URL", raising=False)
    with pytest.raises(SystemExit) as e:
        cli.main(["report", str(tmp_path / "x.db"), "--out", str(tmp_path / "r.md")])
    assert "GROQ_API_KEY" in str(e.value)


def test_rsa_strength_follows_nist_sp800_57():
    from triageguard.crypto import rsa_weak
    assert rsa_weak.security_bits(2048) == 112 and rsa_weak.security_bits(3072) == 128
    assert rsa_weak.security_bits(1536) == 80  # between table rows: the lower strength
    assert round(rsa_weak.gnfs_strength(1024)) == 80  # FIPS 140-2 IG 7.5 formula meets the table
    k = {"bits": 2048, "issues": []}
    assert rsa_weak.strength_score(k) == {"security_bits": 112, "strength": 88, "nist_status": "acceptable"}
    k = {"bits": 1024, "issues": [{"test": "modulus size", "severity": "medium"}]}
    assert rsa_weak.strength_score(k)["nist_status"].startswith("disallowed")
    # at or below the public factoring record, or factored by a test: no security left
    assert rsa_weak.strength_score({"bits": 768, "issues": []})["strength"] == 0
    assert rsa_weak.strength_score({"bits": 4096, "issues": [{"test": "shared prime (GCD)", "severity": "critical"}]})["strength"] == 0


def test_confidence_is_dempster_combination_and_gcm_supports_aes():
    from triageguard.crypto.identify import combine, score
    from triageguard.crypto.signatures import SIGNATURES
    assert abs(combine([0.6, 0.5]) - 0.8) < 1e-9
    sig = {s.name: s for s in SIGNATURES}
    res = {r["algorithm"]: r for r in score({
        "AES S-box": (sig["AES S-box"], [0]), "ChainingModeGCM": (sig["ChainingModeGCM"], [64])})}
    # belief is monotone: AES-GCM is a subset of AES, so AES is at least as likely
    assert res["AES"]["confidence"] == round(combine([0.6, 0.7]) * 100, 1) >= res["AES-GCM"]["confidence"]


def test_risk_is_evidence_fusion_over_independent_sources():
    from triageguard import report

    def f(ref, sev, module, kind="k"):
        return {"ref": ref, "severity": sev, "module": module, "kind": kind, "data": {}}
    # many findings from one source count once (cautious rule), at the strongest one
    assert report.exposure_score([f(f"F{i}", "low", "rsa") for i in range(40)]) == 20
    assert report.compromise_score([f("F1", "critical", "memory")]) == 95
    # two independent medium sources: 1 - 0.45^2
    assert report.compromise_score([f("F1", "medium", "memory"), f("F2", "medium", "static")]) == 80
    # overall: compromise in full, exposure discounted to half (Shafer discounting)
    both = [f("F1", "medium", "memory"), f("F2", "critical", "rsa")]
    assert (report.compromise_score(both), report.exposure_score(both)) == (55, 95)
    assert report.risk_score(both) == round(100 * (1 - 0.45 * (1 - 0.5 * 0.95)))
    assert report.risk_score([f("F1", "critical", "rsa")]) < 50  # weak crypto alone is not an attack
    assert report.risk_band(95) == "critical" and report.risk_band(64) == "medium"


def test_libffi_trampoline_is_not_injection():
    from triageguard.memory import suspicious_processes
    # the region malfind reported in unattended-upgrades on a clean Ubuntu 24.04 VM
    ffi = ("00 00 00 00 00 00 00 00 53 00 00 00 00 00 00 00 f3 0f 1e fa 4c 8d 15 f5 ff ff ff ff 25 07 00 00 00 "
           "0f 1f 80 00 00 00 00 ec 5c 7c 0d f7 74 00 00 68 5a 6d 1e 00 00 00 00 10 f5 87 0d f7 74 00 00")
    vol = {"injected": [{"PID": 843, "Process": "unattended-upgr", "Start": 0x1000, "Protection": "rwx", "Hexdump": ffi}]}
    assert [f["severity"] for f in suspicious_processes(vol)] == ["low"]


def test_known_benign_names_and_platform_keys():
    from triageguard.crypto import rsa_weak
    from triageguard.memory import imitated_tool, suspicious_processes
    assert imitated_tool("python") is None and imitated_tool("nettstat") == "netstat"
    code = " ".join(["48"] * 64)
    vol = {"injected": [{"PID": 1, "Process": "smartscreen.ex", "Start VPN": 0x1000, "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": code},
                        {"PID": 2, "Process": "Microsoft.Acti", "Start VPN": 0x1000, "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": code}]}
    assert {f["severity"] for f in suspicious_processes(vol)} == {"low"}
    k = {"n": (1 << 511) + 1, "e": 65537, "bits": 512, "fingerprint": "dbc228e0c113b4f2"}
    assert [i["severity"] for i in rsa_weak.assess([k])[0]["issues"]] == ["info"]


def test_reverse_shell_chain():
    from triageguard.memory import suspicious_processes
    # the Seized image: ncat -> bash -> python pty.spawn -> bash, all as root
    vol = {"_os": "linux",
           "processes": [{"PID": 2854, "PPID": 1, "ImageFileName": "ncat"}, {"PID": 2876, "PPID": 2854, "ImageFileName": "bash"},
                         {"PID": 2886, "PPID": 2876, "ImageFileName": "python"}, {"PID": 2887, "PPID": 2886, "ImageFileName": "bash"}],
           "cmdlines": [{"PID": 2886, "Process": "python", "Args": 'python -c import pty; pty.spawn("/bin/bash")'}]}
    sev = {f["pid"]: f["severity"] for f in suspicious_processes(vol)}
    assert sev[2876] == "high" and sev[2886] == "high"


def test_xp_heap_and_call_thunks_are_not_injection():
    from triageguard.memory import suspicious_processes
    # regions malfind reported in the M57 XP image: the CSRSS shared heap and OpenOffice's UNO bridge thunks
    heap = "c8 00 00 00 b0 01 00 00 ff ee ff ee 08 70 00 00 08 00 00 00 00 fe 00 00 " + " 00" * 40
    thunks = ("64 d1 86 61 38 00 9a 02 48 00 9a 02 58 00 9a 02 18 00 9a 02 28 00 9a 02 b8 03 00 00 00 ba 00 00 "
              "00 00 e9 9b 1b ec 5e 00 b8 04 00 00 00 ba 00 00 00 00 e9 8b 1b ec 5e 00 b8 00 00 00 00 ba 00 00")
    vol = {"injected": [{"PID": 924, "Process": "csrss.exe", "Start VPN": 0x7f6f0000, "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": heap},
                        {"PID": 3088, "Process": "soffice.bin", "Start VPN": 0x29a0000, "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": thunks}]}
    assert {f["severity"] for f in suspicious_processes(vol)} == {"low"}


def test_llm_report_uses_rescored_findings(tmp_path, monkeypatch):
    import json
    from triageguard import cli, report
    from triageguard.store import Store
    db = tmp_path / "d.db"
    s = Store(str(db))
    s.start_run("d.mem")
    flag = {"pid": 1, "process": "a.exe", "severity": "high", "reason": "1 RWX/injected region(s): 1 x unique code"}
    s.add("memory", "suspicious_process", "PID 1 a.exe: " + flag["reason"], flag, "high")
    s.commit()
    ref = s.findings()[0]["ref"]
    s.close()
    fj = tmp_path / "findings.json"
    fj.write_text(json.dumps([{"ref": ref, "severity": "low", "title": "PID 1 a.exe: 1 RWX/injected region(s): 1 x heap"}]))
    seen = {}
    monkeypatch.setattr(report, "llm_available", lambda: True)

    def fake_generate(findings, *a):
        seen["f"] = findings
        return "x", "llm"
    monkeypatch.setattr(report, "generate", fake_generate)
    cli.main(["report", str(db), "--out", str(tmp_path / "r.md"), "--findings", str(fj)])
    f = seen["f"][0]
    assert f["severity"] == "low" and f["data"]["severity"] == "low" and f["data"]["reason"].endswith("1 x heap")
