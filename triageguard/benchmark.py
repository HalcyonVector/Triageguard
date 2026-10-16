"""Ground-truth test: processes whose crypto we chose, so every detector can be scored.

Each case starts a child Python process that uses (or does not use) a cipher with a
fresh random synthetic key, then this process reads the child's whole address space
from /proc/<pid>/mem (Linux only; reading your own child needs no extra rights) and
runs the same detectors the pipeline runs on a memory dump. Because we know which
cipher ran and which key it used, each result is a true or false positive or negative.

The cases cover the three things a detector can be right about:
  * which ciphers a process implements (cipher identification by constants),
  * whether a live AES key can be read back (key schedule search),
  * whether a ChaCha20 key can be read back, with the context's pending keystream
    block (a partial last block) and without it, and after the context is freed,
  * whether an RSA private key can be rebuilt from primes left in memory, both while
    the key is in use and after the program freed it (the WannaCry flaw, here tested
    against OpenSSL, which wipes key material when it frees it).
"""
import csv
import gc
import json
import os
import subprocess
import sys
import time
from pathlib import Path

from .crypto import aes_keyfind, chacha_keyfind, identify, key_recovery, rsa_weak

CHILD = r'''
import gc, os, sys
case, key = sys.argv[1], bytes.fromhex(sys.argv[2])
keep, n = [], 0
noise = os.urandom(8 << 20)  # random bytes, the hardest background for a false positive
if case != "control":
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, x25519
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
if case.startswith("aes"):
    mode = modes.GCM(b"\0" * 12) if len(key) == 32 else modes.CTR(b"\0" * 16)
    enc = Cipher(algorithms.AES(key), mode).encryptor()
    keep.append(enc.update(b"x" * 4096))
    if case.endswith("freed"):
        del enc
elif case.startswith("chacha20"):
    enc = Cipher(algorithms.ChaCha20(key, os.urandom(16)), None).encryptor()
    keep.append(enc.update(b"x" * (100 if case.endswith("partial") else 4096)))
    if case.endswith("freed"):
        del enc
elif case == "x25519":
    priv = x25519.X25519PrivateKey.generate()
    keep.append(priv.exchange(x25519.X25519PrivateKey.generate().public_key()))
elif case.startswith("rsa"):
    priv = rsa.generate_private_key(65537, 2048)
    n = priv.public_key().public_numbers().n
    keep.append(priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    if case.endswith("freed"):
        del priv
gc.collect()
print(n, flush=True)
sys.stdin.read()
'''

# case: (cipher the process really uses, key we can check)
CASES = {
    "control": (None, None),
    "aes128_live": ("AES", 16),
    "aes256_live": ("AES-GCM", 32),
    "aes128_freed": ("AES", 16),
    "chacha20": ("ChaCha20/Salsa20", 32),
    "chacha20_partial": ("ChaCha20/Salsa20", 32),
    "chacha20_freed": ("ChaCha20/Salsa20", 32),
    "x25519": ("Curve25519", None),
    "rsa_live": ("RSA", None),
    "rsa_freed": ("RSA", None),
}


def dump_child(case, key):
    """Run one case and return (memory bytes, RSA modulus or 0)."""
    p = subprocess.Popen([sys.executable, "-c", CHILD, case, key.hex()], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, text=True)
    try:
        n = int(p.stdout.readline() or 0)
        out = bytearray()
        with open(f"/proc/{p.pid}/maps") as maps, open(f"/proc/{p.pid}/mem", "rb", 0) as mem:
            for line in maps:
                rng, perms = line.split()[:2]
                if "r" not in perms or "[vvar" in line or "[vsyscall]" in line:
                    continue
                lo, hi = (int(x, 16) for x in rng.split("-"))
                try:
                    mem.seek(lo)
                    out += mem.read(hi - lo)
                except (OSError, ValueError):
                    pass
        return bytes(out), n
    finally:
        p.stdin.close()
        p.wait()


def run_case(case, trial):
    used, keylen = CASES[case]
    key = os.urandom(keylen or 32)
    data, n = dump_child(case, key)
    found = identify.score(identify.scan_buffer(data))
    impl = sorted(a["algorithm"] for a in found if a["basis"].startswith("implementation"))
    aes = aes_keyfind.find_keys(data) if keylen in (16, 32) or case == "control" else []
    chacha = chacha_keyfind.find_keys(data)
    mine = [k for k in chacha if k["key"] == key]
    rsa_hit = False
    if n:
        keys = [k for k in rsa_weak.extract_keys(data) if k["n"] == n]
        for k in keys:
            k["format"] = "PEM private"  # only the public key is exported; test the primes, not the format filter
        rsa_hit = bool(key_recovery.recover(keys, data))
    row = {"case": case, "trial": trial, "mb": len(data) >> 20, "uses": used or "none",
           "ciphers_implemented": " ".join(impl),
           "used_cipher_found": (used in impl) if used else "",
           "ciphers_flagged_not_used": len([a for a in impl if a != used and not (used == "AES-GCM" and a == "AES")]),
           "aes_key_expected": bool(keylen in (16, 32) and case.startswith("aes")),
           "aes_key_found": any(k["key"] == key for k in aes),
           "aes_other_schedules": sum(k["key"] != key for k in aes),
           "chacha_key_found": bool(mine), "chacha_key_verified": any(k["verified"] for k in mine),
           # Python 3.13's allocator (mimalloc) seeds its own PRNG with a ChaCha20 state,
           # so a few real but unrelated states turn up in every process
           "chacha_other_keys": sum(k["key"] != key for k in chacha),
           "rsa_expected": case.startswith("rsa"), "rsa_recovered": rsa_hit}
    del data
    gc.collect()
    return row


def summarise(rows):
    def rate(sel, field):
        xs = [r for r in rows if sel(r)]
        return {"hit": sum(bool(r[field]) for r in xs), "n": len(xs)}

    return {
        "cipher_id_recall": rate(lambda r: r["uses"] != "none", "used_cipher_found"),
        "cipher_id_control_flags": rate(lambda r: r["case"] == "control", "ciphers_implemented"),
        "aes_live_recall": rate(lambda r: r["case"] in ("aes128_live", "aes256_live"), "aes_key_found"),
        "aes_freed_found": rate(lambda r: r["case"] == "aes128_freed", "aes_key_found"),
        "aes_control_false_keys": sum(r["aes_other_schedules"] for r in rows if r["case"] == "control"),
        "chacha_live_recall": rate(lambda r: r["case"] in ("chacha20", "chacha20_partial"), "chacha_key_found"),
        "chacha_partial_verified": rate(lambda r: r["case"] == "chacha20_partial", "chacha_key_verified"),
        "chacha_freed_found": rate(lambda r: r["case"] == "chacha20_freed", "chacha_key_found"),
        "chacha_control_other_keys": sum(r["chacha_other_keys"] for r in rows if r["case"] == "control"),
        "rsa_live_recovered": rate(lambda r: r["case"] == "rsa_live", "rsa_recovered"),
        "rsa_freed_recovered": rate(lambda r: r["case"] == "rsa_freed", "rsa_recovered"),
    }


def run(trials=3, out_dir="results/benchmark", log=print):
    if not Path("/proc/self/mem").exists():
        raise SystemExit("The ground-truth test reads /proc/<pid>/mem, so it runs on Linux only (WSL works).")
    rows = []
    for t in range(1, trials + 1):
        for case in CASES:
            start = time.time()
            rows.append(run_case(case, t))
            log(f"trial {t} {case}: {time.time() - start:.1f}s")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "cases.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    summary = {"trials": trials, "python": sys.version.split()[0], **summarise(rows)}
    (out / "summary.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
    return summary
