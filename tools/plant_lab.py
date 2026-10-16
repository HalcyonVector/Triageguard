"""Plant known crypto in a throwaway Linux VM before a memory capture (ground truth for a dump).

Run inside the lab VM (Ubuntu, needs python3-cryptography), then capture memory while it
is still running. Each case is a long-lived process with a fresh random synthetic key:

  updater     AES-256-GCM, key schedule live
  syncd       ChaCha20, key live
  keysvc      RSA-2048 e=65537, private key live (primes in memory)
  legacy_rsa  RSA-2048 e=3, the FIPS 186-5 small-exponent case
  python3     control: same interpreter, no crypto, random noise only

The four crypto processes start from /tmp/tglab/ (like a dropped binary), so the pipeline's
key scan picks them; the control runs from /usr/bin and should not be picked.
The answers go to ~/ground_truth.json, which you copy out next to the dump.

    python3 plant_lab.py          # leaves the processes running; Ctrl+C stops them
"""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# Written to a file and given the key on stdin, so neither the code nor the key shows up
# in the process's command line (linux.psaux would otherwise hand the key to the scanner).
CHILD = r'''
import os, sys
case, key = sys.argv[1], bytes.fromhex(sys.stdin.readline())
keep, n = [os.urandom(8 << 20)], 0
if case != "control":
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
if case == "aes256":
    enc = Cipher(algorithms.AES(key), modes.GCM(b"\0" * 12)).encryptor()
    keep.append(enc.update(b"x" * 4096))
elif case == "chacha20":
    enc = Cipher(algorithms.ChaCha20(key, b"\0" * 16), None).encryptor()
    keep.append(enc.update(b"x" * 4096))
elif case.startswith("rsa"):
    priv = rsa.generate_private_key(3 if case == "rsa_e3" else 65537, 2048)
    n = priv.public_key().public_numbers().n
    keep.append(priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
print(n, flush=True)
sys.stdin.read()
'''

# comm name, case, cipher the process really uses, key length (None = no symmetric key)
CASES = [
    ("updater", "aes256", "AES-GCM", 32),
    ("syncd", "chacha20", "ChaCha20/Salsa20", 32),
    ("keysvc", "rsa", "RSA", None),
    ("legacy_rsa", "rsa_e3", "RSA", None),
    ("python3", "control", None, None),
]
LAB = Path("/tmp/tglab")


def main():
    LAB.mkdir(exist_ok=True)
    worker = LAB / "worker.py"
    worker.write_text(CHILD)
    procs, truth = [], []
    for name, case, cipher, keylen in CASES:
        key = os.urandom(keylen or 32)
        exe = sys.executable
        if case != "control":
            # a symlink keeps the real interpreter but gives the process its own name and a /tmp path
            exe = LAB / name
            if exe.is_symlink() or exe.exists():
                exe.unlink()
            exe.symlink_to(os.path.realpath(sys.executable))
        p = subprocess.Popen([str(exe), str(worker), case], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, text=True)
        p.stdin.write(key.hex() + "\n")
        p.stdin.flush()
        n = int(p.stdout.readline() or 0)
        procs.append(p)
        truth.append({"process": name, "pid": p.pid, "path": str(exe), "case": case, "cipher": cipher or "none",
                      "aes_key": key.hex() if case == "aes256" else "",
                      "chacha20_key": key.hex() if case == "chacha20" else "",
                      "rsa_bits": 2048 if n else 0, "rsa_e": (3 if case == "rsa_e3" else 65537) if n else 0,
                      "rsa_n": format(n, "x") if n else ""})
        print(f"started {name:<11} pid {p.pid:<6} {cipher or 'no crypto (control)'}")
    out = Path.home() / "ground_truth.json"
    out.write_text(json.dumps({"planted_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                               "kernel": os.uname().release, "cases": truth}, indent=1))
    print(f"\nground truth written to {out}\nNow capture memory in another terminal. Ctrl+C here when done.")
    try:
        signal.pause()
    except KeyboardInterrupt:
        pass
    for p in procs:
        p.stdin.close()
        p.wait()


if __name__ == "__main__":
    main()
