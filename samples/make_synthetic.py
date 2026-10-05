"""Build a synthetic 'memory dump' with planted crypto artefacts and fake credentials.

Everything here is generated locally: keys are random, tokens are made up.
Used for tests and for demoing the pipeline without a real dump.

    python samples/make_synthetic.py            -> samples/synthetic.raw
"""

import base64
import json
import os
import random
import secrets
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

rng = random.Random(3141)  # fixed seed so the sample is reproducible


def is_prime(n, k=20):
    if n < 4:
        return n in (2, 3)
    if n % 2 == 0:
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(k):
        x = pow(rng.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def prime(bits):
    while True:
        p = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(p):
            return p


def next_prime(n):
    n |= 1
    while not is_prime(n):
        n += 2
    return n


def capi_blob(n, e, bits):
    return b"\x06\x02\x00\x00\x00\xa4\x00\x00RSA1" + struct.pack("<II", bits, e) + n.to_bytes(bits // 8, "little")


def cng_blob(n, e, bits):
    eb = e.to_bytes((e.bit_length() + 7) // 8, "big")
    return b"RSA1" + struct.pack("<IIIII", bits, len(eb), bits // 8, 0, 0) + eb + n.to_bytes(bits // 8, "big")


def der_spki(n, e):
    return rsa.RSAPublicNumbers(e, n).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def b64url(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def build():
    parts = []
    pad = lambda n=4096: parts.append(b"\x00" * n)

    # crypto constants as they would sit in a loaded binary's .rdata
    parts.append(bytes.fromhex("637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"))  # AES S-box start
    pad()
    parts.append(b"\x00\x00\x00\x00expand 32-byte k\x00\x00\x00\x00")  # ChaCha20 sigma
    pad()
    parts.append(b"\xed" + b"\xff" * 30 + b"\x7f")  # Curve25519 prime
    parts.append("x25519".encode())
    pad()
    parts.append(bytes.fromhex("0000c201840346020807ca068c044e05"))  # GHASH rem_8bit
    parts.append("ChainingModeGCM".encode("utf-16le") + b"\x00\x00")
    pad()

    # RSA keys
    good = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    parts.append(good.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    pad()
    p, q = prime(256), prime(256)
    parts.append(capi_blob(p * q, 3, 512))  # 512-bit, e=3
    pad()
    shared = prime(512)
    parts.append(cng_blob(shared * prime(512), 65537, 1024))  # two keys sharing a prime
    pad(1024)
    parts.append(cng_blob(shared * prime(512), 65537, 1024))
    pad()
    p = prime(1024)
    parts.append(der_spki(p * next_prime(p + 2 ** 20), 65537))  # close primes, Fermat-factorable
    pad()
    n = prime(1024) * prime(1024)
    parts.append(der_spki(n, 65537))  # same modulus, two exponents
    pad(512)
    parts.append(der_spki(n, 17))
    pad()

    # encrypted-looking blob (high entropy)
    parts.append(os.urandom(65536))
    pad()

    # fake credentials
    none_jwt = f"{b64url({'alg': 'none', 'typ': 'JWT'})}.{b64url({'sub': 'synthetic-user', 'role': 'admin'})}."
    hs_jwt = f"{b64url({'alg': 'HS256', 'typ': 'JWT'})}.{b64url({'sub': 'synthetic', 'iss': 'triageguard-lab', 'exp': 1700000000})}.{secrets.token_urlsafe(32)}"
    parts.append(f"Authorization: Bearer {hs_jwt}\r\n".encode())
    pad(256)
    parts.append(f"token={none_jwt}\x00".encode())
    pad(256)
    otp_secret = base64.b32encode(os.urandom(10)).decode().rstrip("=")  # 80-bit, too short
    parts.append(f"otpauth://totp/Lab:student@example.com?secret={otp_secret}&issuer=Lab\x00".encode())
    pad(256)
    parts.append(("ghp_" + "".join(rng.choice("ABCDEFabcdef0123456789") for _ in range(36))).encode())
    pad()

    # ransom-ish strings so static/YARA have something
    parts.append(b"Your files have been encrypted. Pay in bitcoin to http://example7xyz.onion\x00")
    pad()
    return b"".join(parts)


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).with_name("synthetic.raw"))
    out.write_bytes(build())
    print(f"wrote {out} ({out.stat().st_size} bytes)")
