"""Extract RSA public keys from raw bytes and test them for weaknesses.

Formats handled:
  * Windows CryptoAPI PUBLICKEYBLOB / PRIVATEKEYBLOB ("RSA1"/"RSA2", modulus little-endian)
  * Windows CNG BCRYPT_RSAKEY_BLOB ("RSA1"/"RSA2" magic, big-endian fields)
  * DER SubjectPublicKeyInfo (rsaEncryption OID) and PEM blocks

Tests: modulus size, small public exponent, shared modulus, shared prime
(pairwise GCD), close primes (Fermat) and small factors (trial division).
"""

import base64
import hashlib
import math
import re
import struct

from cryptography.hazmat.primitives.serialization import load_der_public_key, load_pem_private_key

CAPI_HDR = re.compile(rb"[\x06\x07]\x02\x00\x00(?:\x00\xa4|\x00\x24)\x00\x00(RSA[12])")
RSA_OID = bytes.fromhex("06092a864886f70d010101")
STANDARD_E = {3, 5, 17, 257, 65537}
PEM_RE = re.compile(rb"-----BEGIN (RSA PRIVATE KEY|PUBLIC KEY|RSA PUBLIC KEY|PRIVATE KEY)-----(.+?)-----END \1-----", re.S)


def _key(n, e, source, offset, fmt):
    return {"n": n, "e": e, "bits": n.bit_length(), "source": source, "offset": hex(offset), "format": fmt,
            "fingerprint": hashlib.sha256(n.to_bytes((n.bit_length() + 7) // 8, "big")).hexdigest()[:16]}


def _capi(data, source):
    keys = []
    for m in CAPI_HDR.finditer(data):
        p = m.end()
        if p + 8 > len(data):
            continue
        bitlen, e = struct.unpack_from("<II", data, p)
        nbytes = bitlen // 8
        if bitlen % 8 or not (256 <= bitlen <= 16384) or p + 8 + nbytes > len(data):
            continue
        n = int.from_bytes(data[p + 8:p + 8 + nbytes], "little")
        if n.bit_length() > bitlen - 8 and e > 1:
            keys.append(_key(n, e, source, m.start(), "CAPI blob"))
    return keys


def _cng(data, source):
    keys = []
    for magic in (b"RSA1", b"RSA2"):
        start = 0
        while (i := data.find(magic, start)) >= 0:
            start = i + 1
            if i >= 8 and data[i - 8:i - 6] in (b"\x06\x02", b"\x07\x02"):
                continue  # CAPI blob, handled above
            if i + 24 > len(data):
                break
            bitlen, cb_e, cb_n = struct.unpack_from("<III", data, i + 4)
            if not (256 <= bitlen <= 16384 and 1 <= cb_e <= 8 and cb_n == bitlen // 8):
                continue
            p = i + 24
            if p + cb_e + cb_n > len(data):
                continue
            e = int.from_bytes(data[p:p + cb_e], "big")
            n = int.from_bytes(data[p + cb_e:p + cb_e + cb_n], "big")
            if e > 1 and n.bit_length() > bitlen - 8:
                keys.append(_key(n, e, source, i, "CNG blob"))
    return keys


def _der(data, source):
    keys = []
    start = 0
    while (i := data.find(RSA_OID, start)) >= 0:
        start = i + 1
        # SubjectPublicKeyInfo starts a few bytes before the OID: 30 82 LL LL 30 0d 06 09 ...
        for back in (6, 5, 4):
            s = i - back
            if s < 0 or data[s] != 0x30:
                continue
            try:
                if data[s + 1] == 0x82:
                    total = 4 + int.from_bytes(data[s + 2:s + 4], "big")
                elif data[s + 1] == 0x81:
                    total = 3 + data[s + 2]
                else:
                    total = 2 + data[s + 1]
                pub = load_der_public_key(bytes(data[s:s + total]))
                nums = pub.public_numbers()
                keys.append(_key(nums.n, nums.e, source, s, "DER SPKI"))
                break
            except Exception:
                continue
    return keys


def _pem(data, source):
    keys = []
    for m in PEM_RE.finditer(data):
        try:  # PEM fragments in memory are often truncated or corrupt
            body = base64.b64decode(b"".join(m.group(2).split()))
            if b"PRIVATE" in m.group(1):
                nums = load_pem_private_key(m.group(0), password=None).public_key().public_numbers()
            else:
                nums = load_der_public_key(body).public_numbers()
            keys.append(_key(nums.n, nums.e, source, m.start(), "PEM"))
        except Exception:
            continue
    return keys


def extract_keys(data, source="buffer"):
    keys = _capi(data, source) + _cng(data, source) + _der(data, source) + _pem(data, source)
    seen, out = set(), []
    for k in keys:  # same key often appears more than once in memory
        if (k["n"], k["e"]) not in seen:
            seen.add((k["n"], k["e"]))
            out.append(k)
    return out


# ---------------------------------------------------------------- tests

def _fermat(n, rounds=50_000):
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(rounds):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def _small_factor(n, limit=100_000):
    if n % 2 == 0:
        return 2
    for p in range(3, limit, 2):
        if n % p == 0:
            return p
    return None


def _pollard_rho(n, max_bits=100):
    """Only for toy moduli; shows 'factorable size' concretely in the demo."""
    if n.bit_length() > max_bits:
        return None
    for c in range(1, 20):
        x = y = 2
        d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d
    return None


def assess(keys):
    """Run weakness tests. Adds 'issues' and 'strength' (0-100) to each key."""
    for k in keys:
        k["issues"] = []
        n, e, bits = k["n"], k["e"], k["bits"]
        if bits <= 512:
            k["issues"].append({"test": "modulus size", "severity": "critical",
                                "detail": f"{bits}-bit modulus is publicly factorable (RSA-512 broken since 1999)"})
        elif bits < 1024:
            k["issues"].append({"test": "modulus size", "severity": "high", "detail": f"{bits}-bit modulus is factorable with academic resources"})
        elif bits < 2048:
            k["issues"].append({"test": "modulus size", "severity": "medium", "detail": f"{bits}-bit modulus is below the NIST 2048-bit minimum"})
        if e < 65537:
            # Hastad needs about e ciphertexts of one message, so only tiny e is a practical risk
            k["issues"].append({"test": "small exponent", "severity": "high" if e == 3 else "medium" if e <= 17 else "low",
                                "detail": f"e={e}; vulnerable to Hastad broadcast / cube-root attacks without proper padding"})
        if (f := _small_factor(n)) or (f := _pollard_rho(n)):
            if bits >= 512:
                # no RSA key generator produces this; in a memory dump it means the
                # bytes were partly overwritten or the structure was mis-parsed
                k["issues"] = [{"test": "invalid modulus", "severity": "info",
                                "detail": f"n has small factor {f}; not a real RSA modulus, likely corrupt memory"}]
                k["corrupt"] = True
                continue
            k["issues"].append({"test": "small factor", "severity": "critical", "detail": f"n has factor {f}"})
            k["factor"] = f
        elif (pq := _fermat(n)):
            k["issues"].append({"test": "close primes (Fermat)", "severity": "critical",
                                "detail": f"|p-q| small, factored: p={hex(pq[0])[:18]}..."})
            k["factor"] = pq[0]

    # cross-key tests (corrupt moduli would only produce bogus shared-prime hits)
    valid = [k for k in keys if not k.get("corrupt")]
    for i, a in enumerate(valid):
        for b in valid[i + 1:]:
            if a["n"] == b["n"] and a["e"] != b["e"]:
                # an odd e next to a standard one is usually a damaged copy of the same key
                odd = {a["e"], b["e"]} - STANDARD_E
                for k, other in ((a, b), (b, a)):
                    k["issues"].append({"test": "shared modulus", "severity": "low" if odd else "critical",
                                        "detail": f"same n as key {other['fingerprint']} with different e"
                                                  + (f"; non-standard e {sorted(odd)} suggests a corrupt copy" if odd
                                                     else "; common-modulus attack recovers plaintext")})
            elif a["n"] != b["n"] and (g := math.gcd(a["n"], b["n"])) > 1:
                for k, other in ((a, b), (b, a)):
                    k["issues"].append({"test": "shared prime (GCD)", "severity": "critical",
                                        "detail": f"gcd with key {other['fingerprint']} is a prime factor; both keys broken"})
                    k["factor"] = g

    penalty = {"critical": 100, "high": 50, "medium": 25, "low": 10, "info": 0}
    for k in keys:
        if k.get("corrupt"):
            k["strength"] = None
            continue
        base = 100 if k["bits"] >= 3072 else 90 if k["bits"] >= 2048 else 60
        k["strength"] = max(0, base - max([penalty[x["severity"]] for x in k["issues"]], default=0))
    return keys


def to_serialisable(keys):
    """Drop the big ints for storage; keep a short modulus preview."""
    out = []
    for k in keys:
        d = {x: v for x, v in k.items() if x not in ("n", "factor")}
        d["n_preview"] = hex(k["n"])[:34] + "..."
        d["factored"] = "factor" in k
        out.append(d)
    return out
