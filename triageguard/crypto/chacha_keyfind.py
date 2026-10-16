"""Find ChaCha20 and Salsa20 keys in memory.

Unlike AES, ChaCha20 has no key schedule: the cipher keeps the 32-byte key as is and
mixes it into a fresh 16-word state for every block (RFC 8439 section 2.3). So there is
no structure inside the key to test, and the key has to be found by what sits around it.
Three layouts are recognised:

  state     the 16-word ChaCha20 state, "expand 32-byte k" then key, counter, nonce
            (RFC 8439 2.3). Hand-written implementations, which most ransomware
            carries, keep the state like this.
  salsa     the Salsa20 state, the same constant spread over the diagonal words
            0, 5, 10, 15 with the key in words 1-4 and 11-14 (Bernstein, "Salsa20
            specification", 2005, section 9). Petya and REvil used Salsa20.
  openssl   OpenSSL 3's ChaCha20 provider context. The generic cipher header records
            keylen 32, ivlen 16 and blocksize 1, a combination no other OpenSSL cipher
            has, and the key follows a few fields later, then the block counter and
            nonce. When a partial block is pending, the context also holds that block's
            keystream, and recomputing it from the key proves the key exactly.
            AES-256-CTR has the same header (OpenSSL's CTR-DRBG uses it in every
            process), so a candidate that starts a valid AES key schedule is skipped.
"""
import hashlib
import re
import struct

from .aes_keyfind import _check as _aes_schedule_at

SIGMA = b"expand 32-byte k"
SALSA_DIAG = re.compile(rb"expa.{16}nd 3.{16}2-by.{16}te k", re.S)
# keylen=32, ivlen=16, blocksize=1 as three little-endian size_t
OSSL_HEADER = re.compile(re.escape(struct.pack("<QQQ", 32, 16, 1)))
OSSL_WINDOW = 256  # how far past the header the key may sit (fields differ between 3.x versions)


def _rotl(v, n):
    return ((v << n) & 0xFFFFFFFF) | (v >> (32 - n))


def chacha_block(key, counter, nonce):
    """One 64-byte ChaCha20 keystream block (RFC 8439 section 2.3)."""
    s = list(struct.unpack("<4I", SIGMA) + struct.unpack("<8I", key) + (counter,) + struct.unpack("<3I", nonce))
    x = s[:]
    for _ in range(10):
        for a, b, c, d in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                           (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl(x[d] ^ x[a], 16)
            x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl(x[b] ^ x[c], 12)
            x[a] = (x[a] + x[b]) & 0xFFFFFFFF; x[d] = _rotl(x[d] ^ x[a], 8)
            x[c] = (x[c] + x[d]) & 0xFFFFFFFF; x[b] = _rotl(x[b] ^ x[c], 7)
    return struct.pack("<16I", *((a + b) & 0xFFFFFFFF for a, b in zip(x, s)))


def _looks_random(key):
    """A real key: many distinct bytes, and no 8-byte word shaped like a pointer or a
    small integer (top two bytes zero), which is what the other context fields hold."""
    if len(key) != 32 or len(set(key)) < 16 or sum(32 <= b < 127 for b in key) > 28:
        return False  # text, such as the banner that follows the constant in OpenSSL's code
    return all(key[i + 6:i + 8] != b"\0\0" for i in range(0, 32, 8))


def _is_pointer(q):
    """A user-space x86-64 pointer: top two bytes zero, the next one set."""
    return len(q) == 8 and q[6:] == b"\0\0" and q[5] != 0


def _openssl(data, at):
    """Key in the ChaCha20 provider context whose cipher header starts at `at`. The
    generic header ends with the hw, ks and libctx pointers, and the cipher's own fields
    start right after them, so the key is the first random-looking 32 bytes that a
    pointer precedes by 24 bytes (that skips the IV copies inside the header)."""
    for off in range(at + 48, at + 24 + OSSL_WINDOW, 8):
        key = bytes(data[off:off + 32])
        if not _is_pointer(bytes(data[off - 24:off - 16])) or not _looks_random(key):
            continue
        if _aes_schedule_at(data, off, 256):
            return None  # an AES-256-CTR context
        ctr = bytes(data[off + 32:off + 48])
        buf = bytes(data[off + 48:off + 112])
        if len(buf) < 64:
            return None
        counter, = struct.unpack("<I", ctr[:4])
        partial, = struct.unpack("<I", data[off + 112:off + 116])
        verified = 0 < partial < 64 and counter > 0 and chacha_block(key, counter - 1, ctr[4:]) == buf
        return off, key, "openssl", verified
    return None


def find_keys(data):
    """Return [{bits, offset, layout, verified, key, key_id}] for every ChaCha20/Salsa20
    key found. As with the AES finder, key_id is a fingerprint and the caller drops 'key'."""
    hits = []
    i = data.find(SIGMA)
    while i >= 0:
        key = bytes(data[i + 16:i + 48])
        if _looks_random(key):
            hits.append((i, key, "state", True))
        i = data.find(SIGMA, i + 1)
    for m in SALSA_DIAG.finditer(data):
        w = m.group(0)
        key = w[4:20] + w[44:60]
        if _looks_random(key):
            hits.append((m.start(), key, "salsa", True))
    for m in OSSL_HEADER.finditer(data):
        h = _openssl(data, m.start())
        if h:
            hits.append(h)
    found, seen = [], set()
    for off, key, layout, verified in hits:
        if (off, key) in seen:
            continue
        seen.add((off, key))
        found.append({"bits": 256, "offset": hex(off), "layout": layout, "verified": verified,
                      "key": key, "key_id": hashlib.sha256(key).hexdigest()[:12]})
    return found
