"""Find AES keys in memory by their key schedules.

Software AES expands its key into round keys once (FIPS 197 section 5.2) and keeps the
whole schedule, 176 bytes for AES-128 and 240 for AES-256, next to the key. That schedule
is structured: most words are the XOR of two earlier ones, so a schedule can be told
apart from random bytes, and the key is its first 16 or 32 bytes. Halderman et al.
("Lest We Remember: Cold Boot Attacks on Encryption Keys", USENIX Security 2008) used
this in aeskeyfind to pull disk encryption keys from RAM.

To stay fast in pure Python the scan XORs whole chunks as big integers: for AES-128,
w[i] = w[i-4] ^ w[i-1] whenever i is not a multiple of 4, so bytes 20..31 of a schedule
equal bytes 4..15 XOR bytes 16..27. Where that holds the XOR of the three shifted copies
is a run of zero bytes, which bytes.find locates at C speed. Each run is then checked by
expanding the candidate key and comparing all round keys. The relations are bytewise, so
they also hold for implementations that store each word byte-swapped (OpenSSL's u32 round
keys on x86); both layouts are checked.
"""
import re

SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)
CHUNK = 32 << 20
# (key bytes, schedule bytes, offset of the first XOR-related word w[nk+1])
SIZES = {128: (16, 176, 20), 256: (32, 240, 36)}


def expand(key):
    """FIPS 197 KeyExpansion, returned as bytes in the standard byte order."""
    nk = len(key) // 4
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (nk + 7)):
        t = list(words[i - 1])
        if i % nk == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [SBOX[b] for b in t]
        words.append([a ^ b for a, b in zip(words[i - nk], t)])
    return bytes(b for w in words for b in w)


def _swap(b):
    return b"".join(b[i:i + 4][::-1] for i in range(0, len(b), 4))


def _xor_shifted(chunk, keylen, lead):
    """Bytes z where z[i] == 0 iff chunk[i+lead] == chunk[i+4] ^ chunk[i+lead-4]."""
    n = len(chunk) - lead
    if n <= 0:
        return b""
    a = int.from_bytes(chunk[lead:lead + n], "little")
    b = int.from_bytes(chunk[4:4 + n], "little")
    c = int.from_bytes(chunk[lead - 4:lead - 4 + n], "little")
    return (a ^ b ^ c).to_bytes(n, "little")


def _check(data, i, bits):
    keylen, size, _ = SIZES[bits]
    sched = bytes(data[i:i + size])
    if len(sched) < size or len(set(sched[:keylen])) < keylen // 2:
        return None  # a real key looks random; this filters zeros and fill patterns
    if expand(sched[:keylen]) == sched:
        return sched[:keylen], "standard"
    if expand(_swap(sched[:keylen])) == _swap(sched):
        return _swap(sched[:keylen]), "word-swapped"
    return None


def find_keys(data, sizes=(128, 256)):
    """Return [{bits, offset, layout, key_id}] for every full AES key schedule in data.
    key_id is a short fingerprint, never the key itself, so reports do not carry key
    material; the key is only kept in the returned 'key' field for the caller to drop."""
    found, seen = [], set()
    for bits in sizes:
        keylen, size, lead = SIZES[bits]
        # the 12 bytes after the lead word are XOR-related, then the next word is not
        run = re.compile(rb"\x00{12,}")
        for start in range(0, len(data), CHUNK):
            chunk = bytes(data[start:start + CHUNK + size])
            z = _xor_shifted(chunk, keylen, lead)
            for m in run.finditer(z):
                # a neighbouring byte can XOR to zero by chance (1 in 256) and stretch the
                # run, so try every start that leaves 12 zeros; long runs are zero-filled
                # memory, where no key can be, so only their last start is tried
                ends = range(m.end() - 12, m.start() - 1, -1) if m.end() - m.start() <= 64 else [m.end() - 12]
                for j in ends:
                    i = start + j
                    if i in seen or i >= start + CHUNK:
                        continue
                    hit = _check(data, i, bits)
                    if hit:
                        seen.add(i)
                        key, layout = hit
                        found.append({"bits": bits, "offset": hex(i), "layout": layout, "key": key,
                                      "key_id": _fingerprint(key)})
                        break
    return found


def _fingerprint(key):
    import hashlib
    return hashlib.sha256(key).hexdigest()[:12]
